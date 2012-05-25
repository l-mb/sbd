
/* 
 * Copyright (C) 2012 Lars Marowsky-Bree <lmb@suse.com>
 * 
 * Based on crm_mon.c, which was:
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* TODO list:
 *
 * - Trying to shutdown a node if no devices are up will fail, since SBD
 * currently uses a message via the disk to achieve this.
 *
 * - Shutting down cluster nodes while the majority of devices is down
 * will eventually take the cluster below the quorum threshold, at which
 * time the remaining cluster nodes will all immediately suicide.
 *
 */

#include "sbd.h"

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/utsname.h>

#include <crm/msg_xml.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>

#include <crm/cib.h>
#include <crm/pengine/status.h>

void clean_up(int rc);
void crm_diff_update(const char *event, xmlNode * msg);
gboolean mon_refresh_state(gpointer user_data);
int cib_connect(gboolean full);
void set_pcmk_health(int healthy);
void notify_parent(void);

int reconnect_msec = 5000;
GMainLoop *mainloop = NULL;
guint timer_id_reconnect = 0;
guint timer_id_notify = 0;

int	pcmk_healthy = 0;

cib_t *cib = NULL;
xmlNode *current_cib = NULL;

long last_refresh = 0;
crm_trigger_t *refresh_trigger = NULL;

static gboolean
mon_timer_popped(gpointer data)
{
	int rc = cib_ok;

	if (timer_id_reconnect > 0) {
		g_source_remove(timer_id_reconnect);
	}

	rc = cib_connect(TRUE);

	if (rc != cib_ok) {
		timer_id_reconnect = g_timeout_add(reconnect_msec, mon_timer_popped, NULL);
		set_pcmk_health(0);
	}
	return FALSE;
}

static void
mon_cib_connection_destroy(gpointer user_data)
{
	if (cib) {
		set_pcmk_health(0);
		/* Reconnecting */
		cib->cmds->signoff(cib);
		timer_id_reconnect = g_timeout_add(reconnect_msec, mon_timer_popped, NULL);
	}
	return;
}

static gboolean
mon_timer_notify(gpointer data)
{
	if (timer_id_notify > 0) {
		g_source_remove(timer_id_notify);
	}

	notify_parent();
	
	timer_id_notify = g_timeout_add(timeout_loop, mon_timer_notify, NULL);
	return FALSE;
}

/*
 * Mainloop signal handler.
 */
static void
mon_shutdown(int nsig)
{
	clean_up(0);
}

int
cib_connect(gboolean full)
{
	int rc = cib_ok;

	CRM_CHECK(cib != NULL, return cib_missing);

	if (cib->state != cib_connected_query && cib->state != cib_connected_command) {

		rc = cib->cmds->signon(cib, crm_system_name, cib_query);

		if (rc != cib_ok) {
			return rc;
		}

		current_cib = get_cib_copy(cib);
		mon_refresh_state(NULL);

		if (full) {
			if (rc == cib_ok) {
				rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
				if (rc == cib_NOTSUPPORTED) {
					/* Notification setup failed, won't be able to reconnect after failure */
					rc = cib_ok;
				}
			}

			if (rc == cib_ok) {
				cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
				rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
			}

			if (rc != cib_ok) {
				/* Notification setup failed, could not monitor CIB actions */
				clean_up(-rc);
			}
		}
	}
	return rc;
}

int
servant_pcmk(const char *diskname, const void* argp)
{
	int exit_code = 0;

	cl_log(LOG_INFO, "Monitoring Pacemaker health");
	set_proc_title("sbd: watcher: Pacemaker");
	reconnect_msec = 2000;

	/* We don't want any noisy crm messages */
	set_crm_log_level(LOG_ERR);
	
	if (current_cib == NULL) {
		cib = cib_new();

		do {
			exit_code = cib_connect(TRUE);

			if (exit_code != cib_ok) {
				sleep(reconnect_msec / 1000);
			}

		} while (exit_code == cib_connection);

		if (exit_code != cib_ok) {
			clean_up(-exit_code);
		}
	}

	mainloop = g_main_new(FALSE);

	mainloop_add_signal(SIGTERM, mon_shutdown);
	mainloop_add_signal(SIGINT, mon_shutdown);
	refresh_trigger = mainloop_add_trigger(G_PRIORITY_LOW, mon_refresh_state, NULL);
	timer_id_notify = g_timeout_add(timeout_loop, mon_timer_notify, NULL);

	g_main_run(mainloop);
	g_main_destroy(mainloop);

	clean_up(0);
	return 0;                   /* never reached */
}

#define LOGONCE(state, lvl, fmt, args...) do {	\
	if (last_state != state) {		\
		cl_log(lvl, fmt, ##args);	\
		last_state = state;		\
	}					\
	} while(0)

static int
compute_status(pe_working_set_t * data_set)
{
	static int	updates = 0;
	static int	last_state = 0;
	int		healthy = 0;
	node_t *dc		= NULL;

	updates++;
	dc = data_set->dc_node;

	if (dc == NULL) {
		/* Means we don't know if we have quorum. Hrm. Probably needs to
		* allow for this state for a period of time and then decide
		* that we don't have quorum - TODO - should we skip
		* notifying the parent? */
		LOGONCE(1, LOG_INFO, "We don't have a DC right now.");
		goto out;
	} else {
		const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);

		if (crm_is_true(quorum)) {
			DBGLOG(LOG_INFO, "We have quorum!");
		} else {
			LOGONCE(3, LOG_WARNING, "We do NOT have quorum!");
			goto out;
		}
	}

	node_t *node = pe_find_node(data_set->nodes, local_uname);

	if (node->details->unclean) {
		LOGONCE(4, LOG_WARNING, "Node state: UNCLEAN");
		goto out;
	} else if (node->details->pending) {
		LOGONCE(5, LOG_WARNING, "Node state: pending");
		/* TODO ? */
	} else if (node->details->online) {
		LOGONCE(6, LOG_INFO, "Node state: online");
		healthy = 1;
	} else {
		LOGONCE(7, LOG_WARNING, "Node state: UNKNOWN");
		goto out;
	}

out:
	set_pcmk_health(healthy);

	return 0;
}

void
set_pcmk_health(int healthy)
{
	pcmk_healthy = healthy;
	notify_parent();
}

void
notify_parent(void)
{
	pid_t		ppid;
	union sigval	signal_value;

	memset(&signal_value, 0, sizeof(signal_value));
	ppid = getppid();

	if (ppid == 1) {
		/* Our parent died unexpectedly. Triggering
		* self-fence. */
		cl_log(LOG_WARNING, "Our parent is dead.");
		do_reset();
	}

	if (pcmk_healthy) {
		DBGLOG(LOG_INFO, "Notifying parent: healthy");
		sigqueue(ppid, SIG_LIVENESS, signal_value);
	} else {
		DBGLOG(LOG_WARNING, "Notifying parent: UNHEALTHY");
		sigqueue(ppid, SIG_PCMK_UNHEALTHY, signal_value);
	}
}

void
crm_diff_update(const char *event, xmlNode * msg)
{
	int rc = -1;
	long now = time(NULL);
	const char *op = NULL;
	unsigned int log_level = LOG_INFO;

	xmlNode *diff = NULL;
	xmlNode *cib_last = NULL;

	if (msg == NULL) {
		crm_err("NULL update");
		return;
	}

	crm_element_value_int(msg, F_CIB_RC, &rc);
	op = crm_element_value(msg, F_CIB_OPERATION);
	diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

	if (rc < cib_ok) {
		log_level = LOG_WARNING;
		cl_log(log_level, "[%s] %s ABORTED: %s", event, op, cib_error2string(rc));
		return;
	}

	if (current_cib != NULL) {
		cib_last = current_cib;
		current_cib = NULL;
		rc = cib_process_diff(op, cib_force_diff, NULL, NULL, diff, cib_last, &current_cib, NULL);

		if (rc != cib_ok) {
			crm_debug("Update didn't apply, requesting full copy: %s", cib_error2string(rc));
			free_xml(current_cib);
			current_cib = NULL;
		}
	}

	if (current_cib == NULL) {
		current_cib = get_cib_copy(cib);
	}

	if ((now - last_refresh) > (reconnect_msec / 1000)) {
		/* Force a refresh */
		mon_refresh_state(NULL);
	} else {
		mainloop_set_trigger(refresh_trigger);
	}
	free_xml(cib_last);
}

gboolean
mon_refresh_state(gpointer user_data)
{
	xmlNode *cib_copy = copy_xml(current_cib);
	pe_working_set_t data_set;

	last_refresh = time(NULL);

	if (cli_config_update(&cib_copy, NULL, FALSE) == FALSE) {
		if (cib) {
			cib->cmds->signoff(cib);
		}
		/* TODO: Not good path, upgrade failed */
		clean_up(1);
		return FALSE;
	}

	set_working_set_defaults(&data_set);
	data_set.input = cib_copy;
	cluster_status(&data_set);

	compute_status(&data_set);

	cleanup_calculations(&data_set);
	return TRUE;
}

void
clean_up(int rc)
{
	if (cib != NULL) {
		cib->cmds->signoff(cib);
		cib_delete(cib);
		cib = NULL;
	}

	if (rc >= 0) {
		exit(rc);
	}
	return;
}
