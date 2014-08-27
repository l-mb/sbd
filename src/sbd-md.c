/*
 * Copyright (C) 2013 Lars Marowsky-Bree <lmb@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sbd.h"

extern int servant_count;
static int servant_inform_parent = 0;

int init_devices(struct servants_list_item *servants)
{
	int rc = 0;
	struct sbd_context *st;
	struct servants_list_item *s;

	for (s = servants; s; s = s->next) {
		fprintf(stdout, "Initializing device %s\n",
				s->devname);
		st = open_device(s->devname, LOG_ERR);
		if (!st) {
			return -1;
		}
		rc = init_device(st);
		close_device(st);
		if (rc == -1) {
			fprintf(stderr, "Failed to init device %s\n", s->devname);
			return rc;
		}
		fprintf(stdout, "Device %s is initialized.\n", s->devname);
	}
	return 0;
}

static int slot_msg_wrapper(const char* devname, int mode, const void* argp)
{
	int rc = 0;
	struct sbd_context *st;
	const struct slot_msg_arg_t* arg = (const struct slot_msg_arg_t*)argp;

        st = open_device(devname, LOG_WARNING);
        if (!st) 
		return -1;
	cl_log(LOG_INFO, "Delivery process handling %s",
			devname);
	rc = slot_msg(st, arg->name, arg->msg);
	close_device(st);
	return rc;
}

static int slot_ping_wrapper(const char* devname, int mode, const void* argp)
{
	int rc = 0;
	const char* name = (const char*)argp;
	struct sbd_context *st;

	st = open_device(devname, LOG_WARNING);
	if (!st)
		return -1;
	rc = slot_ping(st, name);
	close_device(st);
	return rc;
}

int allocate_slots(const char *name, struct servants_list_item *servants)
{
	int rc = 0;
	struct sbd_context *st;
	struct servants_list_item *s;

	for (s = servants; s; s = s->next) {
		fprintf(stdout, "Trying to allocate slot for %s on device %s.\n", 
				name,
				s->devname);
		st = open_device(s->devname, LOG_WARNING);
		if (!st) {
			return -1;
		}
		rc = slot_allocate(st, name);
		close_device(st);
		if (rc < 0)
			return rc;
		fprintf(stdout, "Slot for %s has been allocated on %s.\n",
				name,
				s->devname);
	}
	return 0;
}

int list_slots(struct servants_list_item *servants)
{
	int rc = 0;
	struct servants_list_item *s;
	struct sbd_context *st;

	for (s = servants; s; s = s->next) {
		st = open_device(s->devname, LOG_WARNING);
		if (!st) {
			fprintf(stdout, "== disk %s unreadable!\n", s->devname);
			continue;
		}
		rc = slot_list(st);
		close_device(st);
		if (rc == -1) {
			fprintf(stdout, "== Slots on disk %s NOT dumped\n", s->devname);
		}
	}
	return 0;
}

int ping_via_slots(const char *name, struct servants_list_item *servants)
{
	int sig = 0;
	pid_t pid = 0;
	int status = 0;
	int servants_finished = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s;

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	for (s = servants; s; s = s->next) {
            s->pid = assign_servant(s->devname, &slot_ping_wrapper, 0, (const void*)name);
	}

	while (servants_finished < servant_count) {
		sig = sigwaitinfo(&procmask, &sinfo);
		if (sig == SIGCHLD) {
			while ((pid = wait(&status))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					s = lookup_servant_by_pid(pid);
					if (s) {
						servants_finished++;
					}
				}
			}
		}
	}
	return 0;
}

int quorum_write(int good_servants)
{
	return (good_servants > servant_count/2);	
}

int quorum_read(int good_servants)
{
	if (servant_count >= 3) 
		return (good_servants > servant_count/2);
	else
		return (good_servants >= 1);
}

int messenger(const char *name, const char *msg, struct servants_list_item *servants)
{
	int sig = 0;
	pid_t pid = 0;
	int status = 0;
	int servants_finished = 0;
	int successful_delivery = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s;
	struct slot_msg_arg_t slot_msg_arg = {name, msg};

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	for (s = servants; s; s = s->next) {
            s->pid = assign_servant(s->devname, &slot_msg_wrapper, 0, &slot_msg_arg);
	}
	
	while (!(quorum_write(successful_delivery) || 
		(servants_finished == servant_count))) {
		sig = sigwaitinfo(&procmask, &sinfo);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					servants_finished++;
					if (WIFEXITED(status)
						&& WEXITSTATUS(status) == 0) {
						DBGLOG(LOG_INFO, "Process %d succeeded.",
								(int)pid);
						successful_delivery++;
					} else {
						cl_log(LOG_WARNING, "Process %d failed to deliver!",
								(int)pid);
					}
				}
			}
		}
	}
	if (quorum_write(successful_delivery)) {
		cl_log(LOG_INFO, "Message successfully delivered.");
		return 0;
	} else {
		cl_log(LOG_ERR, "Message is not delivered via more then a half of devices");
		return -1;
	}
}

int dump_headers(struct servants_list_item *servants)
{
	int rc = 0;
	struct servants_list_item *s = servants;
	struct sbd_context *st;

	for (s = servants; s; s = s->next) {
		fprintf(stdout, "==Dumping header on disk %s\n", s->devname);
		st = open_device(s->devname, LOG_WARNING);
		if (!st) {
			fprintf(stdout, "== disk %s unreadable!\n", s->devname);
			continue;
		}

		rc = header_dump(st);
		close_device(st);

		if (rc == -1) {
			fprintf(stdout, "==Header on disk %s NOT dumped\n", s->devname);
		} else {
			fprintf(stdout, "==Header on disk %s is dumped\n", s->devname);
		}
	}
	return rc;
}

void open_any_device(struct servants_list_item *servants)
{
	struct sector_header_s *hdr_cur = NULL;
	struct timespec t_0;
	int t_wait = 0;

	clock_gettime(CLOCK_MONOTONIC, &t_0);

	while (!hdr_cur && t_wait < timeout_startup) {
		struct timespec t_now;
		struct servants_list_item* s;

		for (s = servants; s; s = s->next) {
			struct sbd_context *st = open_device(s->devname, LOG_DEBUG);
			if (!st)
				continue;
			hdr_cur = header_get(st);
			close_device(st);
			if (hdr_cur)
				break;
		}
		clock_gettime(CLOCK_MONOTONIC, &t_now);
		t_wait = t_now.tv_sec - t_0.tv_sec;
		if (!hdr_cur) {
			sleep(timeout_loop);
		}
	}

	if (hdr_cur) {
		timeout_watchdog = hdr_cur->timeout_watchdog;
		timeout_allocate = hdr_cur->timeout_allocate;
		timeout_loop = hdr_cur->timeout_loop;
		timeout_msgwait = hdr_cur->timeout_msgwait;
	} else { 
		cl_log(LOG_ERR, "No devices were available at start-up within %i seconds.",
				timeout_startup);
		exit(1);
	}

	free(hdr_cur);
	return;
}

/*
 ::-::-::-::-::-::-::-::-::-::-::-::-::
   Begin disk based servant code
 ::-::-::-::-::-::-::-::-::-::-::-::-::
*/

static int servant_check_timeout_inconsistent(struct sector_header_s *hdr)
{
	if (timeout_watchdog != hdr->timeout_watchdog) {
		cl_log(LOG_WARNING, "watchdog timeout: %d versus %d on this device",
				(int)timeout_watchdog, (int)hdr->timeout_watchdog);
		return -1;
	}
	if (timeout_allocate != hdr->timeout_allocate) {
		cl_log(LOG_WARNING, "allocate timeout: %d versus %d on this device",
				(int)timeout_allocate, (int)hdr->timeout_allocate);
		return -1;
	}
	if (timeout_loop != hdr->timeout_loop) {
		cl_log(LOG_WARNING, "loop timeout: %d versus %d on this device",
				(int)timeout_loop, (int)hdr->timeout_loop);
		return -1;
	}
	if (timeout_msgwait != hdr->timeout_msgwait) {
		cl_log(LOG_WARNING, "msgwait timeout: %d versus %d on this device",
				(int)timeout_msgwait, (int)hdr->timeout_msgwait);
		return -1;
	}
	return 0;
}

/* This is a bit hackish, but the easiest way to rewire all process
 * exits to send the desired signal to the parent. */
void servant_exit(void)
{
	pid_t ppid;
	union sigval signal_value;

	ppid = getppid();
	if (servant_inform_parent) {
		memset(&signal_value, 0, sizeof(signal_value));
		sigqueue(ppid, SIG_IO_FAIL, signal_value);
	}
}

int servant(const char *diskname, int mode, const void* argp)
{
	struct sector_mbox_s *s_mbox = NULL;
	struct sector_node_s *s_node = NULL;
	struct sector_header_s	*s_header = NULL;
	int mbox;
	int rc = 0;
	time_t t0, t1, latency;
	union sigval signal_value;
	sigset_t servant_masks;
	struct sbd_context *st;
	pid_t ppid;
	char uuid[37];
	const struct servants_list_item *s = argp;

	if (!diskname) {
		cl_log(LOG_ERR, "Empty disk name %s.", diskname);
		return -1;
	}

	cl_log(LOG_INFO, "Servant starting for device %s", diskname);

	/* Block most of the signals */
	sigfillset(&servant_masks);
	sigdelset(&servant_masks, SIGKILL);
	sigdelset(&servant_masks, SIGFPE);
	sigdelset(&servant_masks, SIGILL);
	sigdelset(&servant_masks, SIGSEGV);
	sigdelset(&servant_masks, SIGBUS);
	sigdelset(&servant_masks, SIGALRM);
	/* FIXME: check error */
	sigprocmask(SIG_SETMASK, &servant_masks, NULL);

	atexit(servant_exit);
	servant_inform_parent = 1;

	st = open_device(diskname, LOG_WARNING);
	if (!st) {
		return -1;
	}

	s_header = header_get(st);
	if (!s_header) {
		cl_log(LOG_ERR, "Not a valid header on %s", diskname);
		return -1;
	}

	if (servant_check_timeout_inconsistent(s_header) < 0) {
		cl_log(LOG_ERR, "Timeouts on %s do not match first device",
				diskname);
		return -1;
	}

	if (s_header->minor_version > 0) {
		uuid_unparse_lower(s_header->uuid, uuid);
		cl_log(LOG_INFO, "Device %s uuid: %s", diskname, uuid);
	}

	mbox = slot_allocate(st, local_uname);
	if (mbox < 0) {
		cl_log(LOG_ERR,
		       "No slot allocated, and automatic allocation failed for disk %s.",
		       diskname);
		rc = -1;
		goto out;
	}
	s_node = sector_alloc();
	if (slot_read(st, mbox, s_node) < 0) {
		cl_log(LOG_ERR, "Unable to read node entry on %s",
				diskname);
		exit(1);
	}

	DBGLOG(LOG_INFO, "Monitoring slot %d on disk %s", mbox, diskname);
	if (s_header->minor_version == 0) {
		set_proc_title("sbd: watcher: %s - slot: %d", diskname, mbox);
	} else {
		set_proc_title("sbd: watcher: %s - slot: %d - uuid: %s",
				diskname, mbox, uuid);
	}

	s_mbox = sector_alloc();
	if (s->first_start) {
		if (mode > 0) {
			if (mbox_read(st, mbox, s_mbox) < 0) {
				cl_log(LOG_ERR, "mbox read failed during start-up in servant.");
				rc = -1;
				goto out;
			}
			if (s_mbox->cmd != SBD_MSG_EXIT &&
					s_mbox->cmd != SBD_MSG_EMPTY) {
				/* Not a clean stop. Abort start-up */
				cl_log(LOG_WARNING, "Found fencing message - aborting start-up. Manual intervention required!");
				ppid = getppid();
				sigqueue(ppid, SIG_EXITREQ, signal_value);
				rc = 0;
				goto out;
			}
		}
		DBGLOG(LOG_INFO, "First servant start - zeroing inbox");
		memset(s_mbox, 0, sizeof(*s_mbox));
		if (mbox_write(st, mbox, s_mbox) < 0) {
			rc = -1;
			goto out;
		}
	}

	memset(&signal_value, 0, sizeof(signal_value));

	while (1) {
		struct sector_header_s	*s_header_retry = NULL;
		struct sector_node_s	*s_node_retry = NULL;

		t0 = time(NULL);
		sleep(timeout_loop);

		ppid = getppid();

		if (ppid == 1) {
			/* Our parent died unexpectedly. Triggering
			 * self-fence. */
			do_reset();
		}

		/* These attempts are, by definition, somewhat racy. If
		 * the device is wiped out or corrupted between here and
		 * us reading our mbox, there is nothing we can do about
		 * that. But at least we tried. */
		s_header_retry = header_get(st);
		if (!s_header_retry) {
			cl_log(LOG_ERR, "No longer found a valid header on %s", diskname);
			exit(1);
		}
		if (memcmp(s_header, s_header_retry, sizeof(*s_header)) != 0) {
			cl_log(LOG_ERR, "Header on %s changed since start-up!", diskname);
			exit(1);
		}
		free(s_header_retry);

		s_node_retry = sector_alloc();
		if (slot_read(st, mbox, s_node_retry) < 0) {
			cl_log(LOG_ERR, "slot read failed in servant.");
			exit(1);
		}
		if (memcmp(s_node, s_node_retry, sizeof(*s_node)) != 0) {
			cl_log(LOG_ERR, "Node entry on %s changed since start-up!", diskname);
			exit(1);
		}
		free(s_node_retry);

		if (mbox_read(st, mbox, s_mbox) < 0) {
			cl_log(LOG_ERR, "mbox read failed in servant.");
			exit(1);
		}

		if (s_mbox->cmd > 0) {
			cl_log(LOG_INFO,
			       "Received command %s from %s on disk %s",
			       char2cmd(s_mbox->cmd), s_mbox->from, diskname);

			switch (s_mbox->cmd) {
			case SBD_MSG_TEST:
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(st, mbox, s_mbox);
				sigqueue(ppid, SIG_TEST, signal_value);
				break;
			case SBD_MSG_RESET:
				do_reset();
				break;
			case SBD_MSG_OFF:
				do_off();
				break;
			case SBD_MSG_EXIT:
				sigqueue(ppid, SIG_EXITREQ, signal_value);
				break;
			case SBD_MSG_CRASHDUMP:
				do_crashdump();
				break;
			default:
				/* FIXME:
				   An "unknown" message might result
				   from a partial write.
				   log it and clear the slot.
				 */
				cl_log(LOG_ERR, "Unknown message on disk %s",
				       diskname);
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(st, mbox, s_mbox);
				break;
			}
		}
		sigqueue(ppid, SIG_LIVENESS, signal_value);

		t1 = time(NULL);
		latency = t1 - t0;
		if (timeout_watchdog_warn && (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: %d exceeded threshold %d on disk %s",
			       (int)latency, (int)timeout_watchdog_warn,
			       diskname);
		} else if (debug) {
			DBGLOG(LOG_INFO, "Latency: %d on disk %s", (int)latency,
			       diskname);
		}
	}
 out:
	free(s_mbox);
	close_device(st);
	if (rc == 0) {
		servant_inform_parent = 0;
	}
	return rc;
}


