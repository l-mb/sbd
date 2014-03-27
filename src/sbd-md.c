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

struct servants_list_item *servants_leader = NULL;

static int	servant_count	= 0;
static int	servant_restart_interval = 5;
static int	servant_restart_count = 1;
static int	servant_inform_parent = 0;
static int	check_pcmk = 0;
static int	start_mode = 0;
static char*	pidfile = NULL;

static void open_any_device(void);
static int check_timeout_inconsistent(struct sector_header_s *hdr);

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

int assign_servant(const char* devname, functionp_t functionp, const void* argp)
{
	pid_t pid = 0;
	int rc = 0;

	pid = fork();
	if (pid == 0) {		/* child */
		maximize_priority();
		rc = (*functionp)(devname, argp);
		if (rc == -1)
			exit(1);
		else
			exit(0);
	} else if (pid != -1) {		/* parent */
		return pid;
	} else {
		cl_log(LOG_ERR,"Failed to fork servant");
		exit(1);
	}
}

int init_devices()
{
	int rc = 0;
	struct sbd_context *st;
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
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

int slot_msg_wrapper(const char* devname, const void* argp)
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

int slot_ping_wrapper(const char* devname, const void* argp)
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

int allocate_slots(const char *name)
{
	int rc = 0;
	struct sbd_context *st;
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
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

int list_slots()
{
	int rc = 0;
	struct servants_list_item *s;
	struct sbd_context *st;

	for (s = servants_leader; s; s = s->next) {
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

int ping_via_slots(const char *name)
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

	for (s = servants_leader; s; s = s->next) {
		s->pid = assign_servant(s->devname, &slot_ping_wrapper, (const void*)name);
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

int servant(const char *diskname, const void* argp)
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

	if (check_timeout_inconsistent(s_header) < 0) {
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
		if (start_mode > 0) {
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

void recruit_servant(const char *devname, pid_t pid)
{
	struct servants_list_item *s = servants_leader;
	struct servants_list_item *newbie;

	newbie = malloc(sizeof(*newbie));
	if (!newbie) {
		fprintf(stderr, "malloc failed in recruit_servant.\n");
		exit(1);
	}
	memset(newbie, 0, sizeof(*newbie));
	newbie->devname = strdup(devname);
	newbie->pid = pid;
	newbie->first_start = 1;

	if (!s) {
		servants_leader = newbie;
	} else {
		while (s->next)
			s = s->next;
		s->next = newbie;
	}

	servant_count++;
}

struct servants_list_item *lookup_servant_by_dev(const char *devname)
{
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		if (strncasecmp(s->devname, devname, strlen(s->devname)))
			break;
	}
	return s;
}

struct servants_list_item *lookup_servant_by_pid(pid_t pid)
{
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid == pid)
			break;
	}
	return s;
}

int check_all_dead(void)
{
	struct servants_list_item *s;
	int r = 0;
	union sigval svalue;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if (r == -1 && errno == ESRCH)
				continue;
			return 0;
		}
	}
	return 1;
}


void servant_start(struct servants_list_item *s)
{
	int r = 0;
	union sigval svalue;

	if (s->pid != 0) {
		r = sigqueue(s->pid, 0, svalue);
		if ((r != -1 || errno != ESRCH))
			return;
	}
	s->restarts++;
	if (strcmp("pcmk",s->devname) == 0) {
		DBGLOG(LOG_INFO, "Starting Pacemaker servant");
		s->pid = assign_servant(s->devname, servant_pcmk, NULL);
	} else {
		DBGLOG(LOG_INFO, "Starting servant for device %s",
				s->devname);
		s->pid = assign_servant(s->devname, servant, s);
	}

	clock_gettime(CLOCK_MONOTONIC, &s->t_started);
	return;
}

void servants_start(void)
{
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		s->restarts = 0;
		servant_start(s);
	}
}

void servants_kill(void)
{
	struct servants_list_item *s;
	union sigval svalue;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid != 0)
			sigqueue(s->pid, SIGKILL, svalue);
	}
}

void open_any_device(void)
{
	struct sector_header_s *hdr_cur = NULL;
	struct timespec t_0;
	int t_wait = 0;

	clock_gettime(CLOCK_MONOTONIC, &t_0);

	while (!hdr_cur && t_wait < timeout_startup) {
		struct timespec t_now;
		struct servants_list_item* s;

		for (s = servants_leader; s; s = s->next) {
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

int check_timeout_inconsistent(struct sector_header_s *hdr)
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

inline void cleanup_servant_by_pid(pid_t pid)
{
	struct servants_list_item* s;

	s = lookup_servant_by_pid(pid);
	if (s) {
		cl_log(LOG_WARNING, "Servant for %s (pid: %i) has terminated",
				s->devname, s->pid);
		s->pid = 0;
	} else {
		/* This most likely is a stray signal from somewhere, or
		 * a SIGCHLD for a process that has previously
		 * explicitly disconnected. */
		DBGLOG(LOG_INFO, "cleanup_servant: Nothing known about pid %i",
				pid);
	}
}

int inquisitor_decouple(void)
{
	pid_t ppid = getppid();
	union sigval signal_value;

	/* During start-up, we only arm the watchdog once we've got
	 * quorum at least once. */
	if (watchdog_use) {
		if (watchdog_init() < 0) {
			return -1;
		}
	}

	if (ppid > 1) {
		sigqueue(ppid, SIG_LIVENESS, signal_value);
	}
	return 0;
}

void inquisitor_child(void)
{
	int sig, pid;
	sigset_t procmask;
	siginfo_t sinfo;
	int status;
	struct timespec timeout;
	int exiting = 0;
	int decoupled = 0;
	int pcmk_healthy = 0;
	int pcmk_override = 0;
	time_t latency;
	struct timespec t_last_tickle, t_now;
	struct servants_list_item* s;

	if (debug_mode) {
		cl_log(LOG_ERR, "DEBUG MODE IS ACTIVE - DO NOT RUN IN PRODUCTION!");
	}

	set_proc_title("sbd: inquisitor");

	if (pidfile) {
		if (cl_lock_pidfile(pidfile) < 0) {
			exit(1);
		}
	}

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigaddset(&procmask, SIG_LIVENESS);
	sigaddset(&procmask, SIG_EXITREQ);
	sigaddset(&procmask, SIG_TEST);
	sigaddset(&procmask, SIG_IO_FAIL);
	sigaddset(&procmask, SIG_PCMK_UNHEALTHY);
	sigaddset(&procmask, SIG_RESTART);
	sigaddset(&procmask, SIGUSR1);
	sigaddset(&procmask, SIGUSR2);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	/* We only want this to have an effect during watch right now;
	 * pinging and fencing would be too confused */
	if (check_pcmk) {
		recruit_servant("pcmk", 0);
		servant_count--;
	}

	servants_start();

	timeout.tv_sec = timeout_loop;
	timeout.tv_nsec = 0;
	clock_gettime(CLOCK_MONOTONIC, &t_last_tickle);

	while (1) {
		int good_servants = 0;

		sig = sigtimedwait(&procmask, &sinfo, &timeout);

		clock_gettime(CLOCK_MONOTONIC, &t_now);

		if (sig == SIG_EXITREQ) {
			servants_kill();
			watchdog_close();
			exiting = 1;
		} else if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					cleanup_servant_by_pid(pid);
				}
			}
		} else if (sig == SIG_PCMK_UNHEALTHY) {
			s = lookup_servant_by_pid(sinfo.si_pid);
			if (s && strcmp(s->devname, "pcmk") == 0) {
				if (pcmk_healthy != 0) {
					cl_log(LOG_WARNING, "Pacemaker health check: UNHEALTHY");
				}
				pcmk_healthy = 0;
				clock_gettime(CLOCK_MONOTONIC, &s->t_last);
			} else {
				cl_log(LOG_WARNING, "Ignoring SIG_PCMK_UNHEALTHY from unknown source");
			}
		} else if (sig == SIG_IO_FAIL) {
			s = lookup_servant_by_pid(sinfo.si_pid);
			if (s) {
				DBGLOG(LOG_INFO, "Servant for %s requests to be disowned",
						s->devname);
				cleanup_servant_by_pid(sinfo.si_pid);
			}
		} else if (sig == SIG_LIVENESS) {
			s = lookup_servant_by_pid(sinfo.si_pid);
			if (s) {
				if (strcmp(s->devname, "pcmk") == 0) {
					if (pcmk_healthy != 1) {
						cl_log(LOG_INFO, "Pacemaker health check: OK");
					}
					pcmk_healthy = 1;
				};
				s->first_start = 0;
				clock_gettime(CLOCK_MONOTONIC, &s->t_last);
			}
		} else if (sig == SIG_TEST) {
		} else if (sig == SIGUSR1) {
			if (exiting)
				continue;
			servants_start();
		}

		if (exiting) {
			if (check_all_dead()) {
				if (pidfile) {
					cl_unlock_pidfile(pidfile);
				}
				exit(0);
			} else
				continue;
		}

		good_servants = 0;
		for (s = servants_leader; s; s = s->next) {
			int age = t_now.tv_sec - s->t_last.tv_sec;

			if (!s->t_last.tv_sec)
				continue;
			
			if (age < (int)(timeout_io+timeout_loop)) {
				if (strcmp(s->devname, "pcmk") != 0) {
					good_servants++;
				}
				s->outdated = 0;
			} else if (!s->outdated) {
				if (strcmp(s->devname, "pcmk") == 0) {
					/* If the state is outdated, we
					 * override the last reported
					 * state */
					pcmk_healthy = 0;
					cl_log(LOG_WARNING, "Pacemaker state outdated (age: %d)",
						age);
				} else if (!s->restart_blocked) {
					cl_log(LOG_WARNING, "Servant for %s outdated (age: %d)",
						s->devname, age);
				}
				s->outdated = 1;
			}
		}

		if (quorum_read(good_servants) || pcmk_healthy) {
			if (!decoupled) {
				if (inquisitor_decouple() < 0) {
					servants_kill();
					exiting = 1;
					continue;
				} else {
					decoupled = 1;
				}
			}

			if (!quorum_read(good_servants)) {
				if (!pcmk_override) {
					cl_log(LOG_WARNING, "Majority of devices lost - surviving on pacemaker");
					pcmk_override = 1; /* Just to ensure the message is only logged once */
				}
			} else {
				pcmk_override = 0;
			}

			watchdog_tickle();
			clock_gettime(CLOCK_MONOTONIC, &t_last_tickle);
		}
		
		/* Note that this can actually be negative, since we set
		 * last_tickle after we set now. */
		latency = t_now.tv_sec - t_last_tickle.tv_sec;
		if (timeout_watchdog && (latency > (int)timeout_watchdog)) {
			if (!decoupled) {
				/* We're still being watched by our
				 * parent. We don't fence, but exit. */
				cl_log(LOG_ERR, "SBD: Not enough votes to proceed. Aborting start-up.");
				servants_kill();
				exiting = 1;
				continue;
			}
			if (debug_mode < 2) {
				/* At level 2 or above, we do nothing, but expect
				 * things to eventually return to
				 * normal. */
				do_reset();
			} else {
				cl_log(LOG_ERR, "SBD: DEBUG MODE: Would have fenced due to timeout!");
			}
		}
		if (timeout_watchdog_warn && (latency > (int)timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: No liveness for %d s exceeds threshold of %d s (healthy servants: %d)",
			       (int)latency, (int)timeout_watchdog_warn, good_servants);
		}
		
		for (s = servants_leader; s; s = s->next) {
			int age = t_now.tv_sec - s->t_started.tv_sec;

			if (age > servant_restart_interval) {
				s->restarts = 0;
				s->restart_blocked = 0;
			}

			if (servant_restart_count
					&& (s->restarts >= servant_restart_count)
					&& !s->restart_blocked) {
				if (servant_restart_count > 1) {
					cl_log(LOG_WARNING, "Max retry count (%d) reached: not restarting servant for %s",
							(int)servant_restart_count, s->devname);
				}
				s->restart_blocked = 1;
			}

			if (!s->restart_blocked) {
				servant_start(s);
			}
		}
	}
	/* not reached */
	exit(0);
}

int inquisitor(void)
{
	int sig, pid, inquisitor_pid;
	int status;
	sigset_t procmask;
	siginfo_t sinfo;

	/* Where's the best place for sysrq init ?*/
	sysrq_init();

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigaddset(&procmask, SIG_LIVENESS);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	open_any_device();

	inquisitor_pid = make_daemon();
	if (inquisitor_pid == 0) {
		inquisitor_child();
	} 
	
	/* We're the parent. Wait for a happy signal from our child
	 * before we proceed - we either get "SIG_LIVENESS" when the
	 * inquisitor has completed the first successful round, or
	 * ECHLD when it exits with an error. */

	while (1) {
		sig = sigwaitinfo(&procmask, &sinfo);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				}
				/* We got here because the inquisitor
				 * did not succeed. */
				return -1;
			}
		} else if (sig == SIG_LIVENESS) {
			/* Inquisitor started up properly. */
			return 0;
		} else {
			fprintf(stderr, "Nobody expected the spanish inquisition!\n");
			continue;
		}
	}
	/* not reached */
	return -1;
}

int messenger(const char *name, const char *msg)
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

	for (s = servants_leader; s; s = s->next) {
		s->pid = assign_servant(s->devname, &slot_msg_wrapper, &slot_msg_arg);
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

int dump_headers(void)
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	struct sbd_context *st;

	for (s = servants_leader; s; s = s->next) {
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

int main(int argc, char **argv, char **envp)
{
	int exit_status = 0;
	int c;
	int w = 0;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	} else {
		++cmdname;
	}

	cl_log_set_entity(cmdname);
	cl_log_enable_stderr(0);
	cl_log_set_facility(LOG_DAEMON);

	sbd_get_uname();

	while ((c = getopt(argc, argv, "C:DPRTWZhvw:d:n:p:1:2:3:4:5:t:I:F:S:s:")) != -1) {
		switch (c) {
		case 'D':
			break;
		case 'Z':
			debug_mode++;
			cl_log(LOG_INFO, "Debug mode now at level %d", (int)debug_mode);
			break;
		case 'R':
			skip_rt = 1;
			cl_log(LOG_INFO, "Realtime mode deactivated.");
			break;
		case 'S':
			start_mode = atoi(optarg);
			cl_log(LOG_INFO, "Start mode set to: %d", (int)start_mode);
			break;
		case 's':
			timeout_startup = atoi(optarg);
			cl_log(LOG_INFO, "Start timeout set to: %d", (int)timeout_startup);
			break;
		case 'v':
			debug = 1;
			cl_log(LOG_INFO, "Verbose mode enabled.");
			break;
		case 'T':
			watchdog_set_timeout = 0;
			cl_log(LOG_INFO, "Setting watchdog timeout disabled; using defaults.");
			break;
		case 'W':
			w++;
			break;
		case 'w':
			watchdogdev = strdup(optarg);
			break;
		case 'd':
			recruit_servant(optarg, 0);
			break;
		case 'P':
			check_pcmk = 1;
			break;
		case 'n':
			local_uname = strdup(optarg);
			cl_log(LOG_INFO, "Overriding local hostname to %s", local_uname);
			break;
		case 'p':
			pidfile = strdup(optarg);
			cl_log(LOG_INFO, "pidfile set to %s", pidfile);
			break;
		case 'C':
			timeout_watchdog_crashdump = atoi(optarg);
			cl_log(LOG_INFO, "Setting crashdump watchdog timeout to %d",
					(int)timeout_watchdog_crashdump);
			break;
		case '1':
			timeout_watchdog = atoi(optarg);
			break;
		case '2':
			timeout_allocate = atoi(optarg);
			break;
		case '3':
			timeout_loop = atoi(optarg);
			break;
		case '4':
			timeout_msgwait = atoi(optarg);
			break;
		case '5':
			timeout_watchdog_warn = atoi(optarg);
			cl_log(LOG_INFO, "Setting latency warning to %d",
					(int)timeout_watchdog_warn);
			break;
		case 't':
			servant_restart_interval = atoi(optarg);
			cl_log(LOG_INFO, "Setting servant restart interval to %d",
					(int)servant_restart_interval);
			break;
		case 'I':
			timeout_io = atoi(optarg);
			cl_log(LOG_INFO, "Setting IO timeout to %d",
					(int)timeout_io);
			break;
		case 'F':
			servant_restart_count = atoi(optarg);
			cl_log(LOG_INFO, "Servant restart count set to %d",
					(int)servant_restart_count);
			break;
		case 'h':
			usage();
			return (0);
		default:
			exit_status = -2;
			goto out;
			break;
		}
	}

	if (w > 0) {
		watchdog_use = w % 2;
	}

	if (watchdog_use) {
		cl_log(LOG_INFO, "Watchdog enabled.");
	} else {
		cl_log(LOG_INFO, "Watchdog disabled.");
	}

	if (servant_count < 1 || servant_count > 3) {
		fprintf(stderr, "You must specify 1 to 3 devices via the -d option.\n");
		exit_status = -1;
		goto out;
	}

	/* There must at least be one command following the options: */
	if ((argc - optind) < 1) {
		fprintf(stderr, "Not enough arguments.\n");
		exit_status = -2;
		goto out;
	}

	if (init_set_proc_title(argc, argv, envp) < 0) {
		fprintf(stderr, "Allocation of proc title failed.\n");
		exit_status = -1;
		goto out;
	}

	maximize_priority();

	if (strcmp(argv[optind], "create") == 0) {
		exit_status = init_devices();
	} else if (strcmp(argv[optind], "dump") == 0) {
		exit_status = dump_headers();
	} else if (strcmp(argv[optind], "allocate") == 0) {
		exit_status = allocate_slots(argv[optind + 1]);
	} else if (strcmp(argv[optind], "list") == 0) {
		exit_status = list_slots();
	} else if (strcmp(argv[optind], "message") == 0) {
		exit_status = messenger(argv[optind + 1], argv[optind + 2]);
	} else if (strcmp(argv[optind], "ping") == 0) {
		exit_status = ping_via_slots(argv[optind + 1]);
	} else if (strcmp(argv[optind], "watch") == 0) {
		exit_status = inquisitor();
	} else {
		exit_status = -2;
	}

out:
	if (exit_status < 0) {
		if (exit_status == -2) {
			usage();
		} else {
			fprintf(stderr, "sbd failed; please check the logs.\n");
		}
		return (1);
	}
	return (0);
}
