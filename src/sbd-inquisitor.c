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
#define	LOCKSTRLEN	11

static struct servants_list_item *servants_leader = NULL;

int	check_pcmk = 0;
int	servant_count	= 0;
int	servant_restart_interval = 5;
int	servant_restart_count = 1;
int	start_mode = 0;
char*	pidfile = NULL;

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

int assign_servant(const char* devname, functionp_t functionp, int mode, const void* argp)
{
	pid_t pid = 0;
	int rc = 0;

	pid = fork();
	if (pid == 0) {		/* child */
		maximize_priority();
		rc = (*functionp)(devname, mode, argp);
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
		s->pid = assign_servant(s->devname, servant_pcmk, start_mode, NULL);
	} else {
#if SUPPORT_SHARED_DISK
		DBGLOG(LOG_INFO, "Starting servant for device %s", s->devname);
		s->pid = assign_servant(s->devname, servant, start_mode, s);
#else
                cl_log(LOG_ERR, "Shared disk functionality not supported");
                return;
#endif
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

static int sbd_lock_running(long pid)
{
	int rc = 0;
	long mypid;
	int running = 0;
	char proc_path[PATH_MAX], exe_path[PATH_MAX], myexe_path[PATH_MAX];

	/* check if pid is running */
	if (kill(pid, 0) < 0 && errno == ESRCH) {
		goto bail;
	}

#ifndef HAVE_PROC_PID
	return 1;
#endif

	/* check to make sure pid hasn't been reused by another process */
	snprintf(proc_path, sizeof(proc_path), "/proc/%lu/exe", pid);
	rc = readlink(proc_path, exe_path, PATH_MAX-1);
	if(rc < 0) {
		cl_perror("Could not read from %s", proc_path);
		goto bail;
	}
	exe_path[rc] = 0;
	mypid = (unsigned long) getpid();
	snprintf(proc_path, sizeof(proc_path), "/proc/%lu/exe", mypid);
	rc = readlink(proc_path, myexe_path, PATH_MAX-1);
	if(rc < 0) {
		cl_perror("Could not read from %s", proc_path);
		goto bail;
	}
	myexe_path[rc] = 0;

	if(strcmp(exe_path, myexe_path) == 0) {
		running = 1;
	}

  bail:
	return running;
}

static int
sbd_lock_pidfile(const char *filename)
{
	char lf_name[256], tf_name[256], buf[LOCKSTRLEN+1];
	int fd;
	long	pid, mypid;
	int rc;
	struct stat sbuf;

	if (filename == NULL) {
		errno = EFAULT;
		return -1;
	}

	mypid = (unsigned long) getpid();
	snprintf(lf_name, sizeof(lf_name), "%s",filename);
	snprintf(tf_name, sizeof(tf_name), "%s.%lu",
		 filename, mypid);

	if ((fd = open(lf_name, O_RDONLY)) >= 0) {
		if (fstat(fd, &sbuf) >= 0 && sbuf.st_size < LOCKSTRLEN) {
			sleep(1); /* if someone was about to create one,
			   	   * give'm a sec to do so
				   * Though if they follow our protocol,
				   * this won't happen.  They should really
				   * put the pid in, then link, not the
				   * other way around.
				   */
		}
		if (read(fd, buf, sizeof(buf)) < 1) {
			/* lockfile empty -> rm it and go on */;
		} else {
			if (sscanf(buf, "%lu", &pid) < 1) {
				/* lockfile screwed up -> rm it and go on */
			} else {
				if (pid > 1 && (getpid() != pid)
				&&	sbd_lock_running(pid)) {
					/* is locked by existing process
					 * -> give up */
					close(fd);
					return -1;
				} else {
					/* stale lockfile -> rm it and go on */
				}
			}
		}
		unlink(lf_name);
		close(fd);
	}
	if ((fd = open(tf_name, O_CREAT | O_WRONLY | O_EXCL, 0644)) < 0) {
		/* Hmmh, why did we fail? Anyway, nothing we can do about it */
		return -3;
	}

	/* Slight overkill with the %*d format ;-) */
	snprintf(buf, sizeof(buf), "%*lu\n", LOCKSTRLEN-1, mypid);

	if (write(fd, buf, LOCKSTRLEN) != LOCKSTRLEN) {
		/* Again, nothing we can do about this */
		rc = -3;
		close(fd);
		goto out;
	}
	close(fd);

	switch (link(tf_name, lf_name)) {
	case 0:
		if (stat(tf_name, &sbuf) < 0) {
			/* something weird happened */
			rc = -3;
			break;
		}
		if (sbuf.st_nlink < 2) {
			/* somehow, it didn't get through - NFS trouble? */
			rc = -2;
			break;
		}
		rc = 0;
		break;
	case EEXIST:
		rc = -1;
		break;
	default:
		rc = -3;
	}
 out:
	unlink(tf_name);
	return rc;
}


/*
 * Unlock a file (remove its lockfile) 
 * do we need to check, if its (still) ours? No, IMHO, if someone else
 * locked our line, it's his fault  -tho
 * returns 0 on success
 * <0 if some failure occured
 */

static int
sbd_unlock_pidfile(const char *filename)
{
	char lf_name[256];

	if (filename == NULL) {
		errno = EFAULT;
		return -1;
	}

	snprintf(lf_name, sizeof(lf_name), "%s", filename);

	return unlink(lf_name);
}

int quorum_read(int good_servants)
{
	if (servant_count >= 3) 
		return (good_servants > servant_count/2);
	else
		return (good_servants >= 1);
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
		if (sbd_lock_pidfile(pidfile) < 0) {
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
			watchdog_close(true);
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
					sbd_unlock_pidfile(pidfile);
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

int main(int argc, char **argv, char **envp)
{
	int exit_status = 0;
	int c;
	int w = 0;
        int qb_facility;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	} else {
		++cmdname;
	}

        qb_facility = qb_log_facility2int("daemon");
        qb_log_init(cmdname, qb_facility, LOG_ERR);

        qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);
        qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_FALSE);

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
#if SUPPORT_SHARED_DISK
			recruit_servant(optarg, 0);
#else
                        fprintf(stderr, "Shared disk functionality not supported\n");
			exit_status = -2;
			goto out;
#endif
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

#if SUPPORT_SHARED_DISK
	if (strcmp(argv[optind], "create") == 0) {
		exit_status = init_devices(servants_leader);
	} else if (strcmp(argv[optind], "dump") == 0) {
		exit_status = dump_headers(servants_leader);
	} else if (strcmp(argv[optind], "allocate") == 0) {
            exit_status = allocate_slots(argv[optind + 1], servants_leader);
	} else if (strcmp(argv[optind], "list") == 0) {
		exit_status = list_slots(servants_leader);
	} else if (strcmp(argv[optind], "message") == 0) {
            exit_status = messenger(argv[optind + 1], argv[optind + 2], servants_leader);
	} else if (strcmp(argv[optind], "ping") == 0) {
            exit_status = ping_via_slots(argv[optind + 1], servants_leader);
	} else if (strcmp(argv[optind], "watch") == 0) {
            open_any_device(servants_leader);

                /* We only want this to have an effect during watch right now;
                 * pinging and fencing would be too confused */
                if (check_pcmk) {
                        recruit_servant("pcmk", 0);
                        servant_count--;
                }

                exit_status = inquisitor();

	} else {
		exit_status = -2;
	}
#else
        if (strcmp(argv[optind], "watch") == 0) {
                /* We only want this to have an effect during watch right now;
                 * pinging and fencing would be too confused */
                if (check_pcmk) {
                        recruit_servant("pcmk", 0);
                        servant_count--;
                }

                exit_status = inquisitor();
        }
#endif
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
