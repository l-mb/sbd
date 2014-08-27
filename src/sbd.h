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

#include <arpa/inet.h>
#include <asm/unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libaio.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <qb/qblog.h>

/* signals reserved for multi-disk sbd */
#define SIG_LIVENESS (SIGRTMIN + 1)	/* report liveness of the disk */
#define SIG_EXITREQ  (SIGRTMIN + 2)	/* exit request to inquisitor */
#define SIG_TEST     (SIGRTMIN + 3)	/* trigger self test */
#define SIG_RESTART  (SIGRTMIN + 4)	/* trigger restart of all failed disk */
#define SIG_IO_FAIL  (SIGRTMIN + 5)	/* the IO child requests to be considered failed */
#define SIG_PCMK_UNHEALTHY  (SIGRTMIN + 6)
/* FIXME: should add dynamic check of SIG_XX >= SIGRTMAX */

#define HOG_CHAR	0xff
#define HA_COREDIR      "/var/lib/heartbeat/cores"

/* Sector data types */
struct sector_header_s {
	char	magic[8];
	unsigned char	version;
	unsigned char	slots;
	/* Caveat: stored in network byte-order */
	uint32_t	sector_size;
	uint32_t	timeout_watchdog;
	uint32_t	timeout_allocate;
	uint32_t	timeout_loop;
	uint32_t	timeout_msgwait;
	/* Minor version for extensions to the core data set:
	 * compatible and optional values. */
	unsigned char	minor_version;
	uuid_t		uuid; /* 16 bytes */
};

struct sector_mbox_s {
	signed char	cmd;
	char		from[64];
};

struct sector_node_s {
	/* slots will be created with in_use == 0 */
	char	in_use;
	char 	name[64];
};

struct servants_list_item {
	const char* devname;
	pid_t pid;
	int restarts;
	int restart_blocked;
	int outdated;
	int first_start;
	struct timespec t_last, t_started;
	struct servants_list_item *next;
};

struct sbd_context {
	int	devfd;
	io_context_t	ioctx;
	struct iocb	io;
};

void usage(void);
int watchdog_init_interval(void);
int watchdog_tickle(void);
int watchdog_init(void);
void sysrq_init(void);
void watchdog_close(bool disarm);
void sysrq_trigger(char t);
void do_crashdump(void);
void do_reset(void);
void do_off(void);
pid_t make_daemon(void);
void maximize_priority(void);
void sbd_get_uname(void);

/* Tunable defaults: */
extern unsigned long    timeout_watchdog;
extern unsigned long    timeout_watchdog_warn;
extern unsigned long    timeout_watchdog_crashdump;
extern int      timeout_allocate;
extern int      timeout_loop;
extern int      timeout_msgwait;
extern int      timeout_io;
extern int      timeout_startup;
extern int  watchdog_use;
extern int  watchdog_set_timeout;
extern int  skip_rt;
extern int  debug;
extern int  debug_mode;
extern const char *watchdogdev;
extern char*  local_uname;

/* Global, non-tunable variables: */
extern int  sector_size;
extern int  watchdogfd;
extern const char* cmdname;

typedef int (*functionp_t)(const char* devname, int mode, const void* argp);

int assign_servant(const char* devname, functionp_t functionp, int mode, const void* argp);
int init_devices(struct servants_list_item *servants);
struct slot_msg_arg_t {
	const char* name;
	const char* msg;
};

void open_any_device(struct servants_list_item *servants);
int allocate_slots(const char *name, struct servants_list_item *servants);
int list_slots(struct servants_list_item *servants);
int ping_via_slots(const char *name, struct servants_list_item *servants);
int dump_headers(struct servants_list_item *servants);
int messenger(const char *name, const char *msg, struct servants_list_item *servants);

int servant(const char *diskname, int mode, const void* argp);
int servant_pcmk(const char *diskname, int mode, const void* argp);

struct servants_list_item *lookup_servant_by_dev(const char *devname);
struct servants_list_item *lookup_servant_by_pid(pid_t pid);

int init_set_proc_title(int argc, char *argv[], char *envp[]);
void set_proc_title(const char *fmt,...);

#define cl_log(level, fmt, args...) qb_log_from_external_source( __func__, __FILE__, fmt, level, __LINE__, 0, ##args)

#  define cl_perror(fmt, args...) do {                                  \
	const char *err = strerror(errno);				\
	cl_log(LOG_ERR, fmt ": %s (%d)", ##args, err, errno);		\
    } while(0)

#define DBGLOG(lvl, fmt, args...) do {           \
	if (debug > 0) cl_log(lvl, fmt, ##args); \
	} while(0)
