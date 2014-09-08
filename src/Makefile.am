AM_CFLAGS = -D_GNU_SOURCE -DCHECK_AIS
AM_CPPFLAGS =  -I$(includedir)/pacemaker  \
		$(glib_CFLAGS)

sbin_PROGRAMS = sbd

sbd_SOURCES = sbd-common.c sbd-inquisitor.c sbd-pacemaker.c setproctitle.c

if SUPPORT_SHARED_DISK
sbd_SOURCES += sbd-md.c
endif

sbd_LDFLAGS = $(glib_LIBS) $(libcoroipcc_LIBS)

