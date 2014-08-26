AM_CFLAGS = -D_GNU_SOURCE -DCHECK_AIS
AM_CPPFLAGS =  -I$(includedir)/pacemaker  \
		$(glib_CFLAGS)

sbin_PROGRAMS = sbd

sbd_SOURCES = sbd-common.c sbd-inquisitor.c sbd-md.c sbd-pacemaker.c setproctitle.c

sbd_LDFLAGS = $(glib_LIBS) $(libcoroipcc_LIBS)

