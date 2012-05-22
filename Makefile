CC	= gcc
INSTALL	= install

DESTDIR = /
SBIN	= /usr/sbin
LIBDIR	= /usr/lib
AGENTDIR = ${LIBDIR}/stonith/plugins/external


CFLAGS	+= -D_GNU_SOURCE
INCLUDE = -I/usr/include/pacemaker -I/usr/include/clplumbing \
		-I/usr/include/heartbeat \
		-I/usr/include/glib-2.0 \
		-I${LIBDIR}/glib-2.0/include/

LIBS	= $(GLIBLIB) -laio -lplumbgpl \
	-lcrmcommon -lpe_status -lcib -lpe_rules -lcoroipcc

all:	sbd

sbd:	sbd-md.o sbd-common.o sbd-pacemaker.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

install:	all
	if [ ! -d $(DESTDIR)$(SBIN) ]; then mkdir -p $(DESTDIR)$(SBIN) ; fi
	if [ ! -d $(DESTDIR)$(AGENTDIR) ]; then mkdir -p $(DESTDIR)$(AGENTDIR) ; fi
	$(INSTALL) -m 0755 sbd $(DESTDIR)$(SBIN)	
	$(INSTALL) -m 0755 sbd.agent $(DESTDIR)$(AGENTDIR)/sbd

clean:
	rm -f *.o

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -c -o $@ $<
