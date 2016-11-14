CC=gcc
RM=rm -fr
INSTALL=install
MKDIR=mkdir -p
LN=ln -sf
MV=mv -f
OPTIMIZE=-DNDEBUG -O3
DEBUG=-g3
WARN=-Wall -Wno-incompatible-pointer-types
CFLAGS=
DEFS=
EXE=runevent
BINARYHEAP=../binaryheap
INCLUDE=-I $(BINARYHEAP)

NMDISPATCHER=/etc/NetworkManager/dispatcher.d
DHCLIENTEXIT=/etc/dhcp/dhclient-exit-hooks

SOURCES=$(BINARYHEAP)/bheap.c runevent.c
OBJECTS=$(SOURCES:.c=.o)

CONFIGFILE?=/etc/runevent.conf
SCRIPTPATH?=/usr/share/runevent
DEFS+= -DCONFIGFILE=\"$(CONFIGFILE)\"

EVT_EXT?=.handler
DEFS+= -DEVT_EXT=\"$(EVT_EXT)\"

ifdef GROUP
	DEFS+= -DGROUP=\"$(GROUP)\"
endif

ifdef LOGIN_DEFS
	DEFS+= -DLOGIN_DEFS=\"$(LOGIN_DEFS)\"
endif

ifdef MAILER
	DEFS+= -DMAILER=\"$(MAILER)\"
endif

ifdef SYS_DIR
	DEFS+= -DSYS_DIR=\"$(SYS_DIR)\"
endif

SYS_EVT_DIR?=/etc/events.d
DEFS+= -DSYS_EVT_DIR=\"$(SYS_EVT_DIR)\"

ifdef UID_MAX_KEY
	DEFS+= -DUID_MAX_KEY=\"$(UID_MAX_KEY)\"
endif

ifdef UID_MIN_KEY
	DEFS+= -DUID_MIN_KEY=\"$(UID_MIN_KEY)\"
endif

ifdef USER_EVT_DIR
	DEFS+= -DUSER_EVT_DIR=\"$(USER_EVT_DIR)\"
endif

CFLAGS+= $(DEFS)

default: release
all: debug release

debug:
	$(MAKE) OPTIMIZE="$(DEBUG)" $(OBJECTS) EXE="$(EXE)dbg" $(EXE)dbg

release: $(SOURCES) $(EXE)

.c.o:
	$(CC) $(CFLAGS) $(OPTIMIZE) $(WARN) $(INCLUDE) -c $< -o $@

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OPTIMIZE) $(WARN) $(INCLUDE) $(OBJECTS) -o $(EXE)

clean:
	$(RM) *.o $(EXE) $(EXE)dbg

install:
	$(MKDIR) $(SCRIPTPATH) $(SYS_EVT_DIR)
	$(INSTALL) -g root -o root -m 700 -s $(EXE) /usr/sbin
	$(INSTALL) -g root -o root -m 644 runevent.conf $(CONFIGFILE)
	$(INSTALL) -g root -o root -m 700 -t $(SCRIPTPATH) scripts/*
	$(LN) $(SCRIPTPATH)/nm-dispatcher $(NMDISPATCHER)/99-runevent
	$(MV) $(DHCLIENTEXIT) $(SYS_EVT_DIR)/dhclient-exit-hooks$(EVT_EXT) &> /dev/null || true
	$(LN) $(SCRIPTPATH)/dhclient-exit-hooks $(DHCLIENTEXIT)

uninstall:
	$(RM) /usr/sbin/$(EXE) \
		/etc/$(CONFIGFILE) \
		$(SCRIPTPATH) \
		$(NMDISPATCHER)/99-runevent \
		$(DHCLIENTEXIT)
	$(MV) $(DHCLIENTEXIT)/dhclient-exit-hooks$(EVT_EXT) $(DHCLIENTEXIT) &> /dev/null || true