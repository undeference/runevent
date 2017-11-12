###
# runevent - run system and user handlers in response to events
# <https://github.com/undeference/runevent>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
###

CC=gcc
RM=rm -f
RMDIR=rm -fr
INSTALL=install
MKDIR=mkdir -p
LN=ln -sf
MV=mv -f
OPTIMIZE=-DNDEBUG -O3
DEBUG=-ggdb -g3
WARN=-Wall -Wno-incompatible-pointer-types
CFLAGS=
DEFS=
EXE=runevent
BINARYHEAP=bheap
INCLUDE=-I $(BINARYHEAP)

NMDISPATCHER=/etc/NetworkManager/dispatcher.d
DHCLIENTENTER=/etc/dhcp/dhclient-enter-hooks
DHCLIENTEXIT=/etc/dhcp/dhclient-exit-hooks

SOURCES=$(BINARYHEAP)/bheap.c src/config.c src/runevent.c src/subproc.c
OBJECTS=$(SOURCES:.c=.o)

EXEPATH=/usr/bin
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

.PHONY: all debug release clean install uninstall

default: release

debug: OPTIMIZE=$(DEBUG)
debug: release

release: $(SOURCES) $(EXE)

.c.o:
	$(CC) $(CFLAGS) $(OPTIMIZE) $(WARN) $(INCLUDE) -c $< -o $@

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OPTIMIZE) $(WARN) $(INCLUDE) $(OBJECTS) -o $(EXE)

clean:
	$(RM) $(OBJECTS) $(EXE)

install:
	$(MKDIR) $(SCRIPTPATH) $(SYS_EVT_DIR)
	$(INSTALL) -g root -o root -m 755 -s $(EXE) $(EXEPATH)
	$(INSTALL) -g root -o root -m 644 runevent.conf $(CONFIGFILE)
	$(INSTALL) -g root -o root -m 700 -t $(SCRIPTPATH) scripts/*
	$(LN) $(SCRIPTPATH)/nm-dispatcher $(NMDISPATCHER)/99-runevent
	[ ! -f $(SYS_EVT_DIR)/dhclient-enter-hooks$(EVT_EXT) ] && $(MV) $(DHCLIENTENTER) $(SYS_EVT_DIR)/dhclient-enter-hooks$(EVT_EXT) &> /dev/null || true
	$(LN) $(SCRIPTPATH)/dhclient-enter-hooks $(DHCLIENTENTER)
	[ ! -f $(SYS_EVT_DIR)/dhclient-exit-hooks$(EVT_EXT) ] && $(MV) $(DHCLIENTEXIT) $(SYS_EVT_DIR)/dhclient-exit-hooks$(EVT_EXT) &> /dev/null || true
	$(LN) $(SCRIPTPATH)/dhclient-exit-hooks $(DHCLIENTEXIT)

uninstall:
	$(RM) $(EXEPATH)/$(EXE) \
		$(CONFIGFILE) \
		$(NMDISPATCHER)/99-runevent \
		$(DHCLIENTENTER) \
		$(DHCLIENTEXIT)
	$(RMDIR) $(SCRIPTPATH)
	$(MV) $(DHCLIENTENTER)/dhclient-enter-hooks$(EVT_EXT) $(DHCLIENTENTER) &> /dev/null || true
	$(MV) $(DHCLIENTEXIT)/dhclient-exit-hooks$(EVT_EXT) $(DHCLIENTEXIT) &> /dev/null || true
