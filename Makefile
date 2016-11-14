CC=gcc
RM=rm -f
OPTIMIZE=-DNDEBUG -O3
DEBUG=-g3
WARN=-Wall -Wno-incompatible-pointer-types
CFLAGS=
DEFS=
EXE=runevent
BINARYHEAP=../binaryheap
INCLUDE=-I $(BINARYHEAP)

SOURCES=$(BINARYHEAP)/bheap.c runevent.c
OBJECTS=$(SOURCES:.c=.o)

ifndef CONFIGFILE
	CONFIGFILE=/etc/runevent.conf
endif
DEFS+= -DCONFIGFILE=\"$(CONFIGFILE)\"

ifdef EVT_EXT
	DEFS+= -DEVT_EXT=\"$(EVT_EXT)\"
endif

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

ifdef SYS_EVT_DIR
	DEFS+= -DSYS_EVT_DIR=\"$(SYS_EVT_DIR)\"
endif

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
	install -g root -u root -m 700 $(EXE) /usr/sbin
	install -g root -u root -m 644 $(CONFIGFILE) /etc