CPP=gcc
RM=rm -f
OPTIMIZE=-DNDEBUG -O3
DEBUG=-g3
WARN=-Wall -Wno-incompatible-pointer-types
CFLAGS=
EXE=runevent

ifdef CONFIGFILE
	CFLAGS+=-DCONFIGFILE=\"$(CONFIGFILE)\"
endif

BINARYHEAP=../binaryheap

default: release

bheap.o:
	$(CPP) $(CFLAGS) -I $(BINARYHEAP) $(BINARYHEAP)/bheap.c -c

debug:
	$(MAKE) CFLAGS="$(CFLAGS) $(DEBUG) $(WARN)" bheap.o
	$(CPP) $(CFLAGS) $(DEBUG) $(WARN) -I $(BINARYHEAP) bheap.o runevent.c -o $(EXE)dbg

release:
	$(MAKE) CFLAGS="$(CFLAGS) $(OPTIMIZE) $(WARN)" bheap.o
	$(CPP) $(CFLAGS) $(OPTIMIZE) $(WARN) -I $(BINARYHEAP) bheap.o runevent.c -o $(EXE)

clean:
	$(RM) *.o $(EXE) $(EXE)dbg
