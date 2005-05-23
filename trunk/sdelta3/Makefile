CC      := gcc
PREFIX  ?= /usr
CFLAGS  ?= -O3 -pipe
#CFLAGS  += -finline-functions
LDFLAGS ?= -Wl,-s

.PHONY: all bsd install clean

all:	sdelta3

sdelta3: *.c *.h
	$(CC) $(CFLAGS) $(LDFLAGS) *.c -lcrypto -o sdelta3
	$(CC) $(CFLAGS) $(LDFLAGS) *.c -lcrypto -o sdelta3-fast -DLIGHT

clean:
	rm -f sdelta

bsd:  *.c *.h
	$(CC) $(CFLAGS) -DUSE_LIBMD *.c $(LDFLAGS) -ldlmalloc /usr/lib/libmd.a -o sdelta3
	$(CC) $(CFLAGS) -DUSE_LIBMD *.c $(LDFLAGS) -ldlmalloc /usr/lib/libmd.a -o sdelta3-fast -DLIGHT

install: sdelta
	mkdir   -m 0755  -p                     $(PREFIX)/bin
	install -m 0755  sdelta3  sdelta3-fast  $(PREFIX)/bin
	install -m 0755  sd       sdreq         $(PREFIX)/bin
	mkdir   -m 0755  -p                     $(PREFIX)/share/sdelta
	install -m 0644  LICENSE  USAGE         $(PREFIX)/share/sdelta
	install -m 0644  README   sdreq_README  $(PREFIX)/share/sdelta
	install -m 0644  sdelta.magic           $(PREFIX)/share/sdelta/magic
