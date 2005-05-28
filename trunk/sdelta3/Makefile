CC      := gcc
PREFIX  ?= /usr
CFLAGS  ?= -O3 -pipe
#CFLAGS  += -finline-functions
LDFLAGS ?= -Wl,-s

# Yes it auto detects the libraries to use
# Is this a good method for it?


openssl  = $(shell bash -c "  pkg-config --exists             openssl && \
                              pkg-config --libs               openssl")

gnutls   = $(shell bash -c "! pkg-config --exists             openssl && \
                              pkg-config --exists              gnutls && \
                              pkg-config --atleast-version=1.2 gnutls && \
                              pkg-config --libs                gnutls |  \
                              sed s:^:-DGNUTLS\ :")

gnutls10 = $(shell bash -c "! pkg-config --exists             openssl && \
                              pkg-config --exists              gnutls && \
                              pkg-config --max-version=1.0.99  gnutls && \
                              pkg-config --libs                gnutls |  \
                              sed s:^:-DUSE_GNUTLS10\ :")

libmd    = $(shell bash -c "! pkg-config --exists             openssl && \
                            ! pkg-config --exists              gnutls && \
                              [ -f /usr/lib/libmd.a ]                 && \
                              echo /usr/lib/libmd.a -DUSE_LIBMD")

dlmalloc = $(shell bash -c "  [ -f       /usr/lib/libdlmalloc ]       || \
                              [ -f /usr/local/lib/libdlmalloc ]       && \
                              echo -ldlmalloc")

.PHONY: all bsd install clean

all:	sdelta3 sdelta3-lt


sdelta3: *.c *.h
	$(CC) $(CFLAGS) $(LDFLAGS) *.c -lcrypto -o sdelta3    $(gnutls) $(gnutls10) $(openssl) $(libmd) $(dlmalloc)

sdelta3-lt: *.c *.h
	$(CC) $(CFLAGS) $(LDFLAGS) *.c -lcrypto -o sdelta3-lt $(gnutls) $(gnutls10) $(openssl) $(libmd) $(dlmalloc) -DLIGHT

clean:
	rm -f sdelta3 sdelta3-lt

#bsd:  *.c *.h
#	$(CC) $(CFLAGS) -DUSE_LIBMD *.c $(LDFLAGS) -ldlmalloc /usr/lib/libmd.a -o sdelta3
#	$(CC) $(CFLAGS) -DUSE_LIBMD *.c $(LDFLAGS) -ldlmalloc /usr/lib/libmd.a -o sdelta3-fast -DLIGHT

install: sdelta3 sdelta3-lt
	mkdir   -m 0755  -p                     $(PREFIX)/bin
	install -m 0755  sdelta3  sdelta3-lt    $(PREFIX)/bin
	install -m 0755  sd       sdreq         $(PREFIX)/bin
	mkdir   -m 0755  -p                     $(PREFIX)/share/sdelta
	install -m 0644  LICENSE  USAGE         $(PREFIX)/share/sdelta
	install -m 0644  README   sdreq_README  $(PREFIX)/share/sdelta
	install -m 0644  sdelta.magic           $(PREFIX)/share/sdelta/magic
