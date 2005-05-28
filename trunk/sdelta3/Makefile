CC      := gcc
PREFIX  ?= /usr
CFLAGS  ?= -O3 -pipe
LDFLAGS ?= -Wl,-s

.PHONY: all install clean

all:	sdelta3

sdelta3: *.c *.h
	@if [ "$$(uname)" = 'FreeBSD' ]; then \
	    extra_cflags='-DUSE_LIBMD' extra_ldflags='/usr/lib/libmd.a'; \
	    if [ -e /usr/local/lib/libdlmalloc.so ]; then \
		extra_ldflags="-ldlmalloc $$extra_ldflags"; \
	    else \
		echo '*** For optimal performance, please install'; \
		echo '*** libdlmalloc (/usr/ports/devel/libdlmalloc)'; \
	    fi \
	else \
	    echo -n 'Checking for OpenSSL/libgcrypt... '; \
	    if openssl version >/dev/null; then \
		extra_ldflags='-lcrypto'; \
		echo 'using OpenSSL'; \
	    elif libgcrypt-config --version >/dev/null; then \
		extra_cflags='-DUSE_LIBGCRYPT' \
		extra_ldflags="$$(libgcrypt-config --libs)"; \
		echo 'using libgcrypt'; \
	    else \
		echo 'none found'; \
		echo '*** Please install either OpenSSL or libgcrypt'; \
		exit 1; \
	    fi \
	fi 2>/dev/null; \
	echo -e "\nCompiling sdelta3 and sdelta3-lt with\n\n\tCFLAGS  = $(CFLAGS) $$extra_cflags\n\tLDFLAGS = $$extra_ldflags $(LDFLAGS)\n"; \
	set -e; \
	$(CC) $(CFLAGS) $$extra_cflags         *.c -o sdelta3    $$extra_ldflags $(LDFLAGS); \
	$(CC) $(CFLAGS) $$extra_cflags -DLIGHT *.c -o sdelta3-lt $$extra_ldflags $(LDFLAGS)

clean:
	rm -f sdelta3 sdelta3-lt

install: sdelta3 sdelta3-lt
	mkdir   -m 0755  -p                     $(PREFIX)/bin
	install -m 0755  sdelta3  sdelta3-lt    $(PREFIX)/bin
	install -m 0755  sd       sdreq         $(PREFIX)/bin
	mkdir   -m 0755  -p                     $(PREFIX)/share/sdelta
	install -m 0644  LICENSE  USAGE         $(PREFIX)/share/sdelta
	install -m 0644  README   sdreq_README  $(PREFIX)/share/sdelta
	install -m 0644  sdelta.magic           $(PREFIX)/share/sdelta/magic
