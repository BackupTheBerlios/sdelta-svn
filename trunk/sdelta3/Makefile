CC      =  gcc
PREFIX  = /usr
CFLAGS  = -Os -pipe
LDFLAGS = -Wl,-s

SRCS = blocks.c input.c sdelta3.c temp.c
HDRS = blocks.h digest.h input.h sdelta3.h temp.h

.PHONY: all install clean

all: sdelta3 sdelta3-lt

sdelta3 sdelta3-lt: $(SRCS) $(HDRS)
	@echo -n 'Checking for OpenSSL/libgcrypt... '; \
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
	fi 2>/dev/null; \
	echo -e "\nCompiling sdelta3 and sdelta3-lt with\n\n\tCFLAGS  = $(CFLAGS) $$extra_cflags\n\tLDFLAGS = $$extra_ldflags $(LDFLAGS)\n"; \
	unset PS4; set -e; set -x; \
	$(CC) $(CFLAGS) $$extra_cflags         $(SRCS) -o sdelta3    $$extra_ldflags $(LDFLAGS); \
	$(CC) $(CFLAGS) $$extra_cflags -DLIGHT $(SRCS) -o sdelta3-lt $$extra_ldflags $(LDFLAGS)

clean:
	rm -f sdelta3 sdelta3-lt

install: sdelta3 sdelta3-lt
	mkdir   -m 0755  -p                     $(PREFIX)/bin
	install -m 0755  sdelta3  sdelta3-lt    $(PREFIX)/bin
	install -m 0755  sd3      sdreq         $(PREFIX)/bin
	mkdir   -m 0755  -p                     $(PREFIX)/share/sdelta3
	install -m 0644  LICENSE  USAGE         $(PREFIX)/share/sdelta3
	install -m 0644  README   sdreq_README  $(PREFIX)/share/sdelta3
	install -m 0644  sdelta3.magic          $(PREFIX)/share/sdelta3/magic
