/* $Id: input.c,v 1.7 2005/01/25 17:22:47 svinn Exp $ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "input.h"


#define FNAME (fname ? fname : "stdin")

void load_buf(const char *fname, INPUT_BUF *b) {
    struct stat st;
    size_t alloc_size = 0, cnt;
#if defined(USE_MADVISE) && defined(USE_MAP_ANON)
    size_t offset;	/* to cut off the excess */
#endif

#if defined(USE_MMAP) || defined(USE_MAP_ANON)
    b->mmap_size =
#endif
    b->size = 0;

    if (fname) {
	if (stat(fname, &st) == -1) {
	    perror(fname);
	    exit(EXIT_FAILURE);
	}
	/* on FreeBSD, open(dirname, O_RDONLY) succeeds */
	if (S_ISDIR(st.st_mode)) {
	    fprintf(stderr, "%s: is a directory\n", fname);
	    exit(EXIT_FAILURE);
	}

	if ((b->fd = open(fname, O_RDONLY)) == -1) {
	    perror(fname);
	    exit(EXIT_FAILURE);
	}

	/* regular file or a symlink, so it is safe to use st.st_size */
	if (S_ISREG(st.st_mode)) {
	    if (!(alloc_size = st.st_size)) {
		fprintf(stderr, "%s: file size is zero\n", fname);
		exit(EXIT_FAILURE);
	    }
#ifdef USE_MMAP
	    if ((b->buf = mmap(NULL, alloc_size, PROT_READ, MAP_PRIVATE, b->fd, 0)) == MAP_FAILED)
		/* mmap failed: try to use malloc */
		fprintf(stderr, "warning: %s: mmap(size = %u, fd = %d) failed\n", fname, alloc_size, b->fd);
	    else {
		/* mmaped successfully, so return */
		b->mmap_size = b->size = alloc_size;
		MADVISE(b->buf, alloc_size, MADV_RANDOM);
		return;
	    }
#endif
	}
	/* if it is a device, or USE_MMAP is not defined,
	   or mmap failed, use MAP_ANON or malloc then */
    }
    else
	b->fd = 0;


#ifdef USE_MAP_ANON
    /* try to prepare MAP_ANON, if available */
    if ((b->buf = mmap(NULL, alloc_size ? alloc_size + 1 : MAX_MAP_ANON, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_NORESERVE, -1, 0)) != MAP_FAILED)
	b->mmap_size = alloc_size = alloc_size ? alloc_size + 1 : MAX_MAP_ANON;
    else {
	/* mmap failed, let's try to use malloc */
	fprintf(stderr, "warning: %s: mmap(size = %u, MAP_ANON) failed\n", FNAME, alloc_size ? alloc_size + 1 : MAX_MAP_ANON);
#endif
	alloc_size = alloc_size ? alloc_size + 1 : IBUF_ALLOC_QUANT;
	if (!(b->buf = malloc(alloc_size))) {
	    fprintf(stderr, "%s: malloc(%u) failed\n", FNAME, alloc_size);
	    exit(EXIT_FAILURE);
	}
#ifdef USE_MAP_ANON
    }
#endif

    while (cnt = read(b->fd, b->buf + b->size, alloc_size - b->size)) {
	if (cnt == -1) {
	    perror("read");
	    exit(EXIT_FAILURE);
	}

	b->size += cnt;

	/* input buffer is full: fatal error, if it is a MAP_ANON */
	if (alloc_size == b->size)
#ifdef USE_MAP_ANON
	    if (b->mmap_size) {
		fprintf(stderr, "%s: exceeded MAP_ANON size (%u)\n", FNAME, alloc_size);
		exit(EXIT_FAILURE);
	    }
	    else
#endif
	    /* try to realloc */
	    if (!(b->buf = realloc(b->buf, alloc_size += IBUF_ALLOC_QUANT))) {
		fprintf(stderr, "load_buf: realloc(buf, %u) failed\n", alloc_size);
		exit(EXIT_FAILURE);
	    }
    }

#ifdef USE_MAP_ANON
    /* not mmaped, ergo, malloc'ed */
    if (! b->mmap_size) {
#endif
	/* try to realloc it if needed */
	if (alloc_size - b->size > 1 && !(b->buf = realloc(b->buf, b->size))) {
	    fprintf(stderr, "realloc(buf, %u) failed\n", b->size);
	    exit(EXIT_FAILURE);
	}
#ifdef USE_MAP_ANON
    }
#if defined(USE_MADVISE) || defined(USE_MREMAP)
    else {
#ifdef USE_MREMAP
	/* if mremap is available, use it */
	if ((b->buf = mremap(b->buf, MAX_MAP_ANON, b->mmap_size = b->size, MREMAP_MAYMOVE)) == MAP_FAILED) {
    	    fprintf(stderr, "mremap(%u -> %u) failed\n", MAX_MAP_ANON, b->mmap_size);
    	    exit(EXIT_FAILURE);
	}
#else
	/* if mremap is unavailable, use MADVISE to cut off the excess */
	if ((offset = b->size) % PAGE_SIZE)
	    offset += PAGE_SIZE - offset % PAGE_SIZE;
	if (alloc_size > offset)
	    MADVISE(b->buf + offset, alloc_size - offset, MADV_FREE);
#endif	/* USE_MREMAP */
    }
#endif	/* USE_MADVISE || USE_MREMAP */
#endif	/* USE_MAP_ANON */

    close(b->fd);
    b->fd = -1; /* unload_buf will know that it is closed */
}


void unload_buf(INPUT_BUF *b) {
    if (! b->buf)
	return;

#if defined(USE_MMAP) || defined(USE_MAP_ANON)
    if (b->mmap_size) {
	if (munmap(b->buf, b->mmap_size) == -1)
	    fprintf(stderr, "warning: munmap(0x%p, 0x%x) failed\n", b->buf, b->mmap_size);
	b->buf = NULL;
	/* close if it is not closed */
	if (b->fd != -1) {
	    close(b->fd);
	    b->fd = -1;
	}
	return;
    }
#endif
    /* regular malloc, so just free() it */
    free(b->buf);
    b->buf = NULL;
}

/* vi: set ts=8 sw=4: */
