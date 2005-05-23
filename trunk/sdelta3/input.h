/* $Id: input.h,v 1.4 2005/01/25 17:22:47 svinn Exp $ */

#ifndef __INPUT_H__
#define __INPUT_H__

#include <sys/types.h>
#include <sys/stat.h>

/* PAGE_SIZE definition */
#ifdef __linux__
#include <sys/user.h>
#elif defined(__NetBSD__)
#include <sys/vmparam.h>
#else
#include <sys/param.h>
#if (defined(sun) || defined(__sun)) && !defined(PAGE_SIZE)
#define PAGE_SIZE PAGESIZE
#endif
#endif

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


/* one realloc step */
#define IBUF_ALLOC_QUANT	0x400000

/* mmap is enabled by default */
#define USE_MMAP

/* if USE_MAP_ANON is undefined, mremap is not used */
#ifdef __linux__
#define USE_MREMAP
#endif

#if defined(MAP_ANON) && defined(MAP_NORESERVE)
#define USE_MAP_ANON
#define MAX_MAP_ANON		0x40000000
#endif

/* to disable mmap, MAP_ANON and madvise, uncomment the following: */
/* #undef USE_MMAP
#undef USE_MAP_ANON */

/* to disable *madvise only*, change the following line to `#if 0<newline>' */
#if defined(MADV_SEQUENTIAL) && defined(MADV_FREE) && (defined(USE_MMAP) || defined(USE_MAP_ANON))
#define USE_MADVISE
/* MADVISE_IBUF macro needs this INPUT_BUF pointer to know
   whether the buffer was mmaped */
#define MADVISE_IBUF(ibuf, addr, len, behav) do { \
    if (ibuf->mmap_size && madvise(addr, len, behav) == -1) \
	fprintf(stderr, "warning: madvise(0x%p, 0x%x, %d) failed\n", addr, len, behav); \
} while(0)
#define MADVISE(addr, len, behav) do { \
    if (madvise(addr, len, behav) == -1) \
	fprintf(stderr, "warning: madvise(0x%p, 0x%x, %d) failed\n", addr, len, behav); \
} while(0)
#else
/* do not use madvise */
#define MADVISE_IBUF(ibuf, addr, len, behav)
#define MADVISE(addr, len, behav)
#endif

typedef struct {
    int fd;
    unsigned char *buf;
    size_t size;
#if defined(USE_MMAP) || defined(USE_MAP_ANON)
    size_t mmap_size;
#endif
} INPUT_BUF;

void load_buf(const char *, INPUT_BUF *);
void unload_buf(INPUT_BUF *);

#endif /* __INPUT_H__ */

/* vi: set ts=8 sw=4: */
