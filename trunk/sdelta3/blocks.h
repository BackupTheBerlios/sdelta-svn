#include "temp.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


#ifdef __linux__
#include <endian.h>
#elif defined(sun) || defined(__sun)
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
#ifndef __BYTE_ORDER
#define __LITTLE_ENDIAN	1234
#define __BIG_ENDIAN	4321
#ifdef _LITTLE_ENDIAN
#define __BYTE_ORDER	__LITTLE_ENDIAN
#else
#define __BYTE_ORDER	__BIG_ENDIAN
#endif /* _LITTLE_ENDIAN */
#endif /* __BYTE_ORDER */
#elif defined(_BYTE_ORDER) && !defined(__BYTE_ORDER)
/* FreeBSD-5 NetBSD DFBSD TrustedBSD */
#define __BYTE_ORDER	_BYTE_ORDER
#define __LITTLE_ENDIAN	_LITTLE_ENDIAN
#define __BIG_ENDIAN	_BIG_ENDIAN
#define __PDP_ENDIAN	_PDP_ENDIAN
#elif defined(BYTE_ORDER) && !defined(__BYTE_ORDER)
/* FreeBSD-[34] OpenBSD MirBSD */
#define __BYTE_ORDER	BYTE_ORDER
#define __LITTLE_ENDIAN	LITTLE_ENDIAN
#define __BIG_ENDIAN	BIG_ENDIAN
#define __PDP_ENDIAN	PDP_ENDIAN
#endif

#ifndef __BYTE_ORDER
#error __BYTE_ORDER is undefined
#endif

typedef union DWORD {

  u_int32_t  dword;

  struct {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      u_int16_t  low;
      u_int16_t  high;
    #else
      u_int16_t  high;
      u_int16_t  low;
    #endif
  }  word;

  struct {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      unsigned char  b0;
      unsigned char  b1;
      unsigned char  b2;
      unsigned char  b3;
    #elif __BYTE_ORDER == __BIG_ENDIAN
      unsigned char  b3;
      unsigned char  b2;
      unsigned char  b1;
      unsigned char  b0;
    #else /* __BYTE_ORDER == __PDP_ENDIAN */
      unsigned char  b2;
      unsigned char  b3;
      unsigned char  b1;
      unsigned char  b0;
    #endif
  }  byte;

} DWORD;


typedef union QWORD {

  u_int64_t     qword;

  struct {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      DWORD  low;
      DWORD  high;
    #else
      DWORD  high;
      DWORD  low;
    #endif
  } dword;

} QWORD;


typedef struct INDEX {
  u_int32_t	*natural;
  u_int32_t	 naturals;
} INDEX;

/* int         trip_byte    (unsigned char); */
/* static inline: to be used by blocks.c & sdelta3.c */
static inline int  trip_byte(unsigned char b)  {

  /* ?@ uppercase [\]^_` lowercase  okay */
  /* numbers :;                     okay */

  /* if ( ( '?' <= b ) && ( b <= 'z' ) ) return 0;  
  if ( ( '0' <= b ) && ( b <= ';' ) ) return 0; */

  /* SPACE LF NULL TAB /<> NOP  trip */
  /* Everything else            okay */

  switch (b) {
#ifndef LIGHT
    case ' '  :
#endif
    case 0x0a :
    case 0x00 :
#ifndef LIGHT
    case 0x09 :
    case '/'  :
    case '<'  : 
#endif
    case 0x90 : return 1; break;
    default   : return 0; break;
  }

  return 0;
}


u_int32_t  *block_list   (unsigned char *, int,             u_int32_t *);
void        order_blocks (unsigned char *, u_int32_t *,     int);

void        make_index          (INDEX         *, unsigned char *, int);


/* Provides a good compromise between speed and ideal ordering */
/*
#define  SORT_SIZE 0x400
*/

/* However the larger sort size tends to produce smaller patch files */
#define  SORT_SIZE 0x1000

/*
#define LIGHT 1
*/

/* With    LIGHT defined sdelta3 tends to avoid shreading lines */
/* Without LIGHT defined sdelta3 matches at partial lines       */
