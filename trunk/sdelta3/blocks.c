/*
This code, blocks.c written and copyrighted by Kyle Sallee,
creates and orders lists of dynamically sized blocks of data.
Please read LICENSE if you have not already
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "blocks.h"


u_int32_t       *block_list(unsigned char *b, int s, u_int32_t *c) {

  u_int32_t		*list;
  int			 off, blk, max;

  list =  (u_int32_t *) temp.current;

  max  =  s - SORT_SIZE;
  off  =
  blk  =  0;

  list[blk++]=off++;

  while   ( off < max ) {
    while ( off < max && ! ( trip_byte(b[off++]) ) );
    while ( off < max &&   ( trip_byte(b[off  ]) ) )  off++;
      list[blk++]=off++;
  }

  list[blk]     = s;


/*
   Speed is gained by discarding blocks that are
   less than 4 bytes away from the the following block.
   Normally, this causes a negligible impact upon match
   quality and match selection which can often
   be recovered when longer matches sometimes
   backtrack into previously missed areas.
   However increasing this value above 4 does increase patch size.
*/


  max        = blk;
  off        = 1;
  blk        = 1;

  for(;max>off;off++)
    if ( list[off+1] - list[off] >= 0x04 )
         list[blk++] = list[off];

  list[blk]     = s - SORT_SIZE;

  *c            = blk++;
  temp.current += blk * sizeof(u_int32_t);
  return  list;
}


static unsigned char *qsort_base;
static int compare_mem (const void *v0, const void *v1)  {
    return  memcmp ( qsort_base + *(u_int32_t *)v0,
                     qsort_base + *(u_int32_t *)v1, SORT_SIZE );
}

void  order_blocks ( unsigned char *b, u_int32_t *n, int c ) {
/*
   90% of the time or more during sdelta3 is
   spent sorting the "from file" block list.
   That is why the block list must be small.
   If it is too small then the matches will
   be poor and the blind spots many.
   If it is too large then an excessive amount
   of time is spent on sorting the block list
   Do not try skimping on the SORT_SIZE.
   The most critical factor in sort time is
   the amount of elements in the block list.
*/

  qsort_base = b;
  qsort(n, c, sizeof(u_int32_t), compare_mem);
  return;
}
