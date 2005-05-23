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


int  trip_byte(char b)  {

  /* ?@ uppercase [\]^_` lowercase  okay */
  /* numbers :;                     okay */

  if ( ( '?' <= b ) && ( b <= 'z' ) ) return 0;  
  if ( ( '0' <= b ) && ( b <= ';' ) ) return 0;

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
    case '>'  : 
#endif
    case 0x90 : return 1; break;
    default   : return 0; break;
  }

  return 0;

}

u_int32_t       *block_list(unsigned char *b, int s, u_int32_t *c) {

  u_int32_t     *list;
  int           off, blk, max;

  list =  (u_int32_t *) temp.current;

  max  =  s - 8;
  off  =  \
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
  off        = 0;
  blk        = 0;

  for(;max>off;off++)
    if ( list[off+1] - list[off] >= 0x04 )
         list[blk++] = list[off];

  list[blk]     = s;

/*
  Since sorting and comparing of potential matches extends
  to SORT_SIZE it is important that the block list contain no
  blocks starts that are within SORT_SIZE of the end of the file.
*/

  while ( SORT_SIZE > ( list[blk] - list[blk-1] ) )
    list[--blk] = s;


  *c            = blk++;
  temp.current += blk * sizeof(u_int32_t);
  return  list;
}


void  *order_blocks ( unsigned char *b, u_int32_t *n, int c ) {

#if __GNUC__ >= 4
  auto   int compare_mem (const void *v0, const void *v1)  {
#else
  static int compare_mem (const void *v0, const void *v1)  {
#endif

    return  memcmp ( b + *(u_int32_t *)v0,
                     b + *(u_int32_t *)v1, SORT_SIZE );
  }

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

  qsort(n, c, sizeof(u_int32_t), compare_mem);
  return;
}
