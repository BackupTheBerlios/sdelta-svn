/*

sdelta3.c was written and copyrighted by Kyle Sallee
You may use it in accordance with the 
Sorcerer Public License version 1.1
Please read LICENSE

sdelta3 can identify and combine the difference between two files.
The difference, also called a delta, can be saved to a file.
Then, the second of two files can be generated 
from both the delta and first source file.

sdelta3 is a word blocking dictionary compressor.

*/


#define _GNU_SOURCE

/* for stdin stdout and stderr */
#include <stdio.h>
#include <errno.h>
/* for memcmp */
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef USE_LIBMD
#include <sha.h>
#else
#include <openssl/sha.h>
#endif

#include "input.h"
#include "sdelta3.h"

char    magic[]    =  { 0x13, 0x04, 00, 02 };
int	verbosity  =  0;

#define  leap(frog)                            \
  if ( ceiling >= frog ) {                     \
    from.offset = from.ordered[where + frog];  \
    if ( memcmp(   to.buffer + to.offset,      \
                 from.buffer + from.offset,    \
                 SORT_SIZE ) > 0 ) {           \
            where    +=  frog;                 \
            ceiling  -=  frog;                 \
    } else  ceiling   =  frog - 1;             \
  }

#define  next_offset()  \
    while ((to.ceiling > to.offset) && ! (trip_byte(to.buffer[to.offset++]))); \
    while ((to.ceiling > to.offset) &&   (trip_byte(to.buffer[to.offset  ]))) to.offset++;


void	output_sdelta(FOUND found, TO to, FROM from) {

  DWORD			size, origin, stretch, unmatched_size, slack;
  unsigned char		byte_val;
  int			block;
  DWORD			*dwp;
  unsigned int		offset_unmatched_size;
  SHA_CTX		ctx;
  unsigned char		*here, *there;

  found.buffer   =  (unsigned char *)  temp.current;

  memcpy( found.buffer,      magic,     4  );
  memcpy( found.buffer + DIGEST_SIZE + 4, from.digest, DIGEST_SIZE );
  found.offset   =  4 + 2 * DIGEST_SIZE;

  dwp = (DWORD *)&to.size;
  found.buffer[found.offset++] = dwp->byte.b3;
  found.buffer[found.offset++] = dwp->byte.b2;
  found.buffer[found.offset++] = dwp->byte.b1;
  found.buffer[found.offset++] = dwp->byte.b0;

  to.offset  =  0;

  for ( block = 0;  block < found.count ; block++ ) {

    origin.dword   =  found.pair[block].from.dword;
    if (origin.dword == 0xffffffff)  continue;

    stretch.dword  =  found.pair[block].to.dword - to.offset;
      size.dword   =  found.pair[block].size.dword;
        to.offset  =  found.pair[block].to.dword + size.dword;

    found.buffer[found.offset++] = stretch.byte.b3;
    found.buffer[found.offset++] = stretch.byte.b2;
    found.buffer[found.offset++] = stretch.byte.b1;
    found.buffer[found.offset++] = stretch.byte.b0;

    found.buffer[found.offset++] = size.byte.b3;
    found.buffer[found.offset++] = size.byte.b2;
    found.buffer[found.offset++] = size.byte.b1;
    found.buffer[found.offset++] = size.byte.b0;

    found.buffer[found.offset++] = origin.byte.b3;
    found.buffer[found.offset++] = origin.byte.b2;
    found.buffer[found.offset++] = origin.byte.b1;
    found.buffer[found.offset++] = origin.byte.b0;

  }

         unmatched_size.dword   =  0;
  offset_unmatched_size         =  found.offset;
  found.offset                 +=  4;
     to.offset                  =  0;

  for ( block = 0; block < found.count ; block++ ) {

    if (found.pair[block].from.dword == 0xffffffff) continue;

    stretch.dword    =  found.pair[block].to.dword  -  to.offset;

/*
fprintf(stderr,"blk %i  to %i  stretch %i\n", block, to.offset, stretch.dword);
*/

    if  ( stretch.dword > 0 ) {
      memcpy ( found.buffer + found.offset,
                  to.buffer +    to.offset, stretch.dword );

      unmatched_size.dword  += stretch.dword;
      found.offset          += stretch.dword;
    }
    to.offset = found.pair[block].to.dword +
                found.pair[block].size.dword;
  }

  found.buffer[offset_unmatched_size++] = unmatched_size.byte.b3;
  found.buffer[offset_unmatched_size++] = unmatched_size.byte.b2;
  found.buffer[offset_unmatched_size++] = unmatched_size.byte.b1;
  found.buffer[offset_unmatched_size++] = unmatched_size.byte.b0;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, found.buffer + 4 + DIGEST_SIZE, found.offset - (4 + DIGEST_SIZE));
  SHA1_Final(found.buffer + 4, &ctx);

  fwrite( found.buffer, 1, found.offset, stdout );
}


void  make_sdelta(INPUT_BUF *from_ibuf, INPUT_BUF *to_ibuf)  {
  FROM			from;
  TO			to;
  MATCH			match, potential;
  FOUND			found;
  unsigned int		count, total, where, ceiling, basement;
  int                   limit;
  u_int16_t		tag;
  SHA_CTX		ctx;
  unsigned char		*here, *there;
  QWORD			*from_q, *to_q;
  u_int32_t             *froms;
  int			resize;

/**/
  u_int64_t		sizing=0;
  u_int64_t		leaping=0;
/**/


#if __GNUC__ >= 4
  auto   int compare_dword (const void *v0, const void *v1)  {
#else
  static int compare_dword (const void *v0, const void *v1)  {
#endif
    return  *(u_int32_t *)v0 - *(u_int32_t *)v1;
  }


  from.buffer = from_ibuf->buf;
  to.buffer   =   to_ibuf->buf;
  from.size   = from_ibuf->size;
  to.ceiling  = ( to.size = to_ibuf->size ) - 0x1000;

/*
  to.size     =   to_ibuf->size;
  to.ceiling  =   to.size - 0x1000;
*/

  if ( MAX(MIN(from.size, to.size),0xfff) == 0x3fff) {
    fprintf(stderr,  "Files must be at least 16K each for patch production.\n");
    exit(EXIT_FAILURE);
  }

  from.ordered = block_list   ( from.buffer, from.size,   &from.ordereds );
                 order_blocks ( from.buffer, from.ordered, from.ordereds );

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, from.buffer, from.size);
  SHA1_Final(from.digest, &ctx);

  found.pair                = ( PAIR * ) temp.current;
  found.count               =  0;
  to.offset                 =  0;
  found.pair[0].to.dword    =
  found.pair[0].from.dword  =
  found.pair[0].size.dword  =  0;
  basement                  =  0;

  while  ( to.ceiling > to.offset )  {

/*  fprintf(stderr, "to %i\n", to.block);  */

      where       =  0;
      ceiling     =  from.ordereds;
      ceiling--;

/**/
leaping++;
/**/

      while ( ceiling >= 0x800000 )
      leap(0x800000);
      leap(0x400000);
      leap(0x200000);
      leap(0x100000);
      leap(0x80000);
      leap(0x40000);
      leap(0x20000);
      leap(0x10000);
      leap(0x8000);
      leap(0x4000);
      leap(0x2000);
      leap(0x1000);
      leap(0x800);
      leap(0x400);
      leap(0x200);
      leap(0x100);
      leap(0x80);
      leap(0x40);
      leap(0x20);
      leap(0x10);
      leap(0x8);
      leap(0x4);
      leap(0x2);
      leap(0x1);

      from.offset = from.ordered[where];

     if ( ( *(u_int64_t *)(  to.buffer +   to.offset) !=
            *(u_int64_t *)(from.buffer + from.offset) )  &&
          ( from.ordereds > ++where ) )
       from.offset = from.ordered[where];

      match.blocks   =  1;
      match.total    =  0;
      match.from     =  from.size;
         to.limit    =  to.size - to.offset;
      resize         =  0;

      while( *(u_int64_t *)(  to.buffer +   to.offset) ==
             *(u_int64_t *)(from.buffer + from.offset) ) {
/**/
sizing++;
/**/

        count             =  1;
        from.limit        =  from.size - from.offset;
        limit             =  MIN ( to.limit, from.limit ) / sizeof(QWORD);

        from_q = (QWORD *) ( from.buffer + from.offset );
          to_q = (QWORD *) (   to.buffer +   to.offset );

        if ( ( limit > match.blocks ) &&
             (  from_q[match.blocks].qword ==
                  to_q[match.blocks].qword ) )
          while  ( ( limit > count )  &&
                   ( from_q[count].qword == 
                       to_q[count].qword ) )
            count++;

        potential.blocks = count;
        potential.size   = count * sizeof(QWORD);
        potential.head   =
        potential.tail   = 0;

        limit = MIN( from.offset,
                       to.offset - basement );
         here =        to.offset + to.buffer;     here--;
        there =      from.offset + from.buffer;  there--;
        while ( ( limit                 >  potential.head         ) &&
                ( here[-potential.head] == there[-potential.head] ) )
          potential.head++;

        limit=MIN( from.size   - from.offset,
                     to.size   -   to.offset);
        limit  -=  potential.size;
         here   =  potential.size +   to.buffer +   to.offset;
        there   =  potential.size + from.buffer + from.offset;
        while ( ( limit                >        potential.tail  ) &&
                ( here[potential.tail] == there[potential.tail] ) )
          potential.tail++;

        potential.total =  potential.size + potential.head + potential.tail;

        if ( ( potential.total < match.total ) ||
             ( potential.total < resize      ) )  break;

        if ( ( potential.total  !=  match.total ) ||
             ( from.offset - potential.head < match.from ) ) {
          match.blocks  =                     potential.blocks;
          match.to      =    to.offset      - potential.head;
          match.from    =  from.offset      - potential.head;
          match.total   =                     potential.total;
                 resize =  0;
        }  else  resize++;

        if ( ( match.total < 8192          ) &&
             ( ++where     < from.ordereds ) )
             from.offset   = from.ordered[where];
        else break;

      }  /* finished finding matches for to.block */

      if ( match.total > 0x0c ) {
        found.pair[found.count].to.dword      =  match.to;
        found.pair[found.count].from.dword    =  match.from;
        found.pair[found.count].size.dword    =  match.total;
        basement                              =  match.total + 
                                                 match.to;
/*
fprintf(stderr,"mat %i to %i from %i tot %i\n", 
        found.count, match.to, 
        match.from, match.total);
*/
        found.count++;
        to.offset = match.to + match.total - 1;

              next_offset();
      } else  next_offset();
  }

/* Matching complete */

  found.pair[found.count  ].to.dword    =    to.size;
  found.pair[found.count  ].from.dword  =  from.size;
  found.pair[found.count++].size.dword  =  0;

  temp.current += sizeof(PAIR) * found.count;


/* Tripe is discard for high compression to soak */

  if (found.count > 0x400) {
    froms = (u_int32_t *)temp.current;
    for(count=0; count < found.count; count++)
      froms[count]=found.pair[count].from.dword;
    qsort(froms, found.count, sizeof(u_int32_t), compare_dword);
    ceiling = found.count / 50;  /* 2% */
    where=0; limit=0;
    for(count=0; count < found.count; count++)
      if (froms[count] == where) limit++;
      else {
        if (limit > ceiling) {
          for (basement=0; basement < found.count; basement++)
            if ( found.pair[basement].from.dword == where ) {
                 found.pair[basement].from.dword =  0xffffffff;
                 if (verbosity > 2)
                   fprintf(stderr,"Removed match of length %i\n", found.pair[basement].size.dword);
            }
          if (verbosity > 1)
            fprintf(stderr,"Discarded tripe\n");
        }
        limit = 0;  where = froms[count];
      }
  }


  if ( verbosity > 0 ) {
    fprintf(stderr, "Statistics for sdelta generation.\n");
    fprintf(stderr, "Blocks in from               %i\n", from.ordereds);
/**/
    fprintf(stderr, "Leaping                      %lli\n", leaping);
    fprintf(stderr, "Sizing                       %lli\n", sizing);
/**/
    total=0;
    for ( where = 0; where < found.count; where++)
      total += found.pair[where].size.dword;
    fprintf(stderr, "Tentative Matching bytes     %i\n",           total);
    fprintf(stderr, "Tentative Umatched bytes     %i\n", to.size - total);
    fprintf(stderr, "Tentative Matched sequences  %i\n", found.count);

  }

  unload_buf(from_ibuf);
  output_sdelta(found, to, from);

}


void   make_to(INPUT_BUF *from_ibuf, INPUT_BUF *found_ibuf)  {
  FOUND			found;
  FROM			from, delta;
  TO			to;
  DWORD			*dwp, stretch;
  unsigned char		control;
  u_int32_t		block;
  u_int32_t		size;
  SHA_CTX		ctx;

  if (from_ibuf) {
      from.buffer  =  from_ibuf->buf;
      from.size    =  from_ibuf->size;
  }
  else {
      from.buffer  =  NULL;
      from.size    =  0;
  }
  
  found.buffer  =  found_ibuf->buf;
  found.size    =  found_ibuf->size;

  if  ( memcmp(found.buffer, magic, 4) != 0 ) {
    fprintf(stderr, "Input on stdin did not start with sdelta magic.\n");
    fprintf(stderr, "Hint: cat sdelta_file from_file | sdelta  > to_file\n");
    exit(EXIT_FAILURE);
  }

  found.offset       =  4 + 2 * DIGEST_SIZE;  /* Skip the magic and 2 sha1 */
  dwp                =  (DWORD *)&to.size;
  dwp->byte.b3       =  found.buffer[found.offset++];
  dwp->byte.b2       =  found.buffer[found.offset++];
  dwp->byte.b1       =  found.buffer[found.offset++];
  dwp->byte.b0       =  found.buffer[found.offset++];
  found.count        =  0;
  to.offset          =  0;

  found.pair         = (PAIR *) temp.current;
  found.count        =  0;
  found.offset       =  8 + 2 * DIGEST_SIZE;
  /* Skip the magic and 2 sha1 and to size */

  size          =  1;
  while ( size !=  0 ) {

    stretch.byte.b3 = found.buffer[found.offset++];
    stretch.byte.b2 = found.buffer[found.offset++];
    stretch.byte.b1 = found.buffer[found.offset++];
    stretch.byte.b0 = found.buffer[found.offset++];

    to.offset += stretch.dword;

    found.pair[found.count].size.byte.b3 = found.buffer[found.offset++];
    found.pair[found.count].size.byte.b2 = found.buffer[found.offset++];
    found.pair[found.count].size.byte.b1 = found.buffer[found.offset++];
    found.pair[found.count].size.byte.b0 = found.buffer[found.offset++];

    found.pair[found.count].from.byte.b3 = found.buffer[found.offset++];
    found.pair[found.count].from.byte.b2 = found.buffer[found.offset++];
    found.pair[found.count].from.byte.b1 = found.buffer[found.offset++];
    found.pair[found.count].from.byte.b0 = found.buffer[found.offset++];

    found.pair[found.count].to.dword     = to.offset;
    to.offset +=  size =  found.pair[found.count++].size.dword;

  };

  temp.current += sizeof(PAIR) * found.count;

  dwp           =  (DWORD *)&delta.size;
  dwp->byte.b3  =  found.buffer[found.offset++];
  dwp->byte.b2  =  found.buffer[found.offset++];
  dwp->byte.b1  =  found.buffer[found.offset++];
  dwp->byte.b0  =  found.buffer[found.offset++];

  delta.buffer  =  found.buffer + found.offset;
  if  ( from.buffer == NULL )  {
           from.buffer  =  found.buffer + found.offset + delta.size;
           from.size    =  found.size   - found.offset - delta.size;
          found.size    =  found.size   - from.size    - (4 + DIGEST_SIZE);
  } else  found.size   -=  4 + DIGEST_SIZE;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, from.buffer, from.size);
  SHA1_Final(from.digest, &ctx);
  
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, found.buffer + 4 + DIGEST_SIZE, found.size);
  SHA1_Final(found.digest, &ctx);
	    
  if  ( memcmp( found.digest, found.buffer + 4, DIGEST_SIZE ) != 0 ) {
    fprintf(stderr, "The sha1 for this sdelta did not match.\nAborting.\n");
    exit(EXIT_FAILURE);
  }

  if  ( memcmp( from.digest, found.buffer + DIGEST_SIZE + 4, DIGEST_SIZE ) != 0 ) {
    fprintf(stderr, "The sha1 for the dictionary file did not match.\nAborting.\n");
    exit(EXIT_FAILURE);
  }


  delta.offset  =  0;
   from.offset  =  0;
     to.offset  =  0;
  delta.offset  =  0;

  for ( block = 0; block < found.count; block++ ) {

    stretch.dword = found.pair[block].to.dword - to.offset;
    if ( stretch.dword > 0 ) {
      write( 1, delta.buffer + delta.offset, stretch.dword );
      delta.offset += stretch.dword;
         to.offset += stretch.dword;
    }

    size        = found.pair[block].size.dword;
    from.offset = found.pair[block].from.dword;
    write( 1, from.buffer + from.offset, size );

    to.offset  += size;
  }

  if (from_ibuf)
      unload_buf(from_ibuf);
  unload_buf(found_ibuf);
}


void  help(void)  {
  printf("\nsdelta3 designed programmed and copyrighted by\n");
  printf("Kyle Sallee in 2004, 2005, All Rights Reserved.\n");
  printf("sdelta3 is distributed under the Sorcerer Public License version 1.1\n");
  printf("Please read /usr/doc/sdelta/LICENSE\n\n");

  printf("sdelta records the differences between source tarballs.\n");
  printf("First, sdelta3 can make a delta patch between two files.\n");
  printf("Then,  sdelta3 can make the second file when given both\n");
  printf("the previously generated delta file and the first file.\n\n");

  printf("Below is an example to make a bzip2 compressed sdelta patch file.\n\n");
  printf("$ sdelta3 linux-2.6.7.tar linux-2.6.8.1.tar > linux-2.6.7-2.6.8.1.tar.sd3\n");
  printf("$ bzip2   linux-2.6.7-2.6.8.1.tar.sd3\n\n\n");
  printf("Below is an example for making linux-2.6.8.1.tar\n\n");
  printf("$ bunzip3 linux-2.6.7-2.6.8.1.tar.sd3.bz2\n");
  printf("$ sdelta3 linux-2.6.7.tar linux-2.6.7-2.6.8.1.tar.sd3 > linux-2.6.8.1.tar\n");
  exit(EXIT_FAILURE);
}


void  parse_parameters( char *f1, char *f2)  {
  INPUT_BUF b1, b2;

  load_buf(f1, &b1);
  load_buf(f2, &b2);

  if ( memcmp( b2.buf, magic, 4 ) == 0 ) {
    init_temp(MAX(b1.size, b2.size));      make_to     (&b1, &b2); } else {
    init_temp(MAX(b1.size, b2.size)*3/2);  make_sdelta (&b1, &b2); }

}


void  parse_stdin(void) {
  INPUT_BUF b;

  load_buf(NULL, &b);  init_temp(b.size);
  make_to (NULL, &b);
} 


int	main	(int argc, char **argv)  {

  if  ( NULL !=  getenv("SDELTA_VERBOSE") )
    sscanf(      getenv("SDELTA_VERBOSE"), "%i", &verbosity );  

  switch (argc) {
    case  3 :  parse_parameters(argv[1], argv[2]);  break;
    case  1 :  parse_stdin();                       break;
    default :  help();                              break;
  }
  exit(EXIT_SUCCESS);
}
