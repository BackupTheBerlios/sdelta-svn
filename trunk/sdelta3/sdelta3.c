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
#include "input.h"
#include "sdelta3.h"

char    magic[]    =  { 0x13, 0x04, 00, 02 };
int	verbosity  =  0;


#define  LEAP(frog)                               \
  do {                                            \
    if ( ceiling >= (frog) ) {                    \
      from.offset = from.ordered[where + (frog)]; \
      if ( memcmp(   to.buffer + to.offset,       \
                   from.buffer + from.offset,     \
                   SORT_SIZE ) > 0 ) {            \
              where    +=  (frog);                \
              ceiling  -=  (frog);                \
      } else  ceiling   =  (frog) - 1;            \
    }                                             \
  } while(0)


void  favor_adjacent_found(FOUND f) {
  int  loop, max;

  f.offset = 0;

  max = f.count - 1;

/* 0x0c 0x10 seem to work good */

  for (loop = 1; loop < max; loop++ )
    if   ( ( f.pair[loop  ].size.dword <= 0x0c       ) &&
           ( f.pair[loop  ].to.dword   != 0xffffffff ) ) {
      if ( ( f.pair[loop-1].to.dword   +  f.pair[loop-1].size.dword != f.pair[loop  ].to.dword ) ||
           ( f.pair[loop  ].to.dword   +  f.pair[loop  ].size.dword != f.pair[loop+1].to.dword ) ) {
             f.pair[loop  ].to.dword   =  0xffffffff;
        loop -= 2;
        loop = MAX(loop,1);
      }
    } else
    if   ( ( f.pair[loop  ].size.dword <= 0x10       ) &&
           ( f.pair[loop  ].to.dword   != 0xffffffff ) )
      if ( ( f.pair[loop-1].to.dword   +  f.pair[loop-1].size.dword != f.pair[loop  ].to.dword ) &&
           ( f.pair[loop  ].to.dword   +  f.pair[loop  ].size.dword != f.pair[loop+1].to.dword ) ) {
             f.pair[loop  ].to.dword    = 0xffffffff;
        loop -= 2;
        loop = MAX(loop,1);
      }
}

u_int32_t       remove_overlap_found(FOUND f) {
  int  loop, s, z;

  f.offset = 0;

  for (loop = 1; loop < f.count; loop++ )
    if ( f.pair[loop    ].to.dword   >= f.pair[f.offset].to.dword +
                                        f.pair[f.offset].size.dword ) {
                f.offset++;
         f.pair[f.offset]             = f.pair[loop    ];
    } else
    if ( f.pair[f.offset].size.dword >= f.pair[loop    ].size.dword ) {
      z= f.pair[f.offset].to.dword    + f.pair[f.offset].size.dword -
         f.pair[loop    ].to.dword;
      s= f.pair[loop    ].size.dword  - z;
      if ( s >= 0x08 ) {
                f.offset++;
         f.pair[f.offset].to.dword    = f.pair[loop    ].to.dword   + z;
         f.pair[f.offset].from.dword  = f.pair[loop    ].from.dword + z;
         f.pair[f.offset].size.dword  = s;
      }
    } else {
      s= f.pair[loop    ].to.dword    - f.pair[f.offset].to.dword;
      if ( s >= 0x08 ) {
         f.pair[f.offset].size.dword  = s;
                f.offset++;
      }
      f.offset--;  loop--;  /* Recompare this find with earlier find */
    }
  return f.offset + 1;
}


u_int32_t       remove_tripe_found(FOUND f) {
  int  loop;

  f.offset  = 0;
  for (loop = 0; loop < f.count; loop++ )
    if(f.pair[loop      ].to.dword != 0xffffffff)
       f.pair[f.offset++]           = f.pair[loop];

  return f.offset;
}



void	output_sdelta(FOUND found, TO to, FROM from) {

  DWORD			size, origin, stretch, unmatched_size;
  int			block;
  DWORD			*dwp;
  unsigned int		offset_unmatched_size;
  DECLARE_DIGEST_VARS;

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
/*
    if               (found.pair[block].to.dword == 0xffffffff)  continue;
*/
    origin.dword   =  found.pair[block].from.dword;
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

/*
    if (found.pair[block].to.dword == 0xffffffff) continue;
*/

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

  GET_DIGEST(found.buffer + 4 + DIGEST_SIZE, found.offset - (4 + DIGEST_SIZE), found.buffer + 4);

  fwrite( found.buffer, 1, found.offset, stdout );
}


static int compare_pair (const void *v0, const void *v1)  {
    PAIR *p0, *p1;
    p0 = (PAIR *)v0;
    p1 = (PAIR *)v1;
    return  p0->to.dword - p1->to.dword;
}

void  make_sdelta(INPUT_BUF *from_ibuf, INPUT_BUF *to_ibuf)  {
  FROM			from;
  TO			to;
  MATCH			match, potential;
  FOUND			found;
  unsigned int		count, total, where, ceiling, basement;
  int                   limit, resize;
  DECLARE_DIGEST_VARS;
  unsigned int          *hist;
  unsigned char		*here, *there;
  QWORD			*from_q, *to_q;

/*
  u_int64_t		sizing=0;
  u_int64_t		leaping=0;
*/

  from.buffer = from_ibuf->buf;
  to.buffer   =   to_ibuf->buf;
  from.size   = from_ibuf->size;
  to.ceiling  = ( to.size = to_ibuf->size ) - 0x1000;

/*
  to.size     =   to_ibuf->size;
  to.ceiling  =   to.size - 0x1000;
*/

  if ( MAX(MIN(from.size, to.size), 0x3fff) == 0x3fff) {
    fprintf(stderr,  "Files must be at least 16K each for patch production.\n");
    exit(EXIT_FAILURE);
  }

  from.ordered = block_list   ( from.buffer, from.size,   &from.ordereds );
                 order_blocks ( from.buffer, from.ordered, from.ordereds );

  GET_DIGEST(from.buffer, from.size, from.digest);

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

/*
leaping++;
*/

      while ( ceiling >= 0x800000 )
        LEAP(0x800000);

      LEAP(0x400000);
      LEAP(0x200000);
      LEAP(0x100000);
      LEAP(0x80000);
      LEAP(0x40000);
      LEAP(0x20000);
      LEAP(0x10000);
      LEAP(0x8000);
      LEAP(0x4000);
      LEAP(0x2000);
      LEAP(0x1000);
      LEAP(0x800);
      LEAP(0x400);
      LEAP(0x200);
      LEAP(0x100);
      LEAP(0x80);
      LEAP(0x40);
      LEAP(0x20);
      LEAP(0x10);
      LEAP(0x8);
      LEAP(0x4);
      LEAP(0x2);
      LEAP(0x1);

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
/*
sizing++;
*/

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

        limit = MIN( from.offset, to.offset - basement);
         here = to.offset + to.buffer; here--;
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

      if ( match.total >= 0x08 ) {
        found.pair[found.count].to.dword      =  match.to;
        found.pair[found.count].from.dword    =  match.from;
        found.pair[found.count].size.dword    =  match.total;
/*
fprintf(stderr,"mat %i to %i from %i tot %i\n",
        found.count, match.to,
        match.from, match.total);
*/
        found.count++;
        if ( match.total > 0x100 ) {
          to.offset = match.to + match.total - 1;
          basement  =  match.total +  match.to;
        }
      }

      while (to.ceiling > to.offset && ! trip_byte(to.buffer[to.offset++]))
      	  ;
      while (to.ceiling > to.offset &&   trip_byte(to.buffer[to.offset  ]))
	  to.offset++;
  }

/* Matching complete */

  qsort (found.pair, found.count, sizeof(PAIR), compare_pair );
  found.count = remove_overlap_found(found);
                favor_adjacent_found(found);

  found.pair[found.count  ].to.dword    =    to.size;
  found.pair[found.count  ].from.dword  =  from.size;
  found.pair[found.count++].size.dword  =  0;

  temp.current += sizeof(PAIR) * found.count;


  if ( verbosity > 0 ) {
    total=0;
    for ( where = 0; where < found.count; where++)
      total += found.pair[where].size.dword;

    limit=0;
    count=0;
    for ( where = 0; where < found.count; where++)
      if (       found.pair[where].to.dword == 0xffffffff ) {
        limit += found.pair[where].size.dword;
        count++;
      }

    fprintf(stderr, "Generation Statistics.\n");
    fprintf(stderr, "Searchable sequences  %u\n", from.ordereds);
    fprintf(stderr, "Matched    sequences  %u\n", found.count - count);
    fprintf(stderr, "Tripe      sequences  %u\n", count);
    fprintf(stderr, "Matching   bytes      %u\n", total   - limit);
    fprintf(stderr, "Umatched   bytes      %u\n", to.size - total);
    fprintf(stderr, "Tripe      bytes      %i\n", limit);
/*
    fprintf(stderr, "Leaping               %lli\n", leaping);
    fprintf(stderr, "Sizing                %lli\n", sizing);
*/

    if ( verbosity > 2 ) {
      hist = (unsigned int *) temp.current;
      memset(hist, 0, sizeof(int) * 0x10000);
      for (where = 0; where < found.count; where++)
        if (found.pair[where].to.dword != 0xffffffff)
          if (found.pair[where].size.dword >= 0x10000)
            hist[0]++;  else
            hist[found.pair[where].size.dword]++;
      fprintf(stderr,"Matches of size >= 65536  %u\n", hist[0]);
      for(where = 1; where < 0x10000; where++)
        if( hist[where] > 0 )
          fprintf(stderr, "Matches of size %u  %u\n", where, hist[where]);
    }
  }

  temp.current -= found.count * sizeof(PAIR);
                  found.count = remove_tripe_found(found);
  temp.current += found.count * sizeof(PAIR);

  unload_buf(from_ibuf);
  output_sdelta(found, to, from);

}


void   make_to(INPUT_BUF *from_ibuf, INPUT_BUF *found_ibuf)  {
  FOUND			found;
  FROM			from, delta;
  TO			to;
  DWORD			*dwp, stretch, size, from_off;
  unsigned char		*p;
  DECLARE_DIGEST_VARS;

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
    fprintf(stderr, "The input did not start with sdelta3 magic.\n");
    fprintf(stderr, "Hint: sdelta3 from_file sdelta3_file > to_file\n");
    fprintf(stderr, "  or: cat sdelta3_file from_file | sdelta3 > to_file\n");
    exit(EXIT_FAILURE);
  }

  p = found.buffer + 4 + 2*DIGEST_SIZE;  /* Skip the magic and 2 sha1 */
  dwp                =  (DWORD *)&to.size;
  dwp->byte.b3       =  *p++;
  dwp->byte.b2       =  *p++;
  dwp->byte.b1       =  *p++;
  dwp->byte.b0       =  *p++;

  /* find the last PAIR (triple) */
  for (p += 4; *(u_int32_t *)p; p += 12)
      ;

  p += 8;
  dwp           =  (DWORD *)&delta.size;
  dwp->byte.b3  =  *p++;
  dwp->byte.b2  =  *p++;
  dwp->byte.b1  =  *p++;
  dwp->byte.b0  =  *p++;

  delta.buffer = p;

  if  ( from.buffer == NULL )  {
    from.buffer = delta.buffer + delta.size;
    from.size   = found.size   - (delta.buffer - found.buffer) - delta.size;
    found.size -= from.size;
  }

  found.size -= 4 + DIGEST_SIZE;

  GET_DIGEST(from.buffer, from.size, from.digest);
  GET_DIGEST(found.buffer + 4 + DIGEST_SIZE, found.size, found.digest);

  if  ( memcmp( found.digest, found.buffer + 4, DIGEST_SIZE ) != 0 ) {
    fprintf(stderr, "The sha1 for this sdelta did not match.\nAborting.\n");
    exit(EXIT_FAILURE);
  }

  if  ( memcmp( from.digest, found.buffer + DIGEST_SIZE + 4, DIGEST_SIZE ) != 0 ) {
    fprintf(stderr, "The sha1 for the dictionary file did not match.\nAborting.\n");
    exit(EXIT_FAILURE);
  }

  delta.offset = 0;
  p = found.buffer + 4 + 2*DIGEST_SIZE + 4;
  do {
      stretch.byte.b3 = *p++;
      stretch.byte.b2 = *p++;
      stretch.byte.b1 = *p++;
      stretch.byte.b0 = *p++;
      size.byte.b3 = *p++;
      size.byte.b2 = *p++;
      size.byte.b1 = *p++;
      size.byte.b0 = *p++;
      from_off.byte.b3 = *p++;
      from_off.byte.b2 = *p++;
      from_off.byte.b1 = *p++;
      from_off.byte.b0 = *p++;

      if (stretch.dword) {
	  if (stretch.dword != fwrite(delta.buffer + delta.offset, 1, stretch.dword, stdout)) {
	      fprintf(stderr, "sdelta3: make_to: couldn't write %u bytes to stdout\n", stretch.dword);
	      exit(EXIT_FAILURE);
	  }
	  delta.offset += stretch.dword;
      }

      if (size.dword != fwrite(from.buffer + from_off.dword, 1, size.dword, stdout)) {
	  fprintf(stderr, "sdelta3: make_to: couldn't write %u bytes to stdout\n", size.dword);
	  exit(EXIT_FAILURE);
      }
  } while (size.dword);

  if (from_ibuf)
      unload_buf(from_ibuf);
  unload_buf(found_ibuf);
}


void  help(void)  {
  fprintf(stderr, "\nsdelta3 designed programmed and copyrighted by\n");
  fprintf(stderr, "Kyle Sallee in 2004, 2005, All Rights Reserved.\n");
  fprintf(stderr, "sdelta3 is distributed under the Sorcerer Public License version 1.1\n");
  fprintf(stderr, "Please read /usr/doc/sdelta/LICENSE\n\n");

  fprintf(stderr, "sdelta records the differences between source tarballs.\n");
  fprintf(stderr, "First, sdelta3 can make a delta patch between two files.\n");
  fprintf(stderr, "Then,  sdelta3 can make the second file when given both\n");
  fprintf(stderr, "the previously generated delta file and the first file.\n\n");

  fprintf(stderr, "Below is an example to make a bzip2 compressed sdelta patch file.\n\n");
  fprintf(stderr, "$ sdelta3 linux-2.6.7.tar linux-2.6.8.1.tar > linux-2.6.7-2.6.8.1.tar.sd3\n");
  fprintf(stderr, "$ bzip2   linux-2.6.7-2.6.8.1.tar.sd3\n\n\n");
  fprintf(stderr, "Below is an example for making linux-2.6.8.1.tar\n\n");
  fprintf(stderr, "$ bunzip2 linux-2.6.7-2.6.8.1.tar.sd3.bz2\n");
  fprintf(stderr, "$ sdelta3 linux-2.6.7.tar linux-2.6.7-2.6.8.1.tar.sd3 > linux-2.6.8.1.tar\n");
  exit(EXIT_FAILURE);
}


void  parse_parameters( char *f1, char *f2)  {
  INPUT_BUF b1, b2;

  load_buf(f1, &b1);
  load_buf(f2, &b2);

  if ( memcmp( b2.buf, magic, 4 ) == 0 ) {
    make_to(&b1, &b2);
  } else {
    init_temp(MAX(b1.size, b2.size)*3/2);
    make_sdelta(&b1, &b2);
  }

}


void  parse_stdin(void) {
  INPUT_BUF b;

  load_buf(NULL, &b);
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
