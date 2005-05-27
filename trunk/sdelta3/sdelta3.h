#include <sys/types.h>
#include <netinet/in.h>
#include "blocks.h"
#include "digest.h"

typedef struct FROM {
  unsigned char *buffer;		/* ptr to the file in memory	*/
  size_t	size;
  unsigned char	 digest[DIGEST_SIZE];	/* sha1 of the buffer		*/
  u_int32_t	*ordered;               /* block list                   */
  u_int32_t	 ordereds;
  size_t	 offset;		/* working offset into buffer	*/
  size_t	 block;			/* the currently examined block	*/
  size_t	 limit;
} FROM;


typedef struct TO {
  unsigned char	*buffer;	/* ptr to the file in memory	*/
  size_t	 size;
  size_t	 offset;	/* working offset into buffer	*/
  size_t	 limit;
  size_t	 ceiling;
} TO;

typedef struct MATCH {
  u_int32_t	from, to, blocks, size, head, tail, total;
} MATCH;


typedef struct PAIR {
  DWORD		to, from, size;
} PAIR;


typedef	struct	FOUND	{
  u_int32_t		count;
  PAIR			*pair;
  unsigned char		*buffer;
  u_int32_t		offset, size;
  unsigned char	 	digest[DIGEST_SIZE];
}  FOUND;


#ifndef  FALSE
#define  FALSE 0
#endif

#ifndef  TRUE
#define  TRUE !FALSE
#endif
