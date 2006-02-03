#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>

typedef struct TEMP {
  unsigned char	*start,
		*current;
  int		size;
  FILE		*tfp;
} TEMP;

TEMP temp;

void	init_temp(int);
