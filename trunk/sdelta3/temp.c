#include "temp.h"

void  init_temp(int size) {

  temp.size  =  size;
  temp.tfp   =  tmpfile();

  if  ( temp.tfp == NULL ) {
    perror("Unable to open temporary file.\n");
    exit(EXIT_FAILURE);
  }

  if  ( ftruncate( fileno(temp.tfp), temp.size ) ==  -1 )  {
    perror("Unable to extend temporary file\n");
    exit(EXIT_FAILURE);
  }

  temp.start    =
  temp.current  =  mmap(NULL, temp.size,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_NORESERVE,
                        fileno(temp.tfp), 0);

  if ( temp.start == MAP_FAILED ) {
    perror("Unable to mmap to temporary file\n");
    exit(EXIT_FAILURE);
  }

}
