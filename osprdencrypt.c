#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>
#include <errno.h>

#include "osprd.h"
#include "eosprd.h"

int main(int nargs, char **argv)
{
  int ii = 0;
  int ret;
  if (nargs != 5) 
  {
    printf("Need 5 args.");
    exit(1);
  }

  for (ii = 1; ii < nargs; ii++)
  {
    if (argv[ii][0] == '.')
    {
      argv[ii] = NULL;
    }
  }

  ret = eosprd_encrypt(argv[1], argv[2], argv[3], argv[4]);
  printf("encryption returned: %d\n", ret);

  return 0;
}
