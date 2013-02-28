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
    fprintf(stderr, "\
Usage: ./osprdencrypt RAMDISK_PATH CURRENT_KEY NEW_KEY ALGORITHM\n\
    This program calls:\n\
    eosprd_encrypt(RAMDISK_PATH, CURRENT_KEY, NEW_KEY, ALGORITHM)\n\
    Enter a period ('.') to pass NULL as an argument to eopsrd_encrypt\n");
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
  if (ret == 0)
  {
    printf("Successfully encrypted/decrypted %s\n", argv[1]);
    exit(0);
  }
  else
  {
    printf("Encryption/decryption error\n", argv[1]);
    exit(1);
  }
}
