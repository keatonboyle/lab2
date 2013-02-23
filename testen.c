#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>
#include <errno.h>

#include "osprd.h"
#include "eosprd.h"

int main(int nargs, char **vargs)
{
  int fd;
  int ret;
  char *buf = "hello";
  fd = open("/dev/osprda", O_RDWR);
  printf("fd: %d\n", fd);

  ret = write(fd, 0, 4);
  printf("writeresult: %d\n", ret);

  close(fd);

  fd = eosprd_open("/dev/osprda", O_RDWR, "password");
  printf("fd: %d\n", fd);

  ret = write(fd, buf, 4);
  printf("writeresult: %d\n", ret);



}
