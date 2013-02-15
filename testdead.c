#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osprd.h"

int main(int nargs, char **vargs)
{
  int status;
  pid_t pid = fork();
  if (pid == -1)
    error(1,0,"Problem forking\n");

  int fd = open(vargs[1], O_WRONLY);

  if (pid == 0)    // -------------------------------------------------- CHILD
  {
    int err;
    sleep(1);
    if ((err = ioctl(fd, OSPRDIOCACQUIRE, NULL)) == 0)
    {
      printf("Got dat lock in child\n");
    }
    else
    {
      printf("%d from child ioctl\n", err);
    }

    _exit(0);
  }
  else   // ----------------------------------------------------------- PARENT
  {
    int err;
    int fd2 = open(vargs[1], O_WRONLY);
    if (ioctl(fd, OSPRDIOCACQUIRE, NULL) != -1)
    {
      printf("Got dat lock in parent\n");
    }

    sleep(2);
    if ((err = ioctl(fd, OSPRDIOCACQUIRE, NULL)) == 0)
    {
      printf("Got lock 2 in parent\n");
    }
    else
    {
      while(1);
      printf("%d returned from 2nd ioctl in parent\n", err);
    }
  }

}

