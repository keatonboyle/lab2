#ifndef EOSPRD_H
#define EOSPRD_H

/*#include <linux/types.h>
#include <linux/file.h>*/

#define true 1
#define false 0

// new iotcl constants
#define EOSPRDIOCOPEN 45
#define EOSPRDIOCENCRYPT 46


static int eosprd_open(const char *pathname, int flags, char *key)
{
  int ret;
  int fd;
  fd = open(pathname, flags);

  if (fd == -1)
  {
    return fd;
  }

  ret = ioctl(fd, EOSPRDIOCOPEN, key);

  if (ret == -1)
  {
    close(fd);
    return ret;
  }

  return fd;
}

struct encrypt_args
{
  char *oldkey;
  char *newkey;
  char *algo;
};

static int eopsrd_encrypt(const char *pathname, char *oldkey, 
    char *newkey, char *algo)
{
  int ret;
  int fd;
  struct encrypt_args e_args = 
  {
    .oldkey = oldkey,
    .newkey = newkey,
    .algo = algo
  };

  fd = open(pathname, O_RDWR);

  if (fd == -1)
  {
    return fd;
  }

  ret = ioctl(fd, EOSPRDIOCENCRYPT, &e_args);

  if (ret == -1)
    return ret;

  ret = close(fd);

  if (ret == -1)
  {
    exit(1);
  }

  return 0;
}

static inline int eosprd_decrypt(const char *pathname, char *oldkey)
{
  return eosprd_encrypt(pathname, oldkey, NULL, NULL);
}



#endif
