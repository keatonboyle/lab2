#ifndef EOSPRD_H
#define EOSPRD_H

// new iotcl constants
#define EOSPRDIOCOPEN 45

static int eosprd_open(const char *pathname, mode_t mode, char *password)
{
  int ret;
  int fd;
  fd = open(pathname, mode);
  if (fd == -1)
  {
    return fd;
  }

  ret = ioctl(fd, EOSPRDIOCOPEN, password);

  if (ret == -1)
    return ret;

  return fd;
}

#endif
