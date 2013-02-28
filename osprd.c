#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "spinlock.h"
#include "osprd.h"
#include "eosprd.h"
/*
#include <unistd.h>
#include <sys/types.h>
*/

#include <linux/slab.h>

/* The size of an OSPRD sector. */
#define SECTOR_SIZE 512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED  0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Keaton Boyle, Anthony Ortega");

#define OSPRD_MAJOR 222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);

struct bad_ticket
{
  unsigned ticket_val;
  struct bad_ticket *next;
};

struct pid_list
{
  pid_t pid;
  struct pid_list *next;
};

struct encryption_profile
{
  void (*encrypt_sector) (uint8_t *dst_disk, uint8_t *src, char *key, 
                          int keylen, unsigned long sectorNum);
  void (*decrypt_sector) (uint8_t *dst, uint8_t *src_disk, char *key, 
                          int keylen, unsigned long sectorNum);
  void (*encrypt_key) (uint8_t *dst, uint8_t *src, char *key, int keylen);
  void (*decrypt_key) (uint8_t *dst, uint8_t *src, char *key, int keylen);
};


static struct file_operations osprd_blk_fops;

static const char *sillycrypt_name = "sillycrypt";


/* The internal representation of our device. */
typedef struct osprd_info {
  uint8_t *data;                  // The data array. Its size is
                                  // (nsectors * SECTOR_SIZE) bytes.

  osp_spinlock_t mutex;           // Mutex for synchronizing access to
          // this block device

  unsigned ticket_head;   // Currently running ticket for
          // the device lock

  unsigned ticket_tail;   // Next available ticket for
          // the device lock

  wait_queue_head_t blockq;       // Wait queue for tasks blocked on
          // the device lock

  /* HINT: You may want to add additional fields to help
           in detecting deadlock. */
  
  int w_lock;                  //Count of write locks. 0 or 1
  int r_locks;                 //Count of read locks

  struct pid_list *pids;

  struct bad_ticket *bad_head;

  int encrypted;
  char *key;
  int keylen;   // does not include null byte
  char *algo;
  int algolen;
  struct encryption_profile eprof;

  int enumopen; // num processes currently reading, writing, or de/encrypting
                  // an encrypted ramdisk

  // The following elements are used internally; you don't need
  // to understand them.
  struct request_queue *queue;    // The device request queue.
  spinlock_t qlock;   // Used internally for mutual
                                  //   exclusion in the 'queue'.
  struct gendisk *gd;             // The generic disk.
} osprd_info_t;

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
             void (*callback)(struct file *filp,
            osprd_info_t *user_data),
             osprd_info_t *user_data);

static void osprd_exit(void);

static int modulo(int left, int right)
{
  int tmp = left/right;

  return (left - (right * tmp));
}

static void osprd_read_sector(uint8_t *dst, uint8_t *src_disk, 
                              unsigned long sectorNum)
{
  memcpy(dst, src_disk + sectorNum*SECTOR_SIZE, SECTOR_SIZE);
}

static void osprd_write_sector(uint8_t *dst_disk, uint8_t *src, 
                              unsigned long sectorNum)
{
  memcpy(dst_disk + sectorNum*SECTOR_SIZE, src, SECTOR_SIZE);
}

/*  START SILLYCRYPTING STUFF *************************************************/

static void silly_encrypt(uint8_t *dst, uint8_t *src, char *key, 
    int keylen, size_t datalen)
{
  uint8_t *di = dst;
  uint8_t *si = src;
  int ki = 0;

  for ( ; di < dst + datalen; di++, si++)
  {
    *di = (*si) ^ ((uint8_t) key[ki]);
    ki = modulo((ki+1), keylen);
  }
}

static void silly_decrypt(uint8_t *dst, uint8_t *src, char *key, 
    int keylen, size_t datalen)
{
  silly_encrypt(dst, src, key, keylen, datalen);
}

static void silly_encrypt_sector(uint8_t *dst_disk, uint8_t *src, char *key, 
    int keylen, unsigned long sectorNum)
{
  silly_encrypt(dst_disk+SECTOR_SIZE*sectorNum, src, key, keylen, SECTOR_SIZE);
}

static void silly_decrypt_sector(uint8_t *dst, uint8_t *src_disk, char *key, 
    int keylen, unsigned long sectorNum)
{
  silly_decrypt(dst, src_disk+SECTOR_SIZE*sectorNum, key, keylen, SECTOR_SIZE);
}

static void silly_encrypt_key(uint8_t *dst, uint8_t *src, char *key, 
    int keylen)
{
  silly_encrypt(dst, src, key, keylen, keylen);
}

static void silly_decrypt_key(uint8_t *dst, uint8_t *src, char *key, 
    int keylen)
{
  silly_decrypt(dst, src, key, keylen, keylen);
}

static struct encryption_profile silly_profile = {
  .encrypt_sector = silly_encrypt_sector,
  .decrypt_sector = silly_decrypt_sector,
  .encrypt_key = silly_encrypt_key,
  .decrypt_key = silly_decrypt_key
};


/*  END SILLYCRYPTING STUFF ***************************************************/

  

static int trykey_k(osprd_info_t *d, char *key)
{
  // key is from f_security member, but points to kernelspace
  int r;
  char *key_decryption_output;

  int testkeylen = strnlen(key, 1024);

  if (testkeylen != d->keylen)
    return false;

  key_decryption_output = kmalloc(d->keylen, GFP_ATOMIC);

  d->eprof.decrypt_key(key_decryption_output, d->key, key, d->keylen);
  eprintk("k: keylen: %d\n", d->keylen);
  eprintk("k: d->key: %016lx\n", *((unsigned long *) d->key));
  eprintk("k: key_output: %016lx\n", *((unsigned long *) key_decryption_output));
  eprintk("k: key: %016lx\n", *((unsigned long *) key));

  if (memcmp(key_decryption_output, key, d->keylen) == 0)
  {
    eprintk("correct\n");
    r = true;
  }
  else
  {
    eprintk("false\n");
    r = false;
  }

  memset(key_decryption_output, 0, d->keylen);
  kfree(key_decryption_output);
  return r;
}


static int trykey_user(osprd_info_t *d, char __user *key)
// called during a re-encryption/opening
{
  int r;
  char *userkey_in_k;
  char *key_decryption_output;
  int userkeylen = strnlen_user(key, 1024) - 1;

  if (userkeylen != d->keylen)
    return false;

  userkey_in_k = kmalloc(userkeylen, GFP_ATOMIC);
  if (copy_from_user(userkey_in_k, key, userkeylen))
  {
    osprd_exit();
  }
  key_decryption_output = kmalloc(d->keylen, GFP_ATOMIC);

  eprintk("pre:\n");
  eprintk("user: keylen: %d\n", d->keylen);
  eprintk("user: key: %016lx\n", *((unsigned long *) d->key));
  eprintk("user: key_output: %016lx\n", *((unsigned long *) key_decryption_output));
  eprintk("user: user_key: %016lx\n", *((unsigned long *) userkey_in_k));

  d->eprof.decrypt_key(key_decryption_output, d->key, userkey_in_k, d->keylen);

  eprintk("post:\n");
  eprintk("user: keylen: %d\n", d->keylen);
  eprintk("user: key: %016lx\n", *((unsigned long *) d->key));
  eprintk("user: key_output: %016lx\n", *((unsigned long *) key_decryption_output));
  eprintk("user: user_key: %016lx\n", *((unsigned long *) userkey_in_k));

  if (memcmp(key_decryption_output, userkey_in_k, d->keylen) == 0)
  {
    eprintk("correct\n");
    r = true;
  }
  else
  {
    eprintk("false\n");
    r = false;
  }

  memset(userkey_in_k, 0, d->keylen);
  memset(key_decryption_output, 0, d->keylen);
  kfree(userkey_in_k);
  kfree(key_decryption_output);
  return r;
}



static int decrypt_entire(osprd_info_t *d, char __user *key)
{
  int numChars;
  char *userkey;
  int ret;
  unsigned long sec;

  if (trykey_user(d, key))
  {
    numChars = strnlen_user(key, 1024) - 1;

    userkey = kmalloc(numChars, GFP_ATOMIC);

    ret = copy_from_user(userkey, key, numChars);

    for (sec = 0; sec < nsectors; sec++)
    {
      d->eprof.decrypt_sector(d->data+sec*SECTOR_SIZE, d->data, userkey, 
                              d->keylen, sec);
    }

  }
  else
  {
    return -EKEYREJECTED;
  }

  memset(userkey, 0, numChars);
  kfree(userkey);
  d->encrypted = false;
  return 0;
}
  

static int encrypt_entire(osprd_info_t *d, char __user *key, char __user *algo)
{
  int numChars = 0;
  int ret;
  unsigned long sec;
  
  // ------------------------------------------------------------- SET THINGS UP
  // Find the length of the encryption key
  // While we can get more characters, and those characters aren't NULL bytes
  numChars = strnlen_user(key, 1024) - 1;

  d->key = kmalloc(numChars, GFP_ATOMIC);

  ret = copy_from_user(d->key, key, numChars);

  d->keylen = numChars;

  if (algo)
  {
    numChars = strnlen_user(algo, 1024) - 1;
    d->algo = kmalloc(numChars, GFP_ATOMIC);
    ret = copy_from_user(d->algo, algo, numChars);
    d->algolen = numChars;
  }
  else
  {
    // if the user didn't provide an algoritm, we'd better have a previously 
    //  used one
    if (!d->algo)
    {
      return -ENOSYS;
    }
  }

  // ---------------------------------------------------------------- ENCRYPTION
  // (only sillycrypt supported)
  if (strcmp(d->algo, sillycrypt_name) == 0)
  {
    d->eprof = silly_profile;
  }
  else if (0) // this would be where we'd place other encryption algorithms
  {
    // and assign the correct encryption profile
  }
  else
    return -ENOSYS;

  for (sec = 0; sec < nsectors; sec++)
  {
    d->eprof.encrypt_sector(d->data, d->data+sec*SECTOR_SIZE, d->key, 
                            d->keylen, sec);
  }

  d->eprof.encrypt_key(d->key, d->key, d->key, d->keylen);

  d->encrypted = true;
  
  return 0;
}

static ssize_t eosprd_read(struct file *filp, char __user *buf, size_t length, 
    loff_t *offset)
{
  unsigned long curSector;
  size_t bytesToRead;
  size_t totalRead = 0;
  size_t numFailed;
  uint8_t *kbuffer = kmalloc(SECTOR_SIZE, GFP_ATOMIC);

  osprd_info_t *d = file2osprd(filp);

  if(buf == 0) return -EFAULT;

  if(*offset >= nsectors*SECTOR_SIZE)
      return 0;


  if (d->encrypted) // ----------------------------------------- ENCRYPTED READ
  {

    if(filp->f_security && trykey_k(d, filp->f_security))
    {
      for(curSector = 0; curSector < nsectors; curSector++)
      {
        // if at least part of this sector should be read
        if(*offset < (curSector+1)*SECTOR_SIZE)
        {
          bytesToRead = (curSector+1)*SECTOR_SIZE - *offset;
          if (bytesToRead > length) bytesToRead = length;


          d->eprof.decrypt_sector(kbuffer, d->data, filp->f_security, 
                                  d->keylen, curSector);


          numFailed = copy_to_user(buf, kbuffer + (*offset)%SECTOR_SIZE,
                          bytesToRead);

          if(numFailed)
            eprintk("copy_to_user did not complete successfully\n");

          bytesToRead -= numFailed;

          totalRead += bytesToRead;
          buf += bytesToRead;
          *offset += bytesToRead;
          length -= bytesToRead;

          if (length <= 0) break;
        }
      }
      return totalRead;
    }

  }

  // -------------------------------------------------------------- NORMAL READ
  for(curSector = 0; curSector < nsectors; curSector++)
  {
    // if at least part of this sector should be read
    if(*offset < (curSector+1)*SECTOR_SIZE)
    {
      bytesToRead = (curSector+1)*SECTOR_SIZE - *offset;
      if (bytesToRead > length) bytesToRead = length;

      osprd_read_sector(kbuffer, d->data, curSector);

      numFailed = copy_to_user(buf, kbuffer + *offset%SECTOR_SIZE,
                      bytesToRead);

      if(numFailed)
        eprintk("copy_to_user did not complete successfully\n");

      totalRead += bytesToRead;
      buf += bytesToRead;
      *offset += bytesToRead;
      length -= bytesToRead;

      if (length <= 0) break;
    }
  }

  return totalRead;
}


static ssize_t eosprd_write(struct file *filp, const char __user *buf, 
    size_t length, loff_t *offset)
{
  unsigned long curSector;
  size_t bytesToRead;
  size_t totalRead = 0;
  size_t numFailed;
  uint8_t *kbuffer = kmalloc(SECTOR_SIZE, GFP_ATOMIC);
  
  osprd_info_t *d = file2osprd(filp);

  if(buf == 0) return -EFAULT;

  if(*offset >= nsectors*SECTOR_SIZE)
    return 0;

  if (d->encrypted) // --------------------------------------- ENCRYPTED WRITE
  {
    if(filp->f_security && trykey_k(d, filp->f_security))
    {
      for(curSector = 0; curSector < nsectors; curSector++)
      {
        // if at least part of this sector should be written 
        if(*offset < (curSector+1)*SECTOR_SIZE)
        {
          bytesToRead = (curSector+1)*SECTOR_SIZE - *offset;
          if (bytesToRead > length) bytesToRead = length;

          // read in and decrypt a copy of the sector we'll be writing to 
          d->eprof.decrypt_sector(kbuffer, d->data, filp->f_security, 
                                  d->keylen, curSector);

          // replace a portion (or all) of that copy with the user data
          numFailed = copy_from_user(kbuffer + *offset%SECTOR_SIZE, buf,
                          bytesToRead);

          // encrypt and write the new sector back to disk
          d->eprof.encrypt_sector(d->data, kbuffer, filp->f_security,
                                  d->keylen, curSector);

          if(numFailed)
            eprintk("copy_to_user did not complete successfully\n");

          totalRead += bytesToRead;
          buf += bytesToRead;
          *offset += bytesToRead;
          length -= bytesToRead;

          if (length <= 0) break;
        }
      }
      return totalRead;

    }
    else
    {
      return -EKEYREJECTED;
    }
  }

  // ------------------------------------------------------------ NORMAL WRITE
  for(curSector = 0; curSector < nsectors; curSector++)
  {
    // if at least part of this sector should be written 
    if(*offset < (curSector+1)*SECTOR_SIZE)
    {
      bytesToRead = (curSector+1)*SECTOR_SIZE - *offset;
      if (bytesToRead > length) bytesToRead = length;

      // read in a copy of the sector we'll be writing to 
      osprd_read_sector(kbuffer, d->data, curSector);

      // replace a portion (or all) of that copy with the user data
      numFailed = copy_from_user(kbuffer + *offset%SECTOR_SIZE, buf,
                      bytesToRead);

      // write the new sector back to disk
      osprd_write_sector(d->data, kbuffer, curSector);

      if(numFailed)
        eprintk("copy_to_user did not complete successfully\n");

      totalRead += bytesToRead;
      buf += bytesToRead;
      *offset += bytesToRead;
      length -= bytesToRead;

      if (length <= 0) break;
    }
  }

  return totalRead;
}

#if 0
/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
 
  if (!blk_fs_request(req)) {
    end_request(req, 0);
    return;
  }

  // EXERCISE: Perform the read or write request by copying data between
  // our data array and the request's buffer.
  // Hint: The 'struct request' argument tells you what kind of request
  // this is, and which sectors are being read or written.
  // Read about 'struct request' in <linux/blkdev.h>.
  // Consider the 'req->sector', 'req->current_nr_sectors', and
  // 'req->buffer' members, and the rq_data_dir() function.

  // Your code here.
  //eprintk("Should process request...\n");

  switch(rq_data_dir(req))
  {
    case 0:  // ---------------------------------------------------------- Read
    {
      
      if(req->buffer != 0)
      {
        memcpy((void *)(req->buffer),
          (const void *)(d->data + (req->sector*SECTOR_SIZE)),
          SECTOR_SIZE*req->current_nr_sectors);
      }
      else
        eprintk("BUFFER IS NULL DURING READ!!\n");
      break;
    }

    case 1:  // --------------------------------------------------------- Write
    {
      if(req->buffer != 0)
      {
        memcpy((void *)(d->data + (req->sector*SECTOR_SIZE)),
          (const void*)(req->buffer),
            SECTOR_SIZE*req->current_nr_sectors);
      }
      else
        eprintk("BUFFER IS NULL DURING WRITE!!\n");
      break;
    }
  }
  
  end_request(req, 1);
}
#endif


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
  // Always set the O_SYNC flag. That way, we will get writes immediately
  // instead of waiting for them to get through write-back caches.
  osprd_info_t *d = file2osprd(filp);
  filp->f_flags |= O_SYNC;

  osp_spin_lock(&d->mutex);
  d->enumopen++;
  osp_spin_unlock(&d->mutex);

  return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
  if (filp) {
    char *ci;
    osprd_info_t *d = file2osprd(filp);
    int filp_writable = filp->f_mode & FMODE_WRITE;
    struct pid_list *curr = d->pids;
    struct pid_list **prev = &(d->pids);

    // EXERCISE: If the user closes a ramdisk file that holds
    // a lock, release the lock.  Also wake up blocked processes
    // as appropriate.

    // Your code here.
    
    if((filp->f_flags & F_OSPRD_LOCKED) != F_OSPRD_LOCKED)
    {
      wake_up_all(&d->blockq);
      return 0;
    }
    else
    {
     filp->f_flags ^= F_OSPRD_LOCKED;
     if(filp_writable == 0)
     {
       osp_spin_lock(&d->mutex);
       d->r_locks--;
     }
     else
     {
       osp_spin_lock(&d->mutex);
       d->w_lock = 0;
     }
      curr = d->pids;
      prev = &(d->pids);
      while(curr)
      {
        if(curr->pid == current->pid)
        {
          *prev = curr->next;
          kfree(curr);
          break;
        }
        prev = &(curr->next);
        curr = curr->next;
      } 
       osp_spin_unlock(&d->mutex);
     wake_up_all(&d->blockq);
    }

    if (filp->f_security)
    {
      // Zero out the key, for securty
      for (ci = filp->f_security; *ci != 0; ci++)
      {
        *ci = 0;
      }
      // Free the saved key that this file was using
      kfree(filp->f_security);
      filp->f_security = NULL;
    }



    // This line avoids compiler warnings; you may remove it.
    (void) filp_writable, (void) d;

  }

  return 0;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
    unsigned int cmd, unsigned long arg)
{
  osprd_info_t *d = file2osprd(filp); // device info
  int r = 0;      // return value: initially 0

  // is file open for writing?
  int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

  // This line avoids compiler warnings; you may remove it.
  //(void) filp_writable, (void) d;

  // Set 'r' to the ioctl's return value: 0 on success, negative on error

  if (cmd == OSPRDIOCACQUIRE) {

    // EXERCISE: Lock the ramdisk.
    //
    // If *filp is open for writing (filp_writable), then attempt
    // to write-lock the ramdisk; otherwise attempt to read-lock
    // the ramdisk.
    //
                // This lock request must block using 'd->blockq' until:
    // 1) no other process holds a write lock;
    // 2) either the request is for a read lock, or no other process
    //    holds a read lock; and
    // 3) lock requests should be serviced in order, so no process
    //    that blocked earlier is still blocked waiting for the
    //    lock.
    //
    // If a process acquires a lock, mark this fact by setting
    // 'filp->f_flags |= F_OSPRD_LOCKED'.  You also need to
    // keep track of how many read and write locks are held:
    // change the 'osprd_info_t' structure to do this.
    //
    // Also wake up processes waiting on 'd->blockq' as needed.
    //
    // If the lock request would cause a deadlock, return -EDEADLK.
    // If the lock request blocks and is awoken by a signal, then
    // return -ERESTARTSYS.
    // Otherwise, if we can grant the lock request, return 0.

    // 'd->ticket_head' and 'd->ticket_tail' should help you
    // service lock requests in order.  These implement a ticket
    // order: 'ticket_tail' is the next ticket, and 'ticket_head'
    // is the ticket currently being served.  You should set a local
    // variable to 'd->ticket_head' and increment 'd->ticket_head'.
    // Then, block at least until 'd->ticket_tail == local_ticket'.
    // (Some of these operations are in a critical section and must
    // be protected by a spinlock; which ones?)

    // Your code here (instead of the next two lines).
    
    /*if((filp->f_flags & F_OSPRD_LOCKED) == F_OSPRD_LOCKED)
      return -EDEADLK;*/
    
    struct pid_list *temppl;
    struct pid_list *new;
    unsigned local_ticket;


    osp_spin_lock(&d->mutex);
    temppl = d->pids;
    while(temppl)
    {
      if(temppl->pid == current->pid)
      {
        osp_spin_unlock(&d->mutex);
        return -EDEADLK;
      }
      temppl = temppl->next;
    }
    temppl = d->pids;
    new = ((struct pid_list *) kmalloc(sizeof(struct pid_list),GFP_ATOMIC));
    new->pid = current->pid;
    new->next = temppl;
    d->pids = new;

    local_ticket = d->ticket_head++;
    osp_spin_unlock(&d->mutex);
    
    switch(filp_writable)
    {
      case 0:   // Opened for reading
      {
        struct bad_ticket *currBad;
        struct bad_ticket **prevBad;
        
        for(;;)
        {
          if(wait_event_interruptible(d->blockq,
            (d->ticket_tail == local_ticket) && (d->w_lock == 0)) == -ERESTARTSYS)
          {
            struct pid_list *curr;
            struct pid_list **prev;

            osp_spin_lock(&d->mutex);

            curr = d->pids;
            prev = &(d->pids);

            while(curr)
            {
              if(curr->pid == current->pid)
              {
                *prev = curr->next;
                kfree(curr);
                break;
              }
              prev = &(curr->next);
              curr = curr->next;
            } 
            
            if(d->ticket_tail == local_ticket)
              d->ticket_tail++;
            else
            {
             /*Add my ticket to list*/ 
             struct bad_ticket *temp = d->bad_head;
             struct bad_ticket *n = ((struct bad_ticket*)
              kmalloc(sizeof(struct bad_ticket),GFP_ATOMIC));
             n->ticket_val = local_ticket;
             n->next = temp;
             d->bad_head = n;
            }
            osp_spin_unlock(&d->mutex);
            return -ERESTARTSYS;
          }
          
          osp_spin_lock(&d->mutex);
          if(d->w_lock != 0)
          {
           osp_spin_unlock(&d->mutex);
           continue;
          }
          d->r_locks++;
          d->ticket_tail++;
          
          /*check if ticket_tail is on bad_ticket list*/
          /*If it is, increment ticket_tail and remove that ticket*/
          /*Then redo over again*/
          currBad = d->bad_head;
          prevBad = &(d->bad_head);
          while(currBad)
          {
            if(currBad->ticket_val == d->ticket_tail)
            {
              *prevBad = currBad->next;
              kfree(currBad);
              d->ticket_tail++;
              currBad = d->bad_head;
              prevBad = &(d->bad_head);
              continue;
            }
            prevBad = &(currBad->next);
            currBad = currBad->next;
          }         
          osp_spin_unlock(&d->mutex);
          
          filp->f_flags |= F_OSPRD_LOCKED;
          wake_up_all(&d->blockq);
          break;
        }
        break;
      }
      case 1:  // Opened for writing
      {
        for(;;)
        {
          struct bad_ticket *badcurr = d->bad_head;
          struct bad_ticket **badprev = &(d->bad_head);
          if(wait_event_interruptible(d->blockq,
            (d->ticket_tail == local_ticket) && (d->w_lock == 0)
              && (d->r_locks == 0)) == -ERESTARTSYS)
          {
            struct pid_list *curr;
            struct pid_list **prev;

            osp_spin_lock(&d->mutex);

            curr = d->pids;
            prev = &(d->pids);

            while(curr)
            {
              if(curr->pid == current->pid)
              {
                *prev = curr->next;
                kfree(curr);
                break;
              }
              prev = &(curr->next);
              curr = curr->next;
            } 

            if(d->ticket_tail == local_ticket)
              d->ticket_tail++;
            else
            {
              /*add my ticket to list*/
             struct bad_ticket *temp = d->bad_head;
             struct bad_ticket *n = ((struct bad_ticket*)
              kmalloc(sizeof(struct bad_ticket),GFP_ATOMIC));
             n->ticket_val = local_ticket;
             n->next = temp;
             d->bad_head = n;             
            }
            osp_spin_unlock(&d->mutex);          
            return -ERESTARTSYS;
          }
          
          osp_spin_lock(&d->mutex);
          if((d->w_lock != 0) || (d->r_locks != 0))
          {
           osp_spin_unlock(&d->mutex);
           continue;
          }

          d->w_lock = 1;
          d->ticket_tail++;
          
          /*check if ticket_tail is on bad_ticket list*/
          /*if it is, increment ticket_tail and remove that ticket from the list*/          
          badcurr = d->bad_head;
          badprev = &(d->bad_head);
          while(badcurr)
          {
            if(badcurr->ticket_val == d->ticket_tail)
            {
              *badprev = badcurr->next;
              kfree(badcurr);
              d->ticket_tail++;
              badcurr = d->bad_head;
              badprev = &(d->bad_head);
              continue;
            }
            badprev = &(badcurr->next);
            badcurr = badcurr->next;
          } 
          osp_spin_unlock(&d->mutex);
          
          filp->f_flags |= F_OSPRD_LOCKED;
          break;
        }
        break;
      }
    }
  } 
  else if (cmd == OSPRDIOCTRYACQUIRE) {

    // EXERCISE: ATTEMPT to lock the ramdisk.
    //
    // This is just like OSPRDIOCACQUIRE, except it should never
    // block.  If OSPRDIOCACQUIRE would block or return deadlock,
    // OSPRDIOCTRYACQUIRE should return -EBUSY.
    // Otherwise, if we can grant the lock request, return 0.

    // Your code here (instead of the next two lines).
    
    /*if((filp->f_flags & F_OSPRD_LOCKED) == F_OSPRD_LOCKED)
      return -EBUSY;*/
    
    struct pid_list *temppl;
    struct pid_list *new;
    osp_spin_lock(&d->mutex);
    temppl = d->pids;
    while(temppl)
    {
      if(temppl->pid == current->pid)
      {
        osp_spin_unlock(&d->mutex);
        return -EBUSY;
      }
      temppl = temppl->next;
    }
    temppl = d->pids;
    new = ((struct pid_list *) kmalloc(sizeof(struct pid_list),GFP_ATOMIC));
    new->pid = current->pid;
    new->next = temppl;
    d->pids = new;

    if(d->ticket_head != d->ticket_tail)
    {
      osp_spin_unlock(&d->mutex);
      return -EBUSY;
    }
    
    switch(filp_writable)
    {
      case 0:   // Opened for reading
      {
        if(d->w_lock == 1)
        {
          osp_spin_unlock(&d->mutex);
          return -EBUSY;
        }
        d->ticket_head++;
        d->r_locks++;
        d->ticket_tail++;
        osp_spin_unlock(&d->mutex);
        
        filp->f_flags |= F_OSPRD_LOCKED;
        wake_up_all(&d->blockq);
        break;
      }
      case 1:  // Opened for writing
      {
        if((d->w_lock == 1) || (d->r_locks != 0))
        {
          osp_spin_unlock(&d->mutex);
          return -EBUSY;
        }
        d->ticket_head++;
        d->w_lock = 1;
        d->ticket_tail++;
        osp_spin_unlock(&d->mutex);
        
        filp->f_flags |= F_OSPRD_LOCKED;
        break;
      }
    }
    
    /*eprintk("Attempting to try acquire\n");
    r = -ENOTTY;*/

  } 
  else if (cmd == OSPRDIOCRELEASE) {

    // EXERCISE: Unlock the ramdisk.
    //
    // If the file hasn't locked the ramdisk, return -EINVAL.
    // Otherwise, clear the lock from filp->f_flags, wake up
    // the wait queue, perform any additional accounting steps
    // you need, and return 0.

    // Your code here (instead of the next line).
    
    if((filp->f_flags & F_OSPRD_LOCKED) != F_OSPRD_LOCKED)
      r = -EINVAL;
    else
    {
      struct pid_list *curr;
      struct pid_list **prev;

     filp->f_flags ^= F_OSPRD_LOCKED;
     if(filp_writable == 0)
     {
       osp_spin_lock(&d->mutex);
       d->r_locks--;
     }
     else
     {
       osp_spin_lock(&d->mutex);
       d->w_lock = 0;
     }
      curr = d->pids;
      prev = &(d->pids);
      while(curr)
      {
        if(curr->pid == current->pid)
        {
          *prev = curr->next;
          kfree(curr);
          break;
        }
        prev = &(curr->next);
        curr = curr->next;
      } 
     osp_spin_unlock(&d->mutex);
     wake_up_all(&d->blockq);
    }
    //r -ENOTTY;

  } 
  else if (cmd == EOSPRDIOCOPEN) 
  {
    char *key = (char *) arg;


    if (!key)
    {
      if (d->encrypted)
      {
        return -EKEYREJECTED;
      }
      else
      {
        // No decryption necessary
        return 0;
      }
    }
    else if (trykey_user(d, key))
    {
      int nChars = strnlen_user(key, 1024);
      char *keycopy;


      // Save the key in kernel memory, give the file a pointer to it
      keycopy = kmalloc(nChars, GFP_ATOMIC);
      memcpy(keycopy, key, nChars);

      filp->f_security = keycopy;

      return 0;
    }
    else
    {
      return -EKEYREJECTED;
    }
  }

  else if (cmd == EOSPRDIOCENCRYPT)
  {
    struct encrypt_args *keys = (struct encrypt_args *) arg;

    osp_spin_lock(&d->mutex);
    // if any other files are using this ramdisk, we can't encrypt right now
    if (d->enumopen > 1)
    {
      osp_spin_unlock(&d->mutex);
      return -EBUSY;
    }
    osp_spin_unlock(&d->mutex);

    // If encrypted, decrypt it
    if (d->encrypted)
    {
      if (!(keys->oldkey))
      {
        return -EKEYREJECTED;
      }
      else if (!trykey_user(d, keys->oldkey))
      {
        return -EKEYREJECTED;
      }
      else 
      {
        decrypt_entire(d, keys->oldkey);
      }
    }
    // If you provide a key to an already-decrypted file, that's a problem
    else
    {
      // can't provide a key to an unencrypted file
      if (keys->oldkey)
      {
        return -ENOSYS;
      }
    }

    // If there's a new key, encrypt!
    if (keys->newkey)
    {
      return encrypt_entire(d, keys->newkey, keys->algo);
    }


    // Or leave unencrypted
    return 0;
    
  }
  else
    r = -ENOTTY; /* unknown command */

  return r;
}




// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
  /* Initialize the wait queue. */
  init_waitqueue_head(&d->blockq);
  osp_spin_lock_init(&d->mutex);
  d->ticket_head = d->ticket_tail = 0;

  
  d->w_lock = 0;
  d->r_locks = 0;
  d->bad_head = 0;
  d->pids = 0;
  d->encrypted = 0;
  d->key = 0;
  d->keylen = 0;
  d->algo = 0;
  d->algolen= 0;
  d->enumopen = 0;
  /* Add code here if you add fields to osprd_info_t. */
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

#if 0
// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
  osprd_info_t *d = (osprd_info_t *) q->queuedata;
  struct request *req;

  while ((req = elv_next_request(q)) != NULL)
    osprd_process_request(d, req);
}
#endif


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
  osprd_info_t *d = file2osprd(filp);
  osp_spin_lock(&d->mutex);
  d->enumopen--;
  osp_spin_unlock(&d->mutex);

  if (file2osprd(filp))
    osprd_close_last(inode, filp);
  return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
  if (!osprd_blk_fops.open) {
    memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
    blkdev_release = osprd_blk_fops.release;
    osprd_blk_fops.release = _osprd_release;
  }
  filp->f_op = &osprd_blk_fops;

  /* adding custom reads and writes (for some reason it didn't work to have 
   * these in the osprd_ops structure */
  osprd_blk_fops.read = eosprd_read;
  osprd_blk_fops.write = eosprd_write;

  return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
  .owner = THIS_MODULE,
  .open = _osprd_open,
  // .release = osprd_release, // we must call our own release
  .ioctl = osprd_ioctl
   
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
  if (filp) {
    struct inode *ino = filp->f_dentry->d_inode;
    if (ino->i_bdev
        && ino->i_bdev->bd_disk
        && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
        && ino->i_bdev->bd_disk->fops == &osprd_ops)
      return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
  }
  return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
      void (*callback)(struct file *filp, osprd_info_t *user_data),
      osprd_info_t *user_data)
{
  int fd;
  task_lock(task);
  spin_lock(&task->files->file_lock);
  {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
    struct files_struct *f = task->files;
#else
    struct fdtable *f = task->files->fdt;
#endif
    for (fd = 0; fd < f->max_fds; fd++)
      if (f->fd[fd])
        (*callback)(f->fd[fd], user_data);
  }
  spin_unlock(&task->files->file_lock);
  task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
  wake_up_all(&d->blockq);
  if (d->gd) {
    del_gendisk(d->gd);
    put_disk(d->gd);
  }
  /*
  if (d->queue)
    blk_cleanup_queue(d->queue);
  */
  if (d->data)
    vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
  memset(d, 0, sizeof(osprd_info_t));

  /* Get memory to store the actual block data. */
  if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
    return -1;
  memset(d->data, 0, nsectors * SECTOR_SIZE);

  /* Instead of the optimized request_queue, we're using our own read/write
   * functions

   *  Set up the I/O queue. *
  spin_lock_init(&d->qlock);
  if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
    return -1;
  blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
  d->queue->queuedata = d;
  */

  /* The gendisk structure. */
  if (!(d->gd = alloc_disk(1)))
    return -1;
  d->gd->major = OSPRD_MAJOR;
  d->gd->first_minor = which;
  d->gd->fops = &osprd_ops;



  /*
  d->gd->queue = d->queue;
  */
  d->gd->private_data = d;
  snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
  set_capacity(d->gd, nsectors);
  add_disk(d->gd);

  /* Call the setup function. */
  osprd_setup(d);

  return 0;
}



// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
  int i, r;

  // shut up the compiler
  (void) for_each_open_file;
#ifndef osp_spin_lock
  (void) osp_spin_lock;
  (void) osp_spin_unlock;
#endif

  /* Register the block device name. */
  if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
    printk(KERN_WARNING "osprd: unable to get major number\n");
    return -EBUSY;
  }

  /* Initialize the device structures. */
  for (i = r = 0; i < NOSPRD; i++)
    if (setup_device(&osprds[i], i) < 0)
      r = -EINVAL;

  if (r < 0) {
    printk(KERN_EMERG "osprd: can't set up device structures\n");
    osprd_exit();
    return -EBUSY;
  } else
    return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
  int i;
  for (i = 0; i < NOSPRD; i++)
    cleanup_device(&osprds[i]);
  unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
