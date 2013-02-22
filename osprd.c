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

static struct file_operations osprd_blk_fops;


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
  char *algo;

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

static int trykey(osprd_info_t *d, char *key)
{
  return true;
}

static char *decrypt_entire(osprd_info_t *d, char *key)
{
  char *tmpAlgo = d->algo;
  
  //TODO: Add actual decryption
  
  d->encrypted = false;
  d->algo = 0;
  return tmpAlgo;
}

static void encrypt_entire(osprd_info_t *d, char *key, char *algo)
{
  //TODO: Add actual encryption
  
  d->encrypted = true;
  d->algo = algo;
  return;
}

static ssize_t eosprd_read(struct file *filp, char __user *buf, size_t length, 
    loff_t *offset)
{
  int numFailed;

//  eprintk("Password reading!\n");
  osprd_info_t *d = file2osprd(filp);

  if(*offset >= nsectors*SECTOR_SIZE)
    return 0;

  if(buf != 0)
  {
    numFailed = copy_to_user((void *)(buf), (const void *)(d->data + *offset), 
                             length);
  }
  else
  {
    return -EFAULT;
  }
  *offset += length;
  return length - numFailed;
}

static ssize_t eosprd_write(struct file *filp, const char __user *buf, 
    size_t length, loff_t *offset)
{
  int numFailed;
  
//  eprintk("Password writing!\n");
  osprd_info_t *d = file2osprd(filp);

  if(*offset >= nsectors*SECTOR_SIZE)
    return 0;

  if(buf != 0)
  {
    numFailed = copy_from_user((void *)(d->data + *offset), (const void*)(buf),
                               length);
  }
  else
  {
    return -EFAULT;
  }
  *offset += length;
  return length - numFailed;
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
  filp->f_flags |= O_SYNC;
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
       //eprintk("I released my write lock!\n");
     }
      struct pid_list *curr = d->pids;
      struct pid_list **prev = &(d->pids);
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

    // Zero out the key, for securty
    /*
    for (ci = filp->f_security; *ci != 0; ci++)
    {
      *ci = 0;
    }
    */
    // Free the saved key that this file was using
     /*
    kfree(filp->f_security);
    filp->f_security = NULL;
    */

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
          struct bad_ticket *curr = d->bad_head;
          struct bad_ticket **prev = &(d->bad_head);
          while(curr)
          {
            if(curr->ticket_val == d->ticket_tail)
            {
              *prev = curr->next;
              kfree(curr);
              d->ticket_tail++;
              curr = d->bad_head;
              prev = &(d->bad_head);
              continue;
            }
            prev = &(curr->next);
            curr = curr->next;
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
    struct pid_list *new = ((struct pid_list *)
      kmalloc(sizeof(struct pid_list),GFP_ATOMIC));
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
       //eprintk("I released my write lock!\n");
     }
      struct pid_list *curr = d->pids;
      struct pid_list **prev = &(d->pids);
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
    else if (trykey(d, key))
    {
      char *ci = key;
      int nChars = 0;
      char *keycopy;
      for ( ; *ci != 0; ci++)
      {
        nChars++;
      }

      // Save the key in kernel memory, give the file a pointer to it
      keycopy = kmalloc(nChars+1, GFP_ATOMIC);
      memcpy(keycopy, key, nChars+1);

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
    char *oldalgo = NULL;

    // If encrypted, decrypt it
    if (d->encrypted)
    {
      if (!(keys->oldkey))
      {
        return -EKEYREJECTED;
      }
      else if (!trykey(d, keys->oldkey))
      {
        return -EKEYREJECTED;
      }
      else 
      {
        oldalgo = decrypt_entire(d, keys->oldkey);
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
      // If a new algorithm is provided, use it.  Otherwise, use the previous
      //  one.  If there's a new nor an old algorithm, that's an error.
      char *algo = oldalgo;
      if (keys->algo)
        algo = keys->algo;
      if (!algo)
      {
        return -ENOSYS;
      }
        
      encrypt_entire(d, keys->newkey, NULL);
    }


    // Success!
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
  d->algo = 0;
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

static void osprd_exit(void);


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
