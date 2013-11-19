#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);

static struct file *find_file_by_fd (int fd);
static struct fd_elem *find_fd_elem_by_fd (int fd);
 
struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
  struct list_elem thread_elem;
};

/* Serializes file system operations. */
static struct lock fs_lock;
static struct list file_list;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */

static void
syscall_handler (struct intr_frame *f UNUSED)
{
typedef int syscall_function (int, int, int);

  
  struct syscall 
    {
      size_t arg_cnt;           
      syscall_function *func;   
    };

  static const struct syscall syscall_table[] =
    {
      {0, (syscall_function *) sys_halt},
      {1, (syscall_function *) sys_exit},
      {1, (syscall_function *) sys_exec},
      {1, (syscall_function *) sys_wait},
      {2, (syscall_function *) sys_create},
      {1, (syscall_function *) sys_remove},
      {1, (syscall_function *) sys_open},
      {1, (syscall_function *) sys_filesize},
      {3, (syscall_function *) sys_read},
      {3, (syscall_function *) sys_write},
      {2, (syscall_function *) sys_seek},
      {1, (syscall_function *) sys_tell},
      {1, (syscall_function *) sys_close},
    };

  const struct syscall *sc;
  unsigned calln;
  int args[3];

  /* Get the system call. */
  copy_in (&calln, f->esp, sizeof calln);
  if (calln >= sizeof syscall_table / sizeof *syscall_table)
    thread_exit ();
  sc = syscall_table + calln;

  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);


  f->eax = sc->func (args[0], args[1], args[2]);
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  thread_current ()->wait_status->exit_code = exit_code;
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
	tid_t i;
	char *f = copy_in_string(ufile);

	lock_acquire(&fs_lock);
	i=process_execute(ufile);
	lock_release(&fs_lock);
	palloc_free_page(f);
	return i;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
 return process_wait(child);
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{
  off_t size = (int32_t)initial_size;
  int result = 0;
  if(ufile != NULL) {
    lock_acquire(&fs_lock);
    result = filesys_create(ufile, size);
    lock_release(&fs_lock);
  }
  return result;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{
  int result = 0;
  if(ufile != NULL) {
    lock_acquire(&fs_lock);
    result = filesys_remove(ufile);
    lock_release(&fs_lock);
  }
  return result;
}
 
/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };
 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
 
  fd = malloc (sizeof *fd);
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      fd->file = filesys_open (kfile);
      if (fd->file != NULL)
        {
          struct thread *cur = thread_current ();
          handle = fd->handle = cur->next_handle++;
          list_push_front (&cur->fds, &fd->elem);
        }
      else 
        free (fd);
      lock_release (&fs_lock);
    }
  
  palloc_free_page (kfile);
  return handle;
}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
struct thread *ct = thread_current();
struct list_elem *l;

for(l=list_begin(&ct->fds); l!=list_end(&ct->fds); l=list_next(l)){
	struct file_descriptor *fd;
	fd = list_entry(l, struct file_descriptor, elem);
	if(fd->handle == handle)
		return fd;
}
  thread_exit ();
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
  struct file_descriptor *fd = lookup_fd(handle);
  int s;
  lock_acquire(&fs_lock);
  s = file_length(fd->file);
  lock_release(&fs_lock);

  return s;
  
}
 
/* Read system call. */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  struct file * f;
  unsigned i;
  int ret;
  
  ret = -1; /* Initialize to zero */
  lock_acquire (&fs_lock);
  if (fd == STDIN_FILENO) /* stdin */
    {
      for (i = 0; i != size; ++i)
        *(uint8_t *)(buffer + i) = input_getc ();
      ret = size;
      goto done;
    }
  else if (fd == STDOUT_FILENO) /* stdout */
      goto done;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size)) /* bad ptr */
    {
      lock_release (&fs_lock);
      sys_exit (-1);
    }
  else
    {
      f = find_file_by_fd (fd);
      if (!f)
        goto done;
      ret = file_read (f, buffer, size);
    }
    
done:    
  lock_release (&fs_lock);
  return ret;
}

static struct file *
find_file_by_fd (int fd)
{
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

static struct fd_elem *
find_fd_elem_by_fd (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  
  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}

static int
sys_write (int fd, void *buffer, unsigned length)
{
  struct file * f;
  int ret;
  
  ret = -1;
  lock_acquire (&fs_lock);
  if (fd == STDOUT_FILENO) /* stdout */
    putbuf (buffer, length);
  else if (fd == STDIN_FILENO) /* stdin */
    goto done;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    {
      lock_release (&fs_lock);
      sys_exit (-1);
    }
  else
    {
      f = find_file_by_fd (fd);
      if (!f)
        goto done;
        
      ret = file_write (f, buffer, length);
    }
    
done:
  lock_release (&fs_lock);
  return ret;
}
 
/* Seek system call. */
static int
sys_seek (int fd, unsigned pos)
{
  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1;
  file_seek (f, pos);
  return 0; /* Not used */
}
 
/* Tell system call. */
static int
sys_tell (int fd)
{
  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1;
  return file_tell (f);
}
 
/* Close system call. */
static int
sys_close (int handle) 
{
  struct file_descriptor *fd = find_fd_elem_by_fd(handle);
  int result = 0;
  if(fd) {
    lock_acquire(&fs_lock);
    file_close(fd->file);
    free(fd);
    lock_release(&fs_lock);
  }
  return result;
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e, *next;

  lock_acquire (&fs_lock);

  for (e = list_begin (&cur->fds); e != list_end (&cur->fds); e = next)
    {
    struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
    file_close (fd->file);
    next = list_remove (e);
    free (fd);
    }

  lock_release (&fs_lock);

  return;
}
