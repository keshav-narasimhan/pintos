#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "threads/thread.h"

struct lock filesys_lock;

void syscall_init(void);

/* Userprog syscalls */
void our_sys_halt (void);
void our_sys_exit (int status);
tid_t our_sys_exec (const char *cmd_line);
int our_sys_wait (tid_t pid);
bool our_sys_create (const char *file, unsigned initial_size);
bool our_sys_remove (const char *file);
int our_sys_open (const char *file);
int our_sys_filesize (int fd);
int our_sys_read (int fd, void *buffer, unsigned size);
int our_sys_write (int fd, const void *buffer, unsigned size);
void our_sys_seek (int fd, unsigned position);
unsigned our_sys_tell (int fd);
void our_sys_close (int fd);

/* Filesys syscalls */
bool our_sys_chdir (const char *dir);
bool our_sys_mkdir (const char *dir);
bool our_sys_readdir (int fd, char *name);
bool our_sys_isdir (int fd);
int our_sys_inumber (int fd);



#endif /* userprog/syscall.h */
