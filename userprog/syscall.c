#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

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

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}


static void
syscall_handler(struct intr_frame *f UNUSED)
{
    /* // Remove these when implementing syscalls
    printf("system call!\n");

    thread_exit();
    */

    // get the user stack pointer and get the call number
    int call_no;
    uint32_t *user_sp = (uint32_t*)f->esp;

    // set the stack pointer as a member of the current thread
    thread_current()->user_esp = user_sp;

    // error checking
    if (get_user((uint8_t*)user_sp) == -1 || !is_user_vaddr((const void*)user_sp)) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

    // get the call number
    call_no = (int)(*user_sp);

    switch(call_no) {
        case SYS_HALT: {
            our_sys_halt();
            break;
        }
        case SYS_EXIT: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int status = (int)(*(user_sp + 1));

            // execute the exit() syscall
            our_sys_exit(status);
            break;
        }
        case SYS_EXEC: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            const char *cmd_line = (const char*)(*((int*)user_sp + 1));

            // another check for errors
            if (cmd_line == (const char*)NULL) { f->eax = -1; our_sys_exit(-1); }

            // execute the exec() syscall
            f->eax = our_sys_exec(cmd_line);
            break;
        }
        case SYS_WAIT: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            tid_t tid = (*((tid_t*)user_sp + 1));

            // execute the wait() syscall
            f->eax = our_sys_wait(tid);
            break;
        }
        case SYS_CREATE: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 2)) == -1 || !is_user_vaddr((const void*)(user_sp + 2))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            const char *file = (const char*)(*((int*)user_sp + 1));
            unsigned initial_size = (*((unsigned*)user_sp + 2));

            // another check for errors
            if (file == (const char*)NULL) { f->eax = -1; our_sys_exit(-1); }

            // execute the create() syscall
            f->eax = our_sys_create(file, initial_size);
            break;
        }
        case SYS_REMOVE: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            const char *file = (const char*)(*((int*)user_sp + 1));

            // another check for errors
            if (file == (const char*)NULL) { f->eax = -1; our_sys_exit(-1); }

            // execute the remove() syscall
            f->eax = our_sys_remove(file);
            break;
        }
        case SYS_OPEN: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            const char *file = (const char*)(*((int*)user_sp + 1));

            // another check for errors
            if (file == (const char*)NULL) { f->eax = -1; our_sys_exit(-1); }

            // execute the open() syscall
            f->eax = our_sys_open(file);
            break;
        }
        case SYS_FILESIZE: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int fd = (int)(*(user_sp + 1));

            // execute the filesize() syscall
            f->eax = our_sys_filesize(fd);
            break;
        }
        case SYS_READ: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 2)) == -1 || !is_user_vaddr((const void*)(user_sp + 2))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 3)) == -1 || !is_user_vaddr((const void*)(user_sp + 3))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            int fd = (*((int*)user_sp + 1));
            void *buffer = (void*)(*((int*)user_sp + 2));
            unsigned size = (*((unsigned*)user_sp + 3));

            // another check for errors
            if (!is_user_vaddr(buffer)) { f->eax = -1; our_sys_exit(-1); }

            // execute the read() syscall and put the output in eax register
            f->eax = our_sys_read(fd, buffer, size);
            break;
        }
        case SYS_WRITE: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 2)) == -1 || !is_user_vaddr((const void*)(user_sp + 2))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 3)) == -1 || !is_user_vaddr((const void*)(user_sp + 3))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            int fd = (*((int*)user_sp + 1));
            void *buffer = (void*)(*((int*)user_sp + 2));
            unsigned size = (*((unsigned*)user_sp + 3));

            // another check for errors
            if (!is_user_vaddr(buffer)) { f->eax = -1; our_sys_exit(-1); }

            // execute the write() syscall and put the output in eax register
            f->eax = our_sys_write(fd, buffer, size);
            break;
        }
        case SYS_SEEK: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 2)) == -1 || !is_user_vaddr((const void*)(user_sp + 2))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain arguments
            int fd = (int)(*(user_sp + 1));
            unsigned position = (*((unsigned*)user_sp + 2));

            // execute the seek() syscall
            our_sys_seek(fd, position);
            break;
        }
        case SYS_TELL: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int fd = (int)(*(user_sp + 1));

            // execute the tell() syscall
            f->eax = our_sys_tell(fd);
            break;
        }
        case SYS_CLOSE: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int fd = (int)(*(user_sp + 1));

            // execute the close() syscall
            our_sys_close(fd);
            break;
        }
        case SYS_CHDIR: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            const char *dir = (const char*)(*((int*)user_sp + 1));

            // another check for errors
            if (!is_user_vaddr(dir)) { f->eax = -1; our_sys_exit(-1); }

            // execute the chdir() syscall
            f->eax = our_sys_chdir(dir);
            break;
        }
        case SYS_MKDIR: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            const char *dir = (const char*)(*((int*)user_sp + 1));

            // another check for errors
            if (!is_user_vaddr(dir)) { f->eax = -1; our_sys_exit(-1); }

            // execute the mkdir() syscall
            f->eax = our_sys_mkdir(dir);
            break;
        }
        case SYS_READDIR: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }
            if (get_user((uint8_t*)(user_sp + 2)) == -1 || !is_user_vaddr((const void*)(user_sp + 2))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain the arguments
            int fd = (*((int*)user_sp + 1));
            char *name = (char*)(*((int*)user_sp + 2));

            // another check for errors
            if (!is_user_vaddr(name)) { f->eax = -1; our_sys_exit(-1); }

            // execute the readdir() syscall and put the output in eax register
            f->eax = our_sys_readdir(fd, name);
            break;
        }
        case SYS_ISDIR: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int fd = (int)(*(user_sp + 1));

            // execute the isdir() syscall
            f->eax = our_sys_isdir(fd);
            break;
        }
        case SYS_INUMBER: {
            // error checking
            if (get_user((uint8_t*)(user_sp + 1)) == -1 || !is_user_vaddr((const void*)(user_sp + 1))) { f->eax = -1; our_sys_exit(-1);/*return;*/ }

            // obtain argument
            int fd = (int)(*(user_sp + 1));

            // execute the inumber() syscall
            f->eax = our_sys_inumber(fd);
            break;
        }
        default: {
            break;
        }
    }
}

/** Syscall Functions **/

/*
 * System Call: halt
 * Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h).
 * This should be seldom used, because you lose some information about possible deadlock situations, etc.
 */
void our_sys_halt (void) {
    shutdown_power_off();
}

/*
 * System Call: exit
 * Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it (see below), this is the status that will be returned.
 * Conventionally, a status of 0 indicates success and nonzero values indicate errors.
 */
void our_sys_exit (int status) {
    // get the current thread
    struct thread *curr = thread_current();

    /*
    // try and obtain the parent of this thread
    struct thread *parent = get_parent(curr->parent_tid);

    // parent exists!
    if (parent != (struct thread*)NULL) {
        // get the child processes of the parent
        struct list child_processes = parent->child_processes;

        // get the child_process struct that corresponds to curr
        struct child_process *curr_child = find_child(&child_processes, curr->tid);

        // unblock the semaphore
        sema_up(&(curr_child->exit_sema));
    }
    */
    // try this?
    // lock_acquire(&filesys_lock);
    file_close(curr->executable);
    // lock_release(&filesys_lock);

    // straight from lecture
    printf("%s: exit(%d)\n", curr->name, status);
    curr->exitStatus = status;
    thread_exit();
}

/*
 * System Call: exec
 * Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's
   program id (pid).
 * Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason.
 * Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded
   its executable.
 * You must use appropriate synchronization to ensure this.
 */

tid_t our_sys_exec (const char *cmd_line) {
    // check to see if each byte in cmd_line is valid
    uint8_t *cmd_ptr = (uint8_t*)cmd_line;
    int index = 0;
    int segfault;
    while (index < strlen(cmd_line)) {
        segfault = get_user((const uint8_t*)cmd_ptr);
        if (segfault == -1) { return -1; }

        cmd_ptr += sizeof(uint8_t);
        index++;
    }

    // make a copy of cmd_line
    const char *cmd_cpy = malloc(sizeof(char) * (strlen(cmd_line) + 1));
    strlcpy(cmd_cpy, cmd_line, strlen(cmd_line) + 1);

    // call process execute to create a new child thread to execute cmd_line
    tid_t child_tid = process_execute(cmd_cpy);
    free(cmd_cpy);

    // try and find the child associated with child_tid (if not in all_list, we know it didn't successfully load)
    struct thread *find_child = get_thread(child_tid);
    if (find_child == (struct thread*)NULL) { return -1; }

    // return the tid if successfully loaded
    return child_tid;
}

/*
 * System Call: wait
 * Waits for a child process pid and retrieves the child's exit status.
 * If pid is still alive, waits until it terminates.
 * Then, returns the status that pid passed to exit.
 * If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1.
 * It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the
   parent calls wait, but the kernel must still allow the parent to retrieve its child's exit status, or learn that the
   child was terminated by the kernel.
 * wait must fail and return -1 immediately if any of the following conditions is true:
        - pid does not refer to a direct child of the calling process.
          pid is a direct child of the calling process if and only if the calling process received pid as a return value
          from a successful call to exec.

          Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C,
          even if B is dead.
          A call to wait(C) by process A must fail.
          Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.

        - The process that calls wait has already called wait on pid.
          That is, a process may wait for any given child at most once.
 * Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some
   or all of their children.
   Your design should consider all the ways in which waits can occur.
   All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, and
   regardless of whether the child exits before or after its parent.
 * You must ensure that Pintos does not terminate until the initial process exits.
   The supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main() (in threads/init.c).
   We suggest that you implement process_wait() according to the comment at the top of the function and then implement the
   wait system call in terms of process_wait().
 * Implementing this system call requires considerably more work than any of the rest.
 */
int our_sys_wait (tid_t pid) {
    // return -1;
    return process_wait(pid);
}

/*
 * System Call: create
 * Creates a new file called file initially initial_size bytes in size.
   Returns true if successful, false otherwise.
   Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.
 */
bool our_sys_create (const char *file, unsigned initial_size) {
    if (file == (const char*)NULL) { return false; }

    // check to see if each byte in file is valid
    uint8_t *file_ptr = (uint8_t*)file;
    int index = 0;
    int segfault;
    while (index < strlen(file)) {
        segfault = get_user((const uint8_t*)file_ptr);
        if (segfault == -1) { return false; }

        file_ptr += sizeof(uint8_t);
        index++;
    }

    // utilize filesys command to create the file and return its success
    lock_acquire(&filesys_lock);
    bool successful_create = filesys_create(file, initial_size, false);
    lock_release(&filesys_lock);
    return successful_create;
}

/*
 * System Call: remove
 * Deletes the file called file.
 * Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
 * See Removing an Open File, for details.
 */
bool our_sys_remove (const char *file) {
    lock_acquire(&filesys_lock);
    bool rem = filesys_remove(file);
    lock_release(&filesys_lock);

    return rem;
}

/*
 * System Call: open
 * Opens the file called file.
   Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
 * File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO)
   is standard output.
   The open system call will never return either of these file descriptors, which are valid as system call arguments only as
   explicitly described below.
 * Each process has an independent set of file descriptors.
   File descriptors are not inherited by child processes.
 * When a single file is opened more than once, whether by a single process or different processes, each open returns a new
   file descriptor.
   Different file descriptors for a single file are closed independently in separate calls to close and they do not share a
   file position.
 */
int our_sys_open (const char *file) {
    // check to see if each byte in file is valid
    uint8_t *file_ptr = (uint8_t*)file;
    int index = 0;
    int segfault;
    while (index < strlen(file)) {
        segfault = get_user((const uint8_t*)file_ptr);
        if (segfault == -1) { return -1; }

        file_ptr += sizeof(uint8_t);
        index++;
    }

    // obtain the file opened & do trivial error checking
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    lock_release(&filesys_lock);
    if (f == (struct file*)NULL) { return -1; }

    // if (check_executable(f, file)) { file_deny_write(f); }

    // deny writes to the file? --> just this doesn't work
    // file_deny_write(f);

    // initialize a new file descriptor struct
    struct thread *curr = thread_current();
    struct file_descriptor *new_fd = init_fd(f, curr->next_fd);
    curr->next_fd++;

    // insert into curr's file descriptor table
    list_push_back(&(curr->fdtab), &(new_fd->elem));

    // return the file descriptor
    return new_fd->fd;
}

/*
 * System Call: filesize
 * Returns the size, in bytes, of the file open as fd.
 */
int our_sys_filesize (int fd) {
    // get the file descriptor for the current thread
    struct thread *curr = thread_current();
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);

    // if fd isn't in the list, return -1
    if (file_des == (struct file_descriptor*)NULL) { return -1; }

    // return the file length by utilizing file_length() function
    lock_acquire(&filesys_lock);
    int len = file_length(file_des->f);
    lock_release(&filesys_lock);

    return len;
}

/*
 * System Call: read
 * Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition
   other than end of file).
   Fd 0 reads from the keyboard using input_getc().
 */
int our_sys_read (int fd, void *buffer, unsigned size) {
    // check to see if each byte in buffer is valid
    uint8_t *buf_ptr = (uint8_t*)buffer;
    unsigned buf_index = 0;
    int segfault;
    while (buf_index <= size) {
        segfault = get_user(buf_ptr);
        if (segfault == -1) { return -1; }
        buf_ptr += sizeof(uint8_t);
        buf_index++;
    }

    // read from STDIN
    if (fd == 0) {
        buf_ptr = (uint8_t*)buffer;
        buf_index = 0;

        // utilize input_getc() to fill buffer
        while (buf_index < size) {
            buf_ptr[buf_index] = input_getc();
            buf_index++;
        }

        buf_ptr[buf_index] = 0;
        return size;
    }

    // get the file descriptor corresponding to fd
    struct thread *curr = thread_current();
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);

    // if fd doesn't exist, then return -1
    if (file_des == (struct file_descriptor*)NULL) { return -1; }

    // return the number of bytes read
    lock_acquire(&filesys_lock);
    int len = file_read(file_des->f, buffer, size);
    lock_release(&filesys_lock);

    return len;
}

/*
 * System Call: write
 * Writes size bytes from buffer to the open file fd.
   Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
 * Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system.
   The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written,
   or 0 if no bytes could be written at all.
 * Fd 1 writes to the console.
   Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not
   bigger than a few hundred bytes. (It is reasonable to break up larger buffers.)
   Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human
   readers and our grading scripts.
 */
int our_sys_write (int fd, const void *buffer, unsigned size) {
    // trivial error checking
    if (fd <= 0) { return -1; }
    if (size < 0) { return -1; }

    // check to see if each byte in buffer is valid
    uint8_t *buf_ptr = (uint8_t*)buffer;
    unsigned buf_index = 0;
    int segfault;
    while (buf_index <= size) {
        segfault = get_user(buf_ptr);
        if (segfault == -1) { return -1; }
        buf_ptr += sizeof(uint8_t);
        buf_index++;
    }

    // write to STDOUT
    if (fd == 1) {
        lock_acquire(&filesys_lock);
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    /** test below --> writing to a file instead of STDOUT **/

    // get the file corresponding to fd (if the file isn't open return -1)
    struct thread *curr = thread_current();
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return -1; }

    // write to the file
    lock_acquire(&filesys_lock);
    int num_bytes_written = file_write(file_des->f, buffer, size);
    lock_release(&filesys_lock);

    return num_bytes_written;
}

/*
 * System Call: seek
 * Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
   (Thus, a position of 0 is the file's start.)
 * A seek past the current end of a file is not an error.
   A later read obtains 0 bytes, indicating end of file.
   A later write extends the file, filling any unwritten gap with zeros.
   (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.)
   These semantics are implemented in the file system and do not require any special effort in system call implementation.
 */
void our_sys_seek (int fd, unsigned position) {
    struct thread *curr = thread_current();
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return; }

    lock_acquire(&filesys_lock);
    file_seek(file_des->f, position);
    lock_release(&filesys_lock);
}

/*
 * System Call: tell
 * Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of
   the file.
 */
unsigned our_sys_tell (int fd) {
    struct thread *curr = thread_current();
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return 0; }
    
    lock_acquire(&filesys_lock);
    int tell = file_tell(file_des->f);
    lock_release(&filesys_lock);

    return tell;
}

/*
 * System Call: close
 * Closes file descriptor fd.
   Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for
   each one.
 */
void our_sys_close (int fd) {
    // get the current thread
    struct thread *curr = thread_current();

    // obtain the file descriptor corresponding to fd (return if nothing to close)
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return; }

    // close the file
    struct file *file = file_des->f;
    lock_acquire(&filesys_lock);
    file_close(file);
    lock_release(&filesys_lock);

    list_remove(&(file_des->elem));
    free(file_des);
}

/* 
 * System Call: chdir
 * Changes the current working directory of the process to dir, which may be relative or absolute. 
 * Returns true if successful, false on failure.
 */
bool our_sys_chdir (const char *dir) {
    // check to see if each byte in buffer is valid
    uint8_t *buf_ptr = (uint8_t*)dir;
    unsigned buf_index = 0;
    int size = strlen(dir);
    int segfault;
    while (buf_index <= size) {
        segfault = get_user(buf_ptr);
        if (segfault == -1) { return -1; }
        buf_ptr += sizeof(uint8_t);
        buf_index++;
    }

    /* proper synchronization */
    lock_acquire(&filesys_lock);


    int length = strlen(dir) + 3;
    int index = strlen(dir);
    char *parse_copy = (char*)malloc(length);
    memcpy(parse_copy, dir, length - 2);

    /* populate path */
    parse_copy[index] = '/';
    index += 1;
    parse_copy[index] = '.';
    index += 1;
    parse_copy[index] = 0;
    index += 1;

    struct thread *curr_thr = thread_current();
    struct dir *cwd = curr_thr->current_working_directory;

    struct dir *directory = getDirectoryFromPath(parse_copy);
    if (directory == NULL) {
        lock_release(&filesys_lock);
        return false;
    } else {
        dir_close(cwd);
        cwd = directory;
        curr_thr->current_working_directory = cwd;

        /* proper synchronization */
        lock_release(&filesys_lock);
        return true;
    }
}

/*
 * System Call: mkdir
 * Creates the directory named dir, which may be relative or absolute. 
 * Returns true if successful, false on failure. Fails if dir already exists or if any directory name in dir, besides the last, 
 * does not already exist. That is, mkdir("/a/b/c") succeeds only if /a/b already exists and /a/b/c does not.
 */
bool our_sys_mkdir (const char *dir) {
    // check to see if each byte in buffer is valid
    uint8_t *buf_ptr = (uint8_t*)dir;
    unsigned buf_index = 0;
    int size = strlen(dir);
    int segfault;
    while (buf_index <= size) {
        segfault = get_user(buf_ptr);
        if (segfault == -1) { return -1; }
        buf_ptr += sizeof(uint8_t);
        buf_index++;
    }

    lock_acquire(&filesys_lock);

    bool success_mkdir = filesys_create(dir, 512, true);

    lock_release(&filesys_lock);

    return success_mkdir;
}

/*
 * System Call: readdir
 * Reads a directory entry from file descriptor fd, which must represent a directory. 
 * If successful, stores the null-terminated file name in name, which must have room for READDIR_MAX_LEN + 1 bytes, and returns 
 * true. If no entries are left in the directory, returns false. and .. should not be returned by readdir.
 *
 * If the directory changes while it is open, then it is acceptable for some entries not to be read at all or to be read multiple 
 * times. Otherwise, each directory entry should be read once, in any order.
 *
 * READDIR_MAX_LEN is defined in lib/user/syscall.h. If your file system supports longer file names than the basic file system, 
 * you should increase this value from the default of 14.
 */
bool our_sys_readdir (int fd, char *name) {
    // return false;

    struct thread *curr = thread_current();
    
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return false; }

    struct file *file = file_des->f;
    struct inode *inode = file_get_inode(file);
    if (is_directory(inode)) {
        if (dir_readdir(file->ifDirectory, (char *) name)) {
            return true;
        }
    }
    return false;
}

/*
 * System Call: isdir
 * Returns true if fd represents a directory, false if it represents an ordinary file.
 */
bool our_sys_isdir (int fd) {
    // return false;

    struct thread *curr = thread_current();

    // obtain the file descriptor corresponding to fd (return if nothing to close)
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return false; }

    struct file *file = file_des->f;
    struct inode *inode = file_get_inode(file);
    
    
    return is_directory(inode);
}

/*
 * System Call: inumber
 * Returns the inode number of the inode associated with fd, which may represent an ordinary file or a directory.
 * An inode number persistently identifies a file or directory. 
 * It is unique during the file's existence. In Pintos, the sector number of the inode is suitable for use as an inode number.
 */
int our_sys_inumber (int fd) {
    // return 0;

    struct thread *curr = thread_current();

    // obtain the file descriptor corresponding to fd (return if nothing to close)
    struct file_descriptor *file_des = get_fd(&(curr->fdtab), fd);
    if (file_des == (struct file_descriptor*)NULL) { return -1; }

    struct file *file = file_des->f;
    struct inode *inode = file_get_inode(file);
    
    
    return inode_get_inumber(inode);
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
