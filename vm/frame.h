#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

/* struct for FT entries */
typedef struct fte_t {
  void *kernel_page;     
  void *user_page;       
  int index;            
  struct thread *owner;  
} FTE;

/* functions to initialize/free FT entries + eviction algorithm helper method */
void frame_init();
void free_FTE(void *kpage);
int eviction_helper();

/* allocate FT entries */
FTE *add_FTE(void *upage);

/* global variables used in frame.c */
FTE *FT[367];
struct lock FT_lock;
int clockLRU;

#endif

