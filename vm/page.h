#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* where is the page located? */
typedef enum page_loc_t {
    MEMORY,                
    DISK,                  
    SWAP                   
} page_loc;

/* struct for SPT entries */
typedef struct spte_t {
  /* straight from load_segment */
  struct file *file;            
  int read_bytes;
  int zero_bytes;
  off_t ofs;
  bool rd_only;

  /* necessary for SPT Hash Table */
  struct hash_elem elem;

  /* upage */
  void *upage;

  /* where is the page located */
  int frame_index;
  int swap_index;
  page_loc pageloc;
} SPTE;

/* functions needed for Hash Table functions */
unsigned hash_func(const struct hash_elem *h_elem, void *aux UNUSED);
bool less_func(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
void destroy_func(struct hash_elem *helem, void *aux);

/* functions to add SPT entries to SPT and to get existing SPT entries */
SPTE *get_SPTE(struct hash *spt, void *upage);
SPTE *add_SPTE(struct hash *spt, struct file *file, off_t ofs, void *upage, 
              uint32_t read_bytes, uint32_t zero_bytes, bool read_only, bool stack_page);

#endif
