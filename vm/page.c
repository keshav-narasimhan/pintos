#include "vm/page.h"
#include "userprog/syscall.h"

/* generate hash value for Hash Tables */
unsigned hash_func(const struct hash_elem *h, void *aux UNUSED) {
  /* straight from Stanford Pintos documentation */
  const SPTE *p = hash_entry(h, SPTE, elem);
  return hash_bytes(&p->upage, sizeof(p->upage));
}

/* Returns true if page a precedes page b. */
bool less_func(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
  /* straight from Stanford Pintos documentation */
  const SPTE *a = hash_entry(a_, SPTE, elem);
  const SPTE *b = hash_entry(b_, SPTE, elem);
  return a->upage < b->upage;
}

/* destructor function called by hash_destroy */
void destroy_func(struct hash_elem *h, void *aux UNUSED) {
  /* proper synchronization */
  lock_acquire(&thread_current()->spt_lock);

  /* get the SPT entry based on the passed hash_elem */
  SPTE *spte = hash_entry(h, SPTE, elem);

  /* set bits to false if on swap */
  if (spte->pageloc == SWAP) {
    bitmap_set(swap_bitmap, spte->swap_index, false);
  } 
  /* if in memory, free the kpage (if it exists) */
  if (spte->pageloc == MEMORY) {
    int frame_index = spte->frame_index;
    void *kpage = FT[frame_index]->kernel_page;
    if (kpage) { free_FTE(kpage); }
  }

  /* free the SPT entry */
  free(spte);
  /* proper synchronization */
  lock_release(&thread_current()->spt_lock);
}

/* get a SPT entry based on the upage passed */
SPTE *get_SPTE(struct hash *spt, void *upage) {
  /* dummy SPT entry for hash_find */
  SPTE spte;
  spte.upage = upage;

  /* get the hash_elem corresponding to spte (return null if not found) */
  struct hash_elem *h = hash_find(spt, &spte.elem);
  if (!h) { return (SPTE*)NULL; }

  /* return the SPT entry */
  return hash_entry(h, SPTE, elem);
}

/* add a new SPT entry to the SPT Hash Table */
SPTE *add_SPTE(struct hash *spt, struct file *file, off_t ofs, void *upage, uint32_t read_bytes,
              uint32_t zero_bytes, bool read_only, bool stack_page) {
  /* allocate a new SPT entry (exit if malloc fails) */
  SPTE *spte = malloc(sizeof(SPTE));
  if (!spte) { our_sys_exit(-1); }
  
  /* proper synchronization */
  lock_acquire(&thread_current()->spt_lock);
  
  /* initialize SPT entry's attributes */
  spte->swap_index = -1;
  spte->frame_index = -1;
  spte->file = file;
  spte->ofs = ofs;
  spte->upage = upage;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->rd_only = read_only;
  
  if (stack_page == true) {
    spte->pageloc = MEMORY;
  } else {
    spte->pageloc = DISK;
  }

  /* insert spte into SPT */
  hash_insert(spt, &spte->elem);

  /* proper synchronization */
  lock_release(&thread_current()->spt_lock);
  return spte;
}
