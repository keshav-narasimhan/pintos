#include "vm/frame.h"
#include "userprog/syscall.h"
#define NUM_USER_PAGES 367

/* initialize the frame table lock & the pointer for the clock eviction algorithm */
void frame_init() {
  lock_init(&FT_lock);
  clockLRU = 0;
}

/* free the frame table entry */
void free_FTE(void *kpage) {
  /* proper synchronization */
  lock_acquire(&FT_lock);

  /* get the frame table entry */
  FTE *fte = (FTE*)NULL; //get_FTE(kpage);
  for (int index = 0; index < NUM_USER_PAGES; index++) {
      if (FT[index] != (FTE*)NULL && FT[index]->kernel_page == kpage) {
          fte = FT[index];
          break;
      }
  }

  /* free kpage + clear page table entry + remove from frame table */
  palloc_free_page(fte->kernel_page);
  pagedir_clear_page(fte->owner->pagedir, fte->user_page);
  FT[fte->index] = (FTE*)NULL;
  free(fte);

  /* proper synchronization */
  lock_release(&FT_lock);
}

/* helper function to do the LRU clock algorithm */
int eviction_helper() {
  /* start the algorithm where we left off last time & obtain certain variables */
  int indexLRU = clockLRU;
  uint32_t *pagedir = FT[indexLRU]->owner->pagedir;
  void *kpage = FT[indexLRU]->kernel_page;
  int numTimes = 0;

  /* run the LRU clock algorithm */
  while (pagedir_is_accessed(pagedir, kpage) && numTimes < NUM_USER_PAGES) {
    pagedir_set_accessed(pagedir, kpage, false);
    indexLRU = (indexLRU + 1) % NUM_USER_PAGES;
    pagedir = FT[indexLRU]->owner->pagedir;
    kpage = FT[indexLRU]->kernel_page;
    numTimes++;
  }

  /* update clockLRU */
  clockLRU = (indexLRU + 1) % NUM_USER_PAGES;
  return indexLRU;
}

/* add a new frame table entry */
FTE *add_FTE(void *upage) {
  /* is there any index in the frame table which is open to allocate for the upage? */
  int frame_open_ptr = -1;
  struct thread *new_owner = thread_current();

  /* check to see if there is any NULL entry in the frame table */
  for (int index = 0; index < NUM_USER_PAGES; index++) {
    if (FT[index] == (FTE*)NULL) {
      frame_open_ptr = index;
      break;
    }
  }

  /* there is no room in the frame table currently --> eviction algorithm! */
  if (frame_open_ptr == -1) {
    /* find the index to evict in the frame table and obtain the FT entry */
    frame_open_ptr = eviction_helper();
    FTE *prev_FTE = FT[frame_open_ptr];

    /* get the thread of the previous FT entry */
    struct thread *old_owner = prev_FTE->owner;

    /* proper synchronization */
    lock_acquire(&FT_lock);

    /* get the directory of the new owner and obtain the prev SPT entry */
    uint32_t *pagedir = new_owner->pagedir;
    SPTE *spte = get_SPTE(&old_owner->spt, prev_FTE->user_page);

    /* proper synchronization */
    lock_acquire(&old_owner->spt_lock);

    /* spte is no longer in the FT table */
    spte->frame_index = -1;

    /* if the page was dirty, put it in the swap block, else it was on the disk */
    if (pagedir_is_dirty(pagedir, prev_FTE->kernel_page)) {
      spte->swap_index = swap(prev_FTE->kernel_page, -1);
      spte->pageloc = SWAP;
    } else {
      spte->pageloc = DISK;
    }

    /* proper synchronization */
    lock_release(&old_owner->spt_lock);

    /* free the kpage & clear the page table entry and clear space in the frame table */
    palloc_free_page(prev_FTE->kernel_page);
    pagedir_clear_page(old_owner->pagedir, prev_FTE->user_page);
    FT[frame_open_ptr] = (FTE*)NULL;
    free(prev_FTE);

    /* proper synchronization */
    lock_release(&FT_lock);
  }

  /* proper synchronization */
  lock_acquire(&FT_lock);

  /* get a kpage + allocate space for an FT entry */
  void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  FTE *new_fte = malloc(sizeof(FTE));

  /* exit if the memory allocation failed */
  if (new_fte == (FTE*)NULL) {
    palloc_free_page(kpage);
    lock_release(&FT_lock);
    our_sys_exit(-1);
  }

  /* set attributes of the new FT entry */
  new_fte->user_page = upage;
  new_fte->kernel_page = kpage;
  new_fte->owner = new_owner;
  new_fte->index = frame_open_ptr;

  /* get the SPT entry associated with the upage */
  SPTE *spte = get_SPTE(&new_owner->spt, upage);
  spte->frame_index = frame_open_ptr;

  /* add to frame table */
  FT[frame_open_ptr] = new_fte;

  /* proper synchronization */
  lock_release(&FT_lock);
  return FT[frame_open_ptr];
}

