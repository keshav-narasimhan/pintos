#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* initializer function */
void swap_init();

/* copy data into swap block OR remove page */
int swap(void *upage, int swap_index);

struct block* swap_blk;             /* swap block */
struct bitmap *swap_bitmap;         /* swap bitmap */
struct lock swap_lock;              /* lock for swaps */

#endif
