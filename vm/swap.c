#include "vm/swap.h"
#define SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

/* initialize swap block, swap bitmap, and swap lock */
void swap_init() {
    /* initialize swap block/disk */
    swap_blk = block_get_role(BLOCK_SWAP);

    /* size of the number of swapped pages possible */
    size_t swap_size = block_size(swap_blk) / SECTORS;

    /* get the size of the bitmap */
    swap_bitmap = bitmap_create(swap_size);
    
    /* initialize the lock for swaps */
    lock_init(&swap_lock);
}

/* function to perform swaps */
int swap(void *upage, int currIndex) {
    /* do we read from this block or do we write to it? let's initialize it to a read first */
    void (*read_or_write)(struct block *, block_sector_t, const void *) = &block_read;

    /* proper synchronization */
    lock_acquire(&swap_lock);

    int newIndex;
    /* if the current swap index passed is a valid index, we know the swap block exists --> read from it & remove it! */
    if (currIndex >= 0) {
        bitmap_set(swap_bitmap, currIndex, false);
        newIndex = -1;
    }
    /* put into swap block --> write to swap block */
    else {
        currIndex = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
        newIndex = currIndex;
        read_or_write = &block_write;
    }

    /* proper synchronization */
    lock_release(&swap_lock);

    /* write to swap OR read into memory */
    for (int index = 0; index < SECTORS; index++) {
        (*read_or_write)(swap_blk, currIndex * SECTORS + index, upage + (BLOCK_SECTOR_SIZE * index));
    }

    /* return the new swap index to save in SPT entry for future use */
    return newIndex;
}
