#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <list.h>
#include <stdbool.h>

#include "devices/block.h"
#include "filesys/off_t.h"

struct bitmap;

/* On-disk inode.
 * Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
    block_sector_t start;       /* First data sector. */
    off_t          length;      /* File size in bytes. */
    unsigned       magic;       /* Magic number. */
    // uint32_t       unused[125]; /* Not used. */

    /* pointers */
    block_sector_t direct_pointers[121];
    block_sector_t single_indirect_pointer;
    block_sector_t double_indirect_pointer;

    /* directory or file? */
    bool is_a_directory;
    block_sector_t p;
};

/* In-memory inode. */
struct inode {
    struct list_elem  elem;           /* Element in inode list. */
    block_sector_t    sector;         /* Sector number of disk location. */
    int               open_cnt;       /* Number of openers. */
    bool              removed;        /* True if deleted, false otherwise. */
    int               deny_write_cnt; /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;           /* Inode content. */
};

void inode_init(void);

/* change to specify whether file or directory */
bool inode_create(block_sector_t, off_t, bool is_a_dir);

struct inode *inode_open(block_sector_t);
struct inode *inode_reopen(struct inode *);
block_sector_t inode_get_inumber(const struct inode *);
void inode_close(struct inode *);
void inode_remove(struct inode *);
off_t inode_read_at(struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at(struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write(struct inode *);
void inode_allow_write(struct inode *);
off_t inode_length(const struct inode *);

/* new functions */
bool is_directory(struct inode *inode);
struct inode * inode_get_p(struct inode *inode);
bool add_p(block_sector_t parent, block_sector_t child);

#endif /* filesys/inode.h */
