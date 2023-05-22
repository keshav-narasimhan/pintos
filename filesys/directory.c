#include <list.h>
#include <stdio.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* useful recurring symbols */
#define CURRENT_WORKING_DIRECTORY "."
#define PARENT_OF_CWD ".."

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create(block_sector_t sector, size_t entry_cnt)
{
    return inode_create(sector, entry_cnt * sizeof(struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open(struct inode *inode)
{
    struct dir *dir = calloc(1, sizeof *dir);

    if (inode != NULL && dir != NULL) {
        dir->inode = inode;
        dir->pos = 0;
        return dir;
    } else {
        inode_close(inode);
        free(dir);
        return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root(void)
{
    return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen(struct dir *dir)
{
    return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close(struct dir *dir)
{
    if (dir != NULL) {
        inode_close(dir->inode);
        free(dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode(struct dir *dir)
{
    return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup(const struct dir *dir, const char *name,
       struct dir_entry *ep, off_t *ofsp)
{
    struct dir_entry e;
    size_t ofs;

    ASSERT(dir != NULL);
    ASSERT(name != NULL);

    for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
         ofs += sizeof e) {
        if (e.in_use && !strcmp(name, e.name)) {
            if (ep != NULL) {
                *ep = e;
            }
            if (ofsp != NULL) {
                *ofsp = ofs;
            }
            return true;
        }
    }
    return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup(const struct dir *dir, const char *name,
           struct inode **inode)
{
    struct dir_entry e;

    ASSERT(dir != NULL);
    ASSERT(name != NULL);

    if (strcmp(name, CURRENT_WORKING_DIRECTORY) == 0) { 
        struct dir *set_inode = inode_reopen(dir->inode);
        *inode = set_inode;
    } else if (lookup(dir, name, &e, NULL)) {
        *inode = inode_open(e.inode_sector);
    } else {
        *inode = NULL;
    }

    return *inode != NULL;
}

bool populateInode(struct dir *directory, char *name, struct inode **inode) {
    struct inode *parent;
    bool foundDirectory;

    /* is it not the parent of the CWD? */
    if (strcmp(name, PARENT_OF_CWD) != 0) {
        foundDirectory = dir_lookup(directory, name, inode);
        if (foundDirectory == false) {
            return foundDirectory;
        }
    } else {
        /* TODO */
        parent = get_p(directory->inode);
        *inode = parent;

        if (parent == (struct inode *)NULL) {
            return false;
        }
    }

    return true;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add(struct dir *dir, const char *name, block_sector_t inode_sector)
{
    struct dir_entry e;
    off_t ofs;
    bool success = false;

    ASSERT(dir != NULL);
    ASSERT(name != NULL);

    /* Check NAME for validity. */
    if (*name == '\0' || strlen(name) > NAME_MAX) {
        return false;
    }

    /* Check that NAME is not in use. */
    if (lookup(dir, name, NULL, NULL)) {
        goto done;
    }

    /* TODO */
    struct inode *dir_inode;
    block_sector_t inode_num;
    bool parent;

    dir_inode = dir_get_inode(dir);
    inode_num = inode_get_inumber(dir_inode);
    parent = add_p(inode_num, inode_sector);

    if (parent == false) { goto done; }

    /* Set OFS to offset of free slot.
     * If there are no free slots, then it will be set to the
     * current end-of-file.
     *
     * inode_read_at() will only return a short read at end of file.
     * Otherwise, we'd need to verify that we didn't get a short
     * read due to something intermittent such as low memory. */
    for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
         ofs += sizeof e) {
        if (!e.in_use) {
            break;
        }
    }

    /* Write slot. */
    e.in_use = true;
    strlcpy(e.name, name, sizeof e.name);
    e.inode_sector = inode_sector;
    success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
    return success;
}

/* checks to see if the directory is empty */
bool checkIfDirectoryIsEmpty(struct inode *inode) {
    /* get the directory from the specified inode */
    struct dir *directory = dir_open(inode);
    ASSERT(directory != (struct dir*)NULL);

    /* size of a directory entry */
    struct dir_entry directory_entry;
    off_t dir_entry_size = sizeof(directory_entry);

    /* loop through */
    size_t offset = 0;
    while (inode_read_at(directory->inode, &directory_entry, dir_entry_size, offset) == dir_entry_size) {
        if (directory_entry.in_use == true) {
            dir_close(directory);
            return false;
        }

        offset += dir_entry_size;
    }

    /* if we have gotten all the way through, the directory was empty */
    dir_close(directory);
    return true;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove(struct dir *dir, const char *name)
{
    struct dir_entry e;
    struct inode *inode = NULL;
    bool success = false;
    off_t ofs;

    ASSERT(dir != NULL);
    ASSERT(name != NULL);

    /* Find directory entry. */
    if (!lookup(dir, name, &e, &ofs)) {
        goto done;
    }

    /* Open inode. */
    inode = inode_open(e.inode_sector);
    if (inode == NULL) {
        goto done;
    }

    /* TODO */
    if (is_directory(inode) == true) {
        if (inode->open_cnt > 1) {
            goto done;
        }

        if (checkIfDirectoryIsEmpty(inode) == false) {
            goto done;
        }
    }
    // /* Directory to be deleted is nonempty */
    // if (inode_is_dir)
    // if (inode_is_dir(inode) && !dir_is_empty(inode))
    //     goto done;

    /* Erase directory entry. */
    e.in_use = false;
    if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e) {
        goto done;
    }

    /* Remove inode. */
    inode_remove(inode);
    success = true;

done:
    inode_close(inode);
    return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir(struct dir *dir, char name[NAME_MAX + 1])
{
    struct dir_entry e;

    while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
        dir->pos += sizeof e;
        if (e.in_use) {
            strlcpy(name, e.name, NAME_MAX + 1);
            return true;
        }
    }
    return false;
}

/* open the directory given a path (absolute or relative) */
struct dir* open_directory_given_path(const char *path) {
    /* get current thread */
    struct thread *curr_thread = thread_current();
    struct dir *curr_thread_cwd = curr_thread->current_working_directory;

    /* initialize directory_to_open */
    struct dir *directory_to_open = (struct dir*)NULL;
    if (strcmp(path[0], '/') != 0) {
        /* relative path */
        if (curr_thread_cwd == (struct dir*)NULL) {
            directory_to_open = dir_open_root();
        } else {
            directory_to_open = dir_reopen(curr_thread_cwd);
        }
    } else {
        /* absolute path */
        directory_to_open = dir_open_root();
    }

    /* make a copy of the path in order to tokenize */
    int len_path = strlen(path);
    char copy_path [len_path];
    strlcpy(copy_path, path, len_path + 1);

    /* variables used by strtok_r() and the while loop */ 
    char **savePtr;
    char *token_path = strtok_r(copy_path, "/", savePtr);
    struct inode *inode;
    struct dir *new_dir;

    /* loop through all tokens (files) */
    while(token_path != (char*)NULL) {
        inode = (struct inode *)NULL;

        /* if the file or directory doesn't exist within the cwd, then return an error occured */
        if (dir_lookup(directory_to_open, token_path, &inode) == false) {
            dir_close(directory_to_open);
            return (struct dir*)NULL;
        }

        /* if here, inode has been set to the inode for the file named token_path */
        new_dir = dir_open(inode);
        if (new_dir == (struct dir*)NULL) {
            dir_close(directory_to_open);
            return (struct dir*)NULL;
        }

        /* move to next iteration of the loop */
        dir_close(directory_to_open);
        directory_to_open = new_dir;
        token_path = strtok_r(NULL, "/", savePtr);
    }

    /* make sure we are not returning any directories that have already been removed */
    inode = dir_get_inode(directory_to_open);
    // if (inode->removed == true) {
    //     dir_close(directory_to_open);
    //     return (struct dir*)NULL;
    // }

    /* return the directory */
    return directory_to_open;
}
