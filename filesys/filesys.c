#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"

#define INVALID_NAME ""
#define SLASH "/"
#define CURRENT_WORKING_DIRECTORY "."
#define PARENT ".."

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init(bool format)
{
    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL) {
        PANIC("No file system device found, can't initialize file system.");
    }

    inode_init();
    free_map_init();

    if (format) {
        do_format();
    }

    free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done(void)
{
    free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create(const char *name, off_t initial_size, bool is_a_dir)
{

    if (strcmp(name, INVALID_NAME) == 0) {
        return false;
    }

    /* initialize variables */
    char *filename;
    block_sector_t inode_sector;
    struct dir *dir;
    bool checkDirectory;
    bool success;

    /* populate variables */
    filename = getFileNameFromPath(name);
    checkDirectory = (filename != CURRENT_WORKING_DIRECTORY) && (filename != PARENT);
    inode_sector = 0;
    dir = getDirectoryFromPath(name);

    if (checkDirectory == true) {
        success = (dir != NULL
                && free_map_allocate(1, &inode_sector)
                && inode_create(inode_sector, initial_size, is_a_dir)
                && dir_add(dir, filename, inode_sector));
    } else {
        success = false;
    }

    if (!success && inode_sector != 0) {
        free_map_release(inode_sector, 1);
    }
    dir_close(dir);

    return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
    if (strcmp(name, INVALID_NAME) == 0) { return (struct file*)NULL; }

    // struct dir *dir = dir_open_root();
    struct dir *directory = getDirectoryFromPath(name);
    char *filename = getFileNameFromPath(name);
    struct inode *inode = NULL;

    if (directory != NULL) {
        dir_lookup(directory, filename, &inode);
    }
    dir_close(directory);

    return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove(const char *name)
{
    struct dir *directory = (struct dir*)NULL;
    char *filename = (char*)NULL;
    // struct dir *dir = dir_open_root();

    directory = getDirectoryFromPath(name);
    filename = getFileNameFromPath(name);

    bool ableToRemove = dir_remove(directory, filename);
    bool success = directory != NULL && ableToRemove;

    dir_close(directory);

    return success;
}

char* getFileNameFromPath(char *fname) {
    if (strcmp(fname, SLASH) == 0) {
        char *cwd = (char*)malloc(sizeof(char) * 2);
        cwd[0] = '.';
        cwd[1] = 0;
        return cwd;
    }

    /* make a copy */
    int length = sizeof(char) * strlen(fname) + 1;
    char *fname_copy = (char*)malloc(length);
    memcpy(fname_copy, fname, length);

    /* used by strtok_r() */
    char *savePtr;
    char *currToken = strtok_r(fname_copy, SLASH, &savePtr);
    char *fileToken = (char*)NULL;

    while (currToken != (char*)NULL) {
        fileToken = currToken;
        currToken = strtok_r(NULL, SLASH, &savePtr);
    }

    length = sizeof(char) * strlen(fileToken) + 1;
    char *return_file = (char*)malloc(length);
    memcpy(return_file, fileToken, length);

    free(fname_copy);
    return return_file;
}

struct dir* getDirectoryFromPath(char *fname) {
    /* make a copy of fname to parse */
    int length = strlen(fname) + 1;
    char *fname_copy = (char*)malloc(length);
    memcpy(fname_copy, fname, length);

    /* parse and obtain the first token */
    char *savePtr;
    char *currToken = strtok_r(fname_copy, SLASH, &savePtr);
    char *nextToken = (char*)NULL;

    if (currToken != (char*)NULL) {
        nextToken = strtok_r(NULL, SLASH, &savePtr);
    }

    struct thread *currThr = thread_current();
    struct dir *cwd = currThr->current_working_directory;
    struct dir *dirToOpen = (struct dir*)NULL;

    /* used in while loop */
    bool dirExists;
    bool isDir;
    struct inode *i;

    if (fname_copy[0] == '/') {
        dirToOpen = dir_open_root();
    } else if (cwd == NULL) {
        dirToOpen = dir_open_root();
    } else {
        dirToOpen = dir_reopen(cwd);
    }

    while(nextToken != NULL) {
        if (strcmp(currToken, CURRENT_WORKING_DIRECTORY) > 0) {
            dirExists = dir_lookup(dirToOpen, currToken, &i);
            isDir = is_directory(i);

            if (dirExists == false) {
                return (struct dir*)NULL;
            } else if (isDir) {
                dir_close(dirToOpen);
                dirToOpen = dir_open(i);
            } else {
                inode_close(i);
            }
        }

        currToken = nextToken;
        nextToken = strtok_r(NULL, SLASH, &savePtr);
    }


    /* return the directory */
    free(fname_copy);
    return dirToOpen;
}

/* Formats the file system. */
static void
do_format(void)
{
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16)) {
        PANIC("root directory creation failed");
    }
    free_map_close();
    printf("done.\n");
}

