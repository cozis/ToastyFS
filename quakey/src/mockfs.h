#ifndef MOCKFS_INCLUDED
#define MOCKFS_INCLUDED

#include <stdbool.h>

#define MOCKFS_NAME_SIZE (1<<7)

enum {
    MOCKFS_ERRNO_SUCCESS = 0,
    MOCKFS_ERRNO_NOENT = -1,     // No such file or directory
    MOCKFS_ERRNO_PERM = -2,      // Operation not permitted
    MOCKFS_ERRNO_NOMEM = -3,     // Out of memory
    MOCKFS_ERRNO_NOTDIR = -4,    // Not a directory
    MOCKFS_ERRNO_ISDIR = -5,     // Is a directory
    MOCKFS_ERRNO_INVAL = -6,     // Invalid argument
    MOCKFS_ERRNO_NOTEMPTY = -7,  // Directory not empty
    MOCKFS_ERRNO_NOSPC = -8,     // No space left on device
    MOCKFS_ERRNO_EXIST = -9,     // File exists
    MOCKFS_ERRNO_BUSY  = -10,
    MOCKFS_ERRNO_BADF  = -11,
};

enum {
    MOCKFS_O_RDONLY = 0x00,
    MOCKFS_O_WRONLY = 0x01,
    MOCKFS_O_RDWR   = 0x02,
    MOCKFS_O_CREAT  = 0x40,
    MOCKFS_O_EXCL   = 0x80,
    MOCKFS_O_TRUNC  = 0x200,
    MOCKFS_O_APPEND = 0x400,
};

enum {
    MOCKFS_SEEK_SET = 0,
    MOCKFS_SEEK_CUR = 1,
    MOCKFS_SEEK_END = 2,
};

#define BYTE_CHUNK_SIZE 128

typedef struct ByteChunk ByteChunk;
struct ByteChunk {
    ByteChunk *next;
    char       data[BYTE_CHUNK_SIZE];
};

typedef struct {
    int used;
    int tail_used;
    ByteChunk *head;
    ByteChunk *tail;
} ByteBuffer;

typedef struct MockFS_Entity MockFS_Entity;

typedef struct {
    char *mem;
    int   len;
    int   off;
    MockFS_Entity *root;
    MockFS_Entity *entity_free_list;
    ByteChunk     *chunk_free_list;
} MockFS;

typedef struct {
    MockFS*        mfs;
    MockFS_Entity* entity;
    int            offset;
    int            flags;
} MockFS_OpenFile;

typedef struct {
    MockFS*        mfs;
    MockFS_Entity* entity;
    MockFS_Entity* child;
    int idx;
} MockFS_OpenDir;

typedef struct {
    char name[MOCKFS_NAME_SIZE];
    int  name_len;
    bool is_dir;
} MockFS_Dirent;

int  mockfs_init(MockFS **mfs, char *mem, int len);
void mockfs_free(MockFS *mfs);

int  mockfs_open(MockFS *mfs, char *path, int path_len, int flags, MockFS_OpenFile *open_file);
int  mockfs_open_dir(MockFS *mfs, char *path, int path_len, MockFS_OpenDir *open_dir);

int mockfs_file_size(MockFS_OpenFile *open_file);

void mockfs_close_file(MockFS_OpenFile *open_file);
void mockfs_close_dir(MockFS_OpenDir *open_dir);

int mockfs_read(MockFS_OpenFile *open_file, char *dst, int len);
int mockfs_write(MockFS_OpenFile *open_file, char *src, int len);
int mockfs_read_dir(MockFS_OpenDir *open_dir, MockFS_Dirent *dirent);

int mockfs_sync(MockFS_OpenFile *open_file);
int mockfs_lseek(MockFS_OpenFile *open_file, int offset, int whence);
int mockfs_ftruncate(MockFS_OpenFile *open_file, int new_size);

int mockfs_remove(MockFS *mfs, char *path, int path_len, bool recursive);

int mockfs_mkdir(MockFS *mfs, char *path, int path_len);

int mockfs_rename(MockFS *mfs, char *old_path, int old_path_len, char *new_path, int new_path_len);

#endif // MOCKFS_INCLUDED