#ifndef FILE_SYSTEM_INCLUDED
#define FILE_SYSTEM_INCLUDED

#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <stdint.h>
#include <quakey.h>

#include "basic.h"

typedef struct {
    uint64_t data;
} Handle;

#ifdef _WIN32
typedef struct {
    HANDLE handle;
    WIN32_FIND_DATA find_data;
    bool first;
    bool done;
} DirectoryScanner;
#else
typedef struct {
    DIR *d;
    struct dirent *e;
    bool done;
} DirectoryScanner;
#endif

bool file_exists(string path);
int  file_open(string path, Handle *fd);
void file_close(Handle fd);
int  file_truncate(Handle fd, size_t new_size);
int  file_set_offset(Handle fd, int off);
int  file_get_offset(Handle fd, int *off);
int  file_lock(Handle fd);
int  file_unlock(Handle fd);
int  file_sync(Handle fd);
int  file_read(Handle fd, char *dst, int max);
int  file_write(Handle fd, char *src, int len);
int  file_size(Handle fd, size_t *len);
int  file_write_atomic(string path, string content);
int  create_dir(string path);
int  rename_file_or_dir(string oldpath, string newpath);
int  remove_file_or_dir(string path);
int  get_full_path(string path, char *dst);
int  file_read_all(string path, string *data);

int  directory_scanner_init(DirectoryScanner *scanner, string path);
int  directory_scanner_next(DirectoryScanner *scanner, string *name);
void directory_scanner_free(DirectoryScanner *scanner);

int file_read_exact(Handle handle, char *dst, int len);
int file_write_exact(Handle handle, char *src, int len);

#endif // FILE_SYSTEM_INCLUDED