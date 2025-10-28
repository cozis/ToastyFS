#ifndef TINYDFS_INCLUDED
#define TINYDFS_INCLUDED

#include <stdint.h>
#include <stdbool.h>

typedef struct TinyDFS TinyDFS;

typedef struct {
    char name[128]; // TODO: Implement a proper name length
    bool is_dir;
} TinyDFS_Entity;

typedef enum {
    TINYDFS_RESULT_EMPTY,
    TINYDFS_RESULT_CREATE_ERROR,
    TINYDFS_RESULT_CREATE_SUCCESS,
    TINYDFS_RESULT_DELETE_ERROR,
    TINYDFS_RESULT_DELETE_SUCCESS,
    TINYDFS_RESULT_LIST_ERROR,
    TINYDFS_RESULT_LIST_SUCCESS,
    TINYDFS_RESULT_READ_ERROR,
    TINYDFS_RESULT_READ_SUCCESS,
    TINYDFS_RESULT_WRITE_ERROR,
    TINYDFS_RESULT_WRITE_SUCCESS,
} TinyDFS_ResultType;

typedef struct {

    TinyDFS_ResultType type;

    int num_entities;
    TinyDFS_Entity *entities;
} TinyDFS_Result;

TinyDFS *tinydfs_init(char *addr, uint16_t port);
void tinydfs_free(TinyDFS *tdfs);
void tinydfs_wait(TinyDFS *tdfs, int opidx, TinyDFS_Result *result, int timeout);
int  tinydfs_submit_create (TinyDFS *tdfs, char *path, int path_len, bool is_dir, unsigned int chunk_size);
int  tinydfs_submit_delete (TinyDFS *tdfs, char *path, int path_len);
int  tinydfs_submit_list   (TinyDFS *tdfs, char *path, int path_len);
int  tinydfs_submit_read   (TinyDFS *tdfs, char *path, int path_len, int off, void *dst, int len);
int  tinydfs_submit_write  (TinyDFS *tdfs, char *path, int path_len, int off, void *src, int len);
void tinydfs_result_free(TinyDFS_Result *result);

#endif // TINYDFS_INCLUDED
