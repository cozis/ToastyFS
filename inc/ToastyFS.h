#ifndef TOASTYFS_INCLUDED
#define TOASTYFS_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

typedef struct ToastyFS ToastyFS;

typedef struct {
    char name[128]; // TODO: Implement a proper name length
    bool is_dir;
} ToastyFS_Entity;

typedef enum {
    TOASTYFS_RESULT_EMPTY,
    TOASTYFS_RESULT_CREATE_ERROR,
    TOASTYFS_RESULT_CREATE_SUCCESS,
    TOASTYFS_RESULT_DELETE_ERROR,
    TOASTYFS_RESULT_DELETE_SUCCESS,
    TOASTYFS_RESULT_LIST_ERROR,
    TOASTYFS_RESULT_LIST_SUCCESS,
    TOASTYFS_RESULT_READ_ERROR,
    TOASTYFS_RESULT_READ_SUCCESS,
    TOASTYFS_RESULT_WRITE_ERROR,
    TOASTYFS_RESULT_WRITE_SUCCESS,
} ToastyFS_ResultType;

typedef struct {

    ToastyFS_ResultType type;

    int num_entities;
    ToastyFS_Entity *entities;
} ToastyFS_Result;

ToastyFS *toastyfs_init(char *addr, uint16_t port);
void toastyfs_free(ToastyFS *tfs);
void toastyfs_wait(ToastyFS *tfs, int opidx, ToastyFS_Result *result, int timeout);

bool toastyfs_isdone(ToastyFS *tfs, int opidx, ToastyFS_Result *result);
int  toastyfs_process_events(ToastyFS *tfs, void **contexts, struct pollfd *polled, int num_polled);

int  toastyfs_submit_create (ToastyFS *tfs, char *path, int path_len, bool is_dir, unsigned int chunk_size);
int  toastyfs_submit_delete (ToastyFS *tfs, char *path, int path_len);
int  toastyfs_submit_list   (ToastyFS *tfs, char *path, int path_len);
int  toastyfs_submit_read   (ToastyFS *tfs, char *path, int path_len, int off, void *dst, int len);
int  toastyfs_submit_write  (ToastyFS *tfs, char *path, int path_len, int off, void *src, int len);
void toastyfs_result_free(ToastyFS_Result *result);

#endif // TOASTYFS_INCLUDED
