#ifndef MOUSEFS_INCLUDED
#define MOUSEFS_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

typedef struct MouseFS MouseFS;

typedef struct {
    char name[128]; // TODO: Implement a proper name length
    bool is_dir;
} MouseFS_Entity;

typedef enum {
    MOUSEFS_RESULT_EMPTY,
    MOUSEFS_RESULT_CREATE_ERROR,
    MOUSEFS_RESULT_CREATE_SUCCESS,
    MOUSEFS_RESULT_DELETE_ERROR,
    MOUSEFS_RESULT_DELETE_SUCCESS,
    MOUSEFS_RESULT_LIST_ERROR,
    MOUSEFS_RESULT_LIST_SUCCESS,
    MOUSEFS_RESULT_READ_ERROR,
    MOUSEFS_RESULT_READ_SUCCESS,
    MOUSEFS_RESULT_WRITE_ERROR,
    MOUSEFS_RESULT_WRITE_SUCCESS,
} MouseFS_ResultType;

typedef struct {

    MouseFS_ResultType type;

    int num_entities;
    MouseFS_Entity *entities;
} MouseFS_Result;

MouseFS *mousefs_init(char *addr, uint16_t port);
void mousefs_free(MouseFS *mfs);
void mousefs_wait(MouseFS *mfs, int opidx, MouseFS_Result *result, int timeout);

bool mousefs_isdone(MouseFS *mfs, int opidx, MouseFS_Result *result);
int  mousefs_process_events(MouseFS *mfs, void **contexts, struct pollfd *polled, int num_polled);

int  mousefs_submit_create (MouseFS *mfs, char *path, int path_len, bool is_dir, unsigned int chunk_size);
int  mousefs_submit_delete (MouseFS *mfs, char *path, int path_len);
int  mousefs_submit_list   (MouseFS *mfs, char *path, int path_len);
int  mousefs_submit_read   (MouseFS *mfs, char *path, int path_len, int off, void *dst, int len);
int  mousefs_submit_write  (MouseFS *mfs, char *path, int path_len, int off, void *src, int len);
void mousefs_result_free(MouseFS_Result *result);

#endif // MOUSEFS_INCLUDED
