#ifndef TOASTYFS_INCLUDED
#define TOASTYFS_INCLUDED

#include <stdint.h>

typedef enum {
    TOASTYFS_RESULT_VOID,
    TOASTYFS_RESULT_PUT,
    TOASTYFS_RESULT_GET,
    TOASTYFS_RESULT_DELETE,
} ToastyFS_ResultType;

typedef enum {
    TOASTYFS_ERROR_VOID,
    TOASTYFS_ERROR_OUT_OF_MEMORY,
    TOASTYFS_ERROR_UNEXPECTED_MESSAGE,
    TOASTYFS_ERROR_REJECTED,
    TOASTYFS_ERROR_FULL,
    TOASTYFS_ERROR_NOT_FOUND,
    TOASTYFS_ERROR_TRANSFER_FAILED,
} ToastyFS_Error;

typedef struct {
    ToastyFS_ResultType type;
    ToastyFS_Error error;
    char *data;
    int   size;
} ToastyFS_Result;

typedef struct ToastyFS ToastyFS;

ToastyFS *toastyfs_init(uint64_t client_id, char **addrs, int num_addrs);
void toastyfs_free(ToastyFS *tfs);

void toastyfs_process_events(ToastyFS *tfs, void **ctxs, struct pollfd *pdata, int pnum);
int  toastyfs_register_events(ToastyFS *tfs, void **ctxs, struct pollfd *pdata, int pcap, int *timeout);

int toastyfs_async_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len);

int toastyfs_async_get(ToastyFS *tfs, char *key, int key_len);

int toastyfs_async_delete(ToastyFS *tfs, char *key, int key_len);

ToastyFS_Result toastyfs_get_result(ToastyFS *tfs);

int toastyfs_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len, ToastyFS_Result *res);

int toastyfs_get(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res);

int toastyfs_delete(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res);

#endif // TOASTYFS_INCLUDED
