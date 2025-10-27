#ifndef TINYDFS_INCLUDED
#define TINYDFS_INCLUDED

typedef struct TinyDFS TinyDFS;

typedef enum {
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
} TinyDFS_Result;

typedef int TinyDFS_Handle;
#define TINYDFS_INVALID ((TinyDFS_Handle) -1)

TinyDFS*       tinydfs_init(void);
void           tinydfs_free(TinyDFS *tdfs);
int            tinydfs_wait(TinyDFS *tdfs, TinyDFS_Handle handle, TinyDFS_Result *result, int timeout);
TinyDFS_Handle tinydfs_submit_create (TinyDFS *tdfs, char *path, int path_len, bool is_dir, unsigned int chunk_size);
TinyDFS_Handle tinydfs_submit_delete (TinyDFS *tdfs, char *path, int path_len);
TinyDFS_Handle tinydfs_submit_list   (TinyDFS *tdfs, char *path, int path_len);
TinyDFS_Handle tinydfs_submit_read   (TinyDFS *tdfs, char *path, int path_len, void *dst, int len);
TinyDFS_Handle tinydfs_submit_write  (TinyDFS *tdfs, char *path, int path_len, void *src, int len);

#endif // TINYDFS_INCLUDED
