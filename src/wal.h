#ifndef WAL_INCLUDED
#define WAL_INCLUDED

#include "file_tree.h"
#include "file_system.h"

typedef struct {
    Handle handle;
    int entry_count;
    int entry_limit;
} WAL;

int  wal_open(WAL *wal, FileTree *file_tree, string file_path, int entry_limit);
void wal_close(WAL *wal);
int  wal_append_create(WAL *wal, string path, bool is_dir, uint64_t chunk_size);
int  wal_append_delete(WAL *wal, string path);
int  wal_append_write(WAL *wal, string path, uint64_t off, uint64_t len, uint32_t num_chunks, uint32_t chunk_size, SHA256 *prev_hashes, SHA256 *hashes);

#endif // WAL_INCLUDED
