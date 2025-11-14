#ifndef CHUNK_SERVER_INCLUDED
#define CHUNK_SERVER_INCLUDED

#include <limits.h>

#include "metadata_server.h"
#include "tcp.h"

#define TAG_METADATA_SERVER 1
#define TAG_CHUNK_SERVER    2

#define CHUNK_SERVER_RECONNECT_TIME 10000

typedef struct {
    char path[PATH_MAX];
} ChunkStore;

typedef struct {
    Address addr;
    SHA256  hash;
} PendingDownload;

typedef struct {
    int count;
    int capacity;
    PendingDownload *items;
} PendingDownloadList;

typedef struct {

    bool trace;

    Address local_addr;

    Address remote_addr;

    Time disconnect_time;
    Time last_sync_time;

    TCP tcp;

    ChunkStore store;

    bool downloading;

    PendingDownloadList pending_download_list;

    // List of chunks added since the last update
    HashSet cs_add_list;

    // List of chunks marked for removal after a timeout
    TimedHashSet cs_rem_list;

    // List of chunks that were lost due to errors or forceful removals of chunk files
    HashSet cs_lst_list;

} ChunkServer;

int chunk_server_init(ChunkServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout);
int chunk_server_free(ChunkServer *state);
int chunk_server_step(ChunkServer *state, void **contexts, struct pollfd *polled, int num_polled, int *timeout);

#endif // CHUNK_SERVER_INCLUDED
