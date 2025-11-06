#ifndef CHUNK_SERVER_INCLUDED
#define CHUNK_SERVER_INCLUDED

#include <limits.h>

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
    Address    metadata_server_addr;
    Time       disconnect_time;
    TCP        tcp;
    ChunkStore store;

    bool downloading;
    PendingDownloadList pending_download_list;
} ChunkServer;

int chunk_server_init(ChunkServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout);
int chunk_server_free(ChunkServer *state);
int chunk_server_step(ChunkServer *state, void **contexts, struct pollfd *polled, int num_polled, int *timeout);

#endif // CHUNK_SERVER_INCLUDED
