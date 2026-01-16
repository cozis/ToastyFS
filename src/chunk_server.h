#ifndef CHUNK_SERVER_INCLUDED
#define CHUNK_SERVER_INCLUDED

#define TAG_METADATA_SERVER 1
#define TAG_CHUNK_SERVER    2

typedef struct {
    Address addr;
    SHA256  hash;
} DownloadTarget;

typedef struct {
    DownloadTarget *items;
    int count;
    int capacity;
} DownloadTargets;

typedef struct {

    char path[PATH_MAX];

    bool trace;

    Address local_addr;
    Address remote_addr;

    Time disconnect_time;
    Time last_sync_time;
    int reconnect_delay; // In seconds

    // --- Subsystems ---

    TCP tcp;

    // --- Download Management ---

    bool downloading;
    SHA256 current_download_target_hash;
    DownloadTargets download_targets;

    // --- Chunk Management ---

    // List of chunks added since the last update
    HashSet cs_add_list;

    // List of chunks marked for removal after a timeout
    TimedHashSet cs_rem_list;

    // List of chunks that were lost due to errors or forceful removals of chunk files
    HashSet cs_lst_list;

} ChunkServer;

struct pollfd;

int chunk_server_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int chunk_server_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int chunk_server_free(void *state);

#endif // CHUNK_SERVER_INCLUDED