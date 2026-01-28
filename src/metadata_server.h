#ifndef METADATA_SERVER_INCLUDED
#define METADATA_SERVER_INCLUDED

#include "tcp.h"
#include "wal.h"
#include "basic.h"
#include "config.h"
#include "hash_set.h"
#include "file_tree.h"

#define CONNECTION_TAG_CLIENT  -2
#define CONNECTION_TAG_UNKNOWN -3

typedef struct {

    bool used;
    bool auth;

    int num_addrs;
    Address addrs[MAX_SERVER_ADDRS];

    // List of chunks that are known to be held by CS
    HashSet ms_old_list; // TODO: rename all *_list symbols to *_set

    // List of chunks that should be held by CS
    HashSet ms_add_list;

    // List of chunks that may be held by CS but should removed from it
    HashSet ms_rem_list;

    // Time when last STATE_UPDATE was sent
    Time last_sync_time;
    bool last_sync_done;

    // Time when last response was received
    Time last_response_time; // TODO: don't init to INVALID_TIME but current_time

} ChunkServerPeer;

typedef struct {

    TCP tcp;
    WAL wal;

    FileTree file_tree;

    bool trace;
    int replication_factor;

    int num_chunk_servers;
    ChunkServerPeer chunk_servers[MAX_CHUNK_SERVERS];

} MetadataServer;

struct pollfd;

int metadata_server_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int metadata_server_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int metadata_server_free(void *state);

#endif // METADATA_SERVER_INCLUDED