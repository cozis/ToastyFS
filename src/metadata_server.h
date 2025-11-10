#ifndef METADATA_SERVER_INCLUDED
#define METADATA_SERVER_INCLUDED

#include "tcp.h"
#include "file_tree.h"
#include "config.h"
#include "basic.h"

#define CONNECTION_TAG_CLIENT  -2
#define CONNECTION_TAG_UNKNOWN -3

typedef struct {
    int count;
    int capacity;
    SHA256 *items;
} HashList;

typedef struct {

    bool used;
    bool auth;

    int num_addrs;
    Address addrs[MAX_SERVER_ADDRS];

    // Chunks held by the chunk server during
    // the last update
    HashList old_list;

    // Chunks added to the chunk server since
    // the last update
    HashList add_list;

    // Chunks removed from the chunk server
    // since the last update
    HashList rem_list;

    // Time when last STATE_UPDATE was sent
    Time last_sync_time;
    bool last_sync_done;

    // Time when last response was received
    Time last_response_time; // TODO: don't init to INVALID_TIME but current_time

} ChunkServerPeer;

typedef struct {

    TCP tcp;

    FileTree file_tree;

    bool trace;
    int replication_factor;

    int num_chunk_servers;
    ChunkServerPeer chunk_servers[MAX_CHUNK_SERVERS];

} MetadataServer;

int metadata_server_init(MetadataServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout);
int metadata_server_free(MetadataServer *state);
int metadata_server_step(MetadataServer *state, void **contexts, struct pollfd *polled, int num_polled, int *timeout);

#endif // METADATA_SERVER_INCLUDED
