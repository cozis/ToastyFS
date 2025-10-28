#ifndef METADATA_SERVER_INCLUDED
#define METADATA_SERVER_INCLUDED

#include "tcp.h"
#include "file_tree.h"
#include "config.h"

#define CONNECTION_TAG_CLIENT  -1
#define CONNECTION_TAG_UNKNOWN -2

typedef struct {
    int count;
    int capacity;
    SHA256 *items;
} HashList;

typedef struct {

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

} ChunkServerPeer;

typedef struct {

    TCP tcp;

    FileTree file_tree;

    int replication_factor;

    int num_chunk_servers;
    ChunkServerPeer chunk_servers[MAX_CHUNK_SERVERS];

} MetadataServer;

int metadata_server_init(MetadataServer *state, int argc, char **argv);
int metadata_server_free(MetadataServer *state);
int metadata_server_step(MetadataServer *state);

#endif // METADATA_SERVER_INCLUDED
