#ifndef BLOB_CLIENT_INCLUDED
#define BLOB_CLIENT_INCLUDED

#include <lib/tcp.h>
#include <lib/basic.h>

#include "config.h"
#include "metadata.h"

// Maximum number of chunks per blob in the test client.
// Kept small for simulation; real blobs use META_CHUNKS_MAX.
#define BLOB_MAX_CHUNKS 8

// Chunk data size for the test client (32 bytes = SHA256 hash length).
// Each chunk's data is its hash bytes, making verification trivial.
#define BLOB_TEST_CHUNK_SIZE 32

typedef enum {
    BLOB_IDLE,              // Ready to start a new operation
    BLOB_UPLOADING,         // Sending StoreChunk, waiting for acks
    BLOB_COMMITTING,        // Sent CommitPut, waiting for REPLY
    BLOB_FETCHING_META,     // Sent GetBlob, waiting for response
    BLOB_FETCHING_DATA,     // Sending FetchChunk, waiting for responses
} BlobPhase;

typedef struct {
    SHA256   hash;
    uint32_t size;
    uint32_t ack_mask;   // Bitmask: which servers acked this chunk
    bool     fetched;    // GET: whether chunk data was received and verified
} BlobChunkState;

typedef struct {

    TCP tcp;

    Address server_addrs[NODE_LIMIT];
    int num_servers;
    int f_plus_one;     // Number of servers to upload each chunk to

    uint64_t view_number;
    uint64_t client_id;
    uint64_t request_id;

    BlobPhase phase;
    Time      phase_time;   // When we entered this phase

    // Current blob metadata
    char     bucket[META_BUCKET_MAX];
    char     key[META_KEY_MAX];
    uint64_t blob_size;
    SHA256   content_hash;
    int      num_chunks;
    BlobChunkState chunks[BLOB_MAX_CHUNKS];

    // Upload tracking
    int upload_server_cursor; // Next server index to try for StoreChunk

    // Download tracking
    int fetch_chunk_idx;      // Which chunk we're currently fetching
    int fetch_server_idx;     // Which server to try next

    // Alternation between PUT and GET
    bool do_get_next;         // If true, next op is GET; else PUT

    // Statistics
    int puts_completed;
    int gets_completed;
    int gets_verified;

    Time reconnect_time;

} BlobClientState;

struct pollfd;

int blob_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int blob_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int blob_client_free(void *state);

#endif // BLOB_CLIENT_INCLUDED
