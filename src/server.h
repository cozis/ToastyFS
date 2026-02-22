#ifndef NODE_INCLUDED
#define NODE_INCLUDED

#include "tcp.h"
#include "basic.h"
#include "message.h"
#include "wal.h"
#include "config.h"
#include "metadata.h"
#include "chunk_store.h"
#include "client_table.h"

enum {

    // Normal Protocol
    MESSAGE_TYPE_REQUEST,
    MESSAGE_TYPE_REPLY,
    MESSAGE_TYPE_PREPARE,
    MESSAGE_TYPE_PREPARE_OK,
    MESSAGE_TYPE_COMMIT,

    // View Change Protocol
    MESSAGE_TYPE_BEGIN_VIEW_CHANGE,
    MESSAGE_TYPE_DO_VIEW_CHANGE,
    MESSAGE_TYPE_BEGIN_VIEW,

    // Recovery Protocol
    MESSAGE_TYPE_RECOVERY,
    MESSAGE_TYPE_RECOVERY_RESPONSE,

    // State Transfer Protocol
    MESSAGE_TYPE_GET_STATE,
    MESSAGE_TYPE_NEW_STATE,

    // Client Redirect
    MESSAGE_TYPE_REDIRECT,

    // Chunk Storage Protocol (bypasses log)
    MESSAGE_TYPE_STORE_CHUNK,
    MESSAGE_TYPE_STORE_CHUNK_ACK,
    MESSAGE_TYPE_FETCH_CHUNK,
    MESSAGE_TYPE_FETCH_CHUNK_RESPONSE,

    // Blob Client Protocol
    MESSAGE_TYPE_COMMIT_PUT,
    MESSAGE_TYPE_GET_BLOB,
    MESSAGE_TYPE_GET_BLOB_RESPONSE,
};

typedef struct {
    MessageHeader base;
    MetaOper oper;
    uint64_t client_id;
    uint64_t request_id;
} RequestMessage;

typedef struct {
    MessageHeader base;
    MetaOper oper;
    int sender_idx;
    int log_index;
    int commit_index;
    uint64_t view_number;
    uint64_t client_id;
    uint64_t request_id;
} PrepareMessage;

typedef struct {
    MessageHeader base;
    int sender_idx;
    int log_index;
    uint64_t view_number;
} PrepareOKMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int sender_idx;
    int commit_index;
} CommitMessage;

typedef struct {
    MessageHeader base;
    bool rejected;
    MetaResult result;
    uint64_t request_id;
} ReplyMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int sender_idx;
} BeginViewChangeMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;       // The new view number
    uint64_t old_view_number;   // Last view number when replica was in normal status
    int op_number;              // Number of entries in the log
    int commit_index;
    int sender_idx;
    // Followed by: WALEntry log[op_number]
} DoViewChangeMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int commit_index;
    int op_number;  // Number of WAL entries that follow
    // Followed by: WALEntry log[op_number]
} BeginViewMessage;

typedef struct {
    MessageHeader base;
    int sender_idx;
    uint64_t nonce;
} RecoveryMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int op_number;
    uint64_t nonce;
    int commit_index;
    int sender_idx;
} RecoveryResponseMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int op_number;      // Requester's current log count
    int sender_idx;
} GetStateMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
    int op_number;      // Number of log entries that follow
    int commit_index;
    int start_index;    // Global log index of the first entry in the suffix
    // Followed by: WALEntry log[op_number]
} NewStateMessage;

typedef struct {
    MessageHeader base;
    uint64_t view_number;
} RedirectMessage;

// StoreChunk: client -> any server. Carries chunk data as trailing bytes.
typedef struct {
    MessageHeader base;
    SHA256   hash;
    uint32_t size;
    // Followed by: uint8_t data[size]
} StoreChunkMessage;

// StoreChunkAck: server -> client.
typedef struct {
    MessageHeader base;
    SHA256   hash;
    bool     success;
} StoreChunkAckMessage;

// FetchChunk: client/server -> server. Request a chunk by hash.
typedef struct {
    MessageHeader base;
    SHA256   hash;
    int      sender_idx; // -1 if from a client
} FetchChunkMessage;

// FetchChunkResponse: server -> client/server. Chunk data as trailing bytes.
typedef struct {
    MessageHeader base;
    SHA256   hash;
    uint32_t size; // 0 if chunk not found
    // Followed by: uint8_t data[size]
} FetchChunkResponseMessage;

// CommitPut: blob client -> leader. Commits metadata after chunks uploaded.
// Processed like a REQUEST (goes through VSR log).
typedef struct {
    MessageHeader base;
    MetaOper oper;
    uint64_t client_id;
    uint64_t request_id;
} CommitPutMessage;

// GetBlob: client -> any server. Request metadata for a blob.
typedef struct {
    MessageHeader base;
    char bucket[META_BUCKET_MAX];
    char key[META_KEY_MAX];
} GetBlobMessage;

// GetBlobResponse: server -> client. Returns blob metadata.
typedef struct {
    MessageHeader base;
    bool     found;
    uint64_t size;
    SHA256   content_hash;
    uint32_t num_chunks;
    ChunkRef chunks[META_CHUNKS_MAX];
} GetBlobResponseMessage;

typedef enum {
    STATUS_NORMAL,
    STATUS_CHANGE_VIEW,
    STATUS_RECOVERY,
} Status;

typedef struct {

    TCP tcp;

    Address  self_addr;
    Address  node_addrs[NODE_LIMIT];
    int      num_nodes;

    Status status;

    ClientTable client_table;
    int next_client_tag;

    uint64_t view_number;
    uint64_t last_normal_view;  // Latest view where status was NORMAL

    // These fields are used in recovery mode
    uint32_t recovery_votes;
    uint64_t recovery_nonce;
    uint64_t recovery_view;
    WAL      recovery_log;
    uint64_t recovery_log_view;
    Time     recovery_time;
    int      recovery_commit;

    ///////////////////////////////////////////////////////////
    // VIEW CHANGE

    uint32_t view_change_begin_votes;
    uint32_t view_change_apply_votes;
    WAL      view_change_log; // Best log seen
    uint64_t view_change_old_view;  // Best old_view_number seen in DoViewChange
    int      view_change_commit;    // Best commit_index seen

    ///////////////////////////////////////////////////////////

    // If this is the leader, commit_index is the index of the next uncommitted element
    // of the log (if no uncommitted elements are present, it's equal to the total number
    // of log elements)
    int commit_index;

    PrepareMessage future[FUTURE_LIMIT];
    int num_future;

    bool state_transfer_pending;
    Time state_transfer_time;

    WAL wal;
    ViewAndCommit vc;

    Time heartbeat;

    MetaStore metastore;
    ChunkStore chunk_store;

    // Set at each wakeup
    Time now;

} ServerState;

struct pollfd;

int server_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int server_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int server_free(void *state);

typedef struct {
    int last_min_commit;
    int last_max_commit;
    Status prev_status[NODE_LIMIT];

    // External shadow log of committed operations (unbounded, dynamically allocated)
    MetaOper *shadow_log;
    int shadow_count;
    int shadow_capacity;
} InvariantChecker;

void invariant_checker_init(InvariantChecker *ic);
void invariant_checker_free(InvariantChecker *ic);

// node_handles: opaque QuakeyNode handles for entering host context.
// Pass NULL when running outside the simulation (real mode).
void invariant_checker_run(InvariantChecker *ic, ServerState **nodes, int num_nodes,
    unsigned long long *node_handles);

#endif // NODE_INCLUDED
