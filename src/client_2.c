#include <ToastyFS.h>

// How many chunk transfers can the client perform in parallel
#define PARALLEL_TRANSFER_LIMIT 5

typedef enum {

    // No operation in progress. New ones can be started.
    CLIENT_IDLE,

    // The starting state of all PUT operations where chunks
    // are uploaded to servers before committing any metadata.
    CLIENT_UPLOADING_CHUNKS,

    // This is the state when all chunks of an object have
    // been uploaded and the client is waiting for the server
    // to accept the new object metadata.
    CLIENT_UPLOADING_METADATA,

    // PUT operation failed. The error field of the ToastyFS
    // structure is set accordingly.
    CLIENT_FAILED_PUT,

    // PUT operation succeded
    CLIENT_COMPLETED_PUT,

    CLIENT_DOWNLOADING_METADATA,

    CLIENT_DOWNLOADING_CHUNKS,

    CLIENT_FAILED_GET,

    CLIENT_COMPLETED_GET,

    CLIENT_DELETING_METADATA,

    CLIENT_FAILED_DELETE,

    CLIENT_COMPLETED_DELETE,

} ClientState;

typedef enum {

    // The transfer ready but wasn't started yet
    TRANSFER_PENDING,

    // The transfer started
    TRANSFER_STARTED,

    // The trasfer was stopped on our end
    TRANSFER_ABORTED,

    // The transfer failed
    TRANSFER_FAILED,

    // The transfer is complete
    TRANSFER_COMPLETE,
} TransferState;

// This structure represents the state of a single chunk's transfer.
typedef struct {
    TransferState state;

    // Index of the first chunk with this hash
    int chunk;

    // Index of the target server
    int server;
} Transfer;

// This structure holds metadata associated to a chunk that is being
// uploaded of downloaded. Note that generally speaking multiple
// trasfers may refer to a single chunk
typedef struct {
    char  *ptr;
    int    len;
    SHA256 hash;
} Chunk;

struct ToastyFS {

    // Lower level networking system for message-passing
    MessageSystem *msys;

    ClientState state;

    // Error code that will be returned when the operation completion
    // information is requested.
    ToastyFS_Error error;

    // Metadata associated to the chunks of an object upload
    // or download.
    Chunk *chunks;
    int num_chunks;

    Transfer *transfers;
    int num_transfers;
    bool is_upload; // This flag determines whether transfers are uploads or downloads
};

// This function initializes the ToastyFS client instance.
//
// The client_id is an arbitrary integer that identifies this client
// uniquely. Each client interacting with the ToastyFS cluster must
// have a different one. A client that crashes and restarts may and
// should reuse its old client_id.
//
// The addrs array argument contains the IPv4 addresses of the cluster
// servers, while num_addrs is the number of servers. Addresses are
// expressed in dotted-decimal notation.
ToastyFS *toastyfs_init(uint64_t client_id, char **addrs, int num_addrs)
{
    ToastyFS *tfs = malloc(sizeof(ToastyFS));
    if (tfs == NULL)
        return NULL;

    tfs->msys = message_system_init(addrs, num_addrs);
    if (tfs->msys == NULL) {
        free(tfs);
        return NULL;
    }

    // TODO

    return tfs;
}

// Release resources associated to a ToastyFS client.
void toastyfs_free(ToastyFS *tfs)
{
    message_system_free(tfs->msys);
    free(tfs);
}

static bool
is_result_for_transfer(Transfer *transfer, int server, SHA256 hash)
{
    if (transfer->state != TRANSFER_STARTED)
        return false;

    if (transfer->server != server)
        return false;

    if (memcmp(&transfer->hash, &hash, sizeof(SHA256)))
        return false;

    return true;
}

static void set_upload_result(ToastyFS *tfs, int server, SHA256 hash, bool success)
{
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (is_result_for_transfer(&tfs->transfers[i], server, hash)) {
            if (success) {
                tfs->transfers[i].state = TRANSFER_COMPLETE;
            } else {
                tfs->transfers[i].state = TRANSFER_ABORTED;
            }
        }
    }

    // If this upload was successful and the chunk was now written
    // to a majority of servers, abort any pending uploads of the
    // same hash.

    int num_complete = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (tfs->transfers[i].state == TRANSFER_COMPLETE && !memcmp(tfs->transfers[i].hash, &hash))
            num_complete++;
    }

    if (num_complete > tfs->num_servers/2) {
        for (int i = 0; i < tfs->num_transfers; i++) {
            if (tfs->transfers[i].state == TRANSFER_PENDING && !memcmp(tfs->transfers[i].hash, &hash))
                tfs->transfers[i].state = TRANSFER_ABORTED;
        }
    }
}

static bool
have_pending_or_started_transfers(ToastyFS *tfs)
{
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (tfs->transfers[i].state == TRANSFER_PENDING ||
            tfs->transfers[i].state == TRANSFER_STARTED)
        return true;
    }
    return false;
}

static int successful_uploads_for_chunk(ToastyFS *tfs, SHA256 hash)
{
    int count = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (tfs->transfers[i].state == TRANSFER_COMPLETE
            && !memcmp(&tfs->transfers[i].hash, &hash, sizeof(SHA256))) {
            count++;
        }
    }
    return count;
}

static bool all_chunks_replicated(ToastyFS *tfs)
{
    for (int i = 0; i < tfs->num_chunks; i++) {
        if (successful_uploads_for_chunk(tfs, tfs->chunks[i].hash) < CEIL(tfs->num_servers, 2))
            return false;
    }
    return true;
}

static void process_uploading_chunks(ToastyFS *tfs, void *ptr)
{
    // We are expecting an upload success or failure.
    // Ignore anything else.
    if (message_type(ptr) != MESSAGE_TYPE_STORE_CHUNK_RESPONSE)
        return; // Ignore

    StoreChunkResponseMessage message;
    memcpy(&message, ptr, sizeof(message));

    set_upload_result(tfs, message.base.sender_idx, message.hash, message.success);
    start_uploads(tfs);

    if (!have_pending_or_started_transfers(tfs)) {
        // If we managed to replicate each chunk on a majority
        // of servers, we can commit the operation by sending
        // the object's metadata, else we fail.
        if (all_chunks_replicated(tfs)) {
            RequestMessage message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_COMMIT_PUT,
                    .sender  = xxx,
                    .length  = sizeof(RequestMessage),
                },
                .oper = xxx,
                .client_id = tfs->client_id,
                .request_id = get_next_request_id(tfs),
            };
            send_message(tfs->msys, &message.base);
            tfs->state = CLIENT_UPLOADING_METADATA;
        } else {
            tfs->state = CLIENT_FAILED_PUT;
            tfs->error = xxx;
        }
    }
}

static void process_uploading_metadata(ToastyFS *tfs, void *ptr)
{
    if (message_type(ptr) == MESSAGE_TYPE_REDIRECT) {

        // Replay request
        RequestMessage message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_COMMIT_PUT,
                .sender  = xxx,
                .length  = sizeof(RequestMessage),
            },
            .oper = xxx,
            .client_id = tfs->client_id,
            .request_id = tfs->last_request_id,
        };
        send_message(tfs->msys, tfs->primary, &message.base);

    } else if (message_type(ptr) == MESSAGE_TYPE_REPLY) {

        VsrReplyMessage message;
        memcpy(&message, ptr, sizeof(message));

        if (message.request_id != tfs->last_request_id)
            return; // Ignore

        if (message.rejected) {
            tfs->state = CLIENT_FAILED_PUT;
            tfs->error = xxx;
            return;
        }

        switch (message.meta.type) {
        case META_RESULT_OK:
            tfs->state = CLIENT_COMPLETED_PUT;
            assert(tfs->state == TOASTYFS_ERROR_VOID);
            break;
        case META_RESULT_NOT_FOUND:
            tfs->state = CLIENT_FAILED_PUT;
            tfs->error = TOASTYFS_ERROR_NOT_FOUND;
            break;
        case META_RESULT_FULL:
            tfs->state = CLIENT_ERROR;
            tfs->error = TOASTYFS_ERROR_FULL;
            break;
        }
    }
}

// This function starts transfer operations up to the parallel
// transfer limit.
//
// Note that this function may start uploads of a single chunk
// to more servers than strictly necessary. Operations to all
// servers are scheduled per chunk in case some servers are
// not available. When a chunk is uploaded to enough servers,
// the transfers to the remaining ones are aborted. But if
// more transfers than necessary are started in parallel, it
// is possible for the chunk to become over-replicated. The
// only downside of this is unnecessary usage of network
// bandwidth. This behavior can be solved later as it does not
// impact the overall architecture of the system.
static void start_transfers(ToastyFS *tfs)
{
    // Count how many uploads are started and how many are pending
    int num_started = 0;
    int num_pending = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        switch (tfs->transfers[i].state) {
            case TRANSFER_STARTED: num_started++; break;
            case TRANSFER_PENDING: num_pending++; break;
        }
    }

    // Start operations while some are pending and we didn't reach the limit
    while (num_started < PARALLEL_TRANSFER_LIMIT && num_pending > 0) {

        // Find the next pending operation
        int found = -1;
        for (int i = 0; i < tfs->num_transfers; i++) {
            if (tfs->transfers[i].state == TRANSFER_PENDING) {
                found = i;
                break;
            }
        }
        assert(found > -1);

        int chunk = tfs->transfers[found].chunk;

        if (tfs->is_upload) {
            StoreChunkMessage message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_STORE_CHUNK,
                    .sender  = xxx,
                    .length  = sizeof(StoreChunkMessage) + tfs->chunks[chunk].len;
                },
                .hash = xxx,
                .size = tfs->chunks[chunk].len,
            };
            send_message_ex(tfs->msys, tfs->transfers[found].server,
                &message.base, tfs->chunks[chunk].ptr, tfs->chunks[chunk].len);
        } else {
            FetchChunkMessage message = {
                .bse = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_FETCH_CHUNK,
                    .sender  = xxx,
                    .length  = sizeof(FetchChunkMessage),
                }
                .hash = xxx,
                .sender_idx = -1, // TODO: this is unnecessary
            };
            send_message(tfs->msys, tfs->transfers[found].server, &message.base);
        }

        tfs->transfers[found].state = TRANSFER_STARTED;
        num_started++;
        num_pending++;
    }
}

static void process_downloading_metadata(ToastyFS *tfs, void *ptr)
{
    if (message_type(ptr) == MESSAGE_TYPE_REDIRECT) {

        // Replay request
        RequestMessage message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_xxx,
                .sender  = xxx,
                .length  = sizeof(RequestMessage),
            },
            .oper = xxx,
            .client_id = tfs->client_id,
            .request_id = tfs->last_request_id,
        };
        send_message(tfs->msys, tfs->primary, &message.base);

    } else if (message_type(ptr) == MESSAGE_TYPE_REPLY) {

        VsrReplyMessage message;
        memcpy(&message, ptr, sizeof(message));

        if (message.request_id != tfs->last_request_id)
            return; // Ignore

        if (message.rejected) {
            tfs->state = CLIENT_FAILED_GET;
            tfs->error = xxx;
            return;
        }

        if (message.meta.type != META_RESULT_OK) {
            switch (message.meta.type) {
            case META_RESULT_NOT_FOUND:
                tfs->state = CLIENT_FAILED_GET;
                tfs->error = TOASTYFS_ERROR_NOT_FOUND;
                break;
            case META_RESULT_FULL:
                tfs->state = CLIENT_FAILED_GET;
                tfs->error = TOASTYFS_ERROR_FULL;
                break;
            }
            return;
        }

        if (message.num_chunks == 0) {
            // Early completion
            assert(tfs->error == TOASTYFS_ERROR_VOID);
            tfs->state = CLIENT_COMPLETED_GET;
            return;
        }

        tfs->chunks = malloc(message.num_chunks * sizeof(Chunk));
        if (tfs->chunks == NULL) {
            tfs->state = CLIENT_FAILED_GET;
            tfs->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
            return;
        }
        tfs->num_chunks = message.num_chunks;

        int majority = (tfs->num_servers + 1) / 2;
        int max_transfers = majority * message.num_chunks;
        assert(max_transers > 0);

        tfs->is_upload = false;
        tfs->transfers = malloc(max_transers * sizeof(Transfer));
        if (tfs->transfers == NULL) {
            tfs->state = CLIENT_FAILED_GET;
            tfs->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
            return;
        }
        tfs->num_transfers = 0; // To be decided

        tfs->output_size = message.size;
        tfs->output_data = malloc(message.size);
        if (tfs->output_data == NULL) {
            tfs->state = CLIENT_FAILED_GET;
            tfs->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
            return;
        }

        for (int i = 0; i < message.num_chunks; i++) {

            tfs->chunks[i].ptr = tfs->output_data + i * CHUNK_SIZE;
            tfs->chunks[i].len = MIN(CHUNK_SIZE, tfs->output_size - i * CHUNK_SIZE);
            tfs->chunks[i].hash = message.chunks[i].hash;

            // Schedule transfers if no transfers were scheduled for
            // this hash yet.
            bool duplicate = false;
            for (int j = 0; j < i; j++) {
                if (!memcmp(&tfs->chunks[j].hash, &tfs->chunks[i].hash)) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate) {
                for (int j = 0; j < message.chunks[i].num_servers; j++) {
                    tfs->transfers[tfs->num_transfers].state = TRANSFER_PENDING;
                    tfs->transfers[tfs->num_transfers].chunk = i;
                    tfs->transfers[tfs->num_transfers].server = message.chunks[i].servers[j];
                    tfs->num_transfers++;
                }
            }
        }
        assert(num_transfers > 0);

        start_transfers(tfs);
        tfs->state = CLIENT_DOWNLOADING_CHUNKS;
    }
}

static bool chunk_downloaded(ToastyFS *tfs, int chunk)
{
    for (int j = 0; j < tfs->num_transfers; j++) {
        if (tfs->transfers[j].state == TRANSFER_COMPLETE &&
            !memcmp(&tfs->transfers[j].hash, &tfs->chunks[i]))
            return true;
    }
    return false;
}

static bool all_chunks_retrieved(ToastyFS *tfs)
{
    for (int i = 0; i < tfs->num_chunks; i++) {
        if (!chunk_downloaded(tfs, i))
            return false;
    }
    return true;
}

static void process_downloading_chunks(ToastyFS *tfs, void *ptr)
{
    if (message_type(ptr) != MESSAGE_TYPE_FETCH_CHUNK_RESPONSE)
        return; // Ignore

    FetchChunkResponseMessage message;
    memcpy(&message, ptr, sizeof(message));

    if (message.size == 0) {
        tfs->state = CLIENT_FAILED_GET;
        tfs->error = TOASTYFS_ERROR_NOT_FOUND;
        return;
    }

    char*    chunk_data = (char*) ptr + sizeof(FetchChunkResponseMessage);
    uint32_t chunk_size = message.size;

    for (int i = 0; i < tfs->num_chunks; i++) {
        if (!memcmp(&tfs->chunks[i].hash, &message.hash)) {
            assert(chunk_size == tfs->chunks[i].len);
            memcpy(tfs->chunks[i].ptr, chunk_data, chunk_size);
        }
    }

    start_transfers(tfs);
    if (!have_pending_or_started_transfers(tfs)) {
        if (all_chunks_retrieved(tfs)) {
            tfs->state = CLIENT_COMPLETED_GET;
        } else {
            tfs->state = CLIENT_FAILED_GET;
            tfs->error = xxx;
        }
    }
}

static void process_deleting_metadata(ToastyFS *tfs, void *ptr)
{
    if (message_type(ptr) == MESSAGE_TYPE_REDIRECT) {

        // Replay request
        RequestMessage message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_xxx,
                .sender  = xxx,
                .length  = sizeof(RequestMessage),
            },
            .oper = xxx,
            .client_id = tfs->client_id,
            .request_id = tfs->last_request_id,
        };
        send_message(tfs->msys, tfs->primary, &message.base);

    } else if (message_type(ptr) == MESSAGE_TYPE_REPLY) {

        VsrReplyMessage message;
        memcpy(&message, ptr, sizeof(message));

        if (message.request_id != tfs->last_request_id)
            return; // Ignore

        if (message.rejected) {
            tfs->state = CLIENT_FAILED_DELETE;
            tfs->error = xxx;
            return;
        }

        switch (message.meta.type) {
        case META_RESULT_OK:
            tfs->state = CLIENT_COMPLETED_DELETE;
            assert(tfs->state == TOASTYFS_ERROR_VOID);
            break;
        case META_RESULT_NOT_FOUND:
            tfs->state = CLIENT_FAILED_DELETE;
            tfs->error = TOASTYFS_ERROR_NOT_FOUND;
            break;
        case META_RESULT_FULL:
            tfs->state = CLIENT_FAILED_DELETE;
            tfs->error = TOASTYFS_ERROR_FULL;
            break;
        }
    }
}

void toastyfs_process_events(ToastyFS *tfs,
    void **ptrs, struct pollfd *pfds, int num)
{
    message_system_process_events(tfs->msys, ptrs, pfds, num);

    for (void *ptr; (ptr = get_next_message(tfs->msys)); ) {

        switch (tfs->state) {
        case CLIENT_UPLOADING_CHUNKS:
            process_uploading_chunks(tfs, ptr);
            break;
        case CLIENT_UPLOADING_METADATA:
            process_uploading_metadata(tfs, ptr);
            break;
        case CLIENT_DOWNLOADING_METADATA:
            process_downloading_metadata(tfs, ptr);
            break;
        case CLIENT_DOWNLOADING_CHUNKS:
            process_downloading_chuns(tfs, ptr);
            break;
        case CLIENT_DELETING_METADATA:
            process_deleting_metadata(tfs, ptr);
            break;
        default:
            break; // Wasn't expecting a message. Ignore.
        }

        consume_message(tfs->msys, ptr);
    }
}

int toastyfs_register_events(ToastyFS *tfs, void **ptrs,
    struct pollfd *pfds, int cap, int *timeout)
{
    return message_system_register_events(tfs->msys, ptrs, pfds, cap, timeout);
}

// Begin an asynchronous object creation operation
//
// Note that there can only be one pending operation at a time.
int toastyfs_async_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len)
{
    // Only one operation allowed at a time
    if (tfs->state != CLIENT_IDLE)
        return -1; // TODO: error code
    tfs->error = TOASTYFS_ERROR_VOID;

    // We need to split the data in chunks, then schedule their
    // uploads. Each chunk needs to be uploaded to a majority of
    // servers.
    //
    // The way we do this is by creating an array of transfer
    // descriptors. Each describing a possible upload we may need
    // to make in order to complete the upload.
    //
    // For instance say we needed to upload a single chunk C0 to
    // a cluster with server nodes S1, S2, S3. We would create
    // the following transfer descriptors:
    //
    //   C0 ---> S0
    //   C0 ---> S1
    //   C0 ---> S2
    //
    // Note that C0 only needs to be uploaded to a majority of
    // servers, so only 2 out of 3. This is the list of all
    // possible transfers we may need to happen to complete the
    // overall upload. Once the majority of uploads of a chunk
    // complete, the remaining ones for that chunk are aborted.

    // Count the number of chunks we need to upload. If the data
    // to upload contains a repeated chunk, we only upload that
    // chunk once. This means that the number of chunks we need
    // to process may be less that the object's length divided
    // by the chunk size.
    int max_chunks = CEIL(data_len, CHUNK_SIZE);
    assert(max_chunks > 0);

    tfs->chunks = malloc(max_chunks * sizeof(Chunk));
    if (tfs->chunks == NULL) {
        tfs->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
        return;
    }

    tfs->num_chunks = 0;
    for (int i = 0; i < max_chunks; i++) {

        char *chunk_ptr = data + i * CHUNK_SIZE;
        int   chunk_len = MIN(CHUNK_SIZE, data_len - i * CHUNK_SIZE);

        SHA256 hash = sha256(chunk_ptr, chunk_len);

        bool duplicate = false;
        for (int j = 0; j < i; j++) {
            if (!memcmp(&tfs->chunks[j].hash, &tfs->chunks[i].hash, sizeof(SHA256))) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            tfs->chunks[tfs->num_chunks].ptr = chunk_ptr;
            tfs->chunks[tfs->num_chunks].len = chunk_len;
            tfs->chunks[tfs->num_chunks].hash = hash;
            tfs->num_chunks++;
        }
    }
    assert(tfs->num_chunks > 0);

    int num_transfers = tfs->num_chunks * tfs->num_servers;

    tfs->transfers = malloc(num_transfers * sizeof(Chunk));
    if (tfs->transfers == NULL) {
        tfs->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
        free(tfs->chunks);
        return;
    }

    tfs->is_upload = true;
    tfs->num_transfers = 0;
    for (int i = 0; i < num_chunks; i++) {
        for (int j = 0; j < tfs->num_servers; j++) {
            tfs->transfers[tfs->num_transfers].state = TRANSFER_PENDING;
            tfs->transfers[tfs->num_transfers].chunk = i;
            tfs->transfers[tfs->num_transfers].server = j;
            tfs->num_transfers++;
        }
    }

    start_transfers(tfs);
    tfs->state = CLIENT_UPLOADING_CHUNKS;
    tfs->pending = true;
    return 0;
}

int toastyfs_async_get(ToastyFS *tfs, char *key, int key_len)
{
    // Only one operation allowed at a time
    if (tfs->state != CLIENT_IDLE)
        return -1; // TODO: error code
    tfs->error = TOASTYFS_ERROR_VOID;

    RequestMessage message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_XXX,
            .sender  = xxx,
            .length  = sizeof(RequestMessage),
        },
        .oper = xxx,
        .client_id = tfs->client_id,
        .request_id = get_next_request_id(tfs),
    };
    send_message(tfs->msys, tfs->primary, &message);

    tfs->state = CLIENT_DOWNLOADING_METADATA;
    return 0;
}

int toastyfs_async_delete(ToastyFS *tfs, char *key, int key_len)
{
    // Only one operation allowed at a time
    if (tfs->state != CLIENT_IDLE)
        return -1; // TODO: error code
    tfs->error = TOASTYFS_ERROR_VOID;

    RequestMessage message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_XXX,
            .sender  = xxx,
            .length  = sizeof(RequestMessage),
        },
        .oper = xxx,
        .client_id = tfs->client_id,
        .request_id = get_next_request_id(tfs),
    };
    send_message(tfs->msys, tfs->primary, &message);

    tfs->state = CLIENT_DELETING_METADATA;
    return 0;
}

static ToastyFS_Result get_result(ToastyFS *tfs, bool consume)
{
    ToastyFS_Result result;
    switch (tfs->state) {
    case CLIENT_FAILED_PUT:
        assert(tfs->error != TOASTYFS_RESULT_VOID);
        result.type = TOASTYFS_RESULT_PUT;
        result.error = tfs->error;
        break;
    case CLIENT_COMPLETED_PUT:
        assert(tfs->error == TOASTYFS_RESULT_VOID);
        result.type = TOASTYFS_RESULT_PUT;
        result.error = TOASTYFS_ERROR_VOID;
        break;
    case CLIENT_FAILED_GET:
        // TODO
        break;
    case CLIENT_COMPLETED_GET:
        // TODO
        break;
    case CLIENT_FAILED_DELETE:
        // TODO
        break;
    case CLIENT_COMPLETED_DELETE:
        // TODO
        break;
    default:
        result.type = TOASTYFS_RESULT_VOID;
        result.error = TOASTYFS_ERROR_VOID;
        break;
    }

    if (consume) {
        // Now restore the struct's state to allow new
        // operations to start
        tfs->state = CLIENT_IDLE;
        tfs->error = TOASTYFS_ERROR_VOID;
    }

    return result;
}

ToastyFS_Result toastyfs_get_result(ToastyFS *tfs)
{
    return get_result(tfs, true);
}

static bool result_available(ToastyFS *tfs)
{
    return get_result(tfs, false).type != TOASTYFS_RESULT_VOID;
}

static void wait_completion(ToastyFS *tfs, ToastyFS_Result *res)
{
    while (!result_available(tfs)) {

        void *ptrs[xxx];
        struct pollfd pfds[xxx];
        int timeout;

        int num = toastyfs_register_events(tfs, ptrs, pfds, cap, &timeout);
        // TODO: can register_events fail?
        POLL(pfds, num, timeout);
        toastyfs_process_events(tfs, ptrs, pfds, num);
    }

    *res = toastyfs_get_result(tfs);
}

int toastyfs_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_put(tfs, key, key_len, data, data_len);
    if (ret < 0)
        return ret;
    wait_completion(tfs, res);
    return 0;
}

int toastyfs_get(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_get(tfs, key, key_len);
    if (ret < 0)
        return ret;
    wait_completion(tfs, res);
    return 0;
}

int toastyfs_delete(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_put(tfs, key, key_len);
    if (ret < 0)
        return ret;
    wait_completion(tfs, res);
    return 0;
}