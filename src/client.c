#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <lib/basic.h>

#include "config.h"
#include "metadata.h"
#include "server.h"
#include <toastyfs.h>
#include <stdio.h>

#define POLL_CAPACITY (NODE_LIMIT * 2 + 4)

typedef enum {
    STEP_IDLE,
    STEP_STORE_CHUNK,
    STEP_COMMIT,
    STEP_DELETE,
    STEP_GET,
    STEP_FETCH_CHUNK,
    STEP_GET_DONE,
    STEP_PUT_DONE,
    STEP_DELETE_DONE,
} Step;

typedef enum {
    TRANSFER_PENDING,
    TRANSFER_STARTED,
    TRANSFER_COMPLETED,
    TRANSFER_ABORTED,
} TransferState;

typedef struct {
    TransferState state;
    SHA256        hash;
    char*         data;
    int           size;
    int           location;
} Transfer;

struct ToastyFS {

    MessageSystem msys;

    Address server_addrs[NODE_LIMIT];
    int num_servers;

    uint64_t view_number;
    uint64_t client_id;
    uint64_t request_id;

    Step step;
    ToastyFS_Error error;
    Time step_time;

    char     bucket[META_BUCKET_MAX];
    char     key[META_KEY_MAX];
    uint64_t blob_size;
    SHA256   content_hash;

    Transfer transfers[MAX_TRANSFERS];
    int num_transfers;

    SHA256 chunks[META_CHUNKS_MAX];
    int    chunk_sizes[META_CHUNKS_MAX];
    int    num_chunks;

    char *put_data;
    int   put_data_len;
};

#define TIME_FMT "%7.3fs"
#define TIME_VAL(t) ((double)(t) / 1000000000.0)

static const char *step_name(Step step)
{
    switch (step) {
    case STEP_IDLE:        return "IDLE";
    case STEP_STORE_CHUNK: return "STORE_CHUNK";
    case STEP_COMMIT:      return "COMMIT";
    case STEP_DELETE:      return "DELETE";
    case STEP_GET:         return "GET";
    case STEP_FETCH_CHUNK: return "FETCH_CHUNK";
    case STEP_GET_DONE:    return "GET_DONE";
    case STEP_PUT_DONE:    return "PUT_DONE";
    case STEP_DELETE_DONE: return "DELETE_DONE";
    }
    return "??";
}

static void client_log_impl(ToastyFS *tfs, const char *event, const char *detail)
{
    Time now = get_current_time();
    printf("[" TIME_FMT "] CLIENT %lu %-12s V%-3lu | %-20s %s\n",
        TIME_VAL(now),
        tfs->client_id,
        step_name(tfs->step),
        tfs->view_number,
        event,
        detail ? detail : "");
}

#define client_log(tfs, event, fmt, ...) do {                     \
    char _detail[1024];                                            \
    snprintf(_detail, sizeof(_detail), fmt, ##__VA_ARGS__);       \
    client_log_impl(tfs, event, _detail);                         \
} while (0)

#define client_log_simple(tfs, event) \
    client_log_impl(tfs, event, NULL)

#warning "TODO: Replace compute_chunk_hash with a proper SHA256 implementation"
static SHA256 compute_chunk_hash(const char *data, int size)
{
    SHA256 hash;
    memset(&hash, 0, sizeof(hash));
    for (int i = 0; i < size; i++) {
        hash.data[i % 32] ^= (unsigned char)data[i];
        hash.data[(i + 7) % 32] += (unsigned char)data[i] * 31;
    }
    return hash;
}

ToastyFS *toastyfs_init(uint64_t client_id, char **addrs, int num_addrs)
{
    ToastyFS *tfs = malloc(sizeof(ToastyFS));
    if (tfs == NULL)
        return NULL;

    tfs->view_number = 0;
    tfs->client_id   = client_id;
    tfs->request_id  = 0;

    for (int i = 0; i < num_addrs; i++) {
        if (parse_addr_arg(addrs[i], &tfs->server_addrs[i]) < 0) {
            free(tfs);
            return NULL;
        }
    }
    tfs->num_servers = num_addrs;
    addr_sort(tfs->server_addrs, tfs->num_servers);

    if (message_system_init(&tfs->msys, tfs->server_addrs, num_addrs) < 0) {
        free(tfs);
        return NULL;
    }

    tfs->step = STEP_IDLE;
    tfs->put_data = NULL;
    tfs->put_data_len = 0;
    client_log(tfs, "INIT", "id=%lu servers=%d", client_id, num_addrs);
    return tfs;
}

void toastyfs_free(ToastyFS *tfs)
{
    message_system_free(&tfs->msys);
    free(tfs->put_data);
}

static int find_completed_transfer_for_hash(ToastyFS *tfs, SHA256 hash);
static bool all_chunk_transfers_completed(ToastyFS *tfs);

static bool
transfer_for_hash_already_started(ToastyFS *tfs, SHA256 hash)
{
    for (int j = 0; j < tfs->num_transfers; j++) {
        Transfer *transfer = &tfs->transfers[j];
        if (!memcmp(&hash, &transfer->hash, sizeof(SHA256)) && transfer->state == TRANSFER_STARTED) {
            return true;
        }
    }
    return false;
}

static bool transfer_should_start(ToastyFS *tfs, Transfer *transfer)
{
    return transfer->state == TRANSFER_PENDING
        && !transfer_for_hash_already_started(tfs, transfer->hash);
}

static void add_transfer(ToastyFS *tfs, SHA256 hash, int location, char *data, int size)
{
    assert(tfs->num_transfers < MAX_TRANSFERS);
    Transfer *transfer = &tfs->transfers[tfs->num_transfers];
    transfer->state = TRANSFER_PENDING;
    transfer->hash = hash;
    transfer->data = data;
    transfer->size = size;
    transfer->location = location;
    tfs->num_transfers++;
}

static int leader_idx(ToastyFS *tfs)
{
    return tfs->view_number % tfs->num_servers;
}

static int begin_transfers(ToastyFS *tfs)
{
    // Count started transfers
    int started = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (tfs->transfers[i].state == TRANSFER_STARTED)
            started++;
    }

    if (started == PARALLEL_TRANSFER_MAX)
        return 0;
    assert(started < PARALLEL_TRANSFER_MAX);

    int num = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (transfer_should_start(tfs, &tfs->transfers[i])) {

            if (tfs->step == STEP_STORE_CHUNK) {
                StoreChunkMessage msg = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_STORE_CHUNK,
                        .length  = sizeof(StoreChunkMessage) + tfs->transfers[i].size,
                    },
                    .hash = tfs->transfers[i].hash,
                    .size = tfs->transfers[i].size,
                };
                send_message_ex(&tfs->msys, tfs->transfers[i].location,
                    &msg.base, tfs->transfers[i].data, tfs->transfers[i].size);
            } else {
                FetchChunkMessage msg = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_FETCH_CHUNK,
                        .length  = sizeof(FetchChunkMessage),
                    },
                    .hash = tfs->transfers[i].hash,
                    .sender_idx = -1, // Client (not a peer server)
                };
                send_message(&tfs->msys, tfs->transfers[i].location, &msg.base);
            }
            tfs->transfers[i].state = TRANSFER_STARTED;

            num++;
            if (started + num == PARALLEL_TRANSFER_MAX)
                break;
            assert(started + num < PARALLEL_TRANSFER_MAX);
        }
    }

    if (num > 0)
        client_log(tfs, "BEGIN_TRANSFERS", "started=%d total=%d", num, tfs->num_transfers);
    return num;
}

static int find_started_transfer_by_hash(ToastyFS *tfs, SHA256 hash)
{
    for (int i = 0; i < tfs->num_transfers; i++)
        if (!memcmp(&tfs->transfers[i].hash, &hash, sizeof(SHA256))
            && tfs->transfers[i].state == TRANSFER_STARTED)
        return i;
    return -1;
}

static void
mark_waiting_transfers_for_hash_as_aborted(ToastyFS *tfs, SHA256 hash)
{
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (!memcmp(&tfs->transfers[i].hash, &hash, sizeof(SHA256))
            && tfs->transfers[i].state == TRANSFER_PENDING)
            tfs->transfers[i].state = TRANSFER_ABORTED;
    }
}

static void replay_request(ToastyFS *tfs)
{
    tfs->step_time = get_current_time(); // TODO: Handle INVALID_TIME error
    client_log(tfs, "REPLAY", "step=%s view=%lu", step_name(tfs->step), tfs->view_number);

    switch (tfs->step) {
    case STEP_COMMIT:
        {
            CommitPutMessage msg = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_COMMIT_PUT,
                    .length  = sizeof(CommitPutMessage),
                },
                .oper = {
                    .type = META_OPER_PUT,
                    .size = tfs->blob_size,
                    .content_hash = tfs->content_hash,
                    .num_chunks = tfs->num_chunks,
                },
                .client_id  = tfs->client_id,
                .request_id = tfs->request_id,
            };
            memcpy(msg.oper.bucket, tfs->bucket, META_BUCKET_MAX);
            memcpy(msg.oper.key,    tfs->key,    META_KEY_MAX);
            for (int i = 0; i < tfs->num_chunks; i++) {
                msg.oper.chunks[i].hash = tfs->chunks[i];
                msg.oper.chunks[i].size = tfs->chunk_sizes[i];
            }
            send_message(&tfs->msys, leader_idx(tfs), &msg.base);
        }
        break;
    case STEP_DELETE:
        {
            RequestMessage msg = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_REQUEST,
                    .length  = sizeof(RequestMessage),
                },
                .oper = {
                    .type = META_OPER_DELETE,
                },
                .client_id  = tfs->client_id,
                .request_id = tfs->request_id,
            };
            memcpy(msg.oper.bucket, tfs->bucket, META_BUCKET_MAX);
            memcpy(msg.oper.key,    tfs->key,    META_KEY_MAX);
            send_message(&tfs->msys, leader_idx(tfs), &msg.base);
        }
        break;
    case STEP_GET:
        {
            GetBlobMessage msg = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_GET_BLOB,
                    .length  = sizeof(GetBlobMessage),
                },
            };
            memcpy(msg.bucket, tfs->bucket, META_BUCKET_MAX);
            memcpy(msg.key, tfs->key, META_KEY_MAX);
            send_message(&tfs->msys, leader_idx(tfs), &msg.base);
        }
        break;
    default:
        break;
    }
}

static int process_message(ToastyFS *tfs, uint16_t type, ByteView msg)
{
    switch (tfs->step) {
    case STEP_FETCH_CHUNK:
        {
            if (type == MESSAGE_TYPE_FETCH_CHUNK_RESPONSE) {

                FetchChunkResponseMessage resp;
                if (msg.len < sizeof(FetchChunkResponseMessage))
                    return -1;
                memcpy(&resp, msg.ptr, sizeof(resp));
                char *data = (char *)msg.ptr + sizeof(resp);

                int transfer_idx = find_started_transfer_by_hash(tfs, resp.hash);
                assert(transfer_idx > -1);

                if (resp.size == 0) {
                    client_log(tfs, "RECV FETCH_RESP", "size=0 (not found)");
                    tfs->transfers[transfer_idx].state = TRANSFER_ABORTED;
                    break;
                }

                char *copy = malloc(resp.size);
                if (copy == NULL) {
                    tfs->transfers[transfer_idx].state = TRANSFER_ABORTED;
                    break;
                }
                memcpy(copy, data, resp.size);

                tfs->transfers[transfer_idx].state = TRANSFER_COMPLETED;
                tfs->transfers[transfer_idx].data = copy;
                tfs->transfers[transfer_idx].size = resp.size;
                mark_waiting_transfers_for_hash_as_aborted(tfs, resp.hash);
                client_log(tfs, "RECV FETCH_RESP", "size=%u", resp.size);

                begin_transfers(tfs);
                if (all_chunk_transfers_completed(tfs)) {
                    tfs->error = TOASTYFS_ERROR_VOID;
                    tfs->step = STEP_GET_DONE;
                    client_log_simple(tfs, "ALL CHUNKS FETCHED");
                }

            } else {
                client_log(tfs, "RECV UNEXPECTED", "type=%d in FETCH_CHUNK", type);
                tfs->error = TOASTYFS_ERROR_UNEXPECTED_MESSAGE;
                tfs->step = STEP_GET_DONE;
            }
        }
        break;
    case STEP_STORE_CHUNK:
        {
            if (type == MESSAGE_TYPE_STORE_CHUNK_ACK) {

                StoreChunkAckMessage ack;
                if (msg.len != sizeof(StoreChunkAckMessage))
                    return -1;
                memcpy(&ack, msg.ptr, sizeof(ack));

                client_log(tfs, "RECV STORE_ACK", "success=%d", ack.success);

                if (ack.success) {

                    int transfer_idx = find_started_transfer_by_hash(tfs, ack.hash);
                    assert(transfer_idx > -1);

                    tfs->transfers[transfer_idx].state = TRANSFER_COMPLETED;
                    mark_waiting_transfers_for_hash_as_aborted(tfs, ack.hash);

                    begin_transfers(tfs);
                    if (all_chunk_transfers_completed(tfs)) {

                        tfs->request_id++;
                        CommitPutMessage msg = {
                            .base = {
                                .version = MESSAGE_VERSION,
                                .type    = MESSAGE_TYPE_COMMIT_PUT,
                                .length  = sizeof(CommitPutMessage),
                            },
                            .oper = {
                                .type = META_OPER_PUT,
                                .size = tfs->blob_size,
                                .content_hash = tfs->content_hash,
                                .num_chunks = tfs->num_chunks,
                            },
                            .client_id  = tfs->client_id,
                            .request_id = tfs->request_id,
                        };
                        memcpy(msg.oper.bucket, tfs->bucket, META_BUCKET_MAX);
                        memcpy(msg.oper.key,    tfs->key,    META_KEY_MAX);
                        for (int i = 0; i < tfs->num_chunks; i++) {
                            msg.oper.chunks[i].hash = tfs->chunks[i];
                            msg.oper.chunks[i].size = tfs->chunk_sizes[i];
                        }
                        send_message(&tfs->msys, leader_idx(tfs), &msg.base);
                        tfs->step = STEP_COMMIT;
                        client_log(tfs, "SEND COMMIT_PUT", "key=%s chunks=%d req=%lu",
                            tfs->key, tfs->num_chunks, tfs->request_id);
                    }

                } else {
                    client_log_simple(tfs, "STORE FAILED");
                    tfs->error = TOASTYFS_ERROR_TRANSFER_FAILED;
                    tfs->step = STEP_PUT_DONE;
                }

            } else {
                client_log(tfs, "RECV UNEXPECTED", "type=%d in STORE_CHUNK", type);
                tfs->error = TOASTYFS_ERROR_UNEXPECTED_MESSAGE;
                tfs->step = STEP_PUT_DONE;
            }
        }
        break;
    case STEP_COMMIT:
        {
            if (type == MESSAGE_TYPE_REDIRECT) {

                RedirectMessage redirect;
                if (msg.len != sizeof(RedirectMessage))
                    return -1;
                memcpy(&redirect, msg.ptr, sizeof(redirect));

                client_log(tfs, "RECV REDIRECT", "view=%lu (local view=%lu)", redirect.view_number, tfs->view_number);
                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_REPLY) {

                VsrReplyMessage reply;
                if (msg.len != sizeof(VsrReplyMessage))
                    return -1;
                memcpy(&reply, msg.ptr, sizeof(reply));

                if (reply.request_id != tfs->request_id)
                    return 0;

                if (reply.rejected) {
                    client_log_simple(tfs, "RECV REPLY REJECTED");
                    tfs->error = TOASTYFS_ERROR_REJECTED;
                    tfs->step = STEP_PUT_DONE;
                    break;
                }

                if (reply.result.type == META_RESULT_FULL) {
                    client_log_simple(tfs, "RECV REPLY FULL");
                    tfs->error = TOASTYFS_ERROR_FULL;
                    tfs->step = STEP_PUT_DONE;
                    break;
                }

                assert(reply.result.type == META_RESULT_OK);
                client_log_simple(tfs, "RECV REPLY OK");
                tfs->error = TOASTYFS_ERROR_VOID;
                tfs->step = STEP_PUT_DONE;

            } else {
                client_log(tfs, "RECV UNEXPECTED", "type=%d in COMMIT", type);
                tfs->error = TOASTYFS_ERROR_UNEXPECTED_MESSAGE;
                tfs->step = STEP_PUT_DONE;
            }
        }
        break;
    case STEP_DELETE:
        {
            if (type == MESSAGE_TYPE_REDIRECT) {

                RedirectMessage redirect;
                if (msg.len != sizeof(RedirectMessage))
                    return -1;
                memcpy(&redirect, msg.ptr, sizeof(redirect));

                client_log(tfs, "RECV REDIRECT", "view=%lu (local view=%lu)", redirect.view_number, tfs->view_number);
                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_REPLY) {

                VsrReplyMessage reply;
                if (msg.len != sizeof(VsrReplyMessage))
                    return -1;
                memcpy(&reply, msg.ptr, sizeof(reply));

                if (reply.request_id != tfs->request_id)
                    break;

                if (reply.rejected) {
                    client_log_simple(tfs, "RECV REPLY REJECTED");
                    tfs->error = TOASTYFS_ERROR_REJECTED;
                    tfs->step = STEP_DELETE_DONE;
                    break;
                }

                if (reply.result.type == META_RESULT_FULL) {
                    client_log_simple(tfs, "RECV REPLY FULL");
                    tfs->error = TOASTYFS_ERROR_FULL;
                    tfs->step = STEP_DELETE_DONE;
                    break;
                }

                if (reply.result.type == META_RESULT_NOT_FOUND) {
                    client_log_simple(tfs, "RECV REPLY NOT_FOUND");
                    tfs->error = TOASTYFS_ERROR_NOT_FOUND;
                    tfs->step = STEP_DELETE_DONE;
                    break;
                }

                assert(reply.result.type == META_RESULT_OK);
                client_log_simple(tfs, "RECV REPLY OK");
                tfs->error = TOASTYFS_ERROR_VOID;
                tfs->step = STEP_DELETE_DONE;

            } else {
                client_log(tfs, "RECV UNEXPECTED", "type=%d in DELETE", type);
                tfs->error = TOASTYFS_ERROR_UNEXPECTED_MESSAGE;
                tfs->step = STEP_DELETE_DONE;
            }
        }
        break;
    case STEP_GET:
        {
            if (type == MESSAGE_TYPE_REDIRECT) {

                RedirectMessage redirect;
                if (msg.len != sizeof(RedirectMessage))
                    return -1;
                memcpy(&redirect, msg.ptr, sizeof(redirect));

                client_log(tfs, "RECV REDIRECT", "view=%lu (local view=%lu)", redirect.view_number, tfs->view_number);
                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_GET_BLOB_RESPONSE) {

                GetBlobResponseMessage resp;
                if (msg.len != sizeof(GetBlobResponseMessage))
                    return -1;
                memcpy(&resp, msg.ptr, sizeof(resp));

                client_log(tfs, "RECV GET_BLOB_RESP", "found=%d chunks=%u size=%lu",
                    resp.found, resp.num_chunks, resp.size);

                if (resp.found) {

                    tfs->num_transfers = 0;
                    for (int i = 0; i < (int)resp.num_chunks; i++) {
                        // TODO: The server selection formula is a temporary
                        //       solution. Figure out a proper strategy for
                        //       picking which servers to fetch chunks from.
                        for (int j = 0; j < REPLICATION_FACTOR; j++) {
                            add_transfer(tfs, resp.chunks[i].hash,
                                (i + j) % tfs->num_servers, NULL, 0);
                        }
                        tfs->chunks[i] = resp.chunks[i].hash;
                        tfs->chunk_sizes[i] = resp.chunks[i].size;
                    }
                    tfs->num_chunks = resp.num_chunks;
                    tfs->blob_size = resp.size;

                    if (begin_transfers(tfs) == 0) {
                        tfs->error = TOASTYFS_ERROR_VOID;
                        tfs->step = STEP_GET_DONE;
                    } else {
                        tfs->step = STEP_FETCH_CHUNK;
                    }

                } else {
                    tfs->error = TOASTYFS_ERROR_NOT_FOUND;
                    tfs->step = STEP_GET_DONE;
                }

            } else {
                client_log(tfs, "RECV UNEXPECTED", "type=%d in GET", type);
                tfs->error = TOASTYFS_ERROR_UNEXPECTED_MESSAGE;
                tfs->step = STEP_GET_DONE;
            }
        }
        break;
    default:
        UNREACHABLE;
    }

    return 0;
}

void toastyfs_process_events(ToastyFS *tfs, void **ctxs, struct pollfd *pdata, int pnum)
{
    message_system_process_events(&tfs->msys, ctxs, pdata, pnum);

    void *raw;
    while ((raw = get_next_message(&tfs->msys)) != NULL) {
        Message *header = (Message *)raw;
        ByteView msg_view = { .ptr = raw, .len = header->length };
        process_message(tfs, header->type, msg_view);
        consume_message(&tfs->msys, raw);
    }

    // Check for operation timeout -- retry the current operation if the
    // deadline has passed (handles initial sends that were dropped because
    // the TCP connection wasn't established yet, and unresponsive servers).
    if (tfs->step != STEP_IDLE
        && tfs->step != STEP_PUT_DONE
        && tfs->step != STEP_GET_DONE
        && tfs->step != STEP_DELETE_DONE) {
        Time now = get_current_time();
        Time deadline = tfs->step_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL;
        if (now >= deadline) {
            client_log_simple(tfs, "TIMEOUT RETRY");
            switch (tfs->step) {
            case STEP_STORE_CHUNK:
            case STEP_FETCH_CHUNK:
                for (int i = 0; i < tfs->num_transfers; i++) {
                    if (tfs->transfers[i].state == TRANSFER_STARTED)
                        tfs->transfers[i].state = TRANSFER_PENDING;
                }
                tfs->step_time = now;
                begin_transfers(tfs);
                break;
            case STEP_COMMIT:
            case STEP_DELETE:
            case STEP_GET:
                replay_request(tfs);
                break;
            default:
                break;
            }
        }
    }
}

// TODO: The toastyfs client needs to determine a timeout based on the
//       pending operation status, not just use PRIMARY_DEATH_TIMEOUT_SEC
//       for everything.
int toastyfs_register_events(ToastyFS *tfs, void **ctxs, struct pollfd *pdata, int pcap, int *timeout)
{
    Time now = get_current_time(); // TODO: Handle INVALID_TIME error
    Time deadline = INVALID_TIME;

    if (tfs->step != STEP_IDLE) {
        nearest_deadline(&deadline, tfs->step_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL);
    }

    *timeout = deadline_to_timeout(deadline, now);
    if (pcap < POLL_CAPACITY)
        return -1;
    return message_system_register_events(&tfs->msys, ctxs, pdata, pcap);
}

static void
choose_store_locations_for_chunk(ToastyFS *tfs, int chunk_idx, int *locations)
{
    for (int j = 0; j < REPLICATION_FACTOR; j++) {
        locations[j] = (chunk_idx + j) % tfs->num_servers;
    }
}

// NOTE: Since the client can only perform one request at a time, it's
//       possible for the toastyfs_async_xxx functions to not return an
//       error and instead set a sticky error that will be used when
//       toastyfs_get_result is called.

int toastyfs_async_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

    int num_chunks = CEIL(data_len, CHUNK_SIZE);
    if (num_chunks == 0)
        num_chunks = 1;
    if (num_chunks > META_CHUNKS_MAX)
        return -1;

    // Copy the data for the duration of the upload
    char *data_copy = malloc(data_len);
    if (data_copy == NULL && data_len > 0)
        return -1;
    if (data_len > 0)
        memcpy(data_copy, data, data_len);
    free(tfs->put_data);
    tfs->put_data = data_copy;
    tfs->put_data_len = data_len;

    // Set key/bucket metadata
    memset(tfs->bucket, 0, META_BUCKET_MAX);
    memset(tfs->key, 0, META_KEY_MAX);
    int copy_len = key_len < META_KEY_MAX - 1 ? key_len : META_KEY_MAX - 1;
    memcpy(tfs->key, key, copy_len);

    tfs->blob_size = data_len;
    tfs->content_hash = compute_chunk_hash(data, data_len);
    tfs->num_chunks = num_chunks;
    tfs->num_transfers = 0;

    for (int i = 0; i < num_chunks; i++) {

        int offset = i * CHUNK_SIZE;
        int size = data_len - offset;
        if (size > CHUNK_SIZE)
            size = CHUNK_SIZE;

        SHA256 hash = compute_chunk_hash(data_copy + offset, size);

        int locations[REPLICATION_FACTOR];
        choose_store_locations_for_chunk(tfs, i, locations);

        for (int j = 0; j < REPLICATION_FACTOR; j++)
            add_transfer(tfs, hash, locations[j], data_copy + offset, size);

        tfs->chunks[i] = hash;
        tfs->chunk_sizes[i] = size;
    }

    tfs->step_time = get_current_time(); // TODO: Handle INVALID_TIME error
    tfs->step = STEP_STORE_CHUNK;
    client_log(tfs, "ASYNC PUT", "key=%s size=%d chunks=%d", tfs->key, data_len, num_chunks);

    if (begin_transfers(tfs) == 0) {
        // Early completion
        tfs->error = TOASTYFS_ERROR_VOID;
        tfs->step = STEP_PUT_DONE;
    }
    return 0;
}

int toastyfs_async_get(ToastyFS *tfs, char *key, int key_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

    memset(tfs->bucket, 0, META_BUCKET_MAX);
    memset(tfs->key, 0, META_KEY_MAX);
    int copy_len = key_len < META_KEY_MAX - 1 ? key_len : META_KEY_MAX - 1;
    memcpy(tfs->key, key, copy_len);

    tfs->num_transfers = 0;
    tfs->num_chunks = 0;

    GetBlobMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_GET_BLOB,
            .length  = sizeof(GetBlobMessage),
        },
    };
    memcpy(msg.bucket, tfs->bucket, META_BUCKET_MAX);
    memcpy(msg.key, tfs->key, META_KEY_MAX);

    tfs->step_time = get_current_time(); // TODO: Handle INVALID_TIME error
    tfs->step = STEP_GET;
    client_log(tfs, "ASYNC GET", "key=%s leader=%d", tfs->key, leader_idx(tfs));
    send_message(&tfs->msys, leader_idx(tfs), &msg.base);
    return 0;
}

int toastyfs_async_delete(ToastyFS *tfs, char *key, int key_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

    memset(tfs->bucket, 0, META_BUCKET_MAX);
    memset(tfs->key, 0, META_KEY_MAX);
    int copy_len = key_len < META_KEY_MAX - 1 ? key_len : META_KEY_MAX - 1;
    memcpy(tfs->key, key, copy_len);

    tfs->request_id++;

    RequestMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_REQUEST,
            .length  = sizeof(RequestMessage),
        },
        .oper = {
            .type = META_OPER_DELETE,
        },
        .client_id  = tfs->client_id,
        .request_id = tfs->request_id,
    };
    memcpy(msg.oper.bucket, tfs->bucket, META_BUCKET_MAX);
    memcpy(msg.oper.key,    tfs->key,    META_KEY_MAX);

    tfs->step_time = get_current_time(); // TODO: Handle INVALID_TIME error
    tfs->step = STEP_DELETE;
    client_log(tfs, "ASYNC DELETE", "key=%s req=%lu leader=%d", tfs->key, tfs->request_id, leader_idx(tfs));
    send_message(&tfs->msys, leader_idx(tfs), &msg.base);
    return 0;
}

static int
find_completed_transfer_for_hash(ToastyFS *tfs, SHA256 hash)
{
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (!memcmp(&hash, &tfs->transfers[i].hash, sizeof(SHA256))
            && tfs->transfers[i].state == TRANSFER_COMPLETED)
            return i;
    }
    return -1;
}

static void free_transfer_data(ToastyFS *tfs)
{
    for (int i = 0; i < tfs->num_transfers; i++) {
        // Only free data for fetch transfers (data allocated by malloc in process_message)
        // Upload transfers point into put_data which is freed separately
        if (tfs->step == STEP_GET_DONE && tfs->transfers[i].data != NULL) {
            free(tfs->transfers[i].data);
            tfs->transfers[i].data = NULL;
        }
    }
}

static void get_result(ToastyFS *tfs, ToastyFS_Result *result)
{
    assert(tfs->step == STEP_GET_DONE);

    if (tfs->error != TOASTYFS_ERROR_VOID) {
        free_transfer_data(tfs);
        tfs->step = STEP_IDLE;
        result->type = TOASTYFS_RESULT_GET;
        result->error = tfs->error;
        result->data = NULL;
        result->size = 0;
        return;
    }

    int blob_size = tfs->blob_size;
    char *blob_data = malloc(tfs->blob_size);
    if (blob_data == NULL) {
        free_transfer_data(tfs);
        tfs->step = STEP_IDLE;
        result->type  = TOASTYFS_RESULT_GET;
        result->error = TOASTYFS_ERROR_OUT_OF_MEMORY;
        result->data  = NULL;
        result->size  = 0;
        return;
    }

    int offset = 0;
    for (int i = 0; i < tfs->num_chunks; i++) {

        SHA256 hash = tfs->chunks[i];

        int j = find_completed_transfer_for_hash(tfs, hash);
        if (j < 0) {
            free(blob_data);
            free_transfer_data(tfs);
            tfs->step = STEP_IDLE;
            result->type  = TOASTYFS_RESULT_GET;
            result->error = TOASTYFS_ERROR_TRANSFER_FAILED;
            result->data  = NULL;
            result->size  = 0;
            return;
        }

        char *data = tfs->transfers[j].data;
        int   size = tfs->transfers[j].size;

        if (size > blob_size - offset)
            size = blob_size - offset;

        memcpy(blob_data + offset, data, size);

        offset += size;
    }

    free_transfer_data(tfs);
    tfs->step = STEP_IDLE;

    result->type  = TOASTYFS_RESULT_GET;
    result->error = TOASTYFS_ERROR_VOID;
    result->data  = blob_data;
    result->size  = blob_size;
}

static bool
all_chunk_transfers_completed(ToastyFS *tfs)
{
    for (int i = 0; i < tfs->num_chunks; i++) {
        int j = find_completed_transfer_for_hash(tfs, tfs->chunks[i]);
        if (j < 0)
            return false;
    }
    return true;
}

static void put_result(ToastyFS *tfs, ToastyFS_Result *result)
{
    assert(tfs->step == STEP_PUT_DONE);
    tfs->step = STEP_IDLE;

    // Free the upload data copy
    free(tfs->put_data);
    tfs->put_data = NULL;
    tfs->put_data_len = 0;

    if (tfs->error != TOASTYFS_ERROR_VOID) {
        result->type = TOASTYFS_RESULT_PUT;
        result->error = tfs->error;
        result->data = NULL;
        result->size = 0;
        return;
    }

    if (!all_chunk_transfers_completed(tfs)) {
        result->type  = TOASTYFS_RESULT_PUT;
        result->error = TOASTYFS_ERROR_TRANSFER_FAILED;
        result->data  = NULL;
        result->size  = 0;
        return;
    }

    result->type  = TOASTYFS_RESULT_PUT;
    result->error = TOASTYFS_ERROR_VOID;
    result->data  = NULL;
    result->size  = 0;
}

static void delete_result(ToastyFS *tfs, ToastyFS_Result *result)
{
    assert(tfs->step == STEP_DELETE_DONE);
    tfs->step = STEP_IDLE;

    if (tfs->error != TOASTYFS_ERROR_VOID) {
        result->type = TOASTYFS_RESULT_DELETE;
        result->error = tfs->error;
        result->data = NULL;
        result->size = 0;
        return;
    }

    result->type = TOASTYFS_RESULT_DELETE;
    result->error = TOASTYFS_ERROR_VOID;
    result->data = NULL;
    result->size = 0;
}

ToastyFS_Result toastyfs_get_result(ToastyFS *tfs)
{
    ToastyFS_Result result;
    if (tfs->step == STEP_GET_DONE) {
        get_result(tfs, &result);
    } else if (tfs->step == STEP_PUT_DONE) {
        put_result(tfs, &result);
    } else if (tfs->step == STEP_DELETE_DONE) {
        delete_result(tfs, &result);
    } else {
        result.type = TOASTYFS_RESULT_VOID;
        result.error = TOASTYFS_ERROR_VOID;
        result.data = NULL;
        result.size = 0;
    }
    return result;
}

static int wait_until_result(ToastyFS *tfs, ToastyFS_Result *res)
{
    for (;;) {
        void *ctxs[POLL_CAPACITY];
        struct pollfd arr[POLL_CAPACITY];
        int poll_timeout;
        int num = toastyfs_register_events(tfs, ctxs, arr, POLL_CAPACITY, &poll_timeout);
        if (num < 0)
            return num;

#ifdef _WIN32
        WSAPoll(arr, num, poll_timeout);
#else
        poll(arr, num, poll_timeout);
#endif

        toastyfs_process_events(tfs, ctxs, arr, num);
        *res = toastyfs_get_result(tfs);
        if (res->type != TOASTYFS_RESULT_VOID)
            return 0;
    }
}

int toastyfs_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_put(tfs, key, key_len, data, data_len);
    if (ret < 0)
        return ret;
    return wait_until_result(tfs, res);
}

int toastyfs_get(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_get(tfs, key, key_len);
    if (ret < 0)
        return ret;
    return wait_until_result(tfs, res);
}

int toastyfs_delete(ToastyFS *tfs, char *key, int key_len, ToastyFS_Result *res)
{
    int ret = toastyfs_async_delete(tfs, key, key_len);
    if (ret < 0)
        return ret;
    return wait_until_result(tfs, res);
}
