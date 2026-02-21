#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <poll.h>

#include "tcp.h"
#include "basic.h"
#include "config.h"
#include "metadata.h"
#include "server.h"
#include <toastyfs.h>

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

    TCP tcp;

    Address server_addrs[NODE_LIMIT];
    int num_servers;

    uint64_t view_number;
    uint64_t client_id;
    uint64_t request_id;

    Step step;
    ToastyFS_Error error;
    Time phase_time;

    char     bucket[META_BUCKET_MAX];
    char     key[META_KEY_MAX];
    uint64_t blob_size;
    SHA256   content_hash;
    uint64_t file_size;

    Transfer transfers[META_CHUNKS_MAX * REPLICATION_FACTOR];
    int num_transfers;

    SHA256 chunks[META_CHUNKS_MAX];
    int num_chunks;
};

ToastyFS *toastyfs_alloc(void)
{
    return malloc(sizeof(ToastyFS));
}

int toastyfs_init(ToastyFS *tfs, uint64_t client_id, char **addrs, int num_addrs)
{
    tfs->view_number = 0;
    tfs->client_id   = client_id;
    tfs->request_id  = 0;

    for (int i = 0; i < num_addrs; i++) {
        if (parse_addr_arg(addrs[i], &tfs->server_addrs[i]) < 0)
            return -1;
    }
    tfs->num_servers = num_addrs;
    addr_sort(tfs->server_addrs, tfs->num_servers);

    if (tcp_context_init(&tfs->tcp) < 0)
        return -1;

    tfs->step = STEP_IDLE;
    return 0;
}

void toastyfs_free(ToastyFS *tfs)
{
    tcp_context_free(&tfs->tcp);
}

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
    assert(tfs->num_transfers < xxx);
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

static void send_message_to_server(ToastyFS *tfs, int server_idx, MessageHeader *msg)
{
    int conn_idx = tcp_index_from_tag(&tfs->tcp, server_idx);
    if (conn_idx < 0) {
        tcp_connect(&tfs->tcp, tfs->server_addrs[server_idx], server_idx, NULL);
        return;
    }

    ByteQueue *output = tcp_output_buffer(&tfs->tcp, conn_idx);
    if (output == NULL)
        return;

    byte_queue_write(output, msg, msg->length);
}

static int begin_transfers(ToastyFS *tfs)
{
    int num = 0;
    for (int i = 0; i < tfs->num_transfers; i++) {
        if (transfer_should_start(tfs, &tfs->transfers[i])) {

            FetchChunkMessage msg = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_FETCH_CHUNK,
                    .length  = sizeof(FetchChunkMessage),
                },
                .hash = tfs->transfers[i].hash,
                .sender_idx = -1, // Client (not a peer server)
            };
            send_message_to_server(tfs, tfs->transfers[i].location, (MessageHeader*)&msg);

            tfs->transfers[i].state = TRANSFER_STARTED;
            num++;
        }
    }

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

static int process_message(ToastyFS *tfs,
    int conn_idx, uint8_t type, ByteView msg)
{
    (void) conn_idx;

    switch (tfs->step) {
    case STEP_FETCH_CHUNK:
        {
            if (type == MESSAGE_TYPE_FETCH_CHUNK_RESPONSE) {

                FetchChunkResponseMessage resp;
                if (msg.len < sizeof(FetchChunkResponseMessage))
                    return -1;
                memcpy(&resp, msg.ptr, sizeof(resp));
                char *data = msg.ptr + sizeof(resp);

                int transfer_idx = find_started_transfer_by_hash(tfs, resp.hash);
                assert(transfer_idx > -1);

                if (!resp.size) {
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

                if (begin_transfers(tfs) == 0) {
                    tfs->error = TOASTYFS_ERROR_VOID;
                    tfs->step = STEP_GET_DONE;
                } else {
                    tfs->step = STEP_FETCH_CHUNK;
                }

            } else {
                tfs->error = TOASTYFS_ERROR_XXX;
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

                if (ack.success) {

                    int transfer_idx = find_started_transfer_by_hash(tfs, ack.hash);
                    assert(transfer_idx > -1);

                    // TODO: Mark all waiting transfers for the same hash as ABORTED
                    tfs->transfers[transfer_idx].state = TRANSFER_COMPLETED;

                    if (begin_transfers(tfs) == 0) {

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
                            msg.oper.chunks[i].size = xxx;
                        }
                        send_message_to_server(tfs, leader_idx(tfs), (MessageHeader*)&msg);
                        tfs->step = STEP_COMMIT;

                    } else {
                        tfs->step = STEP_STORE_CHUNK;
                    }

                } else {
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_PUT_DONE;
                }

            } else {
                tfs->error = TOASTYFS_ERROR_XXX;
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

                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_REPLY) {

                ReplyMessage reply;
                if (msg.len != sizeof(ReplyMessage))
                    return -1;
                memcpy(&reply, msg.ptr, sizeof(reply));

                if (reply.request_id != tfs->request_id)
                    return 0;

                if (reply.rejected) {
                    // Operation rejected at the VSR layer
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_PUT_DONE;
                    break;
                }

                if (reply.result.type == META_RESULT_FULL) {
                    // Storage is full
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_PUT_DONE;
                    break;
                }

                assert(reply.result.type == META_RESULT_OK);
                tfs->error = TOASTYFS_ERROR_VOID;
                tfs->step = STEP_PUT_DONE;

            } else {
                tfs->error = TOASTYFS_ERROR_XXX;
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

                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_REPLY) {

                ReplyMessage reply;
                if (msg.len != sizeof(ReplyMessage))
                    return -1;
                memcpy(&reply, msg.ptr, sizeof(reply));

                if (reply.request_id != tfs->request_id)
                    break;

                if (reply.rejected) {
                    // Operation rejected at the VSR layer
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_DELETE_DONE;
                    break;
                }

                if (reply.result.type == META_RESULT_FULL) {
                    // Storage is full
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_DELETE_DONE;
                    break;
                }

                assert(reply.result.type == META_RESULT_OK);
                tfs->error = TOASTYFS_ERROR_VOID;
                tfs->step = STEP_DELETE_DONE;

            } else {
                tfs->error = TOASTYFS_ERROR_XXX;
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

                if (redirect.view_number > tfs->view_number) {
                    tfs->view_number = redirect.view_number;
                    replay_request(tfs);
                }

            } else if (type == MESSAGE_TYPE_GET_BLOB_RESPONSE) {

                GetBlobResponseMessage resp;
                if (msg.len != sizeof(GetBlobResponseMessage))
                    return -1;
                memcpy(&resp, msg.ptr, sizeof(resp));

                if (resp.found) {

                    for (int i = 0; i < resp.num_chunks; i++) {
                        for (int j = 0; j < REPLICATION_FACTOR; j++) {
                            add_transfer(tfs, resp.chunks[i].hash, xxx, NULL, 0);
                        }
                        tfs->chunks[i] = resp.chunks[i].hash;
                    }
                    tfs->num_chunks = resp.num_chunks;
                    tfs->file_size = resp.size;

                    if (begin_transfers(tfs) == 0) {
                        tfs->error = TOASTYFS_ERROR_XXX;
                        tfs->step = STEP_GET_DONE;
                    } else {
                        tfs->step = STEP_FETCH_CHUNK;
                    }

                } else {
                    tfs->error = TOASTYFS_ERROR_XXX;
                    tfs->step = STEP_GET_DONE;
                }

            } else {
                tfs->error = TOASTYFS_ERROR_XXX;
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
    Event events[TCP_EVENT_CAPACITY];
    int num_events = tcp_translate_events(&tfs->tcp, events, ctxs, pdata, pnum);

    for (int i = 0; i < num_events; i++) {

        if (events[i].type == EVENT_DISCONNECT) {
            int conn_idx = events[i].conn_idx;
            tcp_close(&tfs->tcp, conn_idx);
            continue;
        }

        if (events[i].type != EVENT_MESSAGE)
            continue;

        int conn_idx = events[i].conn_idx;
        for (;;) {
            ByteView msg;
            uint16_t msg_type;
            int ret = tcp_next_message(&tfs->tcp, conn_idx, &msg, &msg_type);
            if (ret == 0)
                break;
            if (ret < 0) {
                tcp_close(&tfs->tcp, conn_idx);
                break;
            }

            ret = process_message(tfs, conn_idx, msg_type, msg);
            if (ret < 0) {
                tcp_close(&tfs->tcp, conn_idx);
                break;
            }

            tcp_consume_message(&tfs->tcp, conn_idx);
        }
    }
}

int toastyfs_register_events(ToastyFS *tfs, void **ctxs, struct pollfd *pdata, int pcap)
{
    Time now = get_current_time();
    Time deadline = INVALID_TIME;

    // TODO: Add timeout for the current operation
    if (tfs->step != STEP_IDLE) {
        nearest_deadline(&deadline, tfs->phase_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL);
    }

    (void) deadline_to_timeout(deadline, now);
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    return tcp_register_events(&tfs->tcp, ctxs, pdata);
}

static void
choose_store_locations_for_chunk(ToastyFS *tfs, int *locations)
{
    // TODO: Pick REPLICATION_FACTOR servers and store their
    //       indices in "locations"
}

int toastyfs_async_put(ToastyFS *tfs, char *key, int key_len,
    char *data, int data_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

    for (int i = 0; i < num_chunks; i++) {

        SHA256 hash = xxx;

        int locations[REPLICATION_FACTOR];
        choose_store_locations_for_chunk(tfs, locations);

        for (int j = 0; j < REPLICATION_FACTOR; j++)
            add_transfer(tfs, hash, locations[j], NULL, 0);

        tfs->chunks[i] = hash;
    }

    tfs->step = STEP_STORE_CHUNK;

    if (begin_transfers(tfs) == 0) {
        // Eatly completion
        tfs->step = STEP_PUT_DONE;
    }
    return 0;
}

int toastyfs_async_get(ToastyFS *tfs, char *key, int key_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

    GetBlobMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_GET_BLOB,
            .length  = sizeof(GetBlobMessage),
        },
    };
    memcpy(msg.bucket, tfs->bucket, META_BUCKET_MAX);
    memcpy(msg.key, tfs->key, META_KEY_MAX);

    send_message_to_server(tfs, xxx, (MessageHeader*)&msg);
    return 0;
}

int toastyfs_async_delete(ToastyFS *tfs, char *key, int key_len)
{
    if (tfs->step != STEP_IDLE)
        return -1;

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

    send_message_to_server(tfs, leader_idx(tfs), (MessageHeader*)&msg);
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

static void get_result(ToastyFS *tfs, ToastyFS_Result *result)
{
    assert(tfs->step == STEP_GET_DONE);
    tfs->step = STEP_IDLE;

    if (tfs->error != TOASTYFS_ERROR_VOID) {
        result->type = TOASTYFS_RESULT_GET;
        result->error = tfs->error;
        result->data = NULL;
        result->size = 0;
        return;
    }

    int blob_size = tfs->file_size;
    char *blob_data = malloc(tfs->file_size);
    if (blob_data == NULL) {
        result->type  = TOASTYFS_RESULT_GET;
        result->error = TOASTYFS_ERROR_XXX;
        result->data  = NULL;
        result->size  = 0;
        return;
    }

    int chunk_size = xxx;
    int offset = 0;
    for (int i = 0; i < tfs->num_chunks; i++) {

        SHA256 hash = tfs->chunks[i];

        int j = find_completed_transfer_for_hash(tfs, hash);
        if (j < 0) {
            result->type  = TOASTYFS_RESULT_GET;
            result->error = TOASTYFS_ERROR_XXX;
            result->data  = NULL;
            result->size  = 0;
            return;
        }

        char *data = tfs->transfers[j].data;
        int   size = tfs->transfers[j].size;

        if (size > blob_size - offset)
            size = blob_size - offset;

        memcpy(blob_data + offset, data, size);

        offset += chunk_size;
    }

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

    if (tfs->error != TOASTYFS_ERROR_VOID) {
        result->type = TOASTYFS_RESULT_PUT;
        result->error = tfs->error;
        result->data = NULL;
        result->size = 0;
        return;
    }

    if (!all_chunk_transfers_completed(tfs)) {
        result->type  = TOASTYFS_RESULT_PUT;
        result->error = TOASTYFS_ERROR_XXX;
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
        void *ctxs[TCP_POLL_CAPACITY];
        struct pollfd arr[TCP_POLL_CAPACITY];
        int num = toastyfs_register_events(tfs, ctxs, arr, TCP_POLL_CAPACITY);
        if (num < 0)
            return num;

        poll(arr, num, -1); // TODO: use computed timeout

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
