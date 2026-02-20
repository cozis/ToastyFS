#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <assert.h>

#include "blob_client.h"
#include "server.h"

#define TIME_FMT "%7.3fs"
#define TIME_VAL(t) ((double)(t) / 1000000000.0)

static uint64_t next_blob_client_id = 100;

static uint64_t blob_random(void)
{
#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
    return quakey_random();
#else
    return (uint64_t)rand();
#endif
}

static void blob_log_impl(BlobClientState *state, Time now, const char *event, const char *detail)
{
    printf("[" TIME_FMT "] BLOB   %lu | %-20s %s\n",
        TIME_VAL(now),
        state->client_id,
        event,
        detail ? detail : "");
}

#define blob_log(state, now, event, fmt, ...) do {                  \
    char _detail[256];                                              \
    snprintf(_detail, sizeof(_detail), fmt, ##__VA_ARGS__);         \
    blob_log_impl(state, now, event, _detail);                      \
} while (0)

#define blob_log_simple(state, now, event) \
    blob_log_impl(state, now, event, NULL)

static int leader_idx(BlobClientState *state)
{
    return state->view_number % state->num_servers;
}

///////////////////////////////////////////////////////////////
// Chunk ack counting
///////////////////////////////////////////////////////////////

static int count_acks(uint32_t mask)
{
    int n = 0;
    for (int i = 0; i < 32; i++)
        if (mask & (1u << i)) n++;
    return n;
}

static bool all_chunks_acked(BlobClientState *state)
{
    for (int i = 0; i < state->num_chunks; i++) {
        if (count_acks(state->chunks[i].ack_mask) < state->f_plus_one)
            return false;
    }
    return true;
}

static bool all_chunks_fetched(BlobClientState *state)
{
    for (int i = 0; i < state->num_chunks; i++) {
        if (!state->chunks[i].fetched)
            return false;
    }
    return true;
}

///////////////////////////////////////////////////////////////
// Generate a test blob
///////////////////////////////////////////////////////////////

static void generate_test_blob(BlobClientState *state)
{
    // Generate random bucket/key
    snprintf(state->bucket, META_BUCKET_MAX, "blob-b%d", (int)(blob_random() % 4));
    snprintf(state->key, META_KEY_MAX, "blob-k%d", (int)(blob_random() % 64));

    // 1-3 chunks per blob
    state->num_chunks = 1 + blob_random() % 3;
    state->blob_size = 0;

    for (int i = 0; i < state->num_chunks; i++) {
        // Generate random hash for each chunk
        for (int j = 0; j < 32; j++)
            state->chunks[i].hash.data[j] = blob_random() & 0xFF;
        state->chunks[i].size = BLOB_TEST_CHUNK_SIZE;
        state->chunks[i].ack_mask = 0;
        state->chunks[i].fetched = false;
        state->blob_size += BLOB_TEST_CHUNK_SIZE;
    }

    // Content hash (random for now)
    for (int j = 0; j < 32; j++)
        state->content_hash.data[j] = blob_random() & 0xFF;
}

///////////////////////////////////////////////////////////////
// Send operations
///////////////////////////////////////////////////////////////

// Send StoreChunk for a given chunk to a specific server.
// The chunk data is the hash bytes (32 bytes).
static void send_store_chunk(BlobClientState *state, int chunk_idx, int server_idx)
{
    int conn_idx = tcp_index_from_tag(&state->tcp, server_idx);
    if (conn_idx < 0) {
        tcp_connect(&state->tcp, state->server_addrs[server_idx], server_idx, NULL);
        return; // Will retry next tick
    }

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    if (output == NULL) return;

    StoreChunkMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_STORE_CHUNK,
            .length  = sizeof(StoreChunkMessage) + state->chunks[chunk_idx].size,
        },
        .hash = state->chunks[chunk_idx].hash,
        .size = state->chunks[chunk_idx].size,
    };

    byte_queue_write(output, &msg, sizeof(msg));
    // Chunk data = hash bytes (BLOB_TEST_CHUNK_SIZE = 32 = sizeof(SHA256))
    byte_queue_write(output, state->chunks[chunk_idx].hash.data, state->chunks[chunk_idx].size);
}

static void send_commit_put(BlobClientState *state)
{
    int conn_idx = tcp_index_from_tag(&state->tcp, leader_idx(state));
    if (conn_idx < 0) {
        tcp_connect(&state->tcp, state->server_addrs[leader_idx(state)], leader_idx(state), NULL);
        return;
    }

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    if (output == NULL) return;

    CommitPutMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_COMMIT_PUT,
            .length  = sizeof(CommitPutMessage),
        },
        .oper = {
            .type = META_OPER_PUT,
            .size = state->blob_size,
            .content_hash = state->content_hash,
            .num_chunks = state->num_chunks,
        },
        .client_id  = state->client_id,
        .request_id = state->request_id,
    };
    memcpy(msg.oper.bucket, state->bucket, META_BUCKET_MAX);
    memcpy(msg.oper.key, state->key, META_KEY_MAX);
    for (int i = 0; i < state->num_chunks; i++) {
        msg.oper.chunks[i].hash = state->chunks[i].hash;
        msg.oper.chunks[i].size = state->chunks[i].size;
    }

    byte_queue_write(output, &msg, sizeof(msg));
}

static void send_get_blob(BlobClientState *state, int server_idx)
{
    int conn_idx = tcp_index_from_tag(&state->tcp, server_idx);
    if (conn_idx < 0) {
        tcp_connect(&state->tcp, state->server_addrs[server_idx], server_idx, NULL);
        return;
    }

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    if (output == NULL) return;

    GetBlobMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_GET_BLOB,
            .length  = sizeof(GetBlobMessage),
        },
    };
    memcpy(msg.bucket, state->bucket, META_BUCKET_MAX);
    memcpy(msg.key, state->key, META_KEY_MAX);

    byte_queue_write(output, &msg, sizeof(msg));
}

static void send_fetch_chunk(BlobClientState *state, int chunk_idx, int server_idx)
{
    int conn_idx = tcp_index_from_tag(&state->tcp, server_idx);
    if (conn_idx < 0) {
        tcp_connect(&state->tcp, state->server_addrs[server_idx], server_idx, NULL);
        return;
    }

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    if (output == NULL) return;

    FetchChunkMessage msg = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_FETCH_CHUNK,
            .length  = sizeof(FetchChunkMessage),
        },
        .hash = state->chunks[chunk_idx].hash,
        .sender_idx = -1, // Client (not a peer server)
    };

    byte_queue_write(output, &msg, sizeof(msg));
}

///////////////////////////////////////////////////////////////
// Message processing
///////////////////////////////////////////////////////////////

static int
process_message(BlobClientState *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    (void) conn_idx;
    Time now = get_current_time();

    switch (type) {

    case MESSAGE_TYPE_REDIRECT: {
        RedirectMessage redirect;
        if (msg.len != sizeof(RedirectMessage))
            return -1;
        memcpy(&redirect, msg.ptr, sizeof(redirect));
        if (redirect.view_number > state->view_number) {
            blob_log(state, now, "RECV REDIRECT", "view=%lu -> %lu",
                (unsigned long)state->view_number,
                (unsigned long)redirect.view_number);
            state->view_number = redirect.view_number;
            // Re-send CommitPut to new leader
            if (state->phase == BLOB_COMMITTING) {
                send_commit_put(state);
                state->phase_time = now;
            }
        }
        return 0;
    }

    case MESSAGE_TYPE_STORE_CHUNK_ACK: {
        if (state->phase != BLOB_UPLOADING)
            return 0;

        StoreChunkAckMessage ack;
        if (msg.len != sizeof(StoreChunkAckMessage))
            return -1;
        memcpy(&ack, msg.ptr, sizeof(ack));

        // Find which chunk this ack is for
        for (int i = 0; i < state->num_chunks; i++) {
            if (memcmp(&state->chunks[i].hash, &ack.hash, sizeof(SHA256)) == 0) {
                int tag = tcp_get_tag(&state->tcp, conn_idx);
                if (tag >= 0 && tag < 32 && ack.success)
                    state->chunks[i].ack_mask |= (1u << tag);
                blob_log(state, now, "RECV STORE_ACK", "chunk=%d server=%d ok=%d acks=%d/%d",
                    i, tag, ack.success,
                    count_acks(state->chunks[i].ack_mask), state->f_plus_one);
                break;
            }
        }

        // Check if all chunks have f+1 acks
        if (all_chunks_acked(state)) {
            blob_log(state, now, "UPLOAD DONE", "%s/%s chunks=%d",
                state->bucket, state->key, state->num_chunks);

            // Move to commit phase
            state->phase = BLOB_COMMITTING;
            state->phase_time = now;
            state->request_id++;
            send_commit_put(state);
            blob_log(state, now, "SEND COMMIT_PUT", "%s/%s req=%lu",
                state->bucket, state->key, state->request_id);
        }
        return 0;
    }

    case MESSAGE_TYPE_REPLY: {
        if (state->phase != BLOB_COMMITTING)
            return 0;

        ReplyMessage reply;
        if (msg.len != sizeof(ReplyMessage))
            return -1;
        memcpy(&reply, msg.ptr, sizeof(reply));

        if (reply.request_id != state->request_id)
            return 0;

        if (reply.rejected) {
            blob_log(state, now, "RECV REPLY", "REJECTED, retrying");
            state->phase_time = now;
            send_commit_put(state);
            return 0;
        }

        state->puts_completed++;
        blob_log(state, now, "PUT DONE", "%s/%s puts=%d",
            state->bucket, state->key, state->puts_completed);

        // Next: GET this blob back to verify
        state->do_get_next = true;
        state->phase = BLOB_IDLE;
        return 0;
    }

    case MESSAGE_TYPE_GET_BLOB_RESPONSE: {
        if (state->phase != BLOB_FETCHING_META)
            return 0;

        GetBlobResponseMessage resp;
        if (msg.len != sizeof(GetBlobResponseMessage))
            return -1;
        memcpy(&resp, msg.ptr, sizeof(resp));

        if (!resp.found) {
            // Blob not yet committed on this server, retry another
            blob_log(state, now, "RECV GET_BLOB", "NOT_FOUND, retrying");
            state->fetch_server_idx = (state->fetch_server_idx + 1) % state->num_servers;
            state->phase_time = now;
            send_get_blob(state, state->fetch_server_idx);
            return 0;
        }

        blob_log(state, now, "RECV GET_BLOB", "%s/%s chunks=%u",
            state->bucket, state->key, resp.num_chunks);

        // Verify metadata matches what we uploaded
        if (resp.num_chunks != (uint32_t)state->num_chunks) {
            fprintf(stderr, "BLOB CLIENT: metadata mismatch! expected %d chunks, got %u\n",
                state->num_chunks, resp.num_chunks);
            return -1;
        }
        for (int i = 0; i < state->num_chunks; i++) {
            if (memcmp(&resp.chunks[i].hash, &state->chunks[i].hash, sizeof(SHA256)) != 0) {
                fprintf(stderr, "BLOB CLIENT: chunk %d hash mismatch!\n", i);
                return -1;
            }
        }

        // Start fetching chunk data
        state->phase = BLOB_FETCHING_DATA;
        state->phase_time = now;
        state->fetch_chunk_idx = 0;
        state->fetch_server_idx = 0;
        for (int i = 0; i < state->num_chunks; i++)
            state->chunks[i].fetched = false;

        // Send FetchChunk for the first chunk
        send_fetch_chunk(state, 0, state->fetch_server_idx);
        blob_log(state, now, "SEND FETCH_CHUNK", "chunk=0 server=%d", state->fetch_server_idx);
        return 0;
    }

    case MESSAGE_TYPE_FETCH_CHUNK_RESPONSE: {
        if (state->phase != BLOB_FETCHING_DATA)
            return 0;

        FetchChunkResponseMessage resp;
        if (msg.len < sizeof(FetchChunkResponseMessage))
            return -1;
        memcpy(&resp, msg.ptr, sizeof(resp));

        // Find which chunk this is for
        int chunk_idx = -1;
        for (int i = 0; i < state->num_chunks; i++) {
            if (memcmp(&state->chunks[i].hash, &resp.hash, sizeof(SHA256)) == 0) {
                chunk_idx = i;
                break;
            }
        }
        if (chunk_idx < 0)
            return 0; // Unknown chunk, ignore

        if (resp.size == 0) {
            // Server doesn't have the chunk. Try next server.
            blob_log(state, now, "RECV FETCH_RESP", "chunk=%d NOT_FOUND, trying next server", chunk_idx);
            state->fetch_server_idx = (state->fetch_server_idx + 1) % state->num_servers;
            send_fetch_chunk(state, chunk_idx, state->fetch_server_idx);
            return 0;
        }

        // Verify data size
        uint32_t data_size = msg.len - sizeof(FetchChunkResponseMessage);
        if (data_size != resp.size || resp.size != state->chunks[chunk_idx].size) {
            fprintf(stderr, "BLOB CLIENT: chunk %d size mismatch! expected %u, got %u\n",
                chunk_idx, state->chunks[chunk_idx].size, resp.size);
            return -1;
        }

        // Verify data content (data should equal hash bytes)
        uint8_t *data = (uint8_t *)(msg.ptr + sizeof(FetchChunkResponseMessage));
        if (memcmp(data, state->chunks[chunk_idx].hash.data, BLOB_TEST_CHUNK_SIZE) != 0) {
            fprintf(stderr, "BLOB CLIENT: chunk %d data verification FAILED!\n", chunk_idx);
            return -1;
        }

        state->chunks[chunk_idx].fetched = true;
        blob_log(state, now, "RECV FETCH_RESP", "chunk=%d VERIFIED", chunk_idx);

        // Check if all chunks fetched
        if (all_chunks_fetched(state)) {
            state->gets_completed++;
            state->gets_verified++;
            blob_log(state, now, "GET DONE", "%s/%s gets=%d verified=%d",
                state->bucket, state->key, state->gets_completed, state->gets_verified);

            state->do_get_next = false;
            state->phase = BLOB_IDLE;
            return 0;
        }

        // Fetch next unfetched chunk
        for (int i = 0; i < state->num_chunks; i++) {
            if (!state->chunks[i].fetched) {
                state->fetch_chunk_idx = i;
                state->fetch_server_idx = 0;
                send_fetch_chunk(state, i, 0);
                blob_log(state, now, "SEND FETCH_CHUNK", "chunk=%d server=0", i);
                break;
            }
        }
        return 0;
    }

    default:
        break;
    }

    return 0;
}

///////////////////////////////////////////////////////////////
// Init / Tick / Free
///////////////////////////////////////////////////////////////

int blob_client_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    BlobClientState *state = state_;

    state->num_servers = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --server missing value\n");
                return -1;
            }
            if (state->num_servers == NODE_LIMIT) {
                fprintf(stderr, "Node limit reached\n");
                return -1;
            }
            if (parse_addr_arg(argv[i], &state->server_addrs[state->num_servers++]) < 0) {
                fprintf(stderr, "Malformed address\n");
                return -1;
            }
        } else {
            // Ignore unknown options
        }
    }

    addr_sort(state->server_addrs, state->num_servers);

    if (tcp_context_init(&state->tcp) < 0) {
        fprintf(stderr, "Blob client :: Couldn't setup TCP context\n");
        return -1;
    }

    // f = (num_servers - 1) / 2, so f+1 = (num_servers + 1) / 2
    state->f_plus_one = (state->num_servers + 1) / 2;

    state->view_number = 0;
    state->request_id = 0;
    state->client_id = next_blob_client_id++;
    state->phase = BLOB_IDLE;
    state->phase_time = 0;
    state->do_get_next = false;
    state->puts_completed = 0;
    state->gets_completed = 0;
    state->gets_verified = 0;
    state->reconnect_time = 0;
    state->upload_server_cursor = 0;

    // Connect to all servers
    for (int i = 0; i < state->num_servers; i++) {
        if (tcp_connect(&state->tcp, state->server_addrs[i], i, NULL) < 0) {
            fprintf(stderr, "Blob client :: Couldn't connect to server %d\n", i);
            tcp_context_free(&state->tcp);
            return -1;
        }
    }

    {
        Time now = get_current_time();
        blob_log(state, now, "INIT", "servers=%d f+1=%d", state->num_servers, state->f_plus_one);
    }

    *timeout = 0;
    if (pcap < TCP_POLL_CAPACITY) {
        fprintf(stderr, "Blob client :: Not enough poll capacity\n");
        return -1;
    }
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int blob_client_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    BlobClientState *state = state_;

    Event events[TCP_EVENT_CAPACITY];
    int num_events = tcp_translate_events(&state->tcp, events, ctxs, pdata, *pnum);

    for (int i = 0; i < num_events; i++) {

        if (events[i].type == EVENT_DISCONNECT) {
            int conn_idx = events[i].conn_idx;
            tcp_close(&state->tcp, conn_idx);
            continue;
        }

        if (events[i].type != EVENT_MESSAGE)
            continue;

        int conn_idx = events[i].conn_idx;
        for (;;) {
            ByteView msg;
            uint16_t msg_type;
            int ret = tcp_next_message(&state->tcp, conn_idx, &msg, &msg_type);
            if (ret == 0)
                break;
            if (ret < 0) {
                tcp_close(&state->tcp, conn_idx);
                break;
            }

            ret = process_message(state, conn_idx, msg_type, msg);
            if (ret < 0) {
                tcp_close(&state->tcp, conn_idx);
                break;
            }

            tcp_consume_message(&state->tcp, conn_idx);
        }
    }

    Time now = get_current_time();

    // Timeout handling: if we've been in any phase too long, retry
    if (state->phase != BLOB_IDLE) {
        Time phase_deadline = state->phase_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL;
        if (phase_deadline <= now) {
            blob_log(state, now, "TIMEOUT", "phase=%d, retrying", state->phase);

            switch (state->phase) {
            case BLOB_UPLOADING:
                // Re-send StoreChunk for chunks that need more acks
                for (int c = 0; c < state->num_chunks; c++) {
                    if (count_acks(state->chunks[c].ack_mask) < state->f_plus_one) {
                        for (int s = 0; s < state->f_plus_one; s++) {
                            if (!(state->chunks[c].ack_mask & (1u << s)))
                                send_store_chunk(state, c, s);
                        }
                    }
                }
                state->phase_time = now;
                break;

            case BLOB_COMMITTING:
                state->view_number++;
                send_commit_put(state);
                state->phase_time = now;
                break;

            case BLOB_FETCHING_META:
                state->fetch_server_idx = (state->fetch_server_idx + 1) % state->num_servers;
                send_get_blob(state, state->fetch_server_idx);
                state->phase_time = now;
                break;

            case BLOB_FETCHING_DATA:
                state->fetch_server_idx = (state->fetch_server_idx + 1) % state->num_servers;
                send_fetch_chunk(state, state->fetch_chunk_idx, state->fetch_server_idx);
                state->phase_time = now;
                break;

            default:
                break;
            }
        }
    }

    // Ensure connections to all servers (needed during all phases for
    // retransmission after network partitions or server restarts)
    for (int i = 0; i < state->num_servers; i++) {
        int ci = tcp_index_from_tag(&state->tcp, i);
        if (ci < 0)
            tcp_connect(&state->tcp, state->server_addrs[i], i, NULL);
    }

    // Start new operation when idle
    if (state->phase == BLOB_IDLE) {

        if (state->do_get_next) {
            // GET the blob we just PUT
            state->phase = BLOB_FETCHING_META;
            state->phase_time = now;
            state->fetch_server_idx = 0;

            send_get_blob(state, state->fetch_server_idx);
            blob_log(state, now, "SEND GET_BLOB", "%s/%s server=%d",
                state->bucket, state->key, state->fetch_server_idx);

        } else {
            // PUT a new blob
            generate_test_blob(state);

            state->phase = BLOB_UPLOADING;
            state->phase_time = now;

            blob_log(state, now, "START PUT", "%s/%s chunks=%d",
                state->bucket, state->key, state->num_chunks);

            // Send StoreChunk for each chunk to the first f+1 servers
            for (int c = 0; c < state->num_chunks; c++) {
                for (int s = 0; s < state->f_plus_one; s++) {
                    send_store_chunk(state, c, s);
                }
            }
        }
    }

    // Set timeout
    Time deadline = INVALID_TIME;
    if (state->phase != BLOB_IDLE) {
        nearest_deadline(&deadline, state->phase_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL);
    }
    *timeout = deadline_to_timeout(deadline, now);
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int blob_client_free(void *state_)
{
    BlobClientState *state = state_;
    {
        Time now = get_current_time();
        blob_log(state, now, "SHUTDOWN", "puts=%d gets=%d verified=%d",
            state->puts_completed, state->gets_completed, state->gets_verified);
    }
    tcp_context_free(&state->tcp);
    return 0;
}
