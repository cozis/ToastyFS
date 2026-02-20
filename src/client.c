#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <assert.h>

#include "client.h"
#include "server.h"

//#define CLIENT_TRACE(fmt, ...) {}
#define CLIENT_TRACE(fmt, ...) fprintf(stderr, "CLIENT: " fmt "\n", ##__VA_ARGS__);

#define KEY_POOL_SIZE 128
#define BUCKET_POOL_SIZE 4

static uint64_t next_client_id = 1;

static uint64_t client_random(void)
{
#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
    return quakey_random();
#else
    return (uint64_t)rand();
#endif
}

static MetaOper random_oper(void)
{
    MetaOper oper = {0};
    snprintf(oper.bucket, META_BUCKET_MAX, "b%d", (int)(client_random() % BUCKET_POOL_SIZE));
    snprintf(oper.key, META_KEY_MAX, "k%d", (int)(client_random() % KEY_POOL_SIZE));

    switch (client_random() % 2) {
    case 0:
        oper.type = META_OPER_PUT;
        oper.size = client_random() % (1 << 20);
        oper.num_chunks = 1 + client_random() % 3;
        for (uint32_t i = 0; i < oper.num_chunks; i++) {
            for (int j = 0; j < 32; j++)
                oper.chunks[i].hash.data[j] = client_random() & 0xFF;
            oper.chunks[i].size = client_random() % (4 << 20);
        }
        for (int j = 0; j < 32; j++)
            oper.content_hash.data[j] = client_random() & 0xFF;
        break;
    case 1:
        oper.type = META_OPER_DELETE;
        break;
    }
    return oper;
}

// Format time as seconds with 3 decimal places for trace output
#define TIME_FMT "%7.3fs"
#define TIME_VAL(t) ((double)(t) / 1000000000.0)

static void client_log_impl(ClientState *state, Time now, const char *event, const char *detail)
{
    printf("[" TIME_FMT "] CLIENT %lu | V%-3lu | %-20s %s\n",
        TIME_VAL(now),
        state->client_id,
        state->view_number,
        event,
        detail ? detail : "");
}

#define client_log(state, now, event, fmt, ...) do {                \
    char _detail[256];                                              \
    snprintf(_detail, sizeof(_detail), fmt, ##__VA_ARGS__);         \
    client_log_impl(state, now, event, _detail);                    \
} while (0)

#define client_log_simple(state, now, event) \
    client_log_impl(state, now, event, NULL)

static int leader_idx(ClientState *state)
{
    return state->view_number % state->num_servers;
}

static int
process_message(ClientState *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    (void) conn_idx;

    if (type == MESSAGE_TYPE_REDIRECT) {
        RedirectMessage redirect_message;
        if (msg.len != sizeof(RedirectMessage))
            return -1;
        memcpy(&redirect_message, msg.ptr, sizeof(redirect_message));

        if (redirect_message.view_number > state->view_number) {
            Time now = get_current_time();
            client_log(state, now, "RECV REDIRECT", "view=%lu -> %lu leader=%d",
                (unsigned long)state->view_number,
                (unsigned long)redirect_message.view_number,
                (int)(redirect_message.view_number % state->num_servers));
            state->view_number = redirect_message.view_number;
            state->last_was_rejected = true;
            state->last_was_timeout = false;
            state->pending = false;
        }
        return 0;
    }

    if (!state->pending)
        return -1;

    if (type != MESSAGE_TYPE_REPLY)
        return -1;

    ReplyMessage message;
    if (msg.len != sizeof(ReplyMessage))
        return -1;
    memcpy(&message, msg.ptr, sizeof(message));

    // Ignore stale replies from previous requests. After a timeout
    // the client moves to a new view and sends a new request, but
    // the old leader may still deliver a reply for the old request
    // on the previous connection. Without this check the client
    // would accept the stale result for the wrong operation.
    if (message.request_id != state->request_id)
        return 0;

    {
        Time now = get_current_time();
        char oper_buf[128];
        meta_snprint_oper(oper_buf, sizeof(oper_buf), &state->last_oper);
        if (message.rejected) {
            client_log(state, now, "RECV REPLY", "%s -> REJECTED", oper_buf);
        } else {
            char result_buf[64];
            meta_snprint_result(result_buf, sizeof(result_buf), message.result);
            client_log(state, now, "RECV REPLY", "%s -> %s", oper_buf, result_buf);
        }
    }

    state->last_result = message.result;
    state->last_was_timeout = false;
    state->last_was_rejected = message.rejected;
    state->pending = false;
    return 0;
}

int client_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    ClientState *state = state_;

    state->num_servers = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --server missing value. Usage is --server <addr>:<port>\n");
                return -1;
            }
            if (state->num_servers == NODE_LIMIT) {
                fprintf(stderr, "Node limit of %d reached\n", NODE_LIMIT);
                return -1;
            }
            // TODO: Check address is not duplicated
            if (parse_addr_arg(argv[i], &state->server_addrs[state->num_servers++]) < 0) {
                fprintf(stderr, "Malformed <addr>:<port> pair for --server option\n");
                return -1;
            }
        } else {
            printf("Ignoring option '%s'\n", argv[i]);
        }
    }

    // Now sort the addresses
    addr_sort(state->server_addrs, state->num_servers);

    if (tcp_context_init(&state->tcp) < 0) {
        fprintf(stderr, "Client :: Couldn't setup TCP context\n");
        return -1;
    }

    state->pending = false;

    state->view_number = 0;
    state->request_id = 0;
    state->reconnect_time = 0;

    state->client_id = next_client_id++;

    // Connect to all known servers
    for (int i = 0; i < state->num_servers; i++) {
        if (tcp_connect(&state->tcp, state->server_addrs[i], i, NULL) < 0) {
            fprintf(stderr, "Client :: Couldn't connect to server %d\n", i);
            tcp_context_free(&state->tcp);
            return -1;
        }
    }

    {
        Time now = get_current_time();
        client_log(state, now, "INIT", "servers=%d leader=%d", state->num_servers, leader_idx(state));
    }

    *timeout = 0;
    if (pcap < TCP_POLL_CAPACITY) {
        fprintf(stderr, "Client :: Not enough poll() capacity (got %d, needed %d)\n", pcap, TCP_POLL_CAPACITY);
        return -1;
    }
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int client_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    ClientState *state = state_;

    Event events[TCP_EVENT_CAPACITY];
    int num_events = tcp_translate_events(&state->tcp, events, ctxs, pdata, *pnum);

    for (int i = 0; i < num_events; i++) {

        if (events[i].type == EVENT_DISCONNECT) {
            int conn_idx = events[i].conn_idx;
            int tag = tcp_get_tag(&state->tcp, conn_idx);
            if (tag == leader_idx(state) && state->pending) {
                Time now = get_current_time();
                client_log(state, now, "DISCONNECT", "%s/%s lost leader (node %d)",
                    state->last_oper.bucket, state->last_oper.key, leader_idx(state));
                state->last_was_timeout = true;
                state->last_was_rejected = false;
                state->pending = false;
            }
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

    // If we've been waiting too long for a response, give up and
    // try the next server (the current leader may have crashed and
    // a view change may have happened)
    if (state->pending) {
        Time request_deadline = state->request_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL;
        if (request_deadline <= now) {

            {
                char oper_buf[128];
                meta_snprint_oper(oper_buf, sizeof(oper_buf), &state->last_oper);
                client_log(state, now, "TIMEOUT", "%s", oper_buf);
            }

            state->view_number++;
            state->last_was_timeout = true;
            state->last_was_rejected = false;
            state->pending = false;
        }
    }

    if (!state->pending) {

        int conn_idx = tcp_index_from_tag(&state->tcp, leader_idx(state));
        if (conn_idx < 0) {
            if (state->reconnect_time <= now) {
                tcp_connect(&state->tcp, state->server_addrs[leader_idx(state)], leader_idx(state), NULL);
                state->reconnect_time = now + HEARTBEAT_INTERVAL_SEC * 1000000000ULL;
            }
        } else {

            // Now start a new operation
            state->request_id++;
            state->last_oper = random_oper();

            RequestMessage request_message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_REQUEST,
                    .length  = sizeof(RequestMessage),
                },
                .oper = state->last_oper,
                .client_id = state->client_id,
                .request_id = state->request_id,
            };

            ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
            assert(output);

            byte_queue_write(output, &request_message, request_message.base.length);

            {
                char oper_buf[128];
                meta_snprint_oper(oper_buf, sizeof(oper_buf), &state->last_oper);
                client_log(state, now, "SEND REQUEST", "%s", oper_buf);
            }

            state->pending = true;
            state->request_time = now;
        }
    }

    // Set timeout based on pending request deadline or reconnection delay
    Time deadline = INVALID_TIME;
    if (state->pending) {
        nearest_deadline(&deadline, state->request_time + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL);
    } else {
        int conn_idx = tcp_index_from_tag(&state->tcp, leader_idx(state));
        if (conn_idx < 0 && state->reconnect_time > now) {
            nearest_deadline(&deadline, state->reconnect_time);
        }
    }
    *timeout = deadline_to_timeout(deadline, now);
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int client_free(void *state_)
{
    ClientState *state = state_;

    {
        Time now = get_current_time();
        client_log_simple(state, now, "CRASHED");
    }

    tcp_context_free(&state->tcp);
    return 0;
}
