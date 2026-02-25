#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>

#include "server.h"

typedef enum {
    HR_OK,
    HR_OUT_OF_MEMORY,
    HR_INVALID_MESSAGE,
    HR_DEFERRED,    // Message not consumed; handler will reply and consume later
} HandlerResult;

static int self_idx(Server *state)
{
    for (int i = 0; i < state->num_nodes; i++)
        if (addr_eql(state->node_addrs[i], state->self_addr))
            return i;
    UNREACHABLE;
}

static int primary_idx(Server *state)
{
    return state->view_number % state->num_nodes;
}

static bool is_primary(Server *state)
{
    if (state->status == STATUS_RECOVERY)
        return false;
    return self_idx(state) == primary_idx(state);
}

#define TIME_FMT "%7.3fs"
#define TIME_VAL(t) ((double)(t) / 1000000000.0)

static const char *status_name(Status s)
{
    switch (s) {
    case STATUS_NORMAL:      return "NR";
    case STATUS_CHANGE_VIEW: return "CV";
    case STATUS_RECOVERY:    return "RC";
    }
    return "??";
}

static void node_log_impl(Server *state, const char *event, const char *detail)
{
    printf("[" TIME_FMT "] NODE %d (%s) %s | V%-3llu C%-3d L%-3d | %-20s %s\n",
        TIME_VAL(state->now),
        self_idx(state),
        is_primary(state) ? "PR" : "RE",
        status_name(state->status),
        (unsigned long long)state->view_number,
        state->commit_index,
        state->log.count,
        event,
        detail ? detail : "");
}

#define node_log(state, event, fmt, ...) do {                    \
    char _detail[1024];                                           \
    snprintf(_detail, sizeof(_detail), fmt, ##__VA_ARGS__);      \
    node_log_impl(state, event, _detail);                        \
} while (0)

#define node_log_simple(state, event) \
    node_log_impl(state, event, NULL)

static int count_set(uint32_t word)
{
    int n = 0;
    for (int i = 0; i < (int) sizeof(word) * 8; i++)
        if (word & (1 << i))
            n++;
    return n;
}

static bool reached_quorum(Server *state, uint32_t votes)
{
    return count_set(votes) > state->num_nodes/2;
}

static bool already_voted(uint32_t votes, int idx)
{
    uint32_t mask = 1 << idx;
    return (votes & mask) == mask;
}

static void add_vote(uint32_t *votes, int idx)
{
    *votes |= 1 << idx;
}

// Helper: read a message from raw_message into string-like usage
// raw_message is a pointer to the message bytes in the TCP read buffer
static uint64_t msg_len(void *raw_message)
{
    Message base;
    memcpy(&base, raw_message, sizeof(base));
    return base.length;
}

static void begin_state_transfer(Server *state, int sender_idx)
{
    if (state->state_transfer_pending)
        return;
    state->state_transfer_pending = true;
    state->state_transfer_time = state->now;

    GetStateMessage message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_GET_STATE,
            .length  = sizeof(GetStateMessage),
        },
        .view_number = state->view_number,
        .op_number   = state->log.count,
        .sender_idx  = self_idx(state),
    };
    send_message(state->msys,sender_idx, &message.base);
    node_log(state, "SEND GET_STATE", "to=%d op=%d", sender_idx, state->log.count);
}

static HandlerResult
process_request(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    RequestMessage request_message;
    if (len != sizeof(request_message))
        return HR_INVALID_MESSAGE;
    memcpy(&request_message, raw_message, sizeof(request_message));

    {
        char oper_buf[128];
        meta_snprint_oper(oper_buf, sizeof(oper_buf), &request_message.oper);
        node_log(state, "RECV REQUEST", "client=%llu req=%llu %s",
            (unsigned long long)request_message.client_id, (unsigned long long)request_message.request_id,
            oper_buf);
    }

    {
        ClientTableEntry *entry = client_table_find(&state->client_table, request_message.client_id);
        if (entry == NULL) {

            int ret = client_table_add(
                &state->client_table,
                request_message.client_id,
                request_message.request_id,
                raw_message);

            if (ret < 0) {
                VsrReplyMessage reply_message = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_REPLY,
                        .length  = sizeof(VsrReplyMessage),
                    },
                    .rejected = true,
                    .request_id = request_message.request_id,
                };
                reply_to_message(state->msys, raw_message, &reply_message.base);
                node_log(state, "SEND REPLY", "client=%llu REJECTED (table full)", (unsigned long long)request_message.client_id);
                return HR_OK;
            }

        } else {

            if (entry->pending)
                return HR_OK;

            if (entry->last_request_id > request_message.request_id)
                return HR_OK;

            if (entry->last_request_id == request_message.request_id) {

                VsrReplyMessage reply_message = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_REPLY,
                        .length  = sizeof(VsrReplyMessage),
                    },
                    .rejected = false,
                    .result = entry->last_result,
                    .request_id = request_message.request_id,
                };
                reply_to_message(state->msys, raw_message, &reply_message.base);

                {
                    char result_buf[64];
                    meta_snprint_result(result_buf, sizeof(result_buf), entry->last_result);
                    node_log(state, "SEND REPLY", "client=%llu cached %s", (unsigned long long)request_message.client_id, result_buf);
                }
                return HR_OK;
            }

            entry->last_request_id = request_message.request_id;
            entry->pending_message = raw_message;
            entry->pending = true;
        }
    }

    LogEntry log_entry = {
        .oper        = request_message.oper,
        .votes       = 1 << self_idx(state),
        .view_number = state->view_number,
        .client_id   = request_message.client_id,
        .request_id  = request_message.request_id,
    };
    if (log_append(&state->log, log_entry) < 0)
        return HR_OUT_OF_MEMORY;

    PrepareMessage prepare_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_PREPARE,
            .length  = sizeof(PrepareMessage),
        },
        .oper         = request_message.oper,
        .sender_idx   = self_idx(state),
        .log_index    = state->log.count-1,
        .commit_index = state->commit_index,
        .view_number  = state->view_number,
        .client_id    = request_message.client_id,
        .request_id   = request_message.request_id,
    };
    broadcast_message(state->msys, self_idx(state), &prepare_message.base);

    {
        char oper_buf[128];
        meta_snprint_oper(oper_buf, sizeof(oper_buf), &request_message.oper);
        node_log(state, "SEND PREPARE", "to=* idx=%d %s", state->log.count-1, oper_buf);
    }
    return HR_DEFERRED;
}

static void reply_to_client(Server *state, ClientTableEntry *table_entry,
    uint64_t request_id, MetaOper *oper, MetaResult result)
{
    {
        char oper_buf[128], result_buf[64];
        meta_snprint_oper(oper_buf, sizeof(oper_buf), oper);
        meta_snprint_result(result_buf, sizeof(result_buf), result);
        node_log(state, "SEND REPLY", "client=%llu req=%llu %s -> %s",
            (unsigned long long)table_entry->client_id, (unsigned long long)request_id, oper_buf, result_buf);
    }

    if (table_entry->pending_message) {
        VsrReplyMessage message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_REPLY,
                .length  = sizeof(VsrReplyMessage),
            },
            .result = result,
            .request_id = request_id,
        };
        reply_to_message(state->msys, table_entry->pending_message, &message.base);
        consume_message(state->msys, table_entry->pending_message);
        table_entry->pending_message = NULL;
    }
}

static void advance_commit_index(Server *state, int target_index, bool send_replies)
{
    target_index = MIN(target_index, state->log.count);

    while (state->commit_index < target_index) {

        LogEntry *entry = &state->log.entries[state->commit_index++];

        MetaResult result = meta_store_update(&state->metastore, &entry->oper);
        {
            char oper_buf[128], result_buf[64];
            meta_snprint_oper(oper_buf, sizeof(oper_buf), &entry->oper);
            meta_snprint_result(result_buf, sizeof(result_buf), result);
            node_log(state, "APPLY", "idx=%d %s -> %s", state->commit_index-1, oper_buf, result_buf);
        }

        ClientTableEntry *table_entry = client_table_find(&state->client_table, entry->client_id);
        if (table_entry == NULL)
            continue;

        if (!table_entry->pending)
            continue;

        if (table_entry->last_request_id != entry->request_id)
            continue;

        table_entry->pending = false;
        table_entry->last_result = result;

        if (send_replies)
            reply_to_client(state, table_entry, entry->request_id, &entry->oper, result);
    }
}

static HandlerResult
process_prepare_ok(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    PrepareOKMessage message;
    if (len != sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV PREPARE_OK", "from=%d idx=%d view=%llu",
        message.sender_idx, message.log_index, (unsigned long long)message.view_number);

    if (message.view_number < state->view_number)
        return HR_OK;

    if (message.view_number > state->view_number) {
        state->view_number = message.view_number;
        begin_state_transfer(state, message.sender_idx);
        return HR_OK;
    }

    assert(message.log_index > -1);
    assert(message.log_index < state->log.count);

    if (message.log_index < state->commit_index)
        return HR_OK;

    LogEntry *entry = &state->log.entries[message.log_index];
    add_vote(&entry->votes, message.sender_idx);
    if (reached_quorum(state, entry->votes)) {
        node_log(state, "QUORUM", "idx=%d %s/%s", message.log_index, entry->oper.bucket, entry->oper.key);
        advance_commit_index(state, message.log_index+1, true);
    }
    return HR_OK;
}

static bool
should_store_view_change_log(Server *state, DoViewChangeMessage message)
{
    if (message.old_view_number > state->view_change_old_view)
        return true;

    if (message.old_view_number < state->view_change_old_view)
        return false;

    if (message.op_number <= state->view_change_log.count)
        return false;

    return true;
}

static void
clear_view_change_fields(Server *state)
{
    state->view_change_begin_votes = 0;
    state->view_change_apply_votes = 0;
    state->view_change_old_view = 0;
    state->view_change_commit = 0;
    log_free(&state->view_change_log);
    log_init(&state->view_change_log);
}

static HandlerResult
complete_view_change_and_become_primary(Server *state)
{
    assert(state->commit_index <= state->view_change_commit);

    log_move(&state->log, &state->view_change_log);

    state->status = STATUS_NORMAL;
    state->last_normal_view = state->view_number;
    node_log(state, "STATUS NORMAL", "became primary (view change complete)");

    advance_commit_index(state, state->view_change_commit, false);

    for (int i = state->commit_index; i < state->log.count; i++) {
        LogEntry *entry = &state->log.entries[i];
        entry->votes = 0;
        add_vote(&entry->votes, self_idx(state));
    }

    BeginViewMessage begin_view_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_BEGIN_VIEW,
            .length  = sizeof(BeginViewMessage) + state->log.count * sizeof(LogEntry),
        },
        .view_number = state->view_number,
        .commit_index = state->commit_index,
        .op_number = state->log.count,
    };
    broadcast_message_ex(state->msys, self_idx(state),&begin_view_message.base, state->log.entries, state->log.count * sizeof(LogEntry));

    node_log(state, "SEND BEGIN_VIEW", "to=* view=%llu log=%d commit=%d",
        (unsigned long long)state->view_number, state->log.count, state->commit_index);

    clear_view_change_fields(state);
    return HR_OK;
}

static HandlerResult
process_do_view_change(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    DoViewChangeMessage message;
    if (len < sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV DO_VIEW_CHANGE", "from=%d view=%llu old_view=%llu ops=%d commit=%d",
        message.sender_idx, (unsigned long long)message.view_number, (unsigned long long)message.old_view_number,
        message.op_number, message.commit_index);

    if (message.view_number != state->view_number)
        return HR_OK;

    if (!already_voted(state->view_change_apply_votes, message.sender_idx)) {

        if (should_store_view_change_log(state, message)) {

            state->view_change_old_view = message.old_view_number;

            LogEntry *entries = (LogEntry*) ((uint8_t*)raw_message + sizeof(DoViewChangeMessage));

            int num_entries = (len - sizeof(DoViewChangeMessage)) / sizeof(LogEntry);
            if (num_entries != message.op_number)
                return HR_INVALID_MESSAGE;

            log_free(&state->view_change_log);
            if (log_init_from_network(&state->view_change_log, entries, num_entries) < 0)
                return HR_OUT_OF_MEMORY;
        }

        state->view_change_commit = MAX(state->view_change_commit, message.commit_index);
        add_vote(&state->view_change_apply_votes, message.sender_idx);
    }

    if (reached_quorum(state, state->view_change_apply_votes)) {
        HandlerResult ret = complete_view_change_and_become_primary(state);
        if (ret != HR_OK)
            return ret;
    }

    return HR_OK;
}

static HandlerResult
process_recovery(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    RecoveryMessage recovery_message;
    if (len != sizeof(RecoveryMessage))
        return HR_INVALID_MESSAGE;
    memcpy(&recovery_message, raw_message, sizeof(recovery_message));

    node_log(state, "RECV RECOVERY", "from=%d nonce=%llu", recovery_message.sender_idx, (unsigned long long)recovery_message.nonce);

    node_log(state, "SEND RECOVERY_RESP", "to=%d view=%llu is_primary=%s",
        recovery_message.sender_idx, (unsigned long long)state->view_number, is_primary(state) ? "yes" : "no");

    RecoveryResponseMessage recovery_response_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_RECOVERY_RESPONSE,
            .length  = sizeof(RecoveryResponseMessage),
        },
        .view_number  = state->view_number,
        .op_number    = state->log.count-1,
        .nonce        = recovery_message.nonce,
        .commit_index = state->commit_index,
        .sender_idx   = self_idx(state),
    };
    if (is_primary(state)) {
        recovery_response_message.base.length += state->log.count * sizeof(LogEntry);
        send_message_ex(state->msys,recovery_message.sender_idx, &recovery_response_message.base,
            state->log.entries, state->log.count * sizeof(LogEntry));
    } else {
        send_message(state->msys,recovery_message.sender_idx, &recovery_response_message.base);
    }
    return HR_OK;
}

static HandlerResult
perform_log_transfer_for_view_change(Server *state)
{
    if (is_primary(state)) {
        add_vote(&state->view_change_apply_votes, self_idx(state));

        state->view_change_old_view = state->last_normal_view;
        state->view_change_commit = state->commit_index;

        if (log_init_from_network(&state->view_change_log, state->log.entries, state->log.count) < 0)
            return HR_OUT_OF_MEMORY;

    } else {
        DoViewChangeMessage do_view_change_message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_DO_VIEW_CHANGE,
                .length  = sizeof(DoViewChangeMessage) + state->log.count * sizeof(LogEntry),
            },
            .view_number = state->view_number,
            .old_view_number = state->last_normal_view,
            .op_number = state->log.count,
            .commit_index = state->commit_index,
            .sender_idx = self_idx(state),
        };
        send_message_ex(state->msys,primary_idx(state), &do_view_change_message.base, state->log.entries, state->log.count * sizeof(LogEntry));
        node_log(state, "SEND DO_VIEW_CHANGE", "to=%d view=%llu old_view=%llu log=%d commit=%d",
            primary_idx(state), (unsigned long long)state->view_number, (unsigned long long)state->last_normal_view,
            state->log.count, state->commit_index);
    }

    state->num_future = 0;
    state->state_transfer_pending = false;
    return HR_OK;
}

static HandlerResult
process_begin_view_change(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    BeginViewChangeMessage message;
    if (len != sizeof(BeginViewChangeMessage))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV BEGIN_VIEW_CHG", "from=%d view=%llu", message.sender_idx, (unsigned long long)message.view_number);

    if (message.view_number < state->view_number)
        return HR_OK;

    if (state->status == STATUS_NORMAL) {
        if (state->view_number == message.view_number)
            return HR_OK;
    }

    if (message.view_number > state->view_number) {

        BeginViewChangeMessage message_2 = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_BEGIN_VIEW_CHANGE,
                .length  = sizeof(BeginViewChangeMessage),
            },
            .view_number = message.view_number,
            .sender_idx = self_idx(state),
        };
        broadcast_message(state->msys, self_idx(state),&message_2.base);
        node_log(state, "SEND BEGIN_VIEW_CHG", "to=* view=%llu", (unsigned long long)message.view_number);

        clear_view_change_fields(state);
        state->view_number = message.view_number;
        state->heartbeat = state->now;
        state->status = STATUS_CHANGE_VIEW;
        node_log(state, "STATUS CHANGE_VIEW", "view=%llu", (unsigned long long)state->view_number);
    }

    bool before = reached_quorum(state, state->view_change_begin_votes);

    add_vote(&state->view_change_begin_votes, self_idx(state));
    add_vote(&state->view_change_begin_votes, message.sender_idx);

    if (!before && reached_quorum(state, state->view_change_begin_votes)) {
        HandlerResult ret = perform_log_transfer_for_view_change(state);
        if (ret != HR_OK)
            return ret;
    }

    return HR_OK;
}

static HandlerResult
process_begin_view(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    BeginViewMessage message;
    if (len < sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV BEGIN_VIEW", "view=%llu commit=%d ops=%d",
        (unsigned long long)message.view_number, message.commit_index, message.op_number);

    if (message.view_number < state->view_number)
        return HR_OK;

    state->view_number = message.view_number;

    state->status = STATUS_NORMAL;
    state->last_normal_view = state->view_number;
    node_log(state, "STATUS NORMAL", "new view=%llu (follower)", (unsigned long long)state->view_number);

    int num_entries = (len - sizeof(BeginViewMessage)) / sizeof(LogEntry);
    assert(num_entries >= state->commit_index);

    LogEntry *entries = (LogEntry *)((uint8_t *)raw_message + sizeof(BeginViewMessage));
    log_free(&state->log);
    if (log_init_from_network(&state->log, entries, num_entries) < 0)
        return HR_OUT_OF_MEMORY;

    state->num_future = 0;
    state->state_transfer_pending = false;

    if (state->log.count > message.commit_index) {
        PrepareOKMessage ok_msg = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_PREPARE_OK,
                .length  = sizeof(PrepareOKMessage),
            },
            .sender_idx = self_idx(state),
            .log_index  = state->log.count - 1,
            .view_number = state->view_number,
        };
        send_message(state->msys,primary_idx(state), &ok_msg.base);
        node_log(state, "SEND PREPARE_OK", "to=%d idx=%d %s/%s", primary_idx(state), state->log.count - 1,
            state->log.entries[state->log.count - 1].oper.bucket, state->log.entries[state->log.count - 1].oper.key);
    }

    advance_commit_index(state, message.commit_index, false);

    clear_view_change_fields(state);
    state->heartbeat = state->now;
    return HR_OK;
}

static HandlerResult
process_get_state(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    GetStateMessage get_state_message;
    if (len != sizeof(GetStateMessage))
        return HR_INVALID_MESSAGE;
    memcpy(&get_state_message, raw_message, sizeof(get_state_message));

    node_log(state, "RECV GET_STATE", "from=%d op=%d view=%llu",
        get_state_message.sender_idx, get_state_message.op_number, (unsigned long long)get_state_message.view_number);

    if (state->status != STATUS_NORMAL)
        return HR_OK;

    if (get_state_message.view_number != state->view_number)
        return HR_OK;

    int start = get_state_message.op_number;
    if (start < 0 || start >= state->log.count)
        return HR_OK;

    int num_entries = state->log.count - start;

    NewStateMessage new_state_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_NEW_STATE,
            .length  = sizeof(NewStateMessage) + num_entries * sizeof(LogEntry),
        },
        .view_number  = state->view_number,
        .op_number    = num_entries,
        .commit_index = state->commit_index,
        .start_index  = start,
    };
    send_message_ex(state->msys,get_state_message.sender_idx, &new_state_message.base,
        state->log.entries + start, num_entries * sizeof(LogEntry));
    node_log(state, "SEND NEW_STATE", "to=%d entries=%d commit=%d",
        get_state_message.sender_idx, num_entries, state->commit_index);
    return HR_OK;
}

///////////////////////////////////////////////////////////////
// Chunk and Blob message handlers (bypass VSR log)
///////////////////////////////////////////////////////////////

static HandlerResult
process_store_chunk(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    StoreChunkMessage message;
    if (len < sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    uint32_t data_size = len - sizeof(StoreChunkMessage);
    if (data_size != message.size)
        return HR_INVALID_MESSAGE;

    char *data = (char *)((uint8_t *)raw_message + sizeof(StoreChunkMessage));

    int ret = chunk_store_write(&state->chunk_store, message.hash, data, message.size);

    StoreChunkAckMessage ack = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_STORE_CHUNK_ACK,
            .length  = sizeof(StoreChunkAckMessage),
        },
        .hash    = message.hash,
        .success = (ret == 0),
    };
    reply_to_message(state->msys, raw_message, &ack.base);

    node_log(state, "RECV STORE_CHUNK", "size=%u ok=%d", message.size, ret == 0);
    return HR_OK;
}

static HandlerResult
process_fetch_chunk(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    FetchChunkMessage message;
    if (len != sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    bool exists = chunk_store_exists(&state->chunk_store, message.hash);

    if (!exists) {
        FetchChunkResponseMessage response = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_FETCH_CHUNK_RESPONSE,
                .length  = sizeof(FetchChunkResponseMessage),
            },
            .hash = message.hash,
            .size = 0,
        };
        reply_to_message(state->msys, raw_message, &response.base);

        node_log(state, "RECV FETCH_CHUNK", "NOT_FOUND");
        return HR_OK;
    }

    uint32_t chunk_size = 0;
    for (int i = 0; i < state->metastore.count; i++) {
        ObjectMeta *meta = &state->metastore.entries[i];
        if (meta->deleted) continue;
        for (uint32_t j = 0; j < meta->num_chunks; j++) {
            if (memcmp(&meta->chunks[j].hash, &message.hash, sizeof(SHA256)) == 0) {
                chunk_size = meta->chunks[j].size;
                goto found_size;
            }
        }
    }
    {
        FetchChunkResponseMessage response = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_FETCH_CHUNK_RESPONSE,
                .length  = sizeof(FetchChunkResponseMessage),
            },
            .hash = message.hash,
            .size = 0,
        };
        reply_to_message(state->msys, raw_message, &response.base);

        node_log(state, "RECV FETCH_CHUNK", "NO_META");
        return HR_OK;
    }

found_size:;
    char *chunk_data = malloc(chunk_size);
    if (chunk_data == NULL)
        return HR_OUT_OF_MEMORY;

    int ret = chunk_store_read(&state->chunk_store, message.hash, chunk_data, chunk_size);
    if (ret <= 0) {
        free(chunk_data);
        FetchChunkResponseMessage response = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_FETCH_CHUNK_RESPONSE,
                .length  = sizeof(FetchChunkResponseMessage),
            },
            .hash = message.hash,
            .size = 0,
        };
        if (message.sender_idx >= 0 && message.sender_idx < state->num_nodes)
            send_message(state->msys,message.sender_idx, &response.base);
        else
            reply_to_message(state->msys, raw_message, &response.base);
        node_log(state, "RECV FETCH_CHUNK", "READ_ERR size=%u", chunk_size);
        return HR_OK;
    }

    FetchChunkResponseMessage response = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_FETCH_CHUNK_RESPONSE,
            .length  = sizeof(FetchChunkResponseMessage) + chunk_size,
        },
        .hash = message.hash,
        .size = chunk_size,
    };
    reply_to_message_ex(state->msys, raw_message, &response.base, chunk_data, chunk_size);

    node_log(state, "RECV FETCH_CHUNK", "size=%u", chunk_size);

    free(chunk_data);
    return HR_OK;
}

static HandlerResult
process_get_blob(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    GetBlobMessage message;
    if (len != sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV GET_BLOB", "%s/%s", message.bucket, message.key);

    ObjectMeta *meta = meta_store_lookup(&state->metastore, message.bucket, message.key);

    GetBlobResponseMessage response = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_GET_BLOB_RESPONSE,
            .length  = sizeof(GetBlobResponseMessage),
        },
    };

    if (meta != NULL) {
        response.found = true;
        response.size = meta->size;
        response.content_hash = meta->content_hash;
        response.num_chunks = meta->num_chunks;
        memcpy(response.chunks, meta->chunks, meta->num_chunks * sizeof(ChunkRef));
    } else {
        response.found = false;
    }

    reply_to_message(state->msys, raw_message, &response.base);
    return HR_OK;
}

static HandlerResult
complete_recovery(Server *state)
{
    assert(state->commit_index <= state->recovery_commit);

    state->view_number = state->recovery_view;
    log_move(&state->log, &state->recovery_log);
    advance_commit_index(state, state->recovery_commit, false);

    state->status = STATUS_NORMAL;
    state->last_normal_view = state->view_number;
    node_log(state, "STATUS NORMAL", "recovery complete view=%llu commit=%d",
        (unsigned long long)state->view_number, state->commit_index);

    if (is_primary(state)) {
        for (int i = state->commit_index; i < state->log.count; i++) {
            LogEntry *entry = &state->log.entries[i];
            entry->votes = 0;
            add_vote(&entry->votes, self_idx(state));
        }
    }

    state->heartbeat = state->now;
    return HR_OK;
}

static bool
received_recovery_primary(Server *state)
{
    assert(state->status == STATUS_RECOVERY);

    int pidx = state->recovery_view % state->num_nodes;
    uint32_t primary_mask = 1 << pidx;
    return (state->recovery_votes & primary_mask) != 0;
}

static bool
sender_thinks_he_is_primary(Server *state, RecoveryResponseMessage message)
{
    (void) state;
    return message.sender_idx == (int) (message.view_number % state->num_nodes);
}

static bool
should_store_recovery_log(Server *state, RecoveryResponseMessage message)
{
    return sender_thinks_he_is_primary(state, message)
        && (!received_recovery_primary(state) || state->recovery_log_view < message.view_number);
}

static HandlerResult
process_recovery_response(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    RecoveryResponseMessage message;
    if (len < sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV RECOVERY_RESP", "from=%d view=%llu commit=%d nonce=%llu",
        message.sender_idx, (unsigned long long)message.view_number, message.commit_index, (unsigned long long)message.nonce);

    if (message.nonce != state->recovery_nonce)
        return HR_OK;

    state->recovery_view = MAX(state->recovery_view, message.view_number);

    if (should_store_recovery_log(state, message)) {

        LogEntry *entries = (LogEntry*) ((uint8_t*)raw_message + sizeof(RecoveryResponseMessage));
        int   num_entries = message.op_number + 1;

        assert(num_entries == (int) ((len - sizeof(RecoveryResponseMessage)) / sizeof(LogEntry)));

        log_free(&state->recovery_log);
        if (log_init_from_network(&state->recovery_log, entries, num_entries) < 0)
            return HR_OUT_OF_MEMORY;

        state->recovery_log_view = message.view_number;
        state->recovery_commit = message.commit_index;
    }

    add_vote(&state->recovery_votes, message.sender_idx);
    if (reached_quorum(state, state->recovery_votes) && received_recovery_primary(state)) {
        HandlerResult ret = complete_recovery(state);
        if (ret != HR_OK)
            return ret;
    }
    return HR_OK;
}

static int
process_single_future_list_entry(Server *state)
{
    int i = 0;
    while (i < state->num_future && state->future[i].log_index != state->log.count)
        i++;

    if (i == state->num_future)
        return 0;

    LogEntry entry = {
        .oper = state->future[i].oper,
        .votes = 0,
        .view_number = state->view_number,
        .client_id  = state->future[i].client_id,
        .request_id = state->future[i].request_id,
    };
    if (log_append(&state->log, entry) < 0)
        return -1;

    PrepareOKMessage message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_PREPARE_OK,
            .length  = sizeof(PrepareOKMessage),
        },
        .sender_idx  = self_idx(state),
        .log_index   = state->log.count-1,
        .view_number = state->view_number,
    };
    send_message(state->msys,state->future[i].sender_idx, &message.base);
    return 1;
}

static void
remove_old_future_list_entries(Server *state)
{
    for (int i = 0; i < state->num_future; i++) {
        if (state->future[i].log_index < state->log.count) {
            state->future[i--] = state->future[--state->num_future];
        }
    }
}

static int process_future_list(Server *state)
{
    for (;;) {
        int ret = process_single_future_list_entry(state);
        if (ret != 1)
            break;
    }
    remove_old_future_list_entries(state);
    return 0;
}

static HandlerResult
process_prepare(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    PrepareMessage message;
    if (len != sizeof(message))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    {
        char oper_buf[128];
        meta_snprint_oper(oper_buf, sizeof(oper_buf), &message.oper);
        node_log(state, "RECV PREPARE", "from=%d idx=%d commit=%d view=%llu %s",
            message.sender_idx, message.log_index, message.commit_index,
            (unsigned long long)message.view_number, oper_buf);
    }

    if (message.view_number < state->view_number)
        return HR_OK;

    if (message.view_number > state->view_number) {
        state->view_number = message.view_number;
        if (state->num_future < FUTURE_LIMIT)
            state->future[state->num_future++] = message;
        begin_state_transfer(state, message.sender_idx);
        return HR_OK;
    }

    if (message.log_index < state->log.count)
        return HR_OK;

    if (message.log_index > state->log.count) {
        if (state->num_future < FUTURE_LIMIT)
            state->future[state->num_future++] = message;
        begin_state_transfer(state, message.sender_idx);
        return HR_OK;
    }

    LogEntry log_entry = {
        .oper = message.oper,
        .votes = 0,
        .view_number = state->view_number,
        .client_id  = message.client_id,
        .request_id = message.request_id,
    };
    if (log_append(&state->log, log_entry) < 0)
        return HR_OUT_OF_MEMORY;

    PrepareOKMessage ok_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_PREPARE_OK,
            .length  = sizeof(PrepareOKMessage),
        },
        .sender_idx = self_idx(state),
        .log_index  = state->log.count-1,
        .view_number = state->view_number,
    };
    send_message(state->msys,message.sender_idx, &ok_message.base);
    node_log(state, "SEND PREPARE_OK", "to=%d idx=%d %s/%s",
        message.sender_idx, state->log.count-1, message.oper.bucket, message.oper.key);

    process_future_list(state);
    advance_commit_index(state, message.commit_index, false);

    state->heartbeat = state->now;
    return HR_OK;
}

static HandlerResult
process_commit(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    CommitMessage message;
    if (len != sizeof(CommitMessage))
        return HR_INVALID_MESSAGE;
    memcpy(&message, raw_message, sizeof(message));

    node_log(state, "RECV COMMIT", "commit=%d", message.commit_index);

    if (message.view_number < state->view_number)
        return HR_OK;

    if (message.view_number > state->view_number) {
        begin_state_transfer(state, message.sender_idx);
        return HR_OK;
    }

    advance_commit_index(state, message.commit_index, false);

    state->heartbeat = state->now;
    return HR_OK;
}

static HandlerResult
process_new_state(Server *state, void *raw_message)
{
    uint64_t len = msg_len(raw_message);

    NewStateMessage new_state_message;
    if (len < sizeof(NewStateMessage))
        return HR_INVALID_MESSAGE;
    memcpy(&new_state_message, raw_message, sizeof(new_state_message));

    node_log(state, "RECV NEW_STATE", "entries=%d commit=%d view=%llu",
        new_state_message.op_number, new_state_message.commit_index, (unsigned long long)new_state_message.view_number);

    if (new_state_message.view_number != state->view_number)
        return HR_OK;

    int num_entries = (len - sizeof(NewStateMessage)) / sizeof(LogEntry);
    if (num_entries != new_state_message.op_number)
        return HR_INVALID_MESSAGE;

    if (num_entries == 0)
        return HR_OK;

    LogEntry *entries = (LogEntry *)((uint8_t *)raw_message + sizeof(NewStateMessage));
    int start_index = new_state_message.start_index;
    for (int i = 0; i < num_entries; i++) {

        int global_idx = start_index + i;
        if (global_idx < state->log.count)
            continue;

        LogEntry entry = {
            .oper = entries[i].oper,
            .votes = 0,
            .view_number = state->view_number,
            .client_id = entries[i].client_id,
            .request_id = entries[i].request_id,
        };
        if (log_append(&state->log, entry) < 0)
            return HR_OUT_OF_MEMORY;

        PrepareOKMessage prepare_ok_message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_PREPARE_OK,
                .length  = sizeof(PrepareOKMessage),
            },
            .sender_idx  = self_idx(state),
            .log_index   = state->log.count - 1,
            .view_number = state->view_number,
        };
        send_message(state->msys,primary_idx(state), &prepare_ok_message.base);
        node_log(state, "SEND PREPARE_OK", "to=%d idx=%d %s/%s", primary_idx(state), state->log.count - 1,
            state->log.entries[state->log.count - 1].oper.bucket, state->log.entries[state->log.count - 1].oper.key);
    }

    process_future_list(state);
    advance_commit_index(state, new_state_message.commit_index, false);

    state->state_transfer_pending = false;
    state->heartbeat = state->now;
    return HR_OK;
}

static HandlerResult
send_redirect(Server *state, void *raw_message)
{
    RedirectMessage redirect_message = {
        .base = {
            .version = MESSAGE_VERSION,
            .type    = MESSAGE_TYPE_REDIRECT,
            .length  = sizeof(RedirectMessage),
        },
        .view_number = state->view_number,
    };
    reply_to_message(state->msys, raw_message, &redirect_message.base);

    node_log(state, "SEND REDIRECT", "view=%llu leader=%d",
        (unsigned long long)state->view_number, primary_idx(state));
    return HR_OK;
}

static HandlerResult
process_message(Server *state, void *raw_message)
{
    Message base;
    memcpy(&base, raw_message, sizeof(base));
    uint16_t type = base.type;

    switch (type) {
    case MESSAGE_TYPE_REQUEST:
        if (is_primary(state)) {
            if (state->status == STATUS_NORMAL) {
                return process_request(state, raw_message);
            }
        } else {
            if (state->status == STATUS_NORMAL) {
                return send_redirect(state, raw_message);
            }
        }
        break;
    case MESSAGE_TYPE_COMMIT_PUT:
        if (is_primary(state)) {
            if (state->status == STATUS_NORMAL) {
                return process_request(state, raw_message);
            }
        } else {
            if (state->status == STATUS_NORMAL) {
                return send_redirect(state, raw_message);
            }
        }
        break;
    case MESSAGE_TYPE_PREPARE:
        if (is_primary(state)) {
            // TODO
        } else {
            if (state->status == STATUS_NORMAL) {
                return process_prepare(state, raw_message);
            }
        }
        break;
    case MESSAGE_TYPE_PREPARE_OK:
        if (is_primary(state)) {
            if (state->status == STATUS_NORMAL) {
                return process_prepare_ok(state, raw_message);
            }
        } else {
            // Ignore
        }
        break;
    case MESSAGE_TYPE_COMMIT:
        if (is_primary(state)) {
            // Ignore
        } else {
            if (state->status == STATUS_NORMAL) {
                return process_commit(state, raw_message);
            }
        }
        break;
    case MESSAGE_TYPE_BEGIN_VIEW_CHANGE:
        if (state->status != STATUS_RECOVERY)
            return process_begin_view_change(state, raw_message);
        break;
    case MESSAGE_TYPE_DO_VIEW_CHANGE:
        if (is_primary(state)) {
            if (state->status == STATUS_CHANGE_VIEW) {
                return process_do_view_change(state, raw_message);
            }
        } else {
            // Ignore
        }
        break;
    case MESSAGE_TYPE_BEGIN_VIEW:
        if (state->status != STATUS_RECOVERY) {
            return process_begin_view(state, raw_message);
        }
        break;
    case MESSAGE_TYPE_RECOVERY:
        if (state->status == STATUS_NORMAL) {
            return process_recovery(state, raw_message);
        }
        break;
    case MESSAGE_TYPE_RECOVERY_RESPONSE:
        if (is_primary(state)) {
            // Ignore
        } else {
            if (state->status == STATUS_RECOVERY) {
                return process_recovery_response(state, raw_message);
            }
        }
        break;
    case MESSAGE_TYPE_GET_STATE:
        if (is_primary(state)) {
            return process_get_state(state, raw_message);
        } else {
            // Ignore
        }
        break;
    case MESSAGE_TYPE_NEW_STATE:
        if (is_primary(state)) {
            // Ignore
        } else {
            return process_new_state(state, raw_message);
        }
        break;
    case MESSAGE_TYPE_STORE_CHUNK:
        return process_store_chunk(state, raw_message);
    case MESSAGE_TYPE_FETCH_CHUNK:
        return process_fetch_chunk(state, raw_message);
    case MESSAGE_TYPE_GET_BLOB:
        return process_get_blob(state, raw_message);
    }

    return HR_OK;
}

#define POLL_CAPACITY 1024

int server_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    Server *state = state_;

    Time now = get_current_time();
    if (now == INVALID_TIME) {
        fprintf(stderr, "Node :: Couldn't get current time\n");
        return -1;
    }
    if (now > state->now)
        state->now = now;

    state->num_nodes = 0;

    bool self_addr_set = false;
    const char *chunks_path = "chunks";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--addr")) {
            if (self_addr_set) {
                fprintf(stderr, "Option --addr specified twice\n");
                return -1;
            }
            self_addr_set = true;
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --addr missing value. Usage is --addr <addr>:<port>\n");
                return -1;
            }
            int ret = parse_addr_arg(argv[i], &state->self_addr);
            if (ret < 0) {
                fprintf(stderr, "Malformed <addr>:<port> pair for --addr option\n");
                return -1;
            }
            if (state->num_nodes == NODE_LIMIT) {
                fprintf(stderr, "Node limit of %d reached\n", NODE_LIMIT);
                return -1;
            }
            state->node_addrs[state->num_nodes++] = state->self_addr;
        } else if (!strcmp(argv[i], "--peer")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --peer missing value. Usage is --peer <addr>:<port>\n");
                return -1;
            }
            if (state->num_nodes == NODE_LIMIT) {
                fprintf(stderr, "Node limit of %d reached\n", NODE_LIMIT);
                return -1;
            }
            int ret = parse_addr_arg(argv[i], &state->node_addrs[state->num_nodes]);
            if (ret < 0) {
                fprintf(stderr, "Malformed <addr>:<port> pair for --peer option\n");
                return -1;
            }
            state->num_nodes++;
        } else if (!strcmp(argv[i], "--chunks")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --chunks missing value. Usage is --chunks <path>\n");
                return -1;
            }
            chunks_path = argv[i];
        } else {
            printf("Ignoring option '%s'\n", argv[i]);
        }
    }

    addr_sort(state->node_addrs, state->num_nodes);

    Time deadline = INVALID_TIME;

    state->view_number = 0;
    state->last_normal_view = 0;
    state->heartbeat = now;
    state->commit_index = 0;
    state->num_future = 0;
    state->state_transfer_pending = false;
    state->state_transfer_time = 0;

    state->view_change_begin_votes = 0;
    state->view_change_apply_votes = 0;
    state->view_change_old_view = 0;
    state->view_change_commit = 0;
    log_init(&state->view_change_log);

    state->recovery_votes = 0;
    state->recovery_commit = 0;
    state->recovery_view = 0;
    state->recovery_log_view = 0;
    log_init(&state->recovery_log);

    int marker_fd = open("vsr_boot_marker", O_RDONLY, 0);
    bool previously_crashed = (marker_fd >= 0);
    if (previously_crashed)
        close(marker_fd);
    if (previously_crashed) {
        state->status = STATUS_RECOVERY;
        state->recovery_nonce = now;
        state->recovery_time = now;
    } else {
        state->status = STATUS_NORMAL;
    }
    log_init(&state->log);
    node_log(state, "INIT", "nodes=%d%s", state->num_nodes, previously_crashed ? " (recovering)" : "");

    client_table_init(&state->client_table);

    meta_store_init(&state->metastore);
    if (chunk_store_init(&state->chunk_store, chunks_path) < 0) {
        fprintf(stderr, "Node :: Couldn't initialize chunk store at '%s'\n", chunks_path);
        return -1;
    }

    state->msys = message_system_init(state->node_addrs, state->num_nodes);
    if (state->msys == NULL) {
        fprintf(stderr, "Node :: Couldn't setup message system\n");
        return -1;
    }

    int ret = message_system_listen_tcp(state->msys, state->self_addr);
    if (ret < 0) {
        fprintf(stderr, "Node :: Couldn't setup TCP listener\n");
        message_system_free(state->msys);
        return -1;
    }

    if (!previously_crashed) {
        int fd = open("vsr_boot_marker", O_WRONLY | O_CREAT, 0644);
        if (fd >= 0)
            close(fd);
    }

    if (previously_crashed) {
        node_log(state, "STATUS RECOVERY", "nonce=%llu (crash detected)", (unsigned long long)state->recovery_nonce);

        RecoveryMessage recovery_message = {
            .base = {
                .version = MESSAGE_VERSION,
                .type    = MESSAGE_TYPE_RECOVERY,
                .length  = sizeof(RecoveryMessage),
            },
            .sender_idx = self_idx(state),
            .nonce = state->recovery_nonce,
        };
        broadcast_message(state->msys, self_idx(state),&recovery_message.base);
        node_log(state, "SEND RECOVERY", "to=* nonce=%llu", (unsigned long long)state->recovery_nonce);

        nearest_deadline(&deadline, state->recovery_time + RECOVERY_TIMEOUT_SEC * 1000000000ULL);
    }

    *timeout = deadline_to_timeout(deadline, now);
    if (pcap < POLL_CAPACITY) {
        fprintf(stderr, "Node :: Not enough poll() capacity (got %d, needed %d)\n", pcap, POLL_CAPACITY);
        return -1;
    }
    *pnum = message_system_register_events(state->msys, ctxs, pdata, pcap);
    return 0;
}

int server_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    Server *state = state_;

    state->now = get_current_time();
    if (state->now == INVALID_TIME)
        return -1;

    /////////////////////////////////////////////////////////////////
    // NETWORK EVENTS
    /////////////////////////////////////////////////////////////////

    message_system_process_events(state->msys, ctxs, pdata, *pnum);

    for (void *ptr; (ptr = get_next_message(state->msys)) != NULL; ) {

        HandlerResult ret = process_message(state, ptr);
        if (ret == HR_OUT_OF_MEMORY)
            return -1;

        if (ret != HR_DEFERRED)
            consume_message(state->msys, ptr);
    }

    /////////////////////////////////////////////////////////////////
    // TIME EVENTS
    /////////////////////////////////////////////////////////////////

    Time deadline = INVALID_TIME;

    if (state->status == STATUS_RECOVERY) {
        Time recovery_deadline = state->recovery_time + RECOVERY_TIMEOUT_SEC * 1000000000ULL;
        if (recovery_deadline <= state->now) {
            node_log_simple(state, "TIMEOUT RECOVERY");

            RecoveryMessage recovery_message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_RECOVERY,
                    .length  = sizeof(RecoveryMessage),
                },
                .sender_idx = self_idx(state),
                .nonce = state->recovery_nonce,
            };
            broadcast_message(state->msys, self_idx(state),&recovery_message.base);
            node_log(state, "SEND RECOVERY", "to=* nonce=%llu", (unsigned long long)state->recovery_nonce);

            state->recovery_time = state->now;

        } else {
            nearest_deadline(&deadline, recovery_deadline);
        }
    } else if (state->status == STATUS_CHANGE_VIEW) {

        Time view_change_deadline = state->heartbeat + VIEW_CHANGE_TIMEOUT_SEC * 1000000000ULL;
        if (view_change_deadline <= state->now) {

            node_log_simple(state, "TIMEOUT CHANGE_VIEW");

            clear_view_change_fields(state);

            add_vote(&state->view_change_begin_votes, self_idx(state));

            state->view_number++;
            state->heartbeat = state->now;

            BeginViewChangeMessage begin_view_change_message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_BEGIN_VIEW_CHANGE,
                    .length  = sizeof(BeginViewChangeMessage),
                },
                .view_number = state->view_number,
                .sender_idx = self_idx(state),
            };
            node_log(state, "SEND BEGIN_VIEW_CHG", "to=* view=%llu", (unsigned long long)state->view_number);
            broadcast_message(state->msys, self_idx(state),&begin_view_change_message.base);

        } else {
            nearest_deadline(&deadline, view_change_deadline);
        }
    } else {
        assert(state->status == STATUS_NORMAL);

        if (is_primary(state)) {
            Time heartbeat_deadline = state->heartbeat + HEARTBEAT_INTERVAL_SEC * 1000000000ULL;
            if (heartbeat_deadline <= state->now) {

                CommitMessage commit_message = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_COMMIT,
                        .length  = sizeof(CommitMessage),
                    },
                    .view_number = state->view_number,
                    .sender_idx = self_idx(state),
                    .commit_index = state->commit_index,
                };
                broadcast_message(state->msys, self_idx(state),&commit_message.base);
                node_log(state, "SEND COMMIT", "to=* commit=%d", state->commit_index);

                state->heartbeat = state->now;

            } else {
                nearest_deadline(&deadline, heartbeat_deadline);
            }
        } else {
            Time death_deadline = state->heartbeat + PRIMARY_DEATH_TIMEOUT_SEC * 1000000000ULL;
            if (death_deadline <= state->now) {

                node_log_simple(state, "TIMEOUT PRIMARY_DEATH");

                clear_view_change_fields(state);

                add_vote(&state->view_change_begin_votes, self_idx(state));

                state->view_number++;
                state->status = STATUS_CHANGE_VIEW;
                state->heartbeat = state->now;

                BeginViewChangeMessage begin_view_change_message = {
                    .base = {
                        .version = MESSAGE_VERSION,
                        .type    = MESSAGE_TYPE_BEGIN_VIEW_CHANGE,
                        .length  = sizeof(BeginViewChangeMessage),
                    },
                    .view_number = state->view_number,
                    .sender_idx = self_idx(state),
                };
                broadcast_message(state->msys, self_idx(state),&begin_view_change_message.base);

                node_log(state, "SEND BEGIN_VIEW_CHG", "to=* view=%llu", (unsigned long long)state->view_number);
                node_log(state, "STATUS CHANGE_VIEW", "view=%llu", (unsigned long long)state->view_number);
            } else {
                nearest_deadline(&deadline, death_deadline);
            }
        }
    }

    if (state->state_transfer_pending) {

        Time st_deadline = state->state_transfer_time + STATE_TRANSFER_TIMEOUT_SEC * 1000000000ULL;
        if (st_deadline <= state->now) {
            node_log(state, "TIMEOUT STATE_TRANSFER", "op=%d", state->log.count);

            GetStateMessage get_state_message = {
                .base = {
                    .version = MESSAGE_VERSION,
                    .type    = MESSAGE_TYPE_GET_STATE,
                    .length  = sizeof(GetStateMessage),
                },
                .view_number = state->view_number,
                .op_number   = state->log.count,
                .sender_idx  = self_idx(state),
            };
            send_message(state->msys,primary_idx(state), &get_state_message.base);
            node_log(state, "SEND GET_STATE", "to=%d op=%d", primary_idx(state), state->log.count);

            state->state_transfer_time = state->now;

        } else {
            nearest_deadline(&deadline, st_deadline);
        }
    }

    *timeout = deadline_to_timeout(deadline, state->now);
    if (pcap < POLL_CAPACITY)
        return -1;
    *pnum = message_system_register_events(state->msys, ctxs, pdata, pcap);
    return 0;
}

int server_free(void *state_)
{
    Server *state = state_;

    node_log_simple(state, "CRASHED");

    log_free(&state->log);
    log_free(&state->recovery_log);
    log_free(&state->view_change_log);
    message_system_free(state->msys);
    client_table_free(&state->client_table);
    meta_store_free(&state->metastore);
    chunk_store_free(&state->chunk_store);
    return 0;
}
