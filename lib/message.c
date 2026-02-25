#include <quakey.h>
#include <assert.h>

#include "message.h"

#define MESSAGE_SYSTEM_VERSION 1

int message_system_init(MessageSystem *msys,
    Address *addrs, int num_addrs)
{
    if (num_addrs > MESSAGE_SYSTEM_NODE_LIMIT)
        return -1;
    for (int i = 0; i < num_addrs; i++)
        msys->addrs[i] = addrs[i];
    msys->num_addrs = num_addrs;
    // TODO: sort addresses

    int max_conns = 2 * num_addrs + 1;

    msys->conns = malloc(max_conns * sizeof(ConnMetadata));
    if (msys->conns == NULL)
        return -1;

    msys->max_conns = max_conns;

    for (int i = 0; i < max_conns; i++) {
        msys->conns[i].used = false;
        msys->conns[i].gen = 0;
    }

    int ret = tcp_init(&msys->tcp, max_conns);
    if (ret < 0) {
        free(msys->conns);
        return -1;
    }

    return 0;
}

int message_system_free(MessageSystem *msys)
{
    tcp_free(&msys->tcp);
    free(msys->conns);
    return 0;
}

int message_system_listen_tcp(MessageSystem *msys, Address addr)
{
    int ret = tcp_listen_tcp(&msys->tcp, S(""), addr.port, true, 128);
    if (ret < 0)
        return -1;
    return 0;
}

int message_system_listen_tls(MessageSystem *msys, Address addr)
{
    int ret = tcp_listen_tls(&msys->tcp, S(""), addr.port, true, 128);
    if (ret < 0)
        return -1;
    return 0;
}

void message_system_process_events(MessageSystem *msys,
    void **ptrs, struct pollfd *arr, int num)
{
    tcp_process_events(&msys->tcp, ptrs, arr, num);
}

int message_system_register_events(MessageSystem *msys,
    void **ptrs, struct pollfd *arr, int cap)
{
    return tcp_register_events(&msys->tcp, ptrs, arr, cap);
}

void *get_next_message(MessageSystem *msys)
{
    TCP_Event event;
    while (tcp_next_event(&msys->tcp, &event)) {

        if (event.flags & TCP_EVENT_NEW) {

            // Skip if already set up by ensure_conn (outbound connection)
            if (tcp_get_user_ptr(event.handle) == NULL) {
                int i = 0;
                while (i < msys->max_conns && msys->conns[i].used)
                    i++;

                if (i == msys->max_conns) {
                    tcp_close(event.handle);
                    continue;
                }

                ConnMetadata *meta = &msys->conns[i];
                meta->used = true;
                meta->num_senders = 0;
                meta->message = NULL;
                tcp_set_user_ptr(event.handle, meta);
            }
        }

        ConnMetadata *meta = tcp_get_user_ptr(event.handle);
        assert(meta);


        if (event.flags & TCP_EVENT_HUP) {
            meta->used = false;
            tcp_close(event.handle);
            continue;
        }

        if (!(event.flags & TCP_EVENT_DATA))
            continue;

        if (meta->message)
            continue; // Already processing message

        ByteView buf = tcp_read_buf(event.handle);

        Message message;
        if (buf.len < sizeof(message)) {
            tcp_read_ack(event.handle, 0);
            continue;
        }
        memcpy(&message, buf.ptr, sizeof(message));
        // TODO: endianess?

        if (message.version != MESSAGE_SYSTEM_VERSION) {
            assert(0); // TODO
        }

        if (message.length > (uint64_t)buf.len) {
            tcp_read_ack(event.handle, 0);
            continue; // Still buffering
        }

        // Associate this sender with the TCP connection
        if (message.sender < msys->num_addrs) {
            bool found = false;
            for (int i = 0; i < meta->num_senders; i++) {
                if (meta->senders[i] == message.sender) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                meta->senders[meta->num_senders++] = message.sender;
            }
        }

        meta->message = buf.ptr;
        return buf.ptr;
    }

    return NULL;
}

static TCP_Handle find_conn_by_message(MessageSystem *msys, void *message)
{
    for (int i = 0; i < msys->max_conns; i++) {
        ConnMetadata *meta = &msys->conns[i];
        if (meta->message == message)
            return (TCP_Handle) { &msys->tcp, meta->gen, i };
    }
    return (TCP_Handle) {0};
}

static TCP_Handle find_conn_by_target(MessageSystem *msys, int target)
{
    for (int i = 0; i < msys->max_conns; i++) {
        ConnMetadata *meta = &msys->conns[i];
        for (int j = 0; j < meta->num_senders; j++) {
            if (meta->senders[j] == target) {
                return (TCP_Handle) { &msys->tcp, meta->gen, i };
            }
        }
    }
    return (TCP_Handle) {0};
}

static TCP_Handle ensure_conn(MessageSystem *msys, int target)
{
    TCP_Handle handle = find_conn_by_target(msys, target);
    if (handle.tcp)
        return handle;

    if (target < 0 || target >= msys->num_addrs)
        return (TCP_Handle) {0};

    int ret = tcp_connect(&msys->tcp, false, &msys->addrs[target], 1);
    if (ret < 0)
        return (TCP_Handle) {0};

    // Find the newly created connection slot and pre-associate with target
    for (int i = 0; i < msys->max_conns; i++) {
        TCP_Conn *conn = &msys->tcp.conns[i];
        if (conn->state == TCP_CONN_STATE_FREE)
            continue;
        if (conn->user_ptr != NULL)
            continue;
        if (conn->state != TCP_CONN_STATE_CONNECTING
            && conn->state != TCP_CONN_STATE_ESTABLISHED)
            continue;

        ConnMetadata *meta = &msys->conns[i];
        meta->used = true;
        meta->gen = conn->gen;
        meta->num_senders = 1;
        meta->senders[0] = target;
        meta->message = NULL;

        TCP_Handle h = { &msys->tcp, conn->gen, i };
        tcp_set_user_ptr(h, meta);
        return h;
    }

    return (TCP_Handle) {0};
}

void consume_message(MessageSystem *msys, void *ptr)
{
    int i = 0;
    while (i < msys->max_conns && msys->conns[i].message != ptr)
        i++;

    if (i == msys->max_conns)
        return; // Not found

    Message message;
    memcpy(&message, ptr, sizeof(message));

    TCP_Handle handle = { &msys->tcp, msys->conns[i].gen, i };
    tcp_read_ack(handle, message.length);
    tcp_mark_ready(handle);
    msys->conns[i].message = NULL;
}

void send_message(MessageSystem *msys, int target, Message *message)
{
    TCP_Handle handle = ensure_conn(msys, target);
    if (!handle.tcp) return;
    tcp_write(handle, (string) { (char*) message, message->length });
}

void send_message_ex(MessageSystem *msys, int target,
    Message *header, void *extra, int extra_len)
{
    TCP_Handle handle = ensure_conn(msys, target);
    if (!handle.tcp) return;
    int header_size = header->length - extra_len;
    tcp_write(handle, (string) { (char*) header, header_size });
    tcp_write(handle, (string) { (char*) extra, extra_len });
}

void reply_to_message(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message)
{
    TCP_Handle handle = find_conn_by_message(msys, incoming_message);
    if (!handle.tcp) return;
    tcp_write(handle, (string) { (char*) outgoing_message, outgoing_message->length });
}

void reply_to_message_ex(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message, void *extra, int extra_len)
{
    TCP_Handle handle = find_conn_by_message(msys, incoming_message);
    if (!handle.tcp) return;
    int header_size = outgoing_message->length - extra_len;
    tcp_write(handle, (string) { (char*) outgoing_message, header_size });
    tcp_write(handle, (string) { (char*) extra, extra_len });
}

void broadcast_message(MessageSystem *msys, int self_idx, Message *message)
{
    for (int i = 0; i < msys->num_addrs; i++) {
        if (i != self_idx)
            send_message(msys, i, message);
    }
}

void broadcast_message_ex(MessageSystem *msys, int self_idx,
    Message *header, void *extra, int extra_len)
{
    for (int i = 0; i < msys->num_addrs; i++) {
        if (i != self_idx)
            send_message_ex(msys, i, header, extra, extra_len);
    }
}



