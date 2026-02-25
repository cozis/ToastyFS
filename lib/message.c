#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>

#include "tcp.h"
#include "message.h"

#define MESSAGE_SYSTEM_VERSION 1
#define MESSAGE_SYSTEM_NODE_LIMIT 8

typedef struct {
    bool       used;
    TCP_Handle handle;
    int        senders[MESSAGE_SYSTEM_NODE_LIMIT];
    int        num_senders;
    void*      message;
} Channel;

struct MessageSystem {

    TCP *tcp;

    Address addrs[MESSAGE_SYSTEM_NODE_LIMIT];
    int num_addrs;

    int max_channels;
    Channel channels[];
};

MessageSystem *message_system_init(Address *addrs, int num_addrs)
{
    int max_channels = 2 * num_addrs + 1;
    MessageSystem *msys = malloc(sizeof(MessageSystem) + max_channels * sizeof(Channel));
    if (msys == NULL)
        return NULL;

    if (num_addrs > MESSAGE_SYSTEM_NODE_LIMIT) {
        free(msys);
        return NULL;
    }
    for (int i = 0; i < num_addrs; i++)
        msys->addrs[i] = addrs[i];
    msys->num_addrs = num_addrs;
    addr_sort(msys->addrs, msys->num_addrs);

    msys->max_channels = max_channels;
    for (int i = 0; i < max_channels; i++)
        msys->channels[i].used = 0;

    msys->tcp = tcp_init(max_channels);
    if (msys->tcp == NULL) {
        free(msys);
        return NULL;
    }

    return msys;
}

void message_system_free(MessageSystem *msys)
{
    tcp_free(msys->tcp);
    free(msys);
}

int message_system_listen_tcp(MessageSystem *msys, Address addr)
{
    int ret = tcp_listen_tcp(msys->tcp, addr);
    if (ret < 0)
        return -1;
    return 0;
}

void message_system_process_events(MessageSystem *msys,
    void **ptrs, struct pollfd *pfds, int num)
{
    tcp_process_events(msys->tcp, ptrs, pfds, num);
}

int message_system_register_events(MessageSystem *msys,
    void **ptrs, struct pollfd *pfds, int cap)
{
    return tcp_register_events(msys->tcp, ptrs, pfds, cap);
}

static int
find_free_channel_struct(MessageSystem *msys)
{
    int i = 0;
    while (i < msys->max_channels && msys->channels[i].used)
        i++;

    if (i == msys->max_channels)
        return -1; // No free space

    return i;
}

static bool has_sender(Channel *channel, int sender_idx)
{
    for (int i = 0; i < channel->num_senders; i++)
        if (channel->senders[i] == sender_idx)
            return true;
    return false;
}

static void add_sender(Channel *channel, int sender_idx)
{
    if (has_sender(channel, sender_idx))
        return;
    channel->senders[channel->num_senders++] = sender_idx;
}

void *get_next_message(MessageSystem *msys)
{
    TCP_Event event;
    while (tcp_next_event(msys->tcp, &event)) {

        if (event.flags & TCP_EVENT_NEW) {

            int channel_idx = find_free_channel_struct(msys);
            if (channel_idx < 0) {
                tcp_close(event.handle);
                continue;
            }
            Channel *channel = &msys->channels[channel_idx];

            channel->used = true;
            channel->num_senders = 0;
            channel->message = NULL;
            channel->handle = event.handle;

            tcp_set_user_ptr(event.handle, channel);
        }

        Channel *channel = tcp_get_user_ptr(event.handle);

        if (event.flags & TCP_EVENT_HUP) {
            channel->used = false;
            tcp_close(channel->handle); // TODO: What if the user is still hanging on the message pointer?
        }

        if (!(event.flags & TCP_EVENT_DATA))
            continue;

        string buf = tcp_read_buf(event.handle);

        Message message;
        if (buf.len < (int) sizeof(message)) {
            tcp_read_ack(event.handle, 0);
            continue;
        }
        memcpy(&message, buf.ptr, sizeof(message));
        // TODO: endianess?

        if (message.version != MESSAGE_SYSTEM_VERSION) {
            assert(0); // TODO
        }

        if (message.length > (uint64_t) buf.len) {
            tcp_read_ack(event.handle, 0);
            continue; // Still buffering
        }

        add_sender(channel, message.sender);

        channel->message = buf.ptr;
        return buf.ptr;
    }

    return NULL;
}

static int find_channel_by_message(MessageSystem *msys, void *raw_message)
{
    for (int i = 0; i < msys->max_channels; i++) {
        Channel *channel = &msys->channels[i];
        if (!channel->used)
            continue;
        if (channel->message == raw_message)
            return i;
    }
    return -1;
}

int message_length(void *raw_message)
{
    Message message;
    memcpy(&message, raw_message, sizeof(message));
    return message.length;
}

void consume_message(MessageSystem *msys, void *raw_message)
{
    int channel_idx = find_channel_by_message(msys, raw_message);
    if (channel_idx < 0)
        return;
    Channel *channel = &msys->channels[channel_idx];

    channel->message = NULL;
    tcp_read_ack(channel->handle, message_length(raw_message));
    tcp_mark_ready(channel->handle);
}

static int find_channel_by_target_idx(MessageSystem *msys, int target_idx)
{
    for (int i = 0; i < msys->max_channels; i++) {

        Channel *channel = &msys->channels[i];
        if (!channel->used)
            continue;

        for (int j = 0; j < channel->num_senders; j++) {
            if (channel->senders[j] == target_idx)
                return i;
        }
    }

    return -1;
}

void send_message_ex(MessageSystem *msys, int target_idx,
    Message *message, void *extra, int extra_len)
{
    int channel_idx = find_channel_by_target_idx(msys, target_idx);
    if (channel_idx < 0) {

        // Find an unused channel struct
        channel_idx = find_free_channel_struct(msys);
        if (channel_idx < 0)
            return; // No free space

        // Establish a new connection
        TCP_Handle handle;
        if (tcp_connect(msys->tcp, false, &msys->addrs[target_idx], 1, &handle) < 0)
            return;

        Channel *channel = &msys->channels[channel_idx];
        channel->used = true;
        channel->handle = handle;
        channel->senders[0] = target_idx;
        channel->num_senders = 1;
        channel->message = NULL;

        tcp_set_user_ptr(handle, channel);
    }
    Channel *channel = &msys->channels[channel_idx];

    tcp_write(channel->handle, (string) { (void*) message, message->length - extra_len });
    if (extra_len > 0)
        tcp_write(channel->handle, (string) { extra, extra_len });
}

void send_message(MessageSystem *msys, int target_idx,
    Message *message)
{
    send_message_ex(msys, target_idx, message, NULL, 0);
}

void reply_to_message_ex(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message, void *extra, int extra_len)
{
    int channel_idx = find_channel_by_message(msys, incoming_message);
    if (channel_idx < 0)
        return;
    Channel *channel = &msys->channels[channel_idx];

    int header_size = outgoing_message->length - extra_len;
    tcp_write(channel->handle, (string) { (char*) outgoing_message, header_size });
    if (extra_len > 0)
        tcp_write(channel->handle, (string) { (char*) extra, extra_len });
}

void reply_to_message(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message)
{
    reply_to_message_ex(msys, incoming_message, outgoing_message, NULL, 0);
}

void broadcast_message_ex(MessageSystem *msys, int self_idx,
    Message *message, void *extra, int extra_len)
{
    for (int i = 0; i < msys->num_addrs; i++) {
        if (i != self_idx)
            send_message_ex(msys, i, message, extra, extra_len);
    }
}

void broadcast_message(MessageSystem *msys, int self_idx, Message *message)
{
    broadcast_message_ex(msys, self_idx, message, NULL, 0);
}
