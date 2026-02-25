#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <stdint.h>

#include "basic.h"

typedef struct MessageSystem MessageSystem;

typedef struct {
    uint16_t version;
    uint16_t type;
    uint16_t sender;
    uint64_t length;
} Message;

MessageSystem *message_system_init(Address *addrs, int num_addrs);

void message_system_free(MessageSystem *msys);

int message_system_listen_tcp(MessageSystem *msys, Address addr);

struct pollfd;

void message_system_process_events(MessageSystem *msys,
    void **ptrs, struct pollfd *pfds, int num);

int message_system_register_events(MessageSystem *msys,
    void **ptrs, struct pollfd *pfds, int cap);

void *get_next_message(MessageSystem *msys);

int message_length(void *raw_message);

void consume_message(MessageSystem *msys, void *ptr);

void send_message(MessageSystem *msys, int target, Message *message);

void send_message_ex(MessageSystem *msys, int target,
    Message *header, void *extra, int extra_len);

void reply_to_message(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message);

void reply_to_message_ex(MessageSystem *msys, void *incoming_message,
    Message *outgoing_message, void *extra, int extra_len);

void broadcast_message(MessageSystem *msys, int self_idx, Message *message);

void broadcast_message_ex(MessageSystem *msys, int self_idx,
    Message *header, void *extra, int extra_len);

#endif // MESSAGE_INCLUDED
