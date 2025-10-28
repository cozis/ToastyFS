#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#include <stdbool.h>

#ifdef _WIN32
#else
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#define POLL poll
#define CLOSE_SOCKET close
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#include "byte_queue.h"

#define MAX_CONNS 512

typedef enum {
    EVENT_MESSAGE,
    EVENT_CONNECT,
    EVENT_DISCONNECT,
} EventType;

typedef struct {
    EventType type;
    int conn_idx;
} Event;

typedef struct {
    uint32_t data;
} IPv4;

typedef struct {
    uint16_t data[8];
} IPv6;

typedef struct {
    union {
        IPv4 ipv4;
        IPv6 ipv6;
    };
    bool is_ipv4;
    uint16_t port;
} Address;

typedef struct {
    SOCKET    fd;
    int       tag;
    bool      connecting;
    bool      closing;
    uint32_t  msglen;
    ByteQueue input;
    ByteQueue output;
} Connection;

typedef struct {
    SOCKET listen_fd;
    int    num_conns;
    Connection conns[MAX_CONNS];
} TCP;

bool addr_eql(Address a, Address b);
void tcp_context_init(TCP *tcp);
void tcp_context_free(TCP *tcp);
int  tcp_index_from_tag(TCP *tcp, int tag);
int  tcp_listen(TCP *tcp, char *addr, uint16_t port);
int  tcp_next_message(TCP *tcp, int conn_idx, ByteView *msg, uint16_t *type);
void tcp_consume_message(TCP *tcp, int conn_idx);
int  tcp_process_events(TCP *tcp, Event *events);
ByteQueue *tcp_output_buffer(TCP *tcp, int conn_idx);
int  tcp_connect(TCP *tcp, Address addr, int tag, ByteQueue **output);
void tcp_close(TCP *tcp, int conn_idx);
void tcp_set_tag(TCP *tcp, int conn_idx, int tag);
int  tcp_get_tag(TCP *tcp, int conn_idx);

#endif // TCP_INCLUDED
