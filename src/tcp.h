#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#include <stdbool.h>

#include "system.h"
#include "byte_queue.h"

#ifdef _WIN32
#define CLOSE_SOCKET sys_closesocket
#else
#define CLOSE_SOCKET sys_close
#endif

#define MAX_CONNS 512

typedef enum {
    EVENT_MESSAGE,
    EVENT_CONNECT,
    EVENT_DISCONNECT,
} EventType;

typedef struct {
    EventType type;
    int conn_idx;
    int tag;
} Event;

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
int  tcp_listen(TCP *tcp, string addr, uint16_t port);
int  tcp_next_message(TCP *tcp, int conn_idx, ByteView *msg, uint16_t *type);
void tcp_consume_message(TCP *tcp, int conn_idx);
int  tcp_translate_events(TCP *tcp, Event *events, void **contexts, struct pollfd *polled, int num_polled);
int  tcp_register_events(TCP *tcp, void **contexts, struct pollfd *polled);
ByteQueue *tcp_output_buffer(TCP *tcp, int conn_idx);
int  tcp_connect(TCP *tcp, Address addr, int tag, ByteQueue **output);
void tcp_close(TCP *tcp, int conn_idx);
void tcp_set_tag(TCP *tcp, int conn_idx, int tag, bool unique);
int  tcp_get_tag(TCP *tcp, int conn_idx);

#endif // TCP_INCLUDED
