#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#   define QUAKEY_ENABLE_MOCKS
#   include <quakey.h>
#else
#   ifdef _WIN32
#       include <winsock2.h>
#   endif
#endif

#include "byte_queue.h"

#ifdef _WIN32
#define CLOSE_SOCKET closesocket
#else
#define SOCKET int
#define INVALID_SOCKET -1
#define CLOSE_SOCKET close
#endif

#ifndef TCP_CONNECTION_LIMIT
// Maximum number of connections that can be managed
// simultaneously.
#define TCP_CONNECTION_LIMIT 512
#endif

// This is the maximum number of descriptors that the
// TCP system will want to wait at any given time.
// One descriptor per connection plus a listener socket
// and a self-pipe handle for wakeup.
#define TCP_POLL_CAPACITY (TCP_CONNECTION_LIMIT+2)

// Number of TCP events that can be returned at a given
// time by "tcp_translate_events". There may be a single
// event per connection (MESSAGE, CONNECT, DISCONNECT)
// plus a general WAKEUP event.
#define TCP_EVENT_CAPACITY (TCP_CONNECTION_LIMIT+1)

typedef enum {
    EVENT_WAKEUP,
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
    SOCKET wait_fd;
    SOCKET signal_fd;
    int    num_conns;
    Connection conns[TCP_CONNECTION_LIMIT];
} TCP;

int  tcp_context_init(TCP *tcp);
void tcp_context_free(TCP *tcp);
int  tcp_wakeup(TCP *tcp);
int  tcp_index_from_tag(TCP *tcp, int tag);
int  tcp_listen(TCP *tcp, Address addr);
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
