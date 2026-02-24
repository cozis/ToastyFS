#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#include "basic.h"
#include "byte_queue.h"
#include "tls.h"

typedef struct TCP TCP;

typedef struct {
    TCP*     tcp;
    uint16_t gen;
    int      idx;
} TCP_Handle;

typedef enum {
    TCP_CONN_STATE_FREE,
    TCP_CONN_STATE_HANDSHAKE,
    TCP_CONN_STATE_ESTABLISHED,
    TCP_CONN_STATE_CONNECTING,
    TCP_CONN_STATE_ACCEPTING,
    TCP_CONN_STATE_SHUTDOWN,
} TCP_ConnState;

#define TCP_CONNECT_ADDR_LIMIT 8

enum {
    TCP_EVENT_NEW  = 1<<0,
    TCP_EVENT_HUP  = 1<<1,
    TCP_EVENT_DATA = 1<<2,
};

enum {
    TCP_CONN_FLAG_CLOSED = 1<<0,
    TCP_CONN_FLAG_SECURE = 1<<1,
};

typedef struct {
    TCP_ConnState state;
    int       flags;
    int       events;
    uint16_t  gen;
    int       fd;
    bool      handled;
    bool      closing;
    void     *user_ptr;
    ByteQueue input;
    ByteQueue output;
#ifdef TLS_ENABLED
    TLS_Conn  tls;
#endif
    Address addrs[TCP_CONNECT_ADDR_LIMIT];
    int num_addrs;
    int addr_idx;
} TCP_Conn;

struct TCP {
    int tls_listen_fd;
    int tcp_listen_fd;
    int num_conns;
    int max_conns;
    TCP_Conn *conns;
#ifdef TLS_ENABLED
    TLS_Server tls;
#endif
};

typedef struct {
    int        flags;
    TCP_Handle handle;
} TCP_Event;

typedef ByteQueueOffset TCP_Offset;

struct pollfd;

int        tcp_init(TCP *tcp, int max_conns);
void       tcp_free(TCP *tcp);
int        tcp_listen_tcp(TCP *tcp, string addr, uint16_t port, bool reuse_addr, int backlog);
int        tcp_listen_tls(TCP *tcp, string addr, uint16_t port, bool reuse_addr, int backlog);
int        tcp_add_cert(TCP *tcp, string cert_file, string key_file);
int        tcp_connect(TCP *tcp, bool secure, Address *addrs, int num_addrs);
void       tcp_process_events(TCP *tcp, void **ptrs, struct pollfd *arr, int num);
int        tcp_register_events(TCP *tcp, void **ptrs, struct pollfd *arr, int cap);
bool       tcp_next_event(TCP *tcp, TCP_Event *event);
ByteView   tcp_read_buf(TCP_Handle handle);
void       tcp_read_ack(TCP_Handle handle, int num);
ByteView   tcp_write_buf(TCP_Handle handle);
void       tcp_write_ack(TCP_Handle handle, int num);
TCP_Offset tcp_write_off(TCP_Handle handle);
void       tcp_write(TCP_Handle handle, string str);
void       tcp_patch(TCP_Handle handle, TCP_Offset offset, void *src, int len);
void       tcp_clear_from_offset(TCP_Handle handle, TCP_Offset offset);
void       tcp_close(TCP_Handle handle);
void       tcp_set_user_ptr(TCP_Handle handle, void *ptr);
void      *tcp_get_user_ptr(TCP_Handle handle);
void       tcp_mark_ready(TCP_Handle handle);

#endif // TCP_INCLUDED
