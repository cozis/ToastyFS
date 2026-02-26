#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>

#include "tls.h"
#include "tcp.h"

#ifdef _WIN32
#define CLOSE_SOCKET closesocket
#else
#define SOCKET int
#define INVALID_SOCKET -1
#define CLOSE_SOCKET close
#endif

#define MIN_RECV 4096
#define TCP_CONNECT_ADDR_LIMIT 8

// Flags for the "flags" field in TCP_Conn.
enum {
    TCP_CONN_FLAG_CLOSED = 1<<0,
    TCP_CONN_FLAG_SECURE = 1<<1,
};

typedef enum {
    TCP_CONN_STATE_FREE,
    TCP_CONN_STATE_HANDSHAKE,
    TCP_CONN_STATE_ESTABLISHED,
    TCP_CONN_STATE_CONNECTING,
    TCP_CONN_STATE_ACCEPTING,
    TCP_CONN_STATE_SHUTDOWN,
} TCP_ConnState;

typedef struct {

    // ID of the general state this structure is in
    TCP_ConnState state;

    // Information about the socket:
    //   - TCP_CONN_FLAG_CLOSED
    //       Whether the user is holding a handle to this struct.
    //       It's first set when the TCP_EVENT_NEW is passed to
    //       the user, and it's unset when the user calls tcp_close.
    //   - TCP_CONN_FLAG_SECURE
    //       Whether the connection was establushed via the
    //       encrypted interface or not
    int flags;

    // Events associated to this connection that the user
    // still isn't aware about. These will be returned to
    // the user at the next tcp_next_event call and this
    // field cleared.
    int events;

    // Generation counter for this structure. This allows
    // invalidating handles to this structure. It's important
    // we use an unsigned field here as we rely on it
    // overflowing.
    uint16_t gen;

    // Underlying socket
    SOCKET fd;

    // The socket should be closing as soon as the buffered
    // output data has been flushed. When this is set, no more
    // data can be buffered from the network.
    bool closing;

    // Opaque pointer set by the user. It allows associating
    // the connection's handle to the user's metadata for it.
    void *user_ptr;

    // Input and output buffers
    ByteQueue input;
    ByteQueue output;

    Address addrs[TCP_CONNECT_ADDR_LIMIT];
    int num_addrs;
    int addr_idx;

#ifdef TLS_ENABLED
    TLS_Conn tls;
#endif

} TCP_Conn;

struct TCP {
    // Listening sockets for TCP and TLS connections.
    // Zero, one, or both of these may be set. If both
    // are invalid, the user will only be able to add
    // connections to the TCP pool via tcp_connect.
    // If only one of these is set, all connections will
    // be either plaintext or encrypted. If both are
    // set, some connections will be plaintext and some
    // will be encrypted, but either way they will look
    // the same from the user's perspective as it will
    // only see the plaintext data.
    SOCKET tcp_listen_fd;
    SOCKET tls_listen_fd;

#ifdef TLS_ENABLED
    TLS_Server tls;
#endif

    // Total size of the connection array and how many
    // structures in it are currently in use.
    int max_conns;
    int num_conns;

    // Fixed-size array of connection structures. The
    // array follows the TCP structure in memory, making
    // it possible for it to be allocated with a single
    // malloc call.
    TCP_Conn conns[];
};

static void close_socket(SOCKET fd)
{
#if defined(_WIN32)
    closesocket(fd); // TODO: make sure closesocket is mocked
#else
    close(fd);
#endif
}

static int set_socket_blocking(SOCKET fd, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
    return 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (value)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
    return 0;
#endif
}

static int bind_2(SOCKET fd, Address addr)
{
    if (addr.is_ipv4) {
        struct sockaddr_in buf;
        buf.sin_family = AF_INET;
        buf.sin_port   = htons(addr.port);
        memcpy(&buf.sin_addr, &addr.ipv4, sizeof(IPv4));
        return bind(fd, (struct sockaddr*) &buf, sizeof(buf));
    } else {
        struct sockaddr_in6 buf;
        buf.sin6_family = AF_INET6;
        buf.sin6_port   = htons(addr.port);
        memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(IPv6));
        return bind(fd, (struct sockaddr*) &buf, sizeof(buf));
    }
}

static SOCKET
create_listen_socket(Address addr, bool reuse_addr, int backlog)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (fd == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa); // TODO: check error
        fd = socket(AF_INET, SOCK_STREAM, 0);
    }
#endif
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (set_socket_blocking(fd, false) < 0) {
        close_socket(fd);
        return INVALID_SOCKET;
    }

#ifndef QUAKEY_ENABLE_MOCKS
    if (reuse_addr) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)); // TODO: mock this
    }
#else
    (void) reuse_addr;
#endif

    if (bind_2(fd, addr) < 0) {
        close_socket(fd);
        return INVALID_SOCKET;
    }

    if (listen(fd, backlog) < 0) {
        close_socket(fd);
        return INVALID_SOCKET;
    }

    return fd;
}

static int connect_2(SOCKET fd, Address addr)
{
    if (addr.is_ipv4) {
        struct sockaddr_in buf;
        buf.sin_family = AF_INET;
        buf.sin_port   = htons(addr.port);
        STATIC_ASSERT(sizeof(buf.sin_addr) == sizeof(addr.ipv4));
        memcpy(&buf.sin_addr, &addr.ipv4, sizeof(addr.ipv4));
        return connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    } else {
        struct sockaddr_in6 buf;
        buf.sin6_family = AF_INET;
        buf.sin6_port   = htons(addr.port);
        STATIC_ASSERT(sizeof(buf.sin6_addr) == sizeof(addr.ipv6));
        memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(addr.ipv6));
        return connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    }
}

// See tcp.h
TCP *tcp_init(int max_conns)
{
    TCP *tcp = malloc(sizeof(TCP) + max_conns * sizeof(TCP_Conn));
    if (tcp == NULL)
        return NULL;

    // Initialize TCP_Conn fields that are used event if
    // the structure is free.
    for (int i = 0; i < max_conns; i++) {
        tcp->conns[i].state = TCP_CONN_STATE_FREE;
        tcp->conns[i].gen = 0;
    }

    // Listening sockets is disabled by default. The user
    // must enable it explicitly by calling the tcp_listen_xxx
    // functions.
    tcp->tcp_listen_fd = INVALID_SOCKET;
    tcp->tls_listen_fd = INVALID_SOCKET;

    tcp->max_conns = max_conns;
    tcp->num_conns = 0;

    return tcp;
}

static void tcp_conn_free(TCP_Conn *conn);
static bool tcp_conn_free_maybe(TCP_Conn *conn);

// See tcp.h
void tcp_free(TCP *tcp)
{
    if (tcp->tcp_listen_fd != INVALID_SOCKET)
        close_socket(tcp->tcp_listen_fd);

#ifdef TLS_ENABLED
    if (tcp->tls_listen_fd != INVALID_SOCKET) {
        close_socket(tcp->tls_listen_fd);
        tls_server_free(&tcp->tls);
    }
#endif

    for (int i = 0; i < tcp->max_conns; i++) {
        if (tcp->conns[i].state != TCP_CONN_STATE_FREE)
            tcp_conn_free(&tcp->conns[i]);
    }

    free(tcp);
}

// See tcp.h
int tcp_listen_tcp(TCP *tcp, Address addr)
{
    // Ensure plaintext server mode wasn't enabled already.
    if (tcp->tcp_listen_fd != INVALID_SOCKET)
        return -1;

    // TODO: Make these configurable
    bool reuse_addr = true;
    int backlog = 32;

    SOCKET fd = create_listen_socket(addr, reuse_addr, backlog);
    if (fd == INVALID_SOCKET)
        return -1;

    tcp->tcp_listen_fd = fd;
    return 0;
}

// See tcp.h
int tcp_listen_tls(TCP *tcp, Address addr, string cert_file, string key_file)
{
#ifdef TLS_ENABLED
    // Ensure plaintext server mode wasn't enabled already.
    if (tcp->tls_listen_fd != INVALID_SOCKET)
        return -1;

    // TODO: Make these configurable
    bool reuse_addr = true;
    int backlog = 32;

    SOCKET fd = create_listen_socket(addr, reuse_addr, backlog);
    if (fd == INVALID_SOCKET)
        return -1;

    if (tls_server_init(&tcp->tls, cert_file, key_file) < 0) {
        close_socket(fd);
        return -1;
    }

    tcp->tls_listen_fd = fd;
    return 0;
#else
    (void) tcp;
    (void) addr;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

// See tcp.h
int tcp_add_cert(TCP *tcp, string domain, string cert_file, string key_file)
{
#ifdef TLS_ENABLED
    int ret = tls_server_add_cert(&tcp->tls, domain, cert_file, key_file);
    if (ret < 0)
        return -1;
    return 0;
#else
    (void) tcp;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

static void tcp_conn_init(TCP *tcp, TCP_Conn *conn, bool secure, TCP_ConnState state, SOCKET fd)
{
    conn->state = state;
    conn->flags = 0;
    conn->events = 0;
    conn->closing = false;
    conn->fd = fd;
    conn->num_addrs = 0;
    conn->addr_idx = 0;
    conn->user_ptr = NULL;
    byte_queue_init(&conn->input, 1<<20);
    byte_queue_init(&conn->output, 1<<20);
#ifdef TLS_ENABLED
    if (secure) {
        conn->flags |= TCP_CONN_FLAG_SECURE;
        tls_conn_init(&conn->tls, &tcp->tls);
    }
#else
    (void) tcp;
    (void) secure;
#endif
}

static void tcp_conn_free(TCP_Conn *conn)
{
    if (conn->fd != INVALID_SOCKET)
        close_socket(conn->fd);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE)
        tls_conn_free(&conn->tls);
#endif
    conn->state = TCP_CONN_STATE_FREE;
}

static void tcp_conn_set_addrs(TCP_Conn *conn,
    Address *addrs, int num_addrs)
{
    assert(num_addrs <= TCP_CONNECT_ADDR_LIMIT);
    for (int i = 0; i < num_addrs; i++)
        conn->addrs[i] = addrs[i];
    conn->num_addrs = num_addrs;
}

static string tcp_conn_write_buf(TCP_Conn *conn)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        int cap;
        char *ptr = tls_conn_net_write_buf(&conn->tls, &cap);
        if (ptr == NULL)
            return (string) {0};
        return (string) { ptr, cap };
    }
#endif

    byte_queue_write_setmincap(&conn->input, MIN_RECV);
    return byte_queue_write_buf(&conn->input);
}

static int tcp_conn_write_ack(TCP_Conn *conn, int num)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        int ret = 0;
        tls_conn_net_write_ack(&conn->tls, num);
        for (bool done = false; !done; ) {
            byte_queue_write_setmincap(&conn->input, MIN_RECV);
            string buf = byte_queue_write_buf(&conn->input);
            int n = tls_conn_app_read(&conn->tls, (char*) buf.ptr, buf.len);
            if (n <= 0) {
                if (n < 0) {
                    ret = -1;
                    n = 0;
                }
                done = true;
            }
            byte_queue_write_ack(&conn->input, n);
        }
        return ret;
    }
#endif

    byte_queue_write_ack(&conn->input, num);
    return 0;
}


#ifdef TLS_ENABLED
// Encrypt plaintext from the output queue through SSL_write into the BIO.
static void tcp_conn_tls_encrypt_output(TCP_Conn *conn)
{
    while (!byte_queue_empty(&conn->output)) {
        string src = byte_queue_read_buf(&conn->output);
        if (!src.ptr || src.len == 0) {
            byte_queue_read_ack(&conn->output, 0);
            break;
        }
        int n = tls_conn_app_write(&conn->tls, (char*) src.ptr, src.len);
        if (n <= 0) {
            byte_queue_read_ack(&conn->output, 0);
            break;
        }
        byte_queue_read_ack(&conn->output, n);
    }
}
#endif

static string tcp_conn_read_buf(TCP_Conn *conn)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        tcp_conn_tls_encrypt_output(conn);
        int n;
        char *ptr = tls_conn_net_read_buf(&conn->tls, &n);
        if (ptr == NULL)
            return (string) {0};
        return (string) { ptr, n };
    }
#endif

    return byte_queue_read_buf(&conn->output);
}

static void tcp_conn_read_ack(TCP_Conn *conn, int num)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        tls_conn_net_read_ack(&conn->tls, num);
        return;
    }
#endif

    byte_queue_read_ack(&conn->output, num);
}

static bool tcp_conn_needs_flushing(TCP_Conn *conn)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        return !byte_queue_empty(&conn->output)
            || tls_conn_needs_flushing(&conn->tls);
    }
#endif

    return !byte_queue_empty(&conn->output);
}

static bool tcp_conn_is_buffering(TCP_Conn *conn)
{
    if (conn->closing)
       return false;

    if (conn->state == TCP_CONN_STATE_HANDSHAKE ||
        conn->state == TCP_CONN_STATE_ACCEPTING)
        return true;

    return !byte_queue_reading(&conn->input);
}

static bool tcp_conn_free_maybe(TCP_Conn *conn)
{
    if (!(conn->flags & TCP_CONN_FLAG_CLOSED) && conn->fd == INVALID_SOCKET) {
        tcp_conn_free(conn);
        return true;
    } else {
        return false;
    }
}

static void tcp_conn_invalidate_handles(TCP_Conn *conn)
{
    conn->gen++;
    if (conn->gen == 0)
        conn->gen = 1;
}

static TCP_Handle conn_to_handle(TCP *tcp, TCP_Conn *conn)
{
    TCP_Handle handle = {
        .tcp=tcp,
        .gen=conn->gen,
        .idx=conn - tcp->conns,
    };
    return handle;
}

static TCP_Conn *handle_to_conn(TCP_Handle handle)
{
    if (handle.tcp == NULL)
        return NULL;
    TCP *tcp = handle.tcp;

    if (handle.idx < 0 || handle.idx >= tcp->max_conns)
        return NULL;
    TCP_Conn *conn = &tcp->conns[handle.idx];

    if (conn->state == TCP_CONN_STATE_FREE || conn->gen != handle.gen)
        return NULL;

    return conn;
}

static int find_free_conn_struct(TCP *tcp)
{
    if (tcp->num_conns == tcp->max_conns)
        return -1; // No space left

    // Since we passed the previous check, we know
    // for sure at least one free struct is available
    int i = 0;
    while (tcp->conns[i].state != TCP_CONN_STATE_FREE) {
        i++;
        assert(i < tcp->max_conns);
    }

    return i;
}

static bool connect_in_progress(void)
{
#ifdef _WIN32
#ifdef QUAKEY_ENABLE_MOCKS
    assert(0); // TODO: The mock WSA function must use WSASetLastError
#endif
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

// See tcp.h
int tcp_connect(TCP *tcp, bool secure, Address *addrs, int num_addrs, TCP_Handle *handle)
{
    if (num_addrs == 0)
        return -1;
    Address first_addr = addrs[0];

    int conn_idx = find_free_conn_struct(tcp);
    if (conn_idx < 0)
        return -1; // No space left

    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (fd == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa); // TODO: check error
        fd = socket(AF_INET, SOCK_STREAM, 0);
    }
#endif
    if (fd == INVALID_SOCKET)
        return -1;

    if (set_socket_blocking(fd, false) < 0) {
        close_socket(fd);
        return -1;
    }

    int ret = connect_2(fd, first_addr);

    // Generally speaking connect() requires time to complete.
    // If a connect() operation is started on a non-blocking,
    // socket, the operation will fail with error code EINPROGRESS.
    // The user can then monitor the connecting descriptor until
    // the connection is complete. Under certain circumstances
    // it may be possible for the connection to resolve immediately,
    // which means the connect() function will return 0. We also
    // want to cover those cases.
    TCP_ConnState state;
    if (ret == 0) {
        // Early completion
        if (secure) {
            // If the connection is TLS, we also need to perform the
            // TLS handshake before we can call it established.
            state = TCP_CONN_STATE_HANDSHAKE;
        } else {
            // All done. Connection si ready.
            state = TCP_CONN_STATE_ESTABLISHED;
        }
    } else {
        assert(ret < 0);
        if (connect_in_progress()) {
            // This is the case we expect most often.
            state = TCP_CONN_STATE_CONNECTING;
        } else {
            // Operation could not be started
            close_socket(fd);
            return -1;
        }
    }

    TCP_Conn *conn = &tcp->conns[conn_idx];
    if (handle)
        *handle = conn_to_handle(tcp, conn);

    tcp_conn_init(tcp, conn, secure, state, fd);
    tcp_conn_set_addrs(conn, addrs, num_addrs);
    tcp->num_conns++;
    return 0;
}

// When a connection operation completes with a
// failure, the TCP pool must try to establish
// a connection with the next address specified
// by the user. This function advances the address
// cursor and starts a new connect operation.
static int restart_connect(TCP_Conn *conn)
{
    assert(conn->fd != INVALID_SOCKET);
    close_socket(conn->fd);
    conn->fd = INVALID_SOCKET;

    conn->addr_idx++;
    if (conn->addr_idx == conn->num_addrs)
        return -1; // No more addresses to try
    Address next_addr = conn->addrs[conn->addr_idx];

    // Elsewhere in this file calls to socket() are
    // followed by the initialization of the winsock2
    // subsystem. Here we don't need to worry about
    // that since we know at least one connect() operation
    // was performed before so the winsock2 subsystem was
    // already initialized.
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return -1;

    if (set_socket_blocking(fd, false) < 0) {
        close_socket(fd);
        return -1;
    }

    TCP_ConnState state;
    int ret = connect_2(fd, next_addr);
    if (ret == 0) {
        if (conn->flags & TCP_CONN_FLAG_SECURE) {
            state = TCP_CONN_STATE_HANDSHAKE;
        } else {
            state = TCP_CONN_STATE_ESTABLISHED;
        }
    } else {
        assert(ret < 0);
        if (connect_in_progress()) {
            state = TCP_CONN_STATE_CONNECTING;
        } else {
            close_socket(fd);
            return -1;
        }
    }

    conn->fd = fd;
    conn->state = state;
    return 0;
}

// See tcp.h
int tcp_register_events(TCP *tcp, void **ptrs, struct pollfd *pfds, int cap)
{
    if (cap < tcp->num_conns+2)
        return -1;
    int ret = 0;

    if (tcp->tcp_listen_fd != INVALID_SOCKET) {
        if (tcp->num_conns < tcp->max_conns) {
            pfds[ret].fd = tcp->tcp_listen_fd;
            pfds[ret].events = POLLIN;
            pfds[ret].revents = 0;
            ptrs[ret] = NULL;
            ret++;
        }
    }

    if (tcp->tls_listen_fd != INVALID_SOCKET) {
        if (tcp->num_conns < tcp->max_conns) {
            pfds[ret].fd = tcp->tls_listen_fd;
            pfds[ret].events = POLLIN;
            pfds[ret].revents = 0;
            ptrs[ret] = NULL;
            ret++;
        }
    }

    for (int i=0, j=0; j < tcp->num_conns; i++) {

        TCP_Conn *conn = &tcp->conns[i];
        if (conn->state == TCP_CONN_STATE_FREE)
            continue;
        j++;

        int events = 0;

        if (conn->state == TCP_CONN_STATE_CONNECTING)
            events |= POLLOUT;

        if (tcp_conn_is_buffering(conn))
            events |= POLLIN;

        if (tcp_conn_needs_flushing(conn))
            events |= POLLOUT;

        if (events) {
            pfds[ret].fd = conn->fd;
            pfds[ret].events = events;
            pfds[ret].revents = 0;
            ptrs[ret] = conn;
            ret++;
        }
    }

    return ret;
}

static void
accept_incoming_conns(TCP *tcp, SOCKET listen_fd)
{
    int conn_idx = find_free_conn_struct(tcp);
    if (conn_idx < 0)
        return; // No space left
    TCP_Conn *conn = &tcp->conns[conn_idx];

    SOCKET new_fd = accept(listen_fd, NULL, NULL);
    if (new_fd == INVALID_SOCKET)
        return;

    if (set_socket_blocking(new_fd, false) < 0) {
        close_socket(new_fd);
        return;
    }

    bool secure = (listen_fd == tcp->tls_listen_fd);

    TCP_ConnState state;
    if (secure) {
        state = TCP_CONN_STATE_ACCEPTING;
    } else {
        state = TCP_CONN_STATE_ESTABLISHED;
    }

    tcp_conn_init(tcp, conn, secure, state, new_fd);

    if (!secure)
        conn->events |= TCP_EVENT_NEW;

    tcp->num_conns++;
}

static bool would_block(void)
{
#ifdef _WIN32
#ifdef QUAKEY_ENABLE_MOCKS
    assert(0); // TODO: The mock WSA function must use WSASetLastError
#endif
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EWOULDBLOCK
        || errno == EAGAIN
        || errno == EINTR;
#endif
}

// Returns true if the connection should be closed
static bool
read_from_net_into_conn(TCP_Conn *conn)
{
    bool defer_close = false;
    string buf = tcp_conn_write_buf(conn);
    int n = recv(conn->fd, (char*) buf.ptr, buf.len, 0);
    if (n == 0) {
        defer_close = true;
    } else if (n < 0) {
        if (!would_block())
            defer_close = true;
        n = 0;
    }
    int ret = tcp_conn_write_ack(conn, n);
    if (ret < 0)
        defer_close = true;
    conn->events |= TCP_EVENT_DATA;
    return defer_close;
}

// Returns true if the connection should be closed
static bool
write_from_conn_into_net(TCP_Conn *conn)
{
    bool defer_close = false;
    string buf = tcp_conn_read_buf(conn);
    int n = send(conn->fd, (char*) buf.ptr, buf.len, 0);
    if (n < 0) {
        if (!would_block())
            defer_close = true;
        n = 0;
    }
    tcp_conn_read_ack(conn, n);
    if (conn->closing && !tcp_conn_needs_flushing(conn))
        defer_close = true;
    return defer_close;
}

static void process_conn_events(TCP *tcp, TCP_Conn *conn, int revents)
{
    bool defer_close = false;
    bool defer_connect = false;
    switch (conn->state) {
    case TCP_CONN_STATE_CONNECTING:
        {
            if (revents & POLLOUT) {
                int err = 0;
                socklen_t len = sizeof(err);
                int gsret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len);
                if (gsret < 0) {
                    defer_connect = true;
                    break;
                }

                if (err) {
                    defer_connect = true;
                    break;
                }

                if (conn->flags & TCP_CONN_FLAG_SECURE) {
                    conn->state = TCP_CONN_STATE_HANDSHAKE;
                } else {
                    conn->state = TCP_CONN_STATE_ESTABLISHED;
                }
            }
        }
        break;
    case TCP_CONN_STATE_HANDSHAKE:
    case TCP_CONN_STATE_ACCEPTING:
#ifdef TLS_ENABLED
        {
            if (revents & POLLIN) {
                defer_close = read_from_net_into_conn(conn);
            }
            if (revents & POLLOUT) {
                defer_close = write_from_conn_into_net(conn);
            }
            int ret = tls_conn_handshake(&conn->tls);
            if (ret == -1) {
                defer_close = true;
                break;
            }

            if (ret == 1) {
                conn->state = TCP_CONN_STATE_ESTABLISHED;

                // Don't set the NEW flag if the connection was
                // started by us
                if (conn->num_addrs > 0) {
                    conn->events |= TCP_EVENT_NEW;
                }

                // Decrypt any application data already in the BIO
                for (;;) {
                    byte_queue_write_setmincap(&conn->input, MIN_RECV);
                    string buf = byte_queue_write_buf(&conn->input);
                    if (buf.ptr == NULL)
                        break;
                    int n = tls_conn_app_read(&conn->tls, (char*) buf.ptr, buf.len);
                    if (n <= 0) {
                        byte_queue_write_ack(&conn->input, 0);
                        break;
                    }
                    byte_queue_write_ack(&conn->input, n);
                    conn->events |= TCP_EVENT_DATA;
                }
            }
        }
#endif // TLS_ENABLED
        break;
    case TCP_CONN_STATE_ESTABLISHED:
        {
            if (revents & POLLIN) {
                defer_close = read_from_net_into_conn(conn);
            }
            if (revents & POLLOUT) {
                defer_close = write_from_conn_into_net(conn);
            }
        }
        break;
    case TCP_CONN_STATE_SHUTDOWN:
        {
            // TODO
        }
        break;
    default:
        UNREACHABLE;
    }

    if (defer_connect) {
        int ret = restart_connect(conn);
        if (ret < 0) {
            defer_close = true;
        }
    }

    if (defer_close) {

        close_socket(conn->fd);
        conn->fd = INVALID_SOCKET;
        conn->events |= TCP_EVENT_HUP;

        if (tcp_conn_free_maybe(conn)) {
            tcp->num_conns--;
        }
    }
}

// See tcp.h
void tcp_process_events(TCP *tcp, void **ptrs, struct pollfd *pfds, int num)
{
    for (int i = 0; i < num; i++) {
        if (pfds[i].fd == tcp->tcp_listen_fd ||
            pfds[i].fd == tcp->tls_listen_fd) {
            assert(ptrs[i] == NULL);
            if (pfds[i].revents & POLLIN) {
                accept_incoming_conns(tcp, pfds[i].fd);
            }
        } else {
            TCP_Conn *conn = ptrs[i];
            process_conn_events(tcp, conn, pfds[i].revents);
        }
    }
}

static bool
conn_to_event(TCP *tcp, TCP_Conn *conn, TCP_Event *event)
{
    if (!conn->events)
        return false;
    *event = (TCP_Event) {
        .flags = conn->events,
        .handle = conn_to_handle(tcp, conn),
    };
    conn->events = 0;
    return true;
}

// See tcp.h
bool tcp_next_event(TCP *tcp, TCP_Event *event)
{
    for (int i = 0, j = 0; j < tcp->num_conns; i++) {

        TCP_Conn *conn = &tcp->conns[i];
        if (conn->state == TCP_CONN_STATE_FREE)
            continue;
        j++;

        if (conn->flags & TCP_CONN_FLAG_CLOSED)
            continue; // User isn't interested in this connection anymore

        if (conn_to_event(tcp, conn, event))
            return true;
    }

    return false;
}

// See tcp.h
string tcp_read_buf(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return (string) {0};

    return byte_queue_read_buf(&conn->input);
}

// See tcp.h
void tcp_read_ack(TCP_Handle handle, int num)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_read_ack(&conn->input, num);
}

// See tcp.h
string tcp_write_buf(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return (string) {0};

    return byte_queue_write_buf(&conn->output);
}

// See tcp.h
void tcp_write_ack(TCP_Handle handle, int num)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_write_ack(&conn->output, num);
}

// See tcp.h
TCP_Offset tcp_write_off(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return 0;

    return byte_queue_offset(&conn->output);
}

// See tcp.h
void tcp_write(TCP_Handle handle, string data)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    while (data.len > 0) {
        byte_queue_write_setmincap(&conn->output, data.len);
        string buf = tcp_write_buf(handle);

        if (buf.len == 0)
            break; // Output buffer full or in error state

        int num = MIN(buf.len, data.len);
        memcpy(buf.ptr, data.ptr, num);

        tcp_write_ack(handle, num);
        data.ptr += num;
        data.len -= num;
    }
}

// See tcp.h
void tcp_patch(TCP_Handle handle, TCP_Offset offset, string data)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_patch(&conn->output, offset, data.ptr, data.len);
}

// See tcp.h
void tcp_clear_from_offset(TCP_Handle handle, TCP_Offset offset)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_remove_from_offset(&conn->output, offset);
}

// See tcp.h
void tcp_close(TCP_Handle handle)
{
    TCP *tcp = handle.tcp;
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    // Only free immediately if the user already called tcp_close
    // (CLOSED flag set). Otherwise, keep the connection alive so
    // tcp_next_event can deliver the HUP event to the user.
    conn->flags |= TCP_CONN_FLAG_CLOSED;
    tcp_conn_invalidate_handles(conn);
    if (tcp_conn_free_maybe(conn)) {
        tcp->num_conns--;
    }
}

// See tcp.h
void tcp_set_user_ptr(TCP_Handle handle, void *user_ptr)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    conn->user_ptr = user_ptr;
}

// See tcp.h
void *tcp_get_user_ptr(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return NULL;

    return conn->user_ptr;
}

// See tcp.h
void tcp_mark_ready(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    conn->events |= TCP_EVENT_DATA;
}