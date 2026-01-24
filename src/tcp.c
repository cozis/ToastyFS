
#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>

#include "tcp.h"
#include "message.h"

bool addr_eql(Address a, Address b)
{
    if (a.is_ipv4 != b.is_ipv4)
        return false;

    if (a.port != b.port)
        return false;

    if (a.is_ipv4) {
        if (memcmp(&a.ipv4, &b.ipv4, sizeof(a.ipv4)))
            return false;
    } else {
        if (memcmp(&a.ipv6, &b.ipv6, sizeof(a.ipv6)))
            return false;
    }

    return true;
}

static int set_socket_blocking(SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
#endif

    return 0;
}

static SOCKET create_listen_socket(string addr, uint16_t port)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (set_socket_blocking(fd, false) < 0) {
        CLOSE_SOCKET(fd);
        return INVALID_SOCKET;
    }

    // TODO: mark address as reusable in debug builds

    char tmp[1<<10];
    if (addr.len >= (int) sizeof(tmp)) {
        CLOSE_SOCKET(fd);
        return INVALID_SOCKET;
    }
    memcpy(tmp, addr.ptr, addr.len);
    tmp[addr.len] = '\0';

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_port   = htons(port);
    if (inet_pton(AF_INET, tmp, &bind_buf.sin_addr) != 1) {
        CLOSE_SOCKET(fd);
        return INVALID_SOCKET;
    }

    if (bind(fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf))) {
        CLOSE_SOCKET(fd);
        return INVALID_SOCKET;
    }

    int backlog = 32;
    if (listen(fd, backlog) < 0) {
        CLOSE_SOCKET(fd);
        return INVALID_SOCKET;
    }

    return fd;
}

static int create_socket_pair(SOCKET *a, SOCKET *b)
{
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
        return -1;

    // Bind to loopback address with port 0 (dynamic port assignment)
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = 0; // Let system choose port

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    *a = sock;
    *b = sock;

    // Optional: Set socket to non-blocking mode
    // This prevents send() from blocking if the receive buffer is full
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode); // TODO: does this fail?
    return 0;
#else
    int fds[2];
    if (pipe(fds) < 0)
        return -1;
    *a = fds[0];
    *b = fds[1];
    return 0;
#endif
}

static void close_socket_pair(SOCKET a, SOCKET b)
{
#ifdef _WIN32
    closesocket(a);
    (void) b;
#else
    close(a);
    close(b);
#endif
}

static void conn_init(Connection *conn, SOCKET fd, bool connecting)
{
    conn->fd = fd;
    conn->tag = -1;
    conn->connecting = connecting;
    conn->closing = false;
    conn->msglen = 0;
    byte_queue_init(&conn->input, 1<<20);
    byte_queue_init(&conn->output, 1<<20);
}

static void conn_free(Connection *conn)
{
    CLOSE_SOCKET(conn->fd);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
}

static int conn_events(Connection *conn)
{
    int events = 0;

    if (conn->connecting)
        events |= POLLOUT;
    else {

        assert(!byte_queue_full(&conn->input));
        if (!conn->closing)
            events |= POLLIN;

        if (!byte_queue_empty(&conn->output))
            events |= POLLOUT;
    }
    return events;
}

int tcp_context_init(TCP *tcp)
{
    tcp->listen_fd = INVALID_SOCKET;
    tcp->num_conns = 0;

    if (create_socket_pair(&tcp->wait_fd, &tcp->signal_fd) < 0)
        return -1;

    return 0;
}

void tcp_context_free(TCP *tcp)
{
    // Free all connection byte queues without closing sockets
    // (sockets are managed by the simulation and will be cleaned up separately)
    for (int i = 0; i < tcp->num_conns; i++) {
        byte_queue_free(&tcp->conns[i].input);
        byte_queue_free(&tcp->conns[i].output);
    }
    tcp->num_conns = 0;

    if (tcp->listen_fd != INVALID_SOCKET)
        CLOSE_SOCKET(tcp->listen_fd);

    close_socket_pair(tcp->wait_fd, tcp->signal_fd);
}

int tcp_wakeup(TCP *tcp)
{
    send(tcp->signal_fd, "0", 1, 0); // TODO: Handle error
    return 0;
}

int tcp_index_from_tag(TCP *tcp, int tag)
{
    for (int i = 0; i < tcp->num_conns; i++)
        if (tcp->conns[i].tag == tag)
            return i;
    return -1;
}

int tcp_listen(TCP *tcp, string addr, uint16_t port)
{
    SOCKET listen_fd = create_listen_socket(addr, port);
    if (listen_fd == INVALID_SOCKET)
        return -1;

    tcp->listen_fd = listen_fd;
    return 0;
}

int tcp_next_message(TCP *tcp, int conn_idx, ByteView *msg, uint16_t *type)
{
    *msg = byte_queue_read_buf(&tcp->conns[conn_idx].input);

    uint32_t len;
    int ret = message_peek(*msg, type, &len);

    // Invalid message?
    if (ret < 0) {
        byte_queue_read_ack(&tcp->conns[conn_idx].input, 0);
        return -1;
    }

    // Still buffering header?
    if (ret == 0) {
        byte_queue_read_ack(&tcp->conns[conn_idx].input, 0);
        if (byte_queue_full(&tcp->conns[conn_idx].input))
            return -1;
        return 0;
    }

    // Message received
    assert(ret > 0);
    msg->len = len;
    tcp->conns[conn_idx].msglen = len;

    return 1;
}

void tcp_consume_message(TCP *tcp, int conn_idx)
{
    byte_queue_read_ack(&tcp->conns[conn_idx].input, tcp->conns[conn_idx].msglen);
    tcp->conns[conn_idx].msglen = 0;
}

int tcp_register_events(TCP *tcp, void **contexts, struct pollfd *polled)
{
    int num_polled = 0;

    polled[num_polled].fd = tcp->wait_fd;
    polled[num_polled].events = POLLIN;
    polled[num_polled].revents = 0;
    contexts[num_polled] = NULL;
    num_polled++;

    if (tcp->listen_fd != INVALID_SOCKET && tcp->num_conns < TCP_CONNECTION_LIMIT) {
        polled[num_polled].fd = tcp->listen_fd;
        polled[num_polled].events = POLLIN;
        polled[num_polled].revents = 0;
        contexts[num_polled] = NULL;
        num_polled++;
    }

    for (int i = 0; i < tcp->num_conns; i++) {
        int events = conn_events(&tcp->conns[i]);
        if (events) {
            polled[num_polled].fd = tcp->conns[i].fd;
            polled[num_polled].events = events;
            polled[num_polled].revents = 0;
            contexts[num_polled] = &tcp->conns[i];
            num_polled++;
        }
    }

    return num_polled;
}

// The "events" array must be an array of capacity TCP_EVENT_CAPACITY,
// while "contexts" and "polled" must have capacity TCP_POLL_CAPACITY.
int tcp_translate_events(TCP *tcp, Event *events, void **contexts, struct pollfd *polled, int num_polled)
{
    bool removed[TCP_POLL_CAPACITY];
    for (int i = 0; i < TCP_POLL_CAPACITY; i++)
        removed[i] = false;

    int num_events = 0;
    for (int i = 1; i < num_polled; i++) {

        if (polled[i].fd == tcp->wait_fd) {

            char buf[100];
            recv(tcp->wait_fd, buf, sizeof(buf), 0); // TODO: Make sure all bytes are consumed
            events[num_events++] = (Event) { EVENT_WAKEUP, -1, -1 };

        } else if (polled[i].fd == tcp->listen_fd) {

            assert(contexts[i] == NULL);

            if (polled[i].revents & POLLIN) {
                SOCKET new_fd = accept(tcp->listen_fd, NULL, NULL);
                if (new_fd != INVALID_SOCKET) {

                    if (set_socket_blocking(new_fd, false) < 0)
                        CLOSE_SOCKET(new_fd);
                    else {
                        conn_init(&tcp->conns[tcp->num_conns++], new_fd, false);
                        events[num_events++] = (Event) { EVENT_CONNECT, tcp->num_conns-1, tcp->conns[tcp->num_conns-1].tag };
                    }
                }
            }
            removed[i] = false;

        } else {

            Connection *conn = contexts[i];
            bool defer_close = false;
            bool defer_ready = false;

            if (conn->connecting) {

                // Check for error conditions on the socket
                if (polled[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    defer_close = true;
                } else if (polled[i].revents & POLLOUT) {

                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0)
                        defer_close = true;
                    else {
                        conn->connecting = false;
                        events[num_events++] = (Event) { EVENT_CONNECT, conn - tcp->conns, conn->tag };
                    }
                }

            } else {

                if (polled[i].revents & POLLIN) {
                    byte_queue_write_setmincap(&conn->input, 1<<9);
                    ByteView buf = byte_queue_write_buf(&conn->input);
                    int num = recv(conn->fd, (char*) buf.ptr, buf.len, 0);
                    if (num == 0)
                        defer_close = true;
                    else if (num < 0) {
                        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) // TODO: does Windows return these error codes or not?
                            defer_close = true;
                        num = 0;
                    }
                    byte_queue_write_ack(&conn->input, num);
                    ByteView msg = byte_queue_read_buf(&conn->input);
                    int ret = message_peek(msg, NULL, NULL);
                    byte_queue_read_ack(&conn->input, 0);
                    if (ret < 0) {
                        // Invalid message
                        defer_close = true;
                    } else if (ret == 0) {
                        // Still buffering
                        if (byte_queue_full(&conn->input))
                            defer_close = true;
                    } else {
                        // Message received
                        assert(ret > 0);
                        defer_ready = true;
                    }
                }

                if (polled[i].revents & POLLOUT) {
                    ByteView buf = byte_queue_read_buf(&conn->output);
                    int num = send(conn->fd, (char*) buf.ptr, buf.len, 0);
                    if (num < 0) {
                        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                            defer_close = true;
                        num = 0;
                    }
                    byte_queue_read_ack(&conn->output, num);
                    if (conn->closing && byte_queue_empty(&conn->output))
                        defer_close = true;
                }
            }

            // TODO: byte_queue_error here?

            removed[i] = defer_close;
            if (0) {}
            else if (defer_close) events[num_events++] = (Event) { EVENT_DISCONNECT, conn - tcp->conns, conn->tag };
            else if (defer_ready) events[num_events++] = (Event) { EVENT_MESSAGE,    conn - tcp->conns, conn->tag };
        }
    }

    for (int i = 1; i < num_polled; i++) {
        if (removed[i]) {
            Connection *conn = contexts[i];
            assert(conn);
            conn_free(conn);
            *conn = tcp->conns[--tcp->num_conns];
        }
    }

    return num_events;
}

ByteQueue *tcp_output_buffer(TCP *tcp, int conn_idx)
{
    return &tcp->conns[conn_idx].output;
}

int tcp_connect(TCP *tcp, Address addr, int tag, ByteQueue **output)
{
    if (tcp->num_conns == TCP_CONNECTION_LIMIT)
        return -1;
    int conn_idx = tcp->num_conns;

    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return -1;

    if (set_socket_blocking(fd, false) < 0) {
        CLOSE_SOCKET(fd);
        return -1;
    }

    int ret;
    if (addr.is_ipv4) {
        struct sockaddr_in buf;
        buf.sin_family = AF_INET;
        buf.sin_port = htons(addr.port);
        memcpy(&buf.sin_addr, &addr.ipv4, sizeof(IPv4));
        ret = connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    } else {
        struct sockaddr_in6 buf;
        buf.sin6_family = AF_INET6;
        buf.sin6_port = htons(addr.port);
        memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(IPv6));
        ret = connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    }

    bool connecting;
    if (ret == 0) {
        connecting = false;
    } else {
        if (errno != EINPROGRESS) {
            CLOSE_SOCKET(fd);
            return -1;
        }
        connecting = true;
    }

    // Check that this tag wasn't already used
    for (int i = 0; i < tcp->num_conns; i++)
        assert(tcp->conns[i].tag != tag);

    conn_init(&tcp->conns[conn_idx], fd, connecting);
    tcp->conns[conn_idx].tag = tag;

    if (output)
        *output = &tcp->conns[conn_idx].output;

    tcp->num_conns++;
    return 0;
}

void tcp_close(TCP *tcp, int conn_idx)
{
    tcp->conns[conn_idx].closing = true;
    // TODO: if no event will be triggered, the connection will not be closed
    //       if the output buffer is empty, the connection should be closed here.
}

void tcp_set_tag(TCP *tcp, int conn_idx, int tag, bool unique)
{
    assert(tag != -1);

    if (unique) {
        for (int i = 0; i < tcp->num_conns; i++)
            assert(tcp->conns[i].tag != tag);
    }

    tcp->conns[conn_idx].tag = tag;
}

int tcp_get_tag(TCP *tcp, int conn_idx)
{
    return tcp->conns[conn_idx].tag;
}
