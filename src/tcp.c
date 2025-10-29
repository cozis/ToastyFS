#include <assert.h>
#include <string.h>

#include "tcp.h"
#include "system.h"
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

static SOCKET create_listen_socket(char *addr, uint16_t port)
{
    SOCKET fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &bind_buf.sin_addr) != 1)
        return INVALID_SOCKET;

    if (sys_bind(fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)))
        return INVALID_SOCKET;

    int backlog = 32;
    if (sys_listen(fd, backlog) < 0)
        return INVALID_SOCKET;

    return fd;
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

void tcp_context_init(TCP *tcp)
{
    tcp->listen_fd = INVALID_SOCKET;
    tcp->num_conns = 0;
}

void tcp_context_free(TCP *tcp)
{
    if (tcp->listen_fd != INVALID_SOCKET)
        CLOSE_SOCKET(tcp->listen_fd);
}

int tcp_index_from_tag(TCP *tcp, int tag)
{
    for (int i = 0; i < tcp->num_conns; i++)
        if (tcp->conns[i].tag == tag)
            return i;
    return -1;
}

int tcp_listen(TCP *tcp, char *addr, uint16_t port)
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

    if (tcp->listen_fd != INVALID_SOCKET && tcp->num_conns < MAX_CONNS) {
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

    return 0;
}

// The "events" array must be an array of capacity MAX_CONNS+1
int tcp_translate_events(TCP *tcp, Event *events, void **contexts, struct pollfd *polled, int num_polled)
{
    bool removed[MAX_CONNS+1];

    int num_events = 0;
    for (int i = 0; i < num_polled; i++) {

        if (polled[i].fd == tcp->listen_fd) {

            SOCKET new_fd = sys_accept(tcp->listen_fd, NULL, NULL);
            if (new_fd != INVALID_SOCKET) {
                events[num_events++] = (Event) { EVENT_CONNECT, tcp->num_conns };
                conn_init(&tcp->conns[tcp->num_conns++], new_fd, false);
            }

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
                    if (sys_getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0)
                        defer_close = true;
                    else {
                        conn->connecting = false;
                        events[num_events++] = (Event) { EVENT_CONNECT, conn - tcp->conns };
                    }
                }

            } else {

                if (polled[i].revents & POLLIN) {
                    ByteView buf = byte_queue_write_buf(&conn->input);
                    int num = sys_recv(conn->fd, (char*) buf.ptr, buf.len, 0);
                    if (num == 0)
                        defer_close = true;
                    else if (num < 0) {
                        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                            defer_close = true;
                        num = 0;
                    }
                    byte_queue_write_ack(&conn->input, num);
                    ByteView msg = byte_queue_read_buf(&conn->input);
                    int ret = message_peek(msg, NULL, NULL);
                    if (ret < 0) {
                        // Invalid message
                        byte_queue_read_ack(&conn->input, 0);
                        defer_close = true;
                    } else if (ret == 0) {
                        // Still buffering
                        byte_queue_read_ack(&conn->input, 0);
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
                    int num = sys_send(conn->fd, (char*) buf.ptr, buf.len, 0);
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

            removed[i] = defer_close;
            if (0) {}
            else if (defer_close) events[num_events++] = (Event) { EVENT_DISCONNECT, conn - tcp->conns };
            else if (defer_ready) events[num_events++] = (Event) { EVENT_MESSAGE,    conn - tcp->conns };
        }
    }

    for (int i = 0; i < tcp->num_conns; i++)
        if (removed[i]) {
            conn_free(&tcp->conns[i]);
            tcp->conns[i] = tcp->conns[--tcp->num_conns];
        }
    return num_events;
}

ByteQueue *tcp_output_buffer(TCP *tcp, int conn_idx)
{
    return &tcp->conns[conn_idx].output;
}

int tcp_connect(TCP *tcp, Address addr, int tag, ByteQueue **output)
{
    if (tcp->num_conns == MAX_CONNS)
        return -1;
    int conn_idx = tcp->num_conns;

    SOCKET fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return -1;

    int ret;
    if (addr.is_ipv4) {
        struct sockaddr_in buf;
        buf.sin_family = AF_INET;
        buf.sin_port = htons(addr.port);
        memcpy(&buf.sin_addr, &addr.ipv4, sizeof(IPv4));
        ret = sys_connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    } else {
        struct sockaddr_in6 buf;
        buf.sin6_family = AF_INET6;
        buf.sin6_port = htons(addr.port);
        memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(IPv6));
        ret = sys_connect(fd, (struct sockaddr*) &buf, sizeof(buf));
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
}

void tcp_set_tag(TCP *tcp, int conn_idx, int tag)
{
    tcp->conns[conn_idx].tag = tag;
}

int tcp_get_tag(TCP *tcp, int conn_idx)
{
    return tcp->conns[conn_idx].tag;
}
