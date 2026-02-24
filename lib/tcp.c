#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>

#include "tcp.h"

#define MIN_RECV 4096

#ifdef _WIN32
typedef SOCKET NATIVE_SOCKET;
#else
typedef int NATIVE_SOCKET;
#endif

static void tcp_conn_free(TCP_Conn *conn);
static bool tcp_conn_free_maybe(TCP_Conn *conn);

static int set_socket_blocking(NATIVE_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
    return 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (value)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
    return 0;
#endif
}

static int create_listen_socket(string addr, uint16_t port,
    bool reuse_addr, int backlog)
{
#ifdef _WIN32
    // TODO: Only do this if socket creation fails due to
    //       winsock not being initialized, then try again
    //       with the socket
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    if (set_socket_blocking(fd, false) < 0) {
        close(fd);
        return -1;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        char copy[100];
        if (addr.len >= (int) sizeof(copy)) {
            close(fd);
            return -1;
        }
        memcpy(copy, addr.ptr, addr.len);
        copy[addr.len] = '\0';

        if (inet_pton(AF_INET, copy, &addr_buf) < 0) {
            close(fd);
            return -1;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int tcp_init(TCP *tcp, int max_conns)
{
    TCP_Conn *conns = malloc(max_conns * sizeof(TCP_Conn));
    if (conns == NULL)
        return -1;

    tcp->tls_listen_fd = -1;
    tcp->tcp_listen_fd = -1;
    tcp->num_conns = 0;
    tcp->max_conns = max_conns;
    tcp->conns = conns;

    for (int i = 0; i < tcp->max_conns; i++) {
        tcp->conns[i].state = TCP_CONN_STATE_FREE;
        tcp->conns[i].gen = 0;
    }

    return 0;
}

void tcp_free(TCP *tcp)
{
    for (int i = 0; i < tcp->max_conns; i++) {
        if (tcp->conns[i].state != TCP_CONN_STATE_FREE)
            tcp_conn_free(&tcp->conns[i]);
    }
    free(tcp->conns);

    if (tcp->tcp_listen_fd != -1)
        close(tcp->tcp_listen_fd);

#ifdef TLS_ENABLED
    if (tcp->tls_listen_fd != -1) {
        close(tcp->tls_listen_fd);
        tls_server_free(&tcp->tls);
    }
#endif
}

int tcp_listen_tcp(TCP *tcp, string addr, uint16_t port, bool reuse_addr, int backlog)
{
    if (tcp->tcp_listen_fd != -1)
        return -1;

    int fd = create_listen_socket(addr, port, reuse_addr, backlog);
    if (fd == -1)
        return -1;

    tcp->tcp_listen_fd = fd;
    return 0;
}

int tcp_listen_tls(TCP *tcp, string addr, uint16_t port, bool reuse_addr, int backlog)
{
#ifdef TLS_ENABLED
    if (tcp->tls_listen_fd != -1)
        return -1;

    int fd = create_listen_socket(addr, port, reuse_addr, backlog);
    if (fd == -1)
        return -1;

    tcp->tls_listen_fd = fd;
    return 0;
#else
    (void)tcp; (void)addr; (void)port; (void)reuse_addr; (void)backlog;
    return -1;
#endif
}

int tcp_add_cert(TCP *tcp, string cert_file, string key_file)
{
#ifdef TLS_ENABLED
    return tls_server_add_cert(&tcp->tls, S(""), cert_file, key_file);
#else
    (void)tcp; (void)cert_file; (void)key_file;
    return -1;
#endif
}

static void tcp_conn_init(TCP *tcp, TCP_Conn *conn, bool secure, TCP_ConnState state, int fd)
{
    conn->state = state;
    conn->flags = 0;
    conn->events = 0;
    conn->handled = false;
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
    (void)tcp;
    (void)secure;
#endif
}

static void tcp_conn_free(TCP_Conn *conn)
{
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);

#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        tls_conn_free(&conn->tls);
    }
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

static ByteView tcp_conn_write_buf(TCP_Conn *conn)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        int cap;
        char *ptr = tls_conn_net_write_buf(&conn->tls, &cap);
        if (ptr == NULL)
            return (ByteView) {0};
        return (ByteView) { (uint8_t*) ptr, cap };
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
            ByteView buf = byte_queue_write_buf(&conn->input);
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
        ByteView src = byte_queue_read_buf(&conn->output);
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

static ByteView tcp_conn_read_buf(TCP_Conn *conn)
{
#ifdef TLS_ENABLED
    if (conn->flags & TCP_CONN_FLAG_SECURE) {
        tcp_conn_tls_encrypt_output(conn);
        int n;
        char *ptr = tls_conn_net_read_buf(&conn->tls, &n);
        if (ptr == NULL)
            return (ByteView) {0};
        return (ByteView) { (uint8_t*) ptr, n };
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
    if (!conn->handled && conn->fd < 0) {
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

static int build_sockaddr(Address *addr, struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    if (!addr->is_ipv4)
        return -1; // Only IPv4 supported for now
    out->sin_family = AF_INET;
    out->sin_port = htons(addr->port);
    memcpy(&out->sin_addr, &addr->ipv4, sizeof(addr->ipv4));
    return 0;
}

int tcp_connect(TCP *tcp, bool secure, Address *addrs, int num_addrs)
{
    if (tcp->num_conns == tcp->max_conns)
        return -1;

    int i = 0;
    while (i < tcp->max_conns && tcp->conns[i].state != TCP_CONN_STATE_FREE)
        i++;
    assert(i < tcp->max_conns);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (set_socket_blocking(fd, false) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in sa;
    if (build_sockaddr(&addrs[0], &sa) < 0) {
        close(fd);
        return -1;
    }

    TCP_ConnState state;
    int ret = connect(fd, (struct sockaddr*) &sa, sizeof(sa));
    if (ret == 0) {
        if (secure) {
            state = TCP_CONN_STATE_HANDSHAKE;
        } else {
            state = TCP_CONN_STATE_ESTABLISHED;
        }
    } else {
        assert(ret < 0);
        if (errno == EINPROGRESS) {
            state = TCP_CONN_STATE_CONNECTING;
        } else {
            close(fd);
            return -1;
        }
    }

    tcp_conn_init(tcp, &tcp->conns[i], secure, state, fd);
    tcp_conn_set_addrs(&tcp->conns[i], addrs, num_addrs);
    tcp->num_conns++;
    return 0;
}

static int restart_connect(TCP_Conn *conn)
{
    close(conn->fd);
    conn->fd = -1;

    conn->addr_idx++;
    if (conn->addr_idx == conn->num_addrs) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (set_socket_blocking(fd, false) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in sa;
    if (build_sockaddr(&conn->addrs[conn->addr_idx], &sa) < 0) {
        close(fd);
        return -1;
    }

    TCP_ConnState state;
    int ret = connect(fd, (struct sockaddr*) &sa, sizeof(sa));
    if (ret == 0) {
        if (conn->flags & TCP_CONN_FLAG_SECURE) {
            state = TCP_CONN_STATE_HANDSHAKE;
        } else {
            state = TCP_CONN_STATE_ESTABLISHED;
        }
    } else {
        assert(ret < 0);
        if (errno == EINPROGRESS) {
            state = TCP_CONN_STATE_CONNECTING;
        } else {
            close(fd);
            return -1;
        }
    }

    conn->fd = fd;
    conn->state = state;
    return 0;
}

void tcp_process_events(TCP *tcp, void **ptrs, struct pollfd *arr, int num)
{
    for (int i = 0; i < num; i++) {
        if (arr[i].fd == tcp->tcp_listen_fd ||
            arr[i].fd == tcp->tls_listen_fd) {

            assert(ptrs[i] == NULL);

            if (arr[i].revents & POLLIN) {

                if (tcp->num_conns == tcp->max_conns)
                    continue;

                bool is_tls = false;
                if (arr[i].fd == tcp->tls_listen_fd)
                    is_tls = true;

                int new_fd = accept(arr[i].fd, NULL, NULL);
                if (new_fd == -1)
                    continue;

                if (set_socket_blocking(new_fd, false) < 0) {
                    close(new_fd);
                    continue;
                }

                // Find a free connection slot
                int slot = 0;
                while (slot < tcp->max_conns && tcp->conns[slot].state != TCP_CONN_STATE_FREE)
                    slot++;
                if (slot == tcp->max_conns) {
                    close(new_fd);
                    continue;
                }

                TCP_ConnState state;
                if (is_tls) {
                    state = TCP_CONN_STATE_ACCEPTING;
                } else {
                    state = TCP_CONN_STATE_ESTABLISHED;
                }

                TCP_Conn *conn = &tcp->conns[slot];
                tcp_conn_init(tcp, conn, is_tls, state, new_fd);
                if (!is_tls)
                    conn->events |= TCP_EVENT_NEW;
                tcp->num_conns++;
            }
        } else {

            TCP_Conn *conn = ptrs[i];

            bool defer_ready = false;
            bool defer_close = false;
            bool defer_connect = false;
            switch (conn->state) {
            case TCP_CONN_STATE_CONNECTING:
                {
                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0) {
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
                        conn->events |= TCP_EVENT_NEW;
                    }
                }
                break;
            case TCP_CONN_STATE_HANDSHAKE:
            case TCP_CONN_STATE_ACCEPTING:
                {
#ifdef TLS_ENABLED
                    if (arr[i].revents & POLLIN) {
                        int cap;
                        char *buf = tls_conn_net_write_buf(&conn->tls, &cap);
                        if (buf) {
                            int n = recv(conn->fd, buf, cap, 0);
                            if (n == 0) { defer_close = true; break; }
                            if (n < 0) {
                                if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                                    { defer_close = true; break; }
                                n = 0;
                            }
                            tls_conn_net_write_ack(&conn->tls, n);
                        }
                    }

                    int ret = tls_conn_handshake(&conn->tls);
                    if (ret == -1) {
                        defer_close = true;
                        break;
                    }

                    if (arr[i].revents & POLLOUT) {
                        int num;
                        char *buf = tls_conn_net_read_buf(&conn->tls, &num);
                        if (buf) {
                            int n = send(conn->fd, buf, num, 0);
                            if (n < 0) {
                                if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                                    { defer_close = true; break; }
                                n = 0;
                            }
                            tls_conn_net_read_ack(&conn->tls, n);
                        }
                    }

                    if (ret == 1) {
                        conn->state = TCP_CONN_STATE_ESTABLISHED;
                        conn->events |= TCP_EVENT_NEW;

                        // Decrypt any application data already in the BIO
                        for (;;) {
                            byte_queue_write_setmincap(&conn->input, MIN_RECV);
                            ByteView buf = byte_queue_write_buf(&conn->input);
                            if (!buf.ptr) break;
                            int n = tls_conn_app_read(&conn->tls, (char*) buf.ptr, buf.len);
                            if (n <= 0) { byte_queue_write_ack(&conn->input, 0); break; }
                            byte_queue_write_ack(&conn->input, n);
                            conn->events |= TCP_EVENT_DATA;
                        }
                    }
#else
                    defer_close = true;
#endif
                }
                break;
            case TCP_CONN_STATE_ESTABLISHED:
                {
                    if (arr[i].revents & POLLIN) {
                        ByteView buf = tcp_conn_write_buf(conn);
                        int n = recv(conn->fd, (char*) buf.ptr, buf.len, 0);
                        if (n == 0) {
                            defer_close = true;
                        } else {
                            if (n < 0) {
                                if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                                    defer_close = true;
                                n = 0;
                            }
                        }
                        int ret = tcp_conn_write_ack(conn, n);
                        if (ret < 0)
                            defer_close = true;
                        defer_ready = true;
                    }

                    if (arr[i].revents & POLLOUT) {
                        ByteView buf = tcp_conn_read_buf(conn);
                        int n = send(conn->fd, (char*) buf.ptr, buf.len, 0);
                        if (n < 0) {
                            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                                defer_close = true;
                            n = 0;
                        }
                        tcp_conn_read_ack(conn, n);
                        if (conn->closing && !tcp_conn_needs_flushing(conn))
                            defer_close = true;
                    }
                }
                break;
            case TCP_CONN_STATE_SHUTDOWN:
                {
                    // TLS shutdown — just close for now
                    defer_close = true;
                }
                break;
            default:
                break;
            }

            if (defer_connect) {
                int ret = restart_connect(conn);
                if (ret < 0) {
                    defer_close = true;
                }
            }

            if (defer_ready) {
                conn->events |= TCP_EVENT_DATA;
            }

            if (defer_close) {

                close(conn->fd);
                conn->fd = -1;
                conn->events |= TCP_EVENT_HUP;

                if (tcp_conn_free_maybe(conn)) {
                    tcp->num_conns--;
                }
            }
        }
    }
}

int tcp_register_events(TCP *tcp, void **ptrs, struct pollfd *arr, int cap)
{
    if (cap < tcp->num_conns+2)
        return -1;
    int ret = 0;

    if (tcp->tcp_listen_fd > -1) {
        if (tcp->num_conns < tcp->max_conns) {
            arr[ret].fd = tcp->tcp_listen_fd;
            arr[ret].events = POLLIN;
            arr[ret].revents = 0;
            ptrs[ret] = NULL;
            ret++;
        }
    }

    if (tcp->tls_listen_fd > -1) {
        if (tcp->num_conns < tcp->max_conns) {
            arr[ret].fd = tcp->tls_listen_fd;
            arr[ret].events = POLLIN;
            arr[ret].revents = 0;
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
            arr[ret].fd = conn->fd;
            arr[ret].events = events;
            arr[ret].revents = 0;
            ptrs[ret] = conn;
            ret++;
        }
    }

    return ret;
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

static bool conn_to_event(TCP *tcp, TCP_Conn *conn, TCP_Event *event)
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

ByteView tcp_read_buf(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return (ByteView) {0};

    return byte_queue_read_buf(&conn->input);
}

void tcp_read_ack(TCP_Handle handle, int num)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_read_ack(&conn->input, num);
}

ByteView tcp_write_buf(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return (ByteView) {0};

    return byte_queue_write_buf(&conn->output);
}

void tcp_write_ack(TCP_Handle handle, int num)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_write_ack(&conn->output, num);
}

TCP_Offset tcp_write_off(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return 0;

    return byte_queue_offset(&conn->output);
}

void tcp_write(TCP_Handle handle, string str)
{
    while (str.len > 0) {
        byte_queue_write_setmincap(&handle_to_conn(handle)->output, str.len);
        ByteView buf = tcp_write_buf(handle);
        int num = MIN(buf.len, str.len);
        memcpy(buf.ptr, str.ptr, num);
        tcp_write_ack(handle, num);
        str.ptr += num;
        str.len -= num;
    }
}

void tcp_patch(TCP_Handle handle, TCP_Offset offset, void *src, int len)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_patch(&conn->output, offset, src, len);
}

void tcp_clear_from_offset(TCP_Handle handle, TCP_Offset offset)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    byte_queue_remove_from_offset(&conn->output, offset);
}

void tcp_close(TCP_Handle handle)
{
    TCP *tcp = handle.tcp;
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    conn->flags |= TCP_CONN_FLAG_CLOSED;
    conn->handled = false;
    tcp_conn_invalidate_handles(conn);
    if (tcp_conn_free_maybe(conn)) {
        tcp->num_conns--;
    }
}

void tcp_set_user_ptr(TCP_Handle handle, void *ptr)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    conn->user_ptr = ptr;
}

void *tcp_get_user_ptr(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return NULL;

    return conn->user_ptr;
}

void tcp_mark_ready(TCP_Handle handle)
{
    TCP_Conn *conn = handle_to_conn(handle);
    if (conn == NULL)
        return;

    conn->events |= TCP_EVENT_DATA;
}
