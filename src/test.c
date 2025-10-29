#ifdef BUILD_TEST

#include "system.h"
#include "chunk_server.h"
#include "metadata_server.h"

#define MAX_DESCRIPTORS 1024

typedef enum {
    DESCRIPTOR_TYPE_EMPTY,
    DESCRIPTOR_TYPE_FILE,
    DESCRIPTOR_TYPE_PRECONF_SOCKET,
    DESCRIPTOR_TYPE_LISTEN_SOCKET,
    DESCRIPTOR_TYPE_CONNECTION_SOCKET,
} DescriptorType;

typedef struct {
} DescriptorFile;

typedef struct {

    // Generic fields
    struct sockaddr_in bind;
    bool no_bind;
    bool is_listen;

    // Listen socket
    int backlog;

    // Data socket
    ByteQueue input;
    ByteQueue output;

} DescriptorSocket;

typedef struct {

    DescriptorType type;

    // Socket fields
    struct sockaddr_in bind;
    bool no_bind;

    // Listen socket fields
    int backlog;

    // Data socket fields
    ByteQueue input;
    ByteQueue output;

} Descriptor;

typedef struct {
    int num_desc;
    Descriptor desc[MAX_DESCRIPTORS];
} Process;

#define MAX_PROCESSES (MAX_CHUNK_SERVERS + 1)

MetadataServer metadata_server;

int num_chunk_servers = 0;
ChunkServer chunk_servers[MAX_CHUNK_SERVERS];

int num_processes = 0;
Process processes[MAX_PROCESSES];
Process *current_process;

Socket sys_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET) {
        // TODO: errno
        return BAD_SOCKET;
    }

    if (type != SOCK_STREAM) {
        // TODO: errno
        return BAD_SOCKET;
    }

    if (protocol != 0) {
        // TODO: errno
        return BAD_SOCKET;
    }

    if (num_processes == MAX_PROCESSES) {
        // TODO: errno
        return BAD_SOCKET;
    }

    Socket fd = 0;
    while (current_process->desc[fd].type != DESCRIPTOR_TYPE_EMPTY)
        fd++;

    current_process->desc[fd].type = DESCRIPTOR_TYPE_PRECONF_SOCKET;
    current_process->desc[fd].no_bind = true;
    return fd;
}

int sys_bind(Socket fd, void *addr, size_t addr_len)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_SOCKET) {
        // TODO: errno
        return -1;
    }

    if (addr_len != sizeof(current_process->desc[fd].sock.bind)) {
        // TODO: errno
        return -1;
    }

    // TODO: maybe check that no one else is listening
    //       on this port

    current_process->desc[fd].no_bind = false;
    memcpy(&current_process[fd].desc[fd].bind, addr, addr_len);
    return 0;
}

int sys_listen(Socket fd, int backlog)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_SOCKET) {
        // TODO: errno
        return -1;
    }

    current_process->desc[fd].type = DESCRIPTOR_TYPE_LISTEN-SOCKET;
    current_process->desc[fd].backlog = backlog;
    return 0;
}

int sys_closesocket(Socket fd)
{
    current_process->desc[fd].type = DESCRIPTOR_TYPE_EMPTY;
    return 0;
}

int sys_poll(struct pollfd *polled, int num_polled, int timeout)
{
    int num = 0;
    for (int i = 0; i < num_polled; i++) {

        polled[i].revents = 0;

        Socket fd = polled[i].fd;
        if (fd < 0)
            continue;

        if (polled[i].events & POLLNVAL) {
            // TODO
        }

        if (polled[i].events & POLLERR) {
            // TODO
        }

        if (polled[i].events & POLLHUP) {
            // TODO
        }

        if (polled[i].events & POLLIN) {
            if (!byte_queue_empty(&current_process->desc[fd].data_socket.input))
                polled[i].revents |= POLLIN;
        }

        if (polled[i].events & POLLOUT) {
            if (!byte_queue_full(&current_process->desc[fd].data_socket.output))
                polled[i].revents |= POLLOUT;
        }

        if (polled[i].revents)
            num++;
    }

    return num;
}

Socket sys_accept(Socket fd, void *addr, int *addr_len)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_LISTEN_SOCKET) {
        // TODO: errno
        return BAD_SOCKET;
    }

    // TODO
}

int sys_getsockopt(Socket fd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (level != SOL_SOCKET) {
        // TODO: errno
        return -1;
    }

    switch (optname) {

        case SO_ERROR:
        {
            if (optlen == NULL || *optlen != sizeof(int)) {
                // TODO: errno
                return -1;
            }

            // TODO
        }
        break;

        default:
        // TODO
        break;
    }

    // TODO
}

int sys_setsockopt(Socket fd, int level, int optname, void *optval, socklen_t optlen)
{
    // TODO: errno
    return -1;
}

int sys_recv(Socket fd, void *dst, int len, int flags)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_CONNECTION_SOCKET) {
        // TODO: errno
        return -1;
    }

    ByteQueue *input = &current_process->desc[fd].data_socket.input;
    ByteView buf = byte_queue_read_buf(input);
    if (buf.len > len)
        buf.len = len;
    memcpy(dst, buf.ptr, buf.len);
    byte_queue_read_ack(input, buf.len);

    return buf.len;
}

int sys_send(Socket fd, void *src, int len, int flags)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_CONNECTION_SOCKET) {
        // TODO: errno
        return -1;
    }

    ByteQueue *output = &current_process->desc[fd].data_socket.output;
    ByteView buf = byte_queue_write_buf(output);
    if (buf.len > len)
        buf.len = len;
    memcpy(buf.ptr, src, buf.len);
    byte_queue_write_ack(output, buf.len);

    return buf.len;
}

int sys_connect(Socket fd, void *addr, size_t addr_len)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_PRECONF_SOCKET) {
        // TODO: errno
        return -1;
    }

    current_process->desc[fd].type = DESCRIPTOR_TYPE_CONNECTION_SOCKET;

    // TODO

    errno = EINPROGRESS;
    return 0;
}

int main(void)
{
    num_processes = 8;

    if (num_processes == 0) {
        // TODO
        return -1;
    }

    current_process = &processes[0];
    int ret = metadata_server_init(&metadata_server, 0, NULL);
    if (ret) {
        // TODO
        return -1;
    }

    for (int i = 0; i < num_processes-1; i++) {
        current_process = &processes[i+1];
        ret = chunk_server_init(&chunk_servers[i], 0, NULL);
        if (ret) {
            // TODO
            return -1;
        }
    }

    for (;;) {
        for (int i = 0; i < num_processes; i++) {

            current_process = &processes[i];

            int ret;
            if (i == 0) ret = metadata_server_step(&metadata_server);
            else        ret = chunk_server_step(&chunk_servers[i-1]);

            if (ret) {
                // TODO
            }
        }

        // TODO: process network transit
    }

    for (int i = 0; i < num_processes-1; i++) {
        ret = chunk_server_free(&chunk_servers[i]);
        if (ret) {
            // TODO
            return -1;
        }
    }

    ret = metadata_server_free(&metadata_server);
    if (ret) {
        // TODO
        return -1;
    }

    return 0;
}

#endif // BUILD_TEST
