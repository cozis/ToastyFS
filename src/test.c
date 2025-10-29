#ifdef BUILD_TEST

#include <string.h>
#include <stdbool.h>
#include "system.h"
#include "chunk_server.h"
#include "metadata_server.h"
#include "byte_queue.h"

#define MAX_DESCRIPTORS 1024
#define MAX_PENDING_CONNECTIONS 128

typedef enum {
    DESCRIPTOR_TYPE_EMPTY,
    DESCRIPTOR_TYPE_FILE,
    DESCRIPTOR_TYPE_PRECONF_SOCKET,
    DESCRIPTOR_TYPE_LISTEN_SOCKET,
    DESCRIPTOR_TYPE_CONNECTION_SOCKET,
} DescriptorType;

typedef struct {

    DescriptorType type;

    // Socket fields
    struct sockaddr_in bind;
    bool no_bind;

    // Listen socket fields
    int backlog;
    int pending_connections[MAX_PENDING_CONNECTIONS];
    int num_pending;

    // Data socket fields
    int       peer_process;  // Index of the peer process (-1 if not connected)
    int       peer_fd;       // Descriptor in peer process
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
    while (fd < MAX_DESCRIPTORS && current_process->desc[fd].type != DESCRIPTOR_TYPE_EMPTY)
        fd++;

    if (fd >= MAX_DESCRIPTORS) {
        // TODO: errno
        return BAD_SOCKET;
    }

    current_process->desc[fd].type = DESCRIPTOR_TYPE_PRECONF_SOCKET;
    current_process->desc[fd].no_bind = true;
    current_process->desc[fd].num_pending = 0;
    current_process->desc[fd].peer_process = -1;
    current_process->desc[fd].peer_fd = -1;
    return fd;
}

int sys_bind(Socket fd, void *addr, size_t addr_len)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_PRECONF_SOCKET) {
        // TODO: errno
        return -1;
    }

    if (addr_len != sizeof(current_process->desc[fd].bind)) {
        // TODO: errno
        return -1;
    }

    // TODO: maybe check that no one else is listening
    //       on this port

    current_process->desc[fd].no_bind = false;
    memcpy(&current_process->desc[fd].bind, addr, addr_len);
    return 0;
}

int sys_listen(Socket fd, int backlog)
{
    if (current_process->desc[fd].type != DESCRIPTOR_TYPE_PRECONF_SOCKET) {
        // TODO: errno
        return -1;
    }

    current_process->desc[fd].type = DESCRIPTOR_TYPE_LISTEN_SOCKET;
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
            if (!byte_queue_empty(&current_process->desc[fd].input))
                polled[i].revents |= POLLIN;
        }

        if (polled[i].events & POLLOUT) {
            if (!byte_queue_full(&current_process->desc[fd].output))
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

    if (current_process->desc[fd].num_pending == 0) {
        // No pending connections - would block in real system
        // TODO: errno (EAGAIN/EWOULDBLOCK)
        return BAD_SOCKET;
    }

    // Get the first pending connection descriptor
    Socket new_fd = current_process->desc[fd].pending_connections[0];

    // Remove from pending queue
    current_process->desc[fd].num_pending--;
    for (int i = 0; i < current_process->desc[fd].num_pending; i++) {
        current_process->desc[fd].pending_connections[i] =
            current_process->desc[fd].pending_connections[i + 1];
    }

    // Fill in peer address if requested
    if (addr != NULL && addr_len != NULL) {
        int peer_process = current_process->desc[new_fd].peer_process;
        int peer_fd = current_process->desc[new_fd].peer_fd;
        if (peer_process > -1 && peer_fd > -1) {
            struct sockaddr_in *peer_addr = (struct sockaddr_in *)addr;
            *peer_addr = processes[peer_process].desc[peer_fd].bind;
            *addr_len = sizeof(struct sockaddr_in);
        }
    }

    return new_fd;
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
            if (optlen == NULL || *optlen < sizeof(int)) {
                // TODO: errno
                return -1;
            }

            if (optval == NULL) {
                // TODO: errno
                return -1;
            }

            // In our simulation, all connections succeed immediately
            // and we don't track socket errors, so always return 0
            *(int *)optval = 0;
            *optlen = sizeof(int);
            return 0;
        }

        default:
        // Unsupported socket option
        // TODO: errno (ENOPROTOOPT)
        return -1;
    }
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

    ByteQueue *input = &current_process->desc[fd].input;
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

    ByteQueue *output = &current_process->desc[fd].output;
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

    if (addr_len != sizeof(struct sockaddr_in)) {
        // TODO: errno
        return -1;
    }

    struct sockaddr_in *target_addr = (struct sockaddr_in *)addr;

    // Find the process with a listen socket on this address
    int target_process_idx = -1;
    Socket target_listen_fd = BAD_SOCKET;

    for (int i = 0; i < num_processes; i++) {
        for (int j = 0; j < MAX_DESCRIPTORS; j++) {
            Descriptor *desc = &processes[i].desc[j];
            if (desc->type == DESCRIPTOR_TYPE_LISTEN_SOCKET && !desc->no_bind) {
                if (desc->bind.sin_port == target_addr->sin_port &&
                    (desc->bind.sin_addr.s_addr == target_addr->sin_addr.s_addr ||
                     desc->bind.sin_addr.s_addr == INADDR_ANY)) {
                    target_process_idx = i;
                    target_listen_fd = j;
                    goto found;
                }
            }
        }
    }

found:
    if (target_process_idx < 0) {
        // No listener found - connection refused
        // TODO: errno (ECONNREFUSED)
        return -1;
    }

    // Create a new socket in the target process for the accepted connection
    Socket accept_fd = 0;
    while (accept_fd < MAX_DESCRIPTORS &&
           processes[target_process_idx].desc[accept_fd].type != DESCRIPTOR_TYPE_EMPTY)
        accept_fd++;

    if (accept_fd >= MAX_DESCRIPTORS) {
        // TODO: errno
        return -1;
    }

    // Check if pending queue is full
    if (processes[target_process_idx].desc[target_listen_fd].num_pending >= MAX_PENDING_CONNECTIONS) {
        // TODO: errno (ECONNREFUSED or EAGAIN)
        return -1;
    }

    // Initialize byte queues for both ends of the connection
    byte_queue_init(&current_process->desc[fd].input, 1<<16);
    byte_queue_init(&current_process->desc[fd].output, 1<<16);
    byte_queue_init(&processes[target_process_idx].desc[accept_fd].input, 1<<16);
    byte_queue_init(&processes[target_process_idx].desc[accept_fd].output, 1<<16);

    // Set up the client socket
    current_process->desc[fd].type = DESCRIPTOR_TYPE_CONNECTION_SOCKET;
    int current_process_idx = current_process - processes;
    current_process->desc[fd].peer_process = target_process_idx;
    current_process->desc[fd].peer_fd = accept_fd;

    // Set up the accepted socket
    processes[target_process_idx].desc[accept_fd].type = DESCRIPTOR_TYPE_CONNECTION_SOCKET;
    processes[target_process_idx].desc[accept_fd].no_bind = false;
    processes[target_process_idx].desc[accept_fd].bind = *target_addr;
    processes[target_process_idx].desc[accept_fd].peer_process = current_process_idx;
    processes[target_process_idx].desc[accept_fd].peer_fd = fd;
    processes[target_process_idx].desc[accept_fd].num_pending = 0;

    // Add to pending connections queue
    processes[target_process_idx].desc[target_listen_fd].pending_connections[
        processes[target_process_idx].desc[target_listen_fd].num_pending++] = accept_fd;

    // Connection succeeds immediately in simulation (no EINPROGRESS needed)
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
        // Step each process
        for (int i = 0; i < num_processes; i++) {

            current_process = &processes[i];

            int ret;
            if (i == 0) ret = metadata_server_step(&metadata_server);
            else        ret = chunk_server_step(&chunk_servers[i-1]);

            if (ret) {
                // TODO: handle error
            }
        }

        // Process network transit: move data from output queues to peer input queues
        for (int i = 0; i < num_processes; i++) {
            for (int fd = 0; fd < MAX_DESCRIPTORS; fd++) {
                Descriptor *desc = &processes[i].desc[fd];

                if (desc->type != DESCRIPTOR_TYPE_CONNECTION_SOCKET)
                    continue;

                if (desc->peer_process < 0 || desc->peer_fd < 0)
                    continue;

                // Get peer descriptor
                Descriptor *peer = &processes[desc->peer_process].desc[desc->peer_fd];

                // Transfer data from this socket's output to peer's input
                ByteView output_data = byte_queue_read_buf(&desc->output);
                if (output_data.len > 0) {
                    // Get available space in peer's input queue
                    ByteView peer_input_space = byte_queue_write_buf(&peer->input);

                    // Transfer as much as possible
                    size_t transfer_size = output_data.len;
                    if (transfer_size > peer_input_space.len)
                        transfer_size = peer_input_space.len;

                    if (transfer_size > 0) {
                        memcpy(peer_input_space.ptr, output_data.ptr, transfer_size);
                        byte_queue_write_ack(&peer->input, transfer_size);
                        byte_queue_read_ack(&desc->output, transfer_size);
                    }
                }
            }
        }
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
