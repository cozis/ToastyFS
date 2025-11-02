#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "system.h"
#include "chunk_server.h"
#include "metadata_server.h"

#ifdef _WIN32
#define NATIVE_HANDLE HANDLE
#else
#define NATIVE_HANDLE int
#endif

#define MAX_DESCRIPTORS 1024
#define MAX_ALLOCATIONS  128
#define MAX_PROCESSES     32

#define DATA_QUEUE_SIZE (1<<9)

typedef struct Process Process;

typedef enum {
    DESC_EMPTY,
    DESC_FILE,
    DESC_SOCKET,
    DESC_LISTEN_SOCKET,
    DESC_CONNECTION_SOCKET,
} DescriptorType;

typedef enum {
    DESC_ADDR_VOID,
    DESC_ADDR_IPV4,
    DESC_ADDR_IPV6,
} DescriptorAddressType;

typedef struct {
    DescriptorAddressType type;
    union {
        struct sockaddr_in  ipv4;
        struct sockaddr_in6 ipv6;
    };
} DescriptorAddress;

typedef struct {
    Process *process;
    int descriptor_index;
    uint32_t generation;
} DescriptorHandle;

typedef struct {
    int head;
    int used;
    int size;
    DescriptorHandle *items;
} AcceptQueue;

typedef struct {
    int   size;
    int   used;
    char *data;
} DataQueue;

typedef enum {
    CONNECTION_DELAYED,
    CONNECTION_QUEUED,
    CONNECTION_ESTABLISHED,
    CONNECTION_FAILED,
} ConnectionState;

typedef struct {

    // ------ Common ----------------

    DescriptorType type;
    uint32_t generation;

    // ------ File ------------------

    NATIVE_HANDLE real_fd;

    // ------ Socket ----------------

    // Events reported by the last "poll" call
    // for this descriptor
    int events;

    // Events triggered since the last "poll"
    // call. Note that these may include events
    // not present in the "events" set.
    int revents;

    // Context for this descriptor, set by the
    // last "poll" call.
    void *context;

    // Address bound to this descriptor by the
    // "bind" call.
    DescriptorAddress address;

    // ------ Listen socket ---------

    AcceptQueue accept_queue;

    // ------ Connection socket -----

    ConnectionState connection_state;

    // When QUEUED, this refers to the peer listener
    // socket. When ESTABLISHED, this refers to the
    // peer connection socket.
    DescriptorHandle connection_peer;

    // Address of the last connect() call
    // on this socket if it's still in the
    // "DELAYED" state.
    DescriptorAddress connect_address;

    // Data written to this descriptor using "write"
    // or "send".
    DataQueue output_data;

    // ------------------------------

} Descriptor;

typedef struct {
    void  *ptr;
    size_t len;
    char  *file;
    int    line;
} Allocation;

struct Process {

    int num_desc;
    Descriptor desc[MAX_DESCRIPTORS];

    int num_allocs;
    Allocation allocs[MAX_ALLOCATIONS];

    bool leader;
    union {
        ChunkServer    chunk_server;
        MetadataServer metadata_server;
    };
};

static int num_processes = 0;
static Process *processes[MAX_PROCESSES];
static Process *current_process = NULL;

static void process_poll_array(Process *process,
    void **contexts, struct pollfd *polled, int num_polled)
{
    for (int i = 0, j = 0; j < process->num_desc; i++) {

        Descriptor *desc = &process->desc[i];
        if (desc->type == DESC_EMPTY)
            continue;
        j++;

        desc->events = 0;
        desc->revents = 0;
        desc->context = NULL;
    }

    for (int i = 0; i < num_polled; i++) {

        SOCKET fd = polled[i].fd;
        if (fd == INVALID_SOCKET)
            continue;

        int idx = (int) fd;
        process->desc[idx].events = polled[i].events;
        process->desc[idx].revents = 0;
        process->desc[idx].context = contexts[i];
    }
}

static bool is_leader(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp("--leader", argv[i]) || !strcmp("-l", argv[i]))
            return true;
    return false;
}

#define MAX_ARGS 128

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

int spawn_simulated_process(char *args)
{
    if (num_processes == MAX_PROCESSES)
        return -1;

    char mem[1<<10];
    int args_len = strlen(args);
    if (args_len >= (int) sizeof(mem))
        return -1;
    memcpy(mem, args, args_len);
    mem[args_len] = '\0';

    int argc = 0;
    char *argv[MAX_ARGS];
    for (int cur = 0;;) {

        while (cur < args_len && is_space(args[cur]))
            cur++;

        if (cur == args_len || argc == MAX_ARGS)
            break;

        argv[argc++] = args + cur;

        while (cur < args_len && !is_space(args[cur]))
            cur++;

        args[cur] = '\0';
        if (cur < args_len)
            cur++;
    }

    bool leader = is_leader(argc, argv);

    Process *process = malloc(sizeof(Process));
    if (process == NULL)
        return -1;

    process->leader = leader;
    process->num_desc = 0;
    process->num_allocs = 0;

    void *contexts[MAX_CONNS+1];
    struct pollfd polled[MAX_CONNS+1];
    int num_polled;

    if (leader) {
        num_polled = metadata_server_init(&process->metadata_server, argc, argv, contexts, polled);
    } else {
        num_polled = chunk_server_init(&process->chunk_server, argc, argv, contexts, polled);
    }
    if (num_polled < 0) {
        // TODO
    }

    process_poll_array(process, contexts, polled, num_polled);

    processes[num_processes++] = process;
}

static void free_process(Process *process)
{
    if (process->leader) {
        metadata_server_free(&process->metadata_server);
    } else {
        chunk_server_free(&process->chunk_server);
    }
    free(process);
}

void cleanup_simulation(void)
{
    for (int i = 0; i < num_processes; i++)
        free_process(processes[i]);
}

static bool addr_eql_2(DescriptorAddress a, DescriptorAddress b)
{
    if (a.type != b.type)
        return false;

    if (a.type == DESC_ADDR_IPV4) {
        return a.ipv4.sin_family == b.ipv4.sin_family
            && a.ipv4.sin_port   == b.ipv4.sin_port
            && !memcmp(&a.ipv4.sin_addr, &a.ipv4.sin_addr, sizeof(a.ipv4.sin_addr));
    } else {
        return a.ipv6.sin6_family == b.ipv6.sin6_family
            && a.ipv6.sin6_port   == b.ipv6.sin6_port
            && !memcmp(&a.ipv6.sin6_addr, &a.ipv6.sin6_addr, sizeof(a.ipv6.sin6_addr));
    }
}

static bool find_peer_by_address(DescriptorAddress address, DescriptorHandle *handle)
{
    for (int i = 0; i < num_processes; i++) {

        for (int j = 0, k = 0; k < processes[i]->num_desc; j++) {

            Descriptor *desc = &processes[i]->desc[j];
            if (desc->type == DESC_EMPTY)
                continue;
            k++;

            if (desc->type == DESC_LISTEN_SOCKET &&
                addr_eql_2(address, desc->address)) {
                *handle = (DescriptorHandle) { processes[i], j, desc->generation };
                return true;
            }
        }
    }

    return false;
}

static Descriptor *handle_to_desc(DescriptorHandle handle)
{
    if (handle.process == NULL
        || handle.descriptor_index < 0
        || handle.descriptor_index >= MAX_DESCRIPTORS)
        return NULL;
    Process *process = handle.process;
    Descriptor *desc = &process->desc[handle.descriptor_index];
    if (desc->type == DESC_EMPTY || desc->generation != handle.generation)
        return NULL;
    return desc;
}

static void accept_queue_init(AcceptQueue *accept_queue, int size)
{
    accept_queue->head = 0;
    accept_queue->used = 0;
    accept_queue->size = size;
    accept_queue->items = malloc(size * sizeof(DescriptorHandle));
    if (accept_queue->items == NULL) {
        // TODO
    }
}

static void accept_queue_free(AcceptQueue *accept_queue)
{
    free(accept_queue->items);
}

static bool accept_queue_push(AcceptQueue *accept_queue, DescriptorHandle handle)
{
    if (accept_queue->used == accept_queue->size)
        return false;
    int tail = (accept_queue->head + accept_queue->used) % accept_queue->size;
    accept_queue->items[tail] = handle;
    accept_queue->used++;
    return true;
}

static bool accept_queue_pop(AcceptQueue *accept_queue, DescriptorHandle *item)
{
    if (accept_queue->used == 0)
        return false;
    *item = accept_queue->items[accept_queue->head];
    accept_queue->head = (accept_queue->head + 1) % accept_queue->size;
    accept_queue->used--;
    return true;
}

static void data_queue_init(DataQueue *queue, int size)
{
    queue->used = 0;
    queue->size = size;
    queue->data = malloc(size * sizeof(char));
    if (queue->data == NULL) {
        // TODO
    }
}

static void data_queue_free(DataQueue *queue)
{
    free(queue->data);
}

static int data_queue_read(DataQueue *queue, char *dst, int max)
{
    int num = max;
    if (num > queue->used)
        num = queue->used;

    if (num > 0) {
        memcpy(dst, queue->data, num);
        memmove(queue->data, queue->data + num, queue->used - num);
        queue->used -= num;
    }

    return num;
}

static int data_queue_write(DataQueue *queue, char *src, int len)
{
    int num = len;
    if (num > queue->size - queue->used)
        num = queue->size - queue->used;

    memcpy(queue->data + queue->used, src, num);
    queue->used += num;

    return num;
}

void update_simulation(void)
{
    for (int i = 0; i < num_processes; i++) {
        current_process = processes[i];

        void *contexts[MAX_CONNS+1];
        struct pollfd polled[MAX_CONNS+1];
        int num_polled;

        for (int j = 0, k = 0; k < current_process->num_desc; j++) {

            Descriptor *desc = &current_process->desc[j];
            if (desc->type == DESC_EMPTY)
                continue;
            k++;

            if (desc->type != DESC_SOCKET &&
                desc->type != DESC_LISTEN_SOCKET &&
                desc->type != DESC_CONNECTION_SOCKET)
                continue;

            int revents = desc->events & desc->revents;
            if (revents) {
                polled[num_polled].fd = (SOCKET) j;
                polled[num_polled].events = desc->events;
                polled[num_polled].revents = revents;
                num_polled++;
            }
        }

        if (current_process->leader) {
            num_polled = metadata_server_step(&current_process->metadata_server, contexts, polled, num_polled);
        } else {
            num_polled = chunk_server_step(&current_process->chunk_server, contexts, polled, num_polled);
        }

        if (num_polled < 0) {
            // TODO
        }

        process_poll_array(current_process, contexts, polled, num_polled);

        current_process = NULL;
    }

    for (int i = 0; i < num_processes; i++) {

        for (int j = 0, k = 0; k < processes[i]->num_desc; j++) {

            Descriptor *desc = &processes[i]->desc[j];
            if (desc->type == DESC_EMPTY)
                continue;
            k++;

            if (desc->type != DESC_CONNECTION_SOCKET)
                continue;

            switch (desc->connection_state) {

                case CONNECTION_DELAYED:
                {
                    DescriptorHandle peer_handle;
                    if (!find_peer_by_address(desc->connect_address, &peer_handle)) {
                        desc->connection_state = CONNECTION_FAILED;
                        break;
                    }

                    DescriptorHandle self_handle = { processes[i], j, desc->generation };
                    Descriptor *peer = handle_to_desc(peer_handle);
                    if (!accept_queue_push(&peer->accept_queue, self_handle)) {
                        desc->connection_state = CONNECTION_FAILED;
                        break;
                    }

                    desc->connection_state = CONNECTION_QUEUED;
                    desc->connection_peer = peer_handle;
                }
                break;

                case CONNECTION_QUEUED:
                {
                    if (handle_to_desc(desc->connection_peer) == NULL) {
                        // Listener closed before accepting
                        desc->connection_state = CONNECTION_FAILED;
                        break;
                    }
                }
                break;

                default:
                break;
            }
        }
    }
}

void *mock_malloc(size_t len)
{
    return malloc(len);
}

void *mock_realloc(void *ptr, size_t len)
{
    return realloc(ptr, len);
}

void mock_free(void *ptr)
{
    free(ptr);
}

int mock_remove(char *path)
{
    return remove(path);
}

int mock_rename(char *oldpath, char *newpath)
{
    return rename(oldpath, newpath);
}

SOCKET mock_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM || protocol != 0) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    if (current_process->num_desc == MAX_DESCRIPTORS) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    int idx = 0;
    while (current_process->desc[idx].type != DESC_EMPTY)
        idx++;

    Descriptor *desc = &current_process->desc[idx];
    desc->type = DESC_SOCKET;
    desc->events = 0;
    desc->revents = 0;
    desc->context = NULL;
    desc->address = (DescriptorAddress) { .type=DESC_ADDR_VOID };

    current_process->num_desc++;
    return (SOCKET) idx;
}

static DescriptorAddress convert_address(void *addr, size_t addr_len)
{
    int family = ((struct sockaddr*) addr)->sa_family;

    if (family == AF_INET && addr_len == sizeof(struct sockaddr_in))
        return (DescriptorAddress) { .type=DESC_ADDR_IPV4, .ipv4=*(struct sockaddr_in*) addr };

    if (family == AF_INET6 && addr_len != sizeof(struct sockaddr_in6))
        return (DescriptorAddress) { .type=DESC_ADDR_IPV6, .ipv6=*(struct sockaddr_in6*) addr };

    return (DescriptorAddress) { .type=DESC_ADDR_VOID };
}

int mock_bind(SOCKET fd, void *addr, size_t addr_len)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_SOCKET) {
        // TODO
        return -1;
    }

    DescriptorAddress address = convert_address(addr, addr_len);
    if (address.type == DESC_ADDR_VOID) {
        // TODO
        return -1;
    }

    // TODO: Should check that the address family matched
    //       the one used to create the socket
    desc->address = address;
    return 0;
}

int mock_listen(SOCKET fd, int backlog)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_SOCKET) {
        // TODO
        return -1;
    }

    desc->type = DESC_LISTEN_SOCKET;
    accept_queue_init(&desc->accept_queue, backlog);

    return 0;
}

SOCKET mock_accept(SOCKET fd, void *addr, socklen_t *addr_len)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_LISTEN_SOCKET) {
        // TODO
        return -1;
    }

    DescriptorHandle peer_handle;
    if (!accept_queue_pop(&desc->accept_queue, &peer_handle)) {
        // TODO
        assert(0);
    }

    Descriptor *peer = handle_to_desc(peer_handle);
    if (peer == NULL) {
        // Peer closed without removing itself from the accept queue!
        assert(0);
    }

    if (current_process->num_desc == MAX_DESCRIPTORS) {
        // TODO
    }
    int new_idx = 0;
    while (current_process->desc[new_idx].type != DESC_EMPTY)
        new_idx++;
    Descriptor *new_desc = &current_process->desc[new_idx];
    new_desc->type = DESC_CONNECTION_SOCKET;
    new_desc->events = 0;
    new_desc->revents = 0;
    new_desc->context = NULL;
    new_desc->address = (DescriptorAddress) { .type=DESC_ADDR_VOID };
    new_desc->connection_state = CONNECTION_ESTABLISHED;
    new_desc->connection_peer = peer_handle;
    data_queue_init(&new_desc->output_data, DATA_QUEUE_SIZE);

    peer->connection_peer = (DescriptorHandle) { current_process, new_idx, new_desc->generation };
    peer->connection_state = CONNECTION_ESTABLISHED;
    peer->revents |= POLLOUT;
    data_queue_init(&peer->output_data, DATA_QUEUE_SIZE);

    current_process->num_desc++;
    return (SOCKET) new_idx;
}

int mock_getsockopt(SOCKET fd, int level, int optname, void *optval, socklen_t *optlen)
{
    // TODO
    return -1;
}

int mock_setsockopt(SOCKET fd, int level, int optname, void *optval, socklen_t optlen)
{
    // TODO
    return -1;
}

int mock_recv(SOCKET fd, void *dst, int len, int flags)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    if (flags) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_CONNECTION_SOCKET) {
        // TODO
        return -1;
    }

    if (desc->connection_state != CONNECTION_ESTABLISHED) {
        // TODO
        return -1;
    }

    Descriptor *peer = handle_to_desc(desc->connection_peer);
    if (peer == NULL) {
        // TODO
        return -1;
    }

    DataQueue *input_data = &peer->output_data;
    return data_queue_read(input_data, dst, len);
}

int mock_send(SOCKET fd, void *src, int len, int flags)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    if (flags) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_CONNECTION_SOCKET) {
        // TODO
        return -1;
    }

    if (desc->connection_state != CONNECTION_ESTABLISHED) {
        // TODO
        return -1;
    }

    data_queue_write(&desc->output_data, src, len);
    return len;
}

int mock_connect(SOCKET fd, void *addr, size_t addr_len)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }

    int idx = (int) fd;
    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_SOCKET) {
        // TODO
        return -1;
    }

    desc->type = DESC_CONNECTION_SOCKET;
    desc->connection_state = CONNECTION_DELAYED;
    desc->connect_address = convert_address(addr, addr_len);
    if (desc->connect_address.type == DESC_ADDR_VOID) {
        // TODO
        return -1;
    }

    return -1;
}

static NATIVE_HANDLE
wrap_native_file_into_desc(NATIVE_HANDLE handle)
{
    if (current_process->num_desc == MAX_DESCRIPTORS) {
        // TODO
        return -1;
    }

    int idx = 0;
    while (current_process->desc[idx].type != DESC_EMPTY)
        idx++;

    Descriptor *desc = &current_process->desc[idx];

    desc->type = DESC_FILE;
    desc->real_fd = handle;

    current_process->num_desc++;
    return idx;
}

void accept_queue_remove(AcceptQueue *queue, DescriptorHandle handle)
{
    int i = 0;
    while (i < queue->used && (
        queue->items[i].process != handle.process ||
        queue->items[i].descriptor_index != handle.descriptor_index ||
        queue->items[i].generation != handle.generation))
        i++;

    if (i == queue->used)
        return;

    for (; i < queue->used-1; i++) {
        int u = (queue->head + i + 0) % queue->size;
        int v = (queue->head + i + 1) % queue->size;
        queue->items[u] = queue->items[v];
    }
}

static void close_desc(Descriptor *desc)
{
    switch (desc->type) {

        case DESC_EMPTY:
        // TODO
        break;

        case DESC_FILE:
#ifdef _WIN32
        CloseHandle(desc->real_fd);
#else
        close(desc->real_fd);
#endif
        break;

        case DESC_SOCKET:
        // TODO
        break;

        case DESC_LISTEN_SOCKET:
        accept_queue_free(&desc->accept_queue);
        break;

        case DESC_CONNECTION_SOCKET:
        data_queue_free(&desc->output_data);
        switch (desc->connection_state) {

            case CONNECTION_DELAYED:
            // TODO
            break;

            case CONNECTION_QUEUED:
            {
                Descriptor *peer = handle_to_desc(desc->connection_peer);
                if (peer == NULL) break;

                DescriptorHandle self_handle = { current_process, desc - current_process->desc, desc->generation };
                accept_queue_remove(&peer->accept_queue, self_handle);
            }
            break;

            case CONNECTION_ESTABLISHED:
            // TODO
            break;

            case CONNECTION_FAILED:
            // TODO
            break;
        }
        // TODO
        break;
    }
    desc->type = DESC_EMPTY;
    desc->generation++;
}

#ifdef _WIN32

int mock_closesocket(SOCKET fd)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }
    int idx = (int) fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_SOCKET &&
        desc->type != DESC_LISTEN_SOCKET &&
        desc->type != DESC_CONNECTION_SOCKET) {
        // TODO
        return -1;
    }

    close_desc(desc);
    return 0;
}

HANDLE mock_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    HANDLE handle = CreateFileW(lpFileName,
        dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
    if (handle == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;
    return wrap_native_file_into_desc(handle);
}

BOOL mock_CloseHandle(HANDLE handle)
{
    if (fd == INVALID_SOCKET) {
        // TODO
        return -1;
    }
    int idx = (int) fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    close_desc(desc);
    return 0;
}

BOOL mock_LockFile(HANDLE hFile,
    DWORD dwFileOffsetLow,
    DWORD dwFileOffsetHigh,
    DWORD nNumberOfBytesToLockLow,
    DWORD nNumberOfBytesToLockHigh)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return LockFile(
        desc->real_fd,
        dwFileOffsetLow,
        dwFileOffsetHigh,
        nNumberOfBytesToLockLow,
        nNumberOfBytesToLockHigh);
}

BOOL mock_UnlockFile(
    HANDLE hFile,
    DWORD  dwFileOffsetLow,
    DWORD  dwFileOffsetHigh,
    DWORD  nNumberOfBytesToUnlockLow,
    DWORD  nNumberOfBytesToUnlockHigh)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return UnlockFile(
        desc->real_fd,
        dwFileOffsetLow,
        dwFileOffsetHigh,
        nNumberOfBytesToUnlockLow,
        nNumberOfBytesToUnlockHigh);
}

BOOL mock_FlushFileBuffers(HANDLE handle)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return FlushFileBuffers(desc->real_fd);
}

BOOL mock_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return ReadFile(desc->real_fd, dst, len, num, ov);
}

BOOL mock_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return WriteFile(desc->real_fd, src, len, num ov);
}

BOOL mock_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return FALSE;
    }
    int idx = (int) handle;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return GetFileSizeEx(desc->real_fd, buf);
}

char *mock__fullpath(char *path, char *dst, int cap)
{
    return _fullpath(path, dst, cap);
}

int mock__mkdir(char *path)
{
    return _mkdir(path);
}

#else

int mock_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    // TODO
}

int mock_open(char *path, int flags, int mode)
{
    int fd = open(path, flags, mode);
    if (fd < 0) return -1;

    return wrap_native_file_into_desc(fd);
}

int mock_close(int fd)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = (int) fd;

    Descriptor *desc = &current_process->desc[idx];
    close_desc(desc);
    return 0;
}

int mock_flock(int fd, int op)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return flock(desc->real_fd, op);
}

int mock_fsync(int fd)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return fsync(desc->real_fd);
}

int mock_read(int fd, char *dst, int len)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type == DESC_FILE) {
        return read(desc->real_fd, dst, len);
    } else {
        return mock_recv(fd, dst, len, 0);
    }
}

int mock_write(int fd, char *src, int len)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type == DESC_FILE) {
        return write(desc->real_fd, src, len);
    } else {
        return mock_send(fd, src, len, 0);
    }
}

int mock_fstat(int fd, struct stat *buf)
{
    if (fd < 0) {
        // TODO
        return -1;
    }
    int idx = fd;

    Descriptor *desc = &current_process->desc[idx];
    if (desc->type != DESC_FILE) {
        // TODO
        return -1;
    }

    return fstat(desc->real_fd, buf);
}

int mock_mkstemp(char *path)
{
    return mkstemp(path);
}

char* mock_realpath(char *path, char *dst)
{
    return realpath(path, dst);
}

int mock_mkdir(char *path, mode_t mode)
{
    return mkdir(path, mode);
}

#endif
