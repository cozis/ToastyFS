#include <assert.h>

#include "system.h"
#include "chunk_server.h"
#include "metadata_server.h"

#ifdef _WIN32
#define NATIVE_HANDLE HANDLE
#else
#define SOCKET int
#define INVALID_SOCKET -1
#define NATIVE_HANDLE int
#endif

#define MAX_DESCRIPTORS 1024
#define MAX_ALLOCATIONS  128
#define MAX_PROCESSES     32

#define DATA_QUEUE_SIZE (1<<9)

typedef struct Process Process;

typedef enum {
    DESC_EMPTY,
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

static bool is_leader(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp("--leader", argv[i]) || !strcmp("-l", argv[i]))
            return true;
    return false;
}

int spawn_simulated_process(char *args)
{
    if (num_processes == MAX_PROCESSES)
        return -1;

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
    if (leader) {
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
    Process *process = processes[handle.process_index];
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

        // TODO: fill up poll array

        if (leader) {
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

#ifdef _WIN32

int mock_closesocket(SOCKET fd)
{
    // TODO
}

HANDLE mock_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // TODO
}

BOOL mock_CloseHandle(HANDLE handle)
{
    // TODO
}

BOOL mock_LockFile(HANDLE hFile,
    DWORD dwFileOffsetLow,
    DWORD dwFileOffsetHigh,
    DWORD nNumberOfBytesToLockLow,
    DWORD nNumberOfBytesToLockHigh)
{
    // TODO
}

BOOL mock_UnlockFile(
  HANDLE hFile,
  DWORD  dwFileOffsetLow,
  DWORD  dwFileOffsetHigh,
  DWORD  nNumberOfBytesToUnlockLow,
  DWORD  nNumberOfBytesToUnlockHigh)
{
    // TODO
}

BOOL mock_FlushFileBuffers(HANDLE handle)
{
    // TODO
}

BOOL mock_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    // TODO
}

BOOL mock_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    // TODO
}

BOOL mock_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    // TODO
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
    // TODO
}

int mock_close(int fd)
{
    // TODO
}

int mock_flock(int fd, int op)
{
    // TODO
}

int mock_fsync(int fd)
{
    // TODO
}

int mock_read(int fd, char *dst, int len)
{
    // TODO
}

int mock_write(int fd, char *src, int len)
{
    // TODO
}

int mock_fstat(int fd, struct stat *buf)
{
    // TODO
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
