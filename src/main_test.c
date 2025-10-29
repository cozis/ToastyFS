#ifdef BUILD_TEST

#include "core/chunk_server.h"
#include "core/metadata_server.h"

#define MAX_PROCESSES 128
#define MAX_DESCRIPTORS 1024

typedef enum {
    DESCRIPTOR_TYPE_EMPTY,
    DESCRIPTOR_TYPE_FILE,
    DESCRIPTOR_TYPE_SOCKET,
    DESCRIPTOR_TYPE_LISTENER_SOCKET,
    DESCRIPTOR_TYPE_CONNECTION_SOCKET,
} DescriptorType;

typedef struct {
    int peer_process;
    int peer_fd;
} PendingAccept;

typedef struct {

    // Common
    DescriptorType type;

    // File
    int real_fd;

    // Socket
    bool bound;
    struct sockaddr_in addr;

    // Listener Socket
    PendingAccept *accept_queue;
    int accept_queue_head;
    int accept_queue_size;
    int accept_queue_used;

    // Connection Socket
    bool  pending;
    int   peer_process;
    int   peer_fd;
    char *input;
    int   input_used;
    int   input_size;
    char *output;
    int   output_used;
    int   output_size;

} Descriptor;

typedef struct {
    int num_desc;
    Descriptor desc[MAX_DESCRIPTORS];
} DescriptorTable;

typedef struct {
    void  *ptr;
    size_t len;
    char  *file;
    int    line;
} Allocation;

typedef struct {
    size_t mem_usage;
    int num_allocs;
    Allocation allocs[MAX_ALLOCATIONS];
} AllocationTable;

typedef enum {
    PROCESS_TYPE_CLIENT,
    PROCESS_TYPE_CHUNK_SERVER,
    PROCESS_TYPE_METADATA_SERVER,
} ProcessType;

typedef struct {
    ProcessType type;
    union {
        ChunkServer chunk_server;
        MetadataServer metadata_server;
    };

    DescriptorTable *dt;
    AllocationTable *at;

} Process;

int num_processes = 0;
Process processes[MAX_PROCESSES];
Process *current_process = NULL;
uint64_t current_time = 0;

int find_unused_descriptor(Process *process)
{
    if (process->dt->num_desc == MAX_DESCRIPTORS)
        return -1;

    int i = 0;
    while (process->dt->desc[i].type != DESCRIPTOR_TYPE_EMPTY)
        i++;

    return i;
}

void descriptor_init_as_file(Descriptor *desc, int real_fd)
{
    desc->type = DESCRIPTOR_TYPE_FILE;
    desc->real_fd = real_fd;
}

void descriptor_init_as_socket(Descriptor *desc)
{
    desc->type = DESCRIPTOR_TYPE_SOCKET;
    desc->bound = false;
}

void descriptor_turn_socket_into_listener(Descriptor *desc, int backlog)
{
    desc->type = DESCRIPTOR_TYPE_LISTENER_SOCKET;
    desc->accept_queue = malloc(backlog * sizeof(PendingAccept));
    desc->accept_queue_head = 0;
    desc->accept_queue_used = 0;
    desc->accept_queue_size = backlog;
    if (desc->accept_queue == NULL)
        __builtin_trap();
}

void descriptor_turn_socket_into_connection(Descriptor *desc, int peer_process, int peer_fd)
{
    desc->type = DESCRIPTOR_TYPE_LISTENER_SOCKET;
    desc->pending = true;
    desc->peer_process = peer_process;
    desc->peer_fd = peer_fd;
    desc->input = malloc(1<<9);
    desc->input_size = 1<<9;
    desc->input_used = 0;
    desc->output = malloc(1<<9);
    desc->output_size = 1<<9;
    desc->output_used = 0;
    if (desc->input == NULL || desc->output == NULL)
        __builtin_trap();
}

void descriptor_free(Descriptor *desc)
{
    switch (desc->type) {

        case DESCRIPTOR_TYPE_EMPTY:
        // TODO
        break;

        case DESCRIPTOR_TYPE_FILE:
        close(desc->proxy_fd);
        break;

        case DESCRIPTOR_TYPE_SOCKET:
        break;

        case DESCRIPTOR_TYPE_LISTENER_SOCKET:
        free(desc->accept_queue);
        break;

        case DESCRIPTOR_TYPE_CONNECTION_SOCKET:
        free(desc->input);
        free(desc->output);
        break;
    }
    desc->type = DESCRIPTOR_TYPE_EMPTY;
}

bool is_leader(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--leader") || !strcmp(argv[i], "-l"))
            return true;
    return false;
}

int split_args(char *args, char **out, int max)
{
    int len = strlen(args);
    int cur = 0;
    int num = 0;

    for (;;) {

        while (cur < len && (args[cur] == ' ' || args[cur] == '\t'))
            cur++;

        int off = cur;
        while (cur < len && (args[cur] != ' ' && args[cur] != '\t'))
            cur++;

        if (num < max)
            out[num++] = args + off;

        args[cur++] = '\0';
    }

    return num;
}

#define MAX_ARGS 128

void process_init(Process *process, char *args)
{
    process->dt = malloc(sizeof(DescriptorTable));
    process->at = malloc(sizeof(AllocationTable));
    if (process->dt == NULL || process->at == NULL)
        abort();

    process->dt->num_desc = 0;
    process->at->num_allocs = 0;
    process->at->mem_usage = 0;

    char *argv[MAX_ARGS];
    int argc = split_args(args, argv, MAX_ARGS);

    void *contexts[MAX_CONNS+1];
    struct pollfd polled[MAX_CONNS+1];
    int num_polled;

    current_process = process;
    if (is_leader(argc, argv)) {
        process->type = PROCESS_TYPE_METADATA_SERVER;
        num_polled = metadata_server_init(&process->metadata_server, argc, argv, contexts, polled);
    } else {
        process->type = PROCESS_TYPE_CHUNK_SERVER;
        num_polled = chunk_server_init(&process->chunk_server, argc, argv, contexts, polled);
    }
    current_process = NULL;

    if (num_polled < 0) {
        // TODO
    }
    do_stuff_with_pollfds(contexts, polled, num_polled);
}

void process_step(Process *process)
{
    if (process->type == PROCESS_TYPE_METADATA_SERVER)
        num_polled = metadata_server_step(&process->metadata_server, xxx, yyyy, contexts, polled, num_polled);
    else
        num_polled = chunk_server_step(&process->chunk_server, xxx, yyyy, contexts, polled, num_polled);

    if (num_polled < 0) {
        // TODO
    }
    do_stuff_with_pollfds(contexts, polled, num_polled);
}

void process_free(Process *process)
{
    if (process->type == PROCESS_TYPE_METADATA_SERVER)
        metadata_server_free(&process->metadata_server);
    else
        chunk_server_free(&process->chunk_server);

    free(process->at);
    free(process->dt);
}

void spawn_simulated_process(char *args)
{
    if (num_processes == MAX_PROCESSES)
        abort();

    process_init(&processes[num_processes++], args);
}

void update_simulation(void)
{
    for (int i = 0; i < num_processes; i++)
        process_step(&processes[i]);

    // TODO
}

void cleanup_simulation(void)
{
    for (int i = 0; i < num_processes; i++)
        process_free(&processes[i]);
}

sig_atomic_t simulation_should_stop = false;

int main(int argc, char **argv)
{
    // TODO: set simulation_should_stop=true on ctrl+C

    spawn_simulated_process("--addr 127.0.0.1 8080 --leader");
    spawn_simulated_process("--addr 127.0.0.1 8081");
    spawn_simulated_process("--addr 127.0.0.1 8082");
    spawn_simulated_process("--addr 127.0.0.1 8083");
    spawn_simulated_process("--addr 127.0.0.1 8084");
    spawn_simulated_process("--addr 127.0.0.1 8085");
    spawn_simulated_process("--addr 127.0.0.1 8086");
    spawn_simulated_process("--addr 127.0.0.1 8087");
    spawn_simulated_process("--addr 127.0.0.1 8088");
    spawn_simulated_process("--addr 127.0.0.1 8089");
    spawn_simulated_process("--addr 127.0.0.1 8090");

    while (!simulation_should_stop)
        update_simulation();

    cleanup_simulation();
    return 0;
}

void *sys_malloc_(size_t len, char *file, int line)
{
    if (current_process->at->num_allocs == MAX_ALLOCATIONS)
        __builtin_trap();

    void *ptr = malloc(len);
    if (ptr == NULL)
        __builtin_trap();

    current_process->at->allocs[current_process->at->num_allocs++] = (Allocation) { ptr, len, file, line };
    current_process->at->mem_usage += len;
    return ptr;
}

void *sys_realloc_(void *ptr, size_t len, char *file, int line)
{
    int found = -1;
    for (int i = 0; i < current_process->at->num_allocs; i++)
        if (current_process->at->allocs[i].ptr == ptr) {
            found = i;
            break;
        }
    if (found < 0)
        __builtin_trap();

    size_t old_len = current_process->at->allocs[found].len;
    void  *new_ptr = realloc(ptr, len);
    if (new_ptr == NULL)
        __builtin_trap();

    current_process->at->allocs[found].ptr = new_ptr;
    current_process->at->allocs[found].len = len;
    current_process->at->allocs[found].file = file;
    current_process->at->allocs[found].line = line;

    current_process->at->mem_usage -= old_len;
    current_process->at->mem_usage += len;

    return new_ptr;
}

void sys_free_(void *ptr, char *file, int line)
{
    (void) file;
    (void) line;

    int found = -1;
    for (int i = 0; i < current_process->at->num_allocs; i++)
        if (current_process->at->allocs[i].ptr == ptr) {
            found = i;
            break;
        }
    if (found < 0)
        __builtin_trap();

    current_process->at->mem_usage -= current_process->at->allocs[found].len;
    current_process->at->allocs[found] = current_process->at->allocs[--current_process->num_allocs];
}

#ifdef _WIN32

SOCKET sys_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    if (type != SOCK_STREAM) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    if (protocol != 0) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    int fd = find_unused_descriptor(current_process);
    if (fd < 0) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    // TODO: maybe bind to a random address?

    descriptor_init_as_socket(&current_process->dt->desc[fd]);
    return (SOCKET) fd;
}

int sys_bind(SOCKET fd, void *addr, size_t addr_len)
{
    Descriptor *desc = &current_process->dt->desc[(int) fd];
    if (desc->type != DESCRIPTOR_TYPE_PRECONF_SOCKET) {
        // TODO: errno
        return -1;
    }

    if (addr_len != sizeof(desc->bind)) {
        // TODO: errno
        return -1;
    }

    // TODO: maybe check that no one else is listening
    //       on this port

    desc->bound = true;
    memcpy(&desc->addr, addr, addr_len);
    return 0;
}

int sys_listen(SOCKET fd, int backlog)
{
    Descriptor *desc = &current_process->dt->desc[(int) fd];
    if (desc->type != DESCRIPTOR_TYPE_SOCKET) {
        // TODO: errno
        return -1;
    }
    descriptor_turn_socket_into_listener(desc, backlog);
    return 0;
}

int sys_closesocket(SOCKET fd)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_SOCKET &&
        desc->type != DESCRIPTOR_TYPE_LISTENER_SOCKET
        desc->type != DESCRIPTOR_TYPE_CONNECTION_SOCKET) {
        __builtin_trap();
    }
    descriptor_free(desc);
    return 0;
}

SOCKET sys_accept(SOCKET fd, void *addr, int *addr_len)
{
    Descriptor *desc = &current_process->desc[(int) fd];
    if (desc->type != DESCRIPTOR_TYPE_LISTENER_SOCKET) {
        // TODO: errno
        return INVALID_SOCKET;
    }

    if (desc->accept_queue_used == 0) {
        // TODO: would block
    }
    PendingAccept *pending_accept = desc->accept_queue[desc->accept_queue_head];
    desc->accept_queue_head = (desc->accept_queue_head + 1) % (desc->accept_queue_size);
    desc->accept_queue_used--;

    int new_fd = find_unused_descriptor(current_process);
    if (new_fd < 0) {
        // TODO
    }
    descriptor_init_as_socket(&current_process->desc[new_fd]);
    descriptor_turn_socket_into_connection(&current_process->desc[new_fd], peer_process, peer_fd);
    return (SOCKET) new_fd;
}

int sys_getsockopt(SOCKET fd, int level, int optname, void *optval, int *optlen)
{
    // TODO
}

int sys_setsockopt(SOCKET fd, int level, int optname, void *optval, int optlen)
{
    // TODO
}

int sys_recv(SOCKET fd, void *dst, int len, int flags)
{
    // TODO
}

int sys_send(SOCKET fd, void *src, int len, int flags)
{
    // TODO
}

int sys_connect(SOCKET fd, void *addr, size_t addr_len)
{
    // TODO
}

BOOL sys_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
    // TODO
}

BOOL sys_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    // TODO
}

HANDLE sys_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    int fd = find_unused_descriptor(current_process);
    if (fd < 0) {
        // TODO: WSAGetLastError
        return INVALID_HANDLE_VALUE;
    }

    HANDLE handle = CreateFileW(lpFileName, dwDesiredAccess,
        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
    if (handle == INVALID_HANDLE_VALUE) {
        // TODO
        return INVALID_HANDLE_VALUE;
    }

    Descriptor *desc = current_process->dt->desc[fd];
    descriptor_init_as_file(desc, handle);
    return (HANDLE) fd;
}

BOOL sys_CloseHandle(HANDLE handle)
{
    Descriptor *desc = current_process->dt->desc[(int) handle];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO
        return false;
    }
    return CloseHandle(desc->real_fd);
}

BOOL sys_LockFile(HANDLE handle)
{
    Descriptor *desc = current_process->dt->desc[(int) handle];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO
        return false;
    }
    return LockFile(desc->real_fd);
}

BOOL sys_UnlockFile(HANDLE handle)
{
    Descriptor *desc = current_process->dt->desc[(int) handle];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO
        return false;
    }
    return UnlockFile(desc->real_fd);
}

BOOL sys_FlushFileBuffers(HANDLE handle)
{
    Descriptor *desc = current_process->dt->desc[(int) handle];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO
        return false;
    }
    return FlushFileBuffers(desc->real_fd);
}

BOOL sys_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    if (ov) {
        // TODO
        return false;
    }

    Descriptor *desc = &current_process->dt->desc[(int) handle];
    switch (desc->type) {

        case DESCRIPTOR_TYPE_FILE:
        return ReadFile(desc->real_fd, dst, len, num, ov);

        case DESCRIPTOR_TYPE_CONNECTION_SOCKET:
        {
            int cpy = len;
            if (cpy > desc->input_used)
                cpy = desc->input_used;
            memcpy(dst, desc->input, cpy);
            memmove(desc->input, desc->input + cpy, desc->input_used - cpy);
            desc->input_used -= cpy;
            *num = cpy;
            return true;
        }
        break;

        default:
        // TODO: errno
        return false;
    }
}

BOOL sys_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    if (ov) {
        // TODO
        return false;
    }

    Descriptor *desc = &current_process->dt->desc[(int) handle];
    switch (desc->type) {

        case DESCRIPTOR_TYPE_FILE:
        return WriteFile(desc->real_fd, src, len, num, ov);

        case DESCRIPTOR_TYPE_CONNECTION_SOCKET:
        {
            if (desc->output_size - desc->output_used < len) {
                int new_capacity = 2 * desc->output_size;
                if (new_capacity - desc->output_used < len)
                    new_capacity = desc->output_used + len;
                desc->output = realloc(desc->output, new_capacity);
                if (desc->output == NULL)
                    __builtin_trap();
                desc->output_size = new_capacity;
            }
            memcpy(desc->output + desc->output_used, src, len);
            desc->output_used += len;
            *num = len;
            return true;
        }
        break;

        default:
        // TODO: errno
        return false;
    }
}

BOOL sys_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    Descriptor *desc = current_process->dt->desc[(int) handle];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO
        return false;
    }
    return GetFileSizeEx(desc->real_fd, buf);
}

char *sys__fullpath(char *path, char *dst, int cap)
{
    return _fullpath(path, dst, cap);
}

#else

int sys_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET) {
        // TODO: errno
        return -1;
    }

    if (type != SOCK_STREAM) {
        // TODO: errno
        return -1;
    }

    if (protocol != 0) {
        // TODO: errno
        return -1;
    }

    int fd = find_unused_descriptor(current_process);
    if (fd < 0) {
        // TODO: errno
        return -1;
    }

    // TODO: maybe bind to a random address?

    descriptor_init_as_socket(&current_process->dt->desc[fd]);
    return fd;
}

int sys_bind(int fd, void *addr, size_t addr_len)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_PRECONF_SOCKET) {
        // TODO: errno
        return -1;
    }

    if (addr_len != sizeof(desc->bind)) {
        // TODO: errno
        return -1;
    }

    // TODO: maybe check that no one else is listening
    //       on this port

    desc->bound = true;
    memcpy(&desc->addr, addr, addr_len);
    return 0;
}

int sys_listen(int fd, int backlog)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_SOCKET) {
        // TODO: errno
        return -1;
    }
    descriptor_turn_socket_into_listener(desc, backlog);
    return 0;
}

int sys_accept(int fd, void *addr, int *addr_len)
{
    Descriptor *desc = &current_process->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_LISTENER_SOCKET) {
        // TODO: errno
        return -1;
    }

    if (desc->accept_queue_used == 0) {
        // TODO: would block
    }
    PendingAccept *pending_accept = desc->accept_queue[desc->accept_queue_head];
    desc->accept_queue_head = (desc->accept_queue_head + 1) % (desc->accept_queue_size);
    desc->accept_queue_used--;

    int new_fd = find_unused_descriptor(current_process);
    if (new_fd < 0) {
        // TODO
    }
    descriptor_init_as_socket(&current_process->desc[new_fd]);
    descriptor_turn_socket_into_connection(&current_process->desc[new_fd], peer_process, peer_fd);
    return new_fd;
}

int sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    // TODO
}

int sys_setsockopt(int fd, int level, int optname, void *optval, socklen_t optlen)
{
    // TODO
}

int sys_recv(int fd, void *dst, int len, int flags)
{
    if (flags)
        __builtin_trap();
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_CONNECTION_SOCKET) {
        // TODO: errno
        return -1;
    }
    return sys_read(fd, dst, len);
}

int sys_send(int fd, void *src, int len, int flags)
{
    if (flags)
        __builtin_trap();
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_CONNECTION_SOCKET) {
        // TODO: errno
        return -1;
    }
    return sys_write(fd, src, len);
}

bool sockaddr_eql(struct sockaddr_in a, struct sockaddr_in b)
{
    return a.sin_family == b.sin_family
        && a.sin_port == b.sin_port
        && a.sin_addr == b.sin_addr;
}

int sys_connect(int fd, void *addr, size_t addr_len)
{
    if (addr_len != sizeof(struct sockaddr_in)) {
        // TODO
    }
    struct sockaddr_in tmp;
    memcpy(&tmp, addr, sizeof(tmp));

    int peer_process = -1;
    int peer_fd = -1;
    for (int i = 0; i < num_processes; i++) {
        for (int j = 0; j < processes[i].dt->num_desc; j++) {
            Descriptor *desc = &processes[i].dt->desc[j];
            if (desc->type == DESCRIPTOR_TYPE_LISTENER_SOCKET
                && sockaddr_eql(desc->addr, tmp)) {
                    peer_process = i;
                    peer_fd = j;
                    goto found;
                }
        }
    }
found:
    if (peer_process < 0) {
        // TODO
    }

    int fd = find_unused_descriptor(current_process);
    if (fd < 0) {
        // TODO
    }

    Descriptor *desc = &current_process->desc[fd];
    descriptor_init_as_socket(desc);
    descriptor_turn_socket_into_connection(desc, peer_process, peer_fd);
    return fd;
}

int sys_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    if (clockid != CLOCK_REALTIME) {
        // TODO
    }

    if (tp == NULL) {
        // TODO
    }

    tp->tv_sec = current_time / 1000000000;
    tp->tv_nsec = current_time % 1000000000;
    return 0;
}

int sys_open(char *path, int flags, int mode)
{
    int fd = find_unused_descriptor(current_process);
    if (fd < 0) {
        // TODO: errno
        return -1;
    }

    int real_fd = open(path, flags, mode);
    if (real_fd < 0)
        return real_fd;

    descriptor_init_as_file(&current_process->dt->desc[fd], real_fd);
    return fd;
}

int sys_close(int fd)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    descriptor_free(desc);
    return 0;
}

int sys_flock(int fd, int op)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO: errno
        return -1;
    }

    return flock(desc->real_fd, op);
}

int sys_fsync(int fd)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO: errno
        return -1;
    }

    return fsync(desc->real_fd);
}

int sys_read(int fd, char *dst, int len)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    switch (desc->type) {

        case DESCRIPTOR_TYPE_FILE:
        return read(desc->real_fd, dst, len);

        case DESCRIPTOR_TYPE_CONNECTION_SOCKET:
        {
            int cpy = len;
            if (cpy > desc->input_used)
                cpy = desc->input_used;
            memcpy(dst, desc->input, cpy);
            memmove(desc->input, desc->input + cpy, desc->input_used - cpy);
            desc->input_used -= cpy;
            return cpy;
        }
        break;

        default:
        // TODO: errno
        return -1;
    }
}

int sys_write(int fd, char *src, int len)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    switch (desc->type) {

        case DESCRIPTOR_TYPE_FILE:
        return write(desc->real_fd, dst, len);

        case DESCRIPTOR_TYPE_CONNECTION_SOCKET:
        {
            if (desc->output_size - desc->output_used < len) {
                int new_capacity = 2 * desc->output_size;
                if (new_capacity - desc->output_used < len)
                    new_capacity = desc->output_used + len;
                desc->output = realloc(desc->output, new_capacity);
                if (desc->output == NULL)
                    __builtin_trap();
                desc->output_size = new_capacity;
            }
            memcpy(desc->output + desc->output_used, src, len);
            desc->output_used += len;
            return len;
        }
        break;

        default:
        // TODO: errno
        return -1;
    }
}

int sys_stat(int fd, struct stat *buf)
{
    Descriptor *desc = &current_process->dt->desc[fd];
    if (desc->type != DESCRIPTOR_TYPE_FILE) {
        // TODO: errno
        return -1;
    }

    return stat(desc->real_fd, buf);
}

int sys_mkstemp(char *path)
{
    return mkstemp(path);
}

char* sys_realpath(char *path, char *dst)
{
    return realpath(path, dst);
}

#endif

#endif // BUILD_TEST
