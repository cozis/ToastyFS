/////////////////////////////////////////////////////////////////
// Includes

#include "mockfs.h"
#include <quakey.h>
#include <stdint.h>
#include <assert.h>

/////////////////////////////////////////////////////////////////
// Utilities

#define TODO __builtin_trap()

#ifdef NDEBUG
#define UNREACHABLE {}
#define ASSERT(X) {}
#else
#define UNREACHABLE __builtin_trap()
#define ASSERT(X) {if (!(X)) __builtin_trap();}
#endif

/////////////////////////////////////////////////////////////////
// Basic Types

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

typedef u32 b32;

typedef u64 Nanos;

/////////////////////////////////////////////////////////////////
// Network Types

typedef struct {
    u32 data;
} AddrIPv4;

typedef struct {
    u16 data[8];
} AddrIPv6;

typedef enum {
    ADDR_FAMILY_IPV4,
    ADDR_FAMILY_IPV6,
} AddrFamily;

typedef struct {
    AddrFamily family;
    union {
        AddrIPv4 ipv4;
        AddrIPv6 ipv6;
    };
} Addr;

/////////////////////////////////////////////////////////////////
// Descriptor Type

typedef struct Desc Desc;
typedef struct Host Host;

typedef struct {
    int    head;
    int    count;
    int    capacity;
    Desc **entries;
} AcceptQueue;

typedef struct {
    char *data;
    int   head;
    int   used;
    int   size;
    int   refs;
} SocketQueue;

typedef enum {
    // The Desc structure is unused
    DESC_EMPTY,

    // The Desc represents a socket created
    // with the socket() system call. The
    // specific type of socket depends on
    // how it's configured
    DESC_SOCKET,

    // The Desc represents a listening socket,
    // one created with socket() on which listen()
    // is used.
    DESC_SOCKET_L,

    // The Desc represents a connection socket,
    // one created using accept() or with socket()
    // and then configured using listen()
    DESC_SOCKET_C,

    // The Desc represents an opened file
    DESC_FILE,

    // The Desc represent an open directory
    DESC_DIRECTORY,

    DESC_PIPE,
} DescType;

typedef enum {
    CONNECT_STATUS_WAIT,
    CONNECT_STATUS_DONE,
    CONNECT_STATUS_RESET,
    CONNECT_STATUS_CLOSE,
    CONNECT_STATUS_NOHOST,
} ConnectStatus;

struct Desc {

    // Parent host object
    // This is set once at startup
    Host *host;

    /////////////////////////////////////////
    // General descriptor fields

    DescType type;
    b32      non_blocking;

    /////////////////////////////////////////
    // General socket fields

    // True if bind() has been called on this socket
    b32 is_explicitly_bound;

    // Address and port bound to this socket (either
    // implicitly or explicitly).
    //
    // An implicit bind occurs when listen() or connect()
    // are called on a socket that was never bound to an
    // interface using bind().
    //
    // The address starts out with family equal to the
    // first argument of socket() and address of 0. The
    // port starts from 0.
    Addr bound_addr;
    u16  bound_port;

    /////////////////////////////////////////
    // Listen socket fields

    AcceptQueue accept_queue;

    /////////////////////////////////////////
    // Pipe or Connection socket fields

    // Status code of the connecting process
    ConnectStatus connect_status;

    // These are used when the socket is still connecting
    // (only used by sockets, not pipes)
    Addr connect_addr;
    u16  connect_port;

    // When connected this refers to the peer socket, else it's NULL.
    //
    // The peer is either a listen socket if the connection wasn't
    // accepted yet, or a connection socket if it was. Note that this
    // means the references to this descriptor must be removed from
    // the peer's accept queue if it's freed abruptly.
    Desc *peer;

    // Bytes received from/about to get sent to the peer
    SocketQueue *input;
    SocketQueue *output;

    /////////////////////////////////////////
    // File fields

    MockFS_OpenFile file;

    /////////////////////////////////////////
    // Directory fields

    MockFS_OpenDir dir;

    /////////////////////////////////////////
};

/////////////////////////////////////////////////////////////////
// Host Type

#define HOST_ADDR_LIMIT 2
#define HOST_DESC_LIMIT 1024
#define HOST_ARGC_LIMIT 128

typedef struct Sim Sim;

enum {
    HOST_ERROR_OTHER   = -1,
    HOST_ERROR_FULL    = -2,
    HOST_ERROR_BADIDX  = -3,
    HOST_ERROR_NOTSOCK = -4,
    HOST_ERROR_CANTBIND = -5,
    HOST_ERROR_NOTAVAIL = -6,
    HOST_ERROR_ADDRUSED = -7,
    HOST_ERROR_BADARG   = -8,
    HOST_ERROR_BADFAM   = -9,
    HOST_ERROR_RESET    = -10,
    HOST_ERROR_HANGUP   = -11,
    HOST_ERROR_NOTCONN  = -12,
    HOST_ERROR_IO       = -13,
    HOST_ERROR_ISDIR    = -14,
    HOST_ERROR_WOULDBLOCK = -15,
    HOST_ERROR_NOMEM    = -16,
    HOST_ERROR_NOENT    = -17,
    HOST_ERROR_NOTEMPTY = -18,
    HOST_ERROR_EXIST    = -19,
    HOST_ERROR_EXISTS   = -19,  // Alias for HOST_ERROR_EXIST
    HOST_ERROR_PERM     = -20,
    HOST_ERROR_NOTDIR   = -21,
    HOST_ERROR_NOSPC    = -22,
    HOST_ERROR_BUSY     = -23,
    HOST_ERROR_BADF     = -24,
};

// lseek whence values for host_lseek
enum {
    HOST_SEEK_SET = 0,
    HOST_SEEK_CUR = 1,
    HOST_SEEK_END = 2,
};

enum {
    HOST_FLAG_NONBLOCK = 1,
};

struct Host {

    // Pointer to the parent simulation object
    Sim *sim;

    char *name;

    // Platform used by this host
    QuakeyPlatform platform;

    // State of the ephimeral port allocation
    u16 next_ephemeral_port;

    // Dynamic dopy of the argument string used
    // to setup this host. Null bytes were injected
    // to terminate each argument
    char *arg;

    // Pointers into the argument string to make
    // a list of individual arguments
    int   argc;
    char *argv[HOST_ARGC_LIMIT];

    // Opaque program state
    void *state;
    int   state_size;

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Descriptor table
    int  num_desc;
    Desc desc[HOST_DESC_LIMIT];

    // Addresses bound to this host
    Addr addrs[HOST_ADDR_LIMIT];
    int  num_addrs;

    // Argument for poll()
    void*         poll_ctxs[HOST_DESC_LIMIT];
    struct pollfd poll_array[HOST_DESC_LIMIT];
    int           poll_count;
    int           poll_timeout;

    b32 timedout;
    b32 blocked;

    // Current error number set by system call mocks
    int errno_;

    // Raw disk bytes
    int   disk_size;
    char *disk_data;

    // MockFS instance managing the disk bytes
    MockFS *mfs;
};

typedef struct {
    char name[256];
    bool is_dir;
} DirEntry;

typedef struct {
    int64_t size;
    bool    is_dir;
} FileInfo;

/////////////////////////////////////////////////////////////////
// Simulation Type

typedef enum {
    EVENT_TYPE_CONNECT,
    EVENT_TYPE_DISCONNECT,
    EVENT_TYPE_DATA,
    EVENT_TYPE_WAKEUP,
} TimeEventType;

typedef struct {

    TimeEventType type;

    // Time when the event should happen
    Nanos time;

    // When type=WAKEUP, refers to the host that needs
    // to be woken up
    Host *host;

    // When type=CONNECT or type=DATA, refers to the
    // descriptor that initiated the connection
    Desc *src_desc;

    // When type=DISCONNECT, refers to the descriptor
    // that is receiving the disconnection message
    Desc *dst_desc;

    // When type=DATA, this refers to the output buffer
    // of the socket sending the data. The count variable
    // dictates how many bytes can be read from the queue
    //
    // The queue pointer is reference counted to allow
    // descriptors to be deinitialized without creating
    // dangling DATA events
    int          data_count;
    SocketQueue *data_queue;

    // If set, the DISCONNECT event is to be intended as
    // a forceful shutdown
    b32 rst;
} TimeEvent;

struct Sim {

    uint64_t seed;

    // Current simulated time in nanoseconds
    Nanos current_time;

    // List of simulated hosts. It's an array of pointers
    // so that host structures are not moved when the array
    // is resized. This allows safely holding references to
    // hosts.
    int num_hosts;
    int max_hosts;
    Host **hosts;

    // Array of timed events
    int num_events;
    int max_events;
    TimeEvent *events;
};

static void time_event_wakeup(Sim *sim, Nanos time, Host *host);
static void time_event_connect(Sim *sim, Nanos time, Desc *desc);
static void time_event_disconnect(Sim *sim, Nanos time, Desc *desc, b32 rst);
static void time_event_send_data(Sim *sim, Nanos time, Desc *desc);
static void remove_events_targeting_desc(Sim *sim, Desc *desc);

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////
// Address Code

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static int parse_ipv4(char *src, int len, int *pcur, AddrIPv4 *ipv4)
{
    int cur = *pcur;

	unsigned int out = 0;
	int i = 0;
	for (;;) {

		if (cur == len || !is_digit(src[cur]))
			return -1;

		int b = 0;
		do {
			int x = src[cur++] - '0';
			if (b > (UINT8_MAX - x) / 10)
				return -1;
			b = b * 10 + x;
		} while (cur < len && is_digit(src[cur]));

		out <<= 8;
		out |= (unsigned char) b;

		i++;
		if (i == 4)
			break;

		if (cur == len || src[cur] != '.')
			return -1;
		cur++;
	}

	ipv4->data = out;

	*pcur = cur;
	return 0;
}

static int hex_digit_to_int(char c)
{
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= '0' && c <= '9') return c - '0';
	return -1;
}

static int parse_ipv6_comp(char *src, int len, int *pcur)
{
    int cur = *pcur;

	unsigned short buf;
	if (cur == len || !is_hex_digit(src[cur]))
		return -1;
	buf = hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	if (cur == len || !is_hex_digit(src[cur])) {
	    *pcur = cur;
		return buf;
	}
	buf <<= 4;
	buf |= hex_digit_to_int(src[cur]);
	cur++;

	*pcur = cur;
	return (int) buf;
}

static int parse_ipv6(char *src, int len, int *pcur, AddrIPv6 *ipv6)
{
    int cur = *pcur;

	unsigned short head[8];
	unsigned short tail[8];
	int head_len = 0;
	int tail_len = 0;

	if (len - cur > 1
		&& src[cur+0] == ':'
		&& src[cur+1] == ':')
		cur += 2;
	else {

		for (;;) {

			int ret = parse_ipv6_comp(src, len, &cur);
			if (ret < 0) return ret;

			head[head_len++] = (unsigned short) ret;
			if (head_len == 8) break;

			if (cur == len || src[cur] != ':')
				return -1;
			cur++;

			if (cur < len && src[cur] == ':') {
				cur++;
				break;
			}
		}
	}

	if (head_len < 8) {
		while (cur < len && is_hex_digit(src[cur])) {

			int ret = parse_ipv6_comp(src, len, &cur);
			if (ret < 0) return ret;

			tail[tail_len++] = (unsigned short) ret;
			if (head_len + tail_len == 8) break;

			if (cur == len || src[cur] != ':')
				break;
			cur++;
		}
	}

	for (int i = 0; i < head_len; i++)
		ipv6->data[i] = head[i];

	for (int i = 0; i < 8 - head_len - tail_len; i++)
		ipv6->data[head_len + i] = 0;

	for (int i = 0; i < tail_len; i++)
		ipv6->data[8 - tail_len + i] = tail[i];

	*pcur = cur;
	return 0;
}

static int addr_parse(char *src, Addr *dst)
{
    int cur = 0;
    int len = strlen(src);

    if (parse_ipv4(src, len, &cur, &dst->ipv4) == 0) {
        dst->family = ADDR_FAMILY_IPV4;
        return 0;
    }

    cur = 0;
    if (parse_ipv6(src, len, &cur, &dst->ipv6) == 0) {
        dst->family = ADDR_FAMILY_IPV6;
        return 0;
    }

    return -1;
}

static bool addr_eql(Addr a1, Addr a2)
{
    if (a1.family != a2.family)
        return false;
    if (a1.family == ADDR_FAMILY_IPV4)
        return !memcmp(&a1.ipv4, &a2.ipv4, sizeof(AddrIPv4));
    ASSERT(a1.family == ADDR_FAMILY_IPV6);
    return !memcmp(&a1.ipv6, &a2.ipv6, sizeof(AddrIPv6));
}

static bool is_zero_addr(Addr addr)
{
    char *p;
    int   n;
    if (addr.family == ADDR_FAMILY_IPV4) {
        p = (char*) &addr.ipv4;
        n = sizeof(addr.ipv4);
    } else {
        ASSERT(addr.family == ADDR_FAMILY_IPV6);
        p = (char*) &addr.ipv6;
        n = sizeof(addr.ipv6);
    }
    for (int i = 0; i < n; i++) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

/////////////////////////////////////////////////////////////////
// Socket Queue Code

static SocketQueue *socket_queue_init(int size)
{
    void *mem = malloc(sizeof(SocketQueue) + size);
    if (mem == NULL) {
        TODO;
    }
    SocketQueue *queue = mem;
    queue->head = 0;
    queue->used = 0;
    queue->size = size;
    queue->data = (char*) (queue + 1);
    queue->refs = 1;
    return queue;
}

static SocketQueue *socket_queue_ref(SocketQueue *queue)
{
    queue->refs++;
    return queue;
}

static void socket_queue_unref(SocketQueue *queue)
{
    ASSERT(queue->refs > 0);
    queue->refs--;
    if (queue->refs == 0)
        free(queue);
}

static char *socket_queue_read_buf(SocketQueue *queue, int *num)
{
    *num = queue->used;
    return queue->data + queue->head;
}

static void socket_queue_read_ack(SocketQueue *queue, int num)
{
    queue->head += num;
    queue->used -= num;
}

static int socket_queue_read(SocketQueue *queue, char *dst, int max)
{
    int num;
    char *src = socket_queue_read_buf(queue, &num);

    int copy = max;
    if (copy > num)
        copy = num;
    memcpy(dst, src, copy);

    socket_queue_read_ack(queue, copy);
    return copy;
}

static char *socket_queue_write_buf(SocketQueue *queue, int *cap)
{
    // Only write up to the free space
    if (*cap > queue->size - queue->used)
        *cap = queue->size - queue->used;

    int last = queue->head + queue->used;
    if (queue->size - last < *cap) {
        memmove(queue->data, queue->data + queue->head, queue->used);
        queue->head = 0;
    }

    return queue->data + queue->head + queue->used;
}

static void socket_queue_write_ack(SocketQueue *queue, int num)
{
    queue->used += num;
}

static int socket_queue_write(SocketQueue *queue, char *src, int len)
{
    char *dst = socket_queue_write_buf(queue, &len);
    memcpy(dst, src, len);
    socket_queue_write_ack(queue, len);
    return len;
}

static int socket_queue_move(SocketQueue *dst_queue, SocketQueue *src_queue, int max)
{
    int srclen;
    char *src = socket_queue_read_buf(src_queue, &srclen);

    if (srclen > max)
        srclen = max;

    int dstlen = srclen;
    char *dst = socket_queue_write_buf(dst_queue, &dstlen);

    memcpy(dst, src, dstlen);

    socket_queue_write_ack(dst_queue, dstlen);
    socket_queue_read_ack(src_queue, dstlen);
    return dstlen;
}

static b32 socket_queue_full(SocketQueue *queue)
{
    return queue->used == queue->size;
}

static b32 socket_queue_empty(SocketQueue *queue)
{
    return queue->used == 0;
}

static b32 socket_queue_used(SocketQueue *queue)
{
    return queue->used;
}

/////////////////////////////////////////////////////////////////
// Accept Queue Code

static int accept_queue_init(AcceptQueue *queue, int capacity)
{
    Desc **entries = malloc(capacity * sizeof(Desc*));
    if (entries == NULL)
        return -1;
    queue->head = 0;
    queue->count = 0;
    queue->capacity = capacity;
    queue->entries = entries;
    return 0;
}

static void accept_queue_free(AcceptQueue *queue)
{
    free(queue->entries);
}

static Desc **accept_queue_peek(AcceptQueue *queue, int idx)
{
    if (idx >= queue->count)
        return NULL;
    return &queue->entries[(queue->head + idx) % queue->capacity];
}

static void accept_queue_remove(AcceptQueue *queue, Desc *desc)
{
    int i = 0;
    while (i < queue->count && desc != *accept_queue_peek(queue, i))
        i++;

    if (i == queue->count)
        return; // Not found

    while (i < queue->count-1) {
        *accept_queue_peek(queue, i) = *accept_queue_peek(queue, i+1);
        i++;
    }

    queue->count--;
}

static int accept_queue_push(AcceptQueue *queue, Desc *desc)
{
    if (queue->count == queue->capacity)
        return -1;
    int tail = (queue->head + queue->count) % queue->capacity;
    queue->entries[tail] = desc;
    queue->count++;
    return 0;
}

static int accept_queue_pop(AcceptQueue *queue, Desc **desc)
{
    if (queue->count == 0)
        return -1;
    *desc = queue->entries[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    return 0;
}

static bool accept_queue_empty(AcceptQueue *queue)
{
    return queue->count == 0;
}

/////////////////////////////////////////////////////////////////
// Descriptor Code

// If the descriptor is a connection socket and rst=true,
// the peer connection will be marked as "reset" instead
// of simply closed.
static void desc_free(Sim *sim, Desc *desc, bool rst)
{
    switch (desc->type) {
    case DESC_EMPTY:
        break;
    case DESC_SOCKET:
        break;
    case DESC_SOCKET_L:
        // Update the other ends of the connections waiting to be accepted
        for (int i = 0; i < desc->accept_queue.count; i++) {
            Desc *peer = *accept_queue_peek(&desc->accept_queue, i);
            peer->peer = NULL;
            peer->connect_status = CONNECT_STATUS_RESET;
        }
        accept_queue_free(&desc->accept_queue);
        break;
    case DESC_PIPE:
    case DESC_SOCKET_C:
        // Remove any pending events targeting this descriptor before freeing it
        if (sim)
            remove_events_targeting_desc(sim, desc);
        if (desc->peer) {
            // A connection was previously established.
            // We need to update the other end of the connection.
            Desc *peer = desc->peer;
            if (peer->type == DESC_SOCKET_L) {
                // Connection was waiting to be accepted
                accept_queue_remove(&peer->accept_queue, desc);
            } else {
                ASSERT(peer->type == DESC_SOCKET_C || peer->type == DESC_PIPE);
                peer->peer = NULL;
                peer->connect_status = rst ? CONNECT_STATUS_RESET : CONNECT_STATUS_CLOSE;
            }
        }
        socket_queue_unref(desc->input);
        socket_queue_unref(desc->output);
        break;
    case DESC_FILE:
        mockfs_close_file(&desc->file);
        break;
    case DESC_DIRECTORY:
        mockfs_close_dir(&desc->dir);
        break;
    default:
        UNREACHABLE;
        break;
    }
    desc->type = DESC_EMPTY;
}

/////////////////////////////////////////////////////////////////
// Host Code

// Backlog size used by listen() when the provided
// backlog argument is non-positive
#define DEFAULT_BACKLOG 128

#define FIRST_EPHEMERAL_PORT 10000
#define LAST_EPHEMERAL_PORT  50000

// Current schedulated host
static Host *host___;

int errno___;

static uint64_t sim_random(Sim *sim);

static void abort_(char *str)
{
#ifdef _WIN32
    WriteFile(GetStdHandle((DWORD)-11), str, strlen(str), NULL, NULL);
#else
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (1),
          "D" (1),
          "S" (str),
          "d" (strlen(str))
        : "rcx", "r11", "memory"
    );
    (void) ret;
#endif
    __builtin_trap();
}

static int split_args(char *arg, char **argv, int max_argc)
{
    int argc = 0;
    for (int cur = 0, len = strlen(arg);; ) {

        while (cur < len && (arg[cur] == ' ' || arg[cur] == '\t'))
            cur++;

        if (cur == len)
            break;

        int off = cur;

        while (cur < len && arg[cur] != ' ' && arg[cur] != '\t')
            cur++;

        if (cur < len) {
            arg[cur] = '\0';
            cur++;
        }

        if (argc == max_argc)
            return -1;
        argv[argc++] = arg + off;
    }

    return argc;
}

static void host_init(Host *host, Sim *sim, QuakeySpawn config, char *arg)
{
    host->sim = sim;
    host->name = config.name;
    host->platform = config.platform;
    host->next_ephemeral_port = FIRST_EPHEMERAL_PORT;

    int arg_len = strlen(arg);
    host->arg = malloc(arg_len+1);
    if (host->arg == NULL) {
        TODO;
    }
    memcpy(host->arg, arg, arg_len+1); // +1 for \0

    host->argc = split_args(host->arg, host->argv, HOST_ARGC_LIMIT);
    if (host->argc < 0) {
        TODO;
    }

    if (config.num_addrs > HOST_ADDR_LIMIT) {
        TODO;
    }
    for (int i = 0; i < config.num_addrs; i++) {
        if (addr_parse(config.addrs[i], &host->addrs[i]) < 0) {
            TODO;
        }
    }
    host->num_addrs = config.num_addrs;

    host->state_size = config.state_size;
    host->state = malloc(config.state_size);
    if (host->state == NULL) {
        TODO;
    }

    host->init_func = config.init_func;
    host->tick_func = config.tick_func;
    host->free_func = config.free_func;

    host->num_desc = 0;
    for (int i = 0; i < HOST_DESC_LIMIT; i++) {
        host->desc[i].host = host;
        host->desc[i].type = DESC_EMPTY;
    }

    host->errno_ = 0;

    host->disk_size = config.disk_size;
    host->disk_data = malloc(config.disk_size);
    if (host->disk_data == NULL) {
        TODO;
    }
    // Zero out memory to make sure operations are deterministic
    memset(host->disk_data, 0, config.disk_size);

    int ret = mockfs_init(&host->mfs, host->disk_data, config.disk_size);
    if (ret < 0) {
        TODO;
    }

    host->timedout = false;
    host->blocked = false;
    host->poll_count = 0;
    host->poll_timeout = -1;

    host___ = host;
    ret = config.init_func(
        host->state,
        host->argc,
        host->argv,
        host->poll_ctxs,
        host->poll_array,
        HOST_DESC_LIMIT,
        &host->poll_count,
        &host->poll_timeout
    );
    host___ = NULL;
    if (ret < 0) {
        // TODO: if the node fails to initialize the simulation should continue
        //       running without it
        TODO;
    }

    if (host->poll_timeout > 0)
        time_event_wakeup(host->sim, host->sim->current_time + (Nanos)host->poll_timeout * 1000000ULL, host);
    else if (host->poll_timeout == 0)
        host->timedout = true;  // Immediate timeout, don't create event at current_time
}

static void host_free(Host *host)
{
    host___ = host;
    int ret = host->free_func(host->state);
    host___ = NULL;
    if (ret < 0) {
        TODO;
    }

    mockfs_free(host->mfs);
    free(host->disk_data);

    for (int i = 0; i < HOST_DESC_LIMIT; i++) {
        if (host->desc[i].type != DESC_EMPTY)
            desc_free(host->sim, &host->desc[i], true);
    }

    free(host->state);
    free(host->arg);
}

static b32 host_is_linux(Host *host)
{
    return host->platform == QUAKEY_LINUX;
}

static b32 host_is_windows(Host *host)
{
    return host->platform == QUAKEY_WINDOWS;
}

static Nanos host_time(Host *host)
{
    return host->sim->current_time;
}

static int *host_errno_ptr(Host *host)
{
    return &host->errno_;
}

static bool is_connected_and_accepted(Desc *desc)
{
    assert(desc->type == DESC_SOCKET_C);
    return desc->peer && desc->peer->type != DESC_SOCKET_L;
}

static bool is_desc_idx_valid(Host *host, int desc_idx);

static bool host_ready(Host *host)
{
    if (host->blocked)
        return false;

    if (host->timedout)
        return true;

    // Check if any polled descriptors have pending events
    for (int i = 0; i < host->poll_count; i++) {

        int fd = host->poll_array[i].fd;
        int events = host->poll_array[i].events;

        if (!is_desc_idx_valid(host, fd))
            continue;

        Desc *desc = &host->desc[fd];

        switch (desc->type) {
        case DESC_SOCKET_L:
            if (events & POLLIN) {
                if (!accept_queue_empty(&desc->accept_queue))
                    return true;
            }
            break;
        case DESC_PIPE:
        case DESC_SOCKET_C:
            if (desc->connect_status == CONNECT_STATUS_NOHOST ||
                desc->connect_status == CONNECT_STATUS_RESET)
                return true;
            if (events & POLLIN) {
                if (!socket_queue_empty(desc->input)
                    || desc->connect_status == CONNECT_STATUS_RESET
                    || desc->connect_status == CONNECT_STATUS_CLOSE)
                    return true;
            }
            if (events & POLLOUT) {
                if (!socket_queue_full(desc->output) && is_connected_and_accepted(desc))
                    return true;
            }
            break;
        case DESC_FILE:
        case DESC_DIRECTORY:
            // Files and directories are always ready
            if (events & (POLLIN | POLLOUT))
                return true;
            break;
        default:
            UNREACHABLE;
            break;
        }
    }

    return false;
}

static void set_revents_in_poll_array(Host *host)
{
    for (int i = 0; i < host->poll_count; i++) {

        int fd = host->poll_array[i].fd;
        int events = host->poll_array[i].events;

        if (!is_desc_idx_valid(host, fd))
            continue; // TODO: is this ok?
        Desc *desc = &host->desc[fd];

        int revents = 0;
        switch (desc->type) {
        case DESC_SOCKET:
            // TODO
            break;
        case DESC_SOCKET_L:
            if (events & POLLIN) {
                if (!accept_queue_empty(&desc->accept_queue))
                    revents = POLLIN;
            }
            break;
        case DESC_PIPE:
        case DESC_SOCKET_C:
            if (desc->connect_status == CONNECT_STATUS_NOHOST ||
                desc->connect_status == CONNECT_STATUS_RESET)
                revents |= POLLERR;
            if (events & POLLIN) {
                // TODO: should report prover events when hup and rst are set
                if (!socket_queue_empty(desc->input))
                    revents |= POLLIN;
                if (desc->connect_status == CONNECT_STATUS_RESET ||
                    desc->connect_status == CONNECT_STATUS_CLOSE)
                    revents |= POLLIN;
            }
            if (events & POLLOUT) {
                if (!socket_queue_full(desc->output) && is_connected_and_accepted(desc))
                    revents |= POLLOUT;
            }
            break;
        case DESC_FILE:
            if (events & POLLIN) {
                revents |= POLLIN;
            }
            if (events & POLLOUT) {
                revents |= POLLOUT;
            }
            break;
        case DESC_DIRECTORY:
            if (events & POLLIN) {
                revents |= POLLIN;
            }
            if (events & POLLOUT) {
                revents |= POLLOUT;
            }
            break;
        default:
            UNREACHABLE;
        }

        host->poll_array[i].revents = revents;
    }
}

static void host_update(Host *host)
{
    host->timedout = false;
    set_revents_in_poll_array(host);
    host___ = host;
    int ret = host->tick_func(
        host->state,
        host->poll_ctxs,
        host->poll_array,
        HOST_DESC_LIMIT,
        &host->poll_count,
        &host->poll_timeout
    );
    host___ = NULL;
    if (ret < 0) {
        TODO;
    }

    if (host->poll_timeout > 0)
        time_event_wakeup(host->sim, host->sim->current_time + (Nanos)host->poll_timeout * 1000000ULL, host);
    else if (host->poll_timeout == 0)
        host->timedout = true;  // Immediate timeout, don't create event at current_time
}

static bool host_has_addr(Host *host, Addr addr)
{
    for (int i = 0; i < host->num_addrs; i++) {
        if (addr_eql(host->addrs[i], addr))
            return true;
    }
    return false;
}

// Returns true if the descriptor is a socket bound
// (implicitly or explicitly) to an address
static bool is_bound(Desc *desc)
{
    if (desc->type == DESC_SOCKET)
        return desc->is_explicitly_bound;

    if (desc->type == DESC_SOCKET_C ||
        desc->type == DESC_SOCKET_L)
        return true;

    return false;
}

// Note that this is assumed to work on empty
// descriptors too
static bool is_bound_to(Desc *desc, Addr addr, uint16_t port)
{
    if (!is_bound(desc))
        return false;

    if (!is_zero_addr(desc->bound_addr) && !addr_eql(addr, desc->bound_addr))
        return false;

    if (port != desc->bound_port)
        return false;

    return true;
}

static Desc *host_find_desc_bound_to(Host *host, Addr addr, uint16_t port)
{
    for (int i = 0, j = 0; j < host->num_desc; i++) {

        Desc *desc = &host->desc[i];
        if (desc->type == DESC_EMPTY)
            continue;
        j++;

        if (is_bound_to(desc, addr, port))
            return desc;
    }

    return NULL;
}

static int find_empty_desc_struct(Host *host)
{
    if (host->num_desc == HOST_DESC_LIMIT)
        return -1;

    int i = 0;
    while (host->desc[i].type != DESC_EMPTY) {
        i++;
        ASSERT(i < HOST_DESC_LIMIT);
    }

    return i;
}

static int host_create_socket(Host *host, AddrFamily family)
{
    int desc_idx = find_empty_desc_struct(host);
    if (desc_idx < 0)
        return HOST_ERROR_FULL;
    Desc *desc = &host->desc[desc_idx];

    desc->type = DESC_SOCKET;
    desc->non_blocking = false;
    desc->is_explicitly_bound = false;
    desc->bound_addr = (Addr) { .family=family };
    desc->bound_port = 0;

    host->num_desc++;
    return desc_idx;
}

static int host_create_pipe(Host *host, int *desc_idxs)
{
    int desc_idx_1 = find_empty_desc_struct(host);
    if (desc_idx_1 < 0)
        return HOST_ERROR_FULL;
    Desc *desc_1 = &host->desc[desc_idx_1];

    int desc_idx_2 = find_empty_desc_struct(host);
    if (desc_idx_2 < 0)
        return HOST_ERROR_FULL;
    Desc *desc_2 = &host->desc[desc_idx_2];

    desc_1->type = DESC_PIPE;
    desc_1->non_blocking = false;
    desc_1->connect_status = CONNECT_STATUS_DONE;
    desc_1->peer = desc_2;
    desc_1->input = socket_queue_init(1<<12);
    desc_1->output = socket_queue_init(1<<12);

    desc_2->type = DESC_PIPE;
    desc_2->non_blocking = false;
    desc_2->connect_status = CONNECT_STATUS_DONE;
    desc_2->peer = desc_1;
    desc_2->input = socket_queue_init(1<<12);
    desc_2->output = socket_queue_init(1<<12);

    desc_idxs[0] = desc_idx_1;
    desc_idxs[1] = desc_idx_2;

    host->num_desc += 2;
    return 0;
}

static bool is_desc_idx_valid(Host *host, int desc_idx)
{
    // Out of bounds
    if (desc_idx < 0 || desc_idx >= HOST_DESC_LIMIT)
        return false;

    // Not in use
    if (host->desc[desc_idx].type == DESC_EMPTY)
        return false;

    return true;
}

static bool is_socket(Desc *desc)
{
    return desc->type == DESC_SOCKET
        || desc->type == DESC_SOCKET_L
        || desc->type == DESC_SOCKET_C;
}

static int host_close(Host *host, int desc_idx, bool expect_socket)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;

    if (expect_socket) {
        if (!is_socket(&host->desc[desc_idx]))
            return HOST_ERROR_NOTSOCK;
    }

    if (host->desc[desc_idx].type == DESC_SOCKET_C)
        time_event_disconnect(host->sim, host->sim->current_time + 10000000, &host->desc[desc_idx], false);

    desc_free(host->sim, &host->desc[desc_idx], false);
    host->num_desc--;
    return 0;
}

static bool interf_exists_locally(Host *host, Addr addr)
{
    for (int i = 0; i < host->num_addrs; i++)
        if (addr_eql(host->addrs[i], addr))
            return true;
    return false;
}

static bool addr_in_use(Host *host, Addr addr, uint16_t port)
{
    ASSERT(port != 0);

    if (is_zero_addr(addr)) {
        // Any address may conflict with the zero address,
        // which means we only need to compare ports.
        for (int i = 0; i < HOST_DESC_LIMIT; i++) {
            if (is_socket(&host->desc[i])) {
                if (host->desc[i].bound_port == port)
                    return true;
            }
        }
    } else {
        for (int i = 0; i < HOST_DESC_LIMIT; i++) {
            if (is_bound_to(&host->desc[i], addr, port))
                return true;
        }
    }

    return false;
}

// Returns 0 on error
static uint16_t choose_ephemeral_port(Host *host, Addr addr)
{
    uint16_t first = host->next_ephemeral_port;
    uint16_t *next = &host->next_ephemeral_port;
    do {
        uint16_t port = *next;
        if (*next == LAST_EPHEMERAL_PORT) {
            *next = FIRST_EPHEMERAL_PORT;
        } else {
            (*next)++;
        }
        if (!addr_in_use(host, addr, port))
            return port;
    } while (*next != first);
    return 0;
}

static int host_bind(Host *host, int desc_idx, Addr addr, uint16_t port)
{
    /////////////////////////////////////////////////////////
    // Check index

    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    /////////////////////////////////////////////////////////
    // Check descriptor

    if (!is_socket(desc))
        return HOST_ERROR_NOTSOCK;

    if (host->desc[desc_idx].type != DESC_SOCKET)
        return HOST_ERROR_CANTBIND;

    if (desc->is_explicitly_bound)
        return HOST_ERROR_CANTBIND;

    /////////////////////////////////////////////////////////
    // Check address

    if (addr.family != desc->bound_addr.family)
        return HOST_ERROR_BADFAM;

    if (!is_zero_addr(addr)) {
        if (!interf_exists_locally(host, addr))
            return HOST_ERROR_NOTAVAIL;
    }

    /////////////////////////////////////////////////////////
    // Check port

    if (port == 0) {
        port = choose_ephemeral_port(host, addr);
        if (port == 0)
            return HOST_ERROR_NOTAVAIL;
    } else {
        if (addr_in_use(host, addr, port))
            return HOST_ERROR_ADDRUSED;
    }

    /////////////////////////////////////////////////////////
    // Perform the binding

    desc->is_explicitly_bound = true;
    desc->bound_addr = addr;
    desc->bound_port = port;

    /////////////////////////////////////////////////////////
    return 0;
}

static int host_listen(Host *host, int desc_idx, int backlog)
{
    if (backlog <= 0)
        backlog = DEFAULT_BACKLOG;

    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return HOST_ERROR_BADARG;
        return HOST_ERROR_NOTSOCK;
    }

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephemeral_port(host, desc->bound_addr);
        if (desc->bound_port == 0)
            return HOST_ERROR_ADDRUSED;
    }

    if (accept_queue_init(&desc->accept_queue, backlog) < 0) {
        TODO;
    }

    desc->type = DESC_SOCKET_L;
    return 0;
}

static int host_accept(Host *host, int desc_idx, Addr *addr, uint16_t *port)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_SOCKET_L) {
        if (is_socket(desc))
            return HOST_ERROR_BADARG;
        return HOST_ERROR_NOTSOCK;
    }

    if (!desc->non_blocking)
        abort_("Socket not configured as non-blocking before accept()\n");

    int new_desc_idx = find_empty_desc_struct(host);
    if (new_desc_idx < 0)
        return HOST_ERROR_FULL;
    Desc *new_desc = &host->desc[new_desc_idx];

    Desc *peer;
    if (accept_queue_pop(&desc->accept_queue, &peer) < 0)
        return HOST_ERROR_WOULDBLOCK;

    *addr = peer->bound_addr;
    *port = peer->bound_port;

    Addr local_addr = desc->bound_addr;
    if (is_zero_addr(local_addr)) {
        assert(host->num_addrs > 0);
        local_addr = host->addrs[0];
    }

    new_desc->type = DESC_SOCKET_C;
    new_desc->non_blocking = false;
    new_desc->bound_addr = local_addr;
    new_desc->bound_port = desc->bound_port;
    new_desc->connect_addr = peer->bound_addr;
    new_desc->connect_port = peer->bound_port;
    new_desc->connect_status = CONNECT_STATUS_DONE;
    new_desc->peer = peer;
    new_desc->input = socket_queue_init(1<<12);
    new_desc->output = socket_queue_init(1<<12);

    // Update the peer's end of the connection
    peer->peer = new_desc;

    host->num_desc++;
    return new_desc_idx;
}

// TODO: check error codes returned by this function
static int host_connect(Host *host, int desc_idx,
    Addr addr, uint16_t port)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_SOCKET) {
        if (is_socket(desc))
            return HOST_ERROR_BADARG;
        return HOST_ERROR_NOTSOCK;
    }

    if (!desc->non_blocking)
        abort_("Socket not configured as non-blocking before connect()\n");

    if (!desc->is_explicitly_bound) {
        // We need to bind implicitly
        //
        // The bound_addr field already contains the right
        // family and a zero address. The port is 0, which
        // is not a valid value.
        desc->bound_port = choose_ephemeral_port(host, desc->bound_addr);
        if (desc->bound_port == 0)
            return HOST_ERROR_ADDRUSED;
    }

    // TODO: some percent of times connect() should resolve immediately

    Nanos latency = 10000000;
#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    latency = 1000000 + (rng % 99000000); // between 1ms and 100ms
#endif

    time_event_connect(host->sim, host->sim->current_time + latency, desc);

    desc->connect_addr = addr;
    desc->connect_port = port;
    desc->connect_status = CONNECT_STATUS_WAIT;
    desc->peer = NULL;
    desc->input = socket_queue_init(1<<12);
    desc->output = socket_queue_init(1<<12);

    desc->type = DESC_SOCKET_C;
    return 0;
}

static int host_connect_status(Host *host, int desc_idx, ConnectStatus *status)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_SOCKET_C) {
        if (is_socket(desc))
            return HOST_ERROR_BADARG;
        return HOST_ERROR_NOTSOCK;
    }

    if (status)
        *status = desc->connect_status;
    return 0;
}

static int mockfs_to_quakey_error(int err)
{
    switch (err) {
        case 0: return 0;
        case MOCKFS_ERRNO_NOENT    : return HOST_ERROR_NOENT;
        case MOCKFS_ERRNO_PERM     : return HOST_ERROR_PERM;
        case MOCKFS_ERRNO_NOMEM    : return HOST_ERROR_NOMEM;
        case MOCKFS_ERRNO_NOTDIR   : return HOST_ERROR_NOTDIR;
        case MOCKFS_ERRNO_ISDIR    : return HOST_ERROR_ISDIR;
        case MOCKFS_ERRNO_INVAL    : return HOST_ERROR_BADARG;
        case MOCKFS_ERRNO_NOTEMPTY : return HOST_ERROR_NOTEMPTY;
        case MOCKFS_ERRNO_NOSPC    : return HOST_ERROR_NOSPC;
        case MOCKFS_ERRNO_EXIST    : return HOST_ERROR_EXIST;
        case MOCKFS_ERRNO_BUSY     : return HOST_ERROR_BUSY;
        case MOCKFS_ERRNO_BADF     : return HOST_ERROR_BADF;
        default:
        printf("Unexpected mockfs errno %d\n", err);
        assert(0);
    }
}

static int host_open_file(Host *host, char *path, int flags)
{
    int desc_idx = find_empty_desc_struct(host);
    if (desc_idx < 0)
        return HOST_ERROR_FULL;
    Desc *desc = &host->desc[desc_idx];

    int ret = mockfs_open(host->mfs, path, strlen(path), flags, &desc->file);
    if (ret < 0)
        return mockfs_to_quakey_error(ret);

    desc->type = DESC_FILE;
    desc->non_blocking = false;

    host->num_desc++;
    return desc_idx;
}

static int host_open_dir(Host *host, char *path)
{
    int desc_idx = find_empty_desc_struct(host);
    if (desc_idx < 0)
        return HOST_ERROR_FULL;
    Desc *desc = &host->desc[desc_idx];

    int ret = mockfs_open_dir(host->mfs, path, strlen(path), &desc->dir);
    if (ret < 0)
        return mockfs_to_quakey_error(ret);

    desc->type = DESC_DIRECTORY;
    desc->non_blocking = false;

    host->num_desc++;
    return desc_idx;
}

static int host_read_dir(Host *host, int desc_idx, DirEntry *entry)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_DIRECTORY)
        return HOST_ERROR_BADARG;

    MockFS_Dirent buf;
    int ret = mockfs_read_dir(&desc->dir, &buf);
    if (ret < 0) {
        if (ret == MOCKFS_ERRNO_NOENT)
            return 0;
        return mockfs_to_quakey_error(ret);
    }

    // Copy entry information
    int i = 0;
    while (i < buf.name_len && i < 255) {
        entry->name[i] = buf.name[i];
        i++;
    }
    entry->name[i] = '\0';
    entry->is_dir = buf.is_dir;

    return 1;
}

static int recv_inner(Desc *desc, char *dst, int len)
{
    if (!desc->non_blocking)
        abort_("Socket not configured as non-blocking before recv()\n");

    if (desc->peer == NULL) {
        if (desc->connect_status == CONNECT_STATUS_RESET)
            return HOST_ERROR_RESET;
        if (desc->connect_status == CONNECT_STATUS_CLOSE)
            return HOST_ERROR_HANGUP;
        return HOST_ERROR_NOTCONN;
    }

    int ret = socket_queue_read(desc->input, dst, len);
    if (ret == 0)
        return HOST_ERROR_WOULDBLOCK;

    return ret;
}

static int send_inner(Desc *desc, char *src, int len)
{
    if (!desc->non_blocking)
        abort_("Socket not configured as non-blocking before send()\n");

    if (desc->peer == NULL) {
        if (desc->connect_status == CONNECT_STATUS_RESET)
            return HOST_ERROR_RESET;
        if (desc->connect_status == CONNECT_STATUS_CLOSE)
            return HOST_ERROR_HANGUP;
        return HOST_ERROR_NOTCONN;
    }

    int ret = socket_queue_write(desc->output, src, len);
    if (ret == 0)
        return HOST_ERROR_WOULDBLOCK;

    Nanos latency = 10000000;
#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    latency = 1000000 + (rng % 99000000); // between 1ms and 100ms
#endif
    time_event_send_data(desc->host->sim, desc->host->sim->current_time + latency, desc);

    return ret;
}

static int host_read(Host *host, int desc_idx, char *dst, int len)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    len = 1 + (rng % len);
#endif

    int num = 0;
    if (desc->type == DESC_SOCKET_C ||
        desc->type == DESC_PIPE) {
        num = recv_inner(desc, dst, len);
    } else if (desc->type == DESC_FILE) {
#ifdef FAULT_INJECTION
        uint64_t roll = sim_random(host->sim) % 1000;
        if (roll == 0) return HOST_ERROR_IO;
#endif
        int ret = mockfs_read(&desc->file, dst, len);
        if (ret < 0)
            return mockfs_to_quakey_error(ret);
#ifdef FAULT_INJECTION
        if (ret > 0) {
            // 1 in 10,000 reads gets a bit flip
            if ((sim_random(host->sim) % 10000) == 0) {
                int byte_idx = sim_random(host->sim) % ret;
                int bit_idx = sim_random(host->sim) % 8;
                dst[byte_idx] ^= (1 << bit_idx);
            }
        }
#endif
        num = ret;
    } else {
        if (desc->type == DESC_DIRECTORY)
            return HOST_ERROR_ISDIR;
        return HOST_ERROR_BADARG;
    }

    return num;
}

static int host_write(Host *host, int desc_idx, char *src, int len)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    len = 1 + (rng % len);
#endif

    int num = 0;
    if (desc->type == DESC_SOCKET_C ||
        desc->type == DESC_PIPE) {
        num = send_inner(desc, src, len);
    } else if (desc->type == DESC_FILE) {
#ifdef FAULT_INJECTION
        uint64_t roll = sim_random(host->sim) % 1000;
        if (roll == 0) return HOST_ERROR_IO;
        if (roll == 1) return HOST_ERROR_NOSPC;
#endif
#ifdef FAULT_INJECTION
        int byte_idx = -1;
        int bit_idx;
        if (len > 0) {
            // 1 in 100,000 reads gets a bit flip
            if ((sim_random(host->sim) % 100000) == 0) {
                byte_idx = sim_random(host->sim) % len;
                bit_idx = sim_random(host->sim) % 8;
                src[byte_idx] ^= (1 << bit_idx);
            }
        }
#endif
        int ret = mockfs_write(&desc->file, src, len);
#ifdef FAULT_INJECTION
        if (byte_idx > -1) {
            src[byte_idx] ^= (1 << bit_idx);
        }
#endif
        if (ret < 0)
            return mockfs_to_quakey_error(ret);
        num = ret;
    } else {
        return HOST_ERROR_BADIDX;
    }

    return num;
}

static int host_recv(Host *host, int desc_idx, char *dst, int len)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    len = 1 + (rng % len);
#endif

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = recv_inner(desc, dst, len);
    } else {
        if (!is_socket(desc))
            return HOST_ERROR_NOTSOCK;
        TODO;
    }

    return num;
}

static int host_send(Host *host, int desc_idx, char *src, int len)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

#ifdef FAULT_INJECTION
    Sim *sim = desc->host->sim;
    uint64_t rng = sim_random(sim);
    len = 1 + (rng % len);
#endif

    int num = 0;
    if (desc->type == DESC_SOCKET_C) {
        num = send_inner(desc, src, len);
    } else {
        TODO;
    }

    return num;
}

static int host_mkdir(Host *host, char *path)
{
    int ret = mockfs_mkdir(host->mfs, path, strlen(path));
    if (ret < 0)
        return mockfs_to_quakey_error(ret);
    return 0;
}

static int host_remove(Host *host, char *path)
{
    int ret = mockfs_remove(host->mfs, path, strlen(path), false);
    if (ret < 0)
        return mockfs_to_quakey_error(ret);
    return 0;
}

static int host_rename(Host *host, char *oldpath, char *newpath)
{
    int ret = mockfs_rename(host->mfs, oldpath, strlen(oldpath), newpath, strlen(newpath));
    if (ret < 0)
        return mockfs_to_quakey_error(ret);
    return 0;
}

static int host_fileinfo(Host *host, int desc_idx, FileInfo *info)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    switch (desc->type) {
    case DESC_FILE:
        {
            int size = mockfs_file_size(&desc->file);
            if (size < 0)
                return HOST_ERROR_IO;
            info->size = size;
            info->is_dir = false;
        }
        break;
    case DESC_DIRECTORY:
        {
            info->size = 0;
            info->is_dir = true;
        }
        break;
    default:
        return HOST_ERROR_BADIDX;
    }

    return 0;
}

static int host_lseek(Host *host, int desc_idx, int64_t offset, int whence)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_FILE)
        return HOST_ERROR_BADIDX;

    int lfs_whence;
    switch (whence) {
    case HOST_SEEK_SET:
        lfs_whence = MOCKFS_SEEK_SET;
        break;
    case HOST_SEEK_CUR:
        lfs_whence = MOCKFS_SEEK_CUR;
        break;
    case HOST_SEEK_END:
        lfs_whence = MOCKFS_SEEK_END;
        break;
    default:
        return HOST_ERROR_BADARG;
    }

    int ret = mockfs_lseek(&desc->file, offset, lfs_whence);
    if (ret < 0)
        return HOST_ERROR_BADARG;

    return ret;
}

static int host_fsync(Host *host, int desc_idx)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    if (desc->type != DESC_FILE)
        return HOST_ERROR_BADIDX;

#ifdef FAULT_INJECTION
    uint64_t roll = sim_random(host->sim) % 100;
    if (roll == 0)
        return HOST_ERROR_IO;
#endif

    int ret = mockfs_sync(&desc->file);
    if (ret < 0)
        return mockfs_to_quakey_error(ret);

    return 0;
}

static int host_setdescflags(Host *host, int desc_idx, int flags)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    // TODO: check the descriptor type

    desc->non_blocking = (flags & HOST_FLAG_NONBLOCK) != 0;
    return 0;
}

static int host_getdescflags(Host *host, int desc_idx)
{
    if (!is_desc_idx_valid(host, desc_idx))
        return HOST_ERROR_BADIDX;
    Desc *desc = &host->desc[desc_idx];

    // TODO: check the descriptor type

    int flags = 0;
    if (desc->non_blocking)
        flags |= HOST_FLAG_NONBLOCK;

    return flags;
}

/////////////////////////////////////////////////////////////////
// Time Event Code

static void append_event(Sim *sim, TimeEvent event)
{
    if (sim->num_events == sim->max_events) {
        int n = 2 * sim->max_events;
        if (n == 0)
            n = 8;
        TimeEvent *p = realloc(sim->events, n * sizeof(TimeEvent));
        if (p == NULL) {
            TODO;
        }
        sim->events = p;
        sim->max_events = n;
    }

    sim->events[sim->num_events++] = event;
}

static void time_event_wakeup(Sim *sim, Nanos time, Host *host)
{
    TimeEvent event = {
        .type = EVENT_TYPE_WAKEUP,
        .time = time,
        .host = host,
        .src_desc = NULL,
        .dst_desc = NULL,
        .data_count = 0,
        .data_queue = NULL,
        .rst = false,
    };
    append_event(sim, event);
}

static void time_event_connect(Sim *sim, Nanos time, Desc *desc)
{
    TimeEvent event = {
        .type = EVENT_TYPE_CONNECT,
        .time = time,
        .host = NULL,
        .src_desc = desc,
        .dst_desc = NULL,
        .data_count = 0,
        .data_queue = NULL,
        .rst = false,
    };
    append_event(sim, event);
}

static b32 remove_connect_event(Sim *sim, Desc *desc)
{
    int i = 0;
    while (i < sim->num_events && (sim->events[i].type != EVENT_TYPE_CONNECT || sim->events[i].src_desc != desc))
        i++;

    if (i == sim->num_events)
        return false;

    sim->events[i] = sim->events[--sim->num_events];
    return true;
}

// Remove all events that target a specific descriptor (DISCONNECT and DATA events)
static void remove_events_targeting_desc(Sim *sim, Desc *desc)
{
    int i = 0;
    while (i < sim->num_events) {
        TimeEvent *event = &sim->events[i];
        if (event->dst_desc == desc) {
            // Free any resources associated with the event
            if (event->type == EVENT_TYPE_DATA && event->data_queue) {
                socket_queue_unref(event->data_queue);
            }
            // Remove by swapping with last element
            sim->events[i] = sim->events[--sim->num_events];
            // Don't increment i - need to check the swapped element
        } else {
            i++;
        }
    }
}

static void time_event_disconnect(Sim *sim, Nanos time, Desc *desc, b32 rst)
{
    if (remove_connect_event(sim, desc))
        return;

    if (desc->peer == NULL)
        return;

    TimeEvent event = {
        .type = EVENT_TYPE_DISCONNECT,
        .time = time,
        .host = NULL,
        .src_desc = NULL,
        .dst_desc = desc->peer,
        .data_count = 0,
        .data_queue = NULL,
        .rst = rst,
    };
    append_event(sim, event);
}

static void time_event_send_data(Sim *sim, Nanos time, Desc *desc)
{
    TimeEvent event = {
        .type = EVENT_TYPE_DATA,
        .time = time,
        .host = NULL,
        .src_desc = NULL,
        .dst_desc = desc->peer,
        .data_count = socket_queue_used(desc->output),
        .data_queue = socket_queue_ref(desc->output),
        .rst = false,
    };
    append_event(sim, event);
}

static void time_event_free(TimeEvent *event)
{
    if (event->data_queue)
        socket_queue_unref(event->data_queue);
}

static int sim_find_host(Sim *sim, Addr addr);

static b32 time_event_process(TimeEvent *event, Sim *sim)
{
    b32 consumed = true;
    switch (event->type) {
    case EVENT_TYPE_CONNECT:
        {
            Desc *src_desc = event->src_desc;
            assert(event->dst_desc == NULL);

            int idx = sim_find_host(sim, src_desc->connect_addr);
            if (idx < 0) {
                src_desc->connect_status = CONNECT_STATUS_NOHOST;
                break;
            }
            Host *peer_host = sim->hosts[idx];

            Desc *peer = host_find_desc_bound_to(peer_host,
                src_desc->connect_addr, src_desc->connect_port);
            if (peer == NULL) {
                // Peer host exists but the port isn't open. Reset the connection.
                src_desc->connect_status = CONNECT_STATUS_RESET;
                break;
            }

            assert(peer->type == DESC_SOCKET_L);
            if (accept_queue_push(&peer->accept_queue, src_desc) < 0) {
                // Accept queue is full
                src_desc->connect_status = CONNECT_STATUS_RESET;
                break;
            }

            src_desc->connect_status = CONNECT_STATUS_DONE;
            src_desc->peer = peer; // Resolved!
        }
        break;
    case EVENT_TYPE_DISCONNECT:
        {
            Desc *dst_desc = event->dst_desc;
            assert(dst_desc->type == DESC_SOCKET_C);
            assert(event->src_desc == NULL);
            dst_desc->peer = NULL;
            dst_desc->connect_status = event->rst
                ? CONNECT_STATUS_RESET
                : CONNECT_STATUS_CLOSE;
        }
        break;
    case EVENT_TYPE_DATA:
        {
            Desc *dst_desc = event->dst_desc;
            assert(dst_desc->type == DESC_SOCKET_C);
            assert(event->src_desc == NULL);

            int num = socket_queue_move(dst_desc->input, event->data_queue, event->data_count);
            if (num < 0) {
                TODO;
            }

            event->data_count -= num;
            if (event->data_count == 0) {
                socket_queue_unref(event->data_queue);
            } else {
                // Reschedule to future time so time can advance
                event->time = sim->current_time + 10000000;
                consumed = false;
            }
        }
        break;
    case EVENT_TYPE_WAKEUP:
        event->host->timedout = true;
        break;
    }
    return consumed;
}

/////////////////////////////////////////////////////////////////
// Sim Code

static void sim_init(Sim *sim, uint64_t seed)
{
    sim->seed = seed;
    sim->current_time = 0;
    sim->num_hosts = 0;
    sim->max_hosts = 0;
    sim->hosts = NULL;
    sim->num_events = 0;
    sim->max_events = 0;
    sim->events = NULL;
}

static void sim_free(Sim *sim)
{
    for (int i = 0; i < sim->num_hosts; i++)
        host_free(sim->hosts[i]);
    free(sim->hosts);

    for (int i = 0; i < sim->num_events; i++)
        time_event_free(&sim->events[i]);
    free(sim->events);
}

static void sim_spawn(Sim *sim, QuakeySpawn config, char *arg)
{
    if (sim->num_hosts == sim->max_hosts) {
        int n = 2 * sim->max_hosts;
        if (n == 0)
            n = 8;
        Host **p = realloc(sim->hosts, n * sizeof(Host*));
        if (p == NULL) {
            TODO;
        }
        sim->hosts = p;
        sim->max_hosts = n;
    }

    Host *host = malloc(sizeof(Host));
    if (host == NULL) {
        TODO;
    }
    host_init(host, sim, config, arg);

    sim->hosts[sim->num_hosts++] = host;
}

static int sim_find_host(Sim *sim, Addr addr)
{
    for (int i = 0; i < sim->num_hosts; i++)
        if (host_has_addr(sim->hosts[i], addr))
            return i;
    return -1;
}

static void advance_time_to_next_event(Sim *sim)
{
    if (sim->num_events == 0)
        return;

    Nanos lowest_time = sim->events[0].time;
    for (int i = 1; i < sim->num_events; i++)
        if (lowest_time > sim->events[i].time)
            lowest_time = sim->events[i].time;

    sim->current_time = lowest_time;
}

static void process_events_at_current_time(Sim *sim)
{
    bool deferred_disconnect = false;
    for (int i = 0; i < sim->num_events; i++) {
        if (sim->events[i].time == sim->current_time) {
            if (sim->events[i].type == EVENT_TYPE_DISCONNECT) {
                deferred_disconnect = true;
            } else {
                if (time_event_process(&sim->events[i], sim))
                    sim->events[i--] = sim->events[--sim->num_events];
            }
        }
    }

    if (deferred_disconnect) {
        for (int i = 0; i < sim->num_events; i++) {
                if (sim->events[i].time == sim->current_time)
                if (sim->events[i].type == EVENT_TYPE_DISCONNECT) {
                    if (time_event_process(&sim->events[i], sim))
                        sim->events[i--] = sim->events[--sim->num_events];
                }
        }
    }
}

static int find_first_ready_host(Sim *sim)
{
    int i = 0;
    while (i < sim->num_hosts && !host_ready(sim->hosts[i]))
        i++;
    if (i == sim->num_hosts)
        return -1;
    return i;
}

static void move_host_to_last(Sim *sim, int idx)
{
    assert(idx > -1 && idx < sim->num_hosts);

    Host *host = sim->hosts[idx];
    for (int i = idx; i < sim->num_hosts-1; i++)
        sim->hosts[i] = sim->hosts[i+1];
    sim->hosts[sim->num_hosts-1] = host;
}

static b32 sim_update(Sim *sim)
{
    if (sim->num_hosts == 0)
        return false;

    int host_idx;
    for (;;) {

        // Schedule the first host that's ready.
        //
        // If all host are waiting, advance the time to the
        // next timed event and try again.

        host_idx = find_first_ready_host(sim);
        if (host_idx > -1)
            break;

        for (int i = 0; i < sim->num_hosts; i++)
            sim->hosts[i]->blocked = false;

        advance_time_to_next_event(sim);
        process_events_at_current_time(sim);
    }

    move_host_to_last(sim, host_idx);

    Host *host = sim->hosts[sim->num_hosts-1];

    host_update(host);
    if (host_ready(host))
        host->blocked = true;

    return true;
}

static uint64_t sim_random(Sim *sim)
{
    uint64_t x = sim->seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    sim->seed = x;
    return x;
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// Public Interface

/////////////////////////////////////////////////////////////////
// Quakey Object

int quakey_init(Quakey **quakey, QuakeyUInt64 seed)
{
    Sim *sim = malloc(sizeof(Sim));
    if (sim == NULL)
        return -1;
    sim_init(sim, seed);
    if (quakey) {
        *quakey = (void*) sim;
    } else {
        sim_free(sim);
        free(sim);
    }
    return 0;
}

void quakey_free(Quakey *quakey)
{
    if (quakey) {
        sim_free((Sim*) quakey);
        free(quakey);
    }
}

void quakey_spawn(Quakey *quakey, QuakeySpawn config, char *arg)
{
    return sim_spawn((Sim*) quakey, config, arg);
}

int quakey_schedule_one(Quakey *quakey)
{
    return sim_update((Sim*) quakey);
}

QuakeyUInt64 quakey_random(void)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_errno_ptr() with no node scheduled\n");
    return sim_random(host->sim);
}

/////////////////////////////////////////////////////////////////
// Mock System Calls

int *mock_errno_ptr(void)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_errno_ptr() with no node scheduled\n");

    return host_errno_ptr(host);
}

#ifndef _WIN32

int mock_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET && domain != AF_INET6)
        abort_("Quakey only supports socket() calls with doman=AF_INET or AF_INET6\n");

    if (type != SOCK_STREAM)
        abort_("Quakey only supports socket() calls with type=SOCK_STREAM\n");

    if (protocol != 0)
        abort_("Quakey only supports socket() calls with protocol=0\n");

    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_socket() with no node scheduled\n");

    AddrFamily family;
    switch (domain) {
    case AF_INET:
        family = ADDR_FAMILY_IPV4;
        break;
    case AF_INET6:
        family = ADDR_FAMILY_IPV6;
        break;
    default:
        UNREACHABLE;
    }

    int ret = host_create_socket(host, family);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = EMFILE;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }
    int desc_idx = ret;

    return desc_idx;
}

int mock_close(int fd)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_close() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_close() not from Linux\n");

    int desc_idx = fd;
    int ret = host_close(host, desc_idx, false);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return 0;
}

static int convert_addr(void *addr, size_t addr_len,
    Addr *converted_addr, uint16_t *converted_port)
{
    int family = ((struct sockaddr*) addr)->sa_family;
    switch (family) {
    case AF_INET:
        {
            if (addr_len != sizeof(struct sockaddr_in))
                return -1;
            struct sockaddr_in *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV4;
            converted_addr->ipv4.data = ntohl(((AddrIPv4*) &p->sin_addr)->data);
            *converted_port = ntohs(p->sin_port);
        }
        break;
    case AF_INET6:
        {
            if (addr_len != sizeof(struct sockaddr_in6))
                return -1;
            struct sockaddr_in6 *p = addr;
            converted_addr->family = ADDR_FAMILY_IPV6;
            converted_addr->ipv6   = *(AddrIPv6*) &p->sin6_addr; // TODO: convert to host byte order
            *converted_port        = ntohs(p->sin6_port);
        }
        break;
    default:
        abort_("Quakey only supports the AF_INET and AF_INET6 address families");
    }
    return 0;
}

int mock_bind(int fd, void *addr, unsigned long addr_len)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_bind() with no node scheduled\n");

    Addr     converted_addr;
    uint16_t converted_port;
    int ret = convert_addr(addr, addr_len, &converted_addr, &converted_port);
    if (ret < 0) {
        *host_errno_ptr(host) = EINVAL;
        return ret;
    }

    int desc_idx = fd;
    ret = host_bind(host, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_NOTSOCK:
            *host_errno_ptr(host) = ENOTSOCK;
            return -1;
        case HOST_ERROR_CANTBIND:
            *host_errno_ptr(host) = EINVAL;
            return -1;
        case HOST_ERROR_BADFAM:
            *host_errno_ptr(host) = EAFNOSUPPORT;
            return -1;
        case HOST_ERROR_NOTAVAIL:
            *host_errno_ptr(host) = EADDRNOTAVAIL;
            return -1;
        case HOST_ERROR_ADDRUSED:
            *host_errno_ptr(host) = EADDRINUSE;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return 0;
}

int mock_listen(int fd, int backlog)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_listen() with no node scheduled\n");

    int desc_idx = fd;
    int ret = host_listen(host, desc_idx, backlog);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = EINVAL;
            return -1;
        case HOST_ERROR_NOTSOCK:
            *host_errno_ptr(host) = ENOTSOCK;
            return -1;
        case HOST_ERROR_ADDRUSED:
            *host_errno_ptr(host) = EADDRINUSE;
            return -1;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return 0;
}

int mock_connect(int fd, void *addr, unsigned long addr_len)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_connect() with no node scheduled\n");

    Addr     converted_addr;
    uint16_t converted_port;
    int ret = convert_addr(addr, addr_len, &converted_addr, &converted_port);
    if (ret < 0) {
        *host_errno_ptr(host) = EINVAL;
        return -1;
    }

    // TODO: connect() operations are only allowed on non-blocking
    //       sockets

    int desc_idx = fd;
    ret = host_connect(host, desc_idx, converted_addr, converted_port);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_NOTSOCK:
            *host_errno_ptr(host) = ENOTSOCK;
            return -1;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = EISCONN;
            return -1;
        case HOST_ERROR_ADDRUSED:
            *host_errno_ptr(host) = EADDRINUSE;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EINPROGRESS;
        return -1;
    }

    *host_errno_ptr(host) = EINPROGRESS;
    return -1;
}

int mock_pipe(int *fds)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_pipe() with no node scheduled\n");

    int ret = host_create_pipe(host, fds);
    if (ret < 0)
        return EIO;

    return 0;
}

static int convert_linux_open_flags_to_mockfs(int flags)
{
    int lfs_flags = 0;

    // Convert other flags
    if (flags & O_RDWR)
        lfs_flags |= MOCKFS_O_RDWR;
    if (flags & O_WRONLY)
        lfs_flags |= MOCKFS_O_WRONLY;
    if (flags & O_CREAT)
        lfs_flags |= MOCKFS_O_CREAT;
    if (flags & O_EXCL)
        lfs_flags |= MOCKFS_O_EXCL;
    if (flags & O_TRUNC)
        lfs_flags |= MOCKFS_O_TRUNC;
    if (flags & O_APPEND)
        lfs_flags |= MOCKFS_O_APPEND;

    return lfs_flags;
}

int mock_open(char *path, int flags, int mode)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_open() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_open() not from Linux\n");

    int converted_flags = convert_linux_open_flags_to_mockfs(flags);

    int ret = host_open_file(host, path, converted_flags);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = EMFILE;
            return -1;
        case HOST_ERROR_IO:
            *host_errno_ptr(host) = EIO;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = ENOENT;
        return -1;
    }
    int desc_idx = ret;

    return desc_idx;
}

int mock_read(int fd, char *dst, int len)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_read() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_read() not from Linux\n");

    int ret = host_read(host, fd, dst, len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = EINVAL;
            return -1;
        case HOST_ERROR_ISDIR:
            *host_errno_ptr(host) = EISDIR;
            return -1;
        case HOST_ERROR_IO:
            *host_errno_ptr(host) = EIO;
            return -1;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return ret;
}

int mock_write(int fd, char *src, int len)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_write() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_write() not from Linux\n");

    int ret = host_write(host, fd, src, len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_IO:
            *host_errno_ptr(host) = EIO;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return ret;
}

int mock_recv(int fd, char *dst, int len, int flags)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_recv() with no node scheduled\n");

    if (flags)
        abort_("Call to mock_recv() with non-zero flags\n");

    int ret = host_recv(host, fd, dst, len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_NOTSOCK:
            *host_errno_ptr(host) = ENOTSOCK;
            return -1;
        case HOST_ERROR_NOTCONN:
            *host_errno_ptr(host) = ENOTCONN;
            return -1;
        case HOST_ERROR_RESET:
            *host_errno_ptr(host) = ECONNRESET;
            return -1;
        case HOST_ERROR_HANGUP:
            *host_errno_ptr(host) = 0;
            return 0;
        case HOST_ERROR_WOULDBLOCK:
            *host_errno_ptr(host) = EAGAIN;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    ASSERT(ret > 0);
    return ret;
}

int mock_send(int fd, char *src, int len, int flags)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_send() with no node scheduled\n");

    if (flags)
        abort_("Call to mock_send() with non-zero flags\n");

    int ret = host_send(host, fd, src, len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_RESET:
            *host_errno_ptr(host) = ECONNRESET;
            return -1;
        case HOST_ERROR_HANGUP:
            *host_errno_ptr(host) = EPIPE;
            return -1;
        case HOST_ERROR_WOULDBLOCK:
            *host_errno_ptr(host) = EAGAIN;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }

    return ret;
}

int mock_accept(int fd, void *addr, socklen_t *addr_len)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_accept() with no node scheduled\n");

    Addr     peer_addr;
    uint16_t peer_port;
    int ret = host_accept(host, fd, &peer_addr, &peer_port);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return -1;
        case HOST_ERROR_NOTSOCK:
            *host_errno_ptr(host) = ENOTSOCK;
            return -1;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = EINVAL;
            return -1;
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = EMFILE;
            return -1;
        case HOST_ERROR_WOULDBLOCK:
            *host_errno_ptr(host) = EAGAIN;
            return -1;
        default:
            break;
        }
        *host_errno_ptr(host) = EIO;
        return -1;
    }
    int new_fd = ret;

    // Fill in the address if provided
    if (addr != NULL && addr_len != NULL) {
        if (peer_addr.family == ADDR_FAMILY_IPV4) {
            struct sockaddr_in *sin = addr;
            if (*addr_len >= sizeof(struct sockaddr_in)) {
                sin->sin_family = AF_INET;
                sin->sin_port = peer_port;
                memcpy(&sin->sin_addr, &peer_addr.ipv4, sizeof(peer_addr.ipv4));
                *addr_len = sizeof(struct sockaddr_in);
            }
        } else {
            struct sockaddr_in6 *sin6 = addr;
            if (*addr_len >= sizeof(struct sockaddr_in6)) {
                sin6->sin6_family = AF_INET6;
                sin6->sin6_port = peer_port;
                memcpy(&sin6->sin6_addr, &peer_addr.ipv6, sizeof(peer_addr.ipv6));
                *addr_len = sizeof(struct sockaddr_in6);
            }
        }
    }

    return new_fd;
}

int mock_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (level != SOL_SOCKET)
        abort_("Call to mock_getsockopt() with level other than SOL_SOCKET\n");

    if (optname != SO_ERROR)
        abort_("Call to mock_getsockopt() with option other than SO_ERROR\n");

    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_getsockopt() with no node scheduled\n");

    ConnectStatus status;
    int ret = host_connect_status(host, fd, &status);
    if (ret < 0) {
        TODO;
    }

    int out;
    switch (status) {
    case CONNECT_STATUS_WAIT:
        out = 0;
        break;
    case CONNECT_STATUS_DONE:
        out = 0;
        break;
    case CONNECT_STATUS_RESET:
        out = ECONNRESET;
        break;
    case CONNECT_STATUS_CLOSE:
        out = ECONNRESET;
        break;
    case CONNECT_STATUS_NOHOST:
        out = ETIMEDOUT;
        break;
    default:
        UNREACHABLE;
        break;
    }

    if (*optlen < sizeof(out))
        memcpy(optval, &out, *optlen);
    else {
        memcpy(optval, &out, sizeof(out));
        *optlen = sizeof(out);
    }
    return 0;
}

int mock_remove(char *path)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_remove() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_remove() not from Linux\n");

    int ret = host_remove(host, path);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ENOENT;
            break;
        case HOST_ERROR_NOTEMPTY:
            *host_errno_ptr(host) = ENOTEMPTY;
            break;
        default:
            *host_errno_ptr(host) = EIO;
            break;
        }
        return -1;
    }

    return 0;
}

int mock_rename(char *oldpath, char *newpath)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_rename() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_rename() not from Linux\n");

    int ret = host_rename(host, oldpath, newpath);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ENOENT;
            break;
        case HOST_ERROR_EXIST:
            *host_errno_ptr(host) = EEXIST;
            break;
        case HOST_ERROR_NOTEMPTY:
            *host_errno_ptr(host) = ENOTEMPTY;
            break;
        case HOST_ERROR_ISDIR:
            *host_errno_ptr(host) = EISDIR;
            break;
        default:
            *host_errno_ptr(host) = EIO;
            break;
        }
        return -1;
    }

    return 0;
}

int mock_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_clock_gettime() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_clock_gettime() not from Linux\n");

    if (tp == NULL) {
        *host_errno_ptr(host) = EINVAL;
        return -1;
    }

    // Both CLOCK_REALTIME and CLOCK_MONOTONIC use the same
    // simulated time. In simulation, they're equivalent since
    // we don't model wall-clock vs monotonic differences.
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
        *host_errno_ptr(host) = EINVAL;
        return -1;
    }

    // Get current time
    Nanos now = host_time(host);

    // Convert nanoseconds to timespec
    // 1 second = 1,000,000,000 nanoseconds
    tp->tv_sec  = (time_t)  (now / 1000000000ULL);
    tp->tv_nsec = (int64_t) (now % 1000000000ULL);

    return 0;
}

int mock_flock(int fd, int op)
{
    // TODO
    return 0;
}

int mock_fsync(int fd)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_fsync() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_fsync() not from Linux\n");

    int ret = host_fsync(host, fd);
    if (ret < 0) {
        if (ret == HOST_ERROR_BADIDX)
            *host_errno_ptr(host) = EBADF;
        else
            *host_errno_ptr(host) = EINVAL;
        return -1;
    }

    return 0;
}

off_t mock_lseek(int fd, off_t offset, int whence)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_lseek() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_lseek() not from Linux\n");

    // Convert POSIX whence to HOST whence
    int host_whence;
    switch (whence) {
    case SEEK_SET:
        host_whence = HOST_SEEK_SET;
        break;
    case SEEK_CUR:
        host_whence = HOST_SEEK_CUR;
        break;
    case SEEK_END:
        host_whence = HOST_SEEK_END;
        break;
    default:
        *host_errno_ptr(host) = EINVAL;
        return (off_t)-1;
    }

    int ret = host_lseek(host, fd, offset, host_whence);
    if (ret < 0) {
        if (ret == HOST_ERROR_BADIDX)
            *host_errno_ptr(host) = EBADF;
        else
            *host_errno_ptr(host) = EINVAL;
        return (off_t)-1;
    }

    return (off_t)ret;
}

int mock_fstat(int fd, struct stat *buf)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_fstat() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_fstat() not from Linux\n");

    if (buf == NULL) {
        *host_errno_ptr(host) = EINVAL;
        return -1;
    }

    FileInfo info;
    int ret = host_fileinfo(host, fd, &info);
    if (ret < 0) {
        if (ret == HOST_ERROR_BADIDX) {
            *host_errno_ptr(host) = EBADF;
        } else {
            *host_errno_ptr(host) = EIO;
        }
        return -1;
    }

    memset(buf, 0, sizeof(*buf));

    if (info.is_dir) {
        buf->st_mode = S_IFDIR | 0755;  // Directory with rwxr-xr-x permissions
        buf->st_size = 0;
    } else {
        buf->st_mode = S_IFREG | 0644;  // Regular file with rw-r--r-- permissions
        buf->st_size = (off_t) info.size;
    }

    return 0;
}

int mock_mkstemp(char *path)
{
    TODO;
}

char *mock_realpath(char *path, char *dst)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_realpath() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_realpath() not from Linux\n");

    if (path == NULL) {
        *host_errno_ptr(host) = EINVAL;
        return NULL;
    }

    // Temporary buffer for path normalization
    char temp[4096];
    int temp_len = 0;

    // Copy path to temp
    for (int i = 0; path[i] != '\0' && temp_len < (int)sizeof(temp) - 1; i++) {
        temp[temp_len++] = path[i];
    }
    temp[temp_len] = '\0';

    // Result buffer for the normalized absolute path
    char result[4096];
    int result_len = 0;

    // If path doesn't start with '/', prepend '/' (mock has no CWD, uses root)
    const char *src = temp;
    if (temp[0] != '/') {
        result[result_len++] = '/';
    }

    // Parse path components and resolve . and ..
    while (*src != '\0') {
        // Skip consecutive slashes
        while (*src == '/') src++;

        if (*src == '\0') break;

        // Find end of this component
        const char *end = src;
        while (*end != '\0' && *end != '/') end++;

        int comp_len = (int)(end - src);

        if (comp_len == 1 && src[0] == '.') {
            // Current directory - skip it
        } else if (comp_len == 2 && src[0] == '.' && src[1] == '.') {
            // Parent directory - remove last component from result
            if (result_len > 1) {
                // Find the last slash before the current position
                result_len--;  // Move back from current position
                while (result_len > 0 && result[result_len - 1] != '/') {
                    result_len--;
                }
                if (result_len == 0) {
                    result_len = 1;  // Keep the root slash
                }
            }
        } else {
            // Regular component - add it
            if (result_len > 1 || (result_len == 1 && result[0] != '/')) {
                if (result_len < (int)sizeof(result) - 1)
                    result[result_len++] = '/';
            }
            for (int i = 0; i < comp_len && result_len < (int)sizeof(result) - 1; i++) {
                result[result_len++] = src[i];
            }
        }

        src = end;
    }

    // Ensure we have at least root
    if (result_len == 0) {
        result[result_len++] = '/';
    }
    result[result_len] = '\0';

    // Unlike _fullpath, realpath requires the path to exist
    // Try to open as file first, then as directory
    int fd = host_open_file(host, result, MOCKFS_O_RDONLY);
    if (fd >= 0) {
        host_close(host, fd, false);
    } else {
        // Try as directory
        fd = host_open_dir(host, result);
        if (fd >= 0) {
            host_close(host, fd, false);
        } else {
            // Path doesn't exist
            *host_errno_ptr(host) = ENOENT;
            return NULL;
        }
    }

    // Allocate buffer if dst is NULL
    if (dst == NULL) {
        dst = malloc(result_len + 1);
        if (dst == NULL) {
            *host_errno_ptr(host) = ENOMEM;
            return NULL;
        }
    }

    // Copy result to destination
    for (int i = 0; i <= result_len; i++) {
        dst[i] = result[i];
    }

    return dst;
}

int mock_mkdir(char *path, mode_t mode)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_mkdir() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_mkdir() not from Linux\n");

    // LittleFS doesn't use mode, but we accept it for API compatibility
    (void) mode;

    int ret = host_mkdir(host, path);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_EXIST:
            *host_errno_ptr(host) = EEXIST;
            return -1;
        case HOST_ERROR_NOENT:
            // Parent directory doesn't exist
            *host_errno_ptr(host) = ENOENT;
            return -1;
        default:
            *host_errno_ptr(host) = EIO;
            return -1;
        }
    }

    return 0;
}

int mock_fcntl(int fd, int cmd, int flags)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_fcntl() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_fcntl() not from Linux\n");

    switch (cmd) {

    case F_GETFL:
        {
            int ret = host_getdescflags(host, fd);
            if (ret < 0) {
                *host_errno_ptr(host) = EBADF;
                return -1;
            }

            int flags = 0;
            if (ret & HOST_FLAG_NONBLOCK)
                flags |= O_NONBLOCK;

            return flags;
        }
        break;

    case F_SETFL:
        {
            int host_flags = 0;
            if (flags & O_NONBLOCK)
                host_flags |= HOST_FLAG_NONBLOCK;

            int ret = host_setdescflags(host, fd, host_flags);

            if (ret < 0) {
                *host_errno_ptr(host) = EBADF;
                return -1;
            }
            return 0;
        }
        break;

    default:
        *host_errno_ptr(host) = EINVAL;
        return -1;
    }
}

typedef struct {
    int           fd;    // Descriptor index
    struct dirent entry; // Current entry (returned by readdir)
} DIR_;

DIR *mock_opendir(char *name)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_opendir() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_opendir() not from Linux\n");

    int ret = host_open_dir(host, name);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = EMFILE;
            return NULL;
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ENOENT;
            return NULL;
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = EIO;
            return NULL;
        }
    }

    // Allocate DIR structure
    DIR_ *dirp = malloc(sizeof(DIR_));
    if (dirp == NULL) {
        // Close the descriptor since we can't return it
        host_close(host, ret, false);
        *host_errno_ptr(host) = EMFILE;
        return NULL;
    }

    dirp->fd = ret;
    return (DIR*) dirp;
}

struct dirent* mock_readdir(DIR *dirp)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_readdir() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_readdir() not from Linux\n");

    DIR_ *dirp_ = (DIR_*) dirp;

    if (dirp_ == NULL) {
        *host_errno_ptr(host) = EBADF;
        return NULL;
    }

    DirEntry entry;
    int ret = host_read_dir(host, dirp_->fd, &entry);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            return NULL;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = EBADF;
            return NULL;
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = EIO;
            return NULL;
        }
    }

    if (ret == 0) {
        // End of directory - return NULL without setting errno
        return NULL;
    }

    // Copy to the DIR's entry buffer
    int i = 0;
    while (entry.name[i] != '\0' && i < 255) {
        dirp_->entry.d_name[i] = entry.name[i];
        i++;
    }
    dirp_->entry.d_name[i] = '\0';
    dirp_->entry.d_type = entry.is_dir ? DT_DIR : DT_REG;

    return &dirp_->entry;
}

int mock_closedir(DIR *dirp)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_closedir() with no node scheduled\n");

    if (!host_is_linux(host))
        abort_("Call to mock_closedir() not from Linux\n");

    DIR_ *dirp_ = (DIR_*) dirp;

    if (dirp_ == NULL) {
        *host_errno_ptr(host) = EBADF;
        return -1;
    }

    int ret = host_close(host, dirp_->fd, false);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = EBADF;
            free(dirp_);
            return -1;
        default:
            *host_errno_ptr(host) = EIO;
            free(dirp_);
            return -1;
        }
    }

    free(dirp_);
    return 0;
}

#else

int mock_GetLastError(void)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_GetLastError() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_GetLastError() not from Windows\n");

    // Note that technically on windows errno and GetLastError
    // are different things. Here we use errno_ to store the
    // GetLastError value and assume the user will not access
    // errno.
    return *host_errno_ptr(host);
}

int mock_WSAGetLastError(void)
{
    return mock_GetLastError();
}

void mock_SetLastError(int err)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_SetLastError() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_SetLastError() not from Windows\n");

    *host_errno_ptr(host) = err;
}

void mock_WSASetLastError(int err)
{
    return mock_SetLastError(err);
}

int mock_closesocket(SOCKET fd)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_closesocket() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_closesocket() not from Windows\n");

    int desc_idx = fd;
    int ret = host_close(host, desc_idx, true);  // expect_socket = true
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
        case HOST_ERROR_NOTSOCK:
            // Windows uses WSAGetLastError(), but for simplicity we just return error
            return -1;
        default:
            break;
        }
        return -1;
    }

    return 0;
}

int mock_ioctlsocket(SOCKET fd, long cmd, unsigned long *argp)
{
    TODO;
}

// Helper function to convert wide string to narrow string (ASCII subset)
static int wchar_to_char(WCHAR *src, char *dst, int dst_size)
{
    int i = 0;
    while (src[i] != 0) {
        if (i >= dst_size - 1)
            return -1;  // Buffer too small
        if (src[i] > 127)
            return -1;  // Non-ASCII character
        dst[i] = (char) src[i];
        i++;
    }
    dst[i] = '\0';
    return i;  // Return length
}

// Convert Windows access flags and creation disposition to LFS flags
static int convert_windows_flags_to_lfs(DWORD dwDesiredAccess,
    DWORD dwCreationDisposition, bool *truncate)
{
    int lfs_flags = 0;

    // Convert access mode
    if ((dwDesiredAccess & GENERIC_READ) && (dwDesiredAccess & GENERIC_WRITE))
        lfs_flags = LFS_O_RDWR;
    else if (dwDesiredAccess & GENERIC_WRITE)
        lfs_flags = LFS_O_WRONLY;
    else
        lfs_flags = LFS_O_RDONLY;

    *truncate = false;

    // Convert creation disposition
    switch (dwCreationDisposition) {
    case CREATE_NEW:
        // Creates a new file, fails if file exists
        lfs_flags |= LFS_O_CREAT | LFS_O_EXCL;
        break;
    case CREATE_ALWAYS:
        // Creates a new file, always (truncates if exists)
        lfs_flags |= LFS_O_CREAT | LFS_O_TRUNC;
        *truncate = true;
        break;
    case OPEN_EXISTING:
        // Opens file only if it exists, fails otherwise
        // No extra flags needed - LFS will fail if file doesn't exist
        break;
    case OPEN_ALWAYS:
        // Opens file if it exists, creates if it doesn't
        lfs_flags |= LFS_O_CREAT;
        break;
    case TRUNCATE_EXISTING:
        // Opens and truncates, fails if file doesn't exist
        lfs_flags |= LFS_O_TRUNC;
        *truncate = true;
        break;
    default:
        return -1;  // Invalid creation disposition
    }

    return lfs_flags;
}

HANDLE mock_CreateFileW(WCHAR *lpFileName,
    DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_CreateFileW() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_CreateFileW() not from Windows\n");

    // lpSecurityAttributes and hTemplateFile are typically NULL
    (void) lpSecurityAttributes;
    (void) hTemplateFile;
    (void) dwShareMode;  // Share mode not implemented in simulation
    (void) dwFlagsAndAttributes;  // Attributes not implemented in simulation

    // Convert wide string path to narrow string
    char path[MAX_PATH];
    if (wchar_to_char(lpFileName, path, MAX_PATH) < 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return INVALID_HANDLE_VALUE;
    }

    // Convert Windows flags to LFS flags
    bool truncate;
    int lfs_flags = convert_windows_flags_to_lfs(dwDesiredAccess, dwCreationDisposition, &truncate);
    if (lfs_flags < 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return INVALID_HANDLE_VALUE;
    }

    int ret = host_open_file(host, path, lfs_flags);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = ERROR_NOT_ENOUGH_MEMORY;
            return INVALID_HANDLE_VALUE;
        case HOST_ERROR_EXISTS:
            // CREATE_NEW with existing file
            *host_errno_ptr(host) = ERROR_FILE_EXISTS;
            return INVALID_HANDLE_VALUE;
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ERROR_FILE_NOT_FOUND;
            return INVALID_HANDLE_VALUE;
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return INVALID_HANDLE_VALUE;
        }
    }

    int desc_idx = ret;

    // For OPEN_ALWAYS, if the file already existed, set ERROR_ALREADY_EXISTS
    // (but still return success). This is Windows behavior.
    if (dwCreationDisposition == OPEN_ALWAYS) {
        // We can't easily detect this case here, so we skip it for now
        // A full implementation would check if the file was newly created
    }

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return (HANDLE)(long long)desc_idx;
}

BOOL mock_CloseHandle(HANDLE handle)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_CloseHandle() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_CloseHandle() not from Windows\n");

    if (handle == INVALID_HANDLE_VALUE || handle == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    int desc_idx = (int)(long long)handle;

    // CloseHandle is for file handles, not sockets
    // (sockets use closesocket on Windows)
    int ret = host_close(host, desc_idx, false);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        default:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        }
    }

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

BOOL mock_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh)
{
    TODO;
}

BOOL mock_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh)
{
    TODO;
}

BOOL mock_FlushFileBuffers(HANDLE handle)
{
    TODO;
}

BOOL mock_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_ReadFile() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_ReadFile() not from Windows\n");

    // We don't support overlapped (async) I/O
    if (ov != NULL)
        abort_("Quakey does not support overlapped I/O in ReadFile\n");

    if (handle == INVALID_HANDLE_VALUE || handle == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    if (dst == NULL && len > 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    int desc_idx = (int)(long long)handle;

    int ret = host_read(host, desc_idx, dst, (int)len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        case HOST_ERROR_BADARG:
        case HOST_ERROR_ISDIR:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        }
    }

    if (num != NULL)
        *num = (DWORD)ret;

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

BOOL mock_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_WriteFile() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_WriteFile() not from Windows\n");

    // We don't support overlapped (async) I/O
    if (ov != NULL)
        abort_("Quakey does not support overlapped I/O in WriteFile\n");

    if (handle == INVALID_HANDLE_VALUE || handle == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    if (src == NULL && len > 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    int desc_idx = (int)(long long)handle;

    int ret = host_write(host, desc_idx, src, (int)len);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        }
    }

    if (num != NULL)
        *num = (DWORD)ret;

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

DWORD mock_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_SetFilePointer() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_SetFilePointer() not from Windows\n");

    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return INVALID_SET_FILE_POINTER;
    }

    int desc_idx = (int)(long long)hFile;

    // Convert Windows move method to HOST whence
    int host_whence;
    switch (dwMoveMethod) {
    case FILE_BEGIN:
        host_whence = HOST_SEEK_SET;
        break;
    case FILE_CURRENT:
        host_whence = HOST_SEEK_CUR;
        break;
    case FILE_END:
        host_whence = HOST_SEEK_END;
        break;
    default:
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return INVALID_SET_FILE_POINTER;
    }

    // Build 64-bit offset
    int64_t offset;
    if (lpDistanceToMoveHigh != NULL) {
        // 64-bit seek: combine high and low parts
        offset = ((int64_t)(*lpDistanceToMoveHigh) << 32) | ((uint32_t)lDistanceToMove);
    } else {
        // 32-bit seek: use signed extension
        offset = (int64_t)lDistanceToMove;
    }

    int ret = host_lseek(host, desc_idx, offset, host_whence);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return INVALID_SET_FILE_POINTER;
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = ERROR_NEGATIVE_SEEK;
            return INVALID_SET_FILE_POINTER;
        default:
            *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
            return INVALID_SET_FILE_POINTER;
        }
    }

    int64_t new_pos = (int64_t)ret;

    // Set high part if requested
    if (lpDistanceToMoveHigh != NULL)
        *lpDistanceToMoveHigh = (LONG)(new_pos >> 32);

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return (DWORD)(new_pos & 0xFFFFFFFF);
}

BOOL mock_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_GetFileSizeEx() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_GetFileSizeEx() not from Windows\n");

    if (handle == INVALID_HANDLE_VALUE || handle == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    if (buf == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    int desc_idx = (int)(long long)handle;

    FileInfo info;
    int ret = host_fileinfo(host, desc_idx, &info);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        }
    }

    buf->QuadPart = (LONGLONG)info.size;

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

BOOL mock_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_QueryPerformanceCounter() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_QueryPerformanceCounter() not from Windows\n");

    if (lpPerformanceCount == NULL)
        return 0;  // FALSE

    // Get current time in nanoseconds and convert to performance counter units
    // We use nanoseconds directly as the counter value (frequency = 1,000,000,000)
    Nanos now = host_time(host);
    lpPerformanceCount->QuadPart = (LONGLONG)now;

    return 1;  // TRUE
}

BOOL mock_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_QueryPerformanceFrequency() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_QueryPerformanceFrequency() not from Windows\n");

    if (lpFrequency == NULL)
        return 0;  // FALSE

    // Frequency is 1 billion (nanoseconds per second)
    // This matches our counter which counts in nanoseconds
    lpFrequency->QuadPart = 1000000000LL;

    return 1;  // TRUE
}

char *mock__fullpath(char *path, char *dst, int cap)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock__fullpath() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock__fullpath() not from Windows\n");

    if (path == NULL) {
        *host_errno_ptr(host) = EINVAL;
        return NULL;
    }

    // Temporary buffer for path normalization
    // We'll build the absolute path here
    char temp[4096];
    int temp_len = 0;

    // Copy path to temp, converting backslashes to forward slashes
    for (int i = 0; path[i] != '\0' && temp_len < (int)sizeof(temp) - 1; i++) {
        if (path[i] == '\\') {
            temp[temp_len++] = '/';
        } else {
            temp[temp_len++] = path[i];
        }
    }
    temp[temp_len] = '\0';

    // Result buffer for the normalized absolute path
    char result[4096];
    int result_len = 0;

    // If path doesn't start with '/', prepend '/' (mock has no CWD, uses root)
    const char *src = temp;
    if (temp[0] != '/') {
        result[result_len++] = '/';
    }

    // Parse path components and resolve . and ..
    while (*src != '\0') {
        // Skip consecutive slashes
        while (*src == '/') src++;

        if (*src == '\0') break;

        // Find end of this component
        const char *end = src;
        while (*end != '\0' && *end != '/') end++;

        int comp_len = (int)(end - src);

        if (comp_len == 1 && src[0] == '.') {
            // Current directory - skip it
        } else if (comp_len == 2 && src[0] == '.' && src[1] == '.') {
            // Parent directory - remove last component from result
            if (result_len > 1) {
                // Find the last slash before the current position
                result_len--;  // Move back from current position
                while (result_len > 0 && result[result_len - 1] != '/') {
                    result_len--;
                }
                if (result_len == 0) {
                    result_len = 1;  // Keep the root slash
                }
            }
        } else {
            // Regular component - add it
            if (result_len > 1 || (result_len == 1 && result[0] != '/')) {
                if (result_len < (int)sizeof(result) - 1)
                    result[result_len++] = '/';
            }
            for (int i = 0; i < comp_len && result_len < (int)sizeof(result) - 1; i++) {
                result[result_len++] = src[i];
            }
        }

        src = end;
    }

    // Ensure we have at least root
    if (result_len == 0) {
        result[result_len++] = '/';
    }
    result[result_len] = '\0';

    // Allocate buffer if dst is NULL
    if (dst == NULL) {
        dst = malloc(result_len + 1);
        if (dst == NULL) {
            *host_errno_ptr(host) = ENOMEM;
            return NULL;
        }
    } else {
        // Check if result fits in the provided buffer
        if (result_len + 1 > cap) {
            *host_errno_ptr(host) = ERANGE;
            return NULL;
        }
    }

    // Copy result to destination
    for (int i = 0; i <= result_len; i++) {
        dst[i] = result[i];
    }

    return dst;
}

int mock__mkdir(char *path)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock__mkdir() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock__mkdir() not from Windows\n");

    int ret = host_mkdir(host, path);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_EXIST:
            *host_errno_ptr(host) = EEXIST;
            return -1;
        case HOST_ERROR_NOENT:
            // Parent directory doesn't exist
            *host_errno_ptr(host) = ENOENT;
            return -1;
        default:
            *host_errno_ptr(host) = EIO;
            return -1;
        }
    }

    return 0;
}

// Structure to track Windows find handle state
typedef struct {
    int fd;  // Descriptor index for the directory
} FindHandle;

// Helper function to populate WIN32_FIND_DATAA from a DirEntry
static void populate_find_data(WIN32_FIND_DATAA *data, DirEntry *entry)
{
    // Clear the structure
    for (int i = 0; i < (int)sizeof(WIN32_FIND_DATAA); i++)
        ((char *)data)[i] = 0;

    // Set file attributes
    data->dwFileAttributes = entry->is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;

    // Copy filename
    int i = 0;
    while (entry->name[i] != '\0' && i < MAX_PATH - 1) {
        data->cFileName[i] = entry->name[i];
        i++;
    }
    data->cFileName[i] = '\0';
}

HANDLE mock_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_FindFirstFileA() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_FindFirstFileA() not from Windows\n");

    if (lpFileName == NULL || lpFindFileData == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return INVALID_HANDLE_VALUE;
    }

    // Extract directory path from the search pattern
    // The pattern is typically "path\*" or "path\*.ext"
    // We need to find the last path separator and extract the directory
    char dirpath[MAX_PATH];
    int len = 0;
    while (lpFileName[len] != '\0' && len < MAX_PATH - 1) {
        dirpath[len] = lpFileName[len];
        len++;
    }
    dirpath[len] = '\0';

    // Find the last path separator (either '/' or '\')
    int last_sep = -1;
    for (int i = 0; i < len; i++) {
        if (dirpath[i] == '/' || dirpath[i] == '\\')
            last_sep = i;
    }

    // If we found a separator, truncate to get the directory path
    // If the pattern is just "*", use "." as the directory
    if (last_sep >= 0) {
        dirpath[last_sep] = '\0';
    } else {
        // No separator found - use current directory
        dirpath[0] = '.';
        dirpath[1] = '\0';
    }

    // Open the directory
    int ret = host_open_dir(host, dirpath);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_FULL:
            *host_errno_ptr(host) = ERROR_NOT_ENOUGH_MEMORY;
            return INVALID_HANDLE_VALUE;
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ERROR_PATH_NOT_FOUND;
            return INVALID_HANDLE_VALUE;
        case HOST_ERROR_IO:
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return INVALID_HANDLE_VALUE;
        }
    }

    // Allocate find handle structure
    FindHandle *fh = malloc(sizeof(FindHandle));
    if (fh == NULL) {
        host_close(host, ret, false);
        *host_errno_ptr(host) = ERROR_NOT_ENOUGH_MEMORY;
        return INVALID_HANDLE_VALUE;
    }
    fh->fd = ret;

    // Read the first entry
    DirEntry entry;
    int read_ret = host_read_dir(host, fh->fd, &entry);
    if (read_ret < 0) {
        host_close(host, fh->fd, false);
        free(fh);
        switch (read_ret) {
        case HOST_ERROR_BADIDX:
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return INVALID_HANDLE_VALUE;
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return INVALID_HANDLE_VALUE;
        }
    }

    if (read_ret == 0) {
        // Empty directory - no files found
        host_close(host, fh->fd, false);
        free(fh);
        *host_errno_ptr(host) = ERROR_FILE_NOT_FOUND;
        return INVALID_HANDLE_VALUE;
    }

    // Populate the find data structure
    populate_find_data(lpFindFileData, &entry);

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return (HANDLE)fh;
}

BOOL mock_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_FindNextFileA() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_FindNextFileA() not from Windows\n");

    if (hFindFile == INVALID_HANDLE_VALUE || hFindFile == NULL || lpFindFileData == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    FindHandle *fh = (FindHandle *)hFindFile;

    // Read the next entry
    DirEntry entry;
    int ret = host_read_dir(host, fh->fd, &entry);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_BADIDX:
        case HOST_ERROR_BADARG:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        }
    }

    if (ret == 0) {
        // No more files
        *host_errno_ptr(host) = ERROR_NO_MORE_FILES;
        return 0;  // FALSE
    }

    // Populate the find data structure
    populate_find_data(lpFindFileData, &entry);

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

BOOL mock_FindClose(HANDLE hFindFile)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_FindClose() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_FindClose() not from Windows\n");

    if (hFindFile == INVALID_HANDLE_VALUE || hFindFile == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
        return 0;  // FALSE
    }

    FindHandle *fh = (FindHandle *)hFindFile;

    int ret = host_close(host, fh->fd, false);
    if (ret < 0) {
        free(fh);
        switch (ret) {
        case HOST_ERROR_BADIDX:
            *host_errno_ptr(host) = ERROR_INVALID_HANDLE;
            return 0;  // FALSE
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            return 0;  // FALSE
        }
    }

    free(fh);
    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

BOOL mock_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_MoveFileExW() with no node scheduled\n");

    if (!host_is_windows(host))
        abort_("Call to mock_MoveFileExW() not from Windows\n");

    // Validate parameters
    if (lpExistingFileName == NULL) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    // lpNewFileName can be NULL only with MOVEFILE_DELAY_UNTIL_REBOOT
    // (marks file for deletion on reboot), but we don't support that
    if (lpNewFileName == NULL) {
        if (dwFlags & MOVEFILE_DELAY_UNTIL_REBOOT) {
            // We don't simulate reboot, so just succeed without doing anything
            *host_errno_ptr(host) = ERROR_SUCCESS;
            return 1;  // TRUE
        }
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    // Convert wide string paths to narrow strings
    char oldpath[MAX_PATH];
    char newpath[MAX_PATH];

    if (wchar_to_char(lpExistingFileName, oldpath, MAX_PATH) < 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    if (wchar_to_char(lpNewFileName, newpath, MAX_PATH) < 0) {
        *host_errno_ptr(host) = ERROR_INVALID_PARAMETER;
        return 0;  // FALSE
    }

    // If MOVEFILE_REPLACE_EXISTING is not set and destination exists, fail
    // We need to check this before calling host_rename
    if (!(dwFlags & MOVEFILE_REPLACE_EXISTING)) {
        // Try to check if destination exists by attempting to open it
        int check = host_open_file(host, newpath, LFS_O_RDONLY);
        if (check >= 0) {
            // File exists, close it and return error
            host_close(host, check, false);
            *host_errno_ptr(host) = ERROR_ALREADY_EXISTS;
            return 0;  // FALSE
        }
    }

    int ret = host_rename(host, oldpath, newpath);
    if (ret < 0) {
        switch (ret) {
        case HOST_ERROR_NOENT:
            *host_errno_ptr(host) = ERROR_FILE_NOT_FOUND;
            break;
        case HOST_ERROR_EXIST:
            *host_errno_ptr(host) = ERROR_ALREADY_EXISTS;
            break;
        case HOST_ERROR_NOTEMPTY:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            break;
        case HOST_ERROR_ISDIR:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            break;
        default:
            *host_errno_ptr(host) = ERROR_ACCESS_DENIED;
            break;
        }
        return 0;  // FALSE
    }

    *host_errno_ptr(host) = ERROR_SUCCESS;
    return 1;  // TRUE
}

#endif

void *mock_malloc(size_t size)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_malloc() with no node scheduled\n");
#ifdef FAULT_INJECTION
    if ((sim_random(host->sim) % 1000) == 0)
        return NULL;
#endif
    return malloc(size);
}

void *mock_realloc(void *ptr, size_t size)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_realloc() with no node scheduled\n");
#ifdef FAULT_INJECTION
    if ((sim_random(host->sim) % 1000) == 0)
        return NULL;
#endif
    return realloc(ptr, size);
}

void mock_free(void *ptr)
{
    Host *host = host___;
    if (host == NULL)
        abort_("Call to mock_free() with no node scheduled\n");
    free(ptr);
}
