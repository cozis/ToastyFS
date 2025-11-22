#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define POLL WSAPoll
typedef CRITICAL_SECTION Mutex;
#else
#include <pthread.h>
#include <arpa/inet.h>
#define POLL poll
typedef pthread_mutex_t Mutex;
#endif

#include "tcp.h"
#include "system.h"
#include "config.h"
#include "message.h"

#include <ToastyFS.h>

#define TAG_METADATA_SERVER -2

#define TAG_RETRIEVE_METADATA_FOR_READ  1
#define TAG_RETRIEVE_METADATA_FOR_WRITE 2
#define TAG_COMMIT_WRITE 3

#define TAG_UPLOAD_CHUNK_MIN 1000
#define TAG_UPLOAD_CHUNK_MAX 2000

#define PARALLEL_LIMIT 5

typedef struct {
    SHA256   hash;
    char*    dst;
    uint32_t offset_within_chunk;
    uint32_t length_within_chunk;
    Address  server_addr;      // Chunk server address for this chunk
    int      chunk_server_idx; // Index in toasty->chunk_servers array
} Range;

typedef enum {

    // This upload wasn't started yet
    UPLOAD_WAITING,

    // This upload started
    UPLOAD_PENDING,

    // This upload was WAITING but then
    // was marked as IGNORED
    UPLOAD_IGNORED,

    // Upload was PENDING and FAILED
    UPLOAD_FAILED,

    // Upload was PENDING, then COMPLETED
    // successfully
    UPLOAD_COMPLETED,

} UploadScheduleStatus;

typedef struct {
    UploadScheduleStatus status;

    // Location of the chunk to be patched.
    // The server local ID is used to indicate
    // that different addresses refer to the
    // same server.
    int     server_lid;
    Address address;
    int     chunk_index;

    // The patch offset and data
    char *src;
    int   off;
    int   len;

    // When the upload is successfull, this will
    // hold the hash of the newly created or modified
    // patch.
    SHA256 final_hash;

} UploadSchedule;

typedef enum {
    OPERATION_TYPE_FREE,
    OPERATION_TYPE_CREATE,
    OPERATION_TYPE_DELETE,
    OPERATION_TYPE_LIST,
    OPERATION_TYPE_READ,
    OPERATION_TYPE_WRITE,
} OperationType;

typedef struct {

    OperationType type;

    // Generation counter. Values 0 and 2^16-1 are
    // skipped to make sure ToastyHandle values 0
    // and -1 are always invalid.
    uint16_t generation;

    // Opaque pointer set by the user
    void *user;

    ToastyString path; // Only set for writes
    void *ptr;
    int   off;
    int   len;

    Range *ranges;
    int ranges_head;
    int ranges_count;
    int num_pending;

    // Write fields
    SHA256 *hashes;
    int      num_hashes;
    uint32_t num_chunks;
    uint32_t chunk_size;
    UploadSchedule *uploads;
    int num_uploads;
    int cap_uploads;

    ToastyResult result;
} Operation;

typedef struct {
    int tag;
    int opidx;
} Request;

typedef struct {
    int     head;
    int     count;
    Request items[MAX_REQUESTS_PER_QUEUE];
} RequestQueue;

typedef struct {
    bool         used; // TODO: should be more like "connected"
    Address      addr;
    RequestQueue reqs;
} MetadataServer;

typedef struct {

    bool used;

    // List of addresses associated to this chunk server
    int num_addrs;
    Address addrs[MAX_SERVER_ADDRS];

    // Index of the address currently in use
    int current_addr_idx;

    // If the connection was established
    bool connected;

    RequestQueue reqs;

} ChunkServer;

struct ToastyFS {

    TCP tcp;
    Mutex mutex;

    MetadataServer metadata_server;

    int num_chunk_servers;
    ChunkServer chunk_servers[MAX_CHUNK_SERVERS];

    int num_operations;
    Operation operations[MAX_OPERATIONS];
};

static int mutex_init(Mutex *mutex)
{
#ifdef _WIN32
    InitializeCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_init(mutex, NULL)) // TODO: mock
        return -1;
    return 0;
#endif
}

static int mutex_free(Mutex *mutex)
{
#ifdef _WIN32
    DeleteCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_destroy(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}

static int mutex_lock(Mutex *mutex)
{
#ifdef _WIN32
    EnterCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_lock(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}

static int mutex_unlock(Mutex *mutex)
{
#ifdef _WIN32
    LeaveCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_unlock(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}

static void request_queue_init(RequestQueue *reqs)
{
    reqs->head = 0;
    reqs->count = 0;
}

static int request_queue_push(RequestQueue *reqs, Request req)
{
    if (reqs->count == MAX_REQUESTS_PER_QUEUE)
        return -1;
    int tail = (reqs->head + reqs->count) % MAX_REQUESTS_PER_QUEUE;
    reqs->items[tail] = req;
    reqs->count++;
    return 0;
}

static int request_queue_pop(RequestQueue *reqs, Request *req)
{
    if (reqs->count == 0)
        return -1;
    if (req) *req = reqs->items[reqs->head];
    reqs->head = (reqs->head + 1) % MAX_REQUESTS_PER_QUEUE;
    reqs->count--;
    return 0;
}

static int
alloc_operation(ToastyFS *toasty, OperationType type, int off, void *ptr, int len)
{
    if (toasty->num_operations == MAX_OPERATIONS)
        return -1;
    Operation *o = toasty->operations;
    while (o->type != OPERATION_TYPE_FREE) {
        o++;
        assert(o < toasty->operations + MAX_OPERATIONS);
    }
    o->type = type;
    o->user = NULL;
    o->ptr  = ptr;
    o->off  = off;
    o->len  = len;
    o->result = (ToastyResult) { .type=TOASTY_RESULT_EMPTY };

    toasty->num_operations++;
    return o - toasty->operations;
}

static void free_operation(ToastyFS *toasty, int opidx)
{
    toasty->operations[opidx].type = OPERATION_TYPE_FREE;
    toasty->operations[opidx].generation++;
    if (toasty->operations[opidx].generation == 0 ||
        toasty->operations[opidx].generation == UINT16_MAX)
        toasty->operations[opidx].generation = 1;
    toasty->num_operations--;
}

static ToastyHandle operation_to_handle(ToastyFS *toasty, int opidx)
{
    assert(opidx >= 0);
    assert(opidx <= UINT16_MAX);

    uint16_t generation = toasty->operations[opidx].generation;
    assert(generation != 0);
    assert(generation != UINT16_MAX);

    return ((uint16_t) opidx << 16) | generation;
}

static int handle_to_operation(ToastyFS *toasty, ToastyHandle handle)
{
    if (handle == 0 || handle == UINT32_MAX)
        return -1;

    int opidx = handle >> 16;
    assert(opidx >= 0);
    assert(opidx <= UINT16_MAX);

    if (opidx >= MAX_OPERATIONS)
        return -1;

    uint16_t expected_generation = handle & 0xFFFF;
    if (toasty->operations[opidx].generation != expected_generation)
        return -1;

    return opidx;
}

ToastyFS *toasty_connect(ToastyString addr, uint16_t port)
{
    ToastyFS *toasty = sys_malloc(sizeof(ToastyFS));
    if (toasty == NULL)
        return NULL;

    Address addr2;
    {
        char tmp[128];
        if (addr.len >= (int) sizeof(tmp)) {
            sys_free(toasty);
            return NULL;
        }
        memcpy(tmp, addr.ptr, addr.len);
        tmp[addr.len] = '\0';

        addr2.is_ipv4 = true;
        addr2.port = port;
        if (inet_pton(AF_INET, tmp, &addr2.ipv4) != 1) {
            sys_free(toasty);
            return NULL;
        }
    }

    if (mutex_init(&toasty->mutex) < 0) {
        sys_free(toasty);
        return NULL;
    }

    if (tcp_context_init(&toasty->tcp) < 0) {
        mutex_free(&toasty->mutex);
        sys_free(toasty);
        return NULL;
    }

    if (tcp_connect(&toasty->tcp, addr2, TAG_METADATA_SERVER, NULL) < 0) {
        tcp_context_free(&toasty->tcp);
        mutex_free(&toasty->mutex);
        sys_free(toasty);
        return NULL;
    }

    toasty->num_operations = 0;

    for (int i = 0; i < MAX_OPERATIONS; i++) {
        toasty->operations[i].type = OPERATION_TYPE_FREE;
        toasty->operations[i].generation = 1; // Important not to start from 0 !!!
    }

    // Initialize metadata server (connected during init)
    toasty->metadata_server.used = true;
    toasty->metadata_server.addr = addr2;
    request_queue_init(&toasty->metadata_server.reqs);

    // Initialize chunk servers array (connections created on demand)
    toasty->num_chunk_servers = 0;
    for (int i = 0; i < MAX_CHUNK_SERVERS; i++) {
        toasty->chunk_servers[i].used = false;
    }

    return toasty;
}

int toasty_wakeup(ToastyFS *toasty)
{
    if (mutex_lock(&toasty->mutex) < 0)
        return -1;

    int ret;
    if (tcp_wakeup(&toasty->tcp) < 0)
        ret = -1;

    if (mutex_unlock(&toasty->mutex) < 0)
        return -1;

    return ret;
}

static void
metadata_server_request_start(ToastyFS *toasty, MessageWriter *writer, uint16_t type)
{
    ByteQueue *output;
    if (toasty->metadata_server.used) {

        int conn_idx = tcp_index_from_tag(&toasty->tcp, TAG_METADATA_SERVER);
        assert(conn_idx > -1);

        output = tcp_output_buffer(&toasty->tcp, conn_idx);
    } else {
        if (tcp_connect(&toasty->tcp, toasty->metadata_server.addr, TAG_METADATA_SERVER, &output) < 0) {
            assert(0); // TODO
        }
        toasty->metadata_server.used = true;
    }

    message_writer_init(writer, output, type);
}

static int
metadata_server_request_end(ToastyFS *toasty, MessageWriter *writer, int opidx, int tag)
{
    if (!message_writer_free(writer))
        return -1;

    RequestQueue *reqs = &toasty->metadata_server.reqs;
    if (request_queue_push(reqs, (Request) { tag, opidx }) < 0)
        return -1;

    return 0;
}

void toasty_disconnect(ToastyFS *toasty)
{
    tcp_context_free(&toasty->tcp);
    mutex_free(&toasty->mutex);
    sys_free(toasty);
}

static bool
have_insertection(Address *a, int a_num, Address *b, int b_num)
{
    for (int i = 0; i < a_num; i++)
        for (int j = 0; j < b_num; j++)
            if (addr_eql(a[i], b[j]))
                return true;
    return false;
}

// Get or create connection to a chunk server
static int get_chunk_server(ToastyFS *toasty, Address *addrs, int num_addrs, ByteQueue **output)
{
    // Check if already connected

    int found = -1;
    for (int i = 0; i < toasty->num_chunk_servers; i++) {

        if (!toasty->chunk_servers[i].used)
           continue;

        if (!have_insertection(addrs, num_addrs, toasty->chunk_servers[i].addrs, toasty->chunk_servers[i].num_addrs))
            continue;

        int conn_idx = tcp_index_from_tag(&toasty->tcp, i);
        assert(conn_idx > -1);

        if (output)
            *output = tcp_output_buffer(&toasty->tcp, conn_idx);

        found = i;
        break;
    }

    if (found == -1) {

        if (toasty->num_chunk_servers == MAX_CHUNK_SERVERS)
            return -1;

        // Find free slot
        found = 0;
        while (toasty->chunk_servers[found].used) {
            found++;
            assert(found < MAX_CHUNK_SERVERS);
        }

        if (tcp_connect(&toasty->tcp, addrs[0], found, output) < 0)
            return -1;

        if (num_addrs > MAX_SERVER_ADDRS)
            num_addrs = MAX_SERVER_ADDRS;
        toasty->chunk_servers[found].num_addrs = num_addrs;
        memcpy(toasty->chunk_servers[found].addrs, addrs, num_addrs * sizeof(Address));

        toasty->chunk_servers[found].used = true;
        toasty->chunk_servers[found].current_addr_idx = 0;
        toasty->chunk_servers[found].connected = false;

        request_queue_init(&toasty->chunk_servers[found].reqs);

        toasty->num_chunk_servers++;
    }

    return found;
}

// TODO: is this used anywhere?
static void close_chunk_server(ToastyFS *toasty, int chunk_server_idx)
{
    int conn_idx = tcp_index_from_tag(&toasty->tcp, chunk_server_idx);
    tcp_close(&toasty->tcp, conn_idx);
}

// Send download request for a chunk
static int send_download_chunk(ToastyFS *toasty, int chunk_server_idx,
    SHA256 hash, uint32_t offset, uint32_t length, int opidx, int range_idx)
{
    int conn_idx = tcp_index_from_tag(&toasty->tcp, chunk_server_idx);
    if (conn_idx < 0)
        return -1;

    ByteQueue *output = tcp_output_buffer(&toasty->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK);
    message_write_hash(&writer, hash);
    message_write_u8  (&writer, 0);
    message_write_u32 (&writer, offset);
    message_write_u32 (&writer, length);
    if (!message_writer_free(&writer))
        return -1;

    RequestQueue *reqs = &toasty->chunk_servers[chunk_server_idx].reqs;
    return request_queue_push(reqs, (Request) { range_idx, opidx });
}

static ToastyHandle begin_create(ToastyFS *toasty,
    ToastyString path, bool is_dir, uint32_t chunk_size)
{
    int opidx = -1;
    ToastyHandle handle = TOASTY_INVALID;

    if (mutex_lock(&toasty->mutex) < 0)
        return TOASTY_INVALID;

    OperationType type = OPERATION_TYPE_CREATE;

    opidx = alloc_operation(toasty, type, 0, NULL, 0);
    if (opidx < 0)
        goto unlock_and_exit;

    if (path.len > UINT16_MAX) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }
    uint16_t tmp = path.len;
    uint8_t tmp_u8 = is_dir;

    MessageWriter writer;
    metadata_server_request_start(toasty, &writer, MESSAGE_TYPE_CREATE);

    message_write(&writer, &tmp, sizeof(tmp));
    message_write(&writer, path.ptr, path.len);
    message_write(&writer, &tmp_u8, sizeof(tmp_u8));

    if (!is_dir) {
        if (chunk_size == 0 || chunk_size > UINT32_MAX) {
            free_operation(toasty, opidx);
            opidx = -1;
            goto unlock_and_exit;
        }
        uint32_t tmp_u32 = chunk_size;
        message_write(&writer, &tmp_u32, sizeof(tmp_u32));
    }

    if (metadata_server_request_end(toasty, &writer, opidx, 0) < 0) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }

    handle = operation_to_handle(toasty, opidx);

unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0) {
        if (opidx > -1)
            free_operation(toasty, opidx);
        return TOASTY_INVALID;
    }
    return handle;
}

ToastyHandle toasty_begin_create_dir(ToastyFS *toasty, ToastyString path)
{
    return begin_create(toasty, path, true, 0);
}

ToastyHandle toasty_begin_create_file(ToastyFS *toasty, ToastyString path,
    unsigned int chunk_size)
{
    return begin_create(toasty, path, false, chunk_size);
}

ToastyHandle toasty_begin_delete(ToastyFS *toasty, ToastyString path)
{
    int opidx = -1;
    ToastyHandle handle = TOASTY_INVALID;

    if (mutex_lock(&toasty->mutex) < 0)
        return TOASTY_INVALID;

    OperationType type = OPERATION_TYPE_DELETE;

    opidx = alloc_operation(toasty, type, 0, NULL, 0);
    if (opidx < 0)
        goto unlock_and_exit;

    if (path.len > UINT16_MAX) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }
    uint16_t tmp = path.len;

    MessageWriter writer;
    metadata_server_request_start(toasty, &writer, MESSAGE_TYPE_DELETE);
    message_write(&writer, &tmp, sizeof(tmp));
    message_write(&writer, path.ptr, path.len);
    if (metadata_server_request_end(toasty, &writer, opidx, 0) < 0) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }

    handle = operation_to_handle(toasty, opidx);

unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0) {
        if (opidx > -1)
            free_operation(toasty, opidx);
        return TOASTY_INVALID;
    }
    return handle;
}

ToastyHandle toasty_begin_list(ToastyFS *toasty, ToastyString path)
{
    int opidx = -1;
    ToastyHandle handle = TOASTY_INVALID;

    if (mutex_lock(&toasty->mutex) < 0)
        return TOASTY_INVALID;

    OperationType type = OPERATION_TYPE_LIST;

    opidx = alloc_operation(toasty, type, 0, NULL, 0);
    if (opidx < 0)
        goto unlock_and_exit;

    if (path.len > UINT16_MAX) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }
    uint16_t tmp = path.len;

    MessageWriter writer;
    metadata_server_request_start(toasty, &writer, MESSAGE_TYPE_LIST);
    message_write(&writer, &tmp, sizeof(tmp));
    message_write(&writer, path.ptr, path.len);
    if (metadata_server_request_end(toasty, &writer, opidx, 0) < 0) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }

    handle = operation_to_handle(toasty, opidx);

unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0) {
        if (opidx > -1)
            free_operation(toasty, opidx);
        return TOASTY_INVALID;
    }
    return handle;
}

static int send_read_message(ToastyFS *toasty, int opidx, int tag, ToastyString path, uint32_t offset, uint32_t length)
{
    if (path.len > UINT16_MAX)
        return -1;
    uint16_t path_len = path.len;

    MessageWriter writer;
    metadata_server_request_start(toasty, &writer, MESSAGE_TYPE_READ);
    message_write(&writer, &path_len, sizeof(path_len));
    message_write(&writer, path.ptr,  path.len);
    message_write(&writer, &offset,   sizeof(offset));
    message_write(&writer, &length,   sizeof(length));
    if (metadata_server_request_end(toasty, &writer, opidx, tag) < 0)
        return -1;
    return 0;
}

ToastyHandle toasty_begin_read(ToastyFS *toasty, ToastyString path, int off, void *dst, int len)
{
    int opidx = -1;
    ToastyHandle handle = TOASTY_INVALID;

    if (mutex_lock(&toasty->mutex) < 0)
        goto unlock_and_exit;

    OperationType type = OPERATION_TYPE_READ;

    opidx = alloc_operation(toasty, type, off, dst, len);
    if (opidx < 0)
        goto unlock_and_exit;

    if (send_read_message(toasty, opidx, TAG_RETRIEVE_METADATA_FOR_READ, path, off, len) < 0) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }

    handle = operation_to_handle(toasty, opidx);

unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0) {
        if (opidx > -1)
            free_operation(toasty, opidx);
        return TOASTY_INVALID;
    }
    return handle;
}

ToastyHandle toasty_begin_write(ToastyFS *toasty, ToastyString path, int off, void *src, int len)
{
    int opidx = -1;
    ToastyHandle handle = TOASTY_INVALID;

    if (mutex_lock(&toasty->mutex) < 0)
        goto unlock_and_exit;

    OperationType type = OPERATION_TYPE_WRITE;

    opidx = alloc_operation(toasty, type, off, src, len);
    if (opidx < 0)
        goto unlock_and_exit;

    toasty->operations[opidx].path = path; // TODO: must be a copy

    if (send_read_message(toasty, opidx, TAG_RETRIEVE_METADATA_FOR_WRITE, path, off, len) < 0) {
        free_operation(toasty, opidx);
        opidx = -1;
        goto unlock_and_exit;
    }

    handle = operation_to_handle(toasty, opidx);

unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0) {
        if (opidx > -1)
            free_operation(toasty, opidx);
        return TOASTY_INVALID;
    }
    return handle;
}

void toasty_free_result(ToastyResult *result)
{
    if (result->type == TOASTY_RESULT_LIST_SUCCESS)
        toasty_free_listing(&result->listing);
}

void toasty_set_uesr(ToastyFS *toasty, ToastyHandle handle, void *user)
{
    int opidx = handle_to_operation(toasty, handle);
    if (opidx < 0)
        return;

    toasty->operations[opidx].user = user;
}

static void process_event_for_create(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    (void) request_tag;

    if (msg.len == 0) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    if (type != MESSAGE_TYPE_CREATE_SUCCESS) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_CREATE_SUCCESS, .user=toasty->operations[opidx].user };
}

static void process_event_for_delete(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    (void) request_tag;

    if (msg.len == 0) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    if (type != MESSAGE_TYPE_DELETE_SUCCESS) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_DELETE_SUCCESS, .user=toasty->operations[opidx].user };
}

static void process_event_for_list(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    (void) request_tag;

    if (msg.len == 0) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    if (type != MESSAGE_TYPE_LIST_SUCCESS) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // Read and validate the list data
    uint32_t item_count;
    if (!binary_read(&reader, &item_count, sizeof(item_count))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    uint8_t truncated;
    if (!binary_read(&reader, &truncated, sizeof(truncated))) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    ToastyListingEntry *entities = sys_malloc(item_count * sizeof(ToastyListingEntry));
    if (entities == NULL) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    // Parse each list item
    for (uint32_t i = 0; i < item_count; i++) {
        uint8_t is_dir;
        if (!binary_read(&reader, &is_dir, sizeof(is_dir))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
            sys_free(entities);
            return;
        }

        uint16_t name_len;
        if (!binary_read(&reader, &name_len, sizeof(name_len))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
            sys_free(entities);
            return;
        }

        char *name = (char*) reader.src + reader.cur;
        if (!binary_read(&reader, NULL, name_len)) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
            sys_free(entities);
            return;
        }

        entities[i].is_dir = is_dir;

        if (name_len > sizeof(entities[i].name)-1) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
            sys_free(entities);
            return;
        }
        memcpy(entities[i].name, name, name_len);
        entities[i].name[name_len] = '\0';
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_ERROR, .user=toasty->operations[opidx].user };
        sys_free(entities);
        return;
    }

    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_LIST_SUCCESS, .user=toasty->operations[opidx].user, .listing=(ToastyListing) { item_count, entities } };
}

static void process_event_for_read(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    if (request_tag == TAG_RETRIEVE_METADATA_FOR_READ) {
        // Handle metadata response from metadata server
        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // Skip version
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Check message type
        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(type))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (type != MESSAGE_TYPE_READ_SUCCESS) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Skip message length
        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Read chunk size
        uint32_t chunk_size;
        if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Calculate which chunks we need
        int off = toasty->operations[opidx].off;
        int len = toasty->operations[opidx].len;

        if (len == 0) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_SUCCESS, .user=toasty->operations[opidx].user };
            return;
        }

        uint32_t first_byte = off;
        uint32_t last_byte = off + len - 1;
        uint32_t first_chunk = first_byte / chunk_size;
        uint32_t last_chunk = last_byte / chunk_size;
        uint32_t num_chunks_needed = last_chunk - first_chunk + 1;

        // Read number of hashes
        uint32_t num_hashes;
        if (!binary_read(&reader, &num_hashes, sizeof(num_hashes))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Allocate ranges
        Range *ranges = sys_malloc(num_chunks_needed * sizeof(Range));
        if (ranges == NULL) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        char *ptr = toasty->operations[opidx].ptr;
        int num_ranges_with_data = 0;

        // Parse each chunk's hash and server locations
        for (uint32_t i = 0; i < num_hashes; i++) {

            // Read hash
            SHA256 hash;
            if (!binary_read(&reader, &hash, sizeof(hash))) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            // Read number of servers
            uint32_t num_servers;
            if (!binary_read(&reader, &num_servers, sizeof(num_servers))) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            // Parse IPv4 addresses
            uint32_t num_ipv4;
            if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4))) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            Address server_addr = {0};
            bool found = false;

            // Get first IPv4 address
            for (uint32_t j = 0; j < num_ipv4; j++) {
                IPv4 ipv4;
                uint16_t port;
                if (!binary_read(&reader, &ipv4, sizeof(ipv4)) ||
                    !binary_read(&reader, &port, sizeof(port))) {
                    sys_free(ranges);
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }
                if (!found) {
                    server_addr.is_ipv4 = true;
                    server_addr.ipv4 = ipv4;
                    server_addr.port = port;
                    found = true;
                }
            }

            // Skip IPv6 addresses
            uint32_t num_ipv6;
            if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6))) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }
            for (uint32_t j = 0; j < num_ipv6; j++) {
                if (!binary_read(&reader, NULL, sizeof(IPv6)) ||
                    !binary_read(&reader, NULL, sizeof(uint16_t))) {
                    sys_free(ranges);
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }
            }

            if (!found) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            // Calculate byte range for this chunk
            uint32_t chunk_idx = first_chunk + i;
            uint32_t first_in_chunk = (chunk_idx == first_chunk) ? (first_byte % chunk_size) : 0;
            uint32_t last_in_chunk = (chunk_idx == last_chunk) ? (last_byte % chunk_size) : (chunk_size - 1);
            uint32_t len_in_chunk = 1 + last_in_chunk - first_in_chunk;

            // Fill in range info
            ranges[i].hash = hash;
            ranges[i].dst = ptr;
            ranges[i].offset_within_chunk = first_in_chunk;
            ranges[i].length_within_chunk = len_in_chunk;
            ranges[i].server_addr = server_addr;
            ranges[i].chunk_server_idx = -1;

            ptr += len_in_chunk;
            num_ranges_with_data++;
        }

        // Fill remaining chunks with zeros (sparse file)
        for (uint32_t i = num_hashes; i < num_chunks_needed; i++) {
            uint32_t chunk_idx = first_chunk + i;
            uint32_t first_in_chunk = (chunk_idx == first_chunk) ? (first_byte % chunk_size) : 0;
            uint32_t last_in_chunk = (chunk_idx == last_chunk) ? (last_byte % chunk_size) : (chunk_size - 1);
            uint32_t len_in_chunk = 1 + last_in_chunk - first_in_chunk;

            memset(ptr, 0, len_in_chunk);
            ptr += len_in_chunk;
        }

        // Store range info
        toasty->operations[opidx].ranges = ranges;
        toasty->operations[opidx].ranges_head = 0;
        toasty->operations[opidx].ranges_count = num_ranges_with_data;
        toasty->operations[opidx].num_pending = 0;

        // Start first download
        if (num_ranges_with_data > 0) {
            Range *r = &ranges[0];
            int cs_idx = get_chunk_server(toasty, &r->server_addr, 1, NULL);
            if (cs_idx < 0) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }
            r->chunk_server_idx = cs_idx;

            if (send_download_chunk(toasty, cs_idx, r->hash, r->offset_within_chunk,
                r->length_within_chunk, opidx, 0) < 0) {
                sys_free(ranges);
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            toasty->operations[opidx].num_pending = 1;
            toasty->operations[opidx].ranges_head = 1;
        } else {
            // No chunks to download
            sys_free(ranges);
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_SUCCESS, .user=toasty->operations[opidx].user };
        }

    } else {

        // Handle chunk download response
        int range_idx = request_tag;
        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // Parse response
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(type))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (type != MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint32_t data_len;
        if (!binary_read(&reader, &data_len, sizeof(data_len))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint8_t *data = reader.src + reader.cur;
        if (!binary_read(&reader, NULL, data_len)) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (binary_read(&reader, NULL, 1)) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // Copy data to destination
        if (range_idx >= 0 && range_idx < toasty->operations[opidx].ranges_count) {
            memcpy(toasty->operations[opidx].ranges[range_idx].dst, data, data_len);
        }

        toasty->operations[opidx].num_pending--;

        // Start next download (sequential)
        int next_idx = toasty->operations[opidx].ranges_head;
        if (next_idx < toasty->operations[opidx].ranges_count) {
            Range *r = &toasty->operations[opidx].ranges[next_idx];

            int cs_idx = get_chunk_server(toasty, &r->server_addr, 1, NULL);
            if (cs_idx >= 0) {
                r->chunk_server_idx = cs_idx;
                if (send_download_chunk(toasty, cs_idx, r->hash, r->offset_within_chunk,
                    r->length_within_chunk, opidx, next_idx) == 0) {
                    toasty->operations[opidx].num_pending++;
                    toasty->operations[opidx].ranges_head++;
                }
            }
        }

        // Check if done
        if (toasty->operations[opidx].num_pending == 0) {
            sys_free(toasty->operations[opidx].ranges);
            toasty->operations[opidx].ranges = NULL;
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_READ_SUCCESS, .user=toasty->operations[opidx].user };
        }
    }
}

static int start_upload(ToastyFS *toasty, int opidx)
{
    Operation *o = &toasty->operations[opidx];

    int found = -1;

    // Find a WAITING operation that can be started
    for (int i = 0; i < o->num_uploads; i++) {

        if (o->uploads[i].status != UPLOAD_WAITING)
            continue;

        // Can't start uploads of a chunk to the
        // same server twice.
        bool invalid = false;
        for (int j = 0; j < o->num_uploads; j++) {

            if (j == i)
                continue;

            if (o->uploads[j].status != UPLOAD_PENDING)
                continue;

            if (o->uploads[i].server_lid == o->uploads[j].server_lid ||
                addr_eql(o->uploads[i].address, o->uploads[j].address)) {
                invalid = true;
                break;
            }
        }

        if (invalid)
            continue;

        found = i;
        break;
    }

    if (found < 0)
        return -1; // No upload can be started at this time

    int tag = TAG_UPLOAD_CHUNK_MIN + found;
    assert(tag <= TAG_UPLOAD_CHUNK_MAX);

    ByteQueue *output;
    int chunk_server_idx = get_chunk_server(toasty, &o->uploads[found].address, 1, &output);
    if (chunk_server_idx < 0)
        return -1;

    RequestQueue *reqs = &toasty->chunk_servers[chunk_server_idx].reqs;
    if (request_queue_push(reqs, (Request) { tag, opidx }) < 0) {
        close_chunk_server(toasty, chunk_server_idx);
        return -1;
    }

    if (o->uploads[found].chunk_index >= o->num_hashes) {

        char    *data_ptr   = o->uploads[found].src;
        uint32_t chunk_size = o->chunk_size;
        uint32_t target_off = o->uploads[found].off;
        uint32_t target_len = o->uploads[found].len;

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_CHUNK);
        message_write(&writer, &chunk_size, sizeof(chunk_size));
        message_write(&writer, &target_off, sizeof(target_off));
        message_write(&writer, &target_len, sizeof(target_len));
        message_write(&writer, data_ptr, target_len);
        if (!message_writer_free(&writer)) {
            close_chunk_server(toasty, chunk_server_idx);
            request_queue_pop(reqs, NULL);
            return -1;
        }

    } else {

        char    *data_ptr    = o->uploads[found].src;
        SHA256   target_hash = o->hashes[o->uploads[found].chunk_index];
        uint32_t target_off  = o->uploads[found].off;
        uint32_t target_len  = o->uploads[found].len;

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_UPLOAD_CHUNK);
        message_write(&writer, &target_hash, sizeof(target_hash));
        message_write(&writer, &target_off,  sizeof(target_off));
        message_write(&writer, &target_len,  sizeof(target_len));
        message_write(&writer, data_ptr, target_len);
        if (!message_writer_free(&writer)) {
            close_chunk_server(toasty, chunk_server_idx);
            request_queue_pop(reqs, NULL);
            return -1;
        }
    }

    o->uploads[found].status = UPLOAD_PENDING;
    return 0;
}

static int count_pending_uploads(ToastyFS *toasty, int opidx)
{
    int n = 0;
    for (int i = 0; i < toasty->operations[opidx].num_uploads; i++)
        if (toasty->operations[opidx].uploads[i].status == UPLOAD_PENDING)
            n++;
    return n;
}

static int schedule_upload(ToastyFS *toasty, int opidx, UploadSchedule upload)
{
    Operation *o = &toasty->operations[opidx];

    if (o->num_uploads == o->cap_uploads) {

        int new_cap_uploads;
        if (o->uploads == NULL)
            new_cap_uploads = 8;
        else
            new_cap_uploads = 2 * o->cap_uploads;

        UploadSchedule *uploads = sys_malloc(new_cap_uploads * sizeof(UploadSchedule));
        if (uploads == NULL)
            return -1;

        if (o->num_uploads > 0) {
            memcpy(
                uploads,
                o->uploads,
                o->num_uploads * sizeof(UploadSchedule)
            );
            free(o->uploads);
        }

        o->uploads = uploads;
        o->cap_uploads = new_cap_uploads;
    }

    o->uploads[o->num_uploads++] = upload;
    return 0;
}

static void process_event_for_write(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
        return;
    }

    if (request_tag == TAG_RETRIEVE_METADATA_FOR_WRITE) {

        BinaryReader reader = { msg.ptr, msg.len, 0 };

        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(type))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (type != MESSAGE_TYPE_READ_SUCCESS) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint32_t chunk_size;
        if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }
        toasty->operations[opidx].chunk_size = chunk_size;

        uint32_t num_hashes;
        if (!binary_read(&reader, &num_hashes, sizeof(num_hashes))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint32_t num_all_hasehs = (toasty->operations[opidx].len + chunk_size - 1) / chunk_size;
        uint32_t num_new_hashes = num_all_hasehs - num_hashes;
        assert(num_all_hasehs >= num_hashes);

        toasty->operations[opidx].num_chunks = num_all_hasehs;
        toasty->operations[opidx].num_hashes = num_hashes; // TODO: overflow
        toasty->operations[opidx].hashes = sys_malloc(num_hashes * sizeof(SHA256));
        if (toasty->operations[opidx].hashes == NULL) {
            assert(0); // TODO
        }

        toasty->operations[opidx].uploads = NULL;
        toasty->operations[opidx].num_uploads = 0;
        toasty->operations[opidx].cap_uploads = 0;

        char *full_ptr = toasty->operations[opidx].ptr;
        int   full_off = toasty->operations[opidx].off;
        int   full_len = toasty->operations[opidx].len;

        int relative_off = 0;

        int next_server_lid = 0;
        toasty->operations[opidx].num_uploads = 0;
        for (uint32_t i = 0; i < num_hashes; i++) {

            char *src = full_ptr + relative_off;

            uint32_t off = 0;
            if (i == 0)
               off = full_off % chunk_size;

            uint32_t len = full_len - relative_off;
            if (len > chunk_size - off)
                len = chunk_size - off;

            assert(len <= chunk_size);
            assert(off <= chunk_size);
            assert(off + len <= chunk_size);

            relative_off += len;

            SHA256 hash;
            if (!binary_read(&reader, &hash, sizeof(hash))) {
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            toasty->operations[opidx].hashes[i] = hash;

            uint32_t num_holders;
            if (!binary_read(&reader, &num_holders, sizeof(num_holders))) {
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            for (uint32_t j = 0; j < num_holders; j++) {

                int server_lid = next_server_lid;
                next_server_lid++;

                uint32_t num_ipv4;
                if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }

                for (uint32_t k = 0; k < num_ipv4; k++) {

                    IPv4 ipv4;
                    if (!binary_read(&reader, &ipv4, sizeof(ipv4))) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }

                    uint16_t port;
                    if (!binary_read(&reader, &port, sizeof(port))) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }

                    UploadSchedule upload;
                    upload.status = UPLOAD_WAITING;
                    upload.server_lid = server_lid;
                    upload.address.is_ipv4 = true;
                    upload.address.ipv4 = ipv4;
                    upload.address.port = port;
                    upload.chunk_index = i;
                    upload.src = src;
                    upload.off = off;
                    upload.len = len;
                    if (schedule_upload(toasty, opidx, upload) < 0) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }
                }

                uint32_t num_ipv6;
                if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }

                for (uint32_t k = 0; k < num_ipv6; k++) {

                    IPv6 ipv6;
                    if (!binary_read(&reader, &ipv6, sizeof(ipv6))) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }

                    uint16_t port;
                    if (!binary_read(&reader, &port, sizeof(port))) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }

                    UploadSchedule upload;
                    upload.status = UPLOAD_WAITING;
                    upload.server_lid = server_lid;
                    upload.address.is_ipv4 = false;
                    upload.address.ipv6 = ipv6;
                    upload.address.port = port;
                    upload.chunk_index = i;
                    upload.src = src;
                    upload.off = off;
                    upload.len = len;
                    if (schedule_upload(toasty, opidx, upload) < 0) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }
                }
            }
        }

        uint32_t num_locations;
        if (!binary_read(&reader, &num_locations, sizeof(num_locations))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        for (uint32_t i = 0; i < num_locations; i++) {

            int server_lid = next_server_lid;
            next_server_lid++;

            uint32_t num_ipv4;
            if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4))) {
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            for (uint32_t k = 0; k < num_ipv4; k++) {

                IPv4 ipv4;
                if (!binary_read(&reader, &ipv4, sizeof(ipv4))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }

                uint16_t port;
                if (!binary_read(&reader, &port, sizeof(port))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }
#if 0
                {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipv4, ip_str, sizeof(ip_str));
                    printf("write location %s:%d\n", ip_str, port);
                }
#endif
                int old_relative_off = relative_off;

                for (uint32_t w = 0; w < num_new_hashes; w++) {

                    char *src = full_ptr + relative_off;

                    uint32_t off = 0;
                    if (num_hashes == 0 && w == 0)
                       off = full_off % chunk_size;

                    uint32_t len = full_len - relative_off;
                    if (len > chunk_size - off)
                        len = chunk_size - off;

                    assert(len <= chunk_size);
                    assert(off <= chunk_size);
                    assert(off + len <= chunk_size);

                    relative_off += len;

                    UploadSchedule upload;
                    upload.status = UPLOAD_WAITING;
                    upload.server_lid = server_lid;
                    upload.address.is_ipv4 = true;
                    upload.address.ipv4 = ipv4;
                    upload.address.port = port;
                    upload.chunk_index = num_hashes + w;
                    upload.src = src;
                    upload.off = off;
                    upload.len = len;
                    if (schedule_upload(toasty, opidx, upload) < 0) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }
                }

                relative_off = old_relative_off;
            }

            uint32_t num_ipv6;
            if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6))) {
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                return;
            }

            for (uint32_t k = 0; k < num_ipv6; k++) {

                char *src = full_ptr + relative_off;

                IPv6 ipv6;
                if (!binary_read(&reader, &ipv6, sizeof(ipv6))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }

                uint16_t port;
                if (!binary_read(&reader, &port, sizeof(port))) {
                    toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                    return;
                }
#if 0
                {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &ipv6, ip_str, sizeof(ip_str));
                    printf("write location %s:%d\n", ip_str, port);
                }
#endif
                int old_relative_off = relative_off;

                for (uint32_t w = 0; w < num_new_hashes; w++) {

                    uint32_t off = 0;
                    if (num_hashes == 0 && w == 0)
                       off = full_off % chunk_size;

                    uint32_t len = full_len - relative_off;
                    if (len > chunk_size - off)
                        len = chunk_size - off;

                    assert(len <= chunk_size);
                    assert(off <= chunk_size);
                    assert(off + len <= chunk_size);

                    relative_off += len;

                    UploadSchedule upload;
                    upload.status = UPLOAD_WAITING;
                    upload.server_lid = server_lid;
                    upload.address.is_ipv4 = false;
                    upload.address.ipv6 = ipv6;
                    upload.address.port = port;
                    upload.chunk_index = num_hashes + w;
                    upload.src = src;
                    upload.off = off;
                    upload.len = len;
                    if (schedule_upload(toasty, opidx, upload) < 0) {
                        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                        return;
                    }
                }

                relative_off = old_relative_off;
            }
        }

        // Now start the first batch of uploads
        int started = 0;
        for (int i = 0; i < PARALLEL_LIMIT; i++) {
            if (start_upload(toasty, opidx) == 0)
                started++;
        }

        if (started == 0) {
            // We already failed
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // TODO: Now we need to upload the patches to N of the
        //       chunk servers that are holding each old chunk
        //       All new chunks need to be written to the specified
        //       locations at least N times. If any upload fails,
        //       the write fails. If all writes succede, the client
        //       sends the metadata server a WRITE operation
        //       swapping the old hashes with the new ones.
        //
        // The algorithm should go like this:
        //   - Iterate over each chunk
        //     - Pick the first N holders of the chunk. If less than N
        //       are available, pick M.
        //     - For each pick, take the first address and start the
        //       chunk upload
        //
        // If an upload fails,
        //
        //
        //
        // example upload schedule:
        //   chunk_A server_A addr_0
        //   chunk_A server_A addr_1
        //   chunk_A server_B addr_0
        //   chunk_A server_B addr_1
        //   chunk_A server_B addr_2
        //   chunk_A server_C addr_0
        //   chunk_B server_D addr_0
        //   chunk_B server_E addr_0
        //   chunk_B server_E addr_1
        //   chunk_B server_F addr_0
        //
        // If an upload succedes, all uploads of the chunk to the same server
        // are removed and if this was the N-th successful upload of a chunk,
        // all uploads of the same chunk are removed.
        //
        // Uploads to the same chunk server with different addresses can't
        // be parallelized, so

        // The client should not try any random N chunk servers
        // for upload. It must try all chunk servers until N respond

    } else if (request_tag >= TAG_UPLOAD_CHUNK_MIN && request_tag <= TAG_UPLOAD_CHUNK_MAX) {

        int found = request_tag - TAG_UPLOAD_CHUNK_MIN;

        // Upload complete
        //
        // TODO:
        //   - Mark upload as complete or failed
        //   - If successful, ignore other uploads that don't
        //     need performing anymore, then start new uploads
        //   - On error, return an overall error

        // TODO: Should differentiate between chunk creation
        //       and chunk update.

        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // version
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            assert(0); // TODO
            return;
        }

        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(uint16_t))) {
            assert(0); // TODO
            return;
        }

        // length
        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            assert(0); // TODO
            return;
        }

        uint16_t expected_type;
        if (toasty->operations[opidx].uploads[found].chunk_index >= toasty->operations[opidx].num_hashes) {
            expected_type = MESSAGE_TYPE_CREATE_CHUNK_SUCCESS;
        } else {
            expected_type = MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS;
        }

        if (type != expected_type)
            toasty->operations[opidx].uploads[found].status = UPLOAD_FAILED;
        else {

            SHA256 hash;
            if (!binary_read(&reader, &hash, sizeof(hash))) {
                assert(0); // TODO
                return;
            }

            // Check that there is nothing else to read
            if (binary_read(&reader, NULL, 1)) {
                assert(0); // TODO
                return;
            }

            toasty->operations[opidx].uploads[found].status = UPLOAD_COMPLETED;
            toasty->operations[opidx].uploads[found].final_hash = hash;
            for (int i = 0; i < toasty->operations[opidx].num_uploads; i++) {

                if (toasty->operations[opidx].uploads[i].status == UPLOAD_WAITING
                    && toasty->operations[opidx].uploads[i].chunk_index == toasty->operations[opidx].uploads[found].chunk_index
                    && (addr_eql(toasty->operations[opidx].uploads[i].address, toasty->operations[opidx].uploads[found].address)
                    || toasty->operations[opidx].uploads[i].server_lid == toasty->operations[opidx].uploads[found].server_lid))
                    toasty->operations[opidx].uploads[i].status = UPLOAD_IGNORED;
            }

            // TODO: the new chunk hash should be stored in
            //       the upload struct here
        }

        // Count the number of PENDING uploads and
        // start uploads until N are pending or an
        // error occurs
        int num_pending = count_pending_uploads(toasty, opidx);
        while (num_pending < PARALLEL_LIMIT) {
            if (start_upload(toasty, opidx) < 0)
                break;
            num_pending++;
        }

        if (num_pending == 0) {

            // TODO: Check whether we managed to replicate
            //       all chunks.
            //
            // We need to make sure that every chunk was
            // uploaded to at least N different servers

            typedef struct {
                SHA256  old_hash;
                SHA256  new_hash;
                int     num_locations;
                Address locations[REPLICATION_FACTOR];
            } ChunkUploadResult;

            int num_upload_results = toasty->operations[opidx].num_chunks;
            ChunkUploadResult *upload_results = sys_malloc(num_upload_results * sizeof(ChunkUploadResult));
            if (upload_results == NULL) {
                assert(0); // TODO
            }

            for (int i = 0; i < num_upload_results; i++) {
                if (i < toasty->operations[opidx].num_hashes)
                    upload_results[i].old_hash = toasty->operations[opidx].hashes[i];
                else
                    memset(&upload_results[i].old_hash, 0, sizeof(SHA256));
                upload_results[i].num_locations = 0;
            }

            for (int i = 0; i < toasty->operations[opidx].num_uploads; i++) {
                UploadSchedule *u = &toasty->operations[opidx].uploads[i];
                if (u->status == UPLOAD_COMPLETED) {
                    int n = upload_results[u->chunk_index].num_locations++;
                    upload_results[u->chunk_index].locations[n] = u->address;
                    upload_results[u->chunk_index].new_hash = u->final_hash;
                }
            }

            // Now check that each chunk is replicated
            // at least N times

            bool ok = true;
            for (int i = 0; i < num_upload_results; i++) {
                if (upload_results[i].num_locations < REPLICATION_FACTOR) {
                    ok = false;
                    break;
                }
            }

            if (!ok) {
                toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
                free(upload_results);
                return;
            }

            MessageWriter writer;
            metadata_server_request_start(toasty, &writer, MESSAGE_TYPE_WRITE);

            ToastyString path   = toasty->operations[opidx].path;
            uint32_t     offset = toasty->operations[opidx].off;
            uint32_t     length = toasty->operations[opidx].len;

            if (path.len > UINT16_MAX) {
                assert(0); // TODO
            }
            uint16_t path_len = path.len;

            uint32_t num_chunks = num_upload_results;
            uint32_t chunk_size = toasty->operations[opidx].chunk_size;

            message_write(&writer, &path_len,   sizeof(path_len));
            message_write(&writer, path.ptr,    path.len);
            message_write(&writer, &offset,     sizeof(offset));
            message_write(&writer, &length,     sizeof(length));
            message_write(&writer, &num_chunks, sizeof(num_chunks));
            message_write(&writer, &chunk_size, sizeof(chunk_size));

            for (int i = 0; i < num_upload_results; i++) {

                // TODO: newly create chunks don't have an old hash
                message_write(&writer, &upload_results[i].old_hash, sizeof(upload_results[i].old_hash));
                message_write(&writer, &upload_results[i].new_hash, sizeof(upload_results[i].new_hash));

                uint32_t tmp = upload_results[i].num_locations;
                message_write(&writer, &tmp, sizeof(tmp));

                for (int j = 0; j < upload_results[i].num_locations; j++) {

                    Address addr = upload_results[i].locations[j];

                    uint8_t is_ipv4 = addr.is_ipv4;
                    message_write(&writer, &is_ipv4, sizeof(is_ipv4));
                    if (addr.is_ipv4) message_write(&writer, &addr.ipv4, sizeof(addr.ipv4));
                    else              message_write(&writer, &addr.ipv6, sizeof(addr.ipv6));
                    message_write(&writer, &addr.port, sizeof(addr.port));
                }
            }

            free(upload_results);

            if (metadata_server_request_end(toasty, &writer, opidx, TAG_COMMIT_WRITE) < 0) {
                assert(0); // TODO
            }
        }

    } else {

        assert(request_tag == TAG_COMMIT_WRITE);

        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // version
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(uint16_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        // length
        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (binary_read(&reader, NULL, 1)) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        if (type != MESSAGE_TYPE_WRITE_SUCCESS) {
            toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_ERROR, .user=toasty->operations[opidx].user };
            return;
        }

        toasty->operations[opidx].result = (ToastyResult) { .type=TOASTY_RESULT_WRITE_SUCCESS, .user=toasty->operations[opidx].user };
    }
}

static void process_event(ToastyFS *toasty,
    int opidx, int request_tag, ByteView msg)
{
    switch (toasty->operations[opidx].type) {

        case OPERATION_TYPE_CREATE:
        process_event_for_create(toasty, opidx, request_tag, msg);
        break;

        case OPERATION_TYPE_DELETE:
        process_event_for_delete(toasty, opidx, request_tag, msg);
        break;

        case OPERATION_TYPE_LIST:
        process_event_for_list(toasty, opidx, request_tag, msg);
        break;

        case OPERATION_TYPE_READ:
        process_event_for_read(toasty, opidx, request_tag, msg);
        break;

        case OPERATION_TYPE_WRITE:
        process_event_for_write(toasty, opidx, request_tag, msg);
        break;

        default:
        UNREACHABLE;
    }
}

static bool
translate_operation_into_result(ToastyFS *toasty, int opidx, ToastyResult *result)
{
    if (toasty->operations[opidx].result.type == TOASTY_RESULT_EMPTY)
        return false;
    *result = toasty->operations[opidx].result;
    toasty->operations[opidx].type = OPERATION_TYPE_FREE;
    toasty->num_operations--;
    return true;
}

int toasty_get_result(ToastyFS *toasty, ToastyHandle handle, ToastyResult *result)
{
    int ret;

    if (mutex_lock(&toasty->mutex) < 0) {
        ret = -1;
        goto unlock_and_exit;
    }

    int opidx;
    if (handle == TOASTY_INVALID)
        opidx = -1;
    else {
        opidx = handle_to_operation(toasty, handle);
        if (opidx < 0) {
            ret = -1;
            goto unlock_and_exit;
        }
    }

    if (opidx < 0) {
        for (int i = 0, j = 0; j < toasty->num_operations; i++) {

            if (toasty->operations[i].type == OPERATION_TYPE_FREE)
                continue;
            j++;

            if (translate_operation_into_result(toasty, i, result)) {
                ret = 0;
                goto unlock_and_exit;
            }
        }
    } else {
        if (translate_operation_into_result(toasty, opidx, result)) {
            ret = 0;
            goto unlock_and_exit;
        }
    }

    ret = 1;
unlock_and_exit:
    if (mutex_unlock(&toasty->mutex) < 0)
        return -1;
    return ret;
}

_Static_assert(TCP_POLL_CAPACITY == TOASTY_POLL_CAPACITY);

int toasty_process_events(ToastyFS *toasty, void **contexts, struct pollfd *polled, int num_polled)
{
    if (mutex_lock(&toasty->mutex) < 0)
        return -1;

    int num_events;
    Event events[TCP_EVENT_CAPACITY];

    num_events = tcp_translate_events(&toasty->tcp, events, contexts, polled, num_polled);
    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_WAKEUP:
            // Do nothing
            break;

            case EVENT_CONNECT:
            {
                int tag = tcp_get_tag(&toasty->tcp, conn_idx);
                if (tag != TAG_METADATA_SERVER)
                    toasty->chunk_servers[tag].connected = true;
            }
            break;

            case EVENT_DISCONNECT:
            {
                // A TCP connection was just dropped.
                // For clients, connections can be:
                //   1. To the metadata server
                //   2. or to a chunk server
                // If requests were buffered for the metadata
                // or chunk server, they are considered as failed
                // and their failure event is processed.
                //
                // If a chunk server was never connected,
                // then it's possible that using a different
                // address will allow connecting succesfully
                // and send the buffered messages. Therefore,
                // if a chunk server wasn't connected and
                // there are addresses to try, the messages
                // are not dropped and a new connect process
                // is started.

                RequestQueue *reqs = NULL;

                int tag = tcp_get_tag(&toasty->tcp, conn_idx);
                if (tag == TAG_METADATA_SERVER) {
                    reqs = &toasty->metadata_server.reqs;
                    toasty->metadata_server.used = false;
                } else {
                    assert(tag > -1);

                    if (toasty->chunk_servers[tag].connected)
                        reqs = &toasty->chunk_servers[tag].reqs;
                    else {

                        toasty->chunk_servers[tag].current_addr_idx++;

                        bool started = false;
                        while (toasty->chunk_servers[tag].current_addr_idx < toasty->chunk_servers[tag].num_addrs) {

                            if (tcp_connect(&toasty->tcp, toasty->chunk_servers[tag].addrs[toasty->chunk_servers[tag].current_addr_idx], tag, NULL) == 0) {
                                started = true;
                                break;
                            }

                            toasty->chunk_servers[tag].current_addr_idx++;
                        }

                        if (!started) {
                            reqs = &toasty->chunk_servers[tag].reqs;
                            toasty->chunk_servers[tag].used = false;
                        }
                    }
                }

                if (reqs) {
                    for (Request req; request_queue_pop(reqs, &req) == 0; )
                        process_event(toasty, req.opidx, req.tag, (ByteView) { NULL, 0 });
                }
            }
            break;

            case EVENT_MESSAGE:
            {
                for (;;) {

                    ByteView msg;
                    uint16_t msg_type;
                    int ret = tcp_next_message(&toasty->tcp, conn_idx, &msg, &msg_type);
                    if (ret == 0)
                        break;
                    if (ret < 0) {
                        tcp_close(&toasty->tcp, conn_idx);
                        break;
                    }

                    RequestQueue *reqs;

                    int tag = tcp_get_tag(&toasty->tcp, conn_idx);
                    if (tag == TAG_METADATA_SERVER)
                        reqs = &toasty->metadata_server.reqs;
                    else
                        reqs = &toasty->chunk_servers[tag].reqs;

                    Request req;
                    if (request_queue_pop(reqs, &req) < 0) {
                        // Unexpected message
                        tcp_consume_message(&toasty->tcp, conn_idx);
                        continue;
                    }
                    process_event(toasty, req.opidx, req.tag, msg);

                    tcp_consume_message(&toasty->tcp, conn_idx);
                }
            }
            break;
        }
    }

    int ret = tcp_register_events(&toasty->tcp, contexts, polled);

    if (mutex_unlock(&toasty->mutex) < 0)
        return -1;

    return ret;
}

int toasty_wait_result(ToastyFS *toasty, ToastyHandle handle, ToastyResult *result, int timeout)
{
    Time start_time = INVALID_TIME;
    if (timeout > -1) {
        start_time = get_current_time();
        if (start_time == INVALID_TIME)
            return -1;
    }

    void *contexts[TCP_POLL_CAPACITY];
    struct pollfd polled[TCP_POLL_CAPACITY];
    int num_polled;

    num_polled = toasty_process_events(toasty, contexts, polled, 0);

    for (;;) {

        int ret = toasty_get_result(toasty, handle, result);

        if (ret == -1)
            return -1; // Error

        if (ret == 0)
            break; // Completed

        assert(ret == 1);

        int remaining_timeout = -1;
        if (timeout > -1) {

            Time current_time = get_current_time();
            if (current_time == INVALID_TIME)
                return -1;

            int elapsed = (current_time - start_time) / 1000000;
            if (elapsed > timeout)
                return 1; // Timed out

            remaining_timeout = timeout - elapsed;
        }

        ret = POLL(polled, num_polled, remaining_timeout);
        if (ret < 0)
            return -1;

        // TODO: Detect when this returns WAKEUP
        num_polled = toasty_process_events(toasty, contexts, polled, num_polled);
        if (num_polled < 0)
            return -1;
    }

    return 0;
}

int toasty_create_dir(ToastyFS *toasty, ToastyString path)
{
    ToastyHandle handle = toasty_begin_create_dir(toasty, path);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    toasty_free_result(&result);
    return 0;
}

int toasty_create_file(ToastyFS *toasty, ToastyString path,
    unsigned int chunk_size)
{
    ToastyHandle handle = toasty_begin_create_file(toasty, path, chunk_size);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    toasty_free_result(&result);
    return 0;
}

int toasty_delete(ToastyFS *toasty, ToastyString path)
{
    ToastyHandle handle = toasty_begin_delete(toasty, path);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_DELETE_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    toasty_free_result(&result);
    return 0;
}

int toasty_list(ToastyFS *toasty, ToastyString path, ToastyListing *listing)
{
    ToastyHandle handle = toasty_begin_list(toasty, path);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_LIST_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    if (listing)
        *listing = result.listing;
    else
        toasty_free_result(&result);
    return 0;
}

void toasty_free_listing(ToastyListing *listing)
{
    sys_free(listing->items);
}

int toasty_read(ToastyFS *toasty, ToastyString path,
    int off, void *dst, int len)
{
    ToastyHandle handle = toasty_begin_read(toasty, path, off, dst, len);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_READ_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    toasty_free_result(&result);
    return 0; // TODO: return the number of bytes read?
}

int toasty_write(ToastyFS *toasty, ToastyString path,
    int off, void *src, int len)
{
    ToastyHandle handle = toasty_begin_write(toasty, path, off, src, len);
    if (handle == TOASTY_INVALID)
        return -1;

    ToastyResult result;
    if (toasty_wait_result(toasty, handle, &result, -1) < 0)
        return -1;

    if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
        toasty_free_result(&result);
        return -1;
    }

    toasty_free_result(&result);
    return 0; // TODO: return the number of bytes written?
}
