#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#else
#include <arpa/inet.h>
#endif

#include "tcp.h"
#include "message.h"
#include <TinyDFS.h>

#define MAX_OPERATIONS 128
#define MAX_REQUESTS_PER_QUEUE 128

#define TAG_METADATA_SERVER -2
#define TAG_METADATA_SERVER_TO_CLIENT -3

#define TAG_RETRIEVE_METADATA_FOR_READ  1
#define TAG_RETRIEVE_METADATA_FOR_WRITE 2

typedef struct {
    SHA256   hash;
    char*    dst;
    uint32_t offset_within_chunk;
    uint32_t length_within_chunk;
    Address  server_addr;      // Chunk server address for this chunk
    int      chunk_server_idx; // Index in tdfs->chunk_servers array
} Range;

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

    void *ptr;
    int   off;
    int   len;

    Range *ranges;
    int ranges_head;
    int ranges_count;
    int num_pending;

    TinyDFS_Result result;
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
    bool         used;
    Address      addr;
    RequestQueue reqs;
} MetadataServer;

typedef struct {
    bool         used;
    Address      addr;
    RequestQueue reqs;
} ChunkServer;

struct TinyDFS {

    TCP tcp;

    MetadataServer metadata_server;

    int num_chunk_servers;
    ChunkServer chunk_servers[MAX_CHUNK_SERVERS];

    int num_operations;
    Operation operations[MAX_OPERATIONS];

};

TinyDFS *tinydfs_init(char *addr, uint16_t port)
{
    TinyDFS *tdfs = malloc(sizeof(TinyDFS));
    if (tdfs == NULL)
        return NULL;

    Address addr2;
    addr2.is_ipv4 = true;
    addr2.port = port;
    if (inet_pton(AF_INET, addr, &addr2.ipv4) != 1) {
        free(tdfs);
        return NULL;
    }

    tcp_context_init(&tdfs->tcp);

    if (tcp_connect(&tdfs->tcp, addr2, TAG_METADATA_SERVER, NULL) < 0) {
        tcp_context_free(&tdfs->tcp);
        free(tdfs);
        return NULL;
    }

    tdfs->num_operations = 0;

    for (int i = 0; i < MAX_OPERATIONS; i++)
        tdfs->operations[i].type = OPERATION_TYPE_FREE;

    return tdfs;
}

void tinydfs_free(TinyDFS *tdfs)
{
    tcp_context_free(&tdfs->tcp);
    free(tdfs);
}

static int
alloc_operation(TinyDFS *tdfs, OperationType type, int off, void *ptr, int len)
{
    if (tdfs->num_operations == MAX_OPERATIONS)
        return -1;
    Operation *o = tdfs->operations;
    while (o->type != OPERATION_TYPE_FREE)
        o++;
    o->type = type;
    o->ptr  = ptr;
    o->off  = off;
    o->len  = len;
    o->result = (TinyDFS_Result) { .type=TINYDFS_RESULT_EMPTY };

    tdfs->num_operations++;
    return o - tdfs->operations;
}

static void free_operation(TinyDFS *tdfs, int opidx)
{
    tdfs->operations[opidx].type = OPERATION_TYPE_FREE;
    tdfs->num_operations--;
}

static void
request_queue_init(RequestQueue *reqs)
{
    reqs->head = 0;
    reqs->count = 0;
}

static int
request_queue_push(RequestQueue *reqs, Request req)
{
    if (reqs->count == MAX_REQUESTS_PER_QUEUE)
        return -1;
    int tail = (reqs->head + reqs->count) % MAX_REQUESTS_PER_QUEUE;
    reqs->items[tail] = req;
    reqs->count++;
    return 0;
}

static int
request_queue_pop(RequestQueue *reqs, Request *req)
{
    if (reqs->count == 0)
        return -1;
    if (req) *req = reqs->items[reqs->head];
    reqs->head = (reqs->head + 1) % MAX_REQUESTS_PER_QUEUE;
    reqs->count--;
    return 0;
}

// Get or create connection to a chunk server
static int get_chunk_server_connection(TinyDFS *tdfs, Address addr)
{
    // Check if already connected
    for (int i = 0; i < tdfs->num_chunk_servers; i++) {
        if (tdfs->chunk_servers[i].used && addr_eql(tdfs->chunk_servers[i].addr, addr)) {
            int conn_idx = tcp_index_from_tag(&tdfs->tcp, i);
            if (conn_idx >= 0)
                return i;
        }
    }

    // Find free slot
    int idx = -1;
    for (int i = 0; i < MAX_CHUNK_SERVERS; i++) {
        if (!tdfs->chunk_servers[i].used) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return -1;

    // Connect
    if (tcp_connect(&tdfs->tcp, addr, idx, NULL) < 0)
        return -1;

    // Initialize
    tdfs->chunk_servers[idx].used = true;
    tdfs->chunk_servers[idx].addr = addr;
    request_queue_init(&tdfs->chunk_servers[idx].reqs);
    tdfs->num_chunk_servers++;

    return idx;
}

// Send download request for a chunk
static int send_download_chunk(TinyDFS *tdfs, int chunk_server_idx,
    SHA256 hash, uint32_t offset, uint32_t length, int opidx, int range_idx)
{
    int conn_idx = tcp_index_from_tag(&tdfs->tcp, chunk_server_idx);
    if (conn_idx < 0) return -1;

    MessageWriter writer;
    ByteQueue *output = tcp_output_buffer(&tdfs->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK);

    message_write(&writer, &hash, sizeof(hash));
    message_write(&writer, &offset, sizeof(offset));
    message_write(&writer, &length, sizeof(length));

    if (!message_writer_free(&writer))
        return -1;

    RequestQueue *reqs = &tdfs->chunk_servers[chunk_server_idx].reqs;
    return request_queue_push(reqs, (Request) { range_idx, opidx });
}

static void
metadata_server_request_start(TinyDFS *tdfs, MessageWriter *writer, uint16_t type)
{
    int conn_idx = tcp_index_from_tag(&tdfs->tcp, TAG_METADATA_SERVER);
    ByteQueue *output = tcp_output_buffer(&tdfs->tcp, conn_idx);
    message_writer_init(writer, output, type);
}

static int
metadata_server_request_end(TinyDFS *tdfs, MessageWriter *writer, int opidx, int tag)
{
    if (!message_writer_free(writer))
        return -1;

    RequestQueue *reqs = &tdfs->metadata_server.reqs;
    if (request_queue_push(reqs, (Request) { tag, opidx }) < 0)
        return -1;

    return 0;
}

int tinydfs_submit_create(TinyDFS *tdfs, char *path, int path_len,
    bool is_dir, uint32_t chunk_size)
{
    if (path_len < 0) path_len = strlen(path);

    OperationType type = OPERATION_TYPE_CREATE;
    int opidx = alloc_operation(tdfs, type, 0, NULL, 0);
    if (opidx < 0) return -1;

    MessageWriter writer;
    metadata_server_request_start(tdfs, &writer, MESSAGE_TYPE_CREATE);

    if (path_len > UINT16_MAX) {
        free_operation(tdfs, opidx);
        return -1;
    }
    uint16_t tmp = path_len;
    message_write(&writer, &tmp, sizeof(tmp));

    message_write(&writer, path, path_len);

    uint8_t tmp_u8 = is_dir;
    message_write(&writer, &tmp_u8, sizeof(tmp_u8));

    if (!is_dir) {
        if (chunk_size == 0 || chunk_size > UINT32_MAX) {
            free_operation(tdfs, opidx);
            return -1;
        }
        uint32_t tmp_u32 = chunk_size;
        message_write(&writer, &tmp_u32, sizeof(tmp_u32));
    }

    if (metadata_server_request_end(tdfs, &writer, opidx, 0) < 0) {
        free_operation(tdfs, opidx);
        return -1;
    }

    return 0;
}

int tinydfs_submit_delete(TinyDFS *tdfs, char *path, int path_len)
{
    if (path_len < 0) path_len = strlen(path);

    OperationType type = OPERATION_TYPE_DELETE;
    int opidx = alloc_operation(tdfs, type, 0, NULL, 0);
    if (opidx < 0) return -1;

    MessageWriter writer;
    metadata_server_request_start(tdfs, &writer, MESSAGE_TYPE_DELETE);

    if (path_len > UINT16_MAX) {
        free_operation(tdfs, opidx);
        return -1;
    }
    uint16_t tmp = path_len;
    message_write(&writer, &tmp, sizeof(tmp));

    message_write(&writer, path, path_len);

    if (metadata_server_request_end(tdfs, &writer, opidx, 0) < 0) {
        free_operation(tdfs, opidx);
        return -1;
    }

    return 0;
}

int tinydfs_submit_list(TinyDFS *tdfs, char *path, int path_len)
{
    if (path_len < 0) path_len = strlen(path);

    OperationType type = OPERATION_TYPE_LIST;
    int opidx = alloc_operation(tdfs, type, 0, NULL, 0);
    if (opidx < 0) return -1;

    MessageWriter writer;
    metadata_server_request_start(tdfs, &writer, MESSAGE_TYPE_LIST);

    if (path_len > UINT16_MAX) {
        free_operation(tdfs, opidx);
        return -1;
    }
    uint16_t tmp = path_len;
    message_write(&writer, &tmp, sizeof(tmp));

    message_write(&writer, path, path_len);

    if (metadata_server_request_end(tdfs, &writer, opidx, 0) < 0) {
        free_operation(tdfs, opidx);
        return -1;
    }

    return 0;
}

static int send_read_message(TinyDFS *tdfs, int opidx, int tag, string path, uint32_t offset, uint32_t length)
{
    if (path.len > UINT16_MAX)
        return -1;
    uint16_t path_len = path.len;

    MessageWriter writer;
    metadata_server_request_start(tdfs, &writer, MESSAGE_TYPE_READ);
    message_write(&writer, &path_len, sizeof(path_len));
    message_write(&writer, path.ptr,  path.len);
    message_write(&writer, &offset,   sizeof(offset));
    message_write(&writer, &length,   sizeof(length));
    if (metadata_server_request_end(tdfs, &writer, opidx, tag) < 0)
        return -1;
    return 0;
}

int tinydfs_submit_read(TinyDFS *tdfs, char *path, int path_len, int off, void *dst, int len)
{
    if (path_len < 0) path_len = strlen(path);

    OperationType type = OPERATION_TYPE_READ;
    int opidx = alloc_operation(tdfs, type, off, dst, len);
    if (opidx < 0) return -1;

    if (send_read_message(tdfs, opidx, TAG_RETRIEVE_METADATA_FOR_READ, (string) { path, path_len }, off, len) < 0) {
        free_operation(tdfs, opidx);
        return -1;
    }

    return 0;
}

int tinydfs_submit_write(TinyDFS *tdfs, char *path, int path_len, int off, void *src, int len)
{
    if (path_len < 0) path_len = strlen(path);

    OperationType type = OPERATION_TYPE_WRITE;
    int opidx = alloc_operation(tdfs, type, off, src, len);
    if (opidx < 0) return -1;

    if (send_read_message(tdfs, opidx, TAG_RETRIEVE_METADATA_FOR_WRITE, (string) { path, path_len }, off, len) < 0) {
        free_operation(tdfs, opidx);
        return -1;
    }

    return 0;
}

void tinydfs_result_free(TinyDFS_Result *result)
{
    if (result->type == TINYDFS_RESULT_LIST_SUCCESS)
        free(result->entities);
}

static void process_event_for_create(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_CREATE_SUCCESS) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_ERROR };
        return;
    }

    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_CREATE_SUCCESS };
}

static void process_event_for_delete(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_DELETE_SUCCESS) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_ERROR };
        return;
    }

    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_DELETE_SUCCESS };
}

static void process_event_for_list(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_LIST_SUCCESS) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    // Read and validate the list data
    uint32_t item_count;
    if (!binary_read(&reader, &item_count, sizeof(item_count))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    uint8_t truncated;
    if (!binary_read(&reader, &truncated, sizeof(truncated))) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    TinyDFS_Entity *entities = malloc(item_count * sizeof(TinyDFS_Entity));
    if (entities == NULL) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        return;
    }

    // Parse each list item
    for (uint32_t i = 0; i < item_count; i++) {
        uint8_t is_dir;
        if (!binary_read(&reader, &is_dir, sizeof(is_dir))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
            free(entities);
            return;
        }

        uint16_t name_len;
        if (!binary_read(&reader, &name_len, sizeof(name_len))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
            free(entities);
            return;
        }

        char *name = reader.src + reader.cur;
        if (!binary_read(&reader, NULL, name_len)) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
            free(entities);
            return;
        }

        entities[i].is_dir = is_dir;

        if (name_len > sizeof(entities[i].name)-1) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
            free(entities);
            return;
        }
        memcpy(entities[i].name, name, name_len);
        entities[i].name[name_len] = '\0';
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_ERROR };
        free(entities);
        return;
    }

    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_LIST_SUCCESS, item_count, entities };
}

static void process_event_for_read(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
        return;
    }

    if (request_tag == TAG_RETRIEVE_METADATA_FOR_READ) {
        // Handle metadata response from metadata server
        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // Skip version
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Check message type
        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(type))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        if (type != MESSAGE_TYPE_READ_SUCCESS) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Skip message length
        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Read chunk size
        uint32_t chunk_size;
        if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Calculate which chunks we need
        int off = tdfs->operations[opidx].off;
        int len = tdfs->operations[opidx].len;

        if (len == 0) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_SUCCESS };
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
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Allocate ranges
        Range *ranges = malloc(num_chunks_needed * sizeof(Range));
        if (ranges == NULL) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        char *ptr = tdfs->operations[opidx].ptr;
        int num_ranges_with_data = 0;

        // Parse each chunk's hash and server locations
        for (uint32_t i = 0; i < num_hashes; i++) {
            // Read hash
            SHA256 hash;
            if (!binary_read(&reader, &hash, sizeof(hash))) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                return;
            }

            // Read number of servers
            uint32_t num_servers;
            if (!binary_read(&reader, &num_servers, sizeof(num_servers))) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                return;
            }

            // Parse IPv4 addresses
            uint32_t num_ipv4;
            if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4))) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
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
                    free(ranges);
                    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
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
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                return;
            }
            for (uint32_t j = 0; j < num_ipv6; j++) {
                if (!binary_read(&reader, NULL, sizeof(IPv6)) ||
                    !binary_read(&reader, NULL, sizeof(uint16_t))) {
                    free(ranges);
                    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                    return;
                }
            }

            if (!found) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
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
        tdfs->operations[opidx].ranges = ranges;
        tdfs->operations[opidx].ranges_head = 0;
        tdfs->operations[opidx].ranges_count = num_ranges_with_data;
        tdfs->operations[opidx].num_pending = 0;

        // Start first download
        if (num_ranges_with_data > 0) {
            Range *r = &ranges[0];
            int cs_idx = get_chunk_server_connection(tdfs, r->server_addr);
            if (cs_idx < 0) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                return;
            }
            r->chunk_server_idx = cs_idx;

            if (send_download_chunk(tdfs, cs_idx, r->hash, r->offset_within_chunk,
                r->length_within_chunk, opidx, 0) < 0) {
                free(ranges);
                tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
                return;
            }

            tdfs->operations[opidx].num_pending = 1;
            tdfs->operations[opidx].ranges_head = 1;
        } else {
            // No chunks to download
            free(ranges);
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_SUCCESS };
        }

    } else {
        // Handle chunk download response
        int range_idx = request_tag;
        BinaryReader reader = { msg.ptr, msg.len, 0 };

        // Parse response
        if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        uint16_t type;
        if (!binary_read(&reader, &type, sizeof(type))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        if (type != MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        uint32_t data_len;
        if (!binary_read(&reader, &data_len, sizeof(data_len))) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        uint8_t *data = reader.src + reader.cur;
        if (!binary_read(&reader, NULL, data_len)) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        if (binary_read(&reader, NULL, 1)) {
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_ERROR };
            return;
        }

        // Copy data to destination
        if (range_idx >= 0 && range_idx < tdfs->operations[opidx].ranges_count) {
            memcpy(tdfs->operations[opidx].ranges[range_idx].dst, data, data_len);
        }

        tdfs->operations[opidx].num_pending--;

        // Start next download (sequential)
        int next_idx = tdfs->operations[opidx].ranges_head;
        if (next_idx < tdfs->operations[opidx].ranges_count) {
            Range *r = &tdfs->operations[opidx].ranges[next_idx];

            int cs_idx = get_chunk_server_connection(tdfs, r->server_addr);
            if (cs_idx >= 0) {
                r->chunk_server_idx = cs_idx;
                if (send_download_chunk(tdfs, cs_idx, r->hash, r->offset_within_chunk,
                    r->length_within_chunk, opidx, next_idx) == 0) {
                    tdfs->operations[opidx].num_pending++;
                    tdfs->operations[opidx].ranges_head++;
                }
            }
        }

        // Check if done
        if (tdfs->operations[opidx].num_pending == 0) {
            free(tdfs->operations[opidx].ranges);
            tdfs->operations[opidx].ranges = NULL;
            tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_READ_SUCCESS };
        }
    }
}

static void process_event_for_write(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_WRITE_ERROR };
        return;
    }

    switch (request_tag) {

        case TAG_RETRIEVE_METADATA_FOR_WRITE:
        // Process metadata response and initiate chunk uploads
        // This would involve:
        // 1. Parsing the metadata response (chunk locations, hashes)
        // 2. Computing new chunk data by patching existing chunks
        // 3. Uploading new chunks to chunk servers
        // 4. Committing the write to the metadata server with new hashes
        // For now, this operation is not fully implemented
        tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_WRITE_ERROR };
        return;

        default:
        break;
    }

    // Write operation processing not fully implemented
    tdfs->operations[opidx].result = (TinyDFS_Result) { .type=TINYDFS_RESULT_WRITE_ERROR };
}

static void process_event(TinyDFS *tdfs,
    int opidx, int request_tag, ByteView msg)
{
    switch (tdfs->operations[opidx].type) {
        case OPERATION_TYPE_CREATE: process_event_for_create(tdfs, opidx, request_tag, msg); break;
        case OPERATION_TYPE_DELETE: process_event_for_delete(tdfs, opidx, request_tag, msg); break;
        case OPERATION_TYPE_LIST  : process_event_for_list  (tdfs, opidx, request_tag, msg); break;
        case OPERATION_TYPE_READ  : process_event_for_read  (tdfs, opidx, request_tag, msg); break;
        case OPERATION_TYPE_WRITE : process_event_for_write (tdfs, opidx, request_tag, msg); break;
        default: UNREACHABLE;
    }
}

static bool
translate_operation_into_result(TinyDFS *tdfs, int opidx, TinyDFS_Result *result)
{
    if (tdfs->operations[opidx].result.type == TINYDFS_RESULT_EMPTY)
        return false;
    *result = tdfs->operations[opidx].result;
    tdfs->operations[opidx].type = OPERATION_TYPE_FREE;
    tdfs->num_operations--;
    return true;
}

void tinydfs_wait(TinyDFS *tdfs, int opidx, TinyDFS_Result *result, int timeout)
{
    for (;;) {

        if (opidx < 0) {
            for (int i = 0, j = 0; j < tdfs->num_operations; i++) {

                if (tdfs->operations[i].type == OPERATION_TYPE_FREE)
                    continue;
                j++;

                if (translate_operation_into_result(tdfs, i, result))
                    return;
            }
        } else {
            if (translate_operation_into_result(tdfs, opidx, result))
                return;
        }

        int num_events;
        Event events[MAX_CONNS+1];

        num_events = tcp_process_events(&tdfs->tcp, events);
        for (int i = 0; i < num_events; i++) {
            int conn_idx = events[i].conn_idx;
            switch (events[i].type) {

                case EVENT_CONNECT:
                break;

                case EVENT_DISCONNECT:
                {
                    RequestQueue *reqs;

                    int tag = tcp_get_tag(&tdfs->tcp, conn_idx);
                    if (tag == TAG_METADATA_SERVER_TO_CLIENT)
                        reqs = &tdfs->metadata_server.reqs;
                    else {
                        assert(tag > -1);
                        reqs = &tdfs->chunk_servers[tag].reqs;
                    }

                    for (Request req; request_queue_pop(reqs, &req) == 0; )
                        process_event(tdfs, req.opidx, req.tag, (ByteView) { NULL, 0 });
                }
                break;

                case EVENT_MESSAGE:
                {
                    for (;;) {

                        ByteView msg;
                        uint16_t msg_type;
                        int ret = tcp_next_message(&tdfs->tcp, conn_idx, &msg, &msg_type);
                        if (ret == 0)
                            break;
                        if (ret < 0) {
                            tcp_close(&tdfs->tcp, conn_idx);
                            break;
                        }

                        RequestQueue *reqs;

                        int tag = tcp_get_tag(&tdfs->tcp, conn_idx);
                        if (tag == TAG_METADATA_SERVER_TO_CLIENT)
                            reqs = &tdfs->metadata_server.reqs;
                        else {
                            assert(tag > -1);
                            reqs = &tdfs->chunk_servers[tag].reqs;
                        }

                        Request req;
                        if (request_queue_pop(reqs, &req) < 0) {
                            UNREACHABLE;
                        }
                        process_event(tdfs, req.opidx, req.tag, msg);

                        tcp_consume_message(&tdfs->tcp, conn_idx);
                    }
                }
                break;
            }
        }
    }
}
