#define _GNU_SOURCE

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "message.h"
#include "metadata_server.h"

static void hash_list_init(HashList *hash_list)
{
    hash_list->count = 0;
    hash_list->capacity = 0;
    hash_list->items = NULL;
}

static void hash_list_free(HashList *hash_list)
{
    sys_free(hash_list->items);
}

static int hash_list_insert(HashList *hash_list, SHA256 hash)
{
    // Avoid duplicates
    for (int i = 0; i < hash_list->count; i++)
        if (!memcmp(&hash_list->items[i], &hash, sizeof(SHA256)))
            return 0;  // Already present

    if (hash_list->count == hash_list->capacity) {

        int new_capacity = hash_list->capacity ? hash_list->capacity * 2 : 16;

        SHA256 *new_items = sys_realloc(hash_list->items, new_capacity * sizeof(SHA256));
        if (new_items == NULL)
            return -1;

        hash_list->items = new_items;
        hash_list->capacity = new_capacity;
    }

    hash_list->items[hash_list->count++] = hash;
    return 0;
}

static bool hash_list_contains(HashList *hash_list, SHA256 hash)
{
    for (int j = 0; j < hash_list->count; j++)
        if (!memcmp(&hash, &hash_list->items[j], sizeof(SHA256)))
            return true;
    return false;
}

static void chunk_server_peer_init(ChunkServerPeer *chunk_server)
{
    chunk_server->auth = false;
    chunk_server->num_addrs = 0;
    hash_list_init(&chunk_server->old_list);
    hash_list_init(&chunk_server->add_list);
    hash_list_init(&chunk_server->rem_list);
}

static void chunk_server_peer_free(ChunkServerPeer *chunk_server)
{
    hash_list_free(&chunk_server->rem_list);
    hash_list_free(&chunk_server->add_list);
    hash_list_free(&chunk_server->old_list);
}

static bool chunk_server_peer_contains(ChunkServerPeer *chunk_server, SHA256 hash)
{
    return hash_list_contains(&chunk_server->old_list, hash)
        || hash_list_contains(&chunk_server->add_list, hash);
}

static bool chunk_server_peer_load(ChunkServerPeer *chunk_server)
{
    return chunk_server->old_list.count + chunk_server->add_list.count;
}

// Returns all chunk servers holding the given chunk
//
// The indices of the chunk servers is stored into "out", but at
// most "max" indices are written. The return value is the number
// of indices that would be written if "max" were large enough to
// hold all indices.
static int
all_chunk_servers_holding_chunk(MetadataServer *state, SHA256 hash, int *out, int max)
{
    int num = 0;
    for (int i = 0; i < state->num_chunk_servers; i++) {
        if (num < max && chunk_server_peer_contains(&state->chunk_servers[i], hash))
            out[num] = i;
        num++;
    }
    return num;
}

#ifdef _WIN32
static int compare_chunk_servers(void *data, const void *p1, const void *p2)
#else
static int compare_chunk_servers(const void *p1, const void *p2, void *data)
#endif
{
    int a = *(int*) p1;
    int b = *(int*) p2;
    MetadataServer *state = data;
    int l1 = chunk_server_peer_load(&state->chunk_servers[a]);
    int l2 = chunk_server_peer_load(&state->chunk_servers[b]);
    return l1 - l2;
}

// Returns the indices of chunk servers with lowest load in
// the "out" array. The return value is the number of indices
// written, but no more than "max" are written.
static int choose_servers_for_write(MetadataServer *state, int *out, int max)
{
    int num = state->num_chunk_servers;
    int indices[MAX_CHUNK_SERVERS];

    for (int i = 0; i < num; i++)
        indices[i] = i;

#ifdef _WIN32
    qsort_s(indices, num, sizeof(*indices), compare_chunk_servers, state);
#else
    qsort_r(indices, num, sizeof(*indices), compare_chunk_servers, state);
#endif

    if (max > num) max = num;

    for (int i = 0; i < max; i++)
        out[i] = indices[i]; // Or maybe the other way around? indices[max - i - 1]?

    return num;
}

static int find_chunk_server_by_addr(MetadataServer *state, Address addr)
{
    for (int i = 0; i < state->num_chunk_servers; i++)
        for (int j = 0; j < state->chunk_servers[i].num_addrs; j++)
            if (addr_eql(state->chunk_servers[i].addrs[j], addr))
                return j;
    return -1;
}

// Serialize the list of addresses for the specified
// chunk server.
static void
message_write_server_addr(MessageWriter *writer, ChunkServerPeer *server)
{
    uint32_t num_ipv4 = 0;
    for (int i = 0; i < server->num_addrs; i++)
        if (server->addrs[i].is_ipv4)
            num_ipv4++;

    message_write(writer, &num_ipv4, sizeof(num_ipv4));
    for (int i = 0; i < server->num_addrs; i++)
        if (server->addrs[i].is_ipv4) {
            message_write(writer, &server->addrs[i].ipv4, sizeof(server->addrs[i].ipv4));
            message_write(writer, &server->addrs[i].port, sizeof(server->addrs[i].port));
        }

    uint32_t num_ipv6 = 0;
    for (int i = 0; i < server->num_addrs; i++)
        if (!server->addrs[i].is_ipv4)
            num_ipv6++;

    message_write(writer, &num_ipv6, sizeof(num_ipv6));
    for (int i = 0; i < server->num_addrs; i++)
        if (!server->addrs[i].is_ipv4) {
            message_write(writer, &server->addrs[i].ipv6, sizeof(server->addrs[i].ipv6));
            message_write(writer, &server->addrs[i].port, sizeof(server->addrs[i].port));
        }
}

static int
process_client_create(MetadataServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint8_t is_dir;
    if (binary_read(&reader, &is_dir, sizeof(path_len)))
        return -1;

    uint32_t chunk_size;
    if (is_dir)
        chunk_size = 0;
    else {
        if (binary_read(&reader, &chunk_size, sizeof(chunk_size)))
            return -1;
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    int ret = file_tree_create_entity(&state->file_tree, path, is_dir, chunk_size);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_delete(MetadataServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    int ret = file_tree_delete_entity(&state->file_tree, path);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_DELETE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_DELETE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_list(MetadataServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_LIST_SIZE 128

    ListItem items[MAX_LIST_SIZE];
    int ret = file_tree_list(&state->file_tree, path, items, MAX_LIST_SIZE);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_SUCCESS);

        uint32_t item_count = ret;
        uint8_t truncated = 0;

        if (ret > MAX_LIST_SIZE) {
            truncated = 1;
            item_count = MAX_LIST_SIZE;
        }

        message_write(&writer, &item_count, sizeof(item_count));
        message_write(&writer, &truncated, sizeof(truncated));

        for (int i = 0; i < ret && i < MAX_LIST_SIZE; i++) {

            uint8_t is_dir = items[i].is_dir;
            message_write(&writer, &is_dir, sizeof(is_dir));

            if (items[i].name_len > UINT16_MAX)
                return -1;
            uint16_t name_len = items[i].name_len;
            message_write(&writer, &name_len, sizeof(name_len));

            message_write(&writer, items[i].name, name_len);
        }

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_read(MetadataServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (binary_read(&reader, &length, sizeof(length)))
        return -1;

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_READ_HASHES 128

    uint64_t chunk_size;
    SHA256 hashes[MAX_READ_HASHES];
    int ret = file_tree_read(&state->file_tree, path, offset, length, &chunk_size, hashes, MAX_READ_HASHES);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_SUCCESS);

        if (chunk_size > UINT32_MAX) {
            message_writer_free(&writer);
            return -1;
        }
        uint32_t tmp = chunk_size;
        message_write(&writer, &tmp, sizeof(tmp));

        uint32_t num_hashes = ret;
        message_write(&writer, &num_hashes, sizeof(num_hashes));

        for (uint32_t i = 0; i < num_hashes; i++) {

            int holders[MAX_CHUNK_SERVERS];
            int num_holders = all_chunk_servers_holding_chunk(state, hashes[i], holders, state->replication_factor);

            message_write(&writer, &hashes[i], sizeof(hashes[i]));

            uint32_t tmp = num_holders;
            message_write(&writer, &tmp, sizeof(tmp));

            for (int j = 0; j < num_holders; j++)
                message_write_server_addr(&writer, &state->chunk_servers[holders[j]]);
        }

        int locations[MAX_CHUNK_SERVERS];
        int num_locations = choose_servers_for_write(state, locations, state->replication_factor);

        for (int j = 0; j < num_locations; j++)
            message_write_server_addr(&writer, &state->chunk_servers[locations[j]]);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_write(MetadataServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (binary_read(&reader, &length, sizeof(length)))
        return -1;

    uint32_t num_chunks;
    if (binary_read(&reader, &num_chunks, sizeof(num_chunks)))
        return -1;

    #define MAX_CHUNKS_PER_WRITE 32

    Address addrs[MAX_CHUNKS_PER_WRITE];
    SHA256 new_hashes[MAX_CHUNKS_PER_WRITE];
    SHA256 old_hashes[MAX_CHUNKS_PER_WRITE];

    for (uint32_t i = 0; i < num_chunks; i++) {

        SHA256 old_hash;
        if (binary_read(&reader, &old_hash, sizeof(old_hash)))
            return -1;

        SHA256 new_hash;
        if (binary_read(&reader, &new_hash, sizeof(new_hash)))
            return -1;

        uint8_t is_ipv4;
        if (binary_read(&reader, &is_ipv4, sizeof(is_ipv4)))
            return -1;

        Address addr;
        addr.is_ipv4 = is_ipv4;

        if (is_ipv4) {
            if (binary_read(&reader, &addr.ipv4, sizeof(addr.ipv4)))
                return -1;
        } else {
            if (binary_read(&reader, &addr.ipv6, sizeof(addr.ipv6)))
                return -1;
        }

        if (binary_read(&reader, &addr.port, sizeof(addr.port)))
            return -1;

        addrs[i] = addr;
        new_hashes[i] = new_hash;
        old_hashes[i] = old_hash;
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    // Array to collect hashes that are no longer used anywhere in the file tree
    SHA256 removed_hashes[MAX_CHUNKS_PER_WRITE];
    int num_removed = 0;

    int ret = file_tree_write(&state->file_tree, path, offset, length,
                              old_hashes, new_hashes, removed_hashes, &num_removed);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_WRITE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        // Add new chunks to add_list
        for (uint32_t i = 0; i < num_chunks; i++) {
            int j = find_chunk_server_by_addr(state, addrs[i]);
            if (j == -1)
                return -1;

            if (!hash_list_insert(&state->chunk_servers[j].add_list, new_hashes[i]))
                return -1;
        }

        // Mark removed chunks for deletion on all chunk servers that have them
        // These are chunks that were overwritten and are no longer referenced anywhere
        for (int i = 0; i < num_removed; i++) {
            SHA256 removed_hash = removed_hashes[i];

            // Add to rem_list for all chunk servers that have this chunk
            for (int j = 0; j < state->num_chunk_servers; j++) {
                if (chunk_server_peer_contains(&state->chunk_servers[j], removed_hash)) {
                    if (!hash_list_insert(&state->chunk_servers[j].rem_list, removed_hash))
                        return -1;
                }
            }
        }

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_WRITE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_message(MetadataServer *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_CREATE: return process_client_create(state, conn_idx, msg);
        case MESSAGE_TYPE_DELETE: return process_client_delete(state, conn_idx, msg);
        case MESSAGE_TYPE_LIST  : return process_client_list  (state, conn_idx, msg);
        case MESSAGE_TYPE_READ  : return process_client_read  (state, conn_idx, msg);
        case MESSAGE_TYPE_WRITE : return process_client_write (state, conn_idx, msg);
        default:break;
    }
    return -1;
}

static ChunkServerPeer*
chunk_server_from_conn(MetadataServer *state, int conn_idx)
{
    int tag = tcp_get_tag(&state->tcp, conn_idx);
    assert(tag >= 0);

    return &state->chunk_servers[tag];
}

static int process_chunk_server_auth(MetadataServer *state,
    int conn_idx, ByteView msg)
{
    ChunkServerPeer *chunk_server = chunk_server_from_conn(state, conn_idx);
    chunk_server->num_addrs = 0;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    // Read IPv4s
    {
        uint32_t num_ipv4;
        if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4)))
            return -1;

        for (uint32_t i = 0; i < num_ipv4; i++) {

            IPv4 ipv4;
            if (!binary_read(&reader, &ipv4, sizeof(ipv4)))
                return -1;

            uint16_t port;
            if (!binary_read(&reader, &port, sizeof(port)))
                return -1;

            if (chunk_server->num_addrs < MAX_SERVER_ADDRS)
                chunk_server->addrs[chunk_server->num_addrs++] =
                    (Address) { .ipv4=ipv4, .is_ipv4=true, .port=port };
        }
    }

    // Read IPv6s
    {
        uint32_t num_ipv6;
        if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6)))
            return -1;

        for (uint32_t i = 0; i < num_ipv6; i++) {

            IPv6 ipv6;
            if (!binary_read(&reader, &ipv6, sizeof(ipv6)))
                return -1;

            uint16_t port;
            if (!binary_read(&reader, &port, sizeof(port)))
                return -1;

            if (chunk_server->num_addrs < MAX_SERVER_ADDRS)
                chunk_server->addrs[chunk_server->num_addrs++] =
                    (Address) { .is_ipv4=true, .ipv6=ipv6, .port=port };
        }
    }

    // No addresses were wpecified
    if (chunk_server->num_addrs == 0)
        return -1;

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    // NOTE: In a production system, this should verify the authentication
    // using the shared secret key mentioned in the architecture. For now,
    // we accept all connections that provide valid address information.
    chunk_server->auth = true;

    return 0;
}

static int
process_chunk_server_message(MetadataServer *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH:
        return process_chunk_server_auth(state, conn_idx, msg);
    }
    return -1;
}

static bool is_chunk_server_message_type(uint16_t type)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH:
        case MESSAGE_TYPE_STATE_UPDATE_ERROR:
        case MESSAGE_TYPE_STATE_UPDATE_SUCCESS:
        return true;

        default:
        break;
    }
    return false;
}

int metadata_server_init(MetadataServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout)
{
    (void) argc;
    (void) argv;

    char addr[] = "127.0.0.1";
    uint16_t port = 8080;

    state->replication_factor = 3;
    if (state->replication_factor > MAX_CHUNK_SERVERS)
        return -1;

    state->num_chunk_servers = 0;

    tcp_context_init(&state->tcp);

    int ret = tcp_listen(&state->tcp, addr, port);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    ret = file_tree_init(&state->file_tree);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    *timeout = -1;  // No timeout needed for metadata server
    return tcp_register_events(&state->tcp, contexts, polled);
}

int metadata_server_free(MetadataServer *state)
{
    file_tree_free(&state->file_tree);
    tcp_context_free(&state->tcp);
    return 0;
}

int metadata_server_step(MetadataServer *state, void **contexts, struct pollfd *polled, int num_polled, int *timeout)
{
    Event events[MAX_CONNS+1];
    int num_events = tcp_translate_events(&state->tcp, events, contexts, polled, num_polled);

    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_CONNECT:
            printf("New connection to metadata server\n");
            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_UNKNOWN);
            break;

            case EVENT_DISCONNECT:
            {
                printf("Dropped connection to metadata server\n");
                int tag = tcp_get_tag(&state->tcp, conn_idx);
                if (tag >= 0) {
                    chunk_server_peer_free(&state->chunk_servers[tag]);
                    state->num_chunk_servers--;
                }
            }
            break;

            case EVENT_MESSAGE:
            {
                for (;;) {

                    ByteView msg;
                    uint16_t msg_type;
                    int ret = tcp_next_message(&state->tcp, conn_idx, &msg, &msg_type);
                    if (ret == 0)
                        break;
                    if (ret < 0) {
                        tcp_close(&state->tcp, conn_idx);
                        break;
                    }

                    printf("Processing message to metadata server\n");

                    if (tcp_get_tag(&state->tcp, conn_idx) == CONNECTION_TAG_UNKNOWN) {
                        if (is_chunk_server_message_type(msg_type)) {
                            int chunk_server_idx = state->num_chunk_servers++;
                            chunk_server_peer_init(&state->chunk_servers[chunk_server_idx]);
                            tcp_set_tag(&state->tcp, conn_idx, chunk_server_idx);
                        } else {
                            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_CLIENT);
                        }
                    }

                    if (tcp_get_tag(&state->tcp, conn_idx) == CONNECTION_TAG_CLIENT)
                        ret = process_client_message(state, conn_idx, msg_type, msg);
                    else
                        ret = process_chunk_server_message(state, conn_idx, msg_type, msg);

                    if (ret < 0) {
                        tcp_close(&state->tcp, conn_idx);
                        break;
                    }

                    tcp_consume_message(&state->tcp, conn_idx);
                }
            }
            break;
        }
    }

    *timeout = -1;  // No timeout needed for metadata server
    return tcp_register_events(&state->tcp, contexts, polled);
}
