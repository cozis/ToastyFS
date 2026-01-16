#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdint.h>
#include <assert.h>

#include "message.h"
#include "metadata_server.h"

#define MS_TRACE(fmt, ...) fprintf(stderr, "MS: " fmt "\n", ##__VA_ARGS__);

static void chunk_server_peer_init(ChunkServerPeer *chunk_server, Time current_time)
{
    chunk_server->used = true;
    chunk_server->auth = false;
    chunk_server->num_addrs = 0;
    hash_set_init(&chunk_server->ms_old_list);
    hash_set_init(&chunk_server->ms_add_list);
    hash_set_init(&chunk_server->ms_rem_list);
    chunk_server->last_sync_time = current_time;
    chunk_server->last_response_time = current_time;
}

static void chunk_server_peer_free(ChunkServerPeer *chunk_server)
{
    hash_set_free(&chunk_server->ms_rem_list);
    hash_set_free(&chunk_server->ms_add_list);
    hash_set_free(&chunk_server->ms_old_list);
    chunk_server->used = false;
}

static bool chunk_server_peer_contains(ChunkServerPeer *chunk_server, SHA256 hash)
{
    return hash_set_contains(&chunk_server->ms_old_list, hash)
        || hash_set_contains(&chunk_server->ms_add_list, hash);
}

static bool chunk_server_peer_load(ChunkServerPeer *chunk_server)
{
    return chunk_server->ms_old_list.count
         + chunk_server->ms_add_list.count;
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
        if (chunk_server_peer_contains(&state->chunk_servers[i], hash)) {
            if (num < max)
                out[num] = i;
            num++;
        }
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
static int
choose_servers_for_write(MetadataServer *state, int *out, int max)
{
    int num = state->num_chunk_servers;

    int indices[MAX_CHUNK_SERVERS];
    assert(num <= MAX_CHUNK_SERVERS);

    for (int i = 0; i < num; i++)
        indices[i] = i;

#ifdef _WIN32
    qsort_s(indices, num, sizeof(*indices), compare_chunk_servers, state);
#else
    qsort_r(indices, num, sizeof(*indices), compare_chunk_servers, state);
#endif

    for (int i = 0; i < num; i++) {
        if (i < max)
            out[i] = indices[i]; // Or maybe the other way around? indices[max - i - 1]?
    }

    return num;
}

static int find_chunk_server_by_addr(MetadataServer *state, Address addr)
{
    for (int i = 0; i < state->num_chunk_servers; i++)
        for (int j = 0; j < state->chunk_servers[i].num_addrs; j++)
            if (addr_eql(state->chunk_servers[i].addrs[j], addr))
                return i;
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

    if (!binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (!binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint8_t is_dir;
    if (!binary_read(&reader, &is_dir, sizeof(is_dir)))
        return -1;

    uint32_t chunk_size;
    if (is_dir)
        chunk_size = 0;
    else {
        if (!binary_read(&reader, &chunk_size, sizeof(chunk_size)))
            return -1;
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    if (wal_append_create(&state->wal, path, is_dir, chunk_size) < 0) {
        assert(0); // TODO
    }

    uint64_t gen;
    int ret = file_tree_create_entity(&state->file_tree, path, is_dir, chunk_size, &gen);

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
        message_write(&writer, &gen, sizeof(gen));
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

    uint64_t expect_gen;
    if (!binary_read(&reader, &expect_gen, sizeof(expect_gen)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (!binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (!binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    if (wal_append_delete(&state->wal, path, expect_gen) < 0) {
        assert(0); // TODO
    }

    // TODO: return unused hashes and add them to the ms_rem_list of holder chunk servers
    int ret = file_tree_delete_entity(&state->file_tree, path, expect_gen);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_DELETE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
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

    uint64_t expect_gen;
    if (!binary_read(&reader, &expect_gen, sizeof(expect_gen)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (!binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (!binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_LIST_SIZE 128

    uint64_t gen;
    ListItem items[MAX_LIST_SIZE];
    int ret = file_tree_list(&state->file_tree, path, items, MAX_LIST_SIZE, &gen);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_SUCCESS);

        message_write(&writer, &gen, sizeof(gen));

        uint32_t item_count = ret;
        uint8_t truncated = 0;

        if (ret > MAX_LIST_SIZE) {
            truncated = 1;
            item_count = MAX_LIST_SIZE;
        }

        message_write(&writer, &truncated, sizeof(truncated));
        message_write(&writer, &item_count, sizeof(item_count));

        for (int i = 0; i < ret && i < MAX_LIST_SIZE; i++) {

            message_write(&writer, &items[i].gen, sizeof(items[i].gen));

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

    uint64_t expect_gen;
    if (!binary_read(&reader, &expect_gen, sizeof(expect_gen)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (!binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (!binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (!binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (!binary_read(&reader, &length, sizeof(length)))
        return -1;

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_READ_HASHES 128

    uint64_t gen;
    uint64_t chunk_size;
    uint64_t actual_bytes;
    SHA256 hashes[MAX_READ_HASHES];
    int ret = file_tree_read(&state->file_tree, path, offset, length, &gen, &chunk_size, hashes, MAX_READ_HASHES, &actual_bytes);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        int locations[MAX_CHUNK_SERVERS];
        int num_locations = choose_servers_for_write(state, locations, state->replication_factor);

        assert(num_locations > -1 && num_locations < MAX_CHUNK_SERVERS);
        if (num_locations > state->replication_factor)
            num_locations = state->replication_factor;

        uint32_t tmp_u32 = num_locations;
        message_write(&writer, &tmp_u32, sizeof(tmp_u32));

        for (int j = 0; j < num_locations; j++) {

            int k = locations[j];

            assert(k > -1);
            assert(k < state->num_chunk_servers);
            assert(state->chunk_servers[k].auth == true);
            assert(state->chunk_servers[k].num_addrs > 0);

            message_write_server_addr(&writer, &state->chunk_servers[k]);
        }

        if (!message_writer_free(&writer))
            return -1;

    } else {

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_SUCCESS);

        assert(gen != NO_GENERATION);
        message_write(&writer, &gen, sizeof(gen));

        if (chunk_size > UINT32_MAX) {
            message_writer_free(&writer);
            return -1;
        }
        uint32_t tmp = chunk_size;
        message_write(&writer, &tmp, sizeof(tmp));

        // Send the actual number of bytes that can be read
        if (actual_bytes > UINT32_MAX) {
            message_writer_free(&writer);
            return -1;
        }
        uint32_t tmp_actual = actual_bytes;
        message_write(&writer, &tmp_actual, sizeof(tmp_actual));

        uint32_t num_hashes = ret;
        message_write(&writer, &num_hashes, sizeof(num_hashes));

        for (uint32_t i = 0; i < num_hashes; i++) {

            int holders[MAX_CHUNK_SERVERS];
            int num_holders = all_chunk_servers_holding_chunk(state, hashes[i], holders, state->replication_factor);
            assert(num_holders > -1 && num_holders < MAX_CHUNK_SERVERS);

            message_write(&writer, &hashes[i], sizeof(hashes[i]));

            uint32_t tmp = num_holders;
            message_write(&writer, &tmp, sizeof(tmp));

            for (int j = 0; j < num_holders; j++) {

                int k = holders[j];

                assert(k > -1 && k < state->num_chunk_servers);
                assert(state->chunk_servers[k].auth == true);
                assert(state->chunk_servers[k].num_addrs > 0);

                message_write_server_addr(&writer, &state->chunk_servers[k]);
            }
        }

        int locations[MAX_CHUNK_SERVERS];
        int num_locations = choose_servers_for_write(state, locations, state->replication_factor);

        assert(num_locations > -1 && num_locations < MAX_CHUNK_SERVERS);
        if (num_locations > state->replication_factor)
            num_locations = state->replication_factor;

        uint32_t tmp_u32 = num_locations;
        message_write(&writer, &tmp_u32, sizeof(tmp_u32));

        for (int j = 0; j < num_locations; j++) {

            int k = locations[j];

            assert(k > -1);
            assert(k < state->num_chunk_servers);
            assert(state->chunk_servers[k].auth == true);
            assert(state->chunk_servers[k].num_addrs > 0);

            message_write_server_addr(&writer, &state->chunk_servers[k]);
        }

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

    uint64_t expect_gen;
    if (!binary_read(&reader, &expect_gen, sizeof(expect_gen)))
        return -1;

    uint32_t flags;
    if (!binary_read(&reader, &flags, sizeof(flags)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (!binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2; // TODO: what is this -2 business?

    if (!binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (!binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (!binary_read(&reader, &length, sizeof(length)))
        return -1;

    uint32_t num_chunks;
    if (!binary_read(&reader, &num_chunks, sizeof(num_chunks)))
        return -1;

    #define MAX_CHUNKS_PER_WRITE 32

    typedef struct {
        SHA256  hash;
        int     num_addrs;
        Address addrs[REPLICATION_FACTOR];
    } ChunkWriteResult;

    ChunkWriteResult results[MAX_CHUNKS_PER_WRITE];

    if (num_chunks > MAX_CHUNKS_PER_WRITE)
        return -1; // TODO

    for (uint32_t i = 0; i < num_chunks; i++) {

        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash)))
            return -1;

        results[i].hash = hash;
        results[i].num_addrs = 0;

        uint32_t num_locations;
        if (!binary_read(&reader, &num_locations, sizeof(num_locations)))
            return -1;

        for (uint32_t j = 0; j < num_locations; j++) {

            uint8_t is_ipv4;
            if (!binary_read(&reader, &is_ipv4, sizeof(is_ipv4)))
                return -1;

            Address addr = {0};
            addr.is_ipv4 = is_ipv4;

            if (is_ipv4) {
                if (!binary_read(&reader, &addr.ipv4, sizeof(addr.ipv4)))
                    return -1;
            } else {
                if (!binary_read(&reader, &addr.ipv6, sizeof(addr.ipv6)))
                    return -1;
            }

            if (!binary_read(&reader, &addr.port, sizeof(addr.port)))
                return -1;

            if (results[i].num_addrs < REPLICATION_FACTOR)
                results[i].addrs[results[i].num_addrs++] = addr;
        }
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    // Array to collect hashes that are no longer used anywhere in the file tree
    SHA256 removed_hashes[MAX_CHUNKS_PER_WRITE];
    int num_removed = 0;

    SHA256 new_hashes[MAX_CHUNKS_PER_WRITE];
    for (uint32_t i = 0; i < num_chunks; i++)
        new_hashes[i] = results[i].hash;

    if (wal_append_write(&state->wal, path, offset, length, num_chunks, expect_gen, new_hashes) < 0) {
        assert(0); // TODO
    }

    // Extract flag values
    #define TOASTY_WRITE_CREATE_IF_MISSING (1 << 0)
    #define TOASTY_WRITE_TRUNCATE_AFTER    (1 << 1)
    bool truncate_after = (flags & TOASTY_WRITE_TRUNCATE_AFTER) != 0;

    uint64_t new_gen;
    int ret = file_tree_write(&state->file_tree, path, offset, length,
        num_chunks, expect_gen, &new_gen, new_hashes, removed_hashes, &num_removed, truncate_after);

    // If write failed because file doesn't exist and CREATE_IF_MISSING flag is set,
    // create the file and retry the write.
    // Note: MISSING_FILE_GENERATION works WITH CREATE_IF_MISSING to implement
    // atomic "create-only-if-not-exists" semantics: creates if missing (NOENT),
    // but fails if file already exists (BADGEN from gen_match).
    if (ret == FILETREE_NOENT && (flags & TOASTY_WRITE_CREATE_IF_MISSING)) {
        // Create the file with default chunk size of 4096 bytes
        uint64_t chunk_size = 4096;

        // Log the creation in the WAL
        if (wal_append_create(&state->wal, path, false, chunk_size) < 0) {
            assert(0); // TODO
        }

        uint64_t create_gen;
        int create_ret = file_tree_create_entity(&state->file_tree, path, false, chunk_size, &create_gen);

        if (create_ret == 0) {
            // File created successfully, retry the write with the new generation
            ret = file_tree_write(&state->file_tree, path, offset, length,
                num_chunks, create_gen, &new_gen, new_hashes, removed_hashes, &num_removed, truncate_after);
        }
    }

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

            for (int j = 0; j < results[i].num_addrs; j++) {

                int k = find_chunk_server_by_addr(state, results[i].addrs[j]);
                if (k == -1) return -1;

                if (hash_set_insert(&state->chunk_servers[k].ms_add_list, new_hashes[i]) < 0)
                    return -1;
            }
        }

        // Mark removed chunks for deletion on all chunk servers that have them
        // These are chunks that were overwritten and are no longer referenced anywhere
        for (int i = 0; i < num_removed; i++) {
            SHA256 removed_hash = removed_hashes[i];

            // Add to rem_list for all chunk servers that have this chunk
            for (int j = 0; j < state->num_chunk_servers; j++) {
                if (chunk_server_peer_contains(&state->chunk_servers[j], removed_hash)) {
                    if (!hash_set_insert(&state->chunk_servers[j].ms_rem_list, removed_hash))
                        return -1;
                }
            }
        }

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_WRITE_SUCCESS);

        message_write(&writer, &new_gen, sizeof(new_gen));

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

        if (chunk_server->num_addrs < MAX_SERVER_ADDRS) {
            Address addr = {0};
            addr.ipv4 = ipv4;
            addr.is_ipv4 = true;
            addr.port = port;
            chunk_server->addrs[chunk_server->num_addrs++] = addr;
        }
    }

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

        if (chunk_server->num_addrs < MAX_SERVER_ADDRS) {
            Address addr = {0};
            addr.ipv6 = ipv6;
            addr.is_ipv4 = false;
            addr.port = port;
            chunk_server->addrs[chunk_server->num_addrs++] = addr;
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

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_AUTH_RESPONSE);

    // TODO: Check whether we already hold the chunk list
    //       of this chunk server. If we do, tell it.

    if (!message_writer_free(&writer)) {
        assert(0); // TODO
    }
    return 0;
}

static int process_chunk_server_sync(MetadataServer *state,
    int conn_idx, ByteView msg)
{
    int chunk_server_idx = tcp_get_tag(&state->tcp, conn_idx);
    assert(chunk_server_idx > -1);
    assert(chunk_server_idx <= MAX_CHUNK_SERVERS);

    ChunkServerPeer *chunk_server = &state->chunk_servers[chunk_server_idx];
    assert(chunk_server->used);

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    uint32_t count;
    if (!binary_read(&reader, &count, sizeof(count)))
        return -1;

    for (uint32_t i = 0; i < count; i++) {

        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash)))
            return -1;

        // If the chunk is not referenced by the file tree, do
        // nothing.

        if (!file_tree_uses_hash(&state->file_tree, hash))
            continue;

        // If the chunk is properly replicated or under-replicated,
        // add it to the ms_add_list.

        int holders[MAX_CHUNK_SERVERS];
        int num_holders = all_chunk_servers_holding_chunk(state, hash, holders, MAX_CHUNK_SERVERS);
        assert(num_holders > -1);
        assert(num_holders <= MAX_CHUNK_SERVERS);

        if (num_holders <= state->replication_factor) {
            if (hash_set_insert(&chunk_server->ms_add_list, hash) < 0) {
                assert(0); // TODO
            }
            continue;
        }

        // If the chunk is over-replicated, either don't add
        // it to the ms_add_list or add it to the ms_rem_list
        // of some other holder.
        //
        // TODO: For now we don't add it to the ms_add_list,
        //       but there may be a better solution.
    }

    if (binary_read(&reader, NULL, 1)) // TODO: this should probably be an assertion
        return -1;

    // Respond with ms_add_list and ms_rem_list

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_SYNC_2);

    uint32_t add_count = chunk_server->ms_add_list.count; // TODO: check implicit casts
    message_write(&writer, &add_count, sizeof(add_count));

    for (uint32_t i = 0; i < add_count; i++) {
        SHA256 hash = chunk_server->ms_add_list.items[i];
        message_write(&writer, &hash, sizeof(hash));
    }

    uint32_t rem_count = chunk_server->ms_rem_list.count; // TODO: check implicit casts
    message_write(&writer, &rem_count, sizeof(rem_count));

    for (uint32_t i = 0; i < rem_count; i++) {
        SHA256 hash = chunk_server->ms_rem_list.items[i];
        message_write(&writer, &hash, sizeof(hash));
    }

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int process_chunk_server_sync_3(MetadataServer *state,
    int conn_idx, ByteView msg)
{
    int chunk_server_idx = tcp_get_tag(&state->tcp, conn_idx);
    assert(chunk_server_idx > -1);
    assert(chunk_server_idx <= MAX_CHUNK_SERVERS);

    ChunkServerPeer *chunk_server = &state->chunk_servers[chunk_server_idx];
    assert(chunk_server->used);

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    uint32_t count;
    if (!binary_read(&reader, &count, sizeof(count)))
        return -1;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_SYNC_4);

    HashSet tmp_list;
    hash_set_init(&tmp_list);

    message_write(&writer, &count, sizeof(count));

    for (uint32_t i = 0; i < count; i++) {

        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash))) {
            hash_set_free(&tmp_list);
            return -1;
        }

        // Only hashes that were actually expected to be
        // in on the server should be recovered.
        assert(hash_set_contains(&chunk_server->ms_add_list, hash)
            || hash_set_contains(&chunk_server->ms_old_list, hash));

        if (hash_set_insert(&tmp_list, hash) < 0) {
            hash_set_free(&tmp_list);
            return -1;
        }

        int holders[MAX_CHUNK_SERVERS];
        int num_holders = all_chunk_servers_holding_chunk(state, hash, holders, MAX_CHUNK_SERVERS);
        assert(num_holders > -1);
        assert(num_holders <= MAX_CHUNK_SERVERS);

        uint32_t tmp = num_holders;
        message_write(&writer, &tmp, sizeof(tmp));

        for (int j = 0; j < num_holders; j++) {
            int k = holders[j];
            message_write_server_addr(&writer, &state->chunk_servers[k]);
        }
    }

    if (binary_read(&reader, NULL, 1)) { // TODO: this should probably be an assertion
        hash_set_free(&tmp_list);
        return -1;
    }

    if (hash_set_merge(&chunk_server->ms_old_list, chunk_server->ms_add_list) < 0) {
        hash_set_free(&tmp_list);
        return -1;
    }

    hash_set_remove_set(&chunk_server->ms_old_list, tmp_list);

    hash_set_free(&chunk_server->ms_add_list);
    chunk_server->ms_add_list = tmp_list;

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int
process_chunk_server_message(MetadataServer *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH:
        return process_chunk_server_auth(state, conn_idx, msg);

        case MESSAGE_TYPE_SYNC:
        return process_chunk_server_sync(state, conn_idx, msg);

        case MESSAGE_TYPE_SYNC_3:
        return process_chunk_server_sync_3(state, conn_idx, msg);
    }
    return -1;
}

static bool is_chunk_server_message_type(uint16_t type)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH:
        case MESSAGE_TYPE_SYNC:
        case MESSAGE_TYPE_SYNC_3:
        return true;

        default:
        break;
    }
    return false;
}

int metadata_server_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    MetadataServer *state = state_;

    string addr      = getargs(argc, argv, "--addr", "127.0.0.1");
    int    port      = getargi(argc, argv, "--port", 8080);
    bool   trace     = getargb(argc, argv, "--trace");
    string wal_file  = getargs(argc, argv, "--wal-file", "metadata.wal");
    int    wal_limit = getargi(argc, argv, "--wal-limit", 1000); // TODO: Choose a good default limit

    if (port <= 0 || port >= 1<<16) {
        fprintf(stderr, "metadata server :: Invalid port\n");
        return -1;
    }

    if (wal_limit < 0) {
        fprintf(stderr, "metadata server :: Invalid WAL limit\n");
        return -1;
    }

    state->trace = trace;
    state->replication_factor = 3; // TODO: what about the REPLICATION_FACTOR macro?
    if (state->replication_factor > MAX_CHUNK_SERVERS)
        return -1;

    state->num_chunk_servers = 0;
    for (int i = 0; i < MAX_CHUNK_SERVERS; i++)
        state->chunk_servers[i].used = false;

    if (tcp_context_init(&state->tcp) < 0) {
        fprintf(stderr, "metadata server :: Couldn't setup TCP context\n");
        return -1;
    }

    int ret = tcp_listen(&state->tcp, addr, port);
    if (ret < 0) {
        fprintf(stderr, "metadata server :: Couldn't setup TCP listener\n");
        tcp_context_free(&state->tcp);
        return -1;
    }

    ret = file_tree_init(&state->file_tree);
    if (ret < 0) {
        fprintf(stderr, "metadata server :: Couldn't setup file tree\n");
        tcp_context_free(&state->tcp);
        return -1;
    }

    if (wal_open(&state->wal, &state->file_tree, wal_file, wal_limit) < 0) {
        fprintf(stderr, "metadata server :: Couldn't setup WAL\n");
        assert(0); // TODO
    }

    printf("Metadata server set up (local=%.*s:%d)\n",
        addr.len,
        addr.ptr,
        port
    );

    *timeout = -1;  // No timeout until we have chunk servers
    if (pcap < TCP_POLL_CAPACITY) {
        fprintf(stderr, "metadata server :: Not enough poll() capacity (got %d, needed %d)\n", pcap, TCP_POLL_CAPACITY);
        return -1;
    }
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int metadata_server_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    MetadataServer *state = state_;

    Event events[TCP_EVENT_CAPACITY];
    int num_events = tcp_translate_events(&state->tcp, events, ctxs, pdata, *pnum);

    Time current_time = get_current_time();
    if (current_time == INVALID_TIME)
        return -1;

    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_WAKEUP:
            MS_TRACE("TCP EVENT: wakeup");
            // Do nothing
            break;

            case EVENT_CONNECT:
            MS_TRACE("TCP EVENT: connect");
            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_UNKNOWN, false);
            break;

            case EVENT_DISCONNECT:
            {
                MS_TRACE("TCP EVENT: disconnect");
                if (events[i].tag >= 0) {
                    MS_TRACE("Chunk server disconnected");
                    chunk_server_peer_free(&state->chunk_servers[events[i].tag]);
                    assert(state->num_chunk_servers > 0);
                    state->num_chunk_servers--;
                }
            }
            break;

            case EVENT_MESSAGE:
            {
                // We don't trace message events from chunk servers
                // as it would become very verbose
                for (;;) {

                    ByteView msg;
                    uint16_t msg_type;
                    int ret = tcp_next_message(&state->tcp, conn_idx, &msg, &msg_type);
                    if (ret == 0) {
                        MS_TRACE("Incomplete message");
                        break;
                    }
                    if (ret < 0) {
                        MS_TRACE("Invalid message");
                        tcp_close(&state->tcp, conn_idx);
                        break;
                    }

                    if (state->trace)
                        message_dump(stdout, msg);

                    if (tcp_get_tag(&state->tcp, conn_idx) == CONNECTION_TAG_UNKNOWN) {
                        if (is_chunk_server_message_type(msg_type)) {

                            if (state->num_chunk_servers == MAX_CHUNK_SERVERS) {
                                tcp_close(&state->tcp, conn_idx);
                                break;
                            }

                            int j = 0;
                            while (state->chunk_servers[j].used) {
                                j++;
                                assert(j < MAX_CHUNK_SERVERS);
                            }

                            chunk_server_peer_init(&state->chunk_servers[j], current_time);
                            state->num_chunk_servers++;

                            tcp_set_tag(&state->tcp, conn_idx, j, true);

                        } else {

                            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_CLIENT, false);
                        }
                    }

                    int tag = tcp_get_tag(&state->tcp, conn_idx);
                    if (tag == CONNECTION_TAG_CLIENT) {
                        MS_TRACE("Message from client");
                        ret = process_client_message(state, conn_idx, msg_type, msg);
                    } else {
                        state->chunk_servers[tag].last_response_time = current_time;
                        ret = process_chunk_server_message(state, conn_idx, msg_type, msg);
                    }
                    if (ret < 0) {
                        MS_TRACE("Message processing failure");
                        tcp_close(&state->tcp, conn_idx);
                        break;
                    }

                    tcp_consume_message(&state->tcp, conn_idx);
                }
            }
            break;
        }
    }

    Time next_wakeup = INVALID_TIME;

    // Trigger chunk server timing events
    for (int i = 0, j = 0; j < state->num_chunk_servers; i++) {

        ChunkServerPeer *chunk_server = &state->chunk_servers[i];
        if (!chunk_server->used)
            continue;
        j++;

        Time response_timeout = chunk_server->last_response_time + (Time) RESPONSE_TIME_LIMIT * 1000000000;
        if (current_time > response_timeout) {
            assert(0); // TODO: drop the chunk server
            continue;
        }
        nearest_deadline(&next_wakeup, response_timeout);
    }

    *timeout = deadline_to_timeout(next_wakeup, current_time);
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = tcp_register_events(&state->tcp, ctxs, pdata);
    return 0;
}

int metadata_server_free(void *state_)
{
    MetadataServer *state = state_;

    wal_close(&state->wal);
    file_tree_free(&state->file_tree);
    tcp_context_free(&state->tcp);
    return 0;
}
