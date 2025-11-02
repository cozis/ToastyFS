#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sha256.h"
#include "message.h"
#include "file_system.h"
#include "chunk_server.h"

static void
pending_download_list_init(PendingDownloadList *list)
{
    list->count = 0;
    list->capacity = 0;
    list->items = NULL;
}

static void
pending_download_list_free(PendingDownloadList *list)
{
    sys_free(list->items);
}

static int
pending_download_list_add(PendingDownloadList *list, Address addr, SHA256 hash)
{
    // Avoid duplicates
    for (int i = 0; i < list->count; i++)
        if (addr_eql(list->items[i].addr, addr) && !memcmp(&list->items[i].hash, &hash, sizeof(SHA256)))
            return 0;

    if (list->count == list->capacity) {

        int new_capacity;
        if (list->capacity == 0) new_capacity = 8;
        else                     new_capacity = 2 * list->capacity;

        PendingDownload *new_items = sys_malloc(new_capacity * sizeof(PendingDownload));
        if (new_items == NULL)
            return -1;

        if (list->capacity > 0) {
            memcpy(new_items, list->items, list->count * sizeof(list->items[0]));
            sys_free(list->items);
        }

        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = (PendingDownload) { addr, hash };
    return 0;
}

static int chunk_store_init(ChunkStore *store, string path)
{
    if (create_dir(path) && errno != EEXIST)
        return -1;

    if (get_full_path(path, store->path) < 0)
        return -1;

    return 0;
}

static void chunk_store_free(ChunkStore *store)
{
    (void) store;
}

static void append_hex_as_str(char *out, SHA256 hash)
{
    char table[] = "0123456789abcdef";
    for (int i = 0; i < (int) sizeof(hash); i++) {
        out[(i << 1) + 0] = table[hash.data[i] >> 4];
        out[(i << 1) + 1] = table[hash.data[i] & 0xF];
    }
}

static string hash2path(ChunkStore *store, SHA256 hash, char *out)
{
    strcpy(out, store->path);
    strcat(out, "/");

    size_t tmp = strlen(out);

    append_hex_as_str(out + tmp, hash);

    out[tmp + 64] = '\0';

    return (string) { out, strlen(out) };
}

static int load_chunk(ChunkStore *store, SHA256 hash, string *data)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);
    return file_read_all(path, data);
}

static int store_chunk(ChunkStore *store, string data, SHA256 *hash)
{
    sha256(data.ptr, data.len, (uint8_t*) hash->data);
    char buf[PATH_MAX];
    string path = hash2path(store, *hash, buf);
    return file_write_atomic(path, data);
}

static int chunk_store_get(ChunkStore *store, SHA256 hash, string *data)
{
    return load_chunk(store, hash, data);
}

static int chunk_store_add(ChunkStore *store, string data)
{
    SHA256 dummy;
    return store_chunk(store, data, &dummy);
}

#if 0
static void chunk_store_remove(ChunkStore *store, SHA256 hash)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);

    remove_file_or_dir(path);
}
#endif

static int chunk_store_patch(ChunkStore *store, SHA256 target_chunk,
	uint64_t patch_off, string patch, SHA256 *new_hash)
{
    string data;
    int ret = load_chunk(store, target_chunk, &data);
    if (ret < 0)
        return -1;

    if (patch_off > SIZE_MAX - patch.len) {
        sys_free(data.ptr);
        return -1;
    }

    if (patch_off + (size_t) patch.len > (size_t) data.len) {
        sys_free(data.ptr);
        return -1;
    }

    memcpy(data.ptr + patch_off, patch.ptr, patch.len);

    ret = store_chunk(store, data, new_hash);
    if (ret < 0) {
        sys_free(data.ptr);
        return -1;
    }

    sys_free(data.ptr);
    return 0;
}

static int send_error(TCP *tcp, int conn_idx,
    bool close, uint16_t type, string msg)
{
    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(tcp, conn_idx);
    message_writer_init(&writer, output, type);

    uint16_t len = MIN(msg.len, UINT16_MAX);
    message_write(&writer, &len, sizeof(len));
    message_write(&writer, msg.ptr, len);
    if (!message_writer_free(&writer))
        return -1;
    if (close)
        return -1;
    return 0;
}

static void start_download_if_necessary(ChunkServer *state)
{
    if (state->pending_download_list.count == 0 || state->downloading)
        return;

    ByteQueue *output;
    if (tcp_connect(&state->tcp, state->pending_download_list.items[0].addr, TAG_CHUNK_SERVER, &output) < 0) {
        // Failed to connect, remove this download from the list and try next time
        if (state->pending_download_list.count > 1) {
            memmove(&state->pending_download_list.items[0],
                    &state->pending_download_list.items[1],
                    (state->pending_download_list.count - 1) * sizeof(PendingDownload));
        }
        state->pending_download_list.count--;
        return;
    }

    state->downloading = true;

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK);

    // Write the hash of the chunk to download
    message_write(&writer, &state->pending_download_list.items[0].hash,
                  sizeof(state->pending_download_list.items[0].hash));

    // Request the entire chunk: offset = 0
    uint32_t offset = 0;
    message_write(&writer, &offset, sizeof(offset));

    // Request maximum reasonable chunk size (64MB)
    uint32_t length = 64 * 1024 * 1024;
    message_write(&writer, &length, sizeof(length));

    if (!message_writer_free(&writer)) {
        // Failed to send message, close connection and retry
        state->downloading = false;
        return;
    }
}

static int
process_metadata_server_state_update(ChunkServer *state, int conn_idx, ByteView msg)
{
    uint32_t add_count;
    uint32_t rem_count;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    if (!binary_read(&reader, &add_count, sizeof(add_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    if (!binary_read(&reader, &rem_count, sizeof(rem_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    SHA256 *add_list = sys_malloc(add_count * sizeof(SHA256));
    SHA256 *rem_list = sys_malloc(rem_count * sizeof(SHA256));
    if (add_list == NULL || rem_list == NULL) {
        sys_free(add_list);
        sys_free(rem_list);
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Out of memory"));
    }

    for (uint32_t i = 0; i < add_count; i++) {
        if (!binary_read(&reader, &add_list[i], sizeof(SHA256))) {
            sys_free(add_list);
            sys_free(rem_list);
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
        }
    }

    for (uint32_t i = 0; i < rem_count; i++) {
        if (!binary_read(&reader, &rem_list[i], sizeof(SHA256))) {
            sys_free(add_list);
            sys_free(rem_list);
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
        }
    }

    if (binary_read(&reader, NULL, 1)) {
        sys_free(add_list);
        sys_free(rem_list);
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
    }

    // Process the state update:
    // 1. Move chunks in rem_list from main to orphaned directory (mark for deletion)
    // 2. Move chunks in add_list from orphaned to main directory (unmark for deletion)
    // 3. Check that all chunks in add_list exist

    SHA256 *missing_chunks = NULL;
    uint32_t missing_count = 0;

    // Process add_list: ensure chunks exist and move from orphaned if needed
    for (uint32_t i = 0; i < add_count; i++) {
        char main_path[PATH_MAX];
        char orphaned_path[PATH_MAX];

        // Get paths for main and orphaned locations
        hash2path(&state->store, add_list[i], main_path);
        snprintf(orphaned_path, sizeof(orphaned_path), "%s/orphaned/", state->store.path);

        // Build orphaned path properly
        strcpy(orphaned_path, state->store.path);
        strcat(orphaned_path, "/orphaned/");
        size_t tmp = strlen(orphaned_path);
        append_hex_as_str(orphaned_path + tmp, add_list[i]);
        orphaned_path[tmp + 64] = '\0';

        // Check if chunk exists in main directory
        Handle fd;
        if (file_open((string) { main_path, strlen(main_path) }, &fd) == 0) {
            file_close(fd);
            // Chunk is in main directory, nothing to do
        } else if (file_open((string) { orphaned_path, strlen(orphaned_path) }, &fd) == 0) {
            file_close(fd);
            // Chunk is in orphaned directory, move it back to main
            if (rename_file_or_dir((string) { orphaned_path, strlen(orphaned_path) },
                                   (string) { main_path, strlen(main_path) }) < 0) {
                // Failed to move, treat as missing
                if (missing_chunks == NULL)
                    missing_chunks = sys_malloc(add_count * sizeof(SHA256));
                if (missing_chunks)
                    missing_chunks[missing_count++] = add_list[i];
            }
        } else {
            // Chunk is missing in both locations
            if (missing_chunks == NULL)
                missing_chunks = sys_malloc(add_count * sizeof(SHA256));
            if (missing_chunks)
                missing_chunks[missing_count++] = add_list[i];
        }
    }

    // Process rem_list: move chunks from main to orphaned directory
    // First ensure orphaned directory exists
    char orphaned_dir_path[PATH_MAX];
    snprintf(orphaned_dir_path, sizeof(orphaned_dir_path), "%s/orphaned", state->store.path);
    create_dir((string) { orphaned_dir_path, strlen(orphaned_dir_path) });

    for (uint32_t i = 0; i < rem_count; i++) {
        char main_path[PATH_MAX];
        char orphaned_path[PATH_MAX];

        hash2path(&state->store, rem_list[i], main_path);

        strcpy(orphaned_path, state->store.path);
        strcat(orphaned_path, "/orphaned/");
        size_t tmp = strlen(orphaned_path);
        append_hex_as_str(orphaned_path + tmp, rem_list[i]);
        orphaned_path[tmp + 64] = '\0';

        // Move from main to orphaned (ignore errors, chunk might not exist)
        rename_file_or_dir((string) { main_path, strlen(main_path) },
                          (string) { orphaned_path, strlen(orphaned_path) });
    }

    sys_free(add_list);
    sys_free(rem_list);

    // Send response
    if (missing_count > 0) {
        // Send error with list of missing chunks
        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_STATE_UPDATE_ERROR);

        uint16_t error_len = 15; // "Missing chunks"
        message_write(&writer, &error_len, sizeof(error_len));
        message_write(&writer, "Missing chunks", error_len);

        message_write(&writer, &missing_count, sizeof(missing_count));
        for (uint32_t i = 0; i < missing_count; i++)
            message_write(&writer, &missing_chunks[i], sizeof(SHA256));

        sys_free(missing_chunks);

        if (!message_writer_free(&writer))
            return -1;
    } else {
        // Send success
        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_STATE_UPDATE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_metadata_server_download_locations(ChunkServer *state, int conn_idx, ByteView msg)
{
    (void) conn_idx;

    // The metadata server wants us to download chunks from other chunk servers

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    // The message layout is this:
    //
    //   struct IPv4Pair {
    //     IPv4     addr;
    //     uint16_t port;
    //   }
    //
    //   struct IPv6Pair {
    //     IPv6     addr;
    //     uint16_t port;
    //   }
    //
    //   struct AddressList {
    //     uint8_t  num_ipv4;
    //     uint8_t  num_ipv6;
    //     IPv4Pair ipv4[num_ipv4];
    //     IPv6Pair ipv6[num_ipv6];
    //   }
    //
    //   struct Group {
    //     AddressList address_list;
    //     uint32_t num_hashes;
    //     SHA256 hashes[num_hashes];
    //   }
    //
    //   struct Message {
    //     uint16_t num_groups;
    //     Group    groups[num_groups]
    //   }

    uint16_t num_groups;
    if (binary_read(&reader, &num_groups, sizeof(num_groups)))
        return -1;

    for (uint16_t i = 0; i < num_groups; i++) {

        uint8_t num_ipv4;
        if (binary_read(&reader, &num_ipv4, sizeof(num_ipv4)))
            return -1;

        uint8_t num_ipv6;
        if (binary_read(&reader, &num_ipv6, sizeof(num_ipv6)))
            return -1;

        IPv4     ipv4[UINT8_MAX];
        IPv6     ipv6[UINT8_MAX];
        uint8_t  ipv4_port[UINT8_MAX];
        uint16_t ipv6_port[UINT8_MAX];

        for (uint8_t j = 0; j < num_ipv4; j++) {
            if (binary_read(&reader, &ipv4[i], sizeof(ipv4[i])))
                return -1;
            if (binary_read(&reader, &ipv4_port[i], sizeof(ipv4_port[i])))
                return -1;
        }

        for (uint8_t j = 0; j < num_ipv6; j++) {
            if (binary_read(&reader, &ipv6[i], sizeof(ipv6[i])))
                return -1;
            if (binary_read(&reader, &ipv6_port[i], sizeof(ipv6_port[i])))
                return -1;
        }

        uint32_t num_hashes;
        if (binary_read(&reader, &num_hashes, sizeof(num_hashes)))
            return -1;

        for (uint32_t j = 0; j < num_hashes; j++) {

            SHA256 hash;
            if (binary_read(&reader, &hash, sizeof(hash)))
                return -1;

            for (uint8_t k = 0; k < num_ipv4; k++)
                pending_download_list_add(
                    &state->pending_download_list,
                    (Address) { .is_ipv4=true, .ipv4=ipv4[k], .port=ipv4_port[i] },
                    hash
                );

            for (uint8_t k = 0; k < num_ipv6; k++)
                pending_download_list_add(
                    &state->pending_download_list,
                    (Address) { .is_ipv4=false, .ipv6=ipv6[k], .port=ipv6_port[i] },
                    hash
                );
        }
    }

    if (binary_read(&reader, NULL, 1))
        return -1;

    start_download_if_necessary(state);

    // There is no need to respond here
    return 0;
}

static int
process_metadata_server_message(ChunkServer *state, int conn_idx, uint16_t type, ByteView msg)
{
    switch (type) {

        case MESSAGE_TYPE_STATE_UPDATE:
        return process_metadata_server_state_update(state, conn_idx, msg);

        case MESSAGE_TYPE_DOWNLOAD_LOCATIONS:
        return process_metadata_server_download_locations(state, conn_idx, msg);
    }

    return -1;
}

static int
process_chunk_server_download_error(ChunkServer *state, int conn_idx, ByteView msg)
{
    (void) msg;
    (void) conn_idx;

    // Download failed, mark as not downloading and remove the failed item
    state->downloading = false;

    if (state->pending_download_list.count > 0) {
        // Remove the first item (the one that failed)
        if (state->pending_download_list.count > 1) {
            memmove(&state->pending_download_list.items[0],
                    &state->pending_download_list.items[1],
                    (state->pending_download_list.count - 1) * sizeof(PendingDownload));
        }
        state->pending_download_list.count--;
    }

    // Try next download if any pending
    start_download_if_necessary(state);

    return 0;
}

static int
process_chunk_server_download_success(ChunkServer *state, int conn_idx, ByteView msg)
{
    (void) conn_idx;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    // Read data length
    uint32_t data_len;
    if (!binary_read(&reader, &data_len, sizeof(data_len)))
        return -1;

    // Read the chunk data
    if (data_len > (uint32_t) (reader.len - reader.cur))
        return -1;

    string data = { (char*) reader.src + reader.cur, data_len };

    // Store the downloaded chunk
    if (chunk_store_add(&state->store, data) < 0) {
        // Failed to store, treat as error
        state->downloading = false;
        if (state->pending_download_list.count > 0) {
            if (state->pending_download_list.count > 1) {
                memmove(&state->pending_download_list.items[0],
                        &state->pending_download_list.items[1],
                        (state->pending_download_list.count - 1) * sizeof(PendingDownload));
            }
            state->pending_download_list.count--;
        }
        start_download_if_necessary(state);
        return 0;
    }

    // Download succeeded, mark as not downloading and remove the completed item
    state->downloading = false;

    if (state->pending_download_list.count > 0) {
        // Remove the first item (the one that succeeded)
        if (state->pending_download_list.count > 1) {
            memmove(&state->pending_download_list.items[0],
                    &state->pending_download_list.items[1],
                    (state->pending_download_list.count - 1) * sizeof(PendingDownload));
        }
        state->pending_download_list.count--;
    }

    // Try next download if any pending
    start_download_if_necessary(state);

    return 0;
}

static int
process_chunk_server_message(ChunkServer *state, int conn_idx, uint16_t msg_type, ByteView msg)
{
    switch (msg_type) {

        case MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR:
        return process_chunk_server_download_error(state, conn_idx, msg);

        case MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS:
        return process_chunk_server_download_success(state, conn_idx, msg);
    }

    return -1;
}

static int
process_client_create_chunk(ChunkServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t chunk_size;
    if (!binary_read(&reader, &chunk_size, sizeof(chunk_size)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_len;
    if (!binary_read(&reader, &target_len, sizeof(target_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    string data = { (char*) reader.src + reader.cur, target_len };
    if (!binary_read(&reader, NULL, target_len))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    char *mem = sys_malloc(chunk_size);
    if (mem == NULL)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Out of memory"));

    assert(target_off + data.len <= chunk_size);

    memset(mem, 0, chunk_size);
    memcpy(mem + target_off, data.ptr, data.len);

    SHA256 new_hash;
    sha256(mem, chunk_size, (uint8_t*) new_hash.data);

    int ret = chunk_store_add(&state->store, (string) { mem, chunk_size });

    sys_free(mem);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("I/O error"));

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_CHUNK_SUCCESS);

    message_write(&writer, &new_hash, sizeof(new_hash));

    if (!message_writer_free(&writer))
        return -1;

    return 0;
}

static int
process_client_upload_chunk(ChunkServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 target_hash;
    if (!binary_read(&reader, &target_hash, sizeof(target_hash)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t data_len;
    if (!binary_read(&reader, &data_len, sizeof(data_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    string data = { (char*) reader.src + reader.cur, data_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 new_hash;
    int ret = chunk_store_patch(&state->store, target_hash, target_off, data, &new_hash);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("I/O error"));

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS);

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int
process_client_download_chunk(ChunkServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 target_hash;
    if (!binary_read(&reader, &target_hash, sizeof(target_hash)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_len;
    if (!binary_read(&reader, &target_len, sizeof(target_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    string data;
    int ret = chunk_store_get(&state->store, target_hash, &data);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("I/O error"));

    if (target_off >= (size_t) data.len || target_len > (size_t) data.len - target_off) {
        sys_free(data.ptr);
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid range"));
    }
    string slice = { data.ptr + target_off, target_len };

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS);

    message_write(&writer, &target_len, sizeof(target_len));

    message_write(&writer, slice.ptr, slice.len);

    sys_free(data.ptr);

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int
process_client_message(ChunkServer *state, int conn_idx, uint16_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_CREATE_CHUNK: return process_client_create_chunk(state, conn_idx, msg);
        case MESSAGE_TYPE_UPLOAD_CHUNK: return process_client_upload_chunk(state, conn_idx, msg);
        case MESSAGE_TYPE_DOWNLOAD_CHUNK: return process_client_download_chunk(state, conn_idx, msg);
        default:break;
    }
    return -1;
}

int chunk_server_init(ChunkServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout)
{
    (void) argc;
    (void) argv;

    char addr[] = "127.0.0.1";
    uint16_t port = 8080;
    string path = S("chunk_server_data_0/");

    char     metadata_server_addr[] = "127.0.0.1";
    uint16_t metadata_server_port = 8081;

    tcp_context_init(&state->tcp);

    int ret = tcp_listen(&state->tcp, addr, port);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    ret = chunk_store_init(&state->store, path);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    state->downloading = false;
    pending_download_list_init(&state->pending_download_list);

    // Initialize metadata server address
    // // TODO: This should also support IPv6
    state->metadata_server_addr.is_ipv4 = true;
    if (inet_pton(AF_INET, metadata_server_addr, &state->metadata_server_addr.ipv4) != 1) {
        tcp_context_free(&state->tcp);
        chunk_store_free(&state->store);
        return -1;
    }
    state->metadata_server_addr.port = metadata_server_port;

    state->metadata_server_disconnect_time = 0;

    *timeout = -1;  // No timeout needed for chunk server initially
    return tcp_register_events(&state->tcp, contexts, polled);
}

int chunk_server_free(ChunkServer *state)
{
    pending_download_list_free(&state->pending_download_list);
    chunk_store_free(&state->store);
    tcp_context_free(&state->tcp);
    return 0;
}

int chunk_server_step(ChunkServer *state, void **contexts, struct pollfd *polled, int num_polled, int *timeout)
{
    Event events[MAX_CONNS+1];
    int num_events = tcp_translate_events(&state->tcp, events, contexts, polled, num_polled);

    Time current_time = get_current_time();
    if (current_time == INVALID_TIME)
        return -1;

    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_CONNECT:
            if (tcp_get_tag(&state->tcp, conn_idx) == TAG_METADATA_SERVER)
                state->metadata_server_disconnect_time = 0;
            break;

            case EVENT_DISCONNECT:
            switch (tcp_get_tag(&state->tcp, conn_idx)) {
                case TAG_METADATA_SERVER:
                state->metadata_server_disconnect_time = current_time;
                break;

                case TAG_CHUNK_SERVER:
                // Connection to chunk server disconnected during download
                if (state->downloading) {
                    // Mark as not downloading and retry
                    state->downloading = false;
                    // The current download item will be retried on next call
                    // to start_download_if_necessary
                }
                break;
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

                    switch (tcp_get_tag(&state->tcp, conn_idx)) {
                        case TAG_METADATA_SERVER:
                        ret = process_metadata_server_message(state, conn_idx, msg_type, msg);
                        break;

                        case TAG_CHUNK_SERVER:
                        ret = process_chunk_server_message(state, conn_idx, msg_type, msg);
                        break;

                        default:
                        ret = process_client_message(state, conn_idx, msg_type, msg);
                        break;
                    }

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

    // TODO: periodically look for chunks that have their hashes messed up and delete them

    // TODO: periodically start downloads if some are pending and weren't started yet
    // start_download_if_necessary(state);

    if (state->metadata_server_disconnect_time > 0 && current_time - state->metadata_server_disconnect_time > CHUNK_SERVER_RECONNECT_TIME) {
        ByteQueue *output;
        if (tcp_connect(&state->tcp, state->metadata_server_addr, TAG_METADATA_SERVER, &output) < 0)
            state->metadata_server_disconnect_time = current_time;
        else {
            state->metadata_server_disconnect_time = 0;

            // Send AUTH message to authenticate with metadata server
            MessageWriter writer;
            message_writer_init(&writer, output, MESSAGE_TYPE_AUTH);

            // Send our listening address(es)
            // For now, we only support IPv4 (as noted in program_init)
            uint32_t num_ipv4 = 1;
            message_write(&writer, &num_ipv4, sizeof(num_ipv4));

            // Write our IPv4 address and port
            IPv4 our_ipv4;
            if (inet_pton(AF_INET, "127.0.0.1", &our_ipv4) == 1) {
                message_write(&writer, &our_ipv4, sizeof(our_ipv4));
                uint16_t our_port = 8080; // From program_init
                message_write(&writer, &our_port, sizeof(our_port));
            } else {
                // Failed to parse our address, send 0 IPv4s
                num_ipv4 = 0;
                // We already wrote 1, this is an error case
                // For now, continue with the bad data
            }

            // No IPv6 addresses for now
            uint32_t num_ipv6 = 0;
            message_write(&writer, &num_ipv6, sizeof(num_ipv6));

            if (!message_writer_free(&writer)) {
                // Failed to send AUTH, will retry on next reconnect
                state->metadata_server_disconnect_time = current_time;
            }
        }
    }

    *timeout = -1;  // No timeout needed for chunk server
    return tcp_register_events(&state->tcp, contexts, polled);
}
