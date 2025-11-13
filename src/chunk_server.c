#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "basic.h"
#include "byte_queue.h"
#include "config.h"
#include "sha256.h"
#include "message.h"
#include "file_system.h"
#include "tcp.h"
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
        if (list->capacity == 0)
            new_capacity = 8;
        else
            new_capacity = 2 * list->capacity;

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

static void
removal_list_init(RemovalList *list)
{
    list->count = 0;
    list->capacity = 0;
    list->items = NULL;
}

static void
removal_list_free(RemovalList *list)
{
    sys_free(list->items);
}

static int
removal_list_find(RemovalList *list, SHA256 hash)
{
    for (int i = 0; i < list->count; i++)
        if (!memcmp(&list->items[i].hash, &hash, sizeof(SHA256)))
            return i;
    return -1;
}

static int
removal_list_add(RemovalList *list, SHA256 hash, Time marked_time)
{
    // Check if already in list
    int idx = removal_list_find(list, hash);
    if (idx >= 0) {
        // Already marked, keep the original time
        return 0;
    }

    if (list->count == list->capacity) {
        int new_capacity;
        if (list->capacity == 0)
            new_capacity = 8;
        else
            new_capacity = 2 * list->capacity;

        PendingRemoval *new_items = sys_malloc(new_capacity * sizeof(PendingRemoval));
        if (new_items == NULL)
            return -1;

        if (list->capacity > 0) {
            memcpy(new_items, list->items, list->count * sizeof(list->items[0]));
            sys_free(list->items);
        }

        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = (PendingRemoval) { hash, marked_time };
    return 0;
}

static void
removal_list_remove(RemovalList *list, SHA256 hash)
{
    int idx = removal_list_find(list, hash);
    if (idx >= 0) {
        // Remove by shifting remaining items
        if (idx < list->count - 1) {
            memmove(&list->items[idx], &list->items[idx + 1],
                    (list->count - idx - 1) * sizeof(list->items[0]));
        }
        list->count--;
    }
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
    // TODO: check that the hash matches
    return file_read_all(path, data);
}

static int store_chunk(ChunkStore *store, string data, SHA256 *hash)
{
    sha256(data.ptr, data.len, (uint8_t*) hash->data);
    char buf[PATH_MAX];
    string path = hash2path(store, *hash, buf);

    // Note that this write is not atomic. If we crash
    // while writing, we'll get an inconsistent file.
    // This is okay as long as we check that the hash
    // is correct while reading back the data.
    Handle fd;
    if (file_open(path, &fd) < 0)
        return -1;
    int copied = 0;
    while (copied < data.len) {
        int ret = file_write(fd,
            data.ptr + copied,
            data.len - copied);
        if (ret < 0) {
            file_close(fd);
            return -1;
        }
        copied += ret;
    }
    file_close(fd);
    return 0;
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

static int chunk_store_remove(ChunkStore *store, SHA256 hash)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);

    if (remove_file_or_dir(path) < 0)
        return -1;
    return 0;
}

static bool chunk_store_exists(ChunkStore *store, SHA256 hash)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);

    // Try to open the file to check if it exists
    Handle fd;
    if (file_open(path, &fd) == 0) {
        file_close(fd);
        return true;
    }
    return false;
}

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
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    uint32_t add_count;
    if (!binary_read(&reader, &add_count, sizeof(add_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    uint32_t rem_count;
    if (!binary_read(&reader, &rem_count, sizeof(rem_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    SHA256 *add_list = sys_malloc(add_count * sizeof(SHA256));
    if (add_list == NULL)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Out of memory"));

    SHA256 *rem_list = sys_malloc(rem_count * sizeof(SHA256));
    if (rem_list == NULL) {
        sys_free(add_list);
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

    // Check that all items in the add_list are in the chunk directory
    // Any hashes that are missing are added to a missing list
    SHA256 *missing = NULL;
    uint32_t num_missing = 0;

    Time current_time = get_current_time();

    for (uint32_t i = 0; i < add_count; i++) {
        // If chunk is in removal list, unmark it (remove from removal list)
        removal_list_remove(&state->removal_list, add_list[i]);

        // Check if chunk exists in the chunk store
        if (!chunk_store_exists(&state->store, add_list[i])) {

            // Chunk is missing, add to missing list

            if (missing == NULL) {
                missing = sys_malloc(add_count * sizeof(SHA256));
                if (missing == NULL) {
                    assert(0); // TODO
                }
            }
            missing[num_missing++] = add_list[i];
        }
    }

    // Append items from the rem_list to the removal list with timestamps
    for (uint32_t i = 0; i < rem_count; i++) {
        if (removal_list_add(&state->removal_list, rem_list[i], current_time) < 0) {
            sys_free(add_list);
            sys_free(rem_list);
            sys_free(missing);
            return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Out of memory"));
        }
    }

    sys_free(add_list);
    sys_free(rem_list);

    // Respond to the metadata server
    if (num_missing == 0) {

        // No missing chunks, send success

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_STATE_UPDATE_SUCCESS);
        if (!message_writer_free(&writer))
            return -1;

    } else {

        // Some chunks are missing, send error with missing list

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        assert(output);

        MessageWriter writer;
        message_writer_init(&writer, output, MESSAGE_TYPE_STATE_UPDATE_ERROR);

        // Write error message
        string error_msg = S("Missing chunks");
        uint16_t error_len = (uint16_t)error_msg.len;
        message_write(&writer, &error_len, sizeof(error_len));
        message_write(&writer, error_msg.ptr, error_msg.len);

        // Write missing count and missing hashes
        uint32_t tmp = num_missing;
        message_write(&writer, &tmp, sizeof(tmp));
        message_write(&writer, missing, num_missing * sizeof(SHA256));

        sys_free(missing);

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
    //   struct ServerAddresses {
    //     uint32_t num_ipv4;
    //     uint32_t num_ipv6;
    //     IPv4Pair ipv4[num_ipv4];
    //     IPv6Pair ipv6[num_ipv6];
    //   }
    //
    //   struct Message {
    //     uint32_t num_missing;
    //     struct {
    //       uint32_t num_holders;
    //       ServerAddresses holders[num_holders];
    //       SHA256 hash;
    //     } entries[num_missing];
    //   }

    uint32_t num_missing;
    if (!binary_read(&reader, &num_missing, sizeof(num_missing)))
        return -1;

    for (uint32_t i = 0; i < num_missing; i++) {

        uint32_t num_holders;
        if (!binary_read(&reader, &num_holders, sizeof(num_holders)))
            return -1;

        // Temporary storage for all addresses from all holders
        IPv4     ipv4[256];
        IPv6     ipv6[256];
        uint16_t ipv4_port[256];
        uint16_t ipv6_port[256];
        uint32_t total_ipv4 = 0;
        uint32_t total_ipv6 = 0;

        // Read addresses from each holder
        for (uint32_t j = 0; j < num_holders; j++) {

            uint32_t num_ipv4;
            if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4)))
                return -1;

            uint32_t num_ipv6;
            if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6)))
                return -1;

            // Read IPv4 addresses
            for (uint32_t k = 0; k < num_ipv4; k++) {
                if (total_ipv4 >= 256)
                    return -1;
                if (!binary_read(&reader, &ipv4[total_ipv4], sizeof(ipv4[0])))
                    return -1;
                if (!binary_read(&reader, &ipv4_port[total_ipv4], sizeof(ipv4_port[0])))
                    return -1;
                total_ipv4++;
            }

            // Read IPv6 addresses
            for (uint32_t k = 0; k < num_ipv6; k++) {
                if (total_ipv6 >= 256)
                    return -1;
                if (!binary_read(&reader, &ipv6[total_ipv6], sizeof(ipv6[0])))
                    return -1;
                if (!binary_read(&reader, &ipv6_port[total_ipv6], sizeof(ipv6_port[0])))
                    return -1;
                total_ipv6++;
            }
        }

        // Read the hash
        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash)))
            return -1;

        // Add to pending download list
        for (uint32_t k = 0; k < total_ipv4; k++)
            pending_download_list_add(
                &state->pending_download_list,
                (Address) { .is_ipv4=true, .ipv4=ipv4[k], .port=ipv4_port[k] },
                hash
            );

        for (uint32_t k = 0; k < total_ipv6; k++)
            pending_download_list_add(
                &state->pending_download_list,
                (Address) { .is_ipv4=false, .ipv6=ipv6[k], .port=ipv6_port[k] },
                hash
            );
    }

    if (binary_read(&reader, NULL, 1))
        return -1;

    start_download_if_necessary(state);

    // There is no need to respond here
    return 0;
}

static int
process_metadata_server_chunk_list_request(ChunkServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t)))
        return -1;

    // type
    if (!binary_read(&reader, NULL, sizeof(uint16_t)))
        return -1;

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t)))
        return -1;

    if (binary_read(&reader, NULL, 1))
        return 1;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_CHUNK_LIST);

    // Open the folder of chunks and write all hashes
    // to the metadata server. First, write the number
    // of hashes as a u32 integer, then that number
    // of hashes.
    // If the number is not known ahead of time, write
    // a dummy value and then patch it later.

    ByteQueueOffset offset = byte_queue_offset(writer.output);

    uint32_t num_hashes = 0; // Dummy value
    message_write(&writer, &num_hashes, sizeof(num_hashes));

#ifdef _WIN32
    WIN32_FIND_DATA find_data;
    HANDLE handle = sys_FindFirstFileA(path, &find_data);
    if (handle == INVALID_HANDLE_VALUE) {
        if (sys_GetLastError() == ERROR_FILE_NOT_FOUND) {
            // TODO
        }
        return -1;
    }

    do {

        SHA256 hash;

        // TODO

        message_write(&writer, &hash, sizeof(hash));
        num_hashes++;

    } while (sys_FindNextFileA(handle, &find_data));

    if (sys_GetLastError() != ERROR_NO_MORE_FILES)
        return -1;

    sys_FindClose(handle);
#else
    DIR *d = sys_opendir(path);
    if (d == NULL)
        return -1;

    struct dirent *e;
    while ((e = sys_readdir(d))) {

        SHA256 hash;

        // TODO

        message_write(&writer, &hash, sizeof(hash));
        num_hashes++;
    }

    sys_closedir(d);
#endif

    byte_queue_patch(writer.output, offset, &num_hashes, sizeof(num_hashes));

    if (!message_writer_free(&writer))
        return -1;
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

        case MESSAGE_TYPE_CHUNK_LIST_REQUEST:
        return process_metadata_server_chunk_list_request(state, conn_idx, msg);
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

    assert((uint32_t) data.len <= chunk_size);
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
    if (!binary_read(&reader, NULL, data_len))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

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

    message_write(&writer, &new_hash, sizeof(new_hash));

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
        case MESSAGE_TYPE_CREATE_CHUNK:
        return process_client_create_chunk(state, conn_idx, msg);

        case MESSAGE_TYPE_UPLOAD_CHUNK:
        return process_client_upload_chunk(state, conn_idx, msg);

        case MESSAGE_TYPE_DOWNLOAD_CHUNK:
        return process_client_download_chunk(state, conn_idx, msg);

        default:
        break;
    }
    return -1;
}

static int
start_connecting_to_metadata_server(ChunkServer *state)
{
    ByteQueue *output;
    if (tcp_connect(&state->tcp, state->remote_addr, TAG_METADATA_SERVER, &output) < 0)
        return -1;

    // Send AUTH message to authenticate with metadata server
    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_AUTH);

    // Send our listening address(es)
    // For now, we only support IPv4 (as noted in program_init)
    uint32_t num_ipv4 = 1;
    message_write(&writer, &num_ipv4, sizeof(num_ipv4));

    // Write our IPv4 address and port
    message_write(&writer, &state->local_addr.ipv4, sizeof(state->local_addr.ipv4));
    message_write(&writer, &state->local_addr.port, sizeof(state->local_addr.port));

    // No IPv6 addresses for now
    uint32_t num_ipv6 = 0;
    message_write(&writer, &num_ipv6, sizeof(num_ipv6));

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

int chunk_server_init(ChunkServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout)
{
    string addr  = getargs(argc, argv, "--addr", "127.0.0.1");
    int    port  = getargi(argc, argv, "--port", 8081);
    string path  = getargs(argc, argv, "--path", "chunk_server_data/");
    bool   trace = getargb(argc, argv, "--trace");
    string remote_addr = getargs(argc, argv, "--remote-addr", "127.0.0.1");
    int    remote_port = getargi(argc, argv, "--remote-port", 8080);

    if (port <= 0 || port >= 1<<16)
        return -1;

    if (remote_port <= 0 || remote_port >= 1<<16)
        return -1;

    state->trace = trace;

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
    removal_list_init(&state->removal_list);

    char tmp[1<<10];
    if (addr.len >= (int) sizeof(tmp)) {
        tcp_context_free(&state->tcp);
        return -1;
    }
    memcpy(tmp, addr.ptr, addr.len);
    tmp[addr.len] = '\0';
    state->local_addr.is_ipv4 = true;
    if (inet_pton(AF_INET, tmp, &state->local_addr.ipv4) != 1) {
        tcp_context_free(&state->tcp);
        chunk_store_free(&state->store);
        return -1;
    }
    state->local_addr.port = port;

    // Initialize metadata server address
    // // TODO: This should also support IPv6
    if (remote_addr.len >= (int) sizeof(tmp)) {
        tcp_context_free(&state->tcp);
        return -1;
    }
    memcpy(tmp, remote_addr.ptr, remote_addr.len);
    tmp[remote_addr.len] = '\0';
    state->remote_addr.is_ipv4 = true;
    if (inet_pton(AF_INET, tmp, &state->remote_addr.ipv4) != 1) {
        tcp_context_free(&state->tcp);
        chunk_store_free(&state->store);
        return -1;
    }
    state->remote_addr.port = remote_port;
    state->disconnect_time = INVALID_TIME;

    start_connecting_to_metadata_server(state);

    printf("Chunk server set up (local=%.*s:%d, remote=%.*s:%d, path=%.*s)\n",
        addr.len,
        addr.ptr,
        port,
        remote_addr.len,
        remote_addr.ptr,
        remote_port,
        path.len,
        path.ptr
    );

    *timeout = 0;
    return tcp_register_events(&state->tcp, contexts, polled);
}

int chunk_server_free(ChunkServer *state)
{
    pending_download_list_free(&state->pending_download_list);
    removal_list_free(&state->removal_list);
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
                state->disconnect_time = INVALID_TIME;
            break;

            case EVENT_DISCONNECT:
            switch (tcp_get_tag(&state->tcp, conn_idx)) {

                case TAG_METADATA_SERVER:
                state->disconnect_time = current_time;
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

                    if (state->trace)
                        message_dump(stdout, msg);

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

    Time deadline = INVALID_TIME;

    // Remove items from the remove list that got too old
    for (int i = 0; i <  state->removal_list.count; i++) {
        PendingRemoval *removal = &state->removal_list.items[i];
        Time removal_time = removal->marked_time + (Time) DELETION_TIMEOUT * 1000000000;
        if (removal_time < current_time) {
            if (chunk_store_remove(&state->store, removal->hash) == 0)
                *removal = state->removal_list.items[--state->removal_list.count];
        } else {
            nearest_deadline(&deadline, removal_time);
        }
    }

    // TODO: periodically look for chunks that have their hashes messed up and delete them

    // Periodically retry pending downloads
    start_download_if_necessary(state);

    if (state->disconnect_time != INVALID_TIME) {
        Time reconnect_time = state->disconnect_time + (Time) CHUNK_SERVER_RECONNECT_TIME * 1000000000;
        if (reconnect_time <= current_time) {
            state->disconnect_time = INVALID_TIME;
            if (start_connecting_to_metadata_server(state) < 0)
                state->disconnect_time = current_time;
        }
        if (state->disconnect_time != INVALID_TIME)
            nearest_deadline(&deadline, reconnect_time);
    }

    *timeout = deadline_to_timeout(deadline, current_time);
    return tcp_register_events(&state->tcp, contexts, polled);
}
