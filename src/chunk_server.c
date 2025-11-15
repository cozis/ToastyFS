#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "basic.h"
#include "byte_queue.h"
#include "config.h"
#include "hash_set.h"
#include "sha256.h"
#include "message.h"
#include "file_system.h"
#include "tcp.h"
#include "chunk_server.h"

static void download_targets_init(DownloadTargets *targets)
{
    targets->count = 0;
    targets->capacity = 0;
    targets->items = NULL;
}

static void download_targets_free(DownloadTargets *targets)
{
    sys_free(targets->items);
}

static void download_targets_remove(DownloadTargets *targets,
    SHA256 hash)
{
    // NOTE: This changes the download order!
    for (int i = 0; i < targets->count; i++)
        if (!memcmp(&targets->items[i].hash, &hash, sizeof(SHA256)))
            targets->items[i--] = targets->items[--targets->count];
}

static int download_targets_push(DownloadTargets *targets,
    Address addr, SHA256 hash)
{
    // Avoid duplicates! This is important as the metadata server may
    // tell us to download our missing chunks again while we are still
    // going through the previous list of downloads. This check becomes
    // relevant as the update period approaches the time the chunk server
    // needs to go through a list of downloads.
    for (int i = 0; i < targets->count; i++)
        if (addr_eql(targets->items[i].addr, addr) && !memcmp(&targets->items[i].hash, &hash, sizeof(SHA256)))
            return 0;

    if (targets->count == targets->capacity) {

        int new_capacity;
        if (targets->capacity == 0)
            new_capacity = 8;
        else
            new_capacity = 2 * targets->capacity;

        DownloadTarget *new_items = sys_malloc(new_capacity * sizeof(DownloadTarget));
        if (new_items == NULL)
            return -1;

        if (targets->capacity > 0) {
            memcpy(new_items, targets->items, targets->count * sizeof(targets->items[0]));
            sys_free(targets->items);
        }

        targets->items = new_items;
        targets->capacity = new_capacity;
    }

    targets->items[targets->count++] = (DownloadTarget) { addr, hash };
    return 0;
}

static bool download_targets_pop(DownloadTargets *targets,
    DownloadTarget *target)
{
    // Read the head
    if (targets->count == 0)
        return false;
    *target = targets->items[0];

    // Pop the head
    for (int i = 0; i < targets->count-1; i++)
        targets->items[i] = targets->items[i+1];
    targets->count--;

    // We expect the download list to be empty most
    // of the time, so if this was the last element
    // there may not be a new one for a while and we
    // can clear the array.
    if (targets->count == 0) {
        free(targets->items);
        targets->items = NULL;
        targets->capacity = 0;
    }

    return true;
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
    if (file_open(path, &fd) < 0) // TODO: open in overwrite mode
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
    // TODO: this isn't right. There should be something like file_exists
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

static void start_download(ChunkServer *state)
{
    if (state->downloading)
        return; // Already started

    DownloadTarget target;
    if (!download_targets_pop(&state->download_targets, &target))
        return; // No more downloads

    ByteQueue *output;
    if (tcp_connect(&state->tcp, target.addr, TAG_CHUNK_SERVER, &output) < 0)
        return; // Couldn't start connect operation

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK);

    message_write(&writer, &target.hash, sizeof(target.hash));

    uint32_t offset = 0;
    message_write(&writer, &offset, sizeof(offset));

    uint32_t length = 64 * 1024 * 1024; // TODO: there should be a special value for this
    message_write(&writer, &length, sizeof(length));

    if (!message_writer_free(&writer))
        return; // ???

    state->current_download_target_hash = target.hash;
    state->downloading = true;
}

static int process_metadata_server_sync_2(ChunkServer *state,
    int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    uint32_t add_count;
    if (!binary_read(&reader, &add_count, sizeof(add_count)))
        return -1;

    Time current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        assert(0); // TODO
    }

    HashSet tmp_list;
    hash_set_init(&tmp_list);

    for (uint32_t i = 0; i < add_count; i++) {

        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash)))
            return -1;

        // Elements in ms_add_list that are not held by the
        // chunk server are added to a temporary list tmp_list

        if (!chunk_store_exists(&state->store, hash)) {
            if (hash_set_insert(&tmp_list, hash) < 0) {
                assert(0); // TODO
            }
            continue;
        }

        timed_hash_set_remove(&state->cs_rem_list, hash);
        hash_set_remove(&state->cs_add_list, hash);
    }

    for (int i = 0; i < state->cs_add_list.count; i++) {
        if (timed_hash_set_insert(&state->cs_rem_list, state->cs_add_list.items[i], current_time) < 0) {
            assert(0); // TODO
        }
    }

    hash_set_clear(&state->cs_add_list);

    uint32_t rem_count;
    if (!binary_read(&reader, &rem_count, sizeof(rem_count)))
        return -1;

    for (uint32_t i = 0; i < rem_count; i++) {

        SHA256 hash;
        if (!binary_read(&reader, &hash, sizeof(hash)))
            return -1;

        if (timed_hash_set_insert(&state->cs_rem_list, hash, current_time) < 0) {
            assert(0); // TODO
        }
    }

    if (binary_read(&reader, NULL, 1))
        return -1;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_SYNC_3);

    uint32_t count = tmp_list.count + state->cs_lst_list.count; // TODO: overflow
    message_write(&writer, &count, sizeof(count));

    for (int i = 0; i < tmp_list.count; i++) {
        SHA256 hash = tmp_list.items[i];
        message_write(&writer, &hash, sizeof(hash));
    }

    for (int i = 0; i < state->cs_lst_list.count; i++) {
        SHA256 hash = state->cs_lst_list.items[i];
        message_write(&writer, &hash, sizeof(hash));
    }

    if (!message_writer_free(&writer))
        return -1;

    return 0;
}

static int
process_metadata_server_sync_4(ChunkServer *state, int conn_idx, ByteView msg)
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
            download_targets_push(
                &state->download_targets,
                (Address) { .is_ipv4=true, .ipv4=ipv4[k], .port=ipv4_port[k] },
                hash
            );

        for (uint32_t k = 0; k < total_ipv6; k++)
            download_targets_push(
                &state->download_targets,
                (Address) { .is_ipv4=false, .ipv6=ipv6[k], .port=ipv6_port[k] },
                hash
            );
    }

    if (binary_read(&reader, NULL, 1))
        return -1;

    start_download(state);

    // There is no need to respond here
    return 0;
}

static int
process_metadata_server_auth_response(ChunkServer *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    // TODO: Read whether the metadata server already
    //       holds our list of chunks. If it doesn't,
    //       add all held chunks to the add list.
    bool avoid_full_scan = false;

    if (binary_read(&reader, NULL, 1))
        return -1;

    if (avoid_full_scan)
        return 0;

    string path = { state->store.path, strlen(state->store.path) };

    DirectoryScanner scanner;
    if (directory_scanner_init(&scanner, path) < 0) {
        assert(0); // TODO
    }

    for (;;) {

        string name;
        int ret = directory_scanner_next(&scanner, &name);
        if (ret < 0) {
            assert(0); // TODO
        }
        if (ret == 1)
            break;
        assert(ret == 0);

        SHA256 hash;

        // Hash length as a string is 64 bytes
        if (name.len != 64)
            continue;

        bool invalid = false;
        for (int i = 0; i < 64; i += 2) {

            uint8_t h = name.ptr[i+0];
            uint8_t l = name.ptr[i+1];

            if (0) {}
            else if (h >= '0' && h <= '9') h = h - '0';
            else if (h >= 'a' && h <= 'f') h = h - 'a' + 10;
            else if (h >= 'A' && h <= 'F') h = h - 'A' + 10;
            else { invalid = true; break; }

            if (0) {}
            else if (l >= '0' && l <= '9') l = l - '0';
            else if (l >= 'a' && l <= 'f') l = l - 'a' + 10;
            else if (l >= 'A' && l <= 'F') l = l - 'A' + 10;
            else { invalid = true; break; }

            hash.data[i >> 1] = (h << 4) | l;
        }
        if (invalid) continue;

        if (hash_set_insert(&state->cs_add_list, hash) < 0) {
            assert(0); // TODO
        }
    }

    directory_scanner_free(&scanner);
    return 0;
}

static int
process_metadata_server_message(ChunkServer *state, int conn_idx, uint16_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH_RESPONSE: return process_metadata_server_auth_response(state, conn_idx, msg);
        case MESSAGE_TYPE_SYNC_2: return process_metadata_server_sync_2(state, conn_idx, msg);
        case MESSAGE_TYPE_SYNC_4: return process_metadata_server_sync_4(state, conn_idx, msg);
    }
    return -1;
}

static int
process_chunk_server_download_error(ChunkServer *state, int conn_idx, ByteView msg)
{
    (void) msg;
    (void) conn_idx;

    state->downloading = false;

    start_download(state);
    return 0;
}

static int
process_chunk_server_download_success(ChunkServer *state, int conn_idx, ByteView msg)
{
    (void) conn_idx;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    uint32_t data_len;
    if (!binary_read(&reader, &data_len, sizeof(data_len)))
        return -1;

    if (data_len > (uint32_t) (reader.len - reader.cur))
        return -1;
    string data = { (char*) reader.src + reader.cur, data_len };

    if (!binary_read(&reader, NULL, data_len))
        return -1;

    if (binary_read(&reader, NULL, 1))
        return -1;

    // Store the downloaded chunk
    if (chunk_store_add(&state->store, data) < 0) {
        assert(0); // TODO
    }

    // The download succeded!

    // Mark that we are not downloading anymore
    state->downloading = false;

    // Since we managed to acquire this chunk, we can
    // remove any other downloads to it.
    download_targets_remove(&state->download_targets, state->current_download_target_hash);

    // Add the newly acquired chunk to the add list
    if (hash_set_insert(&state->cs_add_list, state->current_download_target_hash) < 0) {
        assert(0); // TODO
    }

    start_download(state);
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

    if (hash_set_insert(&state->cs_add_list, new_hash) < 0) {
        assert(0); // TODO
    }

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

    if (hash_set_insert(&state->cs_add_list, new_hash) < 0) {
        assert(0); // TODO
    }

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

static int send_sync_message(ChunkServer *state)
{
    assert(state->disconnect_time == INVALID_TIME);

    int conn_idx = tcp_index_from_tag(&state->tcp, TAG_METADATA_SERVER);
    assert(conn_idx > -1);

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    assert(output);

    MessageWriter writer;
    message_writer_init(&writer, output, MESSAGE_TYPE_SYNC);

    // TODO: May be worth it to add a limit to how many
    //       items from the add list are sent every update
    //       to keep messages under 4GB.
    uint32_t count = state->cs_add_list.count; // TODO: check implicit conversions
    message_write(&writer, &count, sizeof(count));

    for (uint32_t i = 0; i < count; i++) {
        SHA256 hash = state->cs_add_list.items[i];
        message_write(&writer, &hash, sizeof(hash));
    }

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

int chunk_server_init(ChunkServer *state, int argc, char **argv, void **contexts, struct pollfd *polled, int *timeout)
{
    string addr        = getargs(argc, argv, "--addr", "127.0.0.1");
    int    port        = getargi(argc, argv, "--port", 8081);
    string path        = getargs(argc, argv, "--path", "chunk_server_data/");
    bool   trace       = getargb(argc, argv, "--trace");
    string remote_addr = getargs(argc, argv, "--remote-addr", "127.0.0.1");
    int    remote_port = getargi(argc, argv, "--remote-port", 8080);

    if (port <= 0 || port >= 1<<16)
        return -1;

    if (remote_port <= 0 || remote_port >= 1<<16)
        return -1;

    Time current_time = get_current_time();

    state->trace = trace;

    state->reconnect_delay = 1; // 1 second

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
    download_targets_init(&state->download_targets);
    hash_set_init(&state->cs_add_list);
    hash_set_init(&state->cs_lst_list);
    timed_hash_set_init(&state->cs_rem_list);

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
    state->last_sync_time = current_time;

    start_connecting_to_metadata_server(state);

    // TODO: add all chunk hashes to the add list

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
    download_targets_free(&state->download_targets);
    timed_hash_set_free(&state->cs_rem_list);
    hash_set_free(&state->cs_lst_list);
    hash_set_free(&state->cs_add_list);
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
            if (tcp_get_tag(&state->tcp, conn_idx) == TAG_METADATA_SERVER) {
                assert(state->disconnect_time == INVALID_TIME);
            }
            break;

            case EVENT_DISCONNECT:
            switch (events[i].tag) {

                case TAG_METADATA_SERVER:
                assert(state->disconnect_time == INVALID_TIME);
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

    {
        int conn_idx = tcp_index_from_tag(&state->tcp, TAG_METADATA_SERVER);
        assert((conn_idx < 0) == (state->disconnect_time != INVALID_TIME));
    }

    Time deadline = INVALID_TIME;

    // Remove items from the remove list that got too old
    for (int i = 0; i < state->cs_rem_list.count; i++) {
        TimedHash *removal = &state->cs_rem_list.items[i];
        Time removal_time = removal->time + (Time) DELETION_TIMEOUT * 1000000000;
        if (removal_time < current_time) {
            if (chunk_store_remove(&state->store, removal->hash) == 0)
                *removal = state->cs_rem_list.items[--state->cs_rem_list.count];
        } else {
            nearest_deadline(&deadline, removal_time);
        }
    }

    if (state->disconnect_time == INVALID_TIME) {
        Time next_sync_time = state->last_sync_time + (Time) SYNC_INTERVAL * 1000000000;
        if (current_time >= next_sync_time) {
            if (send_sync_message(state) < 0) {
                assert(0); // TODO
            }
            state->last_sync_time = current_time;
        } else {
            nearest_deadline(&deadline, next_sync_time);
        }
    }

    // TODO: periodically look for chunks that have their hashes messed up and delete them

    // Periodically retry pending downloads
    start_download(state);

    if (state->disconnect_time != INVALID_TIME) {
        Time reconnect_time = state->disconnect_time + (Time) state->reconnect_delay * 1000000000;
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
