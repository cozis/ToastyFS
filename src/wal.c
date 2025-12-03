#include <stddef.h>
#include <limits.h>
#include <assert.h>
#include <string.h>

#include "wal.h"
#include "file_system.h"
#include "file_tree.h"
#include "system.h"

#define WAL_MAGIC   0xcafebebe
#define WAL_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t reserved;
} WALHeader;

typedef enum {
    WAL_ENTRY_CREATE,
    WAL_ENTRY_DELETE,
    WAL_ENTRY_WRITE,
} WALEntryType;

typedef struct {
    WALEntryType type;

    // create, delete, write
    string path;

    // create, write
    uint64_t chunk_size;

    // delete, write
    uint64_t expect_gen;

    // create
    bool is_dir;

    // write
    uint64_t offset;
    uint64_t length;
    uint32_t num_chunks;
    SHA256 *hashes;

} WALEntry;

static int write_exact(Handle handle, char *src, int len)
{
    int copied = 0;
    while (copied < len) {
        int ret = file_write(handle, src + copied, len - copied);
        if (ret < 0)
            return -1;
        copied += ret;
    }
    return 0;
}

typedef struct {
    Handle handle;
} WriteSnapshotContext;

static int
serialize_callback(char *src, int num, void *data)
{
    WriteSnapshotContext *wsc = data;
    return write_exact(wsc->handle, src, num);
}

static int write_snapshot(FileTree *file_tree, Handle handle)
{
    WriteSnapshotContext wsc;
    wsc.handle = handle;
    if (file_tree_serialize(file_tree, serialize_callback, &wsc) < 0)
        return -1;
    return 0;
}

typedef struct {
    Handle handle;
} ReadSnapshotContext;

static int
deserialize_callback(char *dst, int num, void *data)
{
    ReadSnapshotContext *rsc = data;
    int copied = 0;
    while (copied < num) {
        int ret = file_read(rsc->handle, dst + copied, num - copied);
        if (ret < 0)
            return -1;
        if (ret == 0)
            break;
        copied += ret;
    }
    return copied;
}

static int read_snapshot(FileTree *file_tree, Handle handle)
{
    ReadSnapshotContext rsc;
    rsc.handle = handle;
    int num = file_tree_deserialize(file_tree, deserialize_callback, &rsc);
    if (num < 0)
        return -1;
    return num;
}

static int swap_file(WAL *wal)
{
    // Create a temporary file path
    char temp_path_buf[1<<10];
    if (wal->file_path.len + 5 > (int) sizeof(temp_path_buf))
        return -1;

    memcpy(temp_path_buf, wal->file_path.ptr, wal->file_path.len);
    memcpy(temp_path_buf + wal->file_path.len, ".tmp", 4);
    temp_path_buf[wal->file_path.len + 4] = '\0';

    string temp_path = { temp_path_buf, wal->file_path.len + 4 };

    // Create and open the temporary file
    Handle temp_handle;
    if (file_open(temp_path, &temp_handle) < 0)
        return -1;

    // Write the WAL header
    WALHeader header;
    header.magic = WAL_MAGIC;
    header.version = WAL_VERSION;
    header.reserved = 0;

    if (write_exact(temp_handle, (char*) &header, sizeof(header)) < 0) {
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }

    // Serialize the current file tree to the new file
    if (write_snapshot(wal->file_tree, temp_handle) < 0) {
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }

    // Sync the temporary file to ensure it's written to disk
    if (file_sync(temp_handle) < 0) {
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }

    // Lock the new file before switching
    if (file_lock(temp_handle) < 0) {
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }

    // Unlock and close the old file
    file_unlock(wal->handle);
    file_close(wal->handle);

    // Atomically rename the temporary file to replace the old file
    // On Unix: rename() atomically replaces the destination
    // On Windows: we use MoveFileEx with MOVEFILE_REPLACE_EXISTING for atomicity
#ifdef _WIN32
    // On Windows, use MoveFileEx for atomic replace
    char old_path_zt[1<<10];
    if (wal->file_path.len >= (int) sizeof(old_path_zt)) {
        file_unlock(temp_handle);
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }
    memcpy(old_path_zt, wal->file_path.ptr, wal->file_path.len);
    old_path_zt[wal->file_path.len] = '\0';

    WCHAR old_path_w[MAX_PATH];
    WCHAR temp_path_w[MAX_PATH];

    if (!MultiByteToWideChar(CP_UTF8, 0, old_path_zt, -1, old_path_w, MAX_PATH) ||
        !MultiByteToWideChar(CP_UTF8, 0, temp_path_buf, -1, temp_path_w, MAX_PATH)) {
        file_unlock(temp_handle);
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }

    // MOVEFILE_REPLACE_EXISTING allows atomic overwrite
    if (!sys_MoveFileExW(temp_path_w, old_path_w, MOVEFILE_REPLACE_EXISTING)) {
        file_unlock(temp_handle);
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }
#else
    // On Unix/Linux, rename() atomically replaces the destination
    if (rename_file_or_dir(temp_path, wal->file_path) < 0) {
        file_unlock(temp_handle);
        file_close(temp_handle);
        remove_file_or_dir(temp_path);
        return -1;
    }
#endif

    // Update the WAL to use the new file handle
    wal->handle = temp_handle;
    wal->entry_count = 0;

    return 0;
}

static int read_exact(Handle handle, char *dst, int len)
{
    int copied = 0;
    while (copied < len) {
        int ret = file_read(handle, dst + copied, len - copied);
        if (ret < 0)
            return -1;
        if (ret == 0)
            return 0; // EOF
        copied += ret;
    }
    return copied;
}

static int read_u8(Handle handle, uint8_t *value)
{
    return read_exact(handle, (char*) value, sizeof(*value));
}

static int read_u16(Handle handle, uint16_t *value)
{
    return read_exact(handle, (char*) value, sizeof(*value));
}

static int read_u32(Handle handle, uint32_t *value)
{
    return read_exact(handle, (char*) value, sizeof(*value));
}

static int read_u64(Handle handle, uint64_t *value)
{
    return read_exact(handle, (char*) value, sizeof(*value));
}

static int next_entry(Handle handle, WALEntry *entry)
{
    // Initialize pointers to NULL for cleanup on error
    entry->path.ptr = NULL;
    entry->hashes = NULL;

    uint8_t type;
    int ret = read_u8(handle, &type);
    if (ret == 0)
        return 0; // EOF
    if (ret < 0)
        return -1;

    entry->type = (WALEntryType) type;

    uint16_t path_len;
    if (read_u16(handle, &path_len) <= 0)
        return -1;

    // Dynamically allocate path buffer
    char *path_buffer = sys_malloc(path_len);
    if (!path_buffer)
        return -1;

    if (read_exact(handle, path_buffer, path_len) <= 0) {
        sys_free(path_buffer);
        return -1;
    }

    entry->path.ptr = path_buffer;
    entry->path.len = path_len;

    switch (entry->type) {
    case WAL_ENTRY_CREATE:
        {
            uint8_t is_dir;
            if (read_u8(handle, &is_dir) <= 0)
                goto cleanup_error;
            entry->is_dir = is_dir;

            if (!is_dir) {
                if (read_u64(handle, &entry->chunk_size) <= 0)
                    goto cleanup_error;
            } else {
                entry->chunk_size = 0;
            }
        }
        break;

    case WAL_ENTRY_DELETE:
        {
            if (read_u64(handle, &entry->expect_gen) <= 0)
                goto cleanup_error;
        }
        break;

    case WAL_ENTRY_WRITE:
        {
            if (read_u64(handle, &entry->expect_gen) <= 0)
                goto cleanup_error;
            if (read_u64(handle, &entry->offset) <= 0)
                goto cleanup_error;
            if (read_u64(handle, &entry->length) <= 0)
                goto cleanup_error;
            if (read_u32(handle, &entry->num_chunks) <= 0)
                goto cleanup_error;

            // Dynamically allocate hash buffers
            SHA256 *hashes_buffer = sys_malloc(entry->num_chunks * sizeof(SHA256));
            if (!hashes_buffer) {
                goto cleanup_error;
            }

            if (read_exact(handle, (char*) hashes_buffer, entry->num_chunks * sizeof(SHA256)) <= 0) {
                sys_free(hashes_buffer);
                goto cleanup_error;
            }

            entry->hashes = hashes_buffer;
        }
        break;

    default:
        goto cleanup_error;
    }

    return 1;

cleanup_error:
    if (entry->path.ptr)
        sys_free((char*) entry->path.ptr);
    if (entry->hashes)
        sys_free(entry->hashes);
    return -1;
}

int wal_open(WAL *wal, FileTree *file_tree, string file_path, int entry_limit)
{
    wal->entry_count = 0;
    wal->entry_limit = entry_limit;
    wal->file_tree = file_tree;
    wal->file_path.ptr = NULL;

    // Copy file_path since the passed string may not have the same lifetime as WAL
    char *path_copy = sys_malloc(file_path.len);
    if (!path_copy)
        return -1;
    memcpy(path_copy, file_path.ptr, file_path.len);
    wal->file_path.ptr = path_copy;
    wal->file_path.len = file_path.len;

    Handle handle;
    if (file_open(file_path, &handle) < 0)
        goto error_cleanup_path;

    if (file_lock(handle) < 0) {
        file_close(handle);
        goto error_cleanup_path;
    }

    // Check if the file is empty (newly created) and initialize it
    size_t size;
    if (file_size(handle, &size) < 0) {
        file_close(handle);
        goto error_cleanup_path;
    }

    if (size == 0) {
        // Initialize a new WAL file
        WALHeader header;
        header.magic = WAL_MAGIC;
        header.version = WAL_VERSION;
        header.reserved = 0;

        if (write_exact(handle, (char*) &header, sizeof(header)) < 0) {
            file_close(handle);
            goto error_cleanup_path;
        }

        if (write_snapshot(file_tree, handle) < 0) {
            file_close(handle);
            goto error_cleanup_path;
        }

        if (file_sync(handle) < 0) {
            file_close(handle);
            goto error_cleanup_path;
        }

        // Reset to beginning after initialization
        if (file_set_offset(handle, 0) < 0) {
            file_close(handle);
            goto error_cleanup_path;
        }
    }

    // Read file header
    // NOTE: For now we don't worry about fixing endianess
    WALHeader header;
    for (int copied = 0; copied < (int) sizeof(header); ) {
        int ret = file_read(handle, (char*) &header + copied, (int) sizeof(header) - copied);
        if (ret <= 0) {
            file_close(handle); // TODO: what happens if I close a file without unlocking it?
            goto error_cleanup_path;
        }
        copied += ret;
    }

    // Validate header fields
    if (header.magic != WAL_MAGIC) {
        file_close(handle);
        goto error_cleanup_path;
    }
    if (header.version != WAL_VERSION) {
        file_close(handle);
        goto error_cleanup_path;
    }

    // The read_snapshot function may read more
    // bytes than necessary from the buffer, so
    // we need to save our current position to
    // later restore it to this offset plus what
    // read_snapshot really consumed.
    int saved_offset;
    if (file_get_offset(handle, &saved_offset) < 0) {
        file_close(handle);
        goto error_cleanup_path;
    }

    int num = read_snapshot(file_tree, handle);
    if (num < 0) {
        file_close(handle);
        goto error_cleanup_path;
    }

    // Now restore the offset to the correct position.
    if (num > INT_MAX - saved_offset) {
        file_close(handle);
        goto error_cleanup_path;
    }
    if (file_set_offset(handle, saved_offset + num) < 0) {
        file_close(handle);
        goto error_cleanup_path;
    }

    WALEntry entry;
    for (;;) {

        int ret = next_entry(handle, &entry);
        if (ret == 0)
            break;
        if (ret < 0) {
            file_close(handle);
            goto error_cleanup_path;
        }
        assert(ret == 1);

        switch (entry.type) {
            uint64_t gen;
        case WAL_ENTRY_CREATE:
            file_tree_create_entity(file_tree, entry.path, entry.is_dir, entry.chunk_size, &gen);
            break;
        case WAL_ENTRY_DELETE:
            file_tree_delete_entity(file_tree, entry.path, entry.expect_gen);
            break;
        case WAL_ENTRY_WRITE:
            // WAL replay: use false for truncate_after since truncation was already handled
            file_tree_write(file_tree, entry.path, entry.offset, entry.length, entry.num_chunks, entry.expect_gen, &gen, entry.hashes, NULL, NULL, false);
            break;
        default:
            UNREACHABLE;
        }

        // Free dynamically allocated fields from next_entry
        if (entry.path.ptr)
            sys_free((char*) entry.path.ptr);
        if (entry.hashes)
            sys_free(entry.hashes);

        wal->entry_count++;
    }

    wal->handle = handle;

    if (wal->entry_count >= wal->entry_limit) {
        if (swap_file(wal) < 0) {
            goto error_cleanup_path;
        }
    }
    return 0;

error_cleanup_path:
    sys_free(path_copy);
    return -1;
}

void wal_close(WAL *wal)
{
    file_unlock(wal->handle);
    file_close(wal->handle);
    if (wal->file_path.ptr)
        sys_free((char*) wal->file_path.ptr);
}

static int write_u8(Handle handle, uint8_t value)
{
    return write_exact(handle, (char*) &value, sizeof(value));
}

static int write_u16(Handle handle, uint16_t value)
{
    return write_exact(handle, (char*) &value, sizeof(value));
}

static int write_u32(Handle handle, uint32_t value)
{
    return write_exact(handle, (char*) &value, sizeof(value));
}

static int write_u64(Handle handle, uint64_t value)
{
    return write_exact(handle, (char*) &value, sizeof(value));
}

static int write_str(Handle handle, string value)
{
    return write_exact(handle, value.ptr, value.len);
}

static int append_begin(WAL *wal)
{
    if (wal->entry_count >= wal->entry_limit) {
        if (swap_file(wal) < 0)
            return -1;
    }
    return 0;
}

static int append_end(WAL *wal)
{
    if (file_sync(wal->handle) < 0)
        return -1;
    wal->entry_count++;
    return 0;
}

int wal_append_create(WAL *wal, string path, bool is_dir, uint64_t chunk_size)
{
    if (path.len > UINT16_MAX)
        return -1;

    if (append_begin(wal) < 0)
        return -1;

    write_u8(wal->handle, WAL_ENTRY_CREATE);
    write_u16(wal->handle, path.len);
    write_str(wal->handle, path);
    write_u8(wal->handle, is_dir);
    if (!is_dir)
        write_u64(wal->handle, chunk_size);

    if (append_end(wal) < 0)
        return -1;

    return 0;
}

int wal_append_delete(WAL *wal, string path, uint64_t expect_gen)
{
    if (path.len > UINT16_MAX)
        return -1;

    if (append_begin(wal) < 0)
        return -1;

    // TODO: check for errors
    write_u8(wal->handle, WAL_ENTRY_DELETE);
    write_u16(wal->handle, path.len);
    write_str(wal->handle, path);
    write_u64(wal->handle, expect_gen);

    if (append_end(wal) < 0)
        return -1;

    return 0;
}

int wal_append_write(WAL *wal, string path, uint64_t off,
    uint64_t len, uint32_t num_chunks, uint64_t expect_gen,
    SHA256 *hashes)
{
    if (path.len > UINT16_MAX)
        return -1;

    if (append_begin(wal) < 0)
        return -1;

    if (write_u8(wal->handle, WAL_ENTRY_WRITE) < 0)
        return -1;
    if (write_u16(wal->handle, path.len) < 0)
        return -1;
    if (write_str(wal->handle, path) < 0)
        return -1;
    if (write_u64(wal->handle, expect_gen) < 0)
        return -1;
    if (write_u64(wal->handle, off) < 0)
        return -1;
    if (write_u64(wal->handle, len) < 0)
        return -1;
    if (write_u32(wal->handle, num_chunks) < 0)
        return -1;
    if (write_exact(wal->handle, (char*) hashes, num_chunks * sizeof(SHA256)) < 0)
        return -1;

    if (append_end(wal) < 0)
        return -1;

    return 0;
}
