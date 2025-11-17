#include <stddef.h>
#include <limits.h>
#include <assert.h>
#include <string.h>

#include "wal.h"
#include "file_system.h"
#include "file_tree.h"

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

    // create
    bool is_dir;

    // write
    uint64_t offset;
    uint64_t length;
    uint32_t num_chunks;
    SHA256 *prev_hashes;
    SHA256 *next_hashes;

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
        if (ret <= 0)
            return -1;
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

    // Rename the temporary file to replace the old file
    if (rename_file_or_dir(temp_path, wal->file_path) < 0) {
        file_unlock(temp_handle);
        file_close(temp_handle);
        return -1;
    }

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
    static char path_buffer[1<<10];
    static SHA256 prev_hashes_buffer[1<<10];
    static SHA256 next_hashes_buffer[1<<10];

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

    if (path_len > sizeof(path_buffer))
        return -1;

    if (read_exact(handle, path_buffer, path_len) <= 0)
        return -1;

    entry->path.ptr = path_buffer;
    entry->path.len = path_len;

    switch (entry->type) {
    case WAL_ENTRY_CREATE:
        {
            uint8_t is_dir;
            if (read_u8(handle, &is_dir) <= 0)
                return -1;
            entry->is_dir = is_dir;

            if (!is_dir) {
                if (read_u64(handle, &entry->chunk_size) <= 0)
                    return -1;
            } else {
                entry->chunk_size = 0;
            }
        }
        break;

    case WAL_ENTRY_DELETE:
        // No additional fields
        break;

    case WAL_ENTRY_WRITE:
        {
            if (read_u64(handle, &entry->offset) <= 0)
                return -1;
            if (read_u64(handle, &entry->length) <= 0)
                return -1;
            if (read_u32(handle, &entry->num_chunks) <= 0)
                return -1;
            if (read_u32(handle, (uint32_t*) &entry->chunk_size) <= 0)
                return -1;

            if (entry->num_chunks > sizeof(prev_hashes_buffer) / sizeof(SHA256))
                return -1;

            if (read_exact(handle, (char*) prev_hashes_buffer, entry->num_chunks * sizeof(SHA256)) <= 0)
                return -1;
            if (read_exact(handle, (char*) next_hashes_buffer, entry->num_chunks * sizeof(SHA256)) <= 0)
                return -1;

            entry->prev_hashes = prev_hashes_buffer;
            entry->next_hashes = next_hashes_buffer;
        }
        break;

    default:
        return -1;
    }

    return 1;
}

int wal_open(WAL *wal, FileTree *file_tree, string file_path, int entry_limit)
{
    wal->entry_count = 0;
    wal->entry_limit = entry_limit;
    wal->file_tree = file_tree;
    wal->file_path = file_path;

    Handle handle;
    if (file_open(file_path, &handle) < 0)
        return -1;

    if (file_lock(handle) < 0) {
        file_close(handle);
        return -1;
    }

    // Check if the file is empty (newly created) and initialize it
    size_t size;
    if (file_size(handle, &size) < 0) {
        file_close(handle);
        return -1;
    }

    if (size == 0) {
        // Initialize a new WAL file
        WALHeader header;
        header.magic = WAL_MAGIC;
        header.version = WAL_VERSION;
        header.reserved = 0;

        if (write_exact(handle, (char*) &header, sizeof(header)) < 0) {
            file_close(handle);
            return -1;
        }

        if (write_snapshot(file_tree, handle) < 0) {
            file_close(handle);
            return -1;
        }

        if (file_sync(handle) < 0) {
            file_close(handle);
            return -1;
        }

        // Reset to beginning after initialization
        if (file_set_offset(handle, 0) < 0) {
            file_close(handle);
            return -1;
        }
    }

    // Read file header
    // NOTE: For now we don't worry about fixing endianess
    WALHeader header;
    for (int copied = 0; copied < (int) sizeof(header); ) {
        int ret = file_read(handle, (char*) &header + copied, (int) sizeof(header) - copied);
        if (ret <= 0) {
            file_close(handle); // TODO: what happens if I close a file without unlocking it?
            return -1;
        }
        copied += ret;
    }

    // Validate header fields
    if (header.magic != WAL_MAGIC) {
        file_close(handle);
        return -1;
    }
    if (header.version != WAL_VERSION) {
        file_close(handle);
        return -1;
    }

    // The read_snapshot function may read more
    // bytes than necessary from the buffer, so
    // we need to save our current position to
    // later restore it to this offset plus what
    // read_snapshot really consumed.
    int saved_offset;
    if (file_get_offset(handle, &saved_offset) < 0) {
        file_close(handle);
        return -1;
    }

    int num = read_snapshot(file_tree, handle);
    if (num < 0) {
        file_close(handle);
        return -1;
    }

    // Now restore the offset to the correct position.
    if (num > INT_MAX - saved_offset) {
        file_close(handle);
        return -1;
    }
    if (file_set_offset(handle, saved_offset + num) < 0) {
        file_close(handle);
        return -1;
    }

    WALEntry entry;
    for (;;) {

        int ret = next_entry(handle, &entry);
        if (ret == 0)
            break;
        if (ret < 0) {
            file_close(handle);
            return -1;
        }
        assert(ret == 1);

        switch (entry.type) {
        case WAL_ENTRY_CREATE:
            file_tree_create_entity(file_tree, entry.path, entry.is_dir, entry.chunk_size);
            break;
        case WAL_ENTRY_DELETE:
            file_tree_delete_entity(file_tree, entry.path);
            break;
        case WAL_ENTRY_WRITE:
            file_tree_write(file_tree, entry.path, entry.offset, entry.length, entry.num_chunks, entry.chunk_size, entry.prev_hashes, entry.next_hashes, NULL, NULL);
            break;
        default:
            UNREACHABLE;
        }

        wal->entry_count++;
    }

    wal->handle = handle;

    if (wal->entry_count >= wal->entry_limit) {
        if (swap_file(wal) < 0)
            return -1;
    }
    return 0;
}

void wal_close(WAL *wal)
{
    file_unlock(wal->handle);
    file_close(wal->handle);
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

int wal_append_delete(WAL *wal, string path)
{
    if (path.len > UINT16_MAX)
        return -1;

    if (append_begin(wal) < 0)
        return -1;

    write_u8(wal->handle, WAL_ENTRY_DELETE);
    write_u16(wal->handle, path.len);
    write_str(wal->handle, path);

    if (append_end(wal) < 0)
        return -1;

    return 0;
}

int wal_append_write(WAL *wal, string path, uint64_t off,
    uint64_t len, uint32_t num_chunks, uint32_t chunk_size,
    SHA256 *prev_hashes, SHA256 *hashes)
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
    if (write_u64(wal->handle, off) < 0)
        return -1;
    if (write_u64(wal->handle, len) < 0)
        return -1;
    if (write_u32(wal->handle, num_chunks) < 0)
        return -1;
    if (write_u32(wal->handle, chunk_size) < 0)
        return -1;
    if (write_exact(wal->handle, (char*) prev_hashes, num_chunks * sizeof(SHA256)) < 0)
        return -1;
    if (write_exact(wal->handle, (char*) hashes, num_chunks * sizeof(SHA256)) < 0)
        return -1;

    if (append_end(wal) < 0)
        return -1;

    return 0;
}
