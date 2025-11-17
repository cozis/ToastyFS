#include <stddef.h>
#include <limits.h>
#include <assert.h>

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

typedef struct {
} WriteSnapshotContext;

static int
serialize_callback(char *src, int num, void *data)
{
    WriteSnapshotContext *wsc = data;
    assert(0); // TODO
}

static int write_snapshot(FileTree *file_tree)
{
    WriteSnapshotContext wsc;
    if (file_tree_serialize(file_tree, serialize_callback, &wsc) < 0)
        return -1;
    return 0;
}

typedef struct {
} ReadSnapshotContext;

static int
deserialize_callback(char *dst, int num, void *data)
{
    ReadSnapshotContext *rsc = data;
    assert(0); // TODO
}

static int read_snapshot(FileTree *file_tree, Handle handle)
{
    ReadSnapshotContext rsc;
    int num = file_tree_deserialize(file_tree, deserialize_callback, &rsc);
    if (num < 0)
        return -1;
    return 0;
}

static int swap_file(WAL *wal)
{
    // TODO:
    //   - Create a new temporary file
    //   - Write the WAL file header
    //   - Serialize the current file tree
    //   - Rename the temporary file to a name such that it's the next log file that will be used
    //   - Delete the old log file
    //   NOTE:
    //     - The lock will need to be acquired at some point

    assert(0); // TODO
}

static int next_entry(Handle handle, WALEntry *entry)
{
    assert(0); // TODO
}

int wal_open(WAL *wal, FileTree *file_tree, string file_path, int entry_limit)
{
    wal->entry_count = 0;
    wal->entry_limit = entry_limit;

    Handle handle;
    if (file_open(file_path, &handle) < 0)
        return -1;

    if (file_lock(handle) < 0) {
        file_close(handle);
        return -1;
    }

    // TODO: If the file didn't exist already, initialize it

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

    // Not restore the offset to the correct position.
    if (num > INT_MAX - saved_offset) {
        file_close(handle);
        return -1;
    }
    if (file_set_offset(wal->handle, saved_offset + num) < 0) {
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

static int write_u8(Handle handle, uint8_t value)
{
    return write_exact(handle, (char*) &value, sizeof(value));
}

static int write_u16(Handle handle, uint16_t value)
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

    assert(0); // TODO

    if (append_end(wal) < 0)
        return -1;

    return 0;
}
