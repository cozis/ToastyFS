#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "wal.h"

// FNV-1a checksum over all WALEntryDisk fields except the checksum itself.
static uint32_t wal_entry_checksum(WALEntryDisk *entry)
{
    uint32_t h = 2166136261u;
    const unsigned char *p = (const unsigned char *)entry;
    size_t len = offsetof(WALEntryDisk, checksum);
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static WALEntryDisk wal_entry_to_disk(WALEntry *entry)
{
    WALEntryDisk disk = {
        .oper        = entry->oper,
        .view_number = entry->view_number,
        .client_id   = entry->client_id,
        .request_id  = entry->request_id,
    };
    disk.checksum = wal_entry_checksum(&disk);
    return disk;
}

static WALEntry wal_entry_from_disk(WALEntryDisk *disk)
{
    return (WALEntry) {
        .oper        = disk->oper,
        .votes       = 0,
        .view_number = disk->view_number,
        .client_id   = disk->client_id,
        .request_id  = disk->request_id,
    };
}

static bool wal_is_file_backed(WAL *wal)
{
    return wal->handle.data != 0;
}

static int wal_grow(WAL *wal)
{
    int n = 2 * wal->capacity;
    if (n < 8) n = 8;
    WALEntry *p = realloc(wal->entries, n * sizeof(WALEntry));
    if (p == NULL)
        return -1;
    wal->entries = p;
    wal->capacity = n;
    return 0;
}

void wal_init(WAL *wal)
{
    wal->count = 0;
    wal->capacity = 0;
    wal->entries = NULL;
    wal->handle = (Handle) { 0 };
}

int wal_init_from_file(WAL *wal, string file)
{
    Handle handle;
    if (file_open(file, &handle) < 0)
        return -1;

    size_t size;
    if (file_size(handle, &size) < 0) {
        file_close(handle);
        return -1;
    }

    // Discard any partial trailing entry (crash during write).
    int raw_count = size / sizeof(WALEntryDisk);
    size_t valid_size = raw_count * sizeof(WALEntryDisk);
    if (valid_size < size)
        file_truncate(handle, valid_size);

    WALEntryDisk *disk_entries = malloc(raw_count * sizeof(WALEntryDisk));
    if (disk_entries == NULL && raw_count > 0) {
        file_close(handle);
        return -1;
    }

    if (file_set_offset(handle, 0) < 0) {
        file_close(handle);
        free(disk_entries);
        return -1;
    }

    if (raw_count > 0 && file_read_exact(handle, (char *)disk_entries, raw_count * sizeof(WALEntryDisk)) < 0) {
        file_close(handle);
        free(disk_entries);
        return -1;
    }

    // Verify checksums: truncate at the first corrupted entry.
    int count = raw_count;
    for (int i = 0; i < raw_count; i++) {
        if (disk_entries[i].checksum != wal_entry_checksum(&disk_entries[i])) {
            count = i;
            file_truncate(handle, count * sizeof(WALEntryDisk));
            break;
        }
    }

    // Convert disk entries to in-memory entries.
    WALEntry *entries = malloc(count * sizeof(WALEntry));
    if (entries == NULL && count > 0) {
        file_close(handle);
        free(disk_entries);
        return -1;
    }
    for (int i = 0; i < count; i++)
        entries[i] = wal_entry_from_disk(&disk_entries[i]);
    free(disk_entries);

    // Position file offset at end for future appends.
    if (file_set_offset(handle, count * sizeof(WALEntryDisk)) < 0) {
        file_close(handle);
        free(entries);
        return -1;
    }

    wal->count = count;
    wal->capacity = count;
    wal->entries = entries;
    wal->handle = handle;
    return 0;
}

int wal_init_from_network(WAL *wal, void *src, int num)
{
    wal->count = num;
    wal->capacity = num;
    wal->entries = malloc(num * sizeof(WALEntry));
    if (wal->entries == NULL)
        return -1;
    memcpy(wal->entries, src, num * sizeof(WALEntry));
    wal->handle = (Handle) { 0 };
    return 0;
}

void wal_free(WAL *wal)
{
    free(wal->entries);
    if (wal_is_file_backed(wal))
        file_close(wal->handle);
}

void wal_move(WAL *dst, WAL *src)
{
    free(dst->entries);
    dst->count = src->count;
    dst->capacity = src->capacity;
    dst->entries = src->entries;
    // Do NOT touch dst->handle — caller manages file backing.
    wal_init(src);
}

int wal_append(WAL *wal, WALEntry entry)
{
    if (wal->count == wal->capacity) {
        if (wal_grow(wal) < 0)
            return -1;
    }

    if (wal_is_file_backed(wal)) {
        WALEntryDisk disk = wal_entry_to_disk(&entry);

        if (file_write_exact(wal->handle, (char *)&disk, sizeof(disk)) < 0) {
            // Partial write may have advanced file offset. Truncate and
            // rewind so the file stays consistent with in-memory count.
            file_truncate(wal->handle, wal->count * sizeof(WALEntryDisk));
            file_set_offset(wal->handle, wal->count * sizeof(WALEntryDisk));
            return -1;
        }

        if (file_sync(wal->handle) < 0) {
            file_truncate(wal->handle, wal->count * sizeof(WALEntryDisk));
            file_set_offset(wal->handle, wal->count * sizeof(WALEntryDisk));
            return -1;
        }
    }

    wal->entries[wal->count++] = entry;
    return 0;
}

int wal_truncate(WAL *wal, int new_count)
{
    assert(new_count <= wal->count);
    if (wal->count == new_count)
        return 0;

    if (wal_is_file_backed(wal)) {
        if (file_truncate(wal->handle, new_count * sizeof(WALEntryDisk)) < 0)
            return -1;
        if (file_set_offset(wal->handle, new_count * sizeof(WALEntryDisk)) < 0)
            return -1;
    }

    wal->count = new_count;
    return 0;
}

int wal_replace(WAL *wal, WALEntry *entries, int count)
{
    assert(wal_is_file_backed(wal));

    string tmp_path = S("tmp.log");
    string wal_path = S("vsr.log");

    // Open tmp.log (file_open creates if not exists, opens if exists).
    Handle tmp;
    if (file_open(tmp_path, &tmp) < 0)
        return -1;

    // Truncate in case tmp.log already exists from a previous crash.
    if (file_truncate(tmp, 0) < 0) {
        file_close(tmp);
        return -1;
    }
    if (file_set_offset(tmp, 0) < 0) {
        file_close(tmp);
        return -1;
    }

    // Write all entries to tmp.log.
    for (int i = 0; i < count; i++) {
        WALEntryDisk disk = wal_entry_to_disk(&entries[i]);
        if (file_write_exact(tmp, (char *)&disk, sizeof(disk)) < 0) {
            file_close(tmp);
            return -1;
        }
    }

    // Fsync tmp.log to ensure all data is on disk.
    if (file_sync(tmp) < 0) {
        file_close(tmp);
        return -1;
    }
    file_close(tmp);

    // Close the current WAL handle before rename.
    file_close(wal->handle);
    wal->handle = (Handle) { 0 };

    // Atomically replace the WAL file.
    if (rename_file_or_dir(tmp_path, wal_path) < 0)
        return -1;

    // Reopen the WAL file and seek to end for future appends.
    Handle new_handle;
    if (file_open(wal_path, &new_handle) < 0)
        return -1;
    if (file_set_offset(new_handle, count * sizeof(WALEntryDisk)) < 0) {
        file_close(new_handle);
        return -1;
    }
    wal->handle = new_handle;

    // Update in-memory state.
    free(wal->entries);
    wal->entries = NULL;
    wal->count = 0;
    wal->capacity = 0;

    if (count > 0) {
        wal->entries = malloc(count * sizeof(WALEntry));
        if (wal->entries == NULL)
            return -1;
        memcpy(wal->entries, entries, count * sizeof(WALEntry));
    }
    wal->count = count;
    wal->capacity = count;

    return 0;
}

int wal_entry_count(WAL *wal)
{
    return wal->count;
}

WALEntry *wal_peek_entry(WAL *wal, int idx)
{
    assert(idx >= 0);
    assert(idx < wal->count);
    return &wal->entries[idx];
}
