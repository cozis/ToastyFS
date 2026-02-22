#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "wal.h"

// FNV-1a checksum over all WALEntry fields except the checksum itself.
static uint32_t wal_entry_checksum(WALEntry *entry)
{
    uint32_t h = 2166136261u;
    const unsigned char *p = (const unsigned char *)entry;
    size_t len = offsetof(WALEntry, checksum);
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static void wal_entry_set_checksum(WALEntry *entry)
{
    entry->checksum = wal_entry_checksum(entry);
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

int wal_init_from_file(WAL *wal, string file, bool *was_truncated)
{
    if (was_truncated)
        *was_truncated = false;

    Handle handle;
    if (file_open(file, &handle) < 0)
        return -1;

    size_t size;
    if (file_size(handle, &size) < 0) {
        file_close(handle);
        return -1;
    }

    // Discard any partial trailing entry (crash during write).
    int raw_count = size / sizeof(WALEntry);
    size_t valid_size = raw_count * sizeof(WALEntry);
    if (valid_size < size)
        file_truncate(handle, valid_size);

    WALEntry *entries = malloc(raw_count * sizeof(WALEntry));
    if (entries == NULL && raw_count > 0) {
        file_close(handle);
        return -1;
    }

    if (file_set_offset(handle, 0) < 0) {
        file_close(handle);
        free(entries);
        return -1;
    }

    if (raw_count > 0 && file_read_exact(handle, (char *)entries, raw_count * sizeof(WALEntry)) < 0) {
        file_close(handle);
        free(entries);
        return -1;
    }

    // Verify checksums: truncate at the first corrupted entry.
    int count = raw_count;
    for (int i = 0; i < raw_count; i++) {
        if (entries[i].checksum != wal_entry_checksum(&entries[i])) {
            count = i;
            file_truncate(handle, count * sizeof(WALEntry));
            if (was_truncated)
                *was_truncated = true;
            break;
        }
    }

    // Position file offset at end for future appends.
    if (file_set_offset(handle, count * sizeof(WALEntry)) < 0) {
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
    wal->entries = NULL;
    if (num > 0) {
        wal->entries = malloc(num * sizeof(WALEntry));
        if (wal->entries == NULL)
            return -1;
        memcpy(wal->entries, src, num * sizeof(WALEntry));
    }
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
        wal_entry_set_checksum(&entry);

        if (file_write_exact(wal->handle, (char *)&entry, sizeof(entry)) < 0) {
            // Partial write may have advanced file offset. Truncate and
            // rewind so the file stays consistent with in-memory count.
            file_truncate(wal->handle, wal->count * sizeof(WALEntry));
            file_set_offset(wal->handle, wal->count * sizeof(WALEntry));
            return -1;
        }

        if (file_sync(wal->handle) < 0) {
            file_truncate(wal->handle, wal->count * sizeof(WALEntry));
            file_set_offset(wal->handle, wal->count * sizeof(WALEntry));
            return -1;
        }
    }

    wal->entries[wal->count++] = entry;
    return 0;
}

int wal_update_entry(WAL *wal, int idx)
{
    assert(idx >= 0 && idx < wal->count);

    if (wal_is_file_backed(wal)) {
        WALEntry entry = wal->entries[idx];
        wal_entry_set_checksum(&entry);

        size_t offset = idx * sizeof(WALEntry);
        size_t end_offset = wal->count * sizeof(WALEntry);

        if (file_set_offset(wal->handle, offset) < 0)
            return -1;
        if (file_write_exact(wal->handle, (char *)&entry, sizeof(entry)) < 0)
            return -1;
        if (file_sync(wal->handle) < 0)
            return -1;

        // Restore file offset to end for future appends.
        if (file_set_offset(wal->handle, end_offset) < 0)
            return -1;
    }
    return 0;
}

int wal_truncate(WAL *wal, int new_count)
{
    assert(new_count <= wal->count);
    if (wal->count == new_count)
        return 0;

    if (wal_is_file_backed(wal)) {
        if (file_truncate(wal->handle, new_count * sizeof(WALEntry)) < 0)
            return -1;
        if (file_set_offset(wal->handle, new_count * sizeof(WALEntry)) < 0)
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
        wal_entry_set_checksum(&entries[i]);
        if (file_write_exact(tmp, (char *)&entries[i], sizeof(entries[i])) < 0) {
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

    // TODO: fsync on parent directory

    // Reopen the WAL file and seek to end for future appends.
    Handle new_handle;
    if (file_open(wal_path, &new_handle) < 0)
        return -1;
    if (file_set_offset(new_handle, count * sizeof(WALEntry)) < 0) {
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

///////////////////////////////////////////////////////////////////////////////
// ViewAndCommit — persistent view_number, last_normal_view and commit_index
///////////////////////////////////////////////////////////////////////////////

// On-disk layout (24 bytes):
//   [view_number: 8] [last_normal_view: 8] [commit_index: 4] [checksum: 4]
typedef struct {
    uint64_t view_number;
    uint64_t last_normal_view;
    int      commit_index;
    uint32_t checksum;
} ViewAndCommitDisk;

static uint32_t vc_checksum(uint64_t view_number,
    uint64_t last_normal_view, int commit_index)
{
    uint32_t h = 2166136261u;

    const unsigned char *p = (const unsigned char *)&view_number;
    for (int i = 0; i < (int)sizeof(view_number); i++) {
        h ^= p[i];
        h *= 16777619u;
    }

    p = (const unsigned char *)&last_normal_view;
    for (int i = 0; i < (int)sizeof(last_normal_view); i++) {
        h ^= p[i];
        h *= 16777619u;
    }

    p = (const unsigned char *)&commit_index;
    for (int i = 0; i < (int)sizeof(commit_index); i++) {
        h ^= p[i];
        h *= 16777619u;
    }

    return h;
}

int view_and_commit_init(ViewAndCommit *vc, string file)
{
    Handle handle;
    if (file_open(file, &handle) < 0)
        return -1;

    vc->handle = handle;
    vc->view_number = 0;
    vc->last_normal_view = 0;
    vc->commit_index = 0;

    size_t size;
    if (file_size(handle, &size) < 0) {
        file_close(handle);
        return -1;
    }

    if (size >= sizeof(ViewAndCommitDisk)) {

        if (file_set_offset(handle, 0) < 0) {
            file_close(handle);
            return -1;
        }

        ViewAndCommitDisk disk;
        if (file_read_exact(handle, (char *)&disk, sizeof(disk)) < 0) {
            file_close(handle);
            return -1;
        }

        uint32_t expected_checksum = vc_checksum(disk.view_number,
            disk.last_normal_view, disk.commit_index);

        if (disk.checksum == expected_checksum) {
            vc->view_number = disk.view_number;
            vc->last_normal_view = disk.last_normal_view;
            vc->commit_index = disk.commit_index;
        }

        // If checksum doesn't match, start from defaults (0, 0, 0)
    }

    return 0;
}

void view_and_commit_free(ViewAndCommit *vc)
{
    if (vc->handle.data != 0)
        file_close(vc->handle);
}

int set_view_and_commit(ViewAndCommit *vc, uint64_t view_number,
    uint64_t last_normal_view, int commit_index)
{
    ViewAndCommitDisk disk = {
        .view_number = view_number,
        .last_normal_view = last_normal_view,
        .commit_index = commit_index,
    };
    disk.checksum = vc_checksum(view_number, last_normal_view, commit_index);

    if (file_set_offset(vc->handle, 0) < 0)
        return -1;
    if (file_write_exact(vc->handle, (char *)&disk, sizeof(disk)) < 0)
        return -1;
    if (file_sync(vc->handle) < 0)
        return -1;

    vc->view_number = view_number;
    vc->last_normal_view = last_normal_view;
    vc->commit_index = commit_index;
    return 0;
}
