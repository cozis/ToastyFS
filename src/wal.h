#ifndef WAL_INCLUDED
#define WAL_INCLUDED

#include "metadata.h"
#include "file_system.h"
#include "config.h"

typedef struct {
    MetaOper oper;
    uint32_t votes;       // transient, not persisted to disk
    int      view_number;
    uint64_t client_id;
    uint64_t request_id;
} WALEntry;

// On-disk representation of a WAL entry (excludes transient 'votes' field).
typedef struct {
    MetaOper oper;
    int      view_number;
    uint64_t client_id;
    uint64_t request_id;
    uint32_t checksum;    // FNV-1a over all preceding fields
} WALEntryDisk;

_Static_assert(NODE_LIMIT <= 32, "");

typedef struct {
    int       count;
    int       capacity;
    WALEntry *entries;
    Handle    handle;     // file handle to the WAL (0 = memory-only)
} WAL;

// Initialize an empty, memory-only WAL (no file backing).
void wal_init(WAL *wal);

// Initialize a WAL from an on-disk file. Recovers valid entries,
// discards partial/corrupted trailing entries.
int  wal_init_from_file(WAL *wal, string file);

// Initialize a WAL from network data (memory-only, no file).
int  wal_init_from_network(WAL *wal, void *src, int num);

void wal_free(WAL *wal);

// Move ownership from src to dst. If dst is file-backed, the file
// is NOT affected; use wal_replace for atomic file replacement.
void wal_move(WAL *dst, WAL *src);

// Append an entry. If the WAL is file-backed, writes to disk and
// fsyncs before updating the in-memory buffer.
int  wal_append(WAL *wal, WALEntry entry);

// Truncate the WAL to new_count entries.
int  wal_truncate(WAL *wal, int new_count);

// Atomically replace the WAL file contents with the given entries.
// Writes to a temporary file, fsyncs, then renames over the WAL.
// Updates the in-memory buffer and reopens the file handle.
int  wal_replace(WAL *wal, WALEntry *entries, int count);

int       wal_entry_count(WAL *wal);
WALEntry *wal_peek_entry(WAL *wal, int idx);

#endif // WAL_INCLUDED
