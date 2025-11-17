#include "wal.h"
#include "file_tree.h"

#define WAL_MAGIC   0xcafebebe
#define WAL_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t reserved;
} WALHeader

typedef struct {
} WALEntry;

typedef struct {
} WriteSnapshotContext;

static int
serialize_callback(char *src, int num, void *data)
{
    WriteSnapshotContext *wsc = data;
    if (write(src, num) < 0)
        return -1;
    return 0;
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
serialize_callback(char *src, int num, void *data)
{
    ReadSnapshotContext *rsc = data;
    // TODO
}

static int read_snapshot(FileTree *file_tree)
{
    ReadSnapshotContext rsc;
    int num = file_tree_deserialize(file_tree, deserialize_callback, &rsc);
    if (num < 0)
        return 0;
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

int wal_open(WAL *wal, FileTree *file_tree, string file_path)
{
    // TODO:
    //   - Open the log file at path "file_path"
    //   - Lock the file
    //   - Check that the header is correct
    //   - Load the snapshot at the head of the file in the "file_tree" object
    //   - Loop over the following log entries and replay them
    //   - Then, if there are too many log entries, create a new log file and start using it

    assert(0); // TODO
}

void wal_close(WAL *wal)
{
    // TODO:
    //   - Unlock the file
    //   - Close the file handle

    assert(0); // TODO
}

int wal_append(WAL *wal, WALEntry entry)
{
    // TODO:
    //   - If too many entries were created, start a new log file
    //   - Write the entry
    //   - Sync to disk

    assert(0); // TODO
}
