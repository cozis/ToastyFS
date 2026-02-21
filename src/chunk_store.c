#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdio.h>

#include "chunk_store.h"
#include "file_system.h"

// Build the full path for a chunk: "base_path/HEX_HASH"
// SHA256 hex = 64 chars. Returns string pointing into buf.
static string chunk_path(ChunkStore *cs, SHA256 hash, char *buf, int buf_size)
{
    int base_len = strlen(cs->base_path);
    if (base_len + 1 + 64 + 1 > buf_size)
        return (string){ buf, 0 };

    memcpy(buf, cs->base_path, base_len);
    buf[base_len] = '/';
    append_hex_as_str(buf + base_len + 1, hash);
    buf[base_len + 1 + 64] = '\0';

    return (string){ buf, base_len + 1 + 64 };
}

int chunk_store_init(ChunkStore *cs, const char *base_path)
{
    int len = strlen(base_path);
    if (len >= (int) sizeof(cs->base_path))
        return -1;

    memcpy(cs->base_path, base_path, len + 1);

    string path = { cs->base_path, len };
    create_dir(path); // Ignore error if already exists

    return 0;
}

void chunk_store_free(ChunkStore *cs)
{
    (void) cs;
}

int chunk_store_write(ChunkStore *cs, SHA256 hash, char *data, uint32_t size)
{
    char buf[512];
    string path = chunk_path(cs, hash, buf, sizeof(buf));
    if (path.len == 0)
        return -1;

    Handle fd;
    if (file_open(path, &fd) < 0)
        return -1;

    if (file_truncate(fd, 0) < 0) {
        file_close(fd);
        return -1;
    }

    int ret = file_write_exact(fd, data, size);
    file_close(fd);
    return ret;
}

int chunk_store_read(ChunkStore *cs, SHA256 hash, char *dst, uint32_t size)
{
    char buf[512];
    string path = chunk_path(cs, hash, buf, sizeof(buf));
    if (path.len == 0)
        return -1;

    Handle fd;
    if (file_open(path, &fd) < 0)
        return -1;

    int ret = file_read_exact(fd, dst, size);
    file_close(fd);
    return ret;
}

bool chunk_store_exists(ChunkStore *cs, SHA256 hash)
{
    char buf[512];
    string path = chunk_path(cs, hash, buf, sizeof(buf));
    if (path.len == 0)
        return false;

    // Use file_open instead of file_exists (access) because
    // mock_access is not implemented in the Quakey simulation.
    Handle fd;
    if (file_open(path, &fd) < 0)
        return false;
    file_close(fd);
    return true;
}

int chunk_store_delete(ChunkStore *cs, SHA256 hash)
{
    char buf[512];
    string path = chunk_path(cs, hash, buf, sizeof(buf));
    if (path.len == 0)
        return -1;

    return remove_file_or_dir(path);
}
