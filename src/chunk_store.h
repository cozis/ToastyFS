#ifndef CHUNK_STORE_INCLUDED
#define CHUNK_STORE_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include "basic.h"

typedef struct {
    char base_path[256];
} ChunkStore;

int  chunk_store_init(ChunkStore *cs, const char *base_path);
void chunk_store_free(ChunkStore *cs);
int  chunk_store_write(ChunkStore *cs, SHA256 hash, char *data, uint32_t size);
int  chunk_store_read(ChunkStore *cs, SHA256 hash, char *dst, uint32_t size);
bool chunk_store_exists(ChunkStore *cs, SHA256 hash);
int  chunk_store_delete(ChunkStore *cs, SHA256 hash);

#endif // CHUNK_STORE_INCLUDED
