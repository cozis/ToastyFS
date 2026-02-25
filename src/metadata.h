#ifndef METADATA_INCLUDED
#define METADATA_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include <lib/basic.h>
#include "config.h"

typedef struct {
    SHA256   hash;
    uint32_t size;
    uint16_t num_holders;
    uint16_t holders[REPLICATION_FACTOR];
} ChunkRef;

#define META_BUCKET_MAX  64
#define META_KEY_MAX     512
#define META_CHUNKS_MAX  256

typedef enum {
    META_OPER_NOOP,
    META_OPER_PUT,
    META_OPER_DELETE,
} MetaOperType;

typedef struct {
    MetaOperType type;
    char     bucket[META_BUCKET_MAX];
    char     key[META_KEY_MAX];
    uint64_t size;
    SHA256   content_hash;
    uint32_t num_chunks;
    ChunkRef chunks[META_CHUNKS_MAX];
} MetaOper;

typedef enum {
    META_RESULT_OK,
    META_RESULT_NOT_FOUND,
    META_RESULT_FULL,
} MetaResultType;

typedef struct {
    MetaResultType type;
} MetaResult;

typedef struct {
    char     bucket[META_BUCKET_MAX];
    char     key[META_KEY_MAX];
    uint64_t size;
    SHA256   content_hash;
    uint32_t num_chunks;
    ChunkRef chunks[META_CHUNKS_MAX];
    bool     deleted;
} ObjectMeta;

#define META_ENTRY_LIMIT 4096

typedef struct {
    int count;
    ObjectMeta entries[META_ENTRY_LIMIT];
} MetaStore;

void       meta_store_init(MetaStore *ms);
void       meta_store_free(MetaStore *ms);
MetaResult meta_store_update(MetaStore *ms, MetaOper *oper);
ObjectMeta *meta_store_lookup(MetaStore *ms, const char *bucket, const char *key);

int meta_snprint_oper(char *buf, int size, MetaOper *oper);
int meta_snprint_result(char *buf, int size, MetaResult result);

#endif // METADATA_INCLUDED
