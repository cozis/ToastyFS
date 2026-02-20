#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>
#include <stdio.h>

#include "metadata.h"

void meta_store_init(MetaStore *ms)
{
    memset(ms, 0, sizeof(*ms));
}

void meta_store_free(MetaStore *ms)
{
    (void) ms;
}

static int find_entry(MetaStore *ms, const char *bucket, const char *key)
{
    for (int i = 0; i < ms->count; i++) {
        if (!ms->entries[i].deleted
            && strncmp(ms->entries[i].bucket, bucket, META_BUCKET_MAX) == 0
            && strncmp(ms->entries[i].key, key, META_KEY_MAX) == 0)
            return i;
    }
    return -1;
}

static void copy_oper_to_entry(ObjectMeta *entry, MetaOper *oper)
{
    memcpy(entry->bucket, oper->bucket, META_BUCKET_MAX);
    memcpy(entry->key, oper->key, META_KEY_MAX);
    entry->size = oper->size;
    entry->content_hash = oper->content_hash;
    entry->num_chunks = oper->num_chunks;
    memcpy(entry->chunks, oper->chunks, oper->num_chunks * sizeof(ChunkRef));
    entry->deleted = false;
}

MetaResult meta_store_update(MetaStore *ms, MetaOper *oper)
{
    MetaResult result;

    switch (oper->type) {

    case META_OPER_NOOP:
        result.type = META_RESULT_OK;
        break;

    case META_OPER_PUT:
        {
            // Try to find existing entry with same bucket/key
            int i = find_entry(ms, oper->bucket, oper->key);
            if (i >= 0) {
                // Overwrite in-place
                copy_oper_to_entry(&ms->entries[i], oper);
                result.type = META_RESULT_OK;
                break;
            }

            // Try to reuse a tombstoned slot
            for (i = 0; i < ms->count; i++) {
                if (ms->entries[i].deleted) {
                    copy_oper_to_entry(&ms->entries[i], oper);
                    result.type = META_RESULT_OK;
                    goto done;
                }
            }

            // Allocate new slot
            if (ms->count >= META_ENTRY_LIMIT) {
                result.type = META_RESULT_FULL;
                break;
            }
            copy_oper_to_entry(&ms->entries[ms->count++], oper);
            result.type = META_RESULT_OK;
        }
        break;

    case META_OPER_DELETE:
        {
            int i = find_entry(ms, oper->bucket, oper->key);
            if (i < 0) {
                result.type = META_RESULT_NOT_FOUND;
            } else {
                ms->entries[i].deleted = true;
                result.type = META_RESULT_OK;
            }
        }
        break;

    default:
        assert(0);
        break;
    }

done:
    return result;
}

ObjectMeta *meta_store_lookup(MetaStore *ms, const char *bucket, const char *key)
{
    int i = find_entry(ms, bucket, key);
    if (i < 0)
        return NULL;
    return &ms->entries[i];
}

int meta_snprint_oper(char *buf, int size, MetaOper *oper)
{
    switch (oper->type) {
    case META_OPER_NOOP:
        return snprintf(buf, size, "NOOP");
    case META_OPER_PUT:
        return snprintf(buf, size, "PUT(%s/%s, %u chunks)",
            oper->bucket, oper->key, oper->num_chunks);
    case META_OPER_DELETE:
        return snprintf(buf, size, "DELETE(%s/%s)",
            oper->bucket, oper->key);
    default:
        return snprintf(buf, size, "???");
    }
}

int meta_snprint_result(char *buf, int size, MetaResult result)
{
    switch (result.type) {
    case META_RESULT_OK:        return snprintf(buf, size, "OK");
    case META_RESULT_NOT_FOUND: return snprintf(buf, size, "NOT_FOUND");
    case META_RESULT_FULL:      return snprintf(buf, size, "FULL");
    default:                    return snprintf(buf, size, "???");
    }
}
