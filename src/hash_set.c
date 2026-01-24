#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif
#include <stdint.h>
#include <quakey.h>
#include "hash_set.h"

void hash_set_init(HashSet *set)
{
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

void hash_set_free(HashSet *set)
{
    free(set->items);
    set->items = NULL;
}

void hash_set_clear(HashSet *set)
{
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

int hash_set_insert(HashSet *set, SHA256 hash)
{
    // Avoid duplicates
    for (int i = 0; i < set->count; i++)
        if (!memcmp(&set->items[i], &hash, sizeof(SHA256)))
            return 0;  // Already present

    if (set->count == set->capacity) {

        int new_capacity;
        if (set->items == NULL)
            new_capacity = 16;
        else
            new_capacity = 2 * set->capacity;

        SHA256 *new_items = realloc(set->items, new_capacity * sizeof(SHA256));
        if (new_items == NULL)
            return -1;

        set->items = new_items;
        set->capacity = new_capacity;
    }

    set->items[set->count++] = hash;
    return 0;
}

bool hash_set_remove(HashSet *set, SHA256 hash)
{
    for (int i = 0; i < set->count; i++)
        if (!memcmp(&hash, &set->items[i], sizeof(SHA256))) {
            set->items[i] = set->items[--set->count];
            return true;
        }
    return false;
}

bool hash_set_contains(HashSet *set, SHA256 hash)
{
    for (int i = 0; i < set->count; i++)
        if (!memcmp(&hash, &set->items[i], sizeof(SHA256)))
            return true;
    return false;
}

int hash_set_merge(HashSet *dst, HashSet src)
{
    HashSet ret;
    hash_set_init(&ret);

    for (int i = 0; i < dst->count; i++) {
        if (hash_set_insert(&ret, dst->items[i]) < 0)
            goto error;
    }

    for (int i = 0; i < src.count; i++) {
        if (hash_set_insert(&ret, src.items[i]) < 0)
            goto error;
    }

    hash_set_free(dst);
    *dst = ret;
    return 0;

error:
    hash_set_free(&ret);
    return -1;
}

void hash_set_remove_set(HashSet *dst, HashSet src)
{
    for (int i = 0; i < src.count; i++)
        hash_set_remove(dst, src.items[i]);
}

void timed_hash_set_init(TimedHashSet *set)
{
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

void timed_hash_set_free(TimedHashSet *set)
{
    free(set->items);
    set->items = NULL;
}

int timed_hash_set_find(TimedHashSet *set, SHA256 hash)
{
    for (int i = 0; i < set->count; i++)
        if (!memcmp(&set->items[i].hash, &hash, sizeof(SHA256)))
            return i;
    return -1;
}

int timed_hash_set_insert(TimedHashSet *set, SHA256 hash, Time time)
{
    // Check if already in set
    int idx = timed_hash_set_find(set, hash);
    if (idx >= 0) {
        // Already marked, keep the original time
        return 0;
    }

    if (set->count == set->capacity) {
        int new_capacity;
        if (set->capacity == 0)
            new_capacity = 8;
        else
            new_capacity = 2 * set->capacity;

        TimedHash *new_items = malloc(new_capacity * sizeof(TimedHash));
        if (new_items == NULL)
            return -1;

        if (set->capacity > 0) {
            memcpy(new_items, set->items, set->count * sizeof(set->items[0]));
            free(set->items);
        }

        set->items = new_items;
        set->capacity = new_capacity;
    }

    set->items[set->count++] = (TimedHash) { hash, time };
    return 0;
}

void timed_hash_set_remove(TimedHashSet *set, SHA256 hash)
{
    int idx = timed_hash_set_find(set, hash);
    if (idx >= 0) {
        // Remove by shifting remaining items
        if (idx < set->count - 1) {
            memmove(&set->items[idx], &set->items[idx + 1],
                    (set->count - idx - 1) * sizeof(set->items[0]));
        }
        set->count--;
    }
}
