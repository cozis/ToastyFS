#ifndef HASH_SET_INCLUDED
#define HASH_SET_INCLUDED

#include "basic.h"

typedef struct {
    SHA256 *items;
    int     count;
    int     capacity;
} HashSet;

typedef struct {
    SHA256 hash;
    Time   time;
} TimedHash;

typedef struct {
    TimedHash *items;
    int        count;
    int        capacity;
} TimedHashSet;

void hash_set_init     (HashSet *set);
void hash_set_free     (HashSet *set);
void hash_set_clear    (HashSet *set);
int  hash_set_insert   (HashSet *set, SHA256 hash);
bool hash_set_remove   (HashSet *set, SHA256 hash);
int  hash_set_merge    (HashSet *dst, HashSet src);
void hash_set_remove_set(HashSet *dst, HashSet src);
bool hash_set_contains (HashSet *set, SHA256 hash);

void timed_hash_set_init   (TimedHashSet *set);
void timed_hash_set_free   (TimedHashSet *set);
int  timed_hash_set_find   (TimedHashSet *set, SHA256 hash);
int  timed_hash_set_insert (TimedHashSet *set, SHA256 hash, Time time);
void timed_hash_set_remove (TimedHashSet *set, SHA256 hash);

#endif // HASH_SET_INCLUDED
