#ifndef FILE_TREE_INCLUDED
#define FILE_TREE_INCLUDED

#include "basic.h"

enum {
    FILETREE_NOMEM   = -1,
    FILETREE_NOENT   = -2,
    FILETREE_NOTDIR  = -3,
    FILETREE_ISDIR   = -4,
    FILETREE_EXISTS  = -5,
    FILETREE_BADPATH = -6,
    FILETREE_BADOP   = -7,
};

typedef struct Entity Entity;

typedef struct {
    uint64_t chunk_size; // TODO: this should be an u32
    uint64_t num_chunks; // TODO: and this too
    SHA256 *chunks;
} File;

typedef struct {
    uint64_t max_children;
    uint64_t num_children;
    Entity *children;
} Dir;

struct Entity {
    char name[1<<8];
    uint16_t name_len;
    bool is_dir;
    union {
        Dir  d;
        File f;
    };
};

typedef struct {
    Entity root;
} FileTree;

typedef struct {
    char name[1<<8];
    int  name_len;
    bool is_dir;
} ListItem;

#define MAX_COMPS 32

int    file_tree_init          (FileTree *ft);
void   file_tree_free          (FileTree *ft);
bool   file_tree_uses_hash     (FileTree *ft, SHA256 hash);
int    file_tree_list          (FileTree *ft, string path, ListItem *items, int max_items);
int    file_tree_create_entity (FileTree *ft, string path, bool is_dir, uint64_t chunk_size);
int    file_tree_delete_entity (FileTree *ft, string path);
int    file_tree_write         (FileTree *ft, string path, uint64_t off, uint64_t len, uint32_t num_chunks, uint32_t chunk_size, SHA256 *prev_hashes, SHA256 *hashes, SHA256 *removed_hashes, int *num_removed);
int    file_tree_read          (FileTree *ft, string path, uint64_t off, uint64_t len, uint64_t *chunk_size, SHA256 *hashes, int max_hashes, uint64_t *actual_bytes);
string file_tree_strerror      (int code);
int    file_tree_serialize     (FileTree *ft, int (*flush_fn)(char*,int,void*), void *flush_data);
int    file_tree_deserialize   (FileTree *ft, int (*read_fn)(char*,int,void*), void *read_data);

#endif // FILE_TREE_INCLUDED
