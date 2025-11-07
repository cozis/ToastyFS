#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "system.h"
#include "file_tree.h"

static int parse_path(string path, string *comps, int max)
{
    bool is_absolute = false;
    if (path.len > 0 && path.ptr[0] == '/') {
        is_absolute = true;
        path.ptr++;
        path.len--;
        if (path.len == 0)
            return 0; // Absolute paths with no components are allowed
    }

    int num = 0;
    uint32_t i = 0;
    for (;;) {

        uint32_t off = i;
        while (i < (uint32_t) path.len && path.ptr[i] != '/')
            i++;
        uint32_t len = i - off;

        if (len == 0)
            return -1; // Empty component

        string comp = { path.ptr + off, len };
        if (comp.len == 2 && comp.ptr[0] == '.' && comp.ptr[1] == '.') {
            if (num == 0) {
                // For absolute paths, ".." at root is ignored (stays at root)
                // For relative paths, ".." with no components references parent, which is invalid
                if (!is_absolute)
                    return -1;
                // Otherwise, ignore the ".." (absolute path, already at root)
            } else {
                num--;
            }
        } else if (comp.len != 1 || comp.ptr[0] != '.') {
            if (num == max)
                return -1; // To many components
            comps[num++] = comp;
        }

        if (i == (uint32_t) path.len)
            break;

        assert(path.ptr[i] == '/');
        i++;

        if (i == (uint32_t) path.len)
            break;
    }

    return num;
}

static int dir_find(Dir *parent, string name)
{
    for (uint64_t i = 0; i < parent->num_children; i++)
        if (streq((string) { parent->children[i].name, parent->children[i].name_len }, name))
            return i;
    return -1;
}

static Entity *resolve_path(Entity *root, string *comps, int num_comps)
{
    assert(root->is_dir);

    Entity *current = root;
    for (int i = 0; i < num_comps; i++) {

        if (!current->is_dir)
            return NULL;

        int j = dir_find(&current->d, comps[i]);
        if (j == -1)
            return NULL;

        current = &current->d.children[j];
    }

    return current;
}

static void entity_free(Entity *e);
static bool entity_uses_hash(Entity *e, SHA256 hash);

static void dir_init(Dir *d)
{
    d->num_children = 0;
    d->max_children = 0;
    d->children = NULL;
}

static void dir_free(Dir *d)
{
    for (uint64_t i = 0; i < d->num_children; i++)
        entity_free(&d->children[i]);
    sys_free(d->children);
}

static void dir_remove(Dir *d, int idx)
{
    d->children[idx] = d->children[--d->num_children];
}

static bool dir_uses_hash(Dir *d, SHA256 hash)
{
    for (uint64_t i = 0; i < d->num_children; i++)
        if (entity_uses_hash(&d->children[i], hash))
            return true;
    return false;
}

static void file_init(File *f, uint64_t chunk_size)
{
    f->chunk_size = chunk_size;
    f->num_chunks = 0;
    f->chunks = NULL;
}

static void file_free(File *f)
{
    sys_free(f->chunks);
    f->chunks = NULL;
}

static bool file_uses_hash(File *f, SHA256 hash)
{
    for (uint64_t i = 0; i < f->num_chunks; i++)
        if (!memcmp(&f->chunks[i], &hash, sizeof(SHA256)))
            return true;
    return false;
}

// Fails when the name is too long
static int entity_init(Entity *e, char *name, int name_len,
    bool is_dir, uint64_t chunk_size)
{
    if (name_len >= (int) sizeof(e->name))
        return -1;
    memcpy(e->name, name, name_len);
    e->name[name_len] = '\0';
    e->name_len = (uint16_t) name_len;

    e->is_dir = is_dir;
    if (is_dir)
        dir_init(&e->d);
    else
        file_init(&e->f, chunk_size);

    return 0;
}

static void entity_free(Entity *e)
{
    if (e->is_dir)
        dir_free(&e->d);
    else
        file_free(&e->f);
}

static bool entity_uses_hash(Entity *e, SHA256 hash)
{
    if (e->is_dir)
        return dir_uses_hash(&e->d, hash);
    else
        return file_uses_hash(&e->f, hash);
}

int file_tree_init(FileTree *ft)
{
    int ret = entity_init(&ft->root, "", 0, true, 0);
    if (ret < 0) return -1;

    return 0;
}

void file_tree_free(FileTree *ft)
{
    entity_free(&ft->root);
}

bool file_tree_uses_hash(FileTree *ft, SHA256 hash)
{
    return entity_uses_hash(&ft->root, hash);
}

int file_tree_list(FileTree *ft, string path,
    ListItem *items, int max_items)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return FILETREE_NOENT;

    if (!e->is_dir)
        return FILETREE_NOTDIR;

    Dir *d = &e->d;

    int num_items = d->num_children;
    if (num_items > max_items) num_items = max_items;
    for (int i = 0; i < num_items; i++) {

        Entity *c = &d->children[i];

        int name_cpy = c->name_len;
        if (name_cpy > (int) sizeof(items[i].name)-1)
            name_cpy = (int) sizeof(items[i].name)-1;

        memcpy(items[i].name, c->name, name_cpy);
        items[i].name[name_cpy] = '\0';

        items[i].name_len = name_cpy;
        items[i].is_dir = c->is_dir;
    }

    return d->num_children;
}

int file_tree_create_entity(FileTree *ft, string path,
    bool is_dir, uint64_t chunk_size)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);

    if (num_comps < 0)
        // Couldn't parse path
        return FILETREE_BADPATH;

    if (num_comps == 0)
        // Path is empty, which means the caller is referencing the root,
        // which exists already.
        return FILETREE_EXISTS;

    // Resolve the path up to the second last component
    Entity *e = resolve_path(&ft->root, comps, num_comps-1);

    if (e == NULL)
        // Parent directory doesn't exist
        return FILETREE_NOENT;

    if (!e->is_dir)
        // Parent entity is not a directory
        return FILETREE_NOTDIR;

    string name = comps[num_comps-1];
    if (dir_find(&e->d, name) != -1)
        return FILETREE_EXISTS;

    Dir *d = &e->d;
    if (d->num_children == d->max_children) {

        int new_max = 2 * d->max_children;
        if (new_max == 0)
            new_max = 8;

        Entity *p = sys_malloc(sizeof(Entity) * new_max);
        if (p == NULL)
            return FILETREE_NOMEM;

        for (uint64_t i = 0; i < d->num_children; i++)
            p[i] = d->children[i];

        sys_free(d->children);
        d->children = p;
        d->max_children = new_max;
    }
    Entity *c = &d->children[d->num_children];

    int ret = entity_init(c, (char*) name.ptr, name.len, is_dir, chunk_size);
    if (ret < 0)
        // Invalid name for the new file
        return FILETREE_BADPATH;

    d->num_children++;
    return 0;
}

int file_tree_delete_entity(FileTree *ft, string path)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;
    if (num_comps == 0)
        return FILETREE_BADOP;

    Entity *e = resolve_path(&ft->root, comps, num_comps-1);
    if (e == NULL)
        return FILETREE_NOENT;
    if (!e->is_dir)
        return FILETREE_NOTDIR;

    int i = dir_find(&e->d, comps[num_comps-1]);
    if (i == -1)
        return FILETREE_NOENT;

    dir_remove(&e->d, i);
    return 0;
}

int file_tree_write(FileTree *ft, string path,
    uint64_t off, uint64_t len, SHA256 *prev_hashes,
    SHA256 *hashes, SHA256 *removed_hashes, int *num_removed)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return FILETREE_NOENT;

    if (e->is_dir)
        return FILETREE_ISDIR;

    File *f = &e->f;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = (off + len - 1) / f->chunk_size;

    if (last_chunk_index >= f->num_chunks) {
        SHA256 *new_chunks = sys_malloc((last_chunk_index+1) * sizeof(SHA256));
        if (new_chunks == NULL)
            return FILETREE_NOMEM;
        if (f->chunks) {
            if (f->num_chunks > 0)
                memcpy(new_chunks, f->chunks, f->num_chunks);
            sys_free(f->chunks);
        }
        f->chunks = new_chunks;
        f->num_chunks = last_chunk_index+1;
        for (uint64_t i = f->num_chunks; i < last_chunk_index+1; i++)
            memset(&f->chunks[i], 0, sizeof(SHA256));
    }

    // Verify prev_hashes match
    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++)
        if (memcmp(&f->chunks[i], &prev_hashes[i - first_chunk_index], sizeof(SHA256)))
            return -1;

    // Update chunks
    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++)
        f->chunks[i] = hashes[i - first_chunk_index];

    // Now check which old hashes are no longer used anywhere in the tree
    *num_removed = 0;
    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++) {
        SHA256 old_hash = prev_hashes[i - first_chunk_index];

        // Skip zero hashes
        bool is_zero = true;
        for (int j = 0; j < (int) sizeof(SHA256); j++) {
            if (old_hash.data[j] != 0) {
                is_zero = false;
                break;
            }
        }
        if (is_zero)
            continue;

        // Check if this hash is still used anywhere in the tree
        if (!entity_uses_hash(&ft->root, old_hash)) {
            // Not used - add to removed list
            if (removed_hashes)
                removed_hashes[*num_removed] = old_hash;
            (*num_removed)++;
        }
    }

    return 0;
}

#define ZERO_HASH ((SHA256) { .data={0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } })

int file_tree_read(FileTree *ft, string path,
    uint64_t off, uint64_t len, uint64_t *chunk_size,
    SHA256 *hashes, int max_hashes)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return FILETREE_NOENT;

    if (e->is_dir)
        return FILETREE_NOTDIR;

    File *f = &e->f;

    if (len == 0)
        return 0;

    *chunk_size = f->chunk_size;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = (off + len - 1) / f->chunk_size;

    if (first_chunk_index >= f->num_chunks)
        return 0;

    if (last_chunk_index >= f->num_chunks) {
        if (f->num_chunks == 0)
            return 0;
        last_chunk_index = f->num_chunks-1;
    }

    int num_hashes = 0;
    for (uint32_t i = first_chunk_index; i <= last_chunk_index; i++) {

        SHA256 hash = f->chunks[i];

        if (num_hashes < max_hashes)
            hashes[num_hashes] = hash;
        num_hashes++;
    }

    return num_hashes;
}

string file_tree_strerror(int code)
{
    switch (code) {
        case FILETREE_NOMEM  : return S("Out of memory");
        case FILETREE_NOENT  : return S("No such file or directory");
        case FILETREE_NOTDIR : return S("Entity is not a directory");
        case FILETREE_ISDIR  : return S("Entity is a directory");
        case FILETREE_EXISTS : return S("File or directory already exists");
        case FILETREE_BADPATH: return S("Invalid path");
        case FILETREE_BADOP  : return S("Invalid operation");
        default:break;
    }
    return S("Unknown error");
}
