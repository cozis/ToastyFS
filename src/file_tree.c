#include <limits.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "basic.h"
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

static bool gen_match(uint64_t expected_gen, uint64_t entity_gen)
{
    assert(entity_gen != NO_GENERATION);

    if (expected_gen == NO_GENERATION)
        return true;

    return expected_gen == entity_gen;
}

static uint64_t create_generation(uint64_t *next_gen)
{
    (*next_gen)++;
    if (*next_gen == 0 || *next_gen == UINT64_MAX)
        *next_gen = 1;
    return *next_gen;
}

static int dir_remove(Dir *d, int idx, uint64_t expected_gen)
{
    if (!gen_match(expected_gen, d->children[idx].gen))
        return -1;

    // TODO: pretty sure this leaks memory
    d->children[idx] = d->children[--d->num_children];
    return 0;
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
    f->file_size = 0;
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
    bool is_dir, uint64_t chunk_size, uint64_t *next_gen)
{
    if (name_len >= (int) sizeof(e->name))
        return -1;

    e->gen = create_generation(next_gen);
    assert(e->gen != NO_GENERATION);

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
    ft->next_gen = 1;

    int ret = entity_init(&ft->root, "", 0, true, 0, &ft->next_gen);
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
    ListItem *items, int max_items, uint64_t *gen)
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

    assert(e->gen != NO_GENERATION);
    *gen = e->gen;

    return d->num_children;
}

int file_tree_create_entity(FileTree *ft, string path,
    bool is_dir, uint64_t chunk_size, uint64_t *gen)
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

    int ret = entity_init(c, (char*) name.ptr, name.len, is_dir, chunk_size, &ft->next_gen);
    if (ret < 0)
        // Invalid name for the new file
        return FILETREE_BADPATH;

    assert(e->gen != NO_GENERATION);
    *gen = e->gen;

    d->num_children++;
    return 0;
}

// TODO: this should return the list of unreferenced hashes
int file_tree_delete_entity(FileTree *ft, string path,
    uint64_t expected_gen)
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

    if (dir_remove(&e->d, i, expected_gen) < 0)
        return -1; // TODO: proper error code

    return 0;
}

int file_tree_write(FileTree *ft, string path,
    uint64_t off, uint64_t len, uint32_t num_chunks,
    uint64_t expect_gen,
    uint64_t *new_gen,
    SHA256 *hashes,
    SHA256 *removed_hashes,
    int *num_removed)
{
    // Per protocol spec, WRITE operations cannot use expect_gen=0
    if (expect_gen == NO_GENERATION)
        return FILETREE_BADGEN;

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

    if (!gen_match(expect_gen, e->gen))
        return -1; // TODO: proper error code

    File *f = &e->f;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = first_chunk_index + (len - 1) / f->chunk_size;

    assert(last_chunk_index - first_chunk_index + 1 == num_chunks);

    if (last_chunk_index >= f->num_chunks) {
        uint64_t old_num_chunks = f->num_chunks;
        SHA256 *new_chunks = sys_malloc((last_chunk_index+1) * sizeof(SHA256));
        if (new_chunks == NULL)
            return FILETREE_NOMEM;
        if (f->chunks) {
            if (f->num_chunks > 0)
                memcpy(new_chunks, f->chunks, f->num_chunks * sizeof(SHA256));
            sys_free(f->chunks);
        }
        f->chunks = new_chunks;
        f->num_chunks = last_chunk_index+1;
        for (uint64_t i = old_num_chunks; i < last_chunk_index+1; i++)
            memset(&f->chunks[i], 0, sizeof(SHA256));
    }

    int num_overwritten_hashes = 0;
    SHA256 overwritten_hashes[100]; // TODO: fix this limit
    if (num_chunks > 100) {
        assert(0); // TODO
    }

    // Update chunks
    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++) {
        overwritten_hashes[num_overwritten_hashes++] = f->chunks[i];
        f->chunks[i] = hashes[i - first_chunk_index];
    }

    // Update file size (last byte written + 1)
    uint64_t new_size = off + len;
    if (new_size > f->file_size)
        f->file_size = new_size;

    // Now check which old hashes are no longer used
    // anywhere in the tree
    //
    // NOTE: If removed_hashes is NULL, the caller isn't
    //       interested in which hashes are no longer reachable.
    if (removed_hashes != NULL) {
        *num_removed = 0;
        for (int i = 0; i < num_overwritten_hashes; i++) {

            SHA256 hash = overwritten_hashes[i];

            // Skip zero hashes
            bool is_zero = true;
            for (int j = 0; j < (int) sizeof(SHA256); j++) {
                if (hash.data[j] != 0) {
                    is_zero = false;
                    break;
                }
            }
            if (is_zero)
                continue;

            // Check if this hash is still used anywhere in the tree
            if (!entity_uses_hash(&ft->root, hash)) {
                removed_hashes[*num_removed] = hash;
                (*num_removed)++;
            }
        }
    }

    e->gen = create_generation(&ft->next_gen);
    assert(e->gen != NO_GENERATION);

    *new_gen = e->gen;
    return 0;
}

int file_tree_read(FileTree *ft, string path,
    uint64_t off, uint64_t len, uint64_t *gen, uint64_t *chunk_size,
    SHA256 *hashes, int max_hashes, uint64_t *actual_bytes)
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

    *chunk_size = f->chunk_size;

    // Calculate actual bytes that can be read based on actual file size
    if (off >= f->file_size) {
        *actual_bytes = 0;
    } else if (off + len > f->file_size) {
        *actual_bytes = f->file_size - off;
    } else {
        *actual_bytes = len;
    }

    if (len == 0)
        return 0;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = first_chunk_index + (len - 1) / f->chunk_size;

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

    assert(e->gen != NO_GENERATION);
    *gen = e->gen;

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
        case FILETREE_BADGEN : return S("Generation counter cannot be zero for write operations");
        default:break;
    }
    return S("Unknown error");
}

typedef struct {
    int (*write_fn)(char*,int,void*);
    void *write_data;
    char *buffer;
    int   buffer_size;
    int   buffer_used;
    bool  error;
} SerializeContext;

static void sc_flush(SerializeContext *sc)
{
    if (sc->error)
        return;

    int ret = sc->write_fn(sc->buffer, sc->buffer_used, sc->write_data);
    if (ret < 0) {
        sc->error = true;
        return;
    }

    sc->buffer_used = 0;
}

static void sc_write_mem(SerializeContext *sc, char *src, int len)
{
    if (sc->error)
        return;

    if (sc->buffer_size - sc->buffer_used < len) {

        if (len > sc->buffer_size) {
            sc->error = true;
            return;
        }

        sc_flush(sc);
        if (sc->error)
            return;
    }

    memcpy(sc->buffer + sc->buffer_used, src, len);
    sc->buffer_used += len;
}
static void sc_write_u8  (SerializeContext *sc, uint8_t  value) { sc_write_mem(sc, (char*) &value, (int) sizeof(value)); }
static void sc_write_u16 (SerializeContext *sc, uint16_t value) { sc_write_mem(sc, (char*) &value, (int) sizeof(value)); }
static void sc_write_u64 (SerializeContext *sc, uint64_t value) { sc_write_mem(sc, (char*) &value, (int) sizeof(value)); }
static void sc_write_hash(SerializeContext *sc, SHA256   value) { sc_write_mem(sc, (char*) &value, (int) sizeof(value)); }

static void file_serialize(SerializeContext *sc, File *f)
{
    sc_write_u64(sc, f->chunk_size);
    sc_write_u64(sc, f->num_chunks);
    sc_write_u64(sc, f->file_size);
    for (uint64_t i = 0; i < f->num_chunks; i++)
        sc_write_hash(sc, f->chunks[i]);
}

static void entity_serialize(SerializeContext *sc, Entity *e);

static void dir_serialize(SerializeContext *sc, Dir *d)
{
    sc_write_u64(sc, d->num_children);
    for (uint64_t i = 0; i < d->num_children; i++)
        entity_serialize(sc, &d->children[i]);
}

static void entity_serialize(SerializeContext *sc, Entity *e)
{
    sc_write_u16(sc, e->name_len);
    sc_write_mem(sc, e->name, e->name_len);
    sc_write_u8(sc, e->is_dir);
    if (e->is_dir)
        dir_serialize(sc, &e->d);
    else
        file_serialize(sc, &e->f);
}

int file_tree_serialize(FileTree *ft, int (*write_fn)(char*,int,void*), void *write_data)
{
    SerializeContext sc;
    sc.write_fn = write_fn;
    sc.write_data = write_data;
    sc.buffer_used = 0;
    sc.buffer_size = 1<<10;
    sc.buffer = sys_malloc(sc.buffer_size);
    sc.error = false;
    if (sc.buffer == NULL)
        sc.error = true;
    entity_serialize(&sc, &ft->root);
    sc_flush(&sc);
    sys_free(sc.buffer);
    if (sc.error)
        return -1;
    return 0;
}

typedef struct {
    int (*read_fn)(char*,int,void*);
    void *read_data;
    char *buffer;
    int   buffer_size;
    int   buffer_used;
    int   buffer_head;
    bool  error;
    uint64_t total_read;
} DeserializeContext;

static void dc_read_mem(DeserializeContext *dc, void *dst, int len)
{
    if (dc->error)
        return;

    if (dc->buffer_used < len) {

        if (dc->buffer_size < len) {
            dc->error = true;
            return;
        }

        memmove(dc->buffer, dc->buffer + dc->buffer_head, dc->buffer_used);
        dc->buffer_head = 0;

        int ret = dc->read_fn(
            dc->buffer      + dc->buffer_used,
            dc->buffer_size - dc->buffer_used,
            dc->read_data);
        if (ret < 0) {
            dc->error = true;
            return;
        }
        dc->buffer_used += ret;

        if (dc->buffer_used < len) {
            dc->error = true;
            return;
        }
    }

    memcpy(dst, dc->buffer + dc->buffer_head, len);
    dc->buffer_head += len;
    dc->buffer_used -= len;
    dc->total_read  += len;
}
static void dc_read_u8 (DeserializeContext *dc,  uint8_t  *dst) { dc_read_mem(dc, dst, sizeof(*dst)); }
static void dc_read_u16(DeserializeContext *dc,  uint16_t *dst) { dc_read_mem(dc, dst, sizeof(*dst)); }
static void dc_read_u64(DeserializeContext *dc,  uint64_t *dst) { dc_read_mem(dc, dst, sizeof(*dst)); }
static void dc_read_hash(DeserializeContext *dc, SHA256   *dst) { dc_read_mem(dc, dst, sizeof(*dst)); }

static void file_deserialize(DeserializeContext *dc, File *f)
{
    dc_read_u64(dc, &f->chunk_size);
    dc_read_u64(dc, &f->num_chunks);
    dc_read_u64(dc, &f->file_size);

    f->chunks = sys_malloc(f->num_chunks * sizeof(SHA256));
    if (f->chunks == NULL) {
        assert(0); // TODO
    }

    for (uint64_t i = 0; i < f->num_chunks; i++)
        dc_read_hash(dc, &f->chunks[i]);
}

static void entity_deserialize(DeserializeContext *dc, Entity *e);

static void dir_deserialize(DeserializeContext *dc, Dir *d)
{
    dc_read_u64(dc, &d->num_children);

    d->max_children = d->num_children;
    d->children = sys_malloc(d->num_children * sizeof(Entity));
    if (d->children == NULL) {
        assert(0); // TODO
    }

    // TODO: not checking for errors is not okay as
    //       the code will branch based on garbage
    //       values.
    for (uint64_t i = 0; i < d->num_children; i++)
        entity_deserialize(dc, &d->children[i]);
}

static void entity_deserialize(DeserializeContext *dc, Entity *e)
{
    dc_read_u16(dc, &e->name_len); // TODO: make sure this doesn't go over the static buffer
    dc_read_mem(dc, e->name, e->name_len);

    uint8_t is_dir;
    dc_read_u8 (dc, &is_dir);
    e->is_dir = (is_dir != 0);

    if (e->is_dir)
        dir_deserialize(dc, &e->d);
    else
        file_deserialize(dc, &e->f);
}

int file_tree_deserialize(FileTree *ft, int (*read_fn)(char*,int,void*), void *read_data)
{
    DeserializeContext dc;
    dc.read_fn = read_fn;
    dc.read_data = read_data;
    dc.buffer_head = 0;
    dc.buffer_used = 0;
    dc.buffer_size = 1<<10;
    dc.buffer = sys_malloc(dc.buffer_size);
    dc.error = false;
    if (dc.buffer == NULL)
        dc.error = true;
    dc.total_read = 0;
    entity_deserialize(&dc, &ft->root);
    sys_free(dc.buffer);
    if (dc.error)
        return -1;
    if (dc.total_read > INT_MAX) {
        assert(0); // TODO
    }
    return dc.total_read;
}
