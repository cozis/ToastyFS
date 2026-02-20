#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "mockfs.h"

typedef struct {
    char *ptr;
    int   len;
} Slice;

#define S(X) (Slice) { (X), (int) sizeof(X)-1 }

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

#define MOCKFS_COMP_LIMIT  32

struct MockFS_Entity {
    MockFS_Entity *parent;
    MockFS_Entity *prev;
    MockFS_Entity *next;
    char name[MOCKFS_NAME_SIZE];
    int  name_len;
    bool is_dir;
    int  refcount;  // Number of open file handles pointing to this entity
    union {
        struct {
            MockFS_Entity *head_child;
            MockFS_Entity *tail_child;
        };
        ByteBuffer byte_buffer;
    };
};

static bool slice_eq(Slice s1, Slice s2)
{
    if (s1.len != s2.len)
        return false;
    return !memcmp(s1.ptr, s2.ptr, s1.len);
}

static void *alloc(MockFS *mfs, int len, int align)
{
    int pad = -(unsigned long long) (mfs->mem + mfs->off) & (align - 1);
    if (mfs->len - mfs->off < pad + len)
        return NULL;
    void *p = mfs->mem + mfs->off + pad;
    mfs->off += pad + len;
    return p;
}

static void byte_buffer_init(ByteBuffer *byte_buffer)
{
    byte_buffer->used = 0;
    byte_buffer->tail_used = 0;
    byte_buffer->head = NULL;
    byte_buffer->tail = NULL;
}

static void byte_buffer_free(ByteBuffer *byte_buffer, ByteChunk **free_list)
{
    if (byte_buffer->head) {
        byte_buffer->tail->next = *free_list;
        *free_list = byte_buffer->head;
    }
}

static int convert_offset(ByteBuffer *byte_buffer, int off, ByteChunk **pchunk, int *poffset)
{
    assert(off > -1);

    int skipped = 0;
    ByteChunk *chunk = byte_buffer->head;
    while (chunk) {
        int chunk_used = (chunk->next ? BYTE_CHUNK_SIZE : byte_buffer->tail_used);
        if (off >= skipped && off < skipped + chunk_used) {
            *pchunk = chunk;
            *poffset = off - skipped;
            return 1;
        }
        chunk = chunk->next;
        skipped += chunk_used;
    }

    if (off == skipped) {
        *pchunk = byte_buffer->tail;
        *poffset = byte_buffer->tail ? byte_buffer->tail_used : 0;
        return 1;
    }

    return 0;
}

static int byte_buffer_read(ByteBuffer *byte_buffer, int off, char *dst, int cap)
{
    int rel_off;
    ByteChunk *chunk;
    convert_offset(byte_buffer, off, &chunk, &rel_off);

    int copied = 0;
    while (copied < cap) {
        if (chunk == byte_buffer->tail) {
            if (rel_off == byte_buffer->tail_used)
                break;
            int cpy = MIN(byte_buffer->tail_used - rel_off, cap - copied);
            memcpy(dst + copied, chunk->data + rel_off, cpy);
            copied += cpy;
            break;  // No more chunks after tail
        } else {
            int cpy = MIN(BYTE_CHUNK_SIZE - rel_off, cap - copied);
            memcpy(dst + copied, chunk->data + rel_off, cpy);
            copied += cpy;
            chunk = chunk->next;
            rel_off = 0;
        }
    }

    return copied;
}

// Calculate total used bytes in the buffer
static int byte_buffer_size(ByteBuffer *byte_buffer)
{
    int size = 0;
    ByteChunk *chunk = byte_buffer->head;
    while (chunk) {
        if (chunk->next) {
            size += BYTE_CHUNK_SIZE;
        } else {
            size += byte_buffer->tail_used;
        }
        chunk = chunk->next;
    }
    return size;
}

// Extend buffer to given size by filling with zeros
static int byte_buffer_extend(ByteBuffer *byte_buffer, int target_size, MockFS *mfs)
{
    int current_size = byte_buffer_size(byte_buffer);
    int to_write = target_size - current_size;

    while (to_write > 0) {
        // Get or create tail chunk
        if (byte_buffer->tail == NULL || byte_buffer->tail_used == BYTE_CHUNK_SIZE) {
            ByteChunk *tmp = mfs->chunk_free_list;
            if (tmp == NULL) {
                tmp = alloc(mfs, sizeof(ByteChunk), _Alignof(ByteChunk));
                if (tmp == NULL)
                    return MOCKFS_ERRNO_NOSPC;
            } else {
                mfs->chunk_free_list = tmp->next;
            }
            tmp->next = NULL;

            if (byte_buffer->head == NULL) {
                byte_buffer->head = tmp;
            } else {
                byte_buffer->tail->next = tmp;
            }
            byte_buffer->tail = tmp;
            byte_buffer->tail_used = 0;
        }

        // Fill remaining space in tail chunk with zeros
        int space = BYTE_CHUNK_SIZE - byte_buffer->tail_used;
        int fill = MIN(space, to_write);
        memset(byte_buffer->tail->data + byte_buffer->tail_used, 0, fill);
        byte_buffer->tail_used += fill;
        to_write -= fill;
    }

    return 0;
}

static int byte_buffer_write(ByteBuffer *byte_buffer, int off, char *src, int len, MockFS *mfs)
{
    int rel_off;
    ByteChunk *chunk;
    if (!convert_offset(byte_buffer, off, &chunk, &rel_off)) {
        // Offset is beyond end of buffer - extend with zeros
        int ret = byte_buffer_extend(byte_buffer, off, mfs);
        if (ret < 0)
            return ret;
        convert_offset(byte_buffer, off, &chunk, &rel_off);
    }

    int copied = 0;
    while (copied < len) {

        if (chunk == byte_buffer->tail) {
            if (chunk == NULL || rel_off == BYTE_CHUNK_SIZE) {

                ByteChunk *tmp = mfs->chunk_free_list;
                if (tmp == NULL) {
                    tmp = alloc(mfs, sizeof(ByteChunk), _Alignof(ByteChunk));
                    if (tmp == NULL)
                        return MOCKFS_ERRNO_NOSPC;
                } else {
                    mfs->chunk_free_list = tmp->next;
                }
                tmp->next = NULL;

                if (byte_buffer->head == NULL) {
                    byte_buffer->head = tmp;
                } else {
                    byte_buffer->tail->next = tmp;
                }
                byte_buffer->tail = tmp;
                byte_buffer->tail_used = 0;

                rel_off = 0;

                int cpy = MIN(BYTE_CHUNK_SIZE, len - copied);
                assert(cpy > 0);

                memcpy(tmp->data, src + copied, cpy);
                copied += cpy;
                chunk = tmp;
                rel_off += cpy;

                byte_buffer->tail_used = cpy;

            } else if (rel_off == byte_buffer->tail_used) {

                assert(chunk);

                int cpy = MIN(BYTE_CHUNK_SIZE - byte_buffer->tail_used, len - copied);
                assert(cpy > 0);

                memcpy(chunk->data + byte_buffer->tail_used, src + copied, cpy);

                copied += cpy;
                rel_off += cpy;
                byte_buffer->tail_used += cpy;

            } else {

                assert(rel_off < byte_buffer->tail_used);

                assert(chunk);

                int cpy = MIN(byte_buffer->tail_used - rel_off, len - copied);
                assert(cpy > 0);

                memcpy(chunk->data + rel_off, src + copied, cpy);
                copied += cpy;
                rel_off += cpy;
            }

        } else {

            assert(chunk);

            int cpy = MIN(BYTE_CHUNK_SIZE - rel_off, len - copied);
            assert(cpy > 0);

            memcpy(chunk->data + rel_off, src + copied, cpy);
            copied += cpy;
            chunk = chunk->next;
            rel_off = 0;
        }
    }

    return 0;
}

static int parse_path(char *src, int len, Slice *buf, int cap)
{
    int cur = 0;
    int ret = 0;

    if (len > 0 && src[0] == '/')
        cur++;

    for (;;) {

        int off = cur;
        while (cur < len && src[cur] != '/')
            cur++;
        Slice s = { src + off, cur - off };

        if (s.len > 0) {
            if (ret == cap)
                return -1; // TODO: proper error code
            buf[ret++] = s;
        }

        if (cur == len)
            break;
        assert(src[cur] == '/');
        cur++;
    }

    return ret;
}

static int resolve_path(MockFS *mfs, Slice *comps, int num_comps,
    MockFS_Entity **stack, int cap)
{
    int ret = 0;
    stack[ret++] = mfs->root;

    for (int i = 0; i < num_comps; i++) {

        if (!stack[ret-1]->is_dir)
            return MOCKFS_ERRNO_NOTDIR;

        if (slice_eq(comps[i], S(".."))) {
            ret--;
            continue;
        }

        if (slice_eq(comps[i], S(".")))
            continue;

        MockFS_Entity *child = stack[ret-1]->head_child;
        while (child) {
            if (slice_eq(comps[i], (Slice) { child->name, child->name_len }))
                break;
            child = child->next;
        }

        if (child == NULL)
            return MOCKFS_ERRNO_NOENT;

        if (ret == cap)
            return -1; // TODO: return proper error code
        stack[ret++] = child;
    }

    return ret;
}

static int entity_init(MockFS_Entity *entity, Slice name, bool is_dir)
{
    entity->parent = NULL;
    entity->prev = NULL;
    entity->next = NULL;
    entity->is_dir = is_dir;
    entity->refcount = 0;
    entity->head_child = NULL;
    entity->tail_child = NULL;

    if (name.len > (int) sizeof(entity->name))
        return -1; // TODO: proper error code
    memcpy(entity->name, name.ptr, name.len);
    entity->name_len = name.len;

    return 0;
}

int mockfs_init(MockFS **pmfs, char *mem, int len)
{
    int off = -(unsigned long long) mem & (_Alignof(MockFS)-1);
    if (off + sizeof(MockFS) > (unsigned long long)len)
        return MOCKFS_ERRNO_NOMEM;
    MockFS *mfs = (MockFS *)(mem + off);

    mfs->mem = mem;
    mfs->len = len;
    mfs->off = off + sizeof(MockFS);
    mfs->root = NULL;
    mfs->entity_free_list = NULL;
    mfs->chunk_free_list = NULL;

    MockFS_Entity *entity = alloc(mfs, sizeof(MockFS_Entity), _Alignof(MockFS_Entity));
    if (entity == NULL)
        return MOCKFS_ERRNO_NOMEM;
    entity_init(entity, (Slice) { "", 0 }, true);
    mfs->root = entity;

    *pmfs = mfs;
    return 0;
}

void mockfs_free(MockFS *mfs)
{
    (void) mfs;
}

static bool find_child(MockFS_Entity *entity, Slice child_name)
{
    assert(entity->is_dir);
    MockFS_Entity *child = entity->head_child;
    while (child) {
        if (slice_eq(child_name, (Slice) { child->name, child->name_len }))
            return true;
        child = child->next;
    }
    return false;
}

static int create_entity(MockFS *mfs, MockFS_Entity *parent, Slice name, bool is_dir)
{
    MockFS_Entity *entity = mfs->entity_free_list;
    if (entity == NULL) {
        entity = alloc(mfs, sizeof(MockFS_Entity), _Alignof(MockFS_Entity));
        if (entity == NULL)
            return MOCKFS_ERRNO_NOMEM;
    } else {
        mfs->entity_free_list = entity->next;
    }
    entity->next = NULL;

    int ret = entity_init(entity, name, is_dir);
    if (ret < 0) {
        entity->next = mfs->entity_free_list;
        mfs->entity_free_list = entity;
        return ret;
    }

    // Initialize file-specific fields
    byte_buffer_init(&entity->byte_buffer);

    // Link to parent directory
    entity->parent = parent;
    entity->next = NULL;
    entity->prev = parent->tail_child;

    if (parent->tail_child) {
        parent->tail_child->next = entity;
    } else {
        parent->head_child = entity;
    }
    parent->tail_child = entity;

    return 0;
}

int mockfs_open(MockFS *mfs, char *path, int path_len, int flags, MockFS_OpenFile *open_file)
{
    Slice comps[MOCKFS_COMP_LIMIT];
    int ret = parse_path(path, path_len, comps, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    int num_comps = ret;

    MockFS_Entity *stack[MOCKFS_COMP_LIMIT];
    bool file_was_created = false;
    ret = resolve_path(mfs, comps, num_comps, stack, MOCKFS_COMP_LIMIT);
    if (ret < 0) {
        // If file doesn't exist AND O_CREAT is specified, try to create it
        if (ret == MOCKFS_ERRNO_NOENT && (flags & MOCKFS_O_CREAT)) {
            // Resolve parent directory
            ret = resolve_path(mfs, comps, num_comps-1, stack, MOCKFS_COMP_LIMIT);
            if (ret < 0)
                return ret;
            assert(ret > 0);
            MockFS_Entity *parent = stack[ret-1];

            // Path ending with '/' implies directory, but you can't create
            // a directory with open() - that's what mkdir() is for
            if (path_len > 1 && path[path_len-1] == '/') {
                return MOCKFS_ERRNO_ISDIR;
            }

            // Create the file
            ret = create_entity(mfs, parent, comps[num_comps-1], false);
            if (ret < 0)
                return ret;

            file_was_created = true;

            // Retry full path resolution (now should succeed)
            ret = resolve_path(mfs, comps, num_comps, stack, MOCKFS_COMP_LIMIT);
            assert(ret > 0);
        } else {
            return ret;
        }
    }
    assert(ret > 0);

    // Check for trailing slash (but "/" alone is not a "trailing slash" case)
    bool has_trailing_slash = (path_len > 1 && path[path_len-1] == '/');

    if ((flags & MOCKFS_O_CREAT) && has_trailing_slash)
        return MOCKFS_ERRNO_ISDIR;

    // O_EXCL check: if file already existed and O_EXCL is set, fail
    if ((flags & MOCKFS_O_EXCL) && (flags & MOCKFS_O_CREAT) && !file_was_created)
        return MOCKFS_ERRNO_EXIST;

    if (stack[ret-1]->is_dir)
        return MOCKFS_ERRNO_ISDIR;

    if (has_trailing_slash) {
        // If target is not a directory, return ENOTDIR
        if (!stack[ret-1]->is_dir)
            return MOCKFS_ERRNO_NOTDIR;
    }

    // O_TRUNC: truncate file to zero length if opened for writing
    if ((flags & MOCKFS_O_TRUNC) && (flags & (MOCKFS_O_WRONLY | MOCKFS_O_RDWR))) {
        byte_buffer_free(&stack[ret-1]->byte_buffer, &mfs->chunk_free_list);
        byte_buffer_init(&stack[ret-1]->byte_buffer);
    }

    open_file->mfs = mfs;
    open_file->entity = stack[ret-1];
    open_file->offset = 0;
    open_file->flags = flags;
    open_file->entity->refcount++;
    return 0;
}

int mockfs_open_dir(MockFS *mfs, char *path, int path_len, MockFS_OpenDir *open_dir)
{
    Slice comps[MOCKFS_COMP_LIMIT];
    int ret = parse_path(path, path_len, comps, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    int num_comps = ret;

    MockFS_Entity *stack[MOCKFS_COMP_LIMIT];
    ret = resolve_path(mfs, comps, num_comps, stack, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    assert(ret > 0);

    if (!stack[ret-1]->is_dir)
        return MOCKFS_ERRNO_NOTDIR;

    open_dir->mfs = mfs;
    open_dir->entity = stack[ret-1];
    open_dir->child = stack[ret-1]->head_child;
    open_dir->idx = 0;
    return 0;
}

int mockfs_file_size(MockFS_OpenFile *open_file)
{
    return byte_buffer_size(&open_file->entity->byte_buffer);
}

void mockfs_close_file(MockFS_OpenFile *open_file)
{
    MockFS_Entity *entity = open_file->entity;
    entity->refcount--;

    // If refcount drops to 0 and entity was unlinked (removed while open),
    // now we can actually free it
    if (entity->refcount == 0 && entity->parent == NULL) {
        // Free the byte buffer chunks
        byte_buffer_free(&entity->byte_buffer, &open_file->mfs->chunk_free_list);

        // Add entity to free list
        entity->next = open_file->mfs->entity_free_list;
        open_file->mfs->entity_free_list = entity;
    }
}

void mockfs_close_dir(MockFS_OpenDir *open_dir)
{
    (void) open_dir;
}

int mockfs_read(MockFS_OpenFile *open_file, char *dst, int len)
{
    if (open_file->flags & MOCKFS_O_WRONLY) {
        return MOCKFS_ERRNO_BADF;
    }

    int copied = byte_buffer_read(&open_file->entity->byte_buffer, open_file->offset, dst, len);
    open_file->offset += copied;
    return copied;
}

int mockfs_write(MockFS_OpenFile *open_file, char *src, int len)
{
    if (!(open_file->flags & (MOCKFS_O_WRONLY | MOCKFS_O_RDWR))) {
        return MOCKFS_ERRNO_BADF;
    }

    if ((open_file->flags & MOCKFS_O_WRONLY) && (open_file->flags & MOCKFS_O_RDWR)) {
        return MOCKFS_ERRNO_BADF;
    }

    // If O_APPEND is set, seek to end before writing
    if (open_file->flags & MOCKFS_O_APPEND) {
        open_file->offset = byte_buffer_size(&open_file->entity->byte_buffer);
    }

    int ret = byte_buffer_write(&open_file->entity->byte_buffer, open_file->offset, src, len, open_file->mfs);
    if (ret < 0)
        return ret;

    open_file->offset += len;
    return len;
}

int mockfs_read_dir(MockFS_OpenDir *open_dir, MockFS_Dirent *dirent)
{
    if (open_dir->idx == 0) {
        if (sizeof(dirent->name) < 1)
            return -1; // TODO: proper error code
        dirent->name[0] = '.';
        dirent->name_len = 1;
        dirent->is_dir = true;
        open_dir->idx++;
        return 0;
    }

    if (open_dir->idx == 1) {
        if (sizeof(dirent->name) < 2)
            return -1; // TODO: proper error code
        dirent->name[0] = '.';
        dirent->name[1] = '.';
        dirent->name_len = 2;
        dirent->is_dir = true;
        open_dir->idx++;
        return 0;
    }

    if (open_dir->child == NULL)
        return MOCKFS_ERRNO_NOENT;

    memcpy(dirent->name, open_dir->child->name, open_dir->child->name_len);
    dirent->name_len = open_dir->child->name_len;
    dirent->is_dir = open_dir->child->is_dir;

    open_dir->child = open_dir->child->next;
    open_dir->idx++;
    return 0;
}

int mockfs_sync(MockFS_OpenFile *open_file)
{
    // TODO
    (void) open_file;
    return 0;
}

int mockfs_lseek(MockFS_OpenFile *open_file, int offset, int whence)
{
    int new_offset;

    switch (whence) {
        case MOCKFS_SEEK_SET:
            new_offset = offset;
            break;
        case MOCKFS_SEEK_CUR:
            new_offset = open_file->offset + offset;
            break;
        case MOCKFS_SEEK_END:
            new_offset = byte_buffer_size(&open_file->entity->byte_buffer) + offset;
            break;
        default:
            return MOCKFS_ERRNO_INVAL;
    }

    if (new_offset < 0)
        return MOCKFS_ERRNO_INVAL;

    open_file->offset = new_offset;
    return new_offset;
}

static void byte_buffer_truncate(ByteBuffer *byte_buffer, int new_size, ByteChunk **free_list)
{
    if (new_size == 0) {
        byte_buffer_free(byte_buffer, free_list);
        byte_buffer_init(byte_buffer);
        return;
    }

    // Walk through chunks to find the one containing the new end
    int remaining = new_size;
    ByteChunk *chunk = byte_buffer->head;
    while (chunk) {
        int chunk_used = (chunk->next ? BYTE_CHUNK_SIZE : byte_buffer->tail_used);
        if (remaining <= chunk_used) {
            // This chunk becomes the new tail
            // Free all subsequent chunks
            ByteChunk *to_free = chunk->next;
            if (to_free) {
                // Find end of chain to free
                ByteChunk *last = to_free;
                while (last->next)
                    last = last->next;
                last->next = *free_list;
                *free_list = to_free;
            }
            chunk->next = NULL;
            byte_buffer->tail = chunk;
            byte_buffer->tail_used = remaining;
            return;
        }
        remaining -= BYTE_CHUNK_SIZE;
        chunk = chunk->next;
    }
}

int mockfs_ftruncate(MockFS_OpenFile *open_file, int new_size)
{
    if (new_size < 0)
        return MOCKFS_ERRNO_INVAL;

    if (!(open_file->flags & (MOCKFS_O_WRONLY | MOCKFS_O_RDWR)))
        return MOCKFS_ERRNO_BADF;

    ByteBuffer *bb = &open_file->entity->byte_buffer;
    int current_size = byte_buffer_size(bb);

    if (new_size < current_size) {
        byte_buffer_truncate(bb, new_size, &open_file->mfs->chunk_free_list);
    } else if (new_size > current_size) {
        int ret = byte_buffer_extend(bb, new_size, open_file->mfs);
        if (ret < 0)
            return ret;
    }

    return 0;
}

static int remove_inner(MockFS *mfs, MockFS_Entity *entity, bool recursive)
{
    if (entity->parent == NULL)
        return MOCKFS_ERRNO_BUSY;

    if (entity->is_dir) {
        // Remove children
        if (entity->head_child) {
            if (!recursive)
                return MOCKFS_ERRNO_NOTEMPTY;
            MockFS_Entity *child = entity->head_child;
            while (child) {
                MockFS_Entity *next = child->next;
                remove_inner(mfs, child, true);
                child = next;
            }
        }
    }

    // Unlink entity node from parent
    if (entity->prev) {
        entity->prev->next = entity->next;
    } else {
        entity->parent->head_child = entity->next;
    }

    if (entity->next) {
        entity->next->prev = entity->prev;
    } else {
        entity->parent->tail_child = entity->prev;
    }

    // Mark as unlinked
    entity->parent = NULL;

    // Only fully free the entity if no open handles
    if (entity->refcount == 0) {
        if (!entity->is_dir) {
            // Append chunks to the free list
            byte_buffer_free(&entity->byte_buffer, &mfs->chunk_free_list);
        }

        // Append entity to the free list
        entity->next = mfs->entity_free_list;
        mfs->entity_free_list = entity;
    }

    return 0;
}

int mockfs_remove(MockFS *mfs, char *path, int path_len, bool recursive)
{
    Slice comps[MOCKFS_COMP_LIMIT];
    int ret = parse_path(path, path_len, comps, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    int num_comps = ret;

    if (num_comps > 0) {
        if (slice_eq(comps[num_comps-1], S(".")))
            return MOCKFS_ERRNO_INVAL;

        if (slice_eq(comps[num_comps-1], S("..")))
            return MOCKFS_ERRNO_INVAL;
    }

    MockFS_Entity *stack[MOCKFS_COMP_LIMIT];
    ret = resolve_path(mfs, comps, num_comps, stack, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    assert(ret > 0);

    if (path_len > 0 && path[path_len-1] == '/') {
        if (!stack[ret-1]->is_dir)
            return MOCKFS_ERRNO_NOTDIR;
    }

    return remove_inner(mfs, stack[ret-1], recursive);
}

int mockfs_mkdir(MockFS *mfs, char *path, int path_len)
{
    Slice comps[MOCKFS_COMP_LIMIT];
    int ret = parse_path(path, path_len, comps, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    if (ret == 0)
        return MOCKFS_ERRNO_EXIST;
    int num_comps = ret;

    if (slice_eq(comps[num_comps-1], S(".")))
        return MOCKFS_ERRNO_EXIST;

    if (slice_eq(comps[num_comps-1], S("..")))
        return MOCKFS_ERRNO_INVAL;

    MockFS_Entity *stack[MOCKFS_COMP_LIMIT];
    ret = resolve_path(mfs, comps, num_comps-1, stack, MOCKFS_COMP_LIMIT);
    if (ret < 0)
        return ret;
    assert(ret > 0);
    MockFS_Entity *parent = stack[ret-1];

    if (!parent->is_dir)
        return MOCKFS_ERRNO_NOTDIR;

    if (find_child(parent, comps[num_comps-1]))
        return MOCKFS_ERRNO_EXIST;

    MockFS_Entity *entity = mfs->entity_free_list;
    if (entity == NULL) {
        entity = alloc(mfs, sizeof(MockFS_Entity), _Alignof(MockFS_Entity));
        if (entity == NULL)
            return MOCKFS_ERRNO_NOMEM;
    } else {
        mfs->entity_free_list = entity->next;
    }
    entity->next = NULL;

    ret = entity_init(entity, comps[num_comps-1], true);
    if (ret < 0) {
        entity->next = mfs->entity_free_list;
        mfs->entity_free_list = entity;
        return ret;
    }

    // Initialize byte_buffer to clear all 24 bytes of the union, including
    // byte_buffer.tail (bytes 16-23) which would otherwise retain garbage
    // when reusing an entity from the free list
    byte_buffer_init(&entity->byte_buffer);

    entity->parent = parent;
    entity->next = NULL;
    entity->prev = parent->tail_child;

    if (parent->tail_child) {
        parent->tail_child->next = entity;
    } else {
        parent->head_child = entity;
    }
    parent->tail_child = entity;
    return 0;
}

int mockfs_rename(MockFS *mfs, char *old_path, int old_path_len, char *new_path, int new_path_len)
{
    Slice new_comps[MOCKFS_COMP_LIMIT];
    Slice old_comps[MOCKFS_COMP_LIMIT];
    int num_new_comps = parse_path(new_path, new_path_len, new_comps, MOCKFS_COMP_LIMIT);
    int num_old_comps = parse_path(old_path, old_path_len, old_comps, MOCKFS_COMP_LIMIT);

    if (num_new_comps < 0) return num_new_comps;
    if (num_old_comps < 0) return num_old_comps;

    MockFS_Entity *new_stack[MOCKFS_COMP_LIMIT];
    MockFS_Entity *old_stack[MOCKFS_COMP_LIMIT];
    int num_new_stack = resolve_path(mfs, new_comps, num_new_comps-1, new_stack, MOCKFS_COMP_LIMIT);
    int num_old_stack = resolve_path(mfs, old_comps, num_old_comps, old_stack, MOCKFS_COMP_LIMIT);

    if (num_new_stack == MOCKFS_ERRNO_NOTDIR ||
        num_old_stack == MOCKFS_ERRNO_NOTDIR)
        return MOCKFS_ERRNO_NOTDIR;

    if (num_new_stack < 0)
        return num_new_stack;
    assert(num_new_stack > 0);

    if (!new_stack[num_new_stack-1]->is_dir)
        return MOCKFS_ERRNO_NOTDIR;

    if (num_old_stack < 0)
        return num_old_stack;

    assert(num_old_stack > 0);
    MockFS_Entity *source = old_stack[num_old_stack-1];

    if (source->parent == NULL)
        return MOCKFS_ERRNO_BUSY;

    if (old_path_len > 0 && old_path[old_path_len-1] == '/') {
        if (!source->is_dir)
            return MOCKFS_ERRNO_NOTDIR;
    }

    if (new_path_len > 0 && new_path[new_path_len-1] == '/') {
        if (!source->is_dir)
            return MOCKFS_ERRNO_NOTDIR;
    }

    if (num_new_comps == 0)
        return MOCKFS_ERRNO_BUSY;

    // Make sure the entity isn't being moved inside itself,
    // by checking that the last element of the old stack isn't
    // in the new stack.
    for (int i = 0; i < num_new_stack; i++)
        if (new_stack[i] == source)
            return MOCKFS_ERRNO_INVAL;

    // Check if new path exists
    Slice new_name = new_comps[num_new_comps-1];
    MockFS_Entity *target = NULL;
    MockFS_Entity *child = new_stack[num_new_stack-1]->head_child;
    while (child) {
        if (slice_eq(new_name, (Slice) { child->name, child->name_len })) {
            target = child;
            break;
        }
        child = child->next;
    }

    if (target) {

        if (target == source)
            return 0;

        if (target->is_dir) {

            for (int i = 0; i < num_old_stack; i++)
                if (old_stack[i] == target)
                    return MOCKFS_ERRNO_NOTEMPTY;

            if (!source->is_dir)
                return MOCKFS_ERRNO_ISDIR;

            if (target->head_child)
                return MOCKFS_ERRNO_NOTEMPTY;

        } else {
            if (source->is_dir)
                return MOCKFS_ERRNO_NOTDIR;
        }

        remove_inner(mfs, target, false);
    }

    // Unlink source from old parent
    if (source->prev) {
        source->prev->next = source->next;
    } else {
        source->parent->head_child = source->next;
    }

    if (source->next) {
        source->next->prev = source->prev;
    } else {
        source->parent->tail_child = source->prev;
    }

    // Update source's name
    if (new_name.len > (int) sizeof(source->name))
        return MOCKFS_ERRNO_INVAL;  // Name too long
    memcpy(source->name, new_name.ptr, new_name.len);
    source->name_len = new_name.len;

    // Link source to new parent
    source->parent = new_stack[num_new_stack-1];
    source->next = NULL;
    source->prev = new_stack[num_new_stack-1]->tail_child;

    if (new_stack[num_new_stack-1]->tail_child) {
        new_stack[num_new_stack-1]->tail_child->next = source;
    } else {
        new_stack[num_new_stack-1]->head_child = source;
    }
    new_stack[num_new_stack-1]->tail_child = source;

    return 0;
}
