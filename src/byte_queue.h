#ifndef BYTE_QUEUE_INCLUDED
#define BYTE_QUEUE_INCLUDED

#include <stddef.h>

#include "basic.h"

typedef struct {
    uint8_t *ptr;
    size_t   len;
} ByteView;

typedef struct {
    uint64_t curs;
    uint8_t* data;
    uint32_t head;
    uint32_t size;
    uint32_t used;
    uint32_t limit;
    uint8_t* read_target;
    uint32_t read_target_size;
    int flags;
} ByteQueue;

typedef uint64_t ByteQueueOffset;

enum {
    BYTE_QUEUE_ERROR = 1 << 0,
    BYTE_QUEUE_READ  = 1 << 1,
    BYTE_QUEUE_WRITE = 1 << 2,
};

void byte_queue_init(ByteQueue *queue, uint32_t limit);
void byte_queue_free(ByteQueue *queue);

int byte_queue_error(ByteQueue *queue);
int byte_queue_empty(ByteQueue *queue);
int byte_queue_full(ByteQueue *queue);

ByteView byte_queue_read_buf(ByteQueue *queue);
void     byte_queue_read_ack(ByteQueue *queue, uint32_t num);

ByteView byte_queue_write_buf(ByteQueue *queue);
void     byte_queue_write_ack(ByteQueue *queue, uint32_t num);
int      byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap);
void     byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len);

ByteQueueOffset byte_queue_offset(ByteQueue *queue);
void            byte_queue_patch(ByteQueue *queue, ByteQueueOffset off, void *src, uint32_t len);
uint32_t        byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off);
void            byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset);

#endif // BYTE_QUEUE_INCLUDED
