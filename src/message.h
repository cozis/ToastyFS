#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <stdint.h>
#include <quakey.h>

#include "basic.h"
#include "byte_queue.h"

#define MESSAGE_VERSION 1

typedef struct {
    uint8_t *src;
    int      len;
    int      cur;
} BinaryReader;

typedef struct {
    uint16_t version;
    uint16_t type;
    uint32_t length;
} MessageHeader;

typedef struct {
    ByteQueue *output;
    ByteQueueOffset start;
    ByteQueueOffset patch;
} MessageWriter;

bool binary_read(BinaryReader *reader, void *dst, int len);

void message_writer_init(MessageWriter *writer, ByteQueue *output, uint16_t type);
bool message_writer_free(MessageWriter *writer);
void message_write(MessageWriter *writer, void *mem, int len);
void message_write_u8(MessageWriter *writer, uint8_t value);
void message_write_u32(MessageWriter *writer, uint32_t value);
void message_write_hash(MessageWriter *writer, SHA256 value);

int  message_peek(ByteView msg, uint16_t *type, uint32_t *len);
void message_dump(FILE *stream, ByteView msg);

#endif // MESSAGE_INCLUDED
