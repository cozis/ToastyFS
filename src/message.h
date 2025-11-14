#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <stdio.h>
#include <stdbool.h>

#include "byte_queue.h"

enum {

    // Client -> Metadata server
    MESSAGE_TYPE_CREATE,
    MESSAGE_TYPE_DELETE,
    MESSAGE_TYPE_LIST,
    MESSAGE_TYPE_READ,
    MESSAGE_TYPE_WRITE,

    // Client -> Chunk server
    MESSAGE_TYPE_CREATE_CHUNK,
    MESSAGE_TYPE_UPLOAD_CHUNK,
    MESSAGE_TYPE_DOWNLOAD_CHUNK,

    // Metadata server -> Client
    MESSAGE_TYPE_CREATE_ERROR,
    MESSAGE_TYPE_CREATE_SUCCESS,
    MESSAGE_TYPE_DELETE_ERROR,
    MESSAGE_TYPE_DELETE_SUCCESS,
    MESSAGE_TYPE_LIST_ERROR,
    MESSAGE_TYPE_LIST_SUCCESS,
    MESSAGE_TYPE_READ_ERROR,
    MESSAGE_TYPE_READ_SUCCESS,
    MESSAGE_TYPE_WRITE_ERROR,
    MESSAGE_TYPE_WRITE_SUCCESS,

    // Metadata server -> Chunk server
    MESSAGE_TYPE_AUTH_RESPONSE,
    MESSAGE_TYPE_SYNC_2,
    MESSAGE_TYPE_SYNC_4,
    MESSAGE_TYPE_DOWNLOAD_LOCATIONS,

    // Chunk server -> Metadata server
    MESSAGE_TYPE_AUTH,
    MESSAGE_TYPE_SYNC,
    MESSAGE_TYPE_SYNC_3,

    // Chunk server -> Client
    MESSAGE_TYPE_CREATE_CHUNK_ERROR,
    MESSAGE_TYPE_CREATE_CHUNK_SUCCESS,
    MESSAGE_TYPE_UPLOAD_CHUNK_ERROR,
    MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS,
    MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR,
    MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS,
};

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

int  message_peek(ByteView msg, uint16_t *type, uint32_t *len);
void message_dump(FILE *stream, ByteView msg);

#endif // MESSAGE_INCLUDED
