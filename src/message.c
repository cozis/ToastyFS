#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <stdint.h>
#include <quakey.h>

#include "message.h"

bool binary_read(BinaryReader *reader, void *dst, int len)
{
    if (reader->len - reader->cur < len)
        return false;
    if (dst)
        memcpy(dst, reader->src + reader->cur, len);
    reader->cur += len;
    return true;
}

void message_writer_init(MessageWriter *writer, ByteQueue *output, uint16_t type)
{
    uint16_t version = MESSAGE_VERSION;
    uint32_t dummy = 0; // Dummy value
    writer->output = output;
    writer->start  = byte_queue_offset(output);
    byte_queue_write(output, &version, sizeof(version));
    byte_queue_write(output, &type, sizeof(type));
    writer->patch = byte_queue_offset(output);
    byte_queue_write(output, &dummy, sizeof(dummy));
}

bool message_writer_free(MessageWriter *writer)
{
    uint32_t length = byte_queue_size_from_offset(writer->output, writer->start);
    byte_queue_patch(writer->output, writer->patch, &length, sizeof(length));
    if (byte_queue_error(writer->output)) // TODO: is it possible to restore the state of the queue to before the failure?
        return false;
    return true;
}

void message_write(MessageWriter *writer, void *mem, int len)
{
    byte_queue_write(writer->output, mem, len);
}

void message_write_u8(MessageWriter *writer, uint8_t value)
{
    message_write(writer, &value, (int) sizeof(value));
}

void message_write_u32(MessageWriter *writer, uint32_t value)
{
    message_write(writer, &value, (int) sizeof(value));
}

void message_write_hash(MessageWriter *writer, SHA256 value)
{
    message_write(writer, &value, (int) sizeof(value));
}

int message_peek(ByteView msg, uint16_t *type, uint32_t *len)
{
    if (msg.len < (int) sizeof(MessageHeader))
        return 0;

    MessageHeader header;
    memcpy(&header, msg.ptr, sizeof(header));

    // (We ignore endianess for now)

    if (header.version != MESSAGE_VERSION)
        return -1;

    if (header.length > msg.len)
        return 0;

    if (type) *type = header.type;
    if (len) *len = header.length;

    return 1;
}
