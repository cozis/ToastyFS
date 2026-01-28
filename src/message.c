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

bool binary_read_addr_ipv4(BinaryReader *reader, Address *addr)
{
    if (!binary_read(reader, &addr->ipv4, sizeof(IPv4)))     return false;
    if (!binary_read(reader, &addr->port, sizeof(uint16_t))) return false;
    addr->is_ipv4 = true;
    return true;
}

bool binary_read_addr_ipv6(BinaryReader *reader, Address *addr)
{
    if (!binary_read(reader, &addr->ipv6, sizeof(IPv6)))     return false;
    if (!binary_read(reader, &addr->port, sizeof(uint16_t))) return false;
    addr->is_ipv4 = false;
    return true;
}

int binary_read_addr_list(BinaryReader *reader, Address *addrs, int max_addrs)
{
    uint32_t num_ipv4;
    uint32_t num_ipv6;
    if (!binary_read(reader, &num_ipv4, sizeof(num_ipv4)))
        return -1;
    if (!binary_read(reader, &num_ipv6, sizeof(num_ipv6)))
        return -1;
    int num = 0;
    for (uint32_t i = 0; i < num_ipv4; i++) {
        Address tmp;
        if (!binary_read_addr_ipv4(reader, &tmp))
            return -1;
        if (num < max_addrs)
            addrs[num++] = tmp;
    }
    for (uint32_t i = 0; i < num_ipv6; i++) {
        Address tmp;
        if (!binary_read_addr_ipv6(reader, &tmp))
            return -1;
        if (num < max_addrs)
            addrs[num++] = tmp;
    }
    return num;
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

static char *message_type_to_str(uint16_t type)
{
    switch (type) {
        // Client -> Metadata server
        case MESSAGE_TYPE_CREATE: return "CREATE";
        case MESSAGE_TYPE_DELETE: return "DELETE";
        case MESSAGE_TYPE_LIST: return "LIST";
        case MESSAGE_TYPE_READ: return "READ";
        case MESSAGE_TYPE_WRITE: return "WRITE";

        // Client -> Chunk server
        case MESSAGE_TYPE_CREATE_CHUNK: return "CREATE_CHUNK";
        case MESSAGE_TYPE_UPLOAD_CHUNK: return "UPLOAD_CHUNK";
        case MESSAGE_TYPE_DOWNLOAD_CHUNK: return "DOWNLOAD_CHUNK";

        // Metadata server -> Client
        case MESSAGE_TYPE_CREATE_ERROR: return "CREATE_ERROR";
        case MESSAGE_TYPE_CREATE_SUCCESS: return "CREATE_SUCCESS";
        case MESSAGE_TYPE_DELETE_ERROR: return "DELETE_ERROR";
        case MESSAGE_TYPE_DELETE_SUCCESS: return "DELETE_SUCCESS";
        case MESSAGE_TYPE_LIST_ERROR: return "LIST_ERROR";
        case MESSAGE_TYPE_LIST_SUCCESS: return "LIST_SUCCESS";
        case MESSAGE_TYPE_READ_ERROR: return "READ_ERROR";
        case MESSAGE_TYPE_READ_SUCCESS: return "READ_SUCCESS";
        case MESSAGE_TYPE_WRITE_ERROR: return "WRITE_ERROR";
        case MESSAGE_TYPE_WRITE_SUCCESS: return "WRITE_SUCCESS";

        // Metadata server -> Chunk server
        case MESSAGE_TYPE_SYNC_2: return "SYNC_2";
        case MESSAGE_TYPE_SYNC_4: return "SYNC_4";
        case MESSAGE_TYPE_DOWNLOAD_LOCATIONS: return "DOWNLOAD_LOCATIONS";

        // Chunk server -> Metadata server
        case MESSAGE_TYPE_AUTH: return "AUTH";
        case MESSAGE_TYPE_SYNC: return "SYNC";
        case MESSAGE_TYPE_SYNC_3: return "SYNC_3";

        // Chunk server -> Client
        case MESSAGE_TYPE_CREATE_CHUNK_ERROR: return "CREATE_CHUNK_ERROR";
        case MESSAGE_TYPE_CREATE_CHUNK_SUCCESS: return "CREATE_CHUNK_SUCCESS";
        case MESSAGE_TYPE_UPLOAD_CHUNK_ERROR: return "UPLOAD_CHUNK_ERROR";
        case MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS: return "UPLOAD_CHUNK_SUCCESS";
        case MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR: return "DOWNLOAD_CHUNK_ERROR";
        case MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS: return "DOWNLOAD_CHUNK_SUCCESS";
    }

    return "???";
}

void message_dump(FILE *stream, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    fprintf(stream, "message:\n");

    fprintf(stream, "  header:\n");
    uint16_t version;
    if (!binary_read(&reader, &version, sizeof(version))) {
        fprintf(stream, "    (incomplete)\n");
        return;
    }
    fprintf(stream, "    version: %d\n", version);

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        fprintf(stream, "    (incomplete)\n");
        return;
    }
    fprintf(stream, "    type: %s\n", message_type_to_str(type));

    uint32_t length;
    if (!binary_read(&reader, &length, sizeof(length))) {
        fprintf(stream, "  (incomplete)\n");
        return;
    }
    fprintf(stream, "    length: %d\n", length);

    fprintf(stream, "  body:\n");
    switch (type) {
        // Client -> Metadata server

        case MESSAGE_TYPE_CREATE:
        {
            uint16_t path_len;
            if (!binary_read(&reader, &path_len, sizeof(path_len))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path_len: %d\n", path_len);

            char *path = (char*) reader.src + reader.cur;
            if (!binary_read(&reader, NULL, path_len)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path: %.*s\n", (int) path_len, path);

            uint8_t is_dir;
            if (!binary_read(&reader, &is_dir, sizeof(is_dir))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    is_dir: %s\n", is_dir ? "true" : "false");

            if (!is_dir) {
                uint32_t chunk_size;
                if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
                    fprintf(stream, "    (incomplete)\n");
                    return;
                }
                fprintf(stream, "    chunk_size: %d\n", chunk_size);
            }
        }
        break;

        case MESSAGE_TYPE_DELETE:
        {
            uint16_t path_len;
            if (!binary_read(&reader, &path_len, sizeof(path_len))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path_len: %d\n", path_len);

            char *path = (char*) reader.src + reader.cur;
            if (!binary_read(&reader, NULL, path_len)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path: %.*s\n", (int) path_len, path);
        }
        break;

        case MESSAGE_TYPE_LIST:
        {
            uint16_t path_len;
            if (!binary_read(&reader, &path_len, sizeof(path_len))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path_len: %d\n", path_len);

            char *path = (char*) reader.src + reader.cur;
            if (!binary_read(&reader, NULL, path_len)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path: %.*s\n", (int) path_len, path);
        }
        break;

        case MESSAGE_TYPE_READ:
        {
            uint16_t path_len;
            if (!binary_read(&reader, &path_len, sizeof(path_len))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path_len: %d\n", path_len);

            char *path = (char*) reader.src + reader.cur;
            if (!binary_read(&reader, NULL, path_len)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path: %.*s\n", (int) path_len, path);

            uint32_t offset;
            if (!binary_read(&reader, &offset, sizeof(offset))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    offset: %d\n", offset);

            uint32_t length;
            if (!binary_read(&reader, &length, sizeof(length))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    length: %d\n", length);
        }
        break;

        case MESSAGE_TYPE_WRITE:
        {
            uint16_t path_len;
            if (!binary_read(&reader, &path_len, sizeof(path_len))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path_len: %d\n", path_len);

            char *path = (char*) reader.src + reader.cur;
            if (!binary_read(&reader, NULL, path_len)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    path: %.*s\n", (int) path_len, path);

            uint32_t offset;
            if (!binary_read(&reader, &offset, sizeof(offset))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    offset: %d\n", offset);

            uint32_t length;
            if (!binary_read(&reader, &length, sizeof(length))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    length: %d\n", length);

            uint32_t num_chunks;
            if (!binary_read(&reader, &num_chunks, sizeof(num_chunks))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    num_chunks: %d\n", num_chunks);

            for (uint32_t i = 0; i < num_chunks; i++) {

                char hash_str[64];

                SHA256 old_hash;
                if (!binary_read(&reader, &old_hash, sizeof(old_hash))) {
                    fprintf(stream, "    (incomplete)\n");
                    return;
                }
                append_hex_as_str(hash_str, old_hash);
                fprintf(stream, "    old_hash: %.64s\n", hash_str);

                SHA256 new_hash;
                if (!binary_read(&reader, &new_hash, sizeof(new_hash))) {
                    fprintf(stream, "    (incomplete)\n");
                    return;
                }
                append_hex_as_str(hash_str, new_hash);
                fprintf(stream, "    new_hash: %.64s\n", hash_str);

                uint32_t num_locations;
                if (!binary_read(&reader, &num_locations, sizeof(num_locations))) {
                    fprintf(stream, "    (incomplete)\n");
                    return;
                }
                fprintf(stream, "    num_locations: %d\n", num_locations);

                for (uint32_t j = 0; j < num_locations; j++) {

                    uint8_t is_ipv4;
                    if (!binary_read(&reader, &is_ipv4, sizeof(is_ipv4))) {
                        fprintf(stream, "    (incomplete)\n");
                        return;
                    }
                    fprintf(stream, "    is_ipv4: %s (%d)\n", is_ipv4 ? "true" : "false", is_ipv4);

                    if (is_ipv4) {
                        IPv4 ipv4;
                        if (!binary_read(&reader, &ipv4, sizeof(ipv4))) {
                            fprintf(stream, "    (incomplete)\n");
                            return;
                        }
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ipv4, ip_str, sizeof(ip_str));
                        fprintf(stream, "    ipv4: %s\n", ip_str);
                    } else {
                        IPv6 ipv6;
                        if (!binary_read(&reader, &ipv6, sizeof(ipv6))) {
                            fprintf(stream, "    (incomplete)\n");
                            return;
                        }
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &ipv6, ip_str, sizeof(ip_str));
                        fprintf(stream, "    ipv6: %s\n", ip_str);
                    }

                    uint16_t port;
                    if (!binary_read(&reader, &port, sizeof(port))) {
                        fprintf(stream, "    (incomplete)\n");
                        return;
                    }
                    fprintf(stream, "    port: %d\n", port);
                }
            }
        }
        break;

        // Client -> Chunk server

        case MESSAGE_TYPE_CREATE_CHUNK:
        {
            uint32_t chunk_size;
            if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    chunk_size: %d\n", chunk_size);

            uint32_t offset;
            if (!binary_read(&reader, &offset, sizeof(offset))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    offset: %d\n", offset);

            uint32_t length;
            if (!binary_read(&reader, &length, sizeof(length))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    length: %d\n", length);

            if (!binary_read(&reader, NULL, length)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    data: (...)\n");
        }
        break;

        case MESSAGE_TYPE_UPLOAD_CHUNK:
        {
            SHA256 hash;
            if (!binary_read(&reader, &hash, sizeof(hash))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            char hash_str[64];
            append_hex_as_str(hash_str, hash);
            fprintf(stream, "    hash: %.64s\n", hash_str);

            uint32_t offset;
            if (!binary_read(&reader, &offset, sizeof(offset))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    offset: %d\n", offset);

            uint32_t length;
            if (!binary_read(&reader, &length, sizeof(length))) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    length: %d\n", length);

            if (!binary_read(&reader, NULL, length)) {
                fprintf(stream, "    (incomplete)\n");
                return;
            }
            fprintf(stream, "    data: (...)\n");
        }
        break;

        default:
        printf("    (TODO)\n");
        break;
    }

    if (binary_read(&reader, NULL, 1))
        fprintf(stream, "    (unexpected bytes)\n");
}
