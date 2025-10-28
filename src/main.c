#ifndef BUILD_LIBRARY

#include <string.h>

#include "chunk_server.h"
#include "metadata_server.h"

bool is_leader(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--leader") || !strcmp(argv[i], "-l"))
            return true;
    return false;
}

int main(int argc, char **argv)
{
    int ret;
    if (is_leader(argc, argv)) {

        MetadataServer state;
        ret = metadata_server_init(&state, argc, argv);
        if (ret)
            return ret;

        for (;;) {
            metadata_server_step(&state);
        }

        metadata_server_free(&state);

    } else {

        ChunkServer state;
        ret = chunk_server_init(&state, argc, argv);
        if (ret)
            return ret;

        for (;;) {
            chunk_server_step(&state);
        }

        chunk_server_free(&state);

    }
    return 0;
}

#endif // BUILD_LIBRARY
