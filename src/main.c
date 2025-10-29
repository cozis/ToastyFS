#ifdef BUILD_SERVER

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
            ret = metadata_server_step(&state);
            if (ret)
                return ret;
        }

        ret = metadata_server_free(&state);

    } else {

        ChunkServer state;
        ret = chunk_server_init(&state, argc, argv);
        if (ret)
            return ret;

        for (;;) {
            ret = chunk_server_step(&state);
            if (ret)
                return ret;
        }

        ret = chunk_server_free(&state);
    }
    return ret;
}

#endif // BUILD_SERVER
