#ifdef BUILD_SERVER

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#define POLL WSAPoll
#else
#include <poll.h>
#define POLL poll
#endif

#include "chunk_server.h"
#include "metadata_server.h"

int metadata_server_main(int argc, char **argv)
{
    void *contexts[MAX_CONNS+1];
    struct pollfd polled[MAX_CONNS+1];
    int num_polled;
    MetadataServer state;
    num_polled = metadata_server_init(
        &state, argc, argv, contexts, polled);
    if (num_polled < 0) return -1;
    for (;;) {
        POLL(polled, num_polled, -1);
        num_polled = metadata_server_step(
            &state, contexts, polled, num_polled);
        if (num_polled < 0) return -1;
    }
    metadata_server_free(&state);
    return 0;
}

int chunk_server_main(int argc, char **argv)
{
    void *contexts[MAX_CONNS+1];
    struct pollfd polled[MAX_CONNS+1];
    int num_polled;
    ChunkServer state;
    num_polled = chunk_server_init(
        &state, argc, argv, contexts, polled);
    if (num_polled < 0) return -1;
    for (;;) {
        POLL(polled, num_polled, -1);
        num_polled = chunk_server_step(
            &state, contexts, polled, num_polled);
        if (num_polled < 0) return -1;
    }
    chunk_server_free(&state);
    return 0;
}

bool is_leader(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--leader") || !strcmp(argv[i], "-l"))
            return true;
    return false;
}

int main(int argc, char **argv)
{
    if (is_leader(argc, argv))
        return metadata_server_main(argc, argv);
    else
        return chunk_server_main(argc, argv);
}

#endif
