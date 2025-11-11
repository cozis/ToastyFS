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
    int timeout = -1;
    MetadataServer state;
    num_polled = metadata_server_init(
        &state, argc, argv, contexts, polled, &timeout);
    if (num_polled < 0) return -1;
    for (;;) {
        POLL(polled, num_polled, timeout);

        timeout = -1;
        num_polled = metadata_server_step(
            &state, contexts, polled, num_polled, &timeout);
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
    int timeout = -1;
    ChunkServer state;
    num_polled = chunk_server_init(
        &state, argc, argv, contexts, polled, &timeout);
    if (num_polled < 0) return -1;
    for (;;) {

        POLL(polled, num_polled, timeout);

        timeout = -1;
        num_polled = chunk_server_step(
            &state, contexts, polled, num_polled, &timeout);
        if (num_polled < 0) return -1;
    }
    chunk_server_free(&state);
    return 0;
}

int main(int argc, char **argv)
{
    if (getargb(argc, argv, "--leader"))
        return metadata_server_main(argc, argv);
    else
        return chunk_server_main(argc, argv);
}

#endif
