#ifdef BUILD_SERVER

#include <time.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#define POLL WSAPoll
#else
#include <poll.h>
#define POLL poll
#endif

#include "crash_logger.h"
#include "chunk_server.h"
#include "metadata_server.h"

int metadata_server_main(int argc, char **argv)
{
    {
        time_t now = time(NULL);
        struct tm unpacked_now;
#ifdef _WIN32
        if (gmtime_s(&unpacked_now, &now) != 0)
            return -1;
#else
        if (gmtime_r(&now, &unpacked_now) == NULL)
            return -1;
#endif

        char time[sizeof("YYYYMMDDthhmmssz")];
        int ret = strftime(time, sizeof(time),
            "%Y%m%dT%H%M%SZ", &unpacked_now);
        if (ret != sizeof(time)-1)
            return -1;

        char path[1<<10];
        ret = snprintf(path, sizeof(path), "crash_%s_MS_%d.txt", time, getpid());
        if (ret < 0 || ret >= (int) sizeof(path)) {
            return -1;
        }
        int path_len = ret;

        crash_logger_init(path, path_len);
    }

    void *contexts[TCP_POLL_CAPACITY];
    struct pollfd polled[TCP_POLL_CAPACITY];
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
    crash_logger_free();
    return 0;
}

int chunk_server_main(int argc, char **argv)
{
    {
        time_t now = time(NULL);
        struct tm unpacked_now;
#ifdef _WIN32
        if (gmtime_s(&unpacked_now, &now) != 0)
            return -1;
#else
        if (gmtime_r(&now, &unpacked_now) == NULL)
            return -1;
#endif

        char time[sizeof("YYYYMMDDthhmmssz")];
        int ret = strftime(time, sizeof(time),
            "%Y%m%dT%H%M%SZ", &unpacked_now);
        if (ret != sizeof(time)-1)
            return -1;

        char path[1<<10];
        ret = snprintf(path, sizeof(path), "crash_%s_CS_%d.txt", time, getpid());
        if (ret < 0 || ret >= (int) sizeof(path)) {
            return -1;
        }
        int path_len = ret;

        crash_logger_init(path, path_len);
    }

    void *contexts[TCP_POLL_CAPACITY];
    struct pollfd polled[TCP_POLL_CAPACITY];
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
    crash_logger_free();
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
