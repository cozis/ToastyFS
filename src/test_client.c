#ifdef MAIN_TEST

#define QUAKEY_ENABLE_MOCKS
#include <quakey.h>
#include <assert.h>

#include "tcp.h"
#include "test_client.h"

// Helper function to parse address and port from command line
static bool parse_server_addr(int argc, char **argv, char **addr, uint16_t *port)
{
    // Default to metadata server
    *addr = "127.0.0.1";
    *port = 8080;

    for (int i = 0; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--server") || !strcmp(argv[i], "-s")) {
            *addr = argv[i + 1];
            if (i + 2 < argc) {

                errno = 0;
                char *end;
                long val = strtol(argv[i+2], &end, 10);

                if (end == argv[i+2] || *end != '\0' || errno == ERANGE)
                    break;

                if (val < 0 || val > UINT16_MAX)
                    break;

                *port = (uint16_t) val;
                return true;
            }
        }
    }
    return true;
}

int test_client_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    TestClient *client = state_;

    char *addr;
    uint16_t port;
    parse_server_addr(argc, argv, &addr, &port);

    client->toasty = toasty_connect((ToastyString) { addr, strlen(addr) }, port);
    if (client->toasty == NULL)
        return -1;

    printf("Client set up (remote=%s:%d)\n", addr, port);

    *timeout = 0;
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, *pnum);
    return 0;
}

static int random_in_range(int min, int max)
{
    uint64_t n = quakey_random();
    return min + n % (max - min + 1);
}

int test_client_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    TestClient *client = state_;

    // Process any pending events from the network and get new poll descriptors
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, *pnum);

    assert(0); // TODO

    *timeout = -1;
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, 0);
    return 0;
}

int test_client_free(void *state_)
{
    TestClient *client = state_;

    toasty_disconnect(client->toasty);
    return 0;
}

#endif // MAIN_TEST