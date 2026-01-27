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

    client->state = TEST_CLIENT_STATE_0;
    client->tick  = 0;

    printf("Client set up (remote=%s:%d)\n", addr, port);

    *timeout = -1;
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

    // This must be static as write operations will refer to this data
    // after the function has returned
    static char msg[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
        "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
        "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
        "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
        "in reprehenderit in voluptate velit esse cillum dolore eu fugiat "
        "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
        "sunt in culpa qui officia deserunt mollit anim id est laborum.";

    ToastyString file_path = TOASTY_STR("some_file.txt");

    switch (client->state) {
        int ret;
        ToastyResult result;
    case TEST_CLIENT_STATE_0:
        if (client->tick < 10) {
            *timeout = 0;
            client->tick++;
            return 0;
        }
        client->handle = toasty_begin_create_file(client->toasty, file_path, 128);
        if (client->handle == TOASTY_INVALID) {
            assert(0); // TODO
        }
        printf("Create started\n");
        client->state = TEST_CLIENT_STATE_1;
        break;
    case TEST_CLIENT_STATE_1:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) {
            assert(0); // TODO
        }
        if (ret == 1) {
            break;
        }
        printf("Create completed\n");
        assert(ret == 0);
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            assert(0); // TODO
        }
        client->handle = toasty_begin_write(client->toasty, file_path, 0, msg, sizeof(msg)-1, TOASTY_VERSION_TAG_EMPTY, 0);
        if (client->handle == TOASTY_INVALID) {
            assert(0); // TODO
        }
        printf("Write started\n");
        client->state = TEST_CLIENT_STATE_2;
        break;
    case TEST_CLIENT_STATE_2:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) {
            assert(0); // TODO
        }
        if (ret == 1) {
            break;
        }
        printf("Write completed\n");
        assert(ret == 0);
        if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
            assert(0); // TODO
        }
        client->handle = toasty_begin_read(client->toasty, file_path, 0, client->buf, sizeof(client->buf), TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            assert(0); // TODO
        }
        printf("Read started\n");
        client->state = TEST_CLIENT_STATE_3;
        break;
    case TEST_CLIENT_STATE_3:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) {
            assert(0); // TODO
        }
        if (ret == 1) {
            break;
        }
        printf("Read completed\n");
        assert(ret == 0);
        if (result.type != TOASTY_RESULT_READ_SUCCESS) {
            assert(0); // TODO
        }
        if (result.bytes_read != sizeof(msg)-1) {
            assert(0); // TODO
        }
        if (memcmp(client->buf, msg, sizeof(msg)-1)) {
            assert(0); // TODO
        }
        printf("Test PASSED: Read data matches written data\n");
        exit(0); // Test completed successfully
    }

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