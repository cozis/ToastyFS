#ifndef TEST_CLIENT_INCLUDED
#define TEST_CLIENT_INCLUDED

#include "ToastyFS.h"

typedef enum {
    TEST_CLIENT_STATE_0,
    TEST_CLIENT_STATE_1,
    TEST_CLIENT_STATE_2,
    TEST_CLIENT_STATE_3,
} TestClientState;

typedef struct {
    ToastyFS*       toasty;
    ToastyHandle    handle;
    TestClientState state;
    char buf[1<<10];
} TestClient;

struct pollfd;

int test_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int test_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int test_client_free(void *state);

#endif // TEST_CLIENT_INCLUDED