#ifndef TEST_CLIENT_INCLUDED
#define TEST_CLIENT_INCLUDED

#include "ToastyFS.h"

typedef struct {
    ToastyFS *toasty;
} TestClient;

struct pollfd;

int test_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int test_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int test_client_free(void *state);

#endif // TEST_CLIENT_INCLUDED