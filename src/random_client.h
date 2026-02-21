#ifndef RANDOM_CLIENT_INCLUDED
#define RANDOM_CLIENT_INCLUDED

#include <toastyfs.h>

#include "tcp.h"
#include "basic.h"

#include "config.h"
#include "metadata.h"

typedef struct {
    ToastyFS *tfs;
    bool started;
} RandomClient;

struct pollfd;

int random_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int random_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int random_client_free(void *state);

#endif // RANDOM_CLIENT_INCLUDED
