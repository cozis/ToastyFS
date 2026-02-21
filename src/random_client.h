#ifndef BLOB_CLIENT_INCLUDED
#define BLOB_CLIENT_INCLUDED

#include "tcp.h"
#include "basic.h"

#include "config.h"
#include "metadata.h"

typedef struct {
    ToastyFS *tfs;
} RandomClient;

struct pollfd;

int random_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int random_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int random_client_free(void *state);

#endif // BLOB_CLIENT_INCLUDED
