#ifndef RANDOM_CLIENT_INCLUDED
#define RANDOM_CLIENT_INCLUDED

#include "ToastyFS.h"

#define MAX_PENDING_OPERATION 8

typedef enum {
    PENDING_OPERATION_CREATE,
    PENDING_OPERATION_DELETE,
    PENDING_OPERATION_LIST,
    PENDING_OPERATION_READ,
    PENDING_OPERATION_WRITE,
} PendingOperationType;

typedef struct {
    PendingOperationType type;
    ToastyHandle handle;
    void *ptr;
} PendingOperation;

typedef struct {
    ToastyFS *toasty;
    int num_pending;
    PendingOperation pending[MAX_PENDING_OPERATION];
} RandomClient;

struct pollfd;

int random_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int random_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int random_client_free(void *state);

#endif // RANDOM_CLIENT_INCLUDED