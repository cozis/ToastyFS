#ifndef SIMULATION_CLIENT_INCLUDED
#define SIMULATION_CLIENT_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

#include "TinyDFS.h"

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
    int opidx;
    void *ptr;
} PendingOperation;

typedef struct {
    TinyDFS *tdfs;
    int num_pending;
    PendingOperation pending[MAX_PENDING_OPERATION];
} SimulationClient;

int  simulation_client_init(SimulationClient *client, int argc, char **argv,
                            void **contexts, struct pollfd *polled, int *timeout);
int  simulation_client_step(SimulationClient *client, void **contexts,
                            struct pollfd *polled, int num_polled, int *timeout);
void simulation_client_free(SimulationClient *client);

#endif // SIMULATION_CLIENT_INCLUDED
