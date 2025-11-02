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

typedef enum {
    CLIENT_STATE_INIT,
    CLIENT_STATE_RUNNING,
    CLIENT_STATE_DONE,
} ClientState;

typedef struct {
    TinyDFS *tdfs;
    ClientState state;

    // Track operations
    int create_dir_op;
    int create_file_op;
    int write_op;
    int read_op;
    int list_op;
    int delete_op;

    // Read buffer
    char read_buffer[1024];

    // Test step counter
    int step;
} SimulationClient;

int  simulation_client_init(SimulationClient *client, int argc, char **argv,
                            void **contexts, struct pollfd *polled, int *timeout);
int  simulation_client_step(SimulationClient *client, void **contexts,
                            struct pollfd *polled, int num_polled, int *timeout);
void simulation_client_free(SimulationClient *client);

#endif // SIMULATION_CLIENT_INCLUDED
