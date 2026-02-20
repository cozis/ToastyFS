#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <lib/tcp.h>
#include <lib/basic.h>

#include "config.h"
#include "metadata.h"

typedef struct {

    TCP tcp;

    // True if we are waiting for a response
    bool pending;
    Time request_time; // When the current request was sent

    // The operation sent in the current pending request (for logging)
    MetaOper last_oper;

    // Checker support
    MetaResult    last_result;
    bool          last_was_timeout;
    bool          last_was_rejected;

    Address server_addrs[NODE_LIMIT];
    int num_servers;

    uint64_t view_number;

    uint64_t client_id;
    uint64_t request_id;

    Time reconnect_time; // Earliest time to retry connecting to leader

} ClientState;

struct pollfd;

int client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int client_free(void *state);

#endif // CLIENT_INCLUDED