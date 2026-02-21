#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <toastyfs.h>
#include <stdint.h>
#include <assert.h>

#include "server.h"
#include "random_client.h"

static uint64_t next_random_client_id = 100;

int random_client_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    RandomClient *state = state_;

    char *addrs[NODE_LIMIT];
    int num_addrs = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --server missing value\n");
                return -1;
            }
            if (num_addrs == NODE_LIMIT) {
                fprintf(stderr, "Node limit reached\n");
                return -1;
            }
            addrs[num_addrs] = argv[i];
            num_addrs++;
        } else {
            // Ignore unknown options
        }
    }

    state->tfs = toastyfs_alloc();
    if (state->tfs == NULL)
        return -1;

    uint64_t client_id = next_random_client_id++;
    if (toastyfs_init(state->tfs, client_id, addrs, num_addrs) < 0)
        return -1;

    *timeout = 0;
    if (pcap < TCP_POLL_CAPACITY) {
        fprintf(stderr, "Random client :: Not enough poll capacity\n");
        return -1;
    }
    *pnum = toastyfs_register_events(state->tfs, ctxs, pdata, pcap);
    return 0;
}

int random_client_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    RandomClient *state = state_;
    toastyfs_process_events(state->tfs, ctxs, pdata, *pnum);

    ToastyFS_Result result = toastyfs_get_result(state->tfs);
    switch (result.type) {
    case TOASTYFS_RESULT_VOID:
        break;
    case TOASTYFS_RESULT_PUT:
        {
            // TODO
        }
        break;
    case TOASTYFS_RESULT_GET:
        {
            // TODO
        }
        break;
    case TOASTYFS_RESULT_DELETE:
        {
            // TODO
        }
        break;
    }

    switch (choose_random_oper()) {
    case OPER_GET:
        toastyfs_async_get(state->tfs, xxx);
        break;
    case OPER_PUT:
        toastyfs_async_put(state->tfs, xxx);
        break;
    case OPER_DELETE:
        toastyfs_async_delete(state->tfs, xxx);
        break;
    }

    *pnum = toastyfs_register_events(state->tfs, ctxs, pdata, pcap);
    return 0;
}

int random_client_free(void *state_)
{
    RandomClient *state = state_;
    toastyfs_free(state->tfs);
    return 0;
}
