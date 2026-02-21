#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <toastyfs.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "server.h"
#include "random_client.h"

static uint64_t next_random_client_id = 100;

static const char *error_name(ToastyFS_Error err)
{
    switch (err) {
    case TOASTYFS_ERROR_VOID:               return "OK";
    case TOASTYFS_ERROR_OUT_OF_MEMORY:      return "OUT_OF_MEMORY";
    case TOASTYFS_ERROR_UNEXPECTED_MESSAGE:  return "UNEXPECTED_MSG";
    case TOASTYFS_ERROR_REJECTED:            return "REJECTED";
    case TOASTYFS_ERROR_FULL:               return "FULL";
    case TOASTYFS_ERROR_NOT_FOUND:          return "NOT_FOUND";
    case TOASTYFS_ERROR_TRANSFER_FAILED:    return "TRANSFER_FAILED";
    }
    return "??";
}

static uint64_t rng(void)
{
#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
    return quakey_random();
#else
    return (uint64_t)rand();
#endif
}

typedef enum {
    OPER_PUT,
    OPER_GET,
    OPER_DELETE,
} RandomOper;

static RandomOper choose_random_oper(void)
{
    return rng() % 3;
}

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

    uint64_t client_id = next_random_client_id++;
    state->tfs = toastyfs_init(client_id, addrs, num_addrs);
    if (state->tfs == NULL)
        return -1;
    state->started = false;

    if (pcap < TCP_POLL_CAPACITY) {
        fprintf(stderr, "Random client :: Not enough poll capacity\n");
        return -1;
    }
    *pnum = toastyfs_register_events(state->tfs, ctxs, pdata, pcap, timeout);
    *timeout = 0; // Ensure first tick fires immediately to start an operation
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
        printf("  RANDOM_CLIENT :: PUT result=%s\n", error_name(result.error));
        break;
    case TOASTYFS_RESULT_GET:
        printf("  RANDOM_CLIENT :: GET result=%s size=%d\n", error_name(result.error), result.size);
        free(result.data);
        break;
    case TOASTYFS_RESULT_DELETE:
        printf("  RANDOM_CLIENT :: DELETE result=%s\n", error_name(result.error));
        break;
    }

    // Start a new random operation if idle (previous result was consumed,
    // or this is the first tick and no operation has been started yet)
    if (result.type != TOASTYFS_RESULT_VOID || !state->started) {
        state->started = true;
        char key[64];
        int key_len = snprintf(key, sizeof(key), "k%d", (int)(rng() % 64));

        RandomOper oper = choose_random_oper();
        switch (oper) {
        case OPER_PUT:
            {
                char data[CHUNK_SIZE];
                for (int i = 0; i < CHUNK_SIZE; i++)
                    data[i] = rng() & 0xFF;
                printf("  RANDOM_CLIENT :: starting PUT key=%s size=%d\n", key, CHUNK_SIZE);
                toastyfs_async_put(state->tfs, key, key_len, data, CHUNK_SIZE);
            }
            break;
        case OPER_GET:
            printf("  RANDOM_CLIENT :: starting GET key=%s\n", key);
            toastyfs_async_get(state->tfs, key, key_len);
            break;
        case OPER_DELETE:
            printf("  RANDOM_CLIENT :: starting DELETE key=%s\n", key);
            toastyfs_async_delete(state->tfs, key, key_len);
            break;
        }
    }

    *pnum = toastyfs_register_events(state->tfs, ctxs, pdata, pcap, timeout);
    return 0;
}

int random_client_free(void *state_)
{
    RandomClient *state = state_;
    toastyfs_free(state->tfs);
    return 0;
}
