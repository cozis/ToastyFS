#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS

#include <signal.h>
#include <stdint.h>
#include <quakey.h>
#include <assert.h>

#include "server.h"
#include "random_client.h"

static volatile int simulation_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    simulation_running = 0;
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigint_handler);

    QuakeyUInt64 seed = 1;
    QuakeyUInt64 time_limit_ns = 0; // 0 means no limit

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--time") == 0 && i + 1 < argc) {
            time_limit_ns = strtoull(argv[++i], NULL, 10) * 1000000000ULL;
        }
    }

    Quakey *quakey;
    int ret = quakey_init(&quakey, seed);
    if (ret < 0)
        return -1;

    QuakeyNode node_1;
    QuakeyNode node_2;
    QuakeyNode node_3;

    // Client 1
    {
        QuakeySpawn config = {
            .name       = "rndcli1",
            .state_size = sizeof(RandomClient),
            .init_func  = random_client_init,
            .tick_func  = random_client_tick,
            .free_func  = random_client_free,
            .addrs      = (char*[]) { "127.0.0.2" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        (void) quakey_spawn(quakey, config, "cli --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Client 2
    {
        QuakeySpawn config = {
            .name       = "rndcli2",
            .state_size = sizeof(RandomClient),
            .init_func  = random_client_init,
            .tick_func  = random_client_tick,
            .free_func  = random_client_free,
            .addrs      = (char*[]) { "127.0.0.3" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        (void) quakey_spawn(quakey, config, "cli --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Client 3
    {
        QuakeySpawn config = {
            .name       = "rndcli3",
            .state_size = sizeof(RandomClient),
            .init_func  = random_client_init,
            .tick_func  = random_client_tick,
            .free_func  = random_client_free,
            .addrs      = (char*[]) { "127.0.0.7" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        (void) quakey_spawn(quakey, config, "cli --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Node 1
    {
        QuakeySpawn config = {
            .name       = "server1",
            .state_size = sizeof(Server),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.4" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        node_1 = quakey_spawn(quakey, config, "nd --addr 127.0.0.4:8080 --peer 127.0.0.5:8080 --peer 127.0.0.6:8080");
    }

    // Node 2
    {
        QuakeySpawn config = {
            .name       = "server2",
            .state_size = sizeof(Server),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.5" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        node_2 = quakey_spawn(quakey, config, "nd --peer 127.0.0.4:8080 --addr 127.0.0.5:8080 --peer 127.0.0.6:8080");
    }

    // Node 3
    {
        QuakeySpawn config = {
            .name       = "server3",
            .state_size = sizeof(Server),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.6" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
        };
        node_3 = quakey_spawn(quakey, config, "nd --peer 127.0.0.4:8080 --peer 127.0.0.5:8080 --addr 127.0.0.6:8080");
    }

    // Limit crashes to 1 node at a time (within fault tolerance of f=1).
    // This is dynamically adjusted below: crashes are disabled while
    // any node is still recovering.
    quakey_set_max_crashes(quakey, 1);

    quakey_network_partitioning(quakey, true);

    InvariantChecker invariant_checker;
    invariant_checker_init(&invariant_checker);

    while (simulation_running && (time_limit_ns == 0 || quakey_current_time(quakey) < time_limit_ns)) {

        quakey_schedule_one(quakey);

        Server *arr[] = {
            quakey_node_state(node_1),
            quakey_node_state(node_2),
            quakey_node_state(node_3),
        };
        unsigned long long handles[] = { node_1, node_2, node_3 };
        invariant_checker_run(&invariant_checker, arr, sizeof(arr)/sizeof(arr[0]), handles);

        // VR-Revisited Section 8.2: "a replica is considered failed
        // until it has recovered its state." Disable crashes while
        // any node is recovering to avoid exceeding f simultaneous
        // failures (dead + recovering).
        bool any_recovering = false;
        for (int i = 0; i < 3; i++) {
            if (arr[i] && arr[i]->status == STATUS_RECOVERY)
                any_recovering = true;
        }
        quakey_set_max_crashes(quakey, any_recovering ? 0 : 1);
    }

    invariant_checker_free(&invariant_checker);
    quakey_free(quakey);
    return 0;
}

#endif // MAIN_SIMULATION
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
#ifdef MAIN_CLIENT

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "random_client.h"

#define POLL_CAPACITY 1024

int main(int argc, char **argv)
{
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int ret;
    RandomClient state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = random_client_init(
        &state,
        argc,
        argv,
        poll_ctxs,
        poll_array,
        POLL_CAPACITY,
        &poll_count,
        &poll_timeout
    );
    if (ret < 0)
        return -1;

    for (;;) {

#ifdef _WIN32
        WSAPoll(poll_array, poll_count, poll_timeout);
#else
        poll(poll_array, poll_count, poll_timeout);
#endif

        ret = random_client_tick(
            &state,
            poll_ctxs,
            poll_array,
            POLL_CAPACITY,
            &poll_count,
            &poll_timeout
        );
        if (ret < 0)
            return -1;
    }

    random_client_free(&state);
    return 0;
}

#endif // MAIN_CLIENT
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
#ifdef MAIN_SERVER

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "server.h"

#define POLL_CAPACITY 1024

int main(int argc, char **argv)
{
    int ret;

    // Server is ~40 MB (MetaStore holds 4096 ObjectMeta entries),
    // which exceeds the default stack size.  Heap-allocate it.
    Server *state = malloc(sizeof(Server));
    if (state == NULL) {
        fprintf(stderr, "Failed to allocate Server\n");
        return -1;
    }

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = server_init(
        state,
        argc,
        argv,
        poll_ctxs,
        poll_array,
        POLL_CAPACITY,
        &poll_count,
        &poll_timeout
    );
    if (ret < 0)
        return -1;

    for (;;) {

#ifdef _WIN32
        WSAPoll(poll_array, poll_count, poll_timeout);
#else
        poll(poll_array, poll_count, poll_timeout);
#endif

        ret = server_tick(
            state,
            poll_ctxs,
            poll_array,
            POLL_CAPACITY,
            &poll_count,
            &poll_timeout
        );
        if (ret < 0)
            return -1;
    }

    server_free(state);
    free(state);
    return 0;
}

#endif // MAIN_SERVER
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
#ifdef MAIN_HTTP_PROXY

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

#include "http_proxy.h"

#define POLL_CAPACITY 1024

int main(int argc, char **argv)
{
    int ret;

    HTTPProxy state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = http_proxy_init(
        &state,
        argc,
        argv,
        poll_ctxs,
        poll_array,
        POLL_CAPACITY,
        &poll_count,
        &poll_timeout
    );
    if (ret < 0)
        return -1;

    for (;;) {

#ifdef _WIN32
        WSAPoll(poll_array, poll_count, poll_timeout);
#else
        poll(poll_array, poll_count, poll_timeout);
#endif

        ret = http_proxy_tick(
            &state,
            poll_ctxs,
            poll_array,
            POLL_CAPACITY,
            &poll_count,
            &poll_timeout
        );
        if (ret < 0)
            return -1;
    }

    http_proxy_free(&state);
    return 0;
}

#endif // MAIN_HTTP_PROXY