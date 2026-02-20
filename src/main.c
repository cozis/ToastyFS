#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS

#include <signal.h>
#include <stdint.h>
#include <quakey.h>
#include <assert.h>

#include "server.h"
#include "client.h"
#include "blob_client.h"

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
            .state_size = sizeof(ClientState),
            .init_func  = client_init,
            .tick_func  = client_tick,
            .free_func  = client_free,
            .addrs      = (char*[]) { "127.0.0.2" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        (void) quakey_spawn(quakey, config, "cli --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Client 2
    {
        QuakeySpawn config = {
            .name       = "rndcli2",
            .state_size = sizeof(ClientState),
            .init_func  = client_init,
            .tick_func  = client_tick,
            .free_func  = client_free,
            .addrs      = (char*[]) { "127.0.0.3" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        (void) quakey_spawn(quakey, config, "cli --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Blob Client
    {
        QuakeySpawn config = {
            .name       = "blobcli",
            .state_size = sizeof(BlobClientState),
            .init_func  = blob_client_init,
            .tick_func  = blob_client_tick,
            .free_func  = blob_client_free,
            .addrs      = (char*[]) { "127.0.0.7" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        (void) quakey_spawn(quakey, config, "blob --server 127.0.0.4:8080 --server 127.0.0.5:8080 --server 127.0.0.6:8080");
    }

    // Node 1
    {
        QuakeySpawn config = {
            .name       = "server1",
            .state_size = sizeof(ServerState),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.4" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        node_1 = quakey_spawn(quakey, config, "nd --addr 127.0.0.4:8080 --peer 127.0.0.5:8080 --peer 127.0.0.6:8080");
    }

    // Node 2
    {
        QuakeySpawn config = {
            .name       = "server2",
            .state_size = sizeof(ServerState),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.5" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        node_2 = quakey_spawn(quakey, config, "nd --peer 127.0.0.4:8080 --addr 127.0.0.5:8080 --peer 127.0.0.6:8080");
    }

    // Node 3
    {
        QuakeySpawn config = {
            .name       = "server3",
            .state_size = sizeof(ServerState),
            .init_func  = server_init,
            .tick_func  = server_tick,
            .free_func  = server_free,
            .addrs      = (char*[]) { "127.0.0.6" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
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

        ServerState *arr[] = {
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

#include <poll.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "client.h"

#define POLL_CAPACITY 1024

int main(int argc, char **argv)
{
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int ret;
    ClientState state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = client_init(
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

        ret = client_tick(
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

    client_free(&state);
    return 0;
}

#endif // MAIN_CLIENT
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
#ifdef MAIN_SERVER

#include <poll.h>

#include "server.h"

#define POLL_CAPACITY 1024

int main(int argc, char **argv)
{
    int ret;
    ServerState state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = server_init(
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

        ret = server_tick(
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

    server_free(&state);
    return 0;
}

#endif // MAIN_SERVER