#ifdef MAIN_SIMULATION
#define QUAKEY_ENABLE_MOCKS
#else
#define POLL_CAPACITY 1024
#endif
#include <stdint.h>
#include <quakey.h>

#include "metadata_server.h"
#include "chunk_server.h"
#include "random_client.h"

#ifdef MAIN_METADATA_SERVER
int main(int argc, char **argv)
{
    int ret;
    MetadataServer state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = metadata_server_init(
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

        ret = metadata_server_tick(
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

    metadata_server_free(&state);
    return 0;
}
#endif

#ifdef MAIN_CHUNK_SERVER
int main(int argc, char **argv)
{
    int ret;
    ChunkServer state;

    void*         poll_ctxs[POLL_CAPACITY];
    struct pollfd poll_array[POLL_CAPACITY];
    int poll_count;
    int poll_timeout;

    ret = chunk_server_init(
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

        ret = chunk_server_tick(
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

    chunk_server_free(&state);
    return 0;
}
#endif

#ifdef MAIN_SIMULATION
#include <signal.h>

static volatile int simulation_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    simulation_running = 0;
}

int main(void)
{
    signal(SIGINT, sigint_handler);

    Quakey *quakey;
    int ret = quakey_init(&quakey, 1);
    if (ret < 0)
        return -1;

    // Client 1
    {
        QuakeySpawn config = {
            .name       = "cli1",
            .state_size = sizeof(RandomClient),
            .init_func  = random_client_init,
            .tick_func  = random_client_tick,
            .free_func  = random_client_free,
            .addrs      = (char*[]) { "127.0.0.2" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cli --server 127.0.0.4 8080");
    }

    // Client 2
    {
        QuakeySpawn config = {
            .name       = "cli2",
            .state_size = sizeof(RandomClient),
            .init_func  = random_client_init,
            .tick_func  = random_client_tick,
            .free_func  = random_client_free,
            .addrs      = (char*[]) { "127.0.0.3" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cli --server 127.0.0.4 8080");
    }

    // Metadata Server
    {
        QuakeySpawn config = {
            .name       = "ms",
            .state_size = sizeof(MetadataServer),
            .init_func  = metadata_server_init,
            .tick_func  = metadata_server_tick,
            .free_func  = metadata_server_free,
            .addrs      = (char*[]) { "127.0.0.4" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "ms --addr 127.0.0.4 --port 8080");
    }

    // Chunk Server 1
    {
        QuakeySpawn config = {
            .name       = "cs1",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.5" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.5 --port 8081 --remote-addr 127.0.0.4 --remote-port 8080");
    }

    // Chunk Server 2
    {
        QuakeySpawn config = {
            .name       = "cs2",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.6" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.6 --port 8082 --remote-addr 127.0.0.4 --remote-port 8080");
    }

    // Chunk Server 3
    {
        QuakeySpawn config = {
            .name       = "cs3",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.7" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.7 --port 8083 --remote-addr 127.0.0.4 --remote-port 8080");
    }

    while (simulation_running)
        quakey_schedule_one(quakey);

    quakey_free(quakey);
    return 0;
}
#endif // MAIN_SIMULATION

#ifdef MAIN_TEST
#include <signal.h>
#include "test_client.h"

static volatile int simulation_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    simulation_running = 0;
}

int main(void)
{
    signal(SIGINT, sigint_handler);

    Quakey *quakey;
    int ret = quakey_init(&quakey, 1);
    if (ret < 0)
        return -1;

    // Client 1
    {
        QuakeySpawn config = {
            .name       = "test_cli_1",
            .state_size = sizeof(TestClient),
            .init_func  = test_client_init,
            .tick_func  = test_client_tick,
            .free_func  = test_client_free,
            .addrs      = (char*[]) { "127.0.0.2" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cli --server 127.0.0.3 8080");
    }

    // Metadata Server
    {
        QuakeySpawn config = {
            .name       = "ms",
            .state_size = sizeof(MetadataServer),
            .init_func  = metadata_server_init,
            .tick_func  = metadata_server_tick,
            .free_func  = metadata_server_free,
            .addrs      = (char*[]) { "127.0.0.3" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "ms --addr 127.0.0.3 --port 8080");
    }

    // Chunk Server 1
    {
        QuakeySpawn config = {
            .name       = "cs1",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.4" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.4 --port 8081 --remote-addr 127.0.0.3 --remote-port 8080");
    }

    // Chunk Server 2
    {
        QuakeySpawn config = {
            .name       = "cs2",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.5" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.5 --port 8082 --remote-addr 127.0.0.3 --remote-port 8080");
    }

    // Chunk Server 3
    {
        QuakeySpawn config = {
            .name       = "cs3",
            .state_size = sizeof(ChunkServer),
            .init_func  = chunk_server_init,
            .tick_func  = chunk_server_tick,
            .free_func  = chunk_server_free,
            .addrs      = (char*[]) { "127.0.0.6" },
            .num_addrs  = 1,
            .disk_size  = 10<<20,
            .platform   = QUAKEY_LINUX,
        };
        quakey_spawn(quakey, config, "cs --addr 127.0.0.6 --port 8083 --remote-addr 127.0.0.3 --remote-port 8080");
    }

    while (simulation_running)
        quakey_schedule_one(quakey);

    quakey_free(quakey);
    return 0;
}
#endif // MAIN_TEST
