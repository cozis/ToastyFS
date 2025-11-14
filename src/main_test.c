#ifdef BUILD_TEST

#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include "system.h"

static sig_atomic_t simulation_should_stop = false;

static void signal_handler(int signum)
{
    (void)signum;
    simulation_should_stop = true;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    // Set up signal handlers for clean shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    startup_simulation(2);

    // Spawn metadata server (leader)
    spawn_simulated_process("--addr 127.0.0.1 --port 8080 --leader");

    // Spawn chunk servers
    spawn_simulated_process("--addr 127.0.0.1 --port 8081 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_0/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8082 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_1/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8083 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_2/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8084 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_3/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8085 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_4/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8086 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_5/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8087 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_6/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8088 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_7/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8089 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_8/");
    spawn_simulated_process("--addr 127.0.0.1 --port 8090 --remote-addr 127.0.0.1 --remote-port 8080 --path chunk_server_data_9/");

    // Spawn simulation client
    spawn_simulated_process("--client --remote-addr 127.0.0.1 --remote-port 8080");
    spawn_simulated_process("--client --remote-addr 127.0.0.1 --remote-port 8080");
    spawn_simulated_process("--client --remote-addr 127.0.0.1 --remote-port 8080");
    spawn_simulated_process("--client --remote-addr 127.0.0.1 --remote-port 8080");
    spawn_simulated_process("--client --remote-addr 127.0.0.1 --remote-port 8080");

    while (!simulation_should_stop)
        update_simulation();

    cleanup_simulation();
    return 0;
}

#endif
