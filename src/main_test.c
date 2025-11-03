#ifdef BUILD_TEST

#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include "system.h"

static sig_atomic_t simulation_should_stop = false;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    // TODO: set simulation_should_stop=true on ctrl+C

    startup_simulation();

    // Spawn metadata server (leader)
    spawn_simulated_process("--addr 127.0.0.1 8080 --leader");

    // Spawn chunk servers
    spawn_simulated_process("--addr 127.0.0.1 8081");
    spawn_simulated_process("--addr 127.0.0.1 8082");
    spawn_simulated_process("--addr 127.0.0.1 8083");
    spawn_simulated_process("--addr 127.0.0.1 8084");
    spawn_simulated_process("--addr 127.0.0.1 8085");
    spawn_simulated_process("--addr 127.0.0.1 8086");
    spawn_simulated_process("--addr 127.0.0.1 8087");
    spawn_simulated_process("--addr 127.0.0.1 8088");
    spawn_simulated_process("--addr 127.0.0.1 8089");
    spawn_simulated_process("--addr 127.0.0.1 8090");

    // Spawn simulation client
    spawn_simulated_process("--client --server 127.0.0.1 8080");

    printf("Running simulation (press Ctrl+C to stop)...\n");

    // Run for a limited number of iterations for testing
    int iteration = 0;
    int max_iterations = 100000;  // Increased to allow client operations to complete
    while (!simulation_should_stop && iteration < max_iterations) {
        update_simulation();
        iteration++;

        // Print progress every 10000 iterations
        if (iteration % 10000 == 0) {
            fprintf(stderr, "Iteration %d...\n", iteration);
            fflush(stderr);
        }
    }

    if (iteration >= max_iterations) {
        printf("\nSimulation stopped after %d iterations\n", max_iterations);
    }

    cleanup_simulation();
    printf("Simulation complete!\n");
    return 0;
}

#endif
