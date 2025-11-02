#ifdef BUILD_TEST

#include <signal.h>
#include <stdbool.h>

#include "system.h"

static sig_atomic_t simulation_should_stop = false;

int main(int argc, char **argv)
{
    // TODO: set simulation_should_stop=true on ctrl+C

    spawn_simulated_process("--addr 127.0.0.1 8080 --leader");
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

    while (!simulation_should_stop)
        update_simulation();

    cleanup_simulation();
    return 0;
}

#endif
