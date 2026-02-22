# ToastyFS

ToastyFS is a distributed and fault-tolerant object storage.

## Getting Started

First, build ToastyFS by running the build script:

```sh
./build.sh
```

This will produce three executables: `toastyfs`, `toastyfs_random_client` and `toastyfs_simulation`.

The `toastyfs` is the one you need to run. The other executables are for testing purposes.

You can pick a cluster size based on how many faults you want it to handle. Let's start with a cluster size of 3 which will allow one node to crash at a given time.

Run three instances of `toastyfs` while specifying to each one the addresses of the others:

```sh
./toastyfs --addr 127.0.0.1:8081  --peer 127.0.0.1:8082 --peer 127.0.0.1:8083
./toastyfs --addr 127.0.0.1:8082  --peer 127.0.0.1:8081 --peer 127.0.0.1:8083
./toastyfs --addr 127.0.0.1:8083  --peer 127.0.0.1:8081 --peer 127.0.0.1:8082
```

The cluster is now working.

To upload/download/delete objects, you need to compile a client program which needs the toasty client library.

To build the library, run the following, which will generate the `libtoasty.a` and `libtoasty.so` files:

```sh
Makefile
```

You can use the following example program which will upload a simple object:

```c
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <toastyfs.h>

int main(void)
{
    srand(time(NULL));

    char addr1[] = "127.0.0.1:8081";
    char addr2[] = "127.0.0.1:8082";
    char addr3[] = "127.0.0.1:8083";
    char *addrs[] = { addr1, addr2, addr3 };

    printf("Connecting to cluster...\n");
    ToastyFS *tfs = toastyfs_init(rand(), addrs, 3);
    if (tfs == NULL) {
        fprintf(stderr, "toastyfs_init failed\n");
        return 1;
    }

    char key[]  = "hello";
    char data[] = "world";

    printf("PUT key=\"%s\" data=\"%s\" (%d bytes)\n", key, data, (int)strlen(data));

    ToastyFS_Result res;
    int ret = toastyfs_put(tfs, key, strlen(key), data, strlen(data), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_put returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }

    printf("Done.\n");
    toastyfs_free(tfs);
    return 0;
}
```

Save it as `example_client.c` and compile it by running:

```
gcc example_client.c libtoasty.a -o example
```

By running the client while the cluster is running, the object will be created!

## Fault Tolerance

ToastyFS allows any minority of nodes to be dead at any given time and continue running without issues. Generally speaking, if your system has 2f+1 nodes, it can work without f of them.

## Testing

ToastyFS is tested with Deterministic Simulation Testing (DST).

The entire system (server nodes and clients) is simulated in the memory of a single process deterministically. Faults (node crashes, network partitons) and latencies are pseudo-randonly injected in the simulation such that a variety of scenarios are tested but in a way that can be perfectly reproduced by using the same simulation seed from which all random events are chosen.

After each node schedulation, the simulator inspects all node states at the same instant and verifies that none of the system's invariant were broken.

You can build and run the simulation by doing:

```
./build.sh
./toastyfs_simulation
```

