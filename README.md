# ToastyFS

ToastyFS is a simple, fault-tolerant, highly available object storage featuring:

* Deterministic Simulation Testing
* Cross-Platform (Windows, Linux)
* Minimal Dependencies (OpenSSL and SChannel)
* Viewstamped Replication

I initially started this project to learn about distributed systems. I asked myself what it would take to build my own Dropbox. A rabbit-hole later and here is my distributed storage system!

## Table of Contents

* [ToastyFS](#toastyfs)
  * [Project Status & Known Limitations](#project-status--known-limitations)
* [Getting Started](#getting-started)
  * [Building](#building)
  * [Running a Cluster](#running-a-cluster)
  * [Basic Usage](#basic-usage)
* [Fault Tolerance & High Availability](#fault-tolerance--high-availability)
  * [The Need for Replication](#the-need-for-replication)
  * [Raft VS Viewstamped Replication](#raft-vs-viewstamped-replication)
  * [Replication in ToastyFS](#replication-in-toastyfs)
  * [Failure Scenarios](#failure-scenarios)
* [Architecture](#architecture)
  * [System Components](#system-components)
  * [Request Lifecycle](#request-lifecycle)
* [Testing](#testing)
  * [Deterministic Simulation Testing](#deterministic-simulation-testing)
  * [Testing in ToastyFS](#testing-in-toastyfs)

### Project Status & Known Limitations

This project should be considered a robust proof-of-concept at this time. Features that would be required for long-running instances are missing, such as:

* Log compaction
* Ability to shut down all nodes without resetting the system

## Getting Started

### Building

ToastyFS supports Windows and Linux. Each platform has its own build script:

```
# Windows
.\build.bat

# Linux
./build.sh
```

The build script will produce the following executables:

| Name | Description |
| :--- | :---------- |
| toasty_simulation | Runs a ToastyFS cluster in-memory, with sped-up time and serving a number of random operations. See [Testing](#testing) section for details. |
| toasty | The actual ToastyFS program. This is what you need to run to use ToastyFS. |
| toasty_random_client | An utility client which spams random requests towards a ToastyFS cluster. Useful for testing. |
| toasty_proxy | An HTTP proxy that translates HTTP request to the ToastyFS-specific request protocol. |

On Windows the executables will have the `.exe` extension.

### Running a Cluster

You can then start a ToastyFS cluster by running the cluster script. If you are on Windows, you will need a Linux-compatible shell to run it.

```
./cluster.sh start
./cluster.sh status
```

The cluster is composed of 3 nodes and 1 HTTP proxy listening on `127.0.0.1:3000`.

The cluster can be turned off by doing:

```
./cluster.sh stop
```

### Basic Usage

The HTTP proxy makes it easy to manage ToastyFS instances. You can manage objects via regular HTTP verbs:

```
$ curl -X PUT http://127.0.0.1:3000/first_object -d "I'm the first object"
$ curl -X GET http://127.0.0.1:3000/first_object
I'm the first object
```

## Fault Tolerance & High Availability

### The Need for Replication

To build a fault-tolerant service, it's necessary for it to run on multiple machines in such a way that if a machine dies, the others can continue its work. This is referred to as replication. Designing and implementing a replication system that properly manages all edge cases is **incredibly hard**. Such an algorithm needs to account for any number of node crashes at any phase of the protocol, it needs to account for arbitrary network partitions (network failures that cause the system to be split in multiple groups of nodes) making it impossible for the state of each group to diverge. This is such a hard problem that not only few general algorithms have been designed, but also the number of their implementations is vanishingly low. The common replication algorithms are Raft and Paxos (*). This project uses a less known algorithm called Viewstamped Replication (VSR).

(*) Strictly speaking, Paxos is a consensus algorithm. Replication can be built on top of it.

### Raft VS Viewstamped Replication

For historical reasons, Paxos (1989) is the established algorithm to achieve replication. Paxos is notorious for being hard to understand and implement, so in 2014 a more understandable algorithm called Raft was introduced. Since then, Raft has been the go-to algorithm from new open source projects.

There is also a lesser known replication algorithm called Viewstamped Replication (VSR), which never got much attention from the industry even though it was invented around the same time as Paxos (and arguably, before it). In 2012 the "Viewstamped Replication Revisited" paper was published which offered a modernized design of the protocol. The later paper is the reference for VSR used in this project.

VSR's design is very similar to Raft (which came about 25 years later) but has some important differences. At a high level, Raft was optimized for understandability, while VSR for performance and robustness. VSR offers guarantees that neither Raft nor Paxos are able to offer by default.

A key component of the Raft algorithm is the write-ahead log that each node uses to restore its state in case of a crash. If the disk fails, the log is lost. Raft only guarantees overall availability if no disks fail.

Unlike Raft, VSR does not require a disk. All state necessary for replication can be stored in-memory. Disk storage can be used but it's merely an optional optimization. Even if a disk were used, implementations could fallback to the in-memory variant on the protocol in case of disk failure.

### Replication in ToastyFS

A ToastyFS system is made by a number of servers that are replicated according to VSR. One server acts as primary while the others as backups. Clients send read, update, delete operations to the primary which in turns forwards them to backups. When a majority has agreed to run that command, it is executed and the primary sends the result to the client. Reaching a consensus on operations to perform ensures that if any node crashes, another one can take its place with the same state.

Since ToastyFS relies on reaching majority to update its state, it remains available as long as a majority of nodes stays online. For instance a cluster of 5 nodes will function as long as 3 nodes are live. Generally speaking, a cluster of `2f+1` nodes will tolerate `f` simultaneous failures.

### Failure Scenarios

The primary node periodically sends heartbeat messages to backups. When backups stop receiving messages from the primary, they assume it is dead. The specific timeout is configurable but the default value is 1-2 seconds. The live node then perform a "view change", which means they choose a new primary and ensure it holds the latest state of the system. Any interaction of clients with the original node is lost causing them to timeout. Dropped operations will need to be restarted. If the old primary comes back online, it will do so as a backup.

If a backup node crashes, it simply will simply stop partecipating in consensus, and if a majority of nodes is dead no consensus will be reached at all causing the system to become unavailable.

When a node (be it an old primary or backup) restarts, it enters a recovery state where it asks to rejoin the cluster and the current state of the system is sent back.

A node in the recovery state can only rejoin the cluster if a majority of nodes is still alive, which means that if a majority of nodes dies, the system will become permanently unavailable. This is a consequence of the in-memory implementation of VSR. If it was extended to use a persistent log, the recovery state could be skipped entirely, allowing nodes to rejoin the cluster regardless of the number of nodes that are still alive.

Network partitions are naturally handled by the VSR protocol. If the cluster nodes are partitioned in groups that can't talk with each other, a maximum of one group will be able to reach consensus and continue operation. All other minorities will become unavailable. If the partitions are resolved, stale nodes will request a state transfer and catch up.

Disk corruption will not impact the replication protocol but it may cause object data to be lost on a node. Since such data is stored on a majority of nodes, as long as that data is available on at least one node, it will be possible to retrieve it.

## Architecture

### System Components

ToastyFS is designed to be easy to deploy. A ToastyFS cluster is made of a number of server nodes and a proxy node.

Server nodes store both object metadata and data and speak to each other via a custom protocol. An HTTP proxy node translates regular HTTP operations to the custom protocol.

A cluster must have an odd number of servers that is greater than 1, like 3 or 5. Generally speaking if 2f+1 is the number of servers, the system will continue working if at least f+1 nodes are alive. This is a consequence of the quorum intersection property that VSR relies on.

### Request Lifecycle

When a client starts performs a PUT request to create a new object in the system, the object name and data is first sent to the HTTP proxty. The proxy, which acts as client relative to the ToastyFS servers, splits the data into chunks and for each chunk it picks the servers it should be replicated on. Each chunk must be replicated on a majority of servers. The proxy then uploads the chunks to the servers. If any single upload fails, the overall operation fails. If all uploads succeded, the proxy sends the list of chunks that were uploaded and their new locations to the primary node. The primary forwards the object's metadata to the backups and wait for them to acknowledge it. If a majority is reached, the metadata is committed and a success response is sent back to the proxy. The proxy then forwards the success response to the HTTP client.

When a client performs a GET request, the HTTP proxy requests the list of chunks and their locations to the primary node. The primary node forwards the request to all other backups which acknowledge it. When the majority of servers acknowledge (primary included), the response is sent to the proxy. The proxy then downloads the chunks from their locations and reconstructs the object, which is then sent back to the client over HTTP.

When a client performs a DELETE request, the HTTP proxy sends a DELETE operation to the primary, which forwards it to backups. When a majority of servers acknowledge it, the primary deletes the entry. 

## Testing

### Deterministic Simulation Testing

Testing one of the most important aspects of ToastyFS. Fault tolerant systems must be tested to ensure they are actually capable of handling failures, especially rare ones that is hard to prepare for. To ensure a high degree of certainty, ToastyFS uses **Deterministic Simulation Testing** (DST), the gold standard for distributed system validation.

Generally speaking, simulation testing (deterministic or not) is a way to run a system in an environment that creates a variety of different conditions to see how it reacts. This can be used to check for a system's correctness by aborting the system if incoherent states are reached via assert statements. This makes it possible to determine whether an incoherent state can be reached, but not **why** or **how** it was reached. This is where the deterministic parts comes in.

If the entire simulation is deterministic, running it multiple times will cause the system to evolve in the exact same way, effectively allowing the replaying the causes of the error. Making a simulation deterministic is very hard as any interaction with the outside world needs to be simulated to make it controllable. Note that this includes scheduling: even if nodes in a system send the same exact sequence of messages, the evolution of the system may be completely different due to how each node is scheduled.

### Testing in ToastyFS

ToastyFS uses DST as main form of testing. Running the build script (see [Building](#building)) will produce the `toastyfs_simulation` executable which runs a simulation with 3 server nodes and 3 client nodes which issue random object operations. The entire cluster is simulated in a single process and deterministically. All I/O operations are mocked and a variety of faults are injected pseudo-randomly, such as disk bit flips, network partitions, network delays, node crashes. The cluster configuration and fault injection parameters can trivially be modified in `src/main.c`. The mocking of I/O operations is implemented at the system call level. Each node call mocked version of each system call which interacts with a simplified userspace kernel which routes operations to in-memory disks or in-memory network. Node parallelism is simulated via a non-preemptive userspace scheduler. 