# ToastyFS

ToastyFS is a simple, fault-tolerant, highly available object storage.

Features
* Deterministic Simulation Testing
* Cross-Platform (Windows, Linux)
* Minimal Dependencies (OpenSSL and SChannel)
* Viewstamped Replication

## Quick Start

You can try ToastyFS by building it using one of the provided scripts

```
# Windows
.\build.bat

# Linux
./build.sh
```

You can then start a ToastyFS cluster by running the cluster script. If you are on Windows, you will need a Linux-compatible shell to run it.

```
./cluster.sh start
./cluster.sh status
```

The cluster is composed of 3 nodes and 1 HTTP proxy listening on `127.0.0.1:3000`.

Let's create an object
```
$ curl -X PUT http://127.0.0.1:3000/first_object -d "I'm the first object"
$ curl -X GET http://127.0.0.1:3000/first_object
I'm the first object
```

That's it! You can now turn the cluster off

```
./cluster.sh stop
```

## Fault Tolerance and High Availability

ToastyFS achieves fault tolerance and high availability by replicating all state on multiple nodes in such a way that if a node dies, another one can take its place with no loss of information. As long as a majority of nodes are running, the cluster will be available. ToastyFS uses Viewstamped Replication (VSR), which is an alternative to Raft.

An advantage of VSR over other consensus/replication protocols is that it does not rely on stable storage, which means it can recover from scenarios where the disk stops working. This is generally not true for systems based on Raft, for instance.

## Testing

Since ToastyFS is expected to never lose data and implements complex algorithms to do so, it is essential for it to be well tested. For this reason ToastyFS uses the golden standard for testing distributed systems, **Deterministic Simulation Testing** (DST).

DST consists of running the system in a completely deterministic simulation with the system serving a number of different operations and the injections of faults (network partitions, allocation failures, latency spikes, node crashes). Events are generated pseudo-randomly from a seed value, which means a large amount of scenarios can be tested by varying that seed. Once a bug is found, that specific scenario that caused it can be replayed indefinitely by running simulations with the same seed.

## Motivations

I initially started this project to learn about distributed systems. I asked myself what it would take to build my own Dropbox. A rabbit-hole later and here is my distributed storage system!

## Project Status

This project should be considered a robust proof-of-concept at this time. Features that would be required for long-running instances are missing, such as:

* Log compaction
* Log persistence on disk

If a majority of nodes is turned off, the system's state will be lost. This is in accordance with disk-free version of the Viewstamped Replication protocol.
