# ToastyFS
ToastyFS is a distributed file system designed for self-hosting, so it aims to be pragmatic, understandable, and robust. You can use ToastyFS to store your files reliably over multiple machines knowing they will be automatically replicated and healed in case of failures.

To try it out, run the script `./scripts/cluster_demo.sh`. It will spawn a local cluster with a web interface at `https://127.0.0.1:8090/` which will allow you to PUT, GET, DELETE files.

⚠️ Note that ToastyFS is still in early development ⚠️

🎵 Now let's get toasty 🎵

## Features

- Cross-platform (runs on Windows and Linux)
- Automatic Replication & Self-Healing
- Automatic content deduplication via internal content-addressing
- Configurable file chunk sizes
- Small and understandable

But ToastyFS is still in early development, so here are the missing features:

- No master replication
- No authentication or encryption

## Testing
ToastyFS is tested by running an in-memory simulation of a cluster with many clients running hundreds of random operations in parallel. The test is run for long periods of times under valgrind or compiled with sanitizers.
