# ToastyFS
ToastyFS is a distributed file system designed for self-hosting, so it aims to be pragmatic, understandable, and robust. You can use ToastyFS to store your files reliably over multiple machines knowing they will be automatically replicated and healed in case of hardware failure. ToastyFS works by running nodes on multiple machines. Clients using the ToastyFS C library can then send file operations to the cluster. Here's a quick example:

```c
#include <ToastyFS.h>

int main(void)
{
    ToastyString addr = TOASTY_STR("127.0.0.1");
    int          port = 8080;
    ToastyString file = TOASTY_STR("/my_file.txt");
    
    // Connect to cluster
    ToastyFS *toasty = toasty_connect(addr, port);
    
    // Create and write to a file
    toasty_create_file(toasty, file, 4096);
    toasty_write(toasty, file, 0, "Hello!", 6);
    
    // Read it back
    char buf[6];
    toasty_read(toasty, file, 0, buf, 6);
    
    // Done!
    toasty_disconnect(toasty);
    return 0;
}
```

⚠️ Note that ToastyFS is still in early development ⚠️

🎵 Now let's get toasty 🎵

## Features

- Cross-platform (runs on Windows and Linux)
- Automatic Replication & Self-Healing
- Automatic content deduplication: File contents are de-duplicated automatically with content-addressing.
- Configurable chunk sizes: Each file can have different chunk size optimized for its use case
- Zero dependencies: Pure C implementation with no external libraries

But ToastyFS is still in early development, so here are the missing features:

- No master replication
- No authentication or encryption

## Testing
ToastyFS is tested by running an in-memory simulation of a cluster with many clients running hundreds of random operations in parallel. The test is run for long periods of times under valgrind or compiled with sanitizers.
