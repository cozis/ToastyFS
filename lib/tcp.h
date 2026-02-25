#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#include "byte_queue.h"

// Abstraction over TCP and TLS sockets.
//
// It works by creating a pool of TCP connections. Connections can be added
// to the pool by connecting to other processes via the tcp_connect() function,
// or by adding them automatically as they arrive from other peers, if the
// pool is configured in listening mode. This allows the same abstraction to
// work for servers, clients, and nodes in a larger network that behave both
// as clients and servers.
//
// It features:
//   - Cross-platform (Windows and Linux)
//   - All I/O is multiplexed, which means slow connections will not stall faster ones.
//   - Input and output buffering
//   - Encryption via TLS (OpenSSL on Linux and SChannel on Windows)

// The TCP structure holds the state of a single instance. It is dynamically
// allocated internally so the caller doesn't need to read its contents.
typedef struct TCP TCP;

// Create an instance of the TCP subsystem. The max_conns argument is the
// maximum number of TCP connection this instance will be able to manage.
TCP *tcp_init(int max_conns);

// Free a TCP subsystem instance. Any resources provided by the subsystem
// will be forcefully released too.
void tcp_free(TCP *tcp);

// Enable a listening interface for this TCP pool. Connections accepted via
// this interface will be plaintext.
int tcp_listen_tcp(TCP *tcp, string addr, uint16_t port);

// Enable a listening interface for this TCP pool. Connections accepted via
// this interface will be encrypted. A single TCP pool may be configured for
// plaintext and encrypted connections at the same time. From the user's
// perspective, the interface from which a connections was accepted is totally
// transparent.
// The cert_file and key_file parameters refer to the certificate file and
// associated private key file to use for encryption, both in PEM format.
int tcp_listen_tls(TCP *tcp, string addr, uint16_t port, string cert_file, string key_file);

// If the TCP pool is configured in TLS mode (tcp_listen_tls was called), this
// function can be used to add an additional certificate. Connecting sockets
// will be able to pick the right certificate by expressing the domain name they
// are expecting to talk to.
int tcp_add_cert(TCP *tcp, string domain, string cert_file, string key_file);

// Add a connection to the TCP pool by establishing one towards the specified
// peer. The addrs array (of size num_addrs) contains the list of IP addresses
// for the host. The TCP pool will try each address one by one until a connection
// is established. If the secure argument is true, the connection will be
// encrypted.
int tcp_connect(TCP *tcp, bool secure, Address *addrs, int num_addrs);

// Forward-declare poll item type. The user must include poll.h (Linux) or
// winsock2.h (Windows) to get this definition (and the definition of poll()
// and WSAPoll()).
struct pollfd;

// Initialize an array of pollfd structures with all the descriptor the pool
// needs to monitor with the associated events. The array is such that the caller
// can then call poll() on it to block execution of the process while the TCP
// pool has no work to be done. The number of items written to the array is
// returned.
// The ptrs array is some state set by the TCP pool to associate metadata to
// each descriptor for internal book-keping.
int tcp_register_events(TCP *tcp, void **ptrs, struct pollfd *pfds, int cap);

// After poll() is called and revents flags are set on the array initialized by
// tcp_register_events, this function can be called to go over the triggered
// events and update the internal state of the TCP pool. The ptrs array should
// be passed in as it was initialized by the tcp_register_events as-is.
void tcp_process_events(TCP *tcp, void **ptrs, struct pollfd *pfds, int num);

// Handle structure representing a TCP connection of the TCP pool. The contents
// should not be interpreted by users.
typedef struct {
    TCP *tcp;
    int  idx;
    int  gen;
} TCP_Handle;

// Flags for the "flags" field in TCP_Event.
enum {
    TCP_EVENT_NEW  = 1<<0,
    TCP_EVENT_HUP  = 1<<1,
    TCP_EVENT_DATA = 1<<2,
};

// See tcp_next_event.
typedef struct {
    int flags;
    TCP_Handle handle;
} TCP_Event;

// After tcp_process_events is called, some new events may be available for the
// user. This function returns the next event in the TCP pool.
//
// If an event is available, true is returned and the event structure is
// initialized with the handle to the connection and flags that identify the
// events that triggered associated to that handle. The events are:
//   TCP_EVENT_NEW:  This connection was just established. It's the first time the
//                   user's code sees it.
//   TCP_EVENT_HUP:  The peer disconnected and therefore the user should close
//                   the connection associated to it.
//   TCP_EVENT_DATA: Some bytes were buffered for this connection.
//                   (It's possible that this event to triggered with 0 new bytes,
//                   for instance if the user called tcp_mark_ready)
// Any of these events may happen at the same time. They are not exclusive.
//
// If no event is available, false is returned.
//
// The general way one would use is function is by doing:
//   tcp_process_events(...)
//   for (TCP_Event event; tcp_next_event(tcp, &event); ) {
//     if (event.flags & TCP_EVENT_NEW) {
//       // ...
//     }
//
//     if (event.flags & TCP_EVENT_DATA) {
//       // ...
//     }
//
//     if (event.flags & TCP_EVENT_HUP) {
//       tcp_close(event.handle);
//     }
//   }
//
// Note that the handle returned by the TCP_EVENT_NEW event
// (and all subsequent events) will be valid until the user
// calls tcp_close() on it.
bool tcp_next_event(TCP *tcp, TCP_Event *event);

// Start a read operation into the TCP connection's input buffer.
//
// This function returns a slice of the input buffer. The user
// may inspect the contents and decide to consume some bytes from
// the buffer by calling tcp_read_ack(handle, num) with the number
// of bytes. Reading the input buffer with this function locks the
// buffer not allowing new bytes to be buffered. For this reason
// tcp_read_ack(handle, 0) must be called even if no bytes were
// consumed.
//
// Note that returned bytes are plaintext regardless of whether
// the connection was accepted via the plaintext or encrypted
// listening interface.
string tcp_read_buf(TCP_Handle handle);

// Complete a read operation into the TCP connection's input buffer.
void tcp_read_ack(TCP_Handle handle, int num);

// Start a write operation into the TCP connection's output buffer.
//
// This function is specular to tcp_read_buf except the user must
// write into the returned slice instead of reading from it.
string tcp_write_buf(TCP_Handle handle);

// Complete a write operation into the TCP connection's output buffer.
// The num argument is the number of bytes written into the slice by
// the user.
void tcp_write_ack(TCP_Handle handle, int num);

// See tcp_write_off
typedef ByteQueueOffset TCP_Offset;

// Returns the offset of the next byte that would be written into the
// output buffer.
//
// This offset is such that removing previous data from the output
// buffer will not invalidate such offset. It's useful to calcuate
// the number of bytes between to offsets of apply operations on
// bytes since a given offset on the buffer.
TCP_Offset tcp_write_off(TCP_Handle handle);

// Writes bytes into the TCP connections' output buffer. It's just
// a shorthand for tcp_write_buf/tcp_write_ack.
void tcp_write(TCP_Handle handle, string data);

// Writes bytes at the specified offset of the output buffer. Note
// that this only overwrites bytes in the buffer and does not grow
// its size, therefore the user must have already inserted some values
// after that offset. Also, the region referred by the offset must
// still be into the buffer and not be read out.
void tcp_patch(TCP_Handle handle, TCP_Offset offset, string data);

// Removes all bytes in the TCP connection's output buffer from the
// specified offset onwards.
void tcp_clear_from_offset(TCP_Handle handle, TCP_Offset offset);

// Close a TCP connection. Previously buffered output bytes will be
// sent out asynchronously.
void tcp_close(TCP_Handle handle);

// Associate an opaque pointer value to this connection. The tcp_get_user_ptr
// can be used to retrieve the pointer at any time.
void tcp_set_user_ptr(TCP_Handle handle, void *user_ptr);

// Retrieve the user pointer associated to a TCP connection. If no user
// pointer was previously set, NULL is returned.
void *tcp_get_user_ptr(TCP_Handle handle);

// Mark the TCP connection as "ready" causing it to be returned once more
// by the tcp_next_event() function with the TCP_EVENT_DATA flag set, even
// if no more data was buffered.
void tcp_mark_ready(TCP_Handle handle);

#endif // TCP_INCLUDED
