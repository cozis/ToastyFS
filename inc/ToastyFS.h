#ifndef TOASTY_INCLUDED
#define TOASTY_INCLUDED
//////////////////////////////////////////////////////////////////////////////////
// INCLUDES
//////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdbool.h>

// Get the definition of "struct pollfd"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

//////////////////////////////////////////////////////////////////////////////////
// TYPES & UTILITIES
//////////////////////////////////////////////////////////////////////////////////

typedef struct ToastyFS ToastyFS;

// Helper type to avoid zero-terminated strings
typedef struct {
    char *ptr;
    int   len;
} ToastyString;

// Macro to convert string literals to ToastyStrings
#define TOASTY_STR(X) ((ToastyString) { (X), (int) sizeof(X)-1 })

// Handle representing a pending operation
typedef uint32_t ToastyHandle;

// Invalid value for a ToastyHandle
#define TOASTY_INVALID ((ToastyHandle) 0)

typedef struct {
    char name[128]; // TODO: Implement a proper name length
    bool is_dir;
} ToastyListingEntry;

typedef struct {
    int count;
    ToastyListingEntry *items;
} ToastyListing;

typedef enum {
    TOASTY_RESULT_EMPTY,
    TOASTY_RESULT_CREATE_ERROR,
    TOASTY_RESULT_CREATE_SUCCESS,
    TOASTY_RESULT_DELETE_ERROR,
    TOASTY_RESULT_DELETE_SUCCESS,
    TOASTY_RESULT_LIST_ERROR,
    TOASTY_RESULT_LIST_SUCCESS,
    TOASTY_RESULT_READ_ERROR,
    TOASTY_RESULT_READ_SUCCESS,
    TOASTY_RESULT_WRITE_ERROR,
    TOASTY_RESULT_WRITE_SUCCESS,
} ToastyResultType;

typedef struct {
    ToastyResultType type;
    ToastyListing    listing;
} ToastyResult;

// Instanciate a ToastyFS client object. The "addr" and "port"
// arguments refer to the address and port of the cluster's
// metadata server.
ToastyFS *toasty_connect(ToastyString addr, uint16_t port);

// Release all resources associated to this client
void toasty_disconnect(ToastyFS *toasty);

//////////////////////////////////////////////////////////////////////////////////
// BLOCKING API
//////////////////////////////////////////////////////////////////////////////////

// Creates a directory at the specified path.
// Returns 0 on success, -1 on error.
int toasty_create_dir(ToastyFS *toasty, ToastyString path);

// Creates a file with the given chunk size at
// the specified path. Returns 0 on success, -1
// on error. The chunk size can't be 0.
int toasty_create_file(ToastyFS *toasty, ToastyString path,
    unsigned int chunk_size);

// Deletes a file or directory at the specified path.
// Returns 0 on success, -1 on error.
int toasty_delete(ToastyFS *toasty, ToastyString path);

// Lists all files and directories within the given
// path. Returns 0 and fills up the listing argument
// on success, returns -1 on error. The listing is
// a dynamic array that needs to be freed using
// "toasy_free_listing".
int toasty_list(ToastyFS *toasty, ToastyString path,
    ToastyListing *listing);

// Frees a listing created by "toasty_list".
void toasty_free_listing(ToastyListing *listing);

// Reads "len" bytes at offset "off" from the file at
// the given path. Returns the number of bytes read on
// success, or -1 on error.
int toasty_read(ToastyFS *toasty, ToastyString path, int off,
    void *dst, int len);

// Writes "len" bytes at offset "off" to the file at
// the given path. Returns the number of bytes written
// on success, or -1 on error.
int toasty_write(ToastyFS *toasty, ToastyString path, int off,
    void *src, int len);

//////////////////////////////////////////////////////////////////////////////////
// ASYNCHRONOUS API
//////////////////////////////////////////////////////////////////////////////////

// Begins a directory creation operation and returns
// a handle to it. On error, TOASTY_INVALID is returned.
ToastyHandle toasty_begin_create_dir(ToastyFS *toasty, ToastyString path);

// Begins a file creation operation and returns a
// handle to it. On error, TOASTY_INVALID is returned.
ToastyHandle toasty_begin_create_file(ToastyFS *toasty, ToastyString path,
    unsigned int chunk_size);

// Begins a file or directory deletion operation and
// returns a handle to it. On error, TOASTY_INVALID is
// returned.
ToastyHandle toasty_begin_delete(ToastyFS *toasty, ToastyString path);

// Begins a directory listing operation and returns
// a handle to it. On error, TOASTY_INVALID is returned.
ToastyHandle toasty_begin_list(ToastyFS *toasty, ToastyString path);

// Begins a read operation and returns a handle to it.
// On error, TOASTY_INVALID is returned.
ToastyHandle toasty_begin_read(ToastyFS *toasty, ToastyString path,
    int off, void *dst, int len);

// Begins a write operation and returns a handle to it.
// On error, TOASTY_INVALID is returned. Note that the source
// buffer must be valid until the operation completes.
ToastyHandle toasty_begin_write(ToastyFS *toasty, ToastyString path,
    int off, void *src, int len);

// If the operation specified by "handle" is complete,
// its result is stored in "result" and 0 is returned.
// If the operation is still in progress, 1 is returned.
// On error, -1 is returned. If the handle is TOASTY_INVALID,
// then the result of the first complete operation is
// returned.
// Note that if a result is returned, handles to that
// operation are invalidated.
// The "result" must be freed using "toasty_free_result".
int toasty_get_result(ToastyFS *toasty, ToastyHandle handle,
    ToastyResult *result);

// Blocks execution until an operation is complete. This works
// like "toasty_get_result", except it waits for "timeout" milliseconds
// if the result isn't available. If "timeout" is -1, it waits
// indefinitely.
// The "result" must be freed using "toasty_free_result".
int toasty_wait_result(ToastyFS *toasty, ToastyHandle handle,
    ToastyResult *result, int timeout);

// Frees resources of a "ToastyResult" previously initialized
// by "toasty_get_result" or "toasty_wait_result".
void toasty_free_result(ToastyResult *result);

//////////////////////////////////////////////////////////////////////////////////
// OTHER
//////////////////////////////////////////////////////////////////////////////////

// This is a hook for the simulation testing framework.
// You shouldn't need to use this.
int toasty_process_events(ToastyFS *toasty, void **contexts,
    struct pollfd *polled, int num_polled);

//////////////////////////////////////////////////////////////////////////////////
// THE END
//////////////////////////////////////////////////////////////////////////////////
#endif // TOASTY_INCLUDED
