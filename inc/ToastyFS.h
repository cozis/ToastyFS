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

//////////////////////////////////////////////////////////////////////////////////
// PRIMARY
//////////////////////////////////////////////////////////////////////////////////

// Instanciate a ToastyFS client object. The "addr" and "port"
// arguments refer to the address and port of the cluster's
// metadata server.
ToastyFS *toasty_connect(ToastyString addr, uint16_t port);

// Release all resources associated to this client
void toasty_disconnect(ToastyFS *toasty);

// Threads can call this function to wake up a thread blocked
// inside "toasty_wait_result".
// Return 0 on success, -1 on error.
int toasty_wakeup(ToastyFS *toasty);

//////////////////////////////////////////////////////////////////////////////////
// BLOCKING API
//////////////////////////////////////////////////////////////////////////////////

// TODO: comment
typedef uint64_t ToastyVersionTag;

// TODO: comment
#define TOASTY_VERSION_TAG_EMPTY ((ToastyVersionTag) 0)

// Write operation flags
#define TOASTY_WRITE_CREATE_IF_MISSING (1 << 0)  // Create file if it doesn't exist

// Creates a directory at the specified path.
// Returns 0 on success, -1 on error.
//
// If the version tag is not NULL, it's used to
// return the version tag associated to the newly
// created file.
int toasty_create_dir(ToastyFS *toasty, ToastyString path,
    ToastyVersionTag *vtag);

// Creates a file with the given chunk size at
// the specified path. Returns 0 on success, -1
// on error. The chunk size can't be 0.
//
// If the version tag is not NULL, it's used to
// return the version tag associated to the newly
// created file.
int toasty_create_file(ToastyFS *toasty, ToastyString path,
    unsigned int chunk_size, ToastyVersionTag *vtag);

// Deletes a file or directory at the specified path.
// Returns 0 on success, -1 on error.
//
// If the version tag is not 0, the file/directory
// is only deleted if the tags match.
int toasty_delete(ToastyFS *toasty, ToastyString path, ToastyVersionTag vtag);

typedef struct {
    char name[128]; // TODO: Implement a proper name length
    bool is_dir;
    ToastyVersionTag vtag;
} ToastyListingEntry;

typedef struct {
    int count;
    ToastyListingEntry *items;
} ToastyListing;

// Lists all files and directories within the given
// path. Returns 0 and fills up the listing argument
// on success, returns -1 on error. The listing is
// a dynamic array that needs to be freed using
// "toasy_free_listing".
//
// If the version tag is not 0, the listing only
// succedes if the tag matches the remote one.
// If the operation succedes, the vtag is set to
// the remote tag.
int toasty_list(ToastyFS *toasty, ToastyString path,
    ToastyListing *listing, ToastyVersionTag *vtag);

// Frees a listing created by "toasty_list".
void toasty_free_listing(ToastyListing *listing);

// Reads "len" bytes at offset "off" from the file at
// the given path. Returns the number of bytes read on
// success, or -1 on error.
//
// If vtag is not NULL, the read only succedes if the
// target version tag matches vtag or vtag was 0. If
// the operation succedes, the version tag is set to
// the remote entity's.
int toasty_read(ToastyFS *toasty, ToastyString path, int off,
    void *dst, int len, ToastyVersionTag *vtag);

// Writes "len" bytes at offset "off" to the file at
// the given path. Returns the number of bytes written
// on success, or -1 on error.
//
// For how vtag works, see toasty_read.
//
// The flags parameter can be set to TOASTY_WRITE_CREATE_IF_MISSING
// to automatically create the file if it doesn't exist. A default
// chunk size of 4096 bytes will be used for the created file.
int toasty_write(ToastyFS *toasty, ToastyString path, int off,
    void *src, int len, ToastyVersionTag *vtag, uint32_t flags);

//////////////////////////////////////////////////////////////////////////////////
// ASYNCHRONOUS API
//////////////////////////////////////////////////////////////////////////////////

// Handle representing a pending operation
typedef uint32_t ToastyHandle;

// Invalid value for a ToastyHandle
#define TOASTY_INVALID ((ToastyHandle) 0)

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
//
// If vtag is not 0, the operation only succedes if the
// tag matches the remote entity's.
ToastyHandle toasty_begin_delete(ToastyFS *toasty, ToastyString path,
    ToastyVersionTag vtag);

// Begins a directory listing operation and returns
// a handle to it. On error, TOASTY_INVALID is returned.
//
// If vtag is not 0, the operation only succedes if the
// tag matches the remote entity's.
ToastyHandle toasty_begin_list(ToastyFS *toasty, ToastyString path, ToastyVersionTag vtag);

// Begins a read operation and returns a handle to it.
// On error, TOASTY_INVALID is returned.
//
// If vtag is not 0, the operation only succedes if the
// tag matches the remote entity's.
ToastyHandle toasty_begin_read(ToastyFS *toasty, ToastyString path,
    int off, void *dst, int len, ToastyVersionTag vtag);

// Begins a write operation and returns a handle to it.
// On error, TOASTY_INVALID is returned. Note that the source
// buffer must be valid until the operation completes.
//
// If vtag is not 0, the operation only succedes if the
// tag matches the remote entity's.
//
// The flags parameter can be set to TOASTY_WRITE_CREATE_IF_MISSING
// to automatically create the file if it doesn't exist. A default
// chunk size of 4096 bytes will be used for the created file.
ToastyHandle toasty_begin_write(ToastyFS *toasty, ToastyString path,
    int off, void *src, int len, ToastyVersionTag vtag, uint32_t flags);

// Associate the pointer "user" to the handle. The user
// pointer will be returned in the ToastyResult when the
// operation compltes.
void toasty_set_user(ToastyFS *toasty, ToastyHandle handle, void *user);

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
    ToastyVersionTag vtag;
    void*            user;
    int              bytes_read; // For read operations: actual number of bytes read
} ToastyResult;

// If the operation specified by "handle" is complete,
// its result is stored in "result" and 0 is returned.
// If the operation is still in progress, 1 is returned.
// On error, -1 is returned. If the handle is TOASTY_INVALID,
// then the result of the first complete operation is
// returned.
// Note that if a result is returned, handles to that
// operation are invalidated.
// The "result" must be freed using "toasty_free_result".
//
// Note:
//   If you call this function in a loop, the state of the
//   operation will not progress. You can't wait for completion
//   by calling this in a loop. You need to use "toasty_wait_result"
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

#define TOASTY_POLL_CAPACITY 514

// TODO: comment
int toasty_process_events(ToastyFS *toasty, void **contexts,
    struct pollfd *polled, int num_polled);

//////////////////////////////////////////////////////////////////////////////////
// THE END
//////////////////////////////////////////////////////////////////////////////////
#endif // TOASTY_INCLUDED
