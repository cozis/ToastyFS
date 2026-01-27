#ifndef TEST_CLIENT_INCLUDED
#define TEST_CLIENT_INCLUDED

#include "ToastyFS.h"

typedef enum {
    // Basic file create/write/read test (existing)
    TEST_CLIENT_STATE_INIT,
    TEST_CLIENT_STATE_CREATE_FILE_WAIT,
    TEST_CLIENT_STATE_WRITE_WAIT,
    TEST_CLIENT_STATE_READ_WAIT,

    // Directory tests
    TEST_CLIENT_STATE_CREATE_DIR,
    TEST_CLIENT_STATE_CREATE_DIR_WAIT,
    TEST_CLIENT_STATE_CREATE_SUBDIR,
    TEST_CLIENT_STATE_CREATE_SUBDIR_WAIT,
    TEST_CLIENT_STATE_CREATE_FILE_IN_DIR,
    TEST_CLIENT_STATE_CREATE_FILE_IN_DIR_WAIT,
    TEST_CLIENT_STATE_LIST_DIR,
    TEST_CLIENT_STATE_LIST_DIR_WAIT,
    TEST_CLIENT_STATE_LIST_ROOT,
    TEST_CLIENT_STATE_LIST_ROOT_WAIT,

    // Delete tests
    TEST_CLIENT_STATE_DELETE_FILE,
    TEST_CLIENT_STATE_DELETE_FILE_WAIT,
    TEST_CLIENT_STATE_DELETE_DIR,
    TEST_CLIENT_STATE_DELETE_DIR_WAIT,

    // Write flags tests
    TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING,
    TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING_WAIT,
    TEST_CLIENT_STATE_READ_CREATED_FILE,
    TEST_CLIENT_STATE_READ_CREATED_FILE_WAIT,
    TEST_CLIENT_STATE_WRITE_TRUNCATE,
    TEST_CLIENT_STATE_WRITE_TRUNCATE_WAIT,
    TEST_CLIENT_STATE_READ_TRUNCATED,
    TEST_CLIENT_STATE_READ_TRUNCATED_WAIT,

    // Offset read/write tests
    TEST_CLIENT_STATE_WRITE_AT_OFFSET,
    TEST_CLIENT_STATE_WRITE_AT_OFFSET_WAIT,
    TEST_CLIENT_STATE_READ_AT_OFFSET,
    TEST_CLIENT_STATE_READ_AT_OFFSET_WAIT,

    // Test done
    TEST_CLIENT_STATE_DONE,
} TestClientState;

typedef struct {
    ToastyFS*       toasty;
    ToastyHandle    handle;
    TestClientState state;
    int  tick;
    int  tests_passed;
    char buf[1<<10];
    char buf2[1<<10];  // Secondary buffer for additional reads
} TestClient;

struct pollfd;

int test_client_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int test_client_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int test_client_free(void *state);

#endif // TEST_CLIENT_INCLUDED