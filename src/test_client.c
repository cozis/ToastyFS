#ifdef MAIN_TEST

#define QUAKEY_ENABLE_MOCKS
#include <quakey.h>
#include <assert.h>

#include "tcp.h"
#include "test_client.h"

// Helper function to parse address and port from command line
static bool parse_server_addr(int argc, char **argv, char **addr, uint16_t *port)
{
    // Default to metadata server
    *addr = "127.0.0.1";
    *port = 8080;

    for (int i = 0; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--server") || !strcmp(argv[i], "-s")) {
            *addr = argv[i + 1];
            if (i + 2 < argc) {

                errno = 0;
                char *end;
                long val = strtol(argv[i+2], &end, 10);

                if (end == argv[i+2] || *end != '\0' || errno == ERANGE)
                    break;

                if (val < 0 || val > UINT16_MAX)
                    break;

                *port = (uint16_t) val;
                return true;
            }
        }
    }
    return true;
}

int test_client_init(void *state_, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    TestClient *client = state_;

    char *addr;
    uint16_t port;
    parse_server_addr(argc, argv, &addr, &port);

    client->toasty = toasty_connect((ToastyString) { addr, strlen(addr) }, port);
    if (client->toasty == NULL)
        return -1;

    client->state = TEST_CLIENT_STATE_INIT;
    client->tick  = 0;
    client->tests_passed = 0;

    printf("Client set up (remote=%s:%d)\n", addr, port);
    fflush(stdout);

    *timeout = -1;
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, *pnum);
    return 0;
}

// Static test data
static char lorem_ipsum[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
    "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
    "in reprehenderit in voluptate velit esse cillum dolore eu fugiat "
    "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
    "sunt in culpa qui officia deserunt mollit anim id est laborum.";

static char short_msg[] = "Hello World!";
static char offset_msg[] = "INSERTED_DATA";
static char truncate_msg[] = "Truncated content";

// Test path constants
static ToastyString file_path = TOASTY_STR("some_file.txt");
static ToastyString dir_path = TOASTY_STR("/testdir");
static ToastyString subdir_path = TOASTY_STR("/testdir/subdir");
static ToastyString file_in_dir_path = TOASTY_STR("/testdir/nested_file.txt");
static ToastyString auto_create_path = TOASTY_STR("/auto_created_file.txt");
static ToastyString truncate_file_path = TOASTY_STR("/truncate_test.txt");
static ToastyString offset_file_path = TOASTY_STR("/offset_test.txt");

#define TEST_PASS(name) do { \
    client->tests_passed++; \
    printf("Test PASSED: %s\n", name); \
    fflush(stdout); \
} while(0)

#define TEST_FAIL(name) do { \
    printf("Test FAILED: %s\n", name); \
    fflush(stdout); \
    exit(1); \
} while(0)

int test_client_tick(void *state_, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    TestClient *client = state_;

    // Process any pending events from the network and get new poll descriptors
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, *pnum);

    int ret;
    ToastyResult result;

    switch (client->state) {

    //==========================================================================
    // PHASE 1: Basic file create/write/read test
    //==========================================================================
    case TEST_CLIENT_STATE_INIT:
        if (client->tick < 10) {
            *timeout = 0;
            client->tick++;
            return 0;
        }
        printf("\n=== Phase 1: Basic file operations ===\n");
        client->handle = toasty_begin_create_file(client->toasty, file_path, 128);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create file");
        }
        printf("Create file started\n");
        client->state = TEST_CLIENT_STATE_CREATE_FILE_WAIT;
        break;

    case TEST_CLIENT_STATE_CREATE_FILE_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create file");
        if (ret == 1) break;  // Still in progress
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create file result");
        }
        TEST_PASS("Create file");
        toasty_free_result(&result);

        // Start write
        client->handle = toasty_begin_write(client->toasty, file_path, 0,
            lorem_ipsum, sizeof(lorem_ipsum)-1, TOASTY_VERSION_TAG_EMPTY, 0);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin write");
        }
        printf("Write started\n");
        client->state = TEST_CLIENT_STATE_WRITE_WAIT;
        break;

    case TEST_CLIENT_STATE_WRITE_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for write");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
            TEST_FAIL("write result");
        }
        TEST_PASS("Write data");
        toasty_free_result(&result);

        // Start read
        client->handle = toasty_begin_read(client->toasty, file_path, 0,
            client->buf, sizeof(client->buf), TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin read");
        }
        printf("Read started\n");
        client->state = TEST_CLIENT_STATE_READ_WAIT;
        break;

    case TEST_CLIENT_STATE_READ_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for read");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_READ_SUCCESS) {
            TEST_FAIL("read result type");
        }
        if (result.bytes_read != sizeof(lorem_ipsum)-1) {
            printf("Expected %zu bytes, got %d\n", sizeof(lorem_ipsum)-1, result.bytes_read);
            TEST_FAIL("read bytes count");
        }
        if (memcmp(client->buf, lorem_ipsum, sizeof(lorem_ipsum)-1)) {
            TEST_FAIL("read data mismatch");
        }
        TEST_PASS("Read data matches written data");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_CREATE_DIR;
        *timeout = 0;  // Trigger immediate next iteration
        return 0;

    //==========================================================================
    // PHASE 2: Directory operations
    //==========================================================================
    case TEST_CLIENT_STATE_CREATE_DIR:
        printf("\n=== Phase 2: Directory operations ===\n");
        client->handle = toasty_begin_create_dir(client->toasty, dir_path);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create dir");
        }
        printf("Create directory started\n");
        client->state = TEST_CLIENT_STATE_CREATE_DIR_WAIT;
        break;

    case TEST_CLIENT_STATE_CREATE_DIR_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create dir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create dir result");
        }
        TEST_PASS("Create directory");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_CREATE_SUBDIR;
        *timeout = 0; return 0;

    case TEST_CLIENT_STATE_CREATE_SUBDIR:
        client->handle = toasty_begin_create_dir(client->toasty, subdir_path);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create subdir");
        }
        printf("Create subdirectory started\n");
        client->state = TEST_CLIENT_STATE_CREATE_SUBDIR_WAIT;
        break;

    case TEST_CLIENT_STATE_CREATE_SUBDIR_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create subdir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create subdir result");
        }
        TEST_PASS("Create subdirectory");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_CREATE_FILE_IN_DIR;
        *timeout = 0; return 0;

    case TEST_CLIENT_STATE_CREATE_FILE_IN_DIR:
        client->handle = toasty_begin_create_file(client->toasty, file_in_dir_path, 256);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create file in dir");
        }
        printf("Create file in directory started\n");
        client->state = TEST_CLIENT_STATE_CREATE_FILE_IN_DIR_WAIT;
        break;

    case TEST_CLIENT_STATE_CREATE_FILE_IN_DIR_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create file in dir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create file in dir result");
        }
        TEST_PASS("Create file in directory");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_LIST_DIR;
        *timeout = 0; return 0;

    case TEST_CLIENT_STATE_LIST_DIR:
        client->handle = toasty_begin_list(client->toasty, dir_path, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin list dir");
        }
        printf("List directory started\n");
        client->state = TEST_CLIENT_STATE_LIST_DIR_WAIT;
        break;

    case TEST_CLIENT_STATE_LIST_DIR_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for list dir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_LIST_SUCCESS) {
            TEST_FAIL("list dir result type");
        }
        printf("Directory listing count: %d\n", result.listing.count);
        // Directory should contain subdir and nested_file.txt
        if (result.listing.count != 2) {
            printf("Expected 2 entries, got %d\n", result.listing.count);
            TEST_FAIL("list dir count");
        }
        // Print the entries
        for (int i = 0; i < result.listing.count; i++) {
            printf("  Entry %d: %s (is_dir=%d)\n", i,
                result.listing.items[i].name,
                result.listing.items[i].is_dir);
        }
        TEST_PASS("List directory");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_LIST_ROOT;
        *timeout = 0; return 0;

    case TEST_CLIENT_STATE_LIST_ROOT:
        client->handle = toasty_begin_list(client->toasty, TOASTY_STR("/"), TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin list root");
        }
        printf("List root directory started\n");
        client->state = TEST_CLIENT_STATE_LIST_ROOT_WAIT;
        break;

    case TEST_CLIENT_STATE_LIST_ROOT_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for list root");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_LIST_SUCCESS) {
            TEST_FAIL("list root result type");
        }
        printf("Root listing count: %d\n", result.listing.count);
        for (int i = 0; i < result.listing.count; i++) {
            printf("  Entry %d: %s (is_dir=%d)\n", i,
                result.listing.items[i].name,
                result.listing.items[i].is_dir);
        }
        // Root should have some entries at this point
        if (result.listing.count < 1) {
            TEST_FAIL("list root count");
        }
        TEST_PASS("List root directory");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING;
        *timeout = 0; return 0;

    //==========================================================================
    // PHASE 3: Write flags tests
    //==========================================================================
    case TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING:
        printf("\n=== Phase 3: Additional write tests ===\n");
        // Create a file for testing additional writes
        client->handle = toasty_begin_create_file(client->toasty, auto_create_path, 256);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create auto file");
        }
        printf("Create auto file started\n");
        client->state = TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING_WAIT;
        break;

    case TEST_CLIENT_STATE_WRITE_CREATE_IF_MISSING_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create auto file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create auto file result");
        }
        TEST_PASS("Create auto file");
        toasty_free_result(&result);

        // Now write to the file
        client->handle = toasty_begin_write(client->toasty, auto_create_path, 0,
            short_msg, sizeof(short_msg)-1, TOASTY_VERSION_TAG_EMPTY, 0);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin write to auto file");
        }
        printf("Write to auto file started\n");
        client->state = TEST_CLIENT_STATE_READ_CREATED_FILE;
        break;

    case TEST_CLIENT_STATE_READ_CREATED_FILE:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for write to auto file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
            TEST_FAIL("write to auto file result");
        }
        TEST_PASS("Write to auto file");
        toasty_free_result(&result);

        // Read back the file
        memset(client->buf, 0, sizeof(client->buf));
        client->handle = toasty_begin_read(client->toasty, auto_create_path, 0,
            client->buf, sizeof(client->buf), TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin read auto file");
        }
        printf("Read auto file started\n");
        client->state = TEST_CLIENT_STATE_READ_CREATED_FILE_WAIT;
        break;

    case TEST_CLIENT_STATE_READ_CREATED_FILE_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for read auto file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_READ_SUCCESS) {
            TEST_FAIL("read auto file result type");
        }
        if (result.bytes_read != sizeof(short_msg)-1) {
            printf("Expected %zu bytes, got %d\n", sizeof(short_msg)-1, result.bytes_read);
            TEST_FAIL("read auto file bytes count");
        }
        if (memcmp(client->buf, short_msg, sizeof(short_msg)-1)) {
            TEST_FAIL("read auto file data mismatch");
        }
        TEST_PASS("Read auto file");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_WRITE_TRUNCATE;
        *timeout = 0; return 0;

    case TEST_CLIENT_STATE_WRITE_TRUNCATE:
        // Create a file for testing multiple writes
        client->handle = toasty_begin_create_file(client->toasty, truncate_file_path, 256);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create multi-write file");
        }
        printf("Create multi-write test file started\n");
        client->state = TEST_CLIENT_STATE_WRITE_TRUNCATE_WAIT;
        break;

    case TEST_CLIENT_STATE_WRITE_TRUNCATE_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create multi-write file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create multi-write file result");
        }
        TEST_PASS("Create multi-write file");
        toasty_free_result(&result);

        // Write initial content
        client->handle = toasty_begin_write(client->toasty, truncate_file_path, 0,
            lorem_ipsum, sizeof(lorem_ipsum)-1, TOASTY_VERSION_TAG_EMPTY, 0);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin write multi-write content");
        }
        printf("Write multi-write content started\n");
        client->state = TEST_CLIENT_STATE_READ_TRUNCATED;
        break;

    case TEST_CLIENT_STATE_READ_TRUNCATED:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for write multi-write content");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
            TEST_FAIL("write multi-write content result");
        }
        TEST_PASS("Write multi-write content");
        toasty_free_result(&result);

        // Read back the file
        memset(client->buf, 0, sizeof(client->buf));
        client->handle = toasty_begin_read(client->toasty, truncate_file_path, 0,
            client->buf, sizeof(client->buf), TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin read multi-write file");
        }
        printf("Read multi-write file started\n");
        client->state = TEST_CLIENT_STATE_READ_TRUNCATED_WAIT;
        break;

    case TEST_CLIENT_STATE_READ_TRUNCATED_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for read multi-write file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_READ_SUCCESS) {
            TEST_FAIL("read multi-write file result type");
        }
        if (result.bytes_read != sizeof(lorem_ipsum)-1) {
            printf("Expected %zu bytes, got %d\n", sizeof(lorem_ipsum)-1, result.bytes_read);
            TEST_FAIL("read multi-write file bytes count");
        }
        TEST_PASS("Read multi-write file");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_WRITE_AT_OFFSET;
        *timeout = 0; return 0;

    //==========================================================================
    // PHASE 4: Offset read/write tests
    //==========================================================================
    case TEST_CLIENT_STATE_WRITE_AT_OFFSET:
        printf("\n=== Phase 4: Offset read/write tests ===\n");
        // Create a new file for offset testing with larger chunk size
        client->handle = toasty_begin_create_file(client->toasty, offset_file_path, 256);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin create offset file");
        }
        printf("Create offset test file started\n");
        client->state = TEST_CLIENT_STATE_WRITE_AT_OFFSET_WAIT;
        break;

    case TEST_CLIENT_STATE_WRITE_AT_OFFSET_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for create offset file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
            TEST_FAIL("create offset file result");
        }
        TEST_PASS("Create offset file");
        toasty_free_result(&result);

        // Write initial data (small amount)
        client->handle = toasty_begin_write(client->toasty, offset_file_path, 0,
            short_msg, sizeof(short_msg)-1, TOASTY_VERSION_TAG_EMPTY, 0);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin write initial offset data");
        }
        printf("Write initial offset data started\n");
        client->state = TEST_CLIENT_STATE_READ_AT_OFFSET;
        break;

    case TEST_CLIENT_STATE_READ_AT_OFFSET:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for write initial offset");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_WRITE_SUCCESS) {
            TEST_FAIL("write initial offset result");
        }
        TEST_PASS("Write initial offset data");
        toasty_free_result(&result);

        // Read from the beginning to verify
        memset(client->buf, 0, sizeof(client->buf));
        client->handle = toasty_begin_read(client->toasty, offset_file_path, 0,
            client->buf, sizeof(short_msg)-1, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin read offset file");
        }
        printf("Read offset file started\n");
        client->state = TEST_CLIENT_STATE_READ_AT_OFFSET_WAIT;
        break;

    case TEST_CLIENT_STATE_READ_AT_OFFSET_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for read offset file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_READ_SUCCESS) {
            TEST_FAIL("read offset file result type");
        }
        if (result.bytes_read != sizeof(short_msg)-1) {
            printf("Expected %zu bytes, got %d\n", sizeof(short_msg)-1, result.bytes_read);
            TEST_FAIL("read offset file bytes count");
        }
        TEST_PASS("Read offset file");
        toasty_free_result(&result);
        client->state = TEST_CLIENT_STATE_DELETE_FILE;
        *timeout = 0; return 0;

    //==========================================================================
    // PHASE 5: Delete operations
    //==========================================================================
    case TEST_CLIENT_STATE_DELETE_FILE:
        printf("\n=== Phase 5: Delete operations ===\n");
        // Delete the auto-created file
        client->handle = toasty_begin_delete(client->toasty, auto_create_path, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin delete file");
        }
        printf("Delete auto file started\n");
        client->state = TEST_CLIENT_STATE_DELETE_FILE_WAIT;
        break;

    case TEST_CLIENT_STATE_DELETE_FILE_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for delete file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_DELETE_SUCCESS) {
            TEST_FAIL("delete file result");
        }
        TEST_PASS("Delete file");
        toasty_free_result(&result);

        // Delete the nested file first (before deleting directory)
        client->handle = toasty_begin_delete(client->toasty, file_in_dir_path, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin delete nested file");
        }
        printf("Delete nested file started\n");
        client->state = TEST_CLIENT_STATE_DELETE_DIR;
        break;

    case TEST_CLIENT_STATE_DELETE_DIR:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for delete nested file");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_DELETE_SUCCESS) {
            TEST_FAIL("delete nested file result");
        }
        TEST_PASS("Delete nested file");
        toasty_free_result(&result);

        // Delete the subdirectory
        client->handle = toasty_begin_delete(client->toasty, subdir_path, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin delete subdir");
        }
        printf("Delete subdirectory started\n");
        client->state = TEST_CLIENT_STATE_DELETE_DIR_WAIT;
        break;

    case TEST_CLIENT_STATE_DELETE_DIR_WAIT:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for delete subdir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_DELETE_SUCCESS) {
            TEST_FAIL("delete subdir result");
        }
        TEST_PASS("Delete subdirectory");
        toasty_free_result(&result);

        // Delete the parent directory
        client->handle = toasty_begin_delete(client->toasty, dir_path, TOASTY_VERSION_TAG_EMPTY);
        if (client->handle == TOASTY_INVALID) {
            TEST_FAIL("begin delete dir");
        }
        printf("Delete directory started\n");
        client->state = TEST_CLIENT_STATE_DONE;
        break;

    case TEST_CLIENT_STATE_DONE:
        ret = toasty_get_result(client->toasty, client->handle, &result);
        if (ret < 0) TEST_FAIL("get result for delete dir");
        if (ret == 1) break;
        if (result.type != TOASTY_RESULT_DELETE_SUCCESS) {
            TEST_FAIL("delete dir result");
        }
        TEST_PASS("Delete directory");
        toasty_free_result(&result);

        printf("\n========================================\n");
        printf("All %d tests PASSED!\n", client->tests_passed);
        printf("========================================\n");
        exit(0);
    }

    *timeout = -1;
    if (pcap < TCP_POLL_CAPACITY)
        return -1;
    *pnum = toasty_process_events(client->toasty, ctxs, pdata, 0);
    return 0;
}

int test_client_free(void *state_)
{
    TestClient *client = state_;

    toasty_disconnect(client->toasty);
    return 0;
}

#endif // MAIN_TEST
