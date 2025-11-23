#include <ToastyFS.h>

#include "chttp.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

#define UNREACHABLE __builtin_trap()

#define MAX_PROXIED_OPERATIONS (1<<10)

typedef enum {
    PROXIED_OPERATION_FREE,
    PROXIED_OPERATION_CREATE_DIR,
    PROXIED_OPERATION_CREATE_FILE,
    PROXIED_OPERATION_DELETE,
    PROXIED_OPERATION_READ_DIR,
    PROXIED_OPERATION_READ_FILE,
    PROXIED_OPERATION_WRITE,
} ProxiedOperationType;

typedef struct {
    ProxiedOperationType type;

    // Don't write the content to the response
    // when reading a file or directory.
    bool head_only;

    // Offset of the read/write
    int offset;

    // Length of the read/write
    int length;

    // Number of bytes read/written
    int transferred;

    HTTP_Request *request; // TODO: is it okay to store this pointer?
    HTTP_ResponseBuilder builder;

    ToastyHandle handle;

} ProxiedOperation;

static int find_unused_struct(ProxiedOperation *arr, int num)
{
    if (num == MAX_PROXIED_OPERATIONS)
        return -1;
    int i = 0;
    while (arr[i].type != PROXIED_OPERATION_FREE) {
        i++;
        assert(i < MAX_PROXIED_OPERATIONS);
    }
    return i;
}

int main(int argc, char **argv)
{
    ToastyString upstream_addr = TOASTY_STR("127.0.0.1");
    uint16_t     upstream_port = 9000;

    HTTP_String  local_addr = HTTP_STR("127.0.0.1");
    uint16_t     local_port = 8080;

    for (int i = 1; i < argc; i++) {

        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("TODO: print help\n");
            return 0;
        }

        if (!strcmp(argv[i], "--upstream-addr")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                return -1;
            }
            upstream_addr = (ToastyString) { argv[i], strlen(argv[i]) };

        } else if (!strcmp(argv[i], "--upstream-port")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                return -1;
            }
            int tmp = atoi(argv[i]);
            if (tmp < 1 || tmp > UINT16_MAX) {
                fprintf(stderr, "Error: Invalid port %s\n", argv[i]);
                return -1;
            }
            upstream_port = (uint16_t) tmp;

        } else if (!strcmp(argv[i], "--local-addr")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                return -1;
            }
            local_addr = (HTTP_String) { argv[i], strlen(argv[i]) };

        } else if (!strcmp(argv[i], "--local-port")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                return -1;
            }
            int tmp = atoi(argv[i]);
            if (tmp < 1 || tmp > UINT16_MAX) {
                fprintf(stderr, "Error: Invalid port %s\n", argv[i]);
                return -1;
            }
            local_port = (uint16_t) tmp;
        } else {
            fprintf(stderr, "Error: Invalid option %s\n", argv[i]);
            return -1;
        }
    }

    ToastyFS *toasty = toasty_connect(upstream_addr, upstream_port);
    if (toasty == NULL) {
        printf("toasty_connect error\n");
        return -1;
    }

    HTTP_Server server;
    if (http_server_init(&server) < 0) {
        printf("http_server_init error\n");
        return -1;
    }

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    if (http_server_listen_tcp(&server, local_addr, local_port) < 0) {
        printf("http_server_listen_tcp error\n");
        return -1;
    }

    int num_proxied = 0;
    ProxiedOperation proxied[MAX_PROXIED_OPERATIONS];

    for (int i = 0; i < MAX_PROXIED_OPERATIONS; i++)
        proxied[i].type = PROXIED_OPERATION_FREE;

    for (;;) {

        #define POLL_CAPACITY (HTTP_SERVER_POLL_CAPACITY + TOASTY_POLL_CAPACITY)

        EventRegister reg;
        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        void **http_ptrs = ptrs;
        struct pollfd *http_polled = polled;

        reg = (EventRegister) {
            .ptrs=ptrs,
            .polled=polled,
            .max_polled=HTTP_SERVER_POLL_CAPACITY,
            .num_polled=0,
        };
        if (http_server_register_events(&server, &reg) < 0) {
            printf("http_server_register_events error\n");
            return -1;
        }
        int num_http_polled = reg.num_polled;

        void **toasty_ptrs = ptrs + num_http_polled;
        struct pollfd *toasty_polled = polled + num_http_polled;
        int num_toasty_polled = toasty_process_events(toasty, toasty_ptrs, toasty_polled, 0);
        if (num_toasty_polled < 0)
            return -1;

        int num_polled = num_http_polled + num_toasty_polled;
        if (num_polled > 0)
            POLL(polled, num_polled, -1);

        // First, process toasty events so that we free space
        // for incoming requests

        if (toasty_process_events(toasty, toasty_ptrs, toasty_polled, num_toasty_polled) < 0)
            return -1;

        for (;;) {

            ToastyResult result;
            int ret = toasty_get_result(toasty, TOASTY_INVALID, &result);

            if (ret == 1)
                break; // No completion

            if (ret < 0)
                return -1; // Error

            // Completed
            assert(ret == 0);

            int i = (ProxiedOperation*) result.user - proxied;
            assert(i > -1 && i < MAX_PROXIED_OPERATIONS);

            switch (proxied[i].type) {
            case PROXIED_OPERATION_CREATE_DIR:
            case PROXIED_OPERATION_CREATE_FILE:
                {
                    if (result.type == TOASTY_RESULT_CREATE_SUCCESS) {
                        http_response_builder_status(proxied[i].builder, 201); // Created
                        http_response_builder_send(proxied[i].builder);
                    } else {
                        // TODO: Should differentiate between error conditions
                        http_response_builder_status(proxied[i].builder, 500); // Internal Server Error
                        http_response_builder_send(proxied[i].builder);
                    }
                    proxied[i].type = PROXIED_OPERATION_FREE;
                    num_proxied--;
                }
                break;
            case PROXIED_OPERATION_DELETE:
                {
                    if (result.type == TOASTY_RESULT_DELETE_SUCCESS) {
                        http_response_builder_status(proxied[i].builder, 204); // No Content
                        http_response_builder_send(proxied[i].builder);
                    } else {
                        // TODO: Should differentiate between error conditions
                        http_response_builder_status(proxied[i].builder, 500); // Internal Server Error
                        http_response_builder_send(proxied[i].builder);
                    }
                    proxied[i].type = PROXIED_OPERATION_FREE;
                    num_proxied--;
                }
                break;
            case PROXIED_OPERATION_READ_DIR:
                {
                    if (result.type == TOASTY_RESULT_LIST_SUCCESS) {
                        http_response_builder_status(proxied[i].builder, 200);
                        for (int i = 0; i < result.listing.count; i++)
                            http_response_builder_body(proxied[i].builder, (HTTP_String) {
                                result.listing.items[i].name, strlen(result.listing.items[i].name),
                            });
                        http_response_builder_send(proxied[i].builder);
                        toasty_free_listing(&result.listing);
                    } else {
                        // TODO: Should differentiate between error conditions
                        http_response_builder_status(proxied[i].builder, 500); // Internal Server Error
                        http_response_builder_send(proxied[i].builder);
                    }
                    proxied[i].type = PROXIED_OPERATION_FREE;
                    num_proxied--;
                }
                break;
            case PROXIED_OPERATION_READ_FILE:
                {
                    bool again = false;
                    if (result.type != TOASTY_RESULT_READ_SUCCESS) {
                        http_response_builder_body_ack(proxied[i].builder, 0);
                        http_response_builder_status(proxied[i].builder, 500);
                        http_response_builder_send(proxied[i].builder);
                    } else {

                        // First, ACK the byte we just read, even if it's
                        // just 0 bytes (every bodybuf must by paired with
                        // a bodyack).
                        proxied[i].transferred += result.bytes_read;
                        int ack = proxied[i].head_only ? 0 : result.bytes_read;
                        http_response_builder_body_ack(proxied[i].builder, ack);

                        // If we didn't reach the end of the file, start
                        // a new read.
                        if (result.bytes_read > 0) {

                            // Make sure there is some free space in the buffer
                            int mincap = 1<<10; // TODO: Choose based on overall file size
                            http_response_builder_body_cap(proxied[i].builder, mincap);

                            // Get the location of that buffer
                            int cap;
                            char *dst = http_response_builder_body_buf(proxied[i].builder, &cap);
                            if (dst == NULL) {
                                assert(0); // TODO
                            }

                            ToastyString path = {
                                proxied[i].request->url.path.ptr,
                                proxied[i].request->url.path.len,
                            };
                            proxied[i].handle = toasty_begin_read(toasty, path, proxied[i].transferred, dst, cap);
                            if (proxied[i].handle == TOASTY_INVALID) {
                                assert(0); // TODO
                            }

                            again = true;
                        }
                    }

                    if (!again) {
                        proxied[i].type = PROXIED_OPERATION_FREE;
                        num_proxied--;
                    }
                }
                break;
            case PROXIED_OPERATION_WRITE:
                {
                    if (result.type == TOASTY_RESULT_WRITE_SUCCESS) {
                        http_response_builder_status(proxied[i].builder, 201); // Created
                        http_response_builder_send(proxied[i].builder);
                    } else {
                        // TODO: Should differentiate between error conditions
                        http_response_builder_status(proxied[i].builder, 500); // Internal Server Error
                        http_response_builder_send(proxied[i].builder);
                    }
                    proxied[i].type = PROXIED_OPERATION_FREE;
                    num_proxied--;
                }
                break;
            default:
                UNREACHABLE;
                break;
            }
        }

        reg = (EventRegister) { http_ptrs, http_polled, HTTP_SERVER_POLL_CAPACITY, num_http_polled };
        if (http_server_process_events(&server, &reg) < 0)
            return -1;

        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        if (http_server_next_request(&server, &request, &builder)) {

            switch (request->method) {
            case HTTP_METHOD_GET:
                http_response_builder_status(builder, 501); // Not Implemented
                http_response_builder_send(builder);
                break;
            case HTTP_METHOD_HEAD:
                http_response_builder_status(builder, 501); // Not Implemented
                http_response_builder_send(builder);
                break;
            case HTTP_METHOD_PUT:
                {
                    int i = find_unused_struct(proxied, num_proxied);
                    if (i < 0) {
                        http_response_builder_status(builder, 503); // Service Unavailable
                        http_response_builder_send(builder);
                        break;
                    }

                    ToastyString path = {
                        request->url.path.ptr,
                        request->url.path.len,
                    };
                    ToastyHandle handle = toasty_begin_write(toasty, path, 0, request->body.ptr, request->body.len);
                    if (handle == TOASTY_INVALID) {
                        http_response_builder_status(builder, 500); // Internal Server Error
                        http_response_builder_send(builder);
                        break;
                    }

                    toasty_set_user(toasty, handle, &proxied[num_proxied]);
                    proxied[num_proxied].type    = PROXIED_OPERATION_WRITE;
                    proxied[num_proxied].request = request;
                    proxied[num_proxied].builder = builder;
                    proxied[num_proxied].handle  = handle;
                    num_proxied++;
                }
                break;
            case HTTP_METHOD_DELETE:
                {
                    int i = find_unused_struct(proxied, num_proxied);
                    if (i < 0) {
                        http_response_builder_status(builder, 503); // Service Unavailable
                        http_response_builder_send(builder);
                        break;
                    }

                    ToastyString path = {
                        request->url.path.ptr,
                        request->url.path.len,
                    };
                    ToastyHandle handle = toasty_begin_delete(toasty, path);
                    if (handle == TOASTY_INVALID) {
                        http_response_builder_status(builder, 500); // Internal Server Error
                        http_response_builder_send(builder);
                        break;
                    }

                    toasty_set_user(toasty, handle, &proxied[num_proxied]);
                    proxied[num_proxied].type    = PROXIED_OPERATION_DELETE;
                    proxied[num_proxied].request = request;
                    proxied[num_proxied].builder = builder;
                    proxied[num_proxied].handle  = handle;
                    num_proxied++;
                }
                break;
            case HTTP_METHOD_OPTIONS:
                http_response_builder_status(builder, 200); // OK
                http_response_builder_header(builder, HTTP_STR("Allow: GET, HEAD, PUT, DELETE, OPTIONS"));
                http_response_builder_send(builder);
                break;
            default:
                http_response_builder_status(builder, 405); // Method not allowed
                http_response_builder_header(builder, HTTP_STR("Allow: GET, HEAD, PUT, DELETE, OPTIONS"));
                http_response_builder_send(builder);
                break;
            }
        }
    }

    http_server_free(&server);
    toasty_disconnect(toasty);
    return 0;
}
