#include <ToastyFS.h>

#include "chttp.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

#define UNREACHABLE __builtin_trap()

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

#define MAX_PROXIED_OPERATIONS (1<<10)

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

int main(void)
{
    ToastyString upstream_addr = TOASTY_STR("127.0.0.1");
    uint16_t     upstream_port = 9000;

    HTTP_String  local_addr = HTTP_STR("127.0.0.1");
    uint16_t     local_port = 8080;

    ToastyFS *toasty = toasty_connect(upstream_addr, upstream_port);
    if (toasty == NULL)
        return -1;

    HTTP_Server server;
    if (http_server_init(&server) < 0)
        return -1;

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    if (http_server_listen_tcp(&server, local_addr, local_port) < 0)
        return -1;

    int num_proxied = 0;
    ProxiedOperation proxied[MAX_PROXIED_OPERATIONS];

    for (;;) {

        #define POLL_CAPACITY (HTTP_SERVER_POLL_CAPACITY + TOASTY_POLL_CAPACITY)

        EventRegister reg;
        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        void **http_ptrs = ptrs;
        struct pollfd *http_polled = polled;

        reg = (EventRegister) {
            ptrs,
            polled,
            POLL_CAPACITY,
            0
        };
        if (http_server_register_events(&server, &reg) < 0)
            return -1;
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

            // Find the operation associated to this completion
            int i = 0;
            while (proxied[i].handle != result.handle) {
                i++;
                assert(i < MAX_PROXIED_OPERATIONS);
            }

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
                                result.listing.items[i].name,
                                result.listing.items[i].name_len
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
                        http_response_builder_bodyack(proxied[i].builder, 0);
                        http_response_builder_status(proxied[i].builder, 500);
                        http_response_builder_send(proxied[i].builder);
                    } else {

                        // First, ACK the byte we just read, even if it's
                        // just 0 bytes (every bodybuf must by paired with
                        // a bodyack).
                        proxied[i].transferred += result.count;
                        int ack = proxied[i].head_only ? 0 : result.count;
                        http_response_builder_bodyack(proxied[i].builder, ack);

                        // If we didn't reach the end of the file, start
                        // a new read.
                        if (result.count > 0) {

                            // Make sure there is some free space in the buffer
                            int mincap = 1<<10; // TODO: Choose based on overall file size
                            http_response_builder_bodycap(proxied[i].builder, mincap);

                            // Get the location of that buffer
                            int cap;
                            char *dst = http_response_builder_bodybuf(proxied[i].builder, &cap);
                            if (dst == NULL) {
                                assert(0); // TODO
                            }

                            proxied[i].handle = toasty_begin_read(toasty, path, off, dst, cap);
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

                    ToastyHandle handle = toasty_begin_write(toasty, path, 0, request->body.ptr, request->body.len);
                    if (handle == TOASTY_INVALID) {
                        http_response_builder_status(builder, 500); // Internal Server Error
                        http_response_builder_send(builder);
                        break;
                    }

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

                    ToastyHandle handle = toasty_begin_delete(toasty, path);
                    if (handle == TOASTY_INVALID) {
                        http_response_builder_status(builder, 500); // Internal Server Error
                        http_response_builder_send(builder);
                        break;
                    }

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
