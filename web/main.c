#include <stdio.h>
#include <stdbool.h>

#include <chttp.h>
#include <ToastyFS.h>

#define MAX_WAITING (1<<10)
#define MAX_PENDING (1<<9)

typedef enum {
    OPERATION_FREE,
    OPERATION_CREATE_DIR,
    OPERATION_CREATE_FILE,
    OPERATION_DELETE,
    OPERATION_READ_DIR,
    OPERATION_READ_FILE,
    OPERATION_WRITE,
} OperationType;

typedef struct {
    OperationType type;

    // Number of bytes read/written
    int transferred;

    HTTP_Request *request; // TODO: is it okay to store this pointer?
    HTTP_ResponseBuilder builder;

    ToastyHandle handle;
} Operation;

static int       waiting_head;
static int       num_waiting;
static int       num_pending;
static Operation waiting[MAX_WAITING];
static Operation pending[MAX_PENDING];

void worker(Worker *w)
{
    for (;;) {

        ToastyResult result;
        int ret = toasty_wait_result(toasty, TOASTY_INVALID, &result, -1);
        // TODO: check return value

        // First, process completed requests. This frees up
        // space for new ones.
        //
        // TODO: What if there was a WAKEUP request and no pending operations
        //       are present?

        int i = 0;
        while (pending[i].handle != result.handle) {
            i++;
            assert(i < MAX_PENDING_OPERATIONS);
        }

        bool incomplete = false;
        switch (pending[i].type) {

            int cap;
            int mincap;
            char *dst;
            ToastyString path;

        case OPERATION_CREATE_DIR:
        case OPERATION_CREATE_FILE:
            if (result.type == TOASTY_RESULT_CREATE_SUCCESS) {
                http_response_builder_status(pending[i].builder, 204); // TODO: What is the proper response to a CREATE request?
                http_response_builder_done(pending[i].builder);
            } else {
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
            }
            break;

        case OPERATION_DELETE:
            if (result.type == TOASTY_RESULT_DELETE_SUCCESS) {
                http_response_builder_status(pending[i].builder, 204); // TODO: What is the proper response to a DELETE request?
                http_response_builder_done(pending[i].builder);
            } else {
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
            }
            break;

        case OPERATION_READ_DIR:

            // If the listing failed, abort the request
            if (result.type != TOASTY_RESULT_READ_SUCCESS) {
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
                break;
            }

            http_response_builder_status(pending[i].builder, 500);
            for (int i = 0; i < result.listing.count; i++)
                http_response_builder_body(pending[i].builder, (HTTP_String) {
                    result.listing.items[i].name,
                    result.listing.items[i].name_len
                });
            http_response_builder_done(pending[i].builder);

            toasty_free_listing(&result.listing);
            break;

        case OPERATION_READ_FILE:

            // If the read failed, abort the request
            if (result.type != TOASTY_RESULT_READ_SUCCESS) {
                http_response_builder_bodyack(pending[i].builder, 0);
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
                break;
            }

            // First, ACK the byte we just read, even if it's
            // just 0 bytes (every bodybuf must by paired with
            // a bodyack).
            http_response_builder_bodyack(pending[i].builder, result.count);
            pending[i].transferred += result.count;

            // If we read 0 bytes, there is no more to read.
            if (result.count == 0) {
                http_response_builder_done(pending[i].builder);
                break;
            }

            // There is more to read, so we need to start a
            // new read.

            // Make sure there is some free space in the buffer
            mincap = 1<<10; // TODO: Choose based on overall file size
            http_response_builder_bodycap(pending[i].builder, mincap);

            // Get the location of that buffer
            dst = http_response_builder_bodybuf(pending[i].builder, &cap);
            if (dst == NULL) {
                http_response_builder_done(pending[i].builder);
                break;
            }

            // Begin the read. On error, abort.
            path = (ToastyString) { pending[i].request->path.ptr, pending[i].request.path.len };
            pending[i].handle = toasty_begin_read(toasty, path, off, dst, cap);
            if (pending[i].handle == TOASTY_INVALID) {
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
                break;
            }

            // Most of the time this switch will complete the pending
            // operation, but not for reads.
            incomplete = true;
            break;

        case OPERATION_WRITE:
            if (pending[i].type != TOASTY_RESULT_WRITE_SUCCESS) {
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
                break;
            }
            assert(pending[i].transferred == result.count);
            http_response_builder_done(pending[i].builder);
            break;

        default:
            assert(0); // TODO
        }

        if (!incomplete) {
            // Free the pending structure
            pending[i].type = OPERATION_FREE;
            num_pending--;
        }

        // Now accept operations
        for (Operation req; num_pending < MAX_PENDING_OPERATIONS
            && wait_queue_pop(&wait_queue, &req); ) {

            int i = 0;
            while (pending[i].type != PENDING_OPERATION_FREE) {
                i++;
                assert(i < MAX_PENDING_OPERATIONS);
            }
            pending[i] = req;

            ToastyString path = { pending[i].request->path.ptr, pending[i].request.path.len };
            ToastyString body = { pending[i].request->body.ptr, pending[i].request.body.len };
            switch (pending[i].type) {
                int cap;
                int mincap;
                char *dst;
                uint32_t chunk_size;
            case OPERATION_CREATE_DIR,
                pending[i].handle = toasty_begin_create_dir(toasty, path);
                break;
            case OPERATION_CREATE_FILE,
                chunk_size = 1<<10; // TODO: determine a better chunk size
                pending[i].handle = toasty_begin_create_file(toasty, path, chunk_size);
                break;
            case OPERATION_DELETE,
                pending[i].handle = toasty_begin_delete(toasty, path);
                break;
            case OPERATION_READ,
                http_response_builder_status(pending[i].builder, 200); // TODO: Is statis 200 correct?

                mincap = 1<<10; // TODO: do something smart to choose this
                http_response_builder_bodycap(pending[i].builder, mincap);

                dst = http_response_builder_bodybuf(pending[i].builder, &cap);
                if (dst == NULL)
                    break;

                pending[i].handle = toasty_begin_read(toasty, path, off, dst, cap);
                pending[i].transferred = 0;
                break;
            case OPERATION_WRITE:
                pending[i].handle = toasty_begin_write(toasty, body.ptr, body.len);
                pending[i].transferred = 0;
                break;
            }

            if (pending[i].handle == TOASTY_INVALID) {
                http_response_builder_undo(pending[i].builder);
                http_response_builder_status(pending[i].builder, 500);
                http_response_builder_done(pending[i].builder);
                pending[i].type = OPERATION_FREE;
            }
            num_pending++;
        }
    }
}

int main(void)
{
    http_global_init();

    HTTP_String addr = HTTP_STR("127.0.0.1");
    uint16_t    port = 8080;

    ToastyString backend_addr = TOASTY_STR("127.0.0.1");
    uint16_t     backend_port = 9000;

    HTTP_Server *server = http_server_init(addr, port);
    if (server == NULL)
        return -1;

    ToastyFS *toasty = toasty_connect(backend_addr, backend_port);
    if (toasty == NULL)
        return -1;

    for (;;) {

        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        int ret = http_server_wait(server, &req, &builder);
        if (ret < 0)
            return -1;

        ToastyString path = {
            req->url.path.ptr,
            req->url.path.len
        };

        Operation op;
        op.type = OPERATION_FREE;

        switch (req->method) {

            case HTTP_METHOD_GET:
            // TODO
            break;

            case HTTP_METHOD_HEAD:
            // TODO
            break;

            case HTTP_METHOD_PUT:
            // TODO
            break;

            case HTTP_METHOD_PATCH:
            // TODO
            break;

            case HTTP_METHOD_DELETE:
            // TODO
            break;

            case HTTP_METHOD_OPTIONS:
            http_response_builder_status(builder, 200);
            http_response_builder_header(builder, HTTP_STR("Allow: GET, HEAD, PUT, PATCH, DELETE, OPTIONS"));
            http_response_builder_done(builder);
            break;

            default:
            http_response_builder_status(builder, 200); // TODO: use the status code for invalid methods
            http_response_builder_header(builder, HTTP_STR("Allow: GET, HEAD, PUT, PATCH, DELETE, OPTIONS"));
            http_response_builder_done(builder);
            break;
        }

        if (op.type != OPERATION_FREE) {
            assert(0); // TODO: Append to the queue
        }
    }

    http_server_free(server);
    http_global_free();
    return 0;
}
