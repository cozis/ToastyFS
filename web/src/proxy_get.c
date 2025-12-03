#include "proxy_get.h"

static bool path_refers_to_dir(ToastyString path)
{
    return path.len > 0 && path.ptr[path.len-1] == '/';
}

bool process_request_get(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder)
{
    assert(request->method == HTTP_METHOD_GET
        || request->method == HTTP_METHOD_HEAD);

    http_response_builder_status(builder, 200); // OK

    ToastyString path = {
        request->url.path.ptr,
        request->url.path.len
    };

    ToastyHandle handle;
    if (path_refers_to_dir(path)) {
        handle = toasty_begin_list(state->backend, path,
            TOASTY_VERSION_TAG_EMPTY);
    } else {

        http_response_builder_body_cap(builder, 1<<10); // TODO: pick the prealloc better

        int cap;
        char *dst = http_response_builder_body_buf(builder, &cap);
        // TODO: check for NULL dst

        handle = toasty_begin_read(state->backend, path,
            0, dst, cap, TOASTY_VERSION_TAG_EMPTY);
    }
    if (handle == TOASTY_INVALID) {
        if (!path_refers_to_dir(path))
            http_response_builder_body_ack(builder, 0);
        http_response_builder_status(builder, 500); // Internal Server Error
        http_response_builder_send(builder);
        return false;
    }
    toasty_set_user(state->backend, handle, operation);

    operation->type        = path_refers_to_dir(path) ? PO_READ_DIR : PO_READ_FILE;
    operation->request     = request;
    operation->builder     = builder;
    operation->handle      = handle;
    operation->head_only   = (request->method == HTTP_METHOD_HEAD);
    operation->transferred = 0;
    return true;
}

bool process_request_head(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder)
{
    return process_request_get(state, operation, request, builder);
}

bool process_completion_read_dir(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    if (completion.type == TOASTY_RESULT_LIST_SUCCESS) {
        http_response_builder_status(operation->builder, 200);
        for (int i = 0; i < completion.listing.count; i++)
            http_response_builder_body(operation->builder, (HTTP_String) {
                completion.listing.items[i].name, strlen(completion.listing.items[i].name),
            });
        http_response_builder_send(operation->builder);
        toasty_free_listing(&completion.listing);
    } else {
        // TODO: Should differentiate between error conditions
        http_response_builder_status(operation->builder, 500); // Internal Server Error
        http_response_builder_send(operation->builder);
    }
    return true;
}

bool process_completion_read_file(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    bool again = false;
    if (completion.type != TOASTY_RESULT_READ_SUCCESS) {
        http_response_builder_body_ack(operation->builder, 0);
        http_response_builder_status(operation->builder, 500);
        http_response_builder_send(operation->builder);
    } else {

        // First, ACK the byte we just read, even if it's
        // just 0 bytes (every bodybuf must by paired with
        // a bodyack).
        operation->transferred += completion.bytes_read;
        int ack = operation->head_only ? 0 : completion.bytes_read;
        http_response_builder_body_ack(operation->builder, ack);

        // If we didn't reach the end of the file, start
        // a new read.
        if (completion.bytes_read > 0) {

            // Make sure there is some free space in the buffer
            int mincap = 1<<10; // TODO: Choose based on overall file size
            http_response_builder_body_cap(operation->builder, mincap);

            // Get the location of that buffer
            int cap;
            char *dst = http_response_builder_body_buf(operation->builder, &cap);
            if (dst == NULL) {
                assert(0); // TODO
            }

            ToastyString path = {
                operation->request->url.path.ptr,
                operation->request->url.path.len,
            };
            operation->handle = toasty_begin_read(state->backend, path,
                operation->transferred, dst, cap, TOASTY_VERSION_TAG_EMPTY);
            if (operation->handle == TOASTY_INVALID) {
                assert(0); // TODO
            }

            again = true;
        }
    }

    return !again;
}
