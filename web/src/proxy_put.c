#include "proxy_put.h"

bool process_request_put(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder)
{
    ToastyString path = {
        request->url.path.ptr,
        request->url.path.len,
    };
    // Use TOASTY_WRITE_CREATE_IF_MISSING to automatically create files
    // when they don't exist, enabling PUT operations to create new files
    ToastyHandle handle = toasty_begin_write(state->backend, path, 0,
        request->body.ptr, request->body.len, TOASTY_VERSION_TAG_EMPTY,
        TOASTY_WRITE_CREATE_IF_MISSING);
    if (handle == TOASTY_INVALID) {
        http_response_builder_status(builder, 500); // Internal Server Error
        http_response_builder_send(builder);
        return false;
    }
    toasty_set_user(state->backend, handle, operation);

    operation->type    = PO_WRITE;
    operation->request = request;
    operation->builder = builder;
    operation->handle  = handle;
    return true;
}

bool process_completion_create_dir(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    if (completion.type == TOASTY_RESULT_CREATE_SUCCESS) {
        http_response_builder_status(operation->builder, 201); // Created
        http_response_builder_send(operation->builder);
    } else {
        // TODO: Should differentiate between error conditions
        http_response_builder_status(operation->builder, 500); // Internal Server Error
        http_response_builder_send(operation->builder);
    }
    return true;
}

bool process_completion_create_file(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    if (completion.type == TOASTY_RESULT_CREATE_SUCCESS) {
        http_response_builder_status(operation->builder, 201); // Created
        http_response_builder_send(operation->builder);
    } else {
        // TODO: Should differentiate between error conditions
        http_response_builder_status(operation->builder, 500); // Internal Server Error
        http_response_builder_send(operation->builder);
    }
    return true;
}

bool process_completion_write(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    if (completion.type == TOASTY_RESULT_WRITE_SUCCESS) {
        http_response_builder_status(operation->builder, 201); // Created
        http_response_builder_send(operation->builder);
    } else {
        // TODO: Should differentiate between error conditions
        http_response_builder_status(operation->builder, 500); // Internal Server Error
        http_response_builder_send(operation->builder);
    }
    return true;
}
