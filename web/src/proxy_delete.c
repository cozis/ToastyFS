#include "proxy_delete.h"

bool process_request_delete(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder)
{
    // TODO: Implement If-Match and If-None-Match headers

    HTTP_String path = request->url.path;
    ToastyHandle handle = toasty_begin_delete(state->backend,
        (ToastyString) { path.ptr, path.len }, TOASTY_VERSION_TAG_EMPTY);
    if (handle == TOASTY_INVALID) {
        http_response_builder_status(builder, 500); // Internal Server Error
        http_response_builder_send(builder);
        return false;
    }
    toasty_set_user(state->backend, handle, operation);

    operation->type    = PO_DELETE;
    operation->request = request;
    operation->builder = builder;
    operation->handle  = handle;
    return true;
}

bool process_completion_delete(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion)
{
    if (completion.type == TOASTY_RESULT_DELETE_SUCCESS) {
        http_response_builder_status(operation->builder, 204); // No Content
        http_response_builder_send(operation->builder);
    } else {
        // TODO: Should differentiate between error conditions
        http_response_builder_status(operation->builder, 500); // Internal Server Error
        http_response_builder_send(operation->builder);
    }
    return true;
}
