#include "proxy.h"
#include "proxy_get.h"
#include "proxy_put.h"
#include "proxy_delete.h"

void proxy_init(ProxyState *state, ToastyFS *backend)
{
    state->backend = backend;
    state->num_operations = 0;
    for (int i = 0; i < PROXY_CAPACITY; i++)
        state->operations[i].type = PO_FREE;
}

void proxy_free(ProxyState *state)
{
    for (int i = 0; i < PROXY_CAPACITY; i++) {
        ProxyOperation *operation = &state->operations[i];
        if (operation->type != PO_FREE) {
            http_response_builder_status(operation->builder, 500);
            http_response_builder_send(operation->builder);
        }
    }
}

static ProxyOperation *find_unused_operation(ProxyState *state)
{
    if (state->num_operations == PROXY_CAPACITY)
        return NULL;

    ProxyOperation *operation = state->operations;
    while (operation->type != PO_FREE)
        operation++;

    return operation;
}

void proxy_process_request(ProxyState *state,
    HTTP_Request *request, HTTP_ResponseBuilder builder)
{
    ProxyOperation *operation = find_unused_operation(state);

    bool created = false;
    switch (request->method) {
    case HTTP_METHOD_GET:
        if (operation == NULL) {
            http_response_builder_status(builder, 503); // Service Unavailable
            http_response_builder_send(builder);
        } else {
            created = process_request_get(state, operation, request, builder);
        }
        break;
    case HTTP_METHOD_HEAD:
        if (operation == NULL) {
            http_response_builder_status(builder, 503); // Service Unavailable
            http_response_builder_send(builder);
        } else {
            created = process_request_head(state, operation, request, builder);
        }
        break;
    case HTTP_METHOD_PUT:
        if (operation == NULL) {
            http_response_builder_status(builder, 503); // Service Unavailable
            http_response_builder_send(builder);
        } else {
            created = process_request_put(state, operation, request, builder);
        }
        break;
    case HTTP_METHOD_DELETE:
        if (operation == NULL) {
            http_response_builder_status(builder, 503); // Service Unavailable
            http_response_builder_send(builder);
        } else {
            created = process_request_delete(state, operation, request, builder);
        }
        break;
    case HTTP_METHOD_OPTIONS:
        http_response_builder_status(builder, 200); // OK
        http_response_builder_header(builder,
            HTTP_STR("Allow: GET, HEAD, PUT, DELETE, OPTIONS"));
        http_response_builder_send(builder);
        break;
    default:
        http_response_builder_status(builder, 405); // Method not allowed
        http_response_builder_header(builder,
            HTTP_STR("Allow: GET, HEAD, PUT, DELETE, OPTIONS"));
        http_response_builder_send(builder);
        break;
    }
    if (created) {
        state->num_operations++;
    }
}

void proxy_process_completion(ProxyState *state,
    ToastyResult completion)
{
    bool completed;
    ProxyOperation *operation = completion.user;
    switch (operation->type) {
    case PO_CREATE_DIR:
        completed = process_completion_create_dir(state, operation, completion);
        break;
    case PO_CREATE_FILE:
        completed = process_completion_create_file(state, operation, completion);
        break;
    case PO_DELETE:
        completed = process_completion_delete(state, operation, completion);
        break;
    case PO_READ_DIR:
        completed = process_completion_read_dir(state, operation, completion);
        break;
    case PO_READ_FILE:
        completed = process_completion_read_file(state, operation, completion);
        break;
    case PO_WRITE:
        completed = process_completion_write(state, operation, completion);
        break;
    default:
    }
    if (completed) {
        operation->type = PO_FREE;
        state->num_operations--;
    }
}
