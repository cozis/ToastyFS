#ifndef PROXY_INCLUDED
#define PROXY_INCLUDED

#include <chttp.h>
#include <ToastyFS.h>

#define PROXY_CAPACITY (1<<10)

typedef enum {
    PO_FREE,
    PO_CREATE_DIR,
    PO_CREATE_FILE,
    PO_DELETE,
    PO_READ_DIR,
    PO_READ_FILE,
    PO_WRITE,
} ProxyOperationType;

typedef struct {
    ProxyOperationType   type;
    HTTP_Request*        request;
    HTTP_ResponseBuilder builder;
    ToastyHandle         handle;

    bool head_only;
    int  transferred;
} ProxyOperation;

typedef struct {
    ToastyFS *backend;
    int num_operations;
    ProxyOperation operations[PROXY_CAPACITY];
} ProxyState;

void proxy_init(ProxyState *state, ToastyFS *backend);
void proxy_free(ProxyState *state);

void proxy_process_request(ProxyState *state,
    HTTP_Request *request, HTTP_ResponseBuilder builder);

void proxy_process_completion(ProxyState *state,
    ToastyResult completion);

#endif // PROXY_INCLUDED
