#ifndef PROXY_PUT_INCLUDED
#define PROXY_PUT_INCLUDED

#include "proxy.h"

bool process_request_put(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder);

bool process_completion_create_dir(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

bool process_completion_create_file(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

bool process_completion_write(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

#endif // PROXY_PUT_INCLUDED
