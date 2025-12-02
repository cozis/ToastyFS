#ifndef PROXY_GET_INCLUDED
#define PROXY_GET_INCLUDED

#include "proxy.h"

bool process_request_get(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder);

bool process_request_head(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder);

bool process_completion_read_dir(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

bool process_completion_read_file(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

#endif // PROXY_GET_INCLUDED
