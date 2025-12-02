#ifndef PROXY_DELETE_INCLUDED
#define PROXY_DELETE_INCLUDED

#include "proxy.h"

bool process_request_delete(ProxyState *state, ProxyOperation *operation,
    HTTP_Request *request, HTTP_ResponseBuilder builder);

bool process_completion_delete(ProxyState *state,
    ProxyOperation *operation, ToastyResult completion);

#endif // PROXY_DELETE_INCLUDED
