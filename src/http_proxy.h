#ifndef HTTP_PROXY_INCLUDED
#define HTTP_PROXY_INCLUDED

#include <toastyfs.h>
#include <lib/http_server.h>

typedef enum {
    PROXY_OPER_FREE,
    PROXY_OPER_PENDING,
    PROXY_OPER_STARTED,
} ProxyOperState;

typedef struct {
    ProxyOperState       state;
    HTTP_Request*        request;
    HTTP_ResponseBuilder builder;
} ProxyOper;

typedef struct {
    HTTP_Server http_server;
    ToastyFS *toastyfs;
    ProxyOper *opers;
    int max_opers;
    int num_polled_by_toasty;
} HTTPProxy;

struct pollfd;

int http_proxy_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout);

int http_proxy_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout);

int http_proxy_free(void *state);

#endif // HTTP_PROXY_INCLUDED