#include "http_proxy.h"

int http_proxy_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    HTTPProxy *proxy = state;

    if (http_server_init(&proxy->http_server) < 0)
        return -1;

    if (http_server_listen_tcp(&proxy->http_server, xxx, yyy) < 0)
        return -1;

    return 0;
}

int http_proxy_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    http_server_process_events(&proxy->http_server, ctxs, pdata, *pnum);

    HTTP_Request *request;
    HTTP_ResponseBuilder builder;
    while (http_server_next_request(&proxy->http_server, &request, &builder)) {
        // TODO
        http_response_builder_status(builder, 200);
        http_response_builder_submit(builder);
    }

    *timeout = -1;
    *pnum = http_server_register_events(&proxy->http_server, ctxs, pdata, pcap);
    return 0;
}

int http_proxy_free(void *state)
{
    HTTPProxy *proxy = state;

    http_server_free(&proxy->http_server);
}