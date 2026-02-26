#include "http_proxy.h"
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

int http_proxy_init(void *state, int argc, char **argv,
    void **ctxs, struct pollfd *pdata, int pcap, int *pnum,
    int *timeout)
{
    HTTPProxy *proxy = state;

    char *addrs[NODE_LIMIT];
    int num_addrs = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Option --server missing value\n");
                return -1;
            }
            if (num_addrs == NODE_LIMIT) {
                fprintf(stderr, "Node limit reached\n");
                return -1;
            }
            addrs[num_addrs] = argv[i];
            num_addrs++;
        } else {
            // Ignore unknown options
        }
    }

    // TODO: Make these configurable
    int      max_opers = 128;
    string   http_addr = S("127.0.0.1:3000");
    uint64_t client_id = 999;

    proxy->max_opers = max_opers;
    proxy->opers = malloc(max_opers * sizeof(ProxyOper));
    if (proxy->opers == NULL)
        return -1;

    for (int i = 0; i < max_opers; i++)
        proxy->opers[i].state = PROXY_OPER_FREE;

    if (http_server_init(&proxy->http_server, max_opers) < 0) {
        free(proxy->opers);
        return -1;
    }

    Address http_addr_2;
    if (parse_addr_arg(http_addr, &http_addr_2) < 0) {
        http_server_free(&proxy->http_server);
        free(proxy->opers);
        return -1;
    }
    if (http_server_listen_tcp(&proxy->http_server, http_addr_2) < 0) {
        http_server_free(&proxy->http_server);
        free(proxy->opers);
        return -1;
    }

    proxy->toastyfs = toastyfs_init(client_id, addrs, num_addrs);
    if (proxy->toastyfs == NULL) {
        http_server_free(&proxy->http_server);
        free(proxy->opers);
        return -1;
    }

    // Register events that need to be monitored
    {
        int ret;
        *pnum = 0;
        *timeout = -1;

        ret = toastyfs_register_events(proxy->toastyfs, ctxs, pdata, pcap, timeout);
        if (ret < 0)
            return -1;
        *pnum += ret;
        proxy->num_polled_by_toasty = ret;

        ret = http_server_register_events(&proxy->http_server,
            ctxs + proxy->num_polled_by_toasty,
            pdata + proxy->num_polled_by_toasty,
            pcap - proxy->num_polled_by_toasty);
        if (ret < 0)
            return -1;
        *pnum += ret;
    }
    return 0;
}

int http_proxy_tick(void *state, void **ctxs,
    struct pollfd *pdata, int pcap, int *pnum, int *timeout)
{
    HTTPProxy *proxy = state;

    http_server_process_events(&proxy->http_server,
        ctxs  + proxy->num_polled_by_toasty,
        pdata + proxy->num_polled_by_toasty,
        *pnum - proxy->num_polled_by_toasty);
    toastyfs_process_events(proxy->toastyfs,
        ctxs, pdata, proxy->num_polled_by_toasty);

    // Process operation resolutions
    for (;;) {
        ToastyFS_Result result = toastyfs_get_result(proxy->toastyfs);
        if (result.type == TOASTYFS_RESULT_VOID)
            break;

        // Find the started operation
        int i = 0;
        while (i < proxy->max_opers && proxy->opers[i].state != PROXY_OPER_STARTED)
            i++;
        assert(i < proxy->max_opers); // Wasn't expecting this result

        ProxyOper *oper = &proxy->opers[i];
        assert(oper->state == PROXY_OPER_STARTED);

        HTTP_ResponseBuilder builder = oper->builder;

        switch (result.type) {
        case TOASTYFS_RESULT_PUT:
            if (result.error == TOASTYFS_ERROR_VOID) {
                http_response_builder_status(builder, 201);
                http_response_builder_submit(builder);
            } else if (result.error == TOASTYFS_ERROR_FULL) {
                http_response_builder_status(builder, 507);
                http_response_builder_submit(builder);
            } else {
                http_response_builder_status(builder, 500);
                http_response_builder_submit(builder);
            }
            break;
        case TOASTYFS_RESULT_GET:
            if (result.error == TOASTYFS_ERROR_VOID) {
                http_response_builder_status(builder, 200);
                http_response_builder_content(builder, (string) { result.data, result.size });
                http_response_builder_submit(builder);
                free(result.data);
            } else if (result.error == TOASTYFS_ERROR_NOT_FOUND) {
                http_response_builder_status(builder, 404);
                http_response_builder_submit(builder);
            } else {
                http_response_builder_status(builder, 500);
                http_response_builder_submit(builder);
            }
            break;
        case TOASTYFS_RESULT_DELETE:
            if (result.error == TOASTYFS_ERROR_VOID) {
                http_response_builder_status(builder, 204);
                http_response_builder_submit(builder);
            } else if (result.error == TOASTYFS_ERROR_NOT_FOUND) {
                http_response_builder_status(builder, 404);
                http_response_builder_submit(builder);
            } else {
                http_response_builder_status(builder, 500);
                http_response_builder_submit(builder);
            }
            break;
        default:
            UNREACHABLE;
        }

        oper->state = PROXY_OPER_FREE;
    }

    // Discard pending operations whose connection has been closed.
    // When a client disconnects, the HTTP_Conn is freed and the builder
    // becomes invalid.  The request pointers (url, body) reference the
    // now-freed TCP read buffer, so we must not dereference them.
    for (int i = 0; i < proxy->max_opers; i++) {
        if (proxy->opers[i].state == PROXY_OPER_PENDING
            && !http_response_builder_is_valid(proxy->opers[i].builder)) {
            proxy->opers[i].state = PROXY_OPER_FREE;
        }
    }

    // Buffer operation requests
    for (;;) {
        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        if (!http_server_next_request(&proxy->http_server, &request, &builder))
            break;

        // Only allow GET, PUT, DELETE requests
        if (request->method != CHTTP_METHOD_GET &&
            request->method != CHTTP_METHOD_PUT &&
            request->method != CHTTP_METHOD_DELETE) {
            http_response_builder_status(builder, 405);
            http_response_builder_submit(builder);
            continue;
        }

        // Look for a free operation slot
        int i = 0;
        while (i < proxy->max_opers && proxy->opers[i].state != PROXY_OPER_FREE)
            i++;

        if (i == proxy->max_opers) {
            // Queue is full
            http_response_builder_status(builder, 503);
            http_response_builder_submit(builder);
            continue;
        }

        ProxyOper *oper = &proxy->opers[i];
        assert(oper->state == PROXY_OPER_FREE);

        oper->state = PROXY_OPER_PENDING;
        oper->request = request;
        oper->builder = builder;
    }

    // Start operations
    {
        // Look for a started operation
        bool started = false;
        for (int i = 0; i < proxy->max_opers; i++) {
            if (proxy->opers[i].state == PROXY_OPER_STARTED) {
                started = true;
                break;
            }
        }

        // Start an operation if necessary
        if (!started) {
            // Look for a pending operation
            int i = 0;
            while (i < proxy->max_opers && proxy->opers[i].state != PROXY_OPER_PENDING)
                i++;

            if (i < proxy->max_opers) {
                // Found pending operation
                ProxyOper *oper = &proxy->opers[i];
                HTTP_Request *request = oper->request;
                int ret = -1;

                switch (request->method) {
                case CHTTP_METHOD_GET:
                    ret = toastyfs_async_get(proxy->toastyfs,
                        request->url.path.ptr, request->url.path.len);
                    break;
                case CHTTP_METHOD_PUT:
                    ret = toastyfs_async_put(proxy->toastyfs,
                        request->url.path.ptr, request->url.path.len,
                        request->body.ptr, request->body.len);
                    break;
                case CHTTP_METHOD_DELETE:
                    ret = toastyfs_async_delete(proxy->toastyfs,
                        request->url.path.ptr, request->url.path.len);
                    break;
                default:
                    UNREACHABLE;
                }

                if (ret < 0) {
                    // Async operation failed to start -- respond with error
                    // and free the slot so the proxy doesn't get stuck.
                    http_response_builder_status(oper->builder, 500);
                    http_response_builder_submit(oper->builder);
                    oper->state = PROXY_OPER_FREE;
                } else {
                    oper->state = PROXY_OPER_STARTED;
                }
            }
        }
    }

    // Register events that need to be monitored
    {
        int ret;
        *pnum = 0;
        *timeout = -1;

        ret = toastyfs_register_events(proxy->toastyfs, ctxs, pdata, pcap, timeout);
        if (ret < 0)
            return -1;
        *pnum += ret;
        proxy->num_polled_by_toasty = ret;

        ret = http_server_register_events(&proxy->http_server,
            ctxs + proxy->num_polled_by_toasty,
            pdata + proxy->num_polled_by_toasty,
            pcap - proxy->num_polled_by_toasty);
        if (ret < 0)
            return -1;
        *pnum += ret;
    }
    return 0;
}

int http_proxy_free(void *state)
{
    HTTPProxy *proxy = state;

    toastyfs_free(proxy->toastyfs);
    http_server_free(&proxy->http_server);
    free(proxy->opers);
    return 0;
}
