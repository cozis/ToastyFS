#include "proxy.h"
#include "config.h"
#include "event_loop.h"

int main(int argc, char **argv)
{
    ProxyConfig config;
    parse_config_or_exit(&config, argc, argv);

    ToastyFS *backend = toasty_connect(
        config.upstream_addr,
        config.upstream_port);
    if (backend == NULL) {
        printf("toasty_connect error\n");
        return -1;
    }

    HTTP_Server server;
    if (http_server_init(&server) < 0) {
        printf("http_server_init error\n");
        return -1;
    }
    http_server_set_reuse_addr(&server, config.reuse_addr);
    http_server_set_trace_bytes(&server, config.trace_bytes);

    if (http_server_listen_tcp(&server, config.local_addr, config.local_port) < 0) {
        printf("http_server_listen_tcp error\n");
        return -1;
    }

    EventLoop loop;
    event_loop_init(&loop, &server, backend);

    ProxyState proxy;
    proxy_init(&proxy, backend);

    for (Event event; !event_loop_wait(&loop, &event); ) {

        if (event.type == EVENT_TYPE_REQUEST) {
            proxy_process_request(&proxy, event.request, event.builder);
        } else {
            assert(event.type == EVENT_TYPE_COMPLETION);
            proxy_process_completion(&proxy, event.completion);
        }
    }

    proxy_free(&proxy);
    event_loop_free(&loop);
    http_server_free(&server);
    toasty_disconnect(backend);
    return 0;
}
