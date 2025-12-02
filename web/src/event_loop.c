#include "event_loop.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

#define POLL_CAPACITY (HTTP_SERVER_POLL_CAPACITY + TOASTY_POLL_CAPACITY)

void event_loop_init(EventLoop *loop, HTTP_Server *server,
    ToastyFS *backend)
{
    loop->state = EVENT_LOOP_PROCESSING_COMPLETIONS;
    loop->server = server;
    loop->backend = backend;
}

void event_loop_free(EventLoop *loop)
{
    (void) loop;
}

int event_loop_wait(EventLoop *loop, Event *event)
{
    for (;;) {
        switch (loop->state) {

            int ret;
        case EVENT_LOOP_PROCESSING_COMPLETIONS:

            ret = toasty_get_result(loop->backend, TOASTY_INVALID, &event->completion);
            if (ret < 0)
                return -1; // Error

            if (ret == 0) {
                // Completed
                event->type = EVENT_TYPE_COMPLETION;
                return 0;
            }

            // fallthrough
        case EVENT_LOOP_PROCESSING_REQUESTS:

            if (http_server_next_request(loop->server, &event->request, &event->builder)) {
                // Completed
                event->type = EVENT_TYPE_REQUEST;
                return 0;
            }

            // fallthrough
        }

        EventRegister reg;
        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        void **http_ptrs = ptrs;
        struct pollfd *http_polled = polled;

        reg = (EventRegister) { ptrs, polled, 0 };
        http_server_register_events(loop->server, &reg);
        int num_http_polled = reg.num_polled;

        void **toasty_ptrs = ptrs + num_http_polled;
        struct pollfd *toasty_polled = polled + num_http_polled;
        int num_toasty_polled = toasty_process_events(loop->backend, toasty_ptrs, toasty_polled, 0);
        if (num_toasty_polled < 0)
            return -1;

        int num_polled = num_http_polled + num_toasty_polled;
        if (num_http_polled != 0 && num_toasty_polled != 0)
            POLL(polled, num_polled, -1);

        if (toasty_process_events(loop->backend, toasty_ptrs, toasty_polled, num_toasty_polled) < 0)
            return -1;

        reg = (EventRegister) { http_ptrs, http_polled, num_http_polled };
        http_server_process_events(loop->server, reg);
    }

    // Unreachable
    return -1;
}
