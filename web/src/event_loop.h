#ifndef EVENT_LOOP_INCLUDED
#define EVENT_LOOP_INCLUDED

#include <ToastyFS.h>
#include "chttp.h"

typedef enum {
    EVENT_TYPE_REQUEST,
    EVENT_TYPE_COMPLETION,
} EventType;

typedef struct {
    EventType type;

    // Completion
    ToastyResult completion;

    // Request
    HTTP_Request *request;
    HTTP_ResponseBuilder builder;
} Event;


typedef enum {
    EVENT_LOOP_PROCESSING_REQUESTS,
    EVENT_LOOP_PROCESSING_COMPLETIONS,
} EventLoopState;

typedef struct {
    EventLoopState state;
    HTTP_Server *server;
    ToastyFS *backend;
} EventLoop;

void event_loop_init(EventLoop *loop, HTTP_Server *server,
    ToastyFS *backend);

void event_loop_free(EventLoop *loop);

int event_loop_wait(EventLoop *loop, Event *event);

#endif // EVENT_LOOP_INCLUDED
