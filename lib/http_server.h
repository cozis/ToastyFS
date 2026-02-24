#ifndef HTTP_SERVER_INCLUDED
#define HTTP_SERVER_INCLUDED

#include "tcp.h"
#include "http_parse.h"

typedef CHTTP_Request HTTP_Request;

typedef enum {
    HTTP_CONN_STATE_FREE,
    HTTP_CONN_STATE_IDLE,
    HTTP_CONN_STATE_STATUS,
    HTTP_CONN_STATE_HEADER,
    HTTP_CONN_STATE_CONTENT,
} HTTP_ConnState;

typedef struct {
    HTTP_ConnState state;
    uint16_t gen;
    bool ready;
    int  num_served;
    int  request_len;
    bool keep_alive;
    TCP_Handle handle;
    HTTP_Request request;
    TCP_Offset content_offset;
    TCP_Offset content_length_header_offset;
    TCP_Offset response_offset;
} HTTP_Conn;

typedef struct {
    TCP tcp;
    int num_conns;
    int max_conns;
    HTTP_Conn *conns;
} HTTP_Server;

int  http_server_init(HTTP_Server *server, int max_conns);
void http_server_free(HTTP_Server *server);

int http_server_listen_tcp(HTTP_Server *server, string addr, uint16_t port);

int http_server_listen_tls(HTTP_Server *server, string addr, uint16_t port,
    string cert_file, string key_file);

int http_server_add_cert(HTTP_Server *server, string cert_file, string key_file);

void http_server_process_events(HTTP_Server *server,
    void **ptrs, struct pollfd *arr, int cap);

int http_server_register_events(HTTP_Server *server,
    void **ptrs, struct pollfd *arr, int cap);

typedef struct {
    HTTP_Server *server;
    int idx;
    int gen;
} HTTP_ResponseBuilder;

bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder);

void http_response_builder_status(HTTP_ResponseBuilder builder, int status);
void http_response_builder_header(HTTP_ResponseBuilder builder, string header);
void http_response_builder_content(HTTP_ResponseBuilder builder, string content);
void http_response_builder_submit(HTTP_ResponseBuilder builder);

#endif // HTTP_SERVER_INCLUDED