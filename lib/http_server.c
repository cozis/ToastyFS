#include <quakey.h>
#include <assert.h>

#include "http_server.h"

static string reason_phrase(int status)
{
	switch(status) {

		case 100: return S("Continue");
		case 101: return S("Switching Protocols");
		case 102: return S("Processing");

		case 200: return S("OK");
		case 201: return S("Created");
		case 202: return S("Accepted");
		case 203: return S("Non-Authoritative Information");
		case 204: return S("No Content");
		case 205: return S("Reset Content");
		case 206: return S("Partial Content");
		case 207: return S("Multi-Status");
		case 208: return S("Already Reported");

		case 300: return S("Multiple Choices");
		case 301: return S("Moved Permanently");
		case 302: return S("Found");
		case 303: return S("See Other");
		case 304: return S("Not Modified");
		case 305: return S("Use Proxy");
		case 306: return S("Switch Proxy");
		case 307: return S("Temporary Redirect");
		case 308: return S("Permanent Redirect");

		case 400: return S("Bad Request");
		case 401: return S("Unauthorized");
		case 402: return S("Payment Required");
		case 403: return S("Forbidden");
		case 404: return S("Not Found");
		case 405: return S("Method Not Allowed");
		case 406: return S("Not Acceptable");
		case 407: return S("Proxy Authentication Required");
		case 408: return S("Request Timeout");
		case 409: return S("Conflict");
		case 410: return S("Gone");
		case 411: return S("Length Required");
		case 412: return S("Precondition Failed");
		case 413: return S("Request Entity Too Large");
		case 414: return S("Request-URI Too Long");
		case 415: return S("Unsupported Media Type");
		case 416: return S("Requested Range Not Satisfiable");
		case 417: return S("Expectation Failed");
		case 418: return S("I'm a teapot");
		case 420: return S("Enhance your calm");
		case 422: return S("Unprocessable Entity");
		case 426: return S("Upgrade Required");
		case 429: return S("Too many requests");
		case 431: return S("Request Header Fields Too Large");
		case 449: return S("Retry With");
		case 451: return S("Unavailable For Legal Reasons");

		case 500: return S("Internal Server Error");
		case 501: return S("Not Implemented");
		case 502: return S("Bad Gateway");
		case 503: return S("Service Unavailable");
		case 504: return S("Gateway Timeout");
		case 505: return S("HTTP Version Not Supported");
		case 509: return S("Bandwidth Limit Exceeded");
	}

	return S("???");
}

int http_server_init(HTTP_Server *server, int max_conns)
{
    server->conns = malloc(max_conns * sizeof(HTTP_Conn));
    if (server->conns == NULL)
        return -1;

    for (int i = 0; i < max_conns; i++) {
        server->conns[i].state = HTTP_CONN_STATE_FREE;
        server->conns[i].gen = 1;
    }

    server->max_conns = max_conns;
    server->num_conns = 0;

    server->tcp = tcp_init(max_conns);
    if (server->tcp == NULL) {
        free(server->conns);
        return -1;
    }

    return 0;
}

void http_server_free(HTTP_Server *server)
{
    tcp_free(server->tcp);
    free(server->conns);
}

int http_server_listen_tcp(HTTP_Server *server, Address addr)
{
    int ret = tcp_listen_tcp(server->tcp, addr);
    if (ret < 0)
        return -1;

    return 0;
}

int http_server_listen_tls(HTTP_Server *server, Address addr,
    string cert_file, string key_file)
{
#ifdef TLS_ENABLED
    int ret = tcp_listen_tls(server->tcp, addr, cert_file, key_file);
    if (ret < 0)
        return -1;

    return 0;
#else
    (void) server;
    (void) addr;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

int http_server_add_cert(HTTP_Server *server, string domain, string cert_file, string key_file)
{
    int ret = tcp_add_cert(server->tcp, domain, cert_file, key_file);
    if (ret < 0)
        return -1;

    return 0;
}

static void http_conn_init(HTTP_Conn *conn, TCP_Handle handle)
{
    assert(conn->state == HTTP_CONN_STATE_FREE);
    conn->state = HTTP_CONN_STATE_IDLE;
    conn->ready = false;
    conn->num_served = 0;
    conn->request_len = 0;
    conn->keep_alive = true;
    conn->handle = handle;
}

static void http_conn_free(HTTP_Conn *conn)
{
    assert(conn->state != HTTP_CONN_STATE_FREE);

    conn->gen++;
    if (conn->gen == 0)
        conn->gen = 1;

    tcp_close(conn->handle);

    conn->state = HTTP_CONN_STATE_FREE;
}

void http_server_process_events(HTTP_Server *server,
    void **ptrs, struct pollfd *arr, int num)
{
    tcp_process_events(server->tcp, ptrs, arr, num);

    TCP_Event event;
    while (tcp_next_event(server->tcp, &event)) {

        if (event.flags & TCP_EVENT_NEW) {
            // New connection. Find an HTTP_Conn struct.

            int i = 0;
            while (i < server->max_conns && server->conns[i].state != HTTP_CONN_STATE_FREE)
                i++;
            if (i == server->max_conns) {
                tcp_close(event.handle);
                continue;
            }
            HTTP_Conn *conn = &server->conns[i];

            http_conn_init(conn, event.handle);
            tcp_set_user_ptr(event.handle, conn);

            server->num_conns++;
        }

        HTTP_Conn *conn = tcp_get_user_ptr(event.handle);
        assert(conn);

        bool defer_close = false;
        if (event.flags & TCP_EVENT_DATA) {

            string src = tcp_read_buf(event.handle);
            int ret = chttp_parse_request((char*) src.ptr, src.len, &conn->request);
            if (ret < 0) {
                tcp_read_ack(event.handle, 0);
                defer_close = true;
            } else if (ret == 0) {
                tcp_read_ack(event.handle, 0);
            } else {
                // Request was buffered

                // Decide whether the connection should be closed
                // after the next response

                conn->keep_alive = true;

                if (conn->num_served+1 >= 100)
                    conn->keep_alive = false;

                conn->response_offset = tcp_write_off(event.handle);
                conn->request_len = ret;
                conn->state = HTTP_CONN_STATE_STATUS;
                conn->ready = true;
            }
        }

        if (event.flags & TCP_EVENT_HUP) {
            defer_close = true;
        }

        if (defer_close) {
            http_conn_free(conn);
            server->num_conns--;
        }
    }
}

int http_server_register_events(HTTP_Server *server,
    void **ptrs, struct pollfd *arr, int cap)
{
    return tcp_register_events(server->tcp, ptrs, arr, cap);
}

bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder)
{
    for (int i = 0; i < server->max_conns; i++) {
        if (server->conns[i].state == HTTP_CONN_STATE_FREE)
            continue;

        if (server->conns[i].ready) {
            server->conns[i].ready = false;
            *request = &server->conns[i].request;
            *builder = (HTTP_ResponseBuilder) {
                .server = server,
                .idx = i,
                .gen = server->conns[i].gen,
            };
            return true;
        }
    }

    return false;
}

static HTTP_Conn*
builder_to_conn(HTTP_ResponseBuilder builder)
{
    if (builder.server == NULL)
        return NULL;
    HTTP_Server *server = builder.server;

    if (builder.idx < 0 || builder.idx >= server->max_conns)
        return NULL;
    HTTP_Conn *conn = &server->conns[builder.idx];

    if (conn->state == HTTP_CONN_STATE_FREE || conn->gen != builder.gen)
        return NULL;

    return conn;
}

void http_response_builder_status(HTTP_ResponseBuilder builder, int status)
{
    HTTP_Conn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_CONN_STATE_IDLE)
        return;

    if (conn->state != HTTP_CONN_STATE_STATUS) {
        tcp_clear_from_offset(conn->handle, conn->response_offset);
        conn->state = HTTP_CONN_STATE_STATUS;
    }

    assert(status > 99);
    assert(status < 1000);
    char tmp[3] = {
        '0' + (status % 1000) / 100,
        '0' + (status %  100) / 10,
        '0' + (status %   10) / 1,
    };

    tcp_write(conn->handle, S("HTTP/1.1 "));
    tcp_write(conn->handle, (string) { tmp, 3 });
    tcp_write(conn->handle, S(" "));
    tcp_write(conn->handle, reason_phrase(status));
    tcp_write(conn->handle, S("\r\n"));

    conn->state = HTTP_CONN_STATE_HEADER;
}

void http_response_builder_header(HTTP_ResponseBuilder builder, string header)
{
    HTTP_Conn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_CONN_STATE_HEADER)
        return;

    tcp_write(conn->handle, header);
    tcp_write(conn->handle, S("\r\n"));
}

static void append_special_headers(HTTP_Conn *conn)
{
    if (conn->keep_alive) {
        tcp_write(conn->handle, S("Connection: Keep-Alive\r\n"));
    } else {
        tcp_write(conn->handle, S("Connection: Close\r\n"));
    }
    tcp_write(conn->handle, S("Content-Length: "));
    conn->content_length_header_offset = tcp_write_off(conn->handle);
    tcp_write(conn->handle, S("          "));
    tcp_write(conn->handle, S("\r\n"));
    tcp_write(conn->handle, S("\r\n"));
    conn->content_offset = tcp_write_off(conn->handle);
}

void http_response_builder_content(HTTP_ResponseBuilder builder, string content)
{
    HTTP_Conn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_CONN_STATE_STATUS)
        return;

    if (conn->state != HTTP_CONN_STATE_CONTENT) {
        append_special_headers(conn);
        conn->state = HTTP_CONN_STATE_CONTENT;
    }

    tcp_write(conn->handle, content);
}

void http_response_builder_submit(HTTP_ResponseBuilder builder)
{
    HTTP_Conn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_CONN_STATE_STATUS)
        return;

    if (conn->state != HTTP_CONN_STATE_CONTENT) {
        append_special_headers(conn);
        conn->state = HTTP_CONN_STATE_CONTENT;
    }

    TCP_Offset current_offset = tcp_write_off(conn->handle);
    int content_length = current_offset - conn->content_offset;

    char buf[11];
    int ret = snprintf(buf, sizeof(buf), "%d", content_length);
    assert(ret > 0);
    assert(ret < (int) sizeof(buf));
    tcp_patch(conn->handle, conn->content_length_header_offset, (string) { buf, ret });

    conn->num_served++;

    tcp_read_ack(conn->handle, conn->request_len);
    conn->request_len = 0;

    if (conn->keep_alive) {
        tcp_mark_ready(conn->handle);
        conn->ready = false;
        conn->state = HTTP_CONN_STATE_IDLE;
    } else {
        http_conn_free(conn);
        builder.server->num_conns--;
    }
}
