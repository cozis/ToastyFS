#ifdef TLS_ENABLED
#ifndef TLS_INCLUDED
#define TLS_INCLUDED

#include <stdbool.h>
#include "basic.h"

#define TLS_CERT_LIMIT 8

#ifdef TLS_SCHANNEL

#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <schannel.h>

#include "byte_queue.h"

typedef struct {
    char       domain[128];
    CredHandle cred;
} TLS_Cert;

typedef struct {
    CredHandle     cred;
    PCCERT_CONTEXT cert_ctx;
    int            num_certs;
    TLS_Cert       certs[TLS_CERT_LIMIT];
} TLS_Server;

typedef struct {
    CtxtHandle                ctx;
    bool                      ctx_valid;
    bool                      handshake;
    CredHandle               *cred;
    ByteQueue                 in_buf;
    ByteQueue                 out_buf;
    SecPkgContext_StreamSizes sizes;
    char                     *pending;
    int                       pending_off;
    int                       pending_len;
} TLS_Conn;

#else // OpenSSL

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st     SSL;
typedef struct bio_st     BIO;

typedef struct {
    char domain[128];
    SSL_CTX *ctx;
} TLS_Cert;

typedef struct {
    SSL_CTX *ctx;
    int num_certs;
    TLS_Cert certs[TLS_CERT_LIMIT];
} TLS_Server;

typedef struct {
    SSL  *ssl;
    BIO  *network_bio;
    bool  handshake;
} TLS_Conn;

#endif // TLS_SCHANNEL

void tls_global_init(void);
void tls_global_free(void);

int   tls_server_init(TLS_Server *server, string cert_file, string key_file);
void  tls_server_free(TLS_Server *server);
int   tls_server_add_cert(TLS_Server *server, string domain, string cert_file, string key_file);

int   tls_conn_init(TLS_Conn *conn, TLS_Server *server);
void  tls_conn_free(TLS_Conn *conn);

int   tls_conn_handshake(TLS_Conn *conn);

char *tls_conn_net_write_buf(TLS_Conn *conn, int *cap);
void  tls_conn_net_write_ack(TLS_Conn *conn, int num);

char *tls_conn_net_read_buf(TLS_Conn *conn, int *num);
void  tls_conn_net_read_ack(TLS_Conn *conn, int num);

int   tls_conn_app_write(TLS_Conn *conn, char *dst, int num);
int   tls_conn_app_read(TLS_Conn *conn, char *src, int cap);
int   tls_conn_needs_flushing(TLS_Conn *conn);

#endif // TLS_INCLUDED
#endif // TLS_ENABLED