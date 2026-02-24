#ifdef TLS_ENABLED
#ifdef TLS_OPENSSL

#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <assert.h>

// Avoid name collision between basic.h's SHA256 typedef
// and OpenSSL's SHA256 function
#define SHA256 openssl_SHA256
#include <openssl/ssl.h>
#include <openssl/err.h>
#undef SHA256

#include "tls.h"

void tls_global_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void tls_global_free(void)
{
    EVP_cleanup();
}

static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    TLS_Server *server = arg;

    // The 'ad' parameter is used to set the alert description when returning
    // SSL_TLSEXT_ERR_ALERT_FATAL. Since we only return OK or NOACK, it's unused.
    (void) ad;

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    for (int i = 0; i < server->num_certs; i++) {
        TLS_Cert *cert = &server->certs[i];
        if (!strcmp(cert->domain, servername)) {
            SSL_set_SSL_CTX(ssl, cert->ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int tls_server_init(TLS_Server *server, string cert_file, string key_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    char cert_buf[1024];
    if (cert_file.len >= (int) sizeof(cert_buf)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buf, cert_file.ptr, cert_file.len);
    cert_buf[cert_file.len] = '\0';

    char key_buf[1024];
    if (key_file.len >= (int) sizeof(key_buf)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buf, key_file.ptr, key_file.len);
    key_buf[key_file.len] = '\0';

    // Load certificate and private key
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_buf) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_buf, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(ctx, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(ctx, server);

    server->ctx = ctx;
    server->num_certs = 0;
    return 0;
}

void tls_server_free(TLS_Server *server)
{
    for (int i = 0; i < server->num_certs; i++)
        SSL_CTX_free(server->certs[i].ctx);
    SSL_CTX_free(server->ctx);
}

// TODO: Can the domain be inferred from the cert?
int tls_server_add_cert(TLS_Server *server, string domain, string cert_file, string key_file)
{
    if (server->num_certs == TLS_CERT_LIMIT)
        return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    char cert_buf[1024];
    if (cert_file.len >= (int) sizeof(cert_buf)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buf, cert_file.ptr, cert_file.len);
    cert_buf[cert_file.len] = '\0';

    char key_buf[1024];
    if (key_file.len >= (int) sizeof(key_buf)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buf, key_file.ptr, key_file.len);
    key_buf[key_file.len] = '\0';

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_buf) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_buf, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    TLS_Cert *cert = &server->certs[server->num_certs];
    if (domain.len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    cert->ctx = ctx;
    server->num_certs++;
    return 0;
}

int tls_conn_init(TLS_Conn *conn, TLS_Server *server)
{
    SSL *ssl = SSL_new(server->ctx);
    if (ssl == NULL)
        return -1;

    // Create a BIO pair:
    //   internal_bio  — attached to the SSL object (OpenSSL uses it internally)
    //   network_bio   — you read/write encrypted data from/to this
    BIO *internal_bio = NULL;
    BIO *network_bio = NULL;
    if (!BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0)) {
        SSL_free(ssl);
        return -1;
    }

    // Bind the internal side to the SSL object
    SSL_set_bio(ssl, internal_bio, internal_bio);

    // We're the server side
    SSL_set_accept_state(ssl);

    conn->ssl = ssl;
    conn->network_bio = network_bio;
    conn->handshake = true;
    return 0;
}

void tls_conn_free(TLS_Conn *conn)
{
    SSL_free(conn->ssl);
    BIO_free(conn->network_bio);
}

// Write ciphertext from the connection object to the network
char *tls_conn_net_write_buf(TLS_Conn *conn, int *cap)
{
    char *buf;
    int ret = BIO_nwrite0(conn->network_bio, &buf);
    if (ret <= 0)
        return NULL;
    *cap = ret;
    return buf;
}

// Complete the write from the connection object
void tls_conn_net_write_ack(TLS_Conn *conn, int num)
{
    char *dummy;
    BIO_nwrite(conn->network_bio, &dummy, num);
}

// Read ciphertext from the network into the connection object
char *tls_conn_net_read_buf(TLS_Conn *conn, int *num)
{
    char *buf;
    int ret = BIO_nread0(conn->network_bio, &buf);
    if (ret <= 0)
        return NULL;
    *num = ret;
    return buf;
}

// Complete the read from the network
void tls_conn_net_read_ack(TLS_Conn *conn, int num)
{
    char *dummy;
    BIO_nread(conn->network_bio, &dummy, num);
}

// Write plaintext from the application to the connection object
int tls_conn_app_write(TLS_Conn *conn, char *dst, int num)
{
    assert(!conn->handshake);

    int n = SSL_write(conn->ssl, dst, num);
    if (n > 0)
        return n;

    int err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ ||
        err == SSL_ERROR_WANT_WRITE)
        return 0;

    return -1;
}

// Read plaintext from the connection object into the application
int tls_conn_app_read(TLS_Conn *conn, char *src, int cap)
{
    assert(!conn->handshake);

    int n = SSL_read(conn->ssl, src, cap);
    if (n > 0)
        return n;

    int err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ ||
        err == SSL_ERROR_WANT_WRITE)
        return 0;

    return -1;
}

int tls_conn_handshake(TLS_Conn *conn)
{
    assert(conn->handshake);

    int n = SSL_do_handshake(conn->ssl);
    if (n == 1) {
        conn->handshake = false;
        return 1;
    }

    int err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ ||
        err == SSL_ERROR_WANT_WRITE)
        return 0;

    return -1;
}

int tls_conn_needs_flushing(TLS_Conn *conn)
{
    return BIO_ctrl_pending(conn->network_bio) > 0;
}

#endif // TLS_OPENSSL
#endif // TLS_ENABLED
