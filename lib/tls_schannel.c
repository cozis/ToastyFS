#ifdef TLS_ENABLED
#ifdef TLS_SCHANNEL

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define SECURITY_WIN32
#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <schannel.h>

#include "tls.h"

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

#define TLS_BUF_LIMIT (32 * 1024)

// ============================================================
// Certificate loading
// ============================================================

// Read entire file into malloc'd buffer. Caller must free.
static char *read_file(const char *path, int *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0 || len > 1024 * 1024) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t) len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t) len, f);
    fclose(f);

    buf[nread] = '\0';
    *out_len = (int) nread;
    return buf;
}

// Decode PEM base64 content to DER binary. Returns malloc'd buffer.
static BYTE *pem_to_der(const char *pem, int pem_len, DWORD *out_len)
{
    DWORD len = 0;
    if (!CryptStringToBinaryA(pem, pem_len, CRYPT_STRING_BASE64HEADER,
                              NULL, &len, NULL, NULL))
        return NULL;

    BYTE *der = malloc(len);
    if (!der) return NULL;

    if (!CryptStringToBinaryA(pem, pem_len, CRYPT_STRING_BASE64HEADER,
                              der, &len, NULL, NULL)) {
        free(der);
        return NULL;
    }

    *out_len = len;
    return der;
}

// Import an in-memory PFX blob, acquire SChannel credential.
static int load_pfx_blob(const BYTE *pfx_data, DWORD pfx_len,
                          CredHandle *cred_out, PCCERT_CONTEXT *cert_ctx_out)
{
    CRYPT_DATA_BLOB blob;
    blob.pbData = (BYTE *) pfx_data;
    blob.cbData = pfx_len;

    HCERTSTORE store = PFXImportCertStore(&blob, L"", CRYPT_EXPORTABLE);
    if (!store) return -1;

    // Find first cert with a private key
    PCCERT_CONTEXT cert_ctx = NULL;
    while ((cert_ctx = CertEnumCertificatesInStore(store, cert_ctx)) != NULL) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hkey = 0;
        DWORD key_spec = 0;
        BOOL caller_free = FALSE;
        if (CryptAcquireCertificatePrivateKey(cert_ctx,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                NULL, &hkey, &key_spec, &caller_free)) {
            if (caller_free && hkey) {
                if (key_spec == CERT_NCRYPT_KEY_SPEC)
                    NCryptFreeObject(hkey);
                else
                    CryptReleaseContext(hkey, 0);
            }
            break;
        }
    }

    if (!cert_ctx) {
        CertCloseStore(store, 0);
        return -1;
    }

    PCCERT_CONTEXT dup_ctx = CertDuplicateCertificateContext(cert_ctx);

    SCHANNEL_CRED sc_cred = {0};
    sc_cred.dwVersion = SCHANNEL_CRED_VERSION;
    sc_cred.cCreds = 1;
    sc_cred.paCred = &dup_ctx;
    sc_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;

    TimeStamp expiry;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND,
        NULL, &sc_cred, NULL, NULL,
        cred_out, &expiry);

    if (ss != SEC_E_OK) {
        CertFreeCertificateContext(dup_ctx);
        CertCloseStore(store, 0);
        return -1;
    }

    *cert_ctx_out = dup_ctx;
    // Keep store open — SChannel needs access to the cert+key
    return 0;
}

// Load PEM cert+key using pure CryptoAPI (no external tools).
// Decodes PEM, imports key into a temporary CAPI keyset, exports as
// in-memory PFX, then imports via PFXImportCertStore.
static int load_pem_credential(string cert_file, string key_file,
                               CredHandle *cred_out, PCCERT_CONTEXT *cert_ctx_out)
{
    int result = -1;
    char cert_z[1024], key_z[1024], container[64];
    char *cert_pem = NULL, *key_pem = NULL;
    BYTE *cert_der = NULL, *key_der = NULL;
    BYTE *rsa_blob = NULL, *pkcs8_buf = NULL;
    PCCERT_CONTEXT cert_ctx = NULL;
    HCRYPTPROV hprov = 0;
    HCRYPTKEY hkey = 0;
    HCERTSTORE mem_store = NULL;
    CRYPT_DATA_BLOB pfx = {0};
    int cert_pem_len, key_pem_len;
    DWORD cert_der_len, key_der_len, rsa_blob_len, pkcs8_len;

    snprintf(container, sizeof(container), "tls_tmp_%lu",
             (unsigned long) GetCurrentProcessId());

    // Null-terminate file paths
    if (cert_file.len >= (int) sizeof(cert_z)) goto done;
    memcpy(cert_z, cert_file.ptr, cert_file.len);
    cert_z[cert_file.len] = '\0';

    if (key_file.len >= (int) sizeof(key_z)) goto done;
    memcpy(key_z, key_file.ptr, key_file.len);
    key_z[key_file.len] = '\0';

    // --- Certificate: PEM -> DER -> CERT_CONTEXT ---
    cert_pem = read_file(cert_z, &cert_pem_len);
    if (!cert_pem) goto done;

    cert_der = pem_to_der(cert_pem, cert_pem_len, &cert_der_len);
    if (!cert_der) goto done;

    cert_ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_der, cert_der_len);
    if (!cert_ctx) goto done;

    // --- Private key: PEM -> DER -> CAPI RSA blob ---
    key_pem = read_file(key_z, &key_pem_len);
    if (!key_pem) goto done;

    key_der = pem_to_der(key_pem, key_pem_len, &key_der_len);
    if (!key_der) goto done;

    if (strstr(key_pem, "-----BEGIN PRIVATE KEY-----")) {
        // PKCS#8: unwrap to get inner RSA key
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                key_der, key_der_len, CRYPT_DECODE_ALLOC_FLAG,
                NULL, &pkcs8_buf, &pkcs8_len))
            goto done;

        CRYPT_PRIVATE_KEY_INFO *pki = (CRYPT_PRIVATE_KEY_INFO *) pkcs8_buf;

        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                pki->PrivateKey.pbData, pki->PrivateKey.cbData,
                CRYPT_DECODE_ALLOC_FLAG, NULL, &rsa_blob, &rsa_blob_len))
            goto done;
    } else {
        // Traditional RSA (BEGIN RSA PRIVATE KEY)
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                key_der, key_der_len, CRYPT_DECODE_ALLOC_FLAG,
                NULL, &rsa_blob, &rsa_blob_len))
            goto done;
    }

    // --- Import key into temporary CAPI keyset ---
    CryptAcquireContextA(&hprov, container, MS_ENH_RSA_AES_PROV_A,
                         PROV_RSA_AES, CRYPT_DELETEKEYSET);
    hprov = 0;

    if (!CryptAcquireContextA(&hprov, container, MS_ENH_RSA_AES_PROV_A,
                              PROV_RSA_AES, CRYPT_NEWKEYSET))
        goto done;

    if (!CryptImportKey(hprov, rsa_blob, rsa_blob_len, 0, CRYPT_EXPORTABLE, &hkey))
        goto done;

    // --- Bind key to cert, export PFX in memory ---
    {
        wchar_t containerW[64];
        MultiByteToWideChar(CP_ACP, 0, container, -1, containerW, 64);

        CRYPT_KEY_PROV_INFO prov_info = {0};
        prov_info.pwszContainerName = containerW;
        prov_info.pwszProvName      = (LPWSTR) L"Microsoft Enhanced RSA and AES Cryptographic Provider";
        prov_info.dwProvType        = PROV_RSA_AES;
        prov_info.dwKeySpec         = AT_KEYEXCHANGE;

        if (!CertSetCertificateContextProperty(cert_ctx,
                CERT_KEY_PROV_INFO_PROP_ID, 0, &prov_info))
            goto done;
    }

    mem_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!mem_store) goto done;

    if (!CertAddCertificateContextToStore(mem_store, cert_ctx,
            CERT_STORE_ADD_ALWAYS, NULL))
        goto done;

    // Two-pass PFX export: get size, then export
    pfx.cbData = 0;
    pfx.pbData = NULL;
    if (!PFXExportCertStoreEx(mem_store, &pfx, L"", NULL, EXPORT_PRIVATE_KEYS))
        goto done;

    pfx.pbData = malloc(pfx.cbData);
    if (!pfx.pbData) goto done;

    if (!PFXExportCertStoreEx(mem_store, &pfx, L"", NULL, EXPORT_PRIVATE_KEYS))
        goto done;

    // --- Import PFX blob and acquire SChannel credential ---
    result = load_pfx_blob(pfx.pbData, pfx.cbData, cred_out, cert_ctx_out);

done:
    free(pfx.pbData);
    if (mem_store) CertCloseStore(mem_store, 0);
    if (hkey) CryptDestroyKey(hkey);
    if (hprov) CryptReleaseContext(hprov, 0);
    {   HCRYPTPROV tmp = 0;
        CryptAcquireContextA(&tmp, container, MS_ENH_RSA_AES_PROV_A,
                             PROV_RSA_AES, CRYPT_DELETEKEYSET); }
    if (pkcs8_buf) LocalFree(pkcs8_buf);
    if (rsa_blob) LocalFree(rsa_blob);
    free(key_der);
    free(key_pem);
    free(cert_der);
    free(cert_pem);
    if (cert_ctx) CertFreeCertificateContext(cert_ctx);
    return result;
}

// ============================================================
// Global init/free (no-ops for SChannel)
// ============================================================

void tls_global_init(void)
{
}

void tls_global_free(void)
{
}

// ============================================================
// Server init/free
// ============================================================

int tls_server_init(TLS_Server *server, string cert_file, string key_file)
{
    memset(server, 0, sizeof(*server));
    server->num_certs = 0;

    int ret = load_pem_credential(cert_file, key_file, &server->cred, &server->cert_ctx);
    if (ret < 0)
        return -1;

    return 0;
}

void tls_server_free(TLS_Server *server)
{
    FreeCredentialsHandle(&server->cred);
    if (server->cert_ctx) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hkey = 0;
        DWORD key_spec = 0;
        BOOL caller_free = FALSE;
        if (CryptAcquireCertificatePrivateKey(server->cert_ctx,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hkey, &key_spec, &caller_free)) {
            if (caller_free && hkey)
                NCryptFreeObject(hkey);
        }
        CertFreeCertificateContext(server->cert_ctx);
    }

    for (int i = 0; i < server->num_certs; i++)
        FreeCredentialsHandle(&server->certs[i].cred);
}

int tls_server_add_cert(TLS_Server *server, string domain, string cert_file, string key_file)
{
    if (server->num_certs >= TLS_CERT_LIMIT)
        return -1;

    TLS_Cert *cert = &server->certs[server->num_certs];
    if (domain.len >= (int) sizeof(cert->domain))
        return -1;

    PCCERT_CONTEXT cert_ctx = NULL;
    int ret = load_pem_credential(cert_file, key_file, &cert->cred, &cert_ctx);
    if (ret < 0)
        return -1;

    if (cert_ctx) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hkey = 0;
        DWORD key_spec = 0;
        BOOL caller_free = FALSE;
        if (CryptAcquireCertificatePrivateKey(cert_ctx,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hkey, &key_spec, &caller_free)) {
            if (caller_free && hkey)
                NCryptFreeObject(hkey);
        }
        CertFreeCertificateContext(cert_ctx);
    }

    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    server->num_certs++;
    return 0;
}

// ============================================================
// Connection init/free
// ============================================================

int tls_conn_init(TLS_Conn *conn, TLS_Server *server)
{
    memset(conn, 0, sizeof(*conn));
    conn->ctx_valid = false;
    conn->handshake = true;
    conn->cred = &server->cred;
    byte_queue_init(&conn->in_buf, TLS_BUF_LIMIT);
    byte_queue_init(&conn->out_buf, TLS_BUF_LIMIT);
    conn->pending = NULL;
    conn->pending_off = 0;
    conn->pending_len = 0;
    SecInvalidateHandle(&conn->ctx);
    return 0;
}

void tls_conn_free(TLS_Conn *conn)
{
    if (conn->ctx_valid)
        DeleteSecurityContext(&conn->ctx);
    byte_queue_free(&conn->in_buf);
    byte_queue_free(&conn->out_buf);
    free(conn->pending);
}

// ============================================================
// Handshake
// ============================================================

int tls_conn_handshake(TLS_Conn *conn)
{
    assert(conn->handshake);

    // Read available ciphertext from in_buf
    string in = byte_queue_read_buf(&conn->in_buf);
    if (!in.ptr || in.len == 0) {
        byte_queue_read_ack(&conn->in_buf, 0);
        return 0;
    }

    int in_avail = (int) in.len;

    // Input buffers
    SecBuffer in_bufs[2];
    in_bufs[0].BufferType = SECBUFFER_TOKEN;
    in_bufs[0].pvBuffer   = in.ptr;
    in_bufs[0].cbBuffer   = (unsigned long) in_avail;
    in_bufs[1].BufferType = SECBUFFER_EMPTY;
    in_bufs[1].pvBuffer   = NULL;
    in_bufs[1].cbBuffer   = 0;

    SecBufferDesc in_desc;
    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers  = 2;
    in_desc.pBuffers  = in_bufs;

    // Output buffers
    SecBuffer out_bufs[1];
    out_bufs[0].BufferType = SECBUFFER_TOKEN;
    out_bufs[0].pvBuffer   = NULL;
    out_bufs[0].cbBuffer   = 0;

    SecBufferDesc out_desc;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers  = 1;
    out_desc.pBuffers  = out_bufs;

    DWORD flags = ASC_REQ_STREAM
                | ASC_REQ_SEQUENCE_DETECT
                | ASC_REQ_REPLAY_DETECT
                | ASC_REQ_CONFIDENTIALITY
                | ASC_REQ_ALLOCATE_MEMORY;

    DWORD out_flags = 0;
    TimeStamp expiry;

    SECURITY_STATUS ss = AcceptSecurityContext(
        conn->cred,
        conn->ctx_valid ? &conn->ctx : NULL,
        &in_desc,
        flags,
        0,
        conn->ctx_valid ? NULL : &conn->ctx,
        &out_desc,
        &out_flags,
        &expiry);

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)
        conn->ctx_valid = true;

    // Copy output token to out_buf
    if (out_bufs[0].pvBuffer && out_bufs[0].cbBuffer > 0) {
        byte_queue_write_setmincap(&conn->out_buf, out_bufs[0].cbBuffer);
        byte_queue_write(&conn->out_buf, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
        FreeContextBuffer(out_bufs[0].pvBuffer);
    }

    // Calculate how much input was consumed
    int consumed = in_avail;
    if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0)
        consumed = in_avail - (int) in_bufs[1].cbBuffer;

    if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        // SChannel didn't consume anything
        byte_queue_read_ack(&conn->in_buf, 0);
        return 0;
    }

    byte_queue_read_ack(&conn->in_buf, consumed);

    if (ss == SEC_I_CONTINUE_NEEDED)
        return 0;

    if (ss == SEC_E_OK) {
        conn->handshake = false;
        ss = QueryContextAttributes(&conn->ctx, SECPKG_ATTR_STREAM_SIZES, &conn->sizes);
        if (ss != SEC_E_OK)
            return -1;
        return 1;
    }

    return -1;
}

// ============================================================
// Network I/O (ciphertext ↔ socket)
// ============================================================

char *tls_conn_net_write_buf(TLS_Conn *conn, int *cap)
{
    byte_queue_write_setmincap(&conn->in_buf, 4096);
    string bv = byte_queue_write_buf(&conn->in_buf);
    if (!bv.ptr || bv.len == 0) {
        byte_queue_write_ack(&conn->in_buf, 0);
        return NULL;
    }
    *cap = (int) bv.len;
    return (char *) bv.ptr;
}

void tls_conn_net_write_ack(TLS_Conn *conn, int num)
{
    byte_queue_write_ack(&conn->in_buf, num);
}

char *tls_conn_net_read_buf(TLS_Conn *conn, int *num)
{
    string bv = byte_queue_read_buf(&conn->out_buf);
    if (!bv.ptr || bv.len == 0) {
        byte_queue_read_ack(&conn->out_buf, 0);
        return NULL;
    }
    *num = (int) bv.len;
    return (char *) bv.ptr;
}

void tls_conn_net_read_ack(TLS_Conn *conn, int num)
{
    byte_queue_read_ack(&conn->out_buf, num);
}

// ============================================================
// Application I/O (encrypt/decrypt)
// ============================================================

int tls_conn_app_write(TLS_Conn *conn, char *src, int num)
{
    assert(!conn->handshake);

    if (num <= 0) return 0;

    int max_msg = (int) conn->sizes.cbMaximumMessage;
    if (num > max_msg)
        num = max_msg;

    int header_size  = (int) conn->sizes.cbHeader;
    int trailer_size = (int) conn->sizes.cbTrailer;
    int total = header_size + num + trailer_size;

    // Ensure output buffer has enough space
    byte_queue_write_setmincap(&conn->out_buf, total);
    string bv = byte_queue_write_buf(&conn->out_buf);
    if (!bv.ptr || (int) bv.len < total) {
        // Try with less data
        if (!bv.ptr || (int) bv.len < header_size + trailer_size + 1) {
            byte_queue_write_ack(&conn->out_buf, 0);
            return 0;
        }
        num = (int) bv.len - header_size - trailer_size;
        total = header_size + num + trailer_size;
    }

    char *out_ptr = (char *) bv.ptr;

    // Copy plaintext into the data portion
    memcpy(out_ptr + header_size, src, num);

    // Set up SecBuffers for in-place encryption
    SecBuffer bufs[4];
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer   = out_ptr;
    bufs[0].cbBuffer   = (unsigned long) header_size;

    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer   = out_ptr + header_size;
    bufs[1].cbBuffer   = (unsigned long) num;

    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer   = out_ptr + header_size + num;
    bufs[2].cbBuffer   = (unsigned long) trailer_size;

    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].pvBuffer   = NULL;
    bufs[3].cbBuffer   = 0;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers  = 4;
    desc.pBuffers  = bufs;

    SECURITY_STATUS ss = EncryptMessage(&conn->ctx, 0, &desc, 0);
    if (ss != SEC_E_OK) {
        byte_queue_write_ack(&conn->out_buf, 0);
        return -1;
    }

    int written = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    byte_queue_write_ack(&conn->out_buf, written);

    return num;
}

int tls_conn_app_read(TLS_Conn *conn, char *dst, int cap)
{
    assert(!conn->handshake);

    // Drain any pending plaintext from a previous partial read
    if (conn->pending_len > 0) {
        int n = conn->pending_len;
        if (n > cap) n = cap;
        memcpy(dst, conn->pending + conn->pending_off, n);
        conn->pending_off += n;
        conn->pending_len -= n;
        if (conn->pending_len == 0) {
            free(conn->pending);
            conn->pending = NULL;
            conn->pending_off = 0;
        }
        return n;
    }

    string in = byte_queue_read_buf(&conn->in_buf);
    if (!in.ptr || in.len == 0) {
        byte_queue_read_ack(&conn->in_buf, 0);
        return 0;
    }

    int in_avail = (int) in.len;

    // DecryptMessage operates in-place
    SecBuffer bufs[4];
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].pvBuffer   = in.ptr;
    bufs[0].cbBuffer   = (unsigned long) in_avail;
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[1].pvBuffer   = NULL;
    bufs[1].cbBuffer   = 0;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[2].pvBuffer   = NULL;
    bufs[2].cbBuffer   = 0;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].pvBuffer   = NULL;
    bufs[3].cbBuffer   = 0;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers  = 4;
    desc.pBuffers  = bufs;

    SECURITY_STATUS ss = DecryptMessage(&conn->ctx, &desc, 0, NULL);

    if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        byte_queue_read_ack(&conn->in_buf, 0);
        return 0;
    }

    if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE) {
        byte_queue_read_ack(&conn->in_buf, 0);
        return -1;
    }

    // Find decrypted data and extra ciphertext buffers
    SecBuffer *data_buf = NULL;
    SecBuffer *extra_buf = NULL;
    for (int i = 0; i < 4; i++) {
        if (bufs[i].BufferType == SECBUFFER_DATA)
            data_buf = &bufs[i];
        else if (bufs[i].BufferType == SECBUFFER_EXTRA)
            extra_buf = &bufs[i];
    }

    int result = 0;
    if (data_buf && data_buf->cbBuffer > 0) {
        int total = (int) data_buf->cbBuffer;
        int n = total;
        if (n > cap) n = cap;
        memcpy(dst, data_buf->pvBuffer, n);
        result = n;

        // Save excess plaintext for next call
        int leftover = total - n;
        if (leftover > 0) {
            conn->pending = malloc(leftover);
            if (conn->pending) {
                memcpy(conn->pending, (char *) data_buf->pvBuffer + n, leftover);
                conn->pending_off = 0;
                conn->pending_len = leftover;
            }
        }
    }

    // Consume processed input, keeping any extra ciphertext
    int consumed = in_avail;
    if (extra_buf && extra_buf->cbBuffer > 0)
        consumed = in_avail - (int) extra_buf->cbBuffer;
    byte_queue_read_ack(&conn->in_buf, consumed);

    if (ss == SEC_I_RENEGOTIATE)
        return result > 0 ? result : 0;

    return result;
}

int tls_conn_needs_flushing(TLS_Conn *conn)
{
    return !byte_queue_empty(&conn->out_buf);
}

#endif // TLS_SCHANNEL
#endif // TLS_ENABLED
