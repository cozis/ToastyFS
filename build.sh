#!/bin/bash
set -e

INCLUDES="-Iquakey/include -Iinclude -I."
CFLAGS="-Wall -Wextra -ggdb -O0"

LIB_CORE="lib/basic.c lib/byte_queue.c lib/tcp.c"
LIB_FULL="$LIB_CORE lib/file_system.c lib/message.c"
LIB_TLS="$LIB_FULL lib/tls_openssl.c"
LIB_HTTP="$LIB_TLS lib/http_parse.c lib/http_server.c"

SRC_SERVER="src/server.c src/log.c src/client_table.c src/chunk_store.c src/metadata.c"

QUAKEY="quakey/src/mockfs.c quakey/src/quakey.c"

# 1. Simulation
echo "Building simulation..."
gcc $LIB_FULL \
    $SRC_SERVER src/client.c src/random_client.c src/main.c src/invariant_checker.c \
    $QUAKEY \
    -o toastyfs_simulation \
    $INCLUDES $CFLAGS -DMAIN_SIMULATION -DFAULT_INJECTION

# 2. Server
echo "Building server..."
gcc $LIB_TLS \
    $SRC_SERVER src/main.c \
    -o toastyfs_server \
    $INCLUDES $CFLAGS -DMAIN_SERVER -DTLS_ENABLED -DTLS_OPENSSL -lssl -lcrypto

# 3. Random client
echo "Building random client..."
gcc $LIB_CORE lib/message.c \
    src/client.c src/random_client.c src/main.c \
    -o toastyfs_random_client \
    $INCLUDES $CFLAGS -DMAIN_CLIENT

# 4. HTTP proxy
echo "Building http proxy..."
gcc $LIB_HTTP \
    src/client.c src/http_proxy.c src/main.c \
    -o toastyfs_http_proxy \
    $INCLUDES $CFLAGS -DMAIN_HTTP_PROXY -DTLS_ENABLED -DTLS_OPENSSL -lssl -lcrypto

echo "Done."
