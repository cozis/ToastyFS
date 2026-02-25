set QKY_FILES=quakey/src/mockfs.c quakey/src/quakey.c
set LIB_FILES=lib/basic.c lib/byte_queue.c lib/file_system.c lib/http_parse.c lib/http_server.c lib/message.c lib/tcp.c lib/tls_openssl.c lib/tls_schannel.c
set SRC_FILES=src/chunk_store.c src/client.c src/client_table.c src/http_proxy.c src/invariant_checker.c src/log.c src/main.c src/metadata.c src/random_client.c src/server.c
set FLAGS=-Wall -Wextra -ggdb -O0 -Iquakey/include -Iinclude -I.

gcc -o toasty_simulation    %LIB_FILES% %SRC_FILES% %QKY_FILES% %FLAGS% -DMAIN_SIMULATION -DFAULT_INJECTION -lws2_32
gcc -o toasty               %LIB_FILES% %SRC_FILES% %FLAGS% -DMAIN_SERVER -lws2_32
gcc -o toasty_random_client %LIB_FILES% %SRC_FILES% %FLAGS% -DMAIN_CLIENT -lws2_32
gcc -o toasty_proxy         %LIB_FILES% %SRC_FILES% %FLAGS% -DMAIN_HTTP_PROXY -DTLS_ENABLED -DTLS_SCHANNEL -lws2_32 -lsecur32 -lcrypt32 -lncrypt
