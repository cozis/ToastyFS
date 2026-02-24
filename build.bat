@echo off
setlocal

set INCLUDES=-Iquakey/include -Iinclude -I.
set CFLAGS=-Wall -Wextra -ggdb -O0

set LIB_CORE=lib/basic.c lib/byte_queue.c lib/tcp.c
set LIB_FULL=%LIB_CORE% lib/file_system.c lib/message.c
set LIB_TLS=%LIB_FULL% lib/tls_schannel.c
set LIB_HTTP=%LIB_TLS% lib/http_parse.c lib/http_server.c

set SRC_SERVER=src/server.c src/log.c src/client_table.c src/chunk_store.c src/metadata.c

set QUAKEY=quakey/src/mockfs.c quakey/src/quakey.c

rem 1. Simulation
echo Building simulation...
gcc %LIB_FULL% %SRC_SERVER% src/client.c src/random_client.c src/main.c src/invariant_checker.c %QUAKEY% -o toastyfs_simulation.exe %INCLUDES% %CFLAGS% -DMAIN_SIMULATION -DFAULT_INJECTION -lws2_32
if errorlevel 1 goto :error

rem 2. Server
echo Building server...
gcc %LIB_TLS% %SRC_SERVER% src/main.c -o toastyfs_server.exe %INCLUDES% %CFLAGS% -DMAIN_SERVER -DTLS_ENABLED -DTLS_SCHANNEL -lws2_32 -lsecur32 -lcrypt32 -lncrypt
if errorlevel 1 goto :error

rem 3. Random client
echo Building random client...
gcc %LIB_CORE% src/client.c src/random_client.c src/main.c -o toastyfs_random_client.exe %INCLUDES% %CFLAGS% -DMAIN_CLIENT -lws2_32
if errorlevel 1 goto :error

rem 4. HTTP proxy
echo Building http proxy...
gcc %LIB_HTTP% src/client.c src/http_proxy.c src/main.c -o toastyfs_http_proxy.exe %INCLUDES% %CFLAGS% -DMAIN_HTTP_PROXY -DTLS_ENABLED -DTLS_SCHANNEL -lws2_32 -lsecur32 -lcrypt32 -lncrypt
if errorlevel 1 goto :error

echo Done.
goto :eof

:error
echo Build failed.
exit /b 1
