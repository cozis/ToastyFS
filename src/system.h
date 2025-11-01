#include <stdio.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN

#include <direct.h> // _mkdir
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <poll.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SOCKET int
#define INVALID_SOCKET ((SOCKET) -1)

#endif

#ifdef BUILD_TEST

int    spawn_simulated_process(char *args);
void   update_simulation(void);
void   cleanup_simulation(void);

SOCKET mock_socket(int domain, int type, int protocol);
int    mock_bind(SOCKET fd, void *addr, size_t addr_len);
int    mock_listen(SOCKET fd, int backlog);
SOCKET mock_accept(SOCKET fd, void *addr, socklen_t *addr_len);
int    mock_getsockopt(SOCKET fd, int level, int optname, void *optval, socklen_t *optlen);
int    mock_setsockopt(SOCKET fd, int level, int optname, void *optval, socklen_t optlen);
int    mock_recv(SOCKET fd, void *dst, int len, int flags);
int    mock_send(SOCKET fd, void *src, int len, int flags);
int    mock_connect(SOCKET fd, void *addr, size_t addr_len);

// Common
#define sys_malloc           mock_malloc
#define sys_realloc          mock_realloc
#define sys_free             mock_free
#define sys_remove           mock_remove
#define sys_rename           mock_rename
#define sys_socket           mock_socket
#define sys_bind             mock_bind
#define sys_listen           mock_listen
#define sys_accept           mock_accept
#define sys_getsockopt       mock_getsockopt
#define sys_setsockopt       mock_setsockopt
#define sys_recv             mock_recv
#define sys_send             mock_send
#define sys_connect          mock_connect

// Windows
#define sys__mkdir           mock__mkdir
#define sys_closesocket      mock_closesocket
#define sys_CreateFileW      mock_CreateFileW
#define sys_CloseHandle      mock_CloseHandle
#define sys_LockFile         mock_LockFile
#define sys_UnlockFile       mock_UnlockFile
#define sys_FlushFileBuffers mock_FlushFileBuffers
#define sys_ReadFile         mock_ReadFile
#define sys_WriteFile        mock_WriteFile
#define sys_GetFileSizeEx    mock_GetFileSizeEx
#define sys__fullpath        mock__fullpath
#define sys_QueryPerformanceCounter   mock_QueryPerformanceCounter
#define sys_QueryPerformanceFrequency mock_QueryPerformanceFrequency

// Linux
#define sys_mkdir            mock_mkdir
#define sys_open             mock_open
#define sys_close            mock_close
#define sys_flock            mock_flock
#define sys_fsync            mock_fsync
#define sys_read             mock_read
#define sys_write            mock_write
#define sys_fstat            mock_fstat
#define sys_mkstemp          mock_mkstemp
#define sys_realpath         mock_realpath
#define sys_clock_gettime    mock_clock_gettime

#else

// Common
#define sys_malloc           malloc
#define sys_realloc          realloc
#define sys_free             free
#define sys_remove           remove
#define sys_rename           rename
#define sys_socket           socket
#define sys_bind             bind
#define sys_listen           listen
#define sys_accept           accept
#define sys_getsockopt       getsockopt
#define sys_setsockopt       setsockopt
#define sys_recv             recv
#define sys_send             send
#define sys_connect          connect

// Windows
#define sys__mkdir           _mkdir
#define sys_closesocket      closesocket
#define sys_CreateFileW      CreateFileW
#define sys_CloseHandle      CloseHandle
#define sys_LockFile         LockFile
#define sys_UnlockFile       UnlockFile
#define sys_FlushFileBuffers FlushFileBuffers
#define sys_ReadFile         ReadFile
#define sys_WriteFile        WriteFile
#define sys_GetFileSizeEx    GetFileSizeEx
#define sys__fullpath        _fullpath
#define sys_QueryPerformanceCounter   QueryPerformanceCounter
#define sys_QueryPerformanceFrequency QueryPerformanceFrequency

// Linux
#define sys_mkdir            mkdir
#define sys_open             open
#define sys_close            close
#define sys_flock            flock
#define sys_fsync            fsync
#define sys_read             read
#define sys_write            write
#define sys_fstat            fstat
#define sys_mkstemp          mkstemp
#define sys_realpath         realpath
#define sys_clock_gettime    clock_gettime

#endif
