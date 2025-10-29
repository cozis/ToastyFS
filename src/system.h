#include <stddef.h>

void *sys_malloc_ (size_t len,            char *file, int line);
void *sys_realloc_(void *ptr, size_t len, char *file, int line);
void  sys_free_   (void *ptr,             char *file, int line);

#define sys_malloc(len)       sys_malloc_ ((len),        __FILE__, __LINE__)
#define sys_realloc(ptr, len) sys_realloc_((ptr), (len), __FILE__, __LINE__)
#define sys_free(ptr)         sys_free_   ((ptr),        __FILE__, __LINE__)

int sys_remove(char *path);
int sys_rename(char *oldpath, char *newpath);

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

SOCKET sys_socket           (int domain, int type, int protocol);
int    sys_bind             (SOCKET fd, void *addr, size_t addr_len);
int    sys_listen           (SOCKET fd, int backlog);
int    sys_closesocket      (SOCKET fd);
SOCKET sys_accept           (SOCKET fd, void *addr, int *addr_len);
int    sys_getsockopt       (SOCKET fd, int level, int optname, void *optval, int *optlen);
int    sys_setsockopt       (SOCKET fd, int level, int optname, void *optval, int optlen);
int    sys_recv             (SOCKET fd, void *dst, int len, int flags);
int    sys_send             (SOCKET fd, void *src, int len, int flags);
int    sys_connect          (SOCKET fd, void *addr, size_t addr_len);
BOOL   sys_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL   sys_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
HANDLE sys_CreateFileW      (WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   sys_CloseHandle      (HANDLE handle);
BOOL   sys_LockFile         (HANDLE handle);
BOOL   sys_UnlockFile       (HANDLE handle);
BOOL   sys_FlushFileBuffers (HANDLE handle);
BOOL   sys_ReadFile         (HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL   sys_WriteFile        (HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL   sys_GetFileSizeEx    (HANDLE handle, LARGE_INTEGER *buf);
char*  sys__fullpath        (char *path, char *dst, int cap);

#else

#include <poll.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int   sys_socket            (int domain, int type, int protocol);
int   sys_bind              (int fd, void *addr, size_t addr_len);
int   sys_listen            (int fd, int backlog);
int   sys_accept            (int fd, void *addr, socklen_t *addr_len);
int   sys_getsockopt        (int fd, int level, int optname, void *optval, socklen_t *optlen);
int   sys_setsockopt        (int fd, int level, int optname, void *optval, socklen_t optlen);
int   sys_recv              (int fd, void *dst, int len, int flags);
int   sys_send              (int fd, void *src, int len, int flags);
int   sys_connect           (int fd, void *addr, size_t addr_len);
int   sys_clock_gettime     (clockid_t clockid, struct timespec *tp);
int   sys_open              (char *path, int flags, int mode);
int   sys_close             (int fd);
int   sys_flock             (int fd, int op);
int   sys_fsync             (int fd);
int   sys_read              (int fd, char *dst, int len);
int   sys_write             (int fd, char *src, int len);
int   sys_fstat             (int fd, struct stat *buf);
int   sys_mkstemp           (char *path);
char* sys_realpath          (char *path, char *dst);
int   sys_mkdir             (char *path, mode_t mode);

#endif
