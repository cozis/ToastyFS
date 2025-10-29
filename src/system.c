#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/file.h>

#include "system.h"

void *sys_malloc_(size_t len, char *file, int line)
{
    (void) file;
    (void) line;
    return malloc(len);
}

void *sys_realloc_(void *ptr, size_t len, char *file, int line)
{
    (void) file;
    (void) line;
    return realloc(ptr, len);
}

void sys_free_(void *ptr, char *file, int line)
{
    (void) file;
    (void) line;
    free(ptr);
}

int sys_remove(char *path)
{
    return remove(path);
}

int sys_rename(char *oldpath, char *newpath)
{
    return rename(oldpath, newpath);
}

#ifdef _WIN32

SOCKET sys_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int sys_bind(SOCKET fd, void *addr, size_t addr_len)
{
    return bind(fd, addr, addr_len);
}

int sys_listen(SOCKET fd, int backlog)
{
    return listen(fd, backlog);
}

int sys_closesocket(SOCKET fd)
{
    return closesocket(fd);
}

SOCKET sys_accept(SOCKET fd, void *addr, int *addr_len)
{
    return accept(fd, addr, addr_len);
}

int sys_getsockopt(SOCKET fd, int level, int optname, void *optval, int *optlen)
{
    return getsockopt(fd, level, optname, optval);
}

int sys_setsockopt(SOCKET fd, int level, int optname, void *optval, int optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}

int sys_recv(SOCKET fd, void *dst, int len, int flags)
{
    return recv(fd, dst, len, flags);
}

int sys_send(SOCKET fd, void *src, int len, int flags)
{
    return send(fd, src, len, flags);
}

int sys_connect(SOCKET fd, void *addr, size_t addr_len)
{
    return connect(fd, addr, addr_len);
}

BOOL sys_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
    return QueryPerformanceCounter(lpPerformanceCount);
}

BOOL sys_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    return QueryPerformanceFrequency(lpFrequency);
}

HANDLE sys_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL sys_CloseHandle(HANDLE handle)
{
    return CloseHandle(handle);
}

BOOL sys_LockFile(HANDLE handle)
{
    return LockFile(handle);
}

BOOL sys_UnlockFile(HANDLE handle)
{
    return UnlockFile(handle);
}

BOOL sys_FlushFileBuffers(HANDLE handle)
{
    return FlushFileBuffers(handle);
}

BOOL sys_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    return ReadFile(handle, dst, len, num, ov);
}

BOOL sys_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov)
{
    return WriteFile(handle, src, len, num, ov);
}

BOOL sys_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf)
{
    // TODO
}

char *sys__fullpath(char *path, char *dst, int cap)
{
    return _fullpath(path, dst, cap);
}

#else

int sys_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int sys_bind(int fd, void *addr, size_t addr_len)
{
    return bind(fd, addr, addr_len);
}

int sys_listen(int fd, int backlog)
{
    return listen(fd, backlog);
}

int sys_accept(int fd, void *addr, socklen_t *addr_len)
{
    return accept(fd, addr, addr_len);
}

int sys_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    return getsockopt(fd, level, optname, optval, optlen);
}

int sys_setsockopt(int fd, int level, int optname, void *optval, socklen_t optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}

int sys_recv(int fd, void *dst, int len, int flags)
{
    return recv(fd, dst, len, flags);
}

int sys_send(int fd, void *src, int len, int flags)
{
    return send(fd, src, len, flags);
}

int sys_connect(int fd, void *addr, size_t addr_len)
{
    return connect(fd, addr, addr_len);
}

int sys_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    return clock_gettime(clockid, tp);
}

int sys_open(char *path, int flags, int mode)
{
    return open(path, flags, mode);
}

int sys_close(int fd)
{
    return close(fd);
}

int sys_flock(int fd, int op)
{
    return flock(fd, op);
}

int sys_fsync(int fd)
{
    return fsync(fd);
}

int sys_read(int fd, char *dst, int len)
{
    return read(fd, dst, len);
}

int sys_write(int fd, char *src, int len)
{
    return write(fd, src, len);
}

int sys_fstat(int fd, struct stat *buf)
{
    return fstat(fd, buf);
}

int sys_mkstemp(char *path)
{
    return mkstemp(path);
}

char* sys_realpath(char *path, char *dst)
{
    return realpath(path, dst);
}

int sys_mkdir(char *path, mode_t mode)
{
    return mkdir(path, mode);
}

#endif
