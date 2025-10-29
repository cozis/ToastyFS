#ifndef SYSTEM_INCLUDED
#define SYSTEM_INCLUDED

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#if !defined(_WIN32) || defined(BUILD_TEST)
typedef int Socket;
#define BAD_SOCKET ((Socket) -1)
#else
typedef SOCKET Socket;
#define BAD_SOCKET INVALID_SOCKET
#endif

Socket sys_socket      (int domain, int type, int protocol);
int    sys_bind        (Socket fd, void *addr, size_t addr_len);
int    sys_listen      (Socket fd, int backlog);
int    sys_closesocket (Socket fd);
int    sys_poll        (struct pollfd *polled, int num_polled, int timeout);
Socket sys_accept      (Socket fd, void *addr, int *addr_len);
int    sys_getsockopt  (Socket fd, int level, int optname, void *optval, socklen_t *optlen);
int    sys_setsockopt  (Socket fd, int level, int optname, void *optval, socklen_t optlen);
int    sys_recv        (Socket fd, void *dst, int len, int flags);
int    sys_send        (Socket fd, void *src, int len, int flags);
int    sys_connect     (Socket fd, void *addr, size_t addr_len);

#endif // SYSTEM_INCLUDED
