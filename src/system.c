#ifndef BUILD_TEST

#include "system.h"

Socket sys_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int sys_bind(Socket fd, void *addr, size_t addr_len)
{
    return bind(fd, addr, addr_len);
}

int sys_listen(Socket fd, int backlog)
{
    return listen(fd, backlog);
}

int sys_closesocket(Socket fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

int sys_poll(struct pollfd *polled, int num_polled, int timeout)
{
#ifdef _WIN32
    return WSAPoll(polled, num_polled, timeout);
#else
    return poll(polled, num_polled, timeout);
#endif
}

Socket sys_accept(Socket fd, void *addr, int *addr_len)
{
    return accept(fd, addr, addr_len);
}

int sys_getsockopt(Socket fd, int level, int optname, void *optval, socklen_t *optlen)
{
    return getsockopt(fd, level, optname, optval, optlen);
}

int sys_setsockopt(Socket fd, int level, int optname, void *optval, socklen_t optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}

int sys_recv(Socket fd, void *dst, int len, int flags)
{
    return recv(fd, dst, len, flags);
}

int sys_send(Socket fd, void *src, int len, int flags)
{
    return send(fd, src, len, flags);
}

int sys_connect(Socket fd, void *addr, size_t addr_len)
{
    return connect(fd, addr, addr_len);
}

#endif // BUILD_TEST
