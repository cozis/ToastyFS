#ifndef QUAKEY_INCLUDED
#define QUAKEY_INCLUDED

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#else
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#endif

typedef struct {} Quakey;

// Function pointers to a simulated program's code
typedef int (*QuakeyInitFunc)(void *state, int argc, char **argv, void **ctxs, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyTickFunc)(void *state, void **ctxs, struct pollfd *pdata, int pcap, int *pnum, int *timeout);
typedef int (*QuakeyFreeFunc)(void *state);

typedef struct {

    // Label associated to the process for debugging
    // The string must have global lifetime
    char *name;

    // Size of the opaque state struct
    int state_size;

    // Pointers to program code
    QuakeyInitFunc init_func;
    QuakeyTickFunc tick_func;
    QuakeyFreeFunc free_func;

    // Network addresses enabled on the process
    char **addrs;
    int num_addrs;

    // Disk size for the process
    int disk_size;

} QuakeySpawn;

typedef unsigned long long QuakeyUInt64;

// Start a simulation
int quakey_init(Quakey **quakey, QuakeyUInt64 seed);

// Stop a simulation
void quakey_free(Quakey *quakey);

typedef unsigned long long QuakeyNode;

// Add a program to the simulation
QuakeyNode quakey_spawn(Quakey *quakey, QuakeySpawn config, char *arg);

void *quakey_node_state(QuakeyNode node);

// Schedule and executes one program until it would block, then returns
int quakey_schedule_one(Quakey *quakey);

// Generate a random u64
QuakeyUInt64 quakey_random(void);

typedef struct {
    char name[32];
    int  name_len;
} QuakeySignal;

void quakey_signal(char *name);
int  quakey_get_signal(Quakey *quakey, QuakeySignal *signal);

// Access spawned host information
int         quakey_num_hosts(Quakey *quakey);
void       *quakey_host_state(Quakey *quakey, int idx);  // Returns NULL if host is dead
int         quakey_host_is_dead(Quakey *quakey, int idx);
const char *quakey_host_name(Quakey *quakey, int idx);

// Fault injection control
void quakey_set_max_crashes(Quakey *quakey, int max_crashes);
void quakey_network_partitioning(Quakey *quakey, bool enabled);

// Simulation time
QuakeyUInt64 quakey_current_time(Quakey *quakey);

// Host context (for accessing mock filesystem from outside scheduled context)
void quakey_enter_host(QuakeyNode node);
void quakey_leave_host(void);

int *mock_errno_ptr(void);

// Network mocks (POSIX-style, available on all platforms)
int   mock_socket(int domain, int type, int protocol);
int   mock_bind(int fd, void *addr, unsigned long addr_len);
int   mock_connect(int fd, void *addr, unsigned long addr_len);
int   mock_getsockopt(int fd, int level, int optname, void *optval, unsigned int *optlen);
int   mock_listen(int fd, int backlog);
int   mock_accept(int fd, void *addr, unsigned int *addr_len);
int   mock_pipe(int *fds);
int   mock_recv(int fd, char *dst, int len, int flags);
int   mock_send(int fd, char *src, int len, int flags);

#ifdef _WIN32
// Windows-specific socket functions (use SOCKET type)
int   mock_closesocket(SOCKET fd);
int   mock_ioctlsocket(SOCKET fd, long cmd, unsigned long *argp);
BOOL   mock_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL   mock_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
HANDLE mock_CreateFileW(WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   mock_CloseHandle(HANDLE handle);
BOOL   mock_ReadFile(HANDLE handle, char *dst, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL   mock_WriteFile(HANDLE handle, char *src, DWORD len, DWORD *num, OVERLAPPED *ov);
BOOL   mock_GetFileSizeEx(HANDLE handle, LARGE_INTEGER *buf);
DWORD  mock_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL   mock_LockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh);
BOOL   mock_UnlockFile(HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh);
BOOL   mock_FlushFileBuffers(HANDLE handle);
BOOL   mock_MoveFileExW(WCHAR *lpExistingFileName, WCHAR *lpNewFileName, DWORD dwFlags);
char*  mock__fullpath(char *path, char *dst, int cap);
HANDLE mock_FindFirstFileA(char *lpFileName, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData);
BOOL   mock_FindClose(HANDLE hFindFile);
int    mock__mkdir(char *path);
int   mock_open(char *path, int flags, int mode);
int   mock_close(int fd);
int   mock_read(int fd, char *dst, int len);
int   mock_write(int fd, char *src, int len);
int   mock_remove(char *path);
int   mock_rename(char *oldpath, char *newpath);
int   mock_mkdir(char *path, int mode);
#else
int   mock_clock_gettime(clockid_t clockid, struct timespec *tp);
int   mock_open(char *path, int flags, int mode);
int   mock_fcntl(int fd, int cmd, int flags);
int   mock_close(int fd);
int   mock_ftruncate(int fd, size_t new_size);
int   mock_fstat(int fd, struct stat *buf);
int   mock_read(int fd, char *dst, int len);
int   mock_write(int fd, char *src, int len);
off_t mock_lseek(int fd, off_t offset, int whence);
int   mock_flock(int fd, int op);
int   mock_fsync(int fd);
int   mock_mkstemp(char *path);
int   mock_mkdir(char *path, mode_t mode);
int   mock_remove(char *path);
int   mock_rename(char *oldpath, char *newpath);
char* mock_realpath(char *path, char *dst);
DIR*  mock_opendir(char *name);
struct dirent* mock_readdir(DIR *dirp);
int   mock_closedir(DIR *dirp);
#endif

void *mock_malloc(size_t size);
void *mock_realloc(void *ptr, size_t size);
void  mock_free(void *ptr);

#ifdef QUAKEY_ENABLE_MOCKS

#define QUAKEY_SIGNAL(name) quakey_signal(name)

#undef errno
#define errno (*mock_errno_ptr())

#define malloc           mock_malloc
#define realloc          mock_realloc
#define free             mock_free
#define socket           mock_socket
#define closesocket      mock_closesocket
#define ioctlsocket      mock_ioctlsocket
#define bind             mock_bind
#define connect          mock_connect
#define getsockopt       mock_getsockopt
#define listen           mock_listen
#define accept           mock_accept
#define pipe             mock_pipe
#define recv             mock_recv
#define send             mock_send
#define clock_gettime    mock_clock_gettime
#define QueryPerformanceCounter   mock_QueryPerformanceCounter
#define QueryPerformanceFrequency mock_QueryPerformanceFrequency
#define open             mock_open
#define fcntl            mock_fcntl
#define close            mock_close
#define ftruncate        mock_ftruncate
#define CreateFileW      mock_CreateFileW
#define CloseHandle      mock_CloseHandle
#define ReadFile         mock_ReadFile
#define WriteFile        mock_WriteFile
#define read             mock_read
#define write            mock_write
#define fstat            mock_fstat
#define GetFileSizeEx    mock_GetFileSizeEx
#define lseek            mock_lseek
#define SetFilePointer   mock_SetFilePointer
#define flock            mock_flock
#define LockFile         mock_LockFile
#define UnlockFile       mock_UnlockFile
#define fsync            mock_fsync
#define FlushFileBuffers mock_FlushFileBuffers
#define mkstemp          mock_mkstemp
#define mkdir            mock_mkdir
#define _mkdir           mock__mkdir
#define remove           mock_remove
#define rename           mock_rename
#define MoveFileExW      mock_MoveFileExW
#define realpath         mock_realpath
#define _fullpath        mock__fullpath
#define opendir          mock_opendir
#define readdir          mock_readdir
#define closedir         mock_closedir
#define FindFirstFileA   mock_FindFirstFileA
#define FindNextFileA    mock_FindNextFileA
#define FindClose        mock_FindClose

#else

#define QUAKEY_SIGNAL(name) ((void) (name))

#endif

#endif // QUAKEY_INCLUDED