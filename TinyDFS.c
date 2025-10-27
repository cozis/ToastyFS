// Architecture
//   A TinyDFS instance is composed by a metadata server, a number
//   of chunk servers, and a number of clients.
//
//   The metadata server stores the full file system hieararchy,
//   except instead of storing the file contents, it stores an
//   array of hashes of the chunks of each file. A "chunk" is a
//   file range that is fixed for a single file but may vary
//   between files. Chunk servers hold an array of chunks that
//   are identified by their hash. The metadata server keeps
//   track of which chunks each chunk server is holding.
//
//   Clients are users of the file system that can read and
//   write metadata and files. They are assumed to behave
//   correctly.
//
//   Any read and write operation that doesn't involve file
//   contents can be performed by clients by talking to the
//   metadata server directly. Such operations include creating
//   an empty file or a directory, deleting a file or directory,
//   listing files.
//
//   If a client wants to read a range of bytes from a file,
//   it sends the metadata server the file name and range.
//   The metadata server responds with the chunk size of that
//   file, the list of hashes for the chunks involved in the
//   read, and the IP addresses of the chunk servers that hold
//   each chunk. The metadata server also adds the IP addresses
//   of three chunk servers any new chunks should be written
//   to. The client can then download the chunks from the chunk
//   servers and reassemble the result.
//
//   If a client wants to write at a range of bytes of a file,
//   it starts by reading that range from the metadata server,
//   getting the list of hashes it will modify, their locations,
//   and locations for any new chunks. The client then modifies
//   the chunk by sending to each chunk server the hash to modify
//   and the patch (a range of bytes within a chunk plus the new
//   data). The chunk server creates a new modified chunk and
//   keeps the old version, then returns the new hash. If all
//   modifications are successful, the client holds the set of
//   old hashes and new hashes for that file range. It completes
//   the write by telling the metadata server to swap the old
//   hashes with the new ones. If the old hashes don't match,
//   another write succeded in the mean time and touched that
//   range, therefore the write fails. If the old hashes match,
//   the write succeded. If the client fails to modify any
//   chunks, it doesn't commit the write with the metadata server.
//   Note that write failures may cause chunks to be orphaned
//   on chunk servers. This is solved by a garbage collection
//   algorithm implemented by the synchronization messages
//   between metadata and chunk server.
//
//   Note that clients may cache chunks and index them by their
//   hash. When they read a file and receive its hashes, they may
//   avoid reaching for the chunk servers if they already cached
//   the chunks with those hashes. This allows reading files with
//   only one round trip at no cost of correctness. If getting
//   the up-to-date contents is not a concern, clients may also
//   cache file metadata.
//
// Metadata and chunk server exchange:
//
//   The metadata server is only aware of each chunk server
//   as long as they have a TCP connection. When a chunk server
//   first connects to the metadata server, it authenticates
//   itself and sends its own IP addresses. If the server is
//   authentic, the metadata server requests the full list
//   of chunks the chunk server is holding. Upon receiving the
//   state of chunk server, the metadata server adds all useful
//   chunks to the "old_list" and all useless chunks to the
//   "rem_list", then sends the rem_list to the chunk server
//   which removes those chunks.
//
//   When writes are committed to the metadata server involving
//   new chunks to a chunk server, the metadata server adds those
//   hashes to an "add_list" and any hashes that are not useful
//   anymore to the rem_list.
//
//   Periodically, the metadata server sends the add_list and
//   rem_list to the chunk server. These list tell the chunk
//   server the ideal state it should have from the point of
//   view of the metadata server. Elements in the add_list should
//   already be in the chunk servers, and elements from the
//   rem_list are to be removed. A chunk server marks any chunk
//   in the rem_list as to be removed and checks that hashes
//   in the add list are present. If a chunk in the add list
//   is marked as to be removed, it is unmarked. When a chunk
//   is marked as to be removed for a certain amount of time,
//   it is permanently deleted. When the synchronization is
//   complete, the metadata server merges the add_list into
//   the old_list and clears the rem_list. If chunks in the
//   add_list are not present in the chunk server, it responds
//   with an error message containing the list of missing chunks.
//   The metadata server then responds with a list of chunk
//   server addresses where the chunk server with the missing
//   chunk can download it from. Each chunk server goes
//   through its download list one at the time downloading
//   the missing chunks.
//
//   Note that if the chunk server finds that its holding some
//   chunks that are not in the hash list of the metadata server,
//   that does not mean they are orphaned. It's possible that
//   some writes are being performed by clients that have uploaded
//   chunks to that chunk server but didn't yet acknowledge it
//   to the metadata server. If all goes well and the write
//   succeded, the metadata server will add those hashes to the
//   hash list. Chunk servers should only drop chunks if they
//   are not referenced by the metadata server for a period of
//   time (say, 30 minutes).
//
// Security
//   All nodes of the system share a secret key and use it to
//   authenticate each other and encrypt messages. This allows
//   the server to accept new chunk servers and clients with
//   no prior setup
//
// Reliability
//   The metadata server is a single point of failure. To reduce
//   the impact of crashes, the metadata server stores all write
//   operations into a write-ahead log that is replayed any time
//   the process goes online.
//
// TODO: When a write occurs, the written to chunks must be marked
//       as orphaned or "to-be-deleted" unless they are used by
//       someone else

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define POLL WSAPoll
#define CLOSE_SOCKET closesocket
#else
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define POLL poll
#define CLOSE_SOCKET close
#endif

#if !defined(BUILD_METADATA_SERVER) && !defined(BUILD_CHUNK_SERVER)
#define BUILD_METADATA_SERVER
#endif

//////////////////////////////////////////////////////////////////////////
// BASICS
//////////////////////////////////////////////////////////////////////////

typedef struct {
    char data[64];
} SHA256;

typedef struct {
    char *ptr;
    int   len;
} string;

typedef uint64_t Time;
#define INVALID_TIME ((Time) -1)

#define S(X) ((string) { (X), (int) sizeof(X)-1 })

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

#define UNREACHABLE __builtin_trap();

static bool streq(string s1, string s2)
{
    if (s1.len != s2.len)
        return false;
    for (int i = 0; i < s1.len; i++)
        if (s1.ptr[i] != s2.ptr[i])
            return false;
    return true;
}

// Returns the current time in milliseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
static Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000000000)
            return INVALID_TIME;
        res = sec * 1000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}

//////////////////////////////////////////////////////////////////////////
// SHA256
//////////////////////////////////////////////////////////////////////////

//usr/bin/env clang -Ofast -Wall -Wextra -pedantic ${0} -o ${0%%.c*} $* ;exit $?
//
//  SHA-256 implementation, Mark 2
//
//  Copyright (c) 2010,2014 Literatecode, http://www.literatecode.com
//  Copyright (c) 2022 Ilia Levin (ilia@levin.sg)
//
//  Permission to use, copy, modify, and distribute this software for any
//  purpose with or without fee is hereby granted, provided that the above
//  copyright notice and this permission notice appear in all copies.
//
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

#define SHA256_SIZE_BYTES    (32)

typedef struct {
    uint8_t  buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[64];
} sha256_context;

#ifndef _cbmc_
#define __CPROVER_assume(...) do {} while(0)
#endif

#define FN_ static inline __attribute__((const))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
    return ((x >> (n & 31)) & 0xff);
}

FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
    return ((x << (n & 31)) & 0xffffffff);
}

FN_ uint32_t _r(uint32_t x, uint8_t n)
{
    return ((x >> n) | _shw(x, 32 - n));
}

FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ ((~x) & z));
}

FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (x & z) ^ (y & z));
}

FN_ uint32_t _S0(uint32_t x)
{
    return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
}

FN_ uint32_t _S1(uint32_t x)
{
    return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
}

FN_ uint32_t _G0(uint32_t x)
{
    return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
}

FN_ uint32_t _G1(uint32_t x)
{
    return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
}

FN_ uint32_t _word(uint8_t *c)
{
    return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
}

static void _addbits(sha256_context *ctx, uint32_t n)
{
    __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

    if (ctx->bits[0] > (0xffffffff - n)) {
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    }
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} // _addbits

static void _hash(sha256_context *ctx)
{
    __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

    register uint32_t a, b, c, d, e, f, g, h;
    uint32_t t[2];

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    for (uint32_t i = 0; i < 64; i++) {
        if (i < 16) {
            ctx->W[i] = _word(&ctx->buf[_shw(i, 2)]);
        } else {
            ctx->W[i] = _G1(ctx->W[i - 2])  + ctx->W[i - 7] +
                        _G0(ctx->W[i - 15]) + ctx->W[i - 16];
        }

        t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + ctx->W[i];
        t[1] = _S0(a) + _Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
}

static void sha256_init(sha256_context *ctx)
{
    if (ctx != NULL) {
        ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
        ctx->hash[0] = 0x6a09e667;
        ctx->hash[1] = 0xbb67ae85;
        ctx->hash[2] = 0x3c6ef372;
        ctx->hash[3] = 0xa54ff53a;
        ctx->hash[4] = 0x510e527f;
        ctx->hash[5] = 0x9b05688c;
        ctx->hash[6] = 0x1f83d9ab;
        ctx->hash[7] = 0x5be0cd19;
    }
}

static void sha256_hash(sha256_context *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    if ((ctx != NULL) && (bytes != NULL) && (ctx->len < sizeof(ctx->buf))) {
        __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(bytes));
        __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));
        for (size_t i = 0; i < len; i++) {
            ctx->buf[ctx->len++] = bytes[i];
            if (ctx->len == sizeof(ctx->buf)) {
                _hash(ctx);
                _addbits(ctx, sizeof(ctx->buf) * 8);
                ctx->len = 0;
            }
        }
    }
}

static void sha256_done(sha256_context *ctx, uint8_t *hash)
{
    register uint32_t i, j;

    if (ctx != NULL) {
        j = ctx->len % sizeof(ctx->buf);
        ctx->buf[j] = 0x80;
        for (i = j + 1; i < sizeof(ctx->buf); i++) {
            ctx->buf[i] = 0x00;
        }

        if (ctx->len > 55) {
            _hash(ctx);
            for (j = 0; j < sizeof(ctx->buf); j++) {
                ctx->buf[j] = 0x00;
            }
        }

        _addbits(ctx, ctx->len * 8);
        ctx->buf[63] = _shb(ctx->bits[0],  0);
        ctx->buf[62] = _shb(ctx->bits[0],  8);
        ctx->buf[61] = _shb(ctx->bits[0], 16);
        ctx->buf[60] = _shb(ctx->bits[0], 24);
        ctx->buf[59] = _shb(ctx->bits[1],  0);
        ctx->buf[58] = _shb(ctx->bits[1],  8);
        ctx->buf[57] = _shb(ctx->bits[1], 16);
        ctx->buf[56] = _shb(ctx->bits[1], 24);
        _hash(ctx);

        if (hash != NULL) {
            for (i = 0, j = 24; i < 4; i++, j -= 8) {
                hash[i +  0] = _shb(ctx->hash[0], j);
                hash[i +  4] = _shb(ctx->hash[1], j);
                hash[i +  8] = _shb(ctx->hash[2], j);
                hash[i + 12] = _shb(ctx->hash[3], j);
                hash[i + 16] = _shb(ctx->hash[4], j);
                hash[i + 20] = _shb(ctx->hash[5], j);
                hash[i + 24] = _shb(ctx->hash[6], j);
                hash[i + 28] = _shb(ctx->hash[7], j);
            }
        }
    }
}

static void sha256(const void *data, size_t len, uint8_t *hash)
{
    sha256_context ctx;

    sha256_init(&ctx);
    sha256_hash(&ctx, data, len);
    sha256_done(&ctx, hash);
}

//////////////////////////////////////////////////////////////////////////
// FILE SYSTEM
//////////////////////////////////////////////////////////////////////////

#ifdef __linux__
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

typedef struct {
    uint64_t data;
} Handle;

static int rename_file_or_dir(string oldpath, string newpath);

static int file_open(string path, Handle *fd)
{
#ifdef __linux__
    char zt[1<<10];
    if (path.len >= (int) sizeof(zt))
        return -1;
    memcpy(zt, path.ptr, path.len);
    zt[path.len] = '\0';

    int ret = open(zt, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (ret < 0)
        return -1;

    *fd = (Handle) { (uint64_t) ret };
    return 0;
#endif

#ifdef _WIN32
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path.ptr, path.len, wpath, MAX_PATH);
    wpath[path.len] = L'\0';

    HANDLE h = CreateFileW(
        wpath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE)
        return -1;

    *fd = (Handle) { (uint64_t) h };
    return 0;
#endif
}

static void file_close(Handle fd)
{
#ifdef __linux__
    close((int) fd.data);
#endif

#ifdef _WIN32
    CloseHandle((HANDLE) fd.data);
#endif
}

static int file_lock(Handle fd)
{
#ifdef __linux__
    if (flock((int) fd.data, LOCK_EX) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!LockFile((HANDLE) fd.data, 0, 0, MAXDWORD, MAXDWORD))
        return -1;
    return 0;
#endif
}

static int file_unlock(Handle fd)
{
#ifdef __linux__
    if (flock((int) fd.data, LOCK_UN) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!UnlockFile((HANDLE) fd.data, 0, 0, MAXDWORD, MAXDWORD))
        return -1;
    return 0;
#endif
}

static int file_sync(Handle fd)
{
#ifdef __linux__
    if (fsync((int) fd.data) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!FlushFileBuffers((HANDLE) fd.data))
        return -1;
    return 0;
#endif
}

static int file_read(Handle fd, char *dst, int max)
{
#ifdef __linux__
    return read((int) fd.data, dst, max);
#endif

#ifdef _WIN32
    DWORD num;
    if (!ReadFile((HANDLE) fd.data, dst, max, &num, NULL))
        return -1;
    if (num > INT_MAX)
        return -1;
    return num;
#endif
}

static int file_write(Handle fd, char *src, int len)
{
#ifdef __linux__
    return write((int) fd.data, src, len);
#endif

#ifdef _WIN32
    DWORD num;
    if (!WriteFile((HANDLE) fd.data, src, len, &num, NULL))
        return -1;
    if (num > INT_MAX)
        return -1;
    return num;
#endif
}

static int file_size(Handle fd, size_t *len)
{
#ifdef __linux__
    struct stat buf;
    if (fstat((int) fd.data, &buf) < 0)
        return -1;
    if (buf.st_size < 0 || (uint64_t) buf.st_size > SIZE_MAX)
        return -1;
    *len = (size_t) buf.st_size;
    return 0;
#endif

#ifdef _WIN32
    LARGE_INTEGER buf;
    if (!GetFileSizeEx((HANDLE) fd.data, &buf))
        return -1;
    if (buf.QuadPart < 0 || (uint64_t) buf.QuadPart > SIZE_MAX)
        return -1;
    *len = buf.QuadPart;
    return 0;
#endif
}

// TODO: test this
static string parent_path(string path)
{
    if (path.len > 0 && path.ptr[path.len-1] == '/')
        path.len--;

    if (path.len == 0)
        return S("");

    while (path.len > 0 && path.ptr[path.len-1] != '/')
        path.len--;

    if (path.len > 0)
        path.len--;

    return path;
}

static int write_bytes(int fd, string data)
{
    size_t written = 0;
    while (written < (size_t) data.len) {
        int ret = write(fd, data.ptr + written, data.len - written);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        written += (size_t) ret;
    }
    assert((size_t) data.len == written);
    return 0;
}

static int file_write_atomic(string path, string content)
{
    string parent = parent_path(path);

    char pattern[] = "/tmp_XXXXXXXX";

    char tmp_path[PATH_MAX];
    if (parent.len + strlen(pattern) >= (int) sizeof(tmp_path))
        return -1;
    memcpy(tmp_path, parent.ptr, parent.len);
    memcpy(tmp_path + parent.len, pattern, strlen(pattern));
    tmp_path[parent.len + strlen(pattern)] = '\0';

    int fd = mkstemp(tmp_path);
    if (fd < 0)
        return -1;

    if (write_bytes(fd, content) < 0) {
        close(fd);
        remove(tmp_path);
        return -1;
    }

#ifdef _WIN32
    if (_commit(fd)) {
        close(fd);
        remove(tmp_path);
        return -1;
    }
#else
    if (fsync(fd)) {
        close(fd);
        remove(tmp_path);
        return -1;
    }
#endif

    close(fd);

    if (rename_file_or_dir((string) { tmp_path, strlen(tmp_path) }, path)) {
        remove(tmp_path);
        return -1;
    }
    return 0;
}

static int create_dir(string path)
{
    char zt[PATH_MAX];
    if (path.len >= (int) sizeof(zt))
        return -1;
    memcpy(zt, path.ptr, path.len);
    zt[path.len] = '\0';

#ifdef _WIN32
    if (mkdir(zt) < 0)
        return -1;
#else
    if (mkdir(zt, 0766))
        return -1;
#endif

    return 0;
}

static int rename_file_or_dir(string oldpath, string newpath)
{
    char oldpath_zt[PATH_MAX];
    if (oldpath.len >= (int) sizeof(oldpath_zt))
        return -1;
    memcpy(oldpath_zt, oldpath.ptr, oldpath.len);
    oldpath_zt[oldpath.len] = '\0';

    char newpath_zt[PATH_MAX];
    if (newpath.len >= (int) sizeof(newpath_zt))
        return -1;
    memcpy(newpath_zt, newpath.ptr, newpath.len);
    newpath_zt[newpath.len] = '\0';

    if (rename(oldpath_zt, newpath_zt))
        return -1;
    return 0;
}

static int remove_file_or_dir(string path)
{
    char path_zt[PATH_MAX];
    if (path.len >= (int) sizeof(path_zt))
        return -1;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

    if (remove(path_zt))
        return -1;
    return 0;
}

static int get_full_path(string path, char *dst)
{
    char path_zt[PATH_MAX];
    if (path.len >= (int) sizeof(path_zt))
        return -1;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

#ifdef __linux__
    if (realpath(path_zt, dst) == NULL)
        return -1;
#endif

#ifdef _WIN32
    if (_fullpath(path_zt, dst, PATH_MAX) == NULL)
        return -1;
#endif

    size_t path_len = strlen(dst);
    if (path_len > 0 && dst[path_len-1] == '/')
        dst[path_len-1] = '\0';

    return 0;
}

static int file_read_all(string path, string *data)
{
    Handle fd;
    int ret = file_open(path, &fd);
    if (ret < 0)
        return -1;

    size_t len;
    ret = file_size(fd, &len);
    if (ret < 0) {
        file_close(fd);
        return -1;
    }

    char *dst = malloc(len);
    if (dst == NULL) {
        file_close(fd);
        return -1;
    }

    int copied = 0;
    while ((size_t) copied < len) {
        ret = file_read(fd, dst + copied, len - copied);
        if (ret < 0) {
            file_close(fd);
            return -1;
        }
        copied += ret;
    }

    *data = (string) { dst, len };
    file_close(fd);
    return 0;
}

//////////////////////////////////////////////////////////////////////////
// BYTE QUEUE
//////////////////////////////////////////////////////////////////////////

// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

typedef struct {
    uint8_t *ptr;
    size_t   len;
} ByteView;

typedef struct {
    uint64_t curs;
    uint8_t* data;
    uint32_t head;
    uint32_t size;
    uint32_t used;
    uint32_t limit;
    uint8_t* read_target;
    uint32_t read_target_size;
    int flags;
} ByteQueue;

typedef uint64_t ByteQueueOffset;

enum {
    BYTE_QUEUE_ERROR = 1 << 0,
    BYTE_QUEUE_READ  = 1 << 1,
    BYTE_QUEUE_WRITE = 1 << 2,
};

static void *mymalloc(ByteQueue *queue, uint32_t len)
{
    (void) queue;
    return malloc(len);
}

static void myfree(ByteQueue *queue, void *ptr, uint32_t len)
{
    (void) queue;
    (void) len,
    free(ptr);
}

// Initialize the queue
static void byte_queue_init(ByteQueue *queue, uint32_t limit)
{
    queue->flags = 0;
    queue->head = 0;
    queue->size = 0;
    queue->used = 0;
    queue->curs = 0;
    queue->limit = limit;
    queue->data = NULL;
    queue->read_target = NULL;
}

// Deinitialize the queue
static void byte_queue_free(ByteQueue *queue)
{
    if (queue->read_target) {
        if (queue->read_target != queue->data)
            myfree(queue, queue->read_target, queue->read_target_size);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }

    myfree(queue, queue->data, queue->size);
    queue->data = NULL;
}

static int byte_queue_error(ByteQueue *queue)
{
    return queue->flags & BYTE_QUEUE_ERROR;
}

static int byte_queue_empty(ByteQueue *queue)
{
    return queue->used == 0;
}

static int byte_queue_full(ByteQueue *queue)
{
    return queue->used == queue->limit;
}

// Start a read operation on the queue.
//
// This function returnes the pointer to the memory region containing the bytes
// to read. Callers can't read more than [*len] bytes from it. To complete the
// read, the [byte_queue_read_ack] function must be called with the number of
// bytes that were acknowledged by the caller.
//
// Note:
//   - You can't have more than one pending read.
static ByteView byte_queue_read_buf(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_READ) == 0);
    queue->flags |= BYTE_QUEUE_READ;
    queue->read_target      = queue->data;
    queue->read_target_size = queue->size;

    if (queue->data == NULL)
        return (ByteView) {NULL, 0};

    return (ByteView) { queue->data + queue->head, queue->used };
}

// Complete a previously started operation on the queue.
static void byte_queue_read_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_READ) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_READ;

    assert((uint32_t) num <= queue->used);
    queue->head += (uint32_t) num;
    queue->used -= (uint32_t) num;
    queue->curs += (uint32_t) num;

    if (queue->read_target) {
        if (queue->read_target != queue->data)
            myfree(queue, queue->read_target, queue->read_target_size);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }
}

static ByteView byte_queue_write_buf(ByteQueue *queue)
{
    if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);
    queue->flags |= BYTE_QUEUE_WRITE;

    return (ByteView) {
        queue->data + (queue->head + queue->used),
        queue->size - (queue->head + queue->used),
    };
}

static void byte_queue_write_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_WRITE;
    queue->used += num;
}

// Sets the minimum capacity for the next write operation
// and returns 1 if the content of the queue was moved, else
// 0 is returned.
//
// You must not call this function while a write is pending.
// In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue, &cap);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
static int byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap)
{
    // Sticky error
    if (queue->flags & BYTE_QUEUE_ERROR)
        return 0;

    // In general, the queue's contents look like this:
    //
    //                           size
    //                           v
    //   [___xxxxxxxxxxxx________]
    //   ^   ^           ^
    //   0   head        head + used
    //
    // This function needs to make sure that at least [mincap]
    // bytes are available on the right side of the content.
    //
    // We have 3 cases:
    //
    //   1) If there is enough memory already, this function doesn't
    //      need to do anything.
    //
    //   2) If there isn't enough memory on the right but there is
    //      enough free memory if we cound the left unused region,
    //      then the content is moved back to the
    //      start of the buffer.
    //
    //   3) If there isn't enough memory considering both sides, this
    //      function needs to allocate a new buffer.
    //
    // If there are pending read or write operations, the application
    // is holding pointers to the buffer, so we need to make sure
    // to not invalidate them. The only real problem is pending reads
    // since this function can only be called before starting a write
    // opearation.
    //
    // To avoid invalidating the read pointer when we allocate a new
    // buffer, we don't free the old buffer. Instead, we store the
    // pointer in the "old" field so that the read ack function can
    // free it.
    //
    // To avoid invalidating the pointer when we are moving back the
    // content since there is enough memory at the start of the buffer,
    // we just avoid that. Even if there is enough memory considering
    // left and right free regions, we allocate a new buffer.

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);

    uint32_t total_free_space = queue->size - queue->used;
    uint32_t free_space_after_data = queue->size - queue->used - queue->head;

    int moved = 0;
    if (free_space_after_data < mincap) {

        if (total_free_space < mincap || (queue->read_target == queue->data)) {
            // Resize required

            if (queue->used + mincap > queue->limit) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            uint32_t size;
            if (queue->size > UINT32_MAX / 2)
                size = UINT32_MAX;
            else
                size = 2 * queue->size;

            if (size < queue->used + mincap)
                size = queue->used + mincap;

            if (size > queue->limit)
                size = queue->limit;

            uint8_t *data = mymalloc(queue, size);
            if (!data) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            if (queue->used > 0)
                memcpy(data, queue->data + queue->head, queue->used);

            if (queue->read_target != queue->data)
                myfree(queue, queue->data, queue->size);

            queue->data = data;
            queue->head = 0;
            queue->size = size;

        } else {
            // Move required
            memmove(queue->data, queue->data + queue->head, queue->used);
            queue->head = 0;
        }

        moved = 1;
    }

    return moved;
}

static void byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len)
{
    byte_queue_write_setmincap(queue, len);
    ByteView dst = byte_queue_write_buf(queue);
    if (dst.ptr) {
        memcpy(dst.ptr, ptr, len);
        byte_queue_write_ack(queue, len);
    }
}

static ByteQueueOffset byte_queue_offset(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteQueueOffset) { 0 };
    return (ByteQueueOffset) { queue->curs + queue->used };
}

static uint32_t byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off)
{
    return queue->curs + queue->used - off;
}

static void byte_queue_patch(ByteQueue *queue, ByteQueueOffset off,
    void *src, uint32_t len)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    // Check that the offset is in range
    assert(off >= queue->curs && off - queue->curs < queue->used);

    // Check that the length is in range
    assert(len <= queue->used - (off - queue->curs));

    // Perform the patch
    uint8_t *dst = queue->data + queue->head + (off - queue->curs);
    memcpy(dst, src, len);
}

static void byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    uint64_t num = (queue->curs + queue->used) - offset;
    assert(num <= queue->used);

    queue->used -= num;
}

//////////////////////////////////////////////////////////////////////////
// SERIALIZATION
//////////////////////////////////////////////////////////////////////////

enum {

    // Client -> Metadata server
    MESSAGE_TYPE_CREATE,
    MESSAGE_TYPE_DELETE,
    MESSAGE_TYPE_LIST,
    MESSAGE_TYPE_READ,
    MESSAGE_TYPE_WRITE,

    // Client -> Chunk server
    MESSAGE_TYPE_CREATE_CHUNK,
    MESSAGE_TYPE_UPLOAD_CHUNK,
    MESSAGE_TYPE_DOWNLOAD_CHUNK,

    // Metadata server -> Client
    MESSAGE_TYPE_CREATE_ERROR,
    MESSAGE_TYPE_CREATE_SUCCESS,
    MESSAGE_TYPE_DELETE_ERROR,
    MESSAGE_TYPE_DELETE_SUCCESS,
    MESSAGE_TYPE_LIST_ERROR,
    MESSAGE_TYPE_LIST_SUCCESS,
    MESSAGE_TYPE_READ_ERROR,
    MESSAGE_TYPE_READ_SUCCESS,
    MESSAGE_TYPE_WRITE_ERROR,
    MESSAGE_TYPE_WRITE_SUCCESS,

    // Metadata server -> Chunk server
    MESSAGE_TYPE_STATE_UPDATE,
    MESSAGE_TYPE_DOWNLOAD_LOCATIONS,

    // Chunk server -> Metadata server
    MESSAGE_TYPE_AUTH,
    MESSAGE_TYPE_STATE_UPDATE_ERROR,
    MESSAGE_TYPE_STATE_UPDATE_SUCCESS,

    // Chunk server -> Client
    MESSAGE_TYPE_CREATE_CHUNK_ERROR,
    MESSAGE_TYPE_CREATE_CHUNK_SUCCESS,
    MESSAGE_TYPE_UPLOAD_CHUNK_ERROR,
    MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS,
    MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR,
    MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS,
};

#define MESSAGE_VERSION 1

typedef struct {
    uint8_t *src;
    int      len;
    int      cur;
} BinaryReader;

typedef struct {
    uint16_t version;
    uint16_t type;
    uint32_t length;
} MessageHeader;

typedef struct {
    ByteQueue *output;
    ByteQueueOffset start;
    ByteQueueOffset patch;
} MessageWriter;

static bool binary_read(BinaryReader *reader, void *dst, int len)
{
    if (reader->len - reader->cur < len)
        return false;
    if (dst)
        memcpy(dst, reader->src + reader->cur, len);
    reader->cur += len;
    return true;
}

static void message_writer_init(MessageWriter *writer, ByteQueue *output, uint16_t type)
{
    uint16_t version = MESSAGE_VERSION;
    uint16_t dummy = 0; // Dummy value
    writer->output = output;
    writer->start  = byte_queue_offset(output);
    byte_queue_write(output, &version, sizeof(version));
    byte_queue_write(output, &type, sizeof(type));
    writer->patch = byte_queue_offset(output);
    byte_queue_write(output, &dummy, sizeof(dummy));
}

static bool message_writer_free(MessageWriter *writer)
{
    uint32_t length = byte_queue_size_from_offset(writer->output, writer->start);
    byte_queue_patch(writer->output, writer->patch, &length, sizeof(length));
    if (byte_queue_error(writer->output))
        return false;
    return true;
}

static void message_write(MessageWriter *writer, void *mem, int len)
{
    byte_queue_write(writer->output, mem, len);
}

static int message_peek(ByteView msg, uint16_t *type, uint32_t *len)
{
    if (msg.len < (int) sizeof(MessageHeader))
        return 0;

    MessageHeader header;
    memcpy(&header, msg.ptr, sizeof(header));

    // (We ignore endianess for now)

    if (header.version != MESSAGE_VERSION)
        return -1;

    if (header.length > msg.len)
        return 0;

    if (type) *type = header.type;
    if (len) *len = header.length;

    return 1;
}

//////////////////////////////////////////////////////////////////////////
// ASYNCHRONOUS TCP
//////////////////////////////////////////////////////////////////////////

#define MAX_CONNS 512

typedef enum {
    EVENT_MESSAGE,
    EVENT_CONNECT,
    EVENT_DISCONNECT,
} EventType;

typedef struct {
    EventType type;
    int conn_idx;
} Event;

typedef struct {
    uint32_t data;
} IPv4;

typedef struct {
    uint16_t data[8];
} IPv6;

typedef struct {
    union {
        IPv4 ipv4;
        IPv6 ipv6;
    };
    bool is_ipv4;
    uint16_t port;
} Address;

typedef struct {
    SOCKET    fd;
    int       tag;
    bool      connecting;
    bool      closing;
    uint32_t  msglen;
    ByteQueue input;
    ByteQueue output;
} Connection;

typedef struct {
    SOCKET listen_fd;
    int    num_conns;
    Connection conns[MAX_CONNS];
} TCP;

static bool addr_eql(Address a, Address b)
{
    if (a.is_ipv4 != b.is_ipv4)
        return false;

    if (a.port != b.port)
        return false;

    if (a.is_ipv4) {
        if (memcmp(&a.ipv4, &b.ipv4, sizeof(a.ipv4)))
            return false;
    } else {
        if (memcmp(&a.ipv6, &b.ipv6, sizeof(a.ipv6)))
            return false;
    }

    return true;
}

static SOCKET create_listen_socket(char *addr, uint16_t port)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &bind_buf.sin_addr) != 1)
        return INVALID_SOCKET;

    if (bind(fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)))
        return INVALID_SOCKET;

    int backlog = 32;
    if (listen(fd, backlog) < 0)
        return INVALID_SOCKET;

    return fd;
}

static void conn_init(Connection *conn, SOCKET fd, bool connecting)
{
    conn->fd = fd;
    conn->tag = -1;
    conn->connecting = connecting;
    conn->closing = false;
    conn->msglen = 0;
    byte_queue_init(&conn->input, 1<<20);
    byte_queue_init(&conn->output, 1<<20);
}

static void conn_free(Connection *conn)
{
    CLOSE_SOCKET(conn->fd);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
}

static int conn_events(Connection *conn)
{
    int events = 0;

    if (conn->connecting)
        events |= POLLOUT;
    else {

        assert(!byte_queue_full(&conn->input));
        if (!conn->closing)
            events |= POLLIN;

        if (!byte_queue_empty(&conn->output))
            events |= POLLOUT;
    }
    return events;
}

static void tcp_context_init(TCP *tcp)
{
    tcp->listen_fd = INVALID_SOCKET;
    tcp->num_conns = 0;
}

static void tcp_context_free(TCP *tcp)
{
    if (tcp->listen_fd != INVALID_SOCKET)
        CLOSE_SOCKET(tcp->listen_fd);
}

static int tcp_listen(TCP *tcp, char *addr, uint16_t port)
{
    SOCKET listen_fd = create_listen_socket(addr, port);
    if (listen_fd == INVALID_SOCKET)
        return -1;

    tcp->listen_fd = listen_fd;
    return 0;
}

static int tcp_next_message(TCP *tcp, int conn_idx, ByteView *msg, uint16_t *type)
{
    *msg = byte_queue_read_buf(&tcp->conns[conn_idx].input);

    uint32_t len;
    int ret = message_peek(*msg, type, &len);

    // Invalid message?
    if (ret < 0) {
        byte_queue_read_ack(&tcp->conns[conn_idx].input, 0);
        return -1;
    }

    // Still buffering header?
    if (ret == 0) {
        byte_queue_read_ack(&tcp->conns[conn_idx].input, 0);
        if (byte_queue_full(&tcp->conns[conn_idx].input))
            return -1;
        return 0;
    }

    // Message received
    assert(ret > 0);
    msg->len = len;
    tcp->conns[conn_idx].msglen = len;

    return 1;
}

static void tcp_consume_message(TCP *tcp, int conn_idx)
{
    byte_queue_read_ack(&tcp->conns[conn_idx].input, tcp->conns[conn_idx].msglen);
    tcp->conns[conn_idx].msglen = 0;
}

// The "events" array must be an array of capacity MAX_CONNS+1
static int tcp_process_events(TCP *tcp, Event *events)
{
    struct pollfd polled[MAX_CONNS + 1];
    void *contexts[MAX_CONNS + 1];
    int num_polled = 0;

    if (tcp->listen_fd != INVALID_SOCKET && tcp->num_conns < MAX_CONNS) {
        polled[num_polled].fd = tcp->listen_fd;
        polled[num_polled].events = POLLIN;
        polled[num_polled].revents = 0;
        contexts[num_polled] = NULL;
        num_polled++;
    }

    for (int i = 0; i < tcp->num_conns; i++) {
        int events = conn_events(&tcp->conns[i]);
        if (events) {
            polled[num_polled].fd = tcp->conns[i].fd;
            polled[num_polled].events = events;
            polled[num_polled].revents = 0;
            contexts[num_polled] = &tcp->conns[i];
            num_polled++;
        }
    }

    POLL(polled, num_polled, -1);

    bool removed[MAX_CONNS+1];

    int num_events = 0;
    for (int i = 0; i < num_polled; i++) {

        if (polled[i].fd == tcp->listen_fd) {

            SOCKET new_fd = accept(tcp->listen_fd, NULL, NULL);
            if (new_fd != INVALID_SOCKET) {
                events[num_events++] = (Event) { EVENT_CONNECT, tcp->num_conns };
                conn_init(&tcp->conns[tcp->num_conns++], new_fd, false);
            }

        } else {

            Connection *conn = contexts[i];
            bool defer_close = false;
            bool defer_ready = false;

            if (conn->connecting) {

                // TODO: handle error event flags
                if (polled[i].revents & POLLOUT) {

                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0)
                        defer_close = true;
                    else {
                        conn->connecting = false;
                        events[num_events++] = (Event) { EVENT_CONNECT, conn - tcp->conns };
                    }
                }

            } else {

                if (polled[i].revents & POLLIN) {
                    ByteView buf = byte_queue_write_buf(&conn->input);
                    int num = recv(conn->fd, (char*) buf.ptr, buf.len, 0);
                    if (num == 0)
                        defer_close = true;
                    else if (num < 0) {
                        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                            defer_close = true;
                        num = 0;
                    }
                    byte_queue_write_ack(&conn->input, num);
                    ByteView msg = byte_queue_read_buf(&conn->input);
                    int ret = message_peek(msg, NULL, NULL);
                    if (ret < 0) {
                        // Invalid message
                        byte_queue_read_ack(&conn->input, 0);
                        defer_close = true;
                    } else if (ret == 0) {
                        // Still buffering
                        byte_queue_read_ack(&conn->input, 0);
                        if (byte_queue_full(&conn->input))
                            defer_close = true;
                    } else {
                        // Message received
                        assert(ret > 0);
                        defer_ready = true;
                    }
                }

                if (polled[i].revents & POLLOUT) {
                    ByteView buf = byte_queue_read_buf(&conn->output);
                    int num = send(conn->fd, (char*) buf.ptr, buf.len, 0);
                    if (num < 0) {
                        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN)
                            defer_close = true;
                        num = 0;
                    }
                    byte_queue_read_ack(&conn->output, num);
                    if (conn->closing && byte_queue_empty(&conn->output))
                        defer_close = true;
                }
            }

            removed[i] = defer_close;
            if (0) {}
            else if (defer_close) events[num_events++] = (Event) { EVENT_DISCONNECT, conn - tcp->conns };
                else if (defer_ready) events[num_events++] = (Event) { EVENT_MESSAGE,    conn - tcp->conns };
        }
    }

    for (int i = 0; i < tcp->num_conns; i++)
        if (removed[i]) {
            conn_free(&tcp->conns[i]);
            tcp->conns[i] = tcp->conns[--tcp->num_conns];
        }
    return num_events;
}

static ByteQueue *tcp_output_buffer(TCP *tcp, int conn_idx)
{
    return &tcp->conns[conn_idx].output;
}

static int tcp_connect(TCP *tcp, Address addr, int tag, ByteQueue **output)
{
    if (tcp->num_conns == MAX_CONNS)
        return -1;
    int conn_idx = tcp->num_conns;

    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return -1;

    int ret;
    if (addr.is_ipv4) {
        struct sockaddr_in buf;
        buf.sin_family = AF_INET;
        buf.sin_port = htons(addr.port);
        memcpy(&buf.sin_addr, &addr.ipv4, sizeof(IPv4));
        ret = connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    } else {
        struct sockaddr_in6 buf;
        buf.sin6_family = AF_INET6;
        buf.sin6_port = htons(addr.port);
        memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(IPv6));
        ret = connect(fd, (struct sockaddr*) &buf, sizeof(buf));
    }

    bool connecting;
    if (ret == 0) {
        connecting = false;
    } else {
        if (errno != EINPROGRESS) {
            CLOSE_SOCKET(fd);
            return -1;
        }
        connecting = true;
    }

    conn_init(&tcp->conns[conn_idx], fd, connecting);
    tcp->conns[conn_idx].tag = tag;

    if (output)
        *output = &tcp->conns[conn_idx].output;

    tcp->num_conns++;
    return 0;
}

static void tcp_close(TCP *tcp, int conn_idx)
{
    tcp->conns[conn_idx].closing = true;
}

static void tcp_set_tag(TCP *tcp, int conn_idx, int tag)
{
    tcp->conns[conn_idx].tag = tag;
}

static int tcp_get_tag(TCP *tcp, int conn_idx)
{
    return tcp->conns[conn_idx].tag;
}

//////////////////////////////////////////////////////////////////////////
// FILE TREE
//////////////////////////////////////////////////////////////////////////
#ifdef BUILD_METADATA_SERVER

enum {
    FILETREE_NOMEM   = -1,
    FILETREE_NOENT   = -2,
    FILETREE_NOTDIR  = -3,
    FILETREE_ISDIR   = -4,
    FILETREE_EXISTS  = -5,
    FILETREE_BADPATH = -6,
    FILETREE_BADOP   = -7,
};

typedef struct Entity Entity;

typedef struct {
    uint64_t chunk_size;
    uint64_t num_chunks;
    SHA256 *chunks;
} File;

typedef struct {
    uint64_t max_children;
    uint64_t num_children;
    Entity *children;
} Dir;

struct Entity {
    char name[1<<8];
    uint16_t name_len;
    bool is_dir;
    union {
        Dir  d;
        File f;
    };
};

typedef struct {
    Entity root;
} FileTree;

typedef struct {
    char name[1<<8];
    int  name_len;
    bool is_dir;
} ListItem;

#define MAX_COMPS 32

static int parse_path(string path, string *comps, int max)
{
    if (path.len > 0 && path.ptr[0] == '/') {
        path.ptr++;
        path.len--;
        if (path.len == 0)
            return 0; // Absolute paths with no components are allowed
    }

    int num = 0;
    uint32_t i = 0;
    for (;;) {

        uint32_t off = i;
        while (i < (uint32_t) path.len && path.ptr[i] != '/')
            i++;
        uint32_t len = i - off;

        if (len == 0)
            return -1; // Empty component

        string comp = { path.ptr + off, len };
        if (comp.len == 2 && comp.ptr[0] == '.' && comp.ptr[1] == '.') {
            if (num == 0)
                return -1; // Path references the parent of the root. TODO: What if the path is absolute?
            num--;
        } else if (comp.len != 1 || comp.ptr[0] != '.') {
            if (num == max)
                return -1; // To many components
            comps[num++] = comp;
        }

        if (i == (uint32_t) path.len)
            break;

        assert(path.ptr[i] == '/');
        i++;

        if (i == (uint32_t) path.len)
            break;
    }

    return num;
}

static int dir_find(Dir *parent, string name)
{
    for (uint64_t i = 0; i < parent->num_children; i++)
        if (streq((string) { parent->children[i].name, parent->children[i].name_len }, name))
            return i;
    return -1;
}

static Entity *resolve_path(Entity *root, string *comps, int num_comps)
{
    assert(root->is_dir);

    Entity *current = root;
    for (int i = 0; i < num_comps; i++) {

        if (!current->is_dir)
            return NULL;

        int j = dir_find(&current->d, comps[i]);
        if (j == -1)
            return NULL;

        current = &current->d.children[j];
    }

    return current;
}

static void entity_free(Entity *e);
static bool entity_uses_hash(Entity *e, SHA256 hash);

static void dir_init(Dir *d)
{
    d->num_children = 0;
    d->max_children = 0;
    d->children = NULL;
}

static void dir_free(Dir *d)
{
    for (uint64_t i = 0; i < d->num_children; i++)
        entity_free(&d->children[i]);
    free(d->children);
}

static void dir_remove(Dir *d, int idx)
{
    d->children[idx] = d->children[--d->num_children];
}

static bool dir_uses_hash(Dir *d, SHA256 hash)
{
    for (uint64_t i = 0; i < d->num_children; i++)
        if (entity_uses_hash(&d->children[i], hash))
            return true;
    return false;
}

static void file_init(File *f, uint64_t chunk_size)
{
    f->chunk_size = chunk_size;
    f->num_chunks = 0;
    f->chunks = NULL;
}

static void file_free(File *f)
{
    free(f->chunks);
    f->chunks = NULL;
}

static bool file_uses_hash(File *f, SHA256 hash)
{
    for (uint64_t i = 0; i < f->num_chunks; i++)
        if (!memcmp(&f->chunks[i], &hash, sizeof(SHA256)))
            return true;
    return false;
}

// Fails when the name is too long
static int entity_init(Entity *e, char *name, int name_len,
    bool is_dir, uint64_t chunk_size)
{
    if (name_len >= (int) sizeof(e->name))
        return -1;
    memcpy(e->name, name, name_len);
    e->name[name_len] = '\0';
    e->name_len = (uint16_t) name_len;

    e->is_dir = is_dir;
    if (is_dir)
        dir_init(&e->d);
    else
        file_init(&e->f, chunk_size);

    return 0;
}

static void entity_free(Entity *e)
{
    if (e->is_dir)
        dir_free(&e->d);
    else
        file_free(&e->f);
}

static bool entity_uses_hash(Entity *e, SHA256 hash)
{
    if (e->is_dir)
        return dir_uses_hash(&e->d, hash);
    else
        return file_uses_hash(&e->f, hash);
}

static int file_tree_init(FileTree *ft)
{
    int ret = entity_init(&ft->root, "", 0, true, 0);
    if (ret < 0) return -1;

    return 0;
}

static void file_tree_free(FileTree *ft)
{
    entity_free(&ft->root);
}

static bool file_tree_uses_hash(FileTree *ft, SHA256 hash)
{
    return entity_uses_hash(&ft->root, hash);
}

static int file_tree_list(FileTree *ft, string path,
    ListItem *items, int max_items)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return FILETREE_NOENT;

    if (!e->is_dir)
        return FILETREE_NOTDIR;

    Dir *d = &e->d;

    int num_items = d->num_children;
    if (num_items > max_items) num_items = max_items;
    for (int i = 0; i < num_items; i++) {

        Entity *c = &d->children[i];

        int name_cpy = c->name_len;
        if (name_cpy > (int) sizeof(items[i].name)-1)
            name_cpy = (int) sizeof(items[i].name)-1;

        memcpy(items[i].name, c->name, name_cpy);
        items[i].name[name_cpy] = '\0';

        items[i].name_len = name_cpy;
        items[i].is_dir = c->is_dir;
    }

    return d->num_children;
}

static int
file_tree_create_entity(FileTree *ft, string path,
    bool is_dir, uint64_t chunk_size)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);

    if (num_comps < 0)
        // Couldn't parse path
        return FILETREE_BADPATH;

    if (num_comps == 0)
        // Path is empty, which means the caller is referencing the root,
        // which exists already.
        return FILETREE_EXISTS;

    // Resolve the path up to the second last component
    Entity *e = resolve_path(&ft->root, comps, num_comps-1);

    if (e == NULL)
        // Parent directory doesn't exist
        return FILETREE_NOENT;

    if (!e->is_dir)
        // Parent entity is not a directory
        return FILETREE_NOTDIR;

    string name = comps[num_comps-1];
    if (dir_find(&e->d, name) != -1)
        return FILETREE_EXISTS;

    Dir *d = &e->d;
    if (d->num_children == d->max_children) {

        int new_max = 2 * d->max_children;
        if (new_max == 0)
            new_max = 8;

        Entity *p = malloc(sizeof(Entity) * new_max);
        if (p == NULL)
            return FILETREE_NOMEM;

        for (uint64_t i = 0; i < d->num_children; i++)
            p[i] = d->children[i];

        free(d->children);
        d->children = p;
        d->max_children = new_max;
    }
    Entity *c = &d->children[d->num_children];

    int ret = entity_init(c, (char*) name.ptr, name.len, is_dir, chunk_size);
    if (ret < 0)
        // Invalid name for the new file
        return FILETREE_BADPATH;

    d->num_children++;
    return 0;
}

static int
file_tree_delete_entity(FileTree *ft, string path)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;
    if (num_comps == 0)
        return FILETREE_BADOP;

    Entity *e = resolve_path(&ft->root, comps, num_comps-1);
    if (e == NULL)
        return FILETREE_NOENT;
    if (!e->is_dir)
        return FILETREE_NOTDIR;

    int i = dir_find(&e->d, comps[num_comps-1]);
    if (i == -1)
        return FILETREE_NOENT;

    dir_remove(&e->d, i);
    return 0;
}

static int file_tree_write(FileTree *ft, string path,
    uint64_t off, uint64_t len, SHA256 *prev_hashes,
    SHA256 *hashes)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return -1; // TODO: proper error code

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return -1; // TODO: proper error code

    if (e->is_dir)
        return -1; // TODO: proper error code

    File *f = &e->f;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = (off + len - 1) / f->chunk_size;

    if (last_chunk_index >= f->num_chunks) {
        SHA256 *new_chunks = malloc((last_chunk_index+1) * sizeof(SHA256));
        if (new_chunks == NULL)
            return -1; // TODO: proper error code
        if (f->chunks) {
            if (f->num_chunks > 0)
                memcpy(new_chunks, f->chunks, f->num_chunks);
            free(f->chunks);
        }
        f->chunks = new_chunks;
        f->num_chunks = last_chunk_index+1;
        for (uint64_t i = f->num_chunks; i < last_chunk_index+1; i++)
            memset(&f->chunks[i], 0, sizeof(SHA256));
    }

    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++)
        if (memcmp(&f->chunks[i], &prev_hashes[i - first_chunk_index], sizeof(SHA256)))
            return -1;

    for (uint64_t i = first_chunk_index; i <= last_chunk_index; i++)
        f->chunks[i] = hashes[i - first_chunk_index];

    return 0;
}

#define ZERO_HASH ((SHA256) { .data={0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } })

static int file_tree_read(FileTree *ft, string path,
    uint64_t off, uint64_t len, uint64_t *chunk_size,
    SHA256 *hashes, int max_hashes)
{
    int num_comps;
    string comps[MAX_COMPS];

    num_comps = parse_path(path, comps, MAX_COMPS);
    if (num_comps < 0)
        return FILETREE_BADPATH;

    Entity *e = resolve_path(&ft->root, comps, num_comps);

    if (e == NULL)
        return FILETREE_NOENT;

    if (e->is_dir)
        return FILETREE_NOTDIR;

    File *f = &e->f;

    if (len == 0)
        return 0;

    *chunk_size = f->chunk_size;

    uint64_t first_chunk_index = off / f->chunk_size;
    uint64_t  last_chunk_index = (off + len - 1) / f->chunk_size;

    int num_hashes = 0;
    for (uint32_t i = first_chunk_index; i <= last_chunk_index; i++) {

        SHA256 hash;
        if (i >= f->num_chunks)
            hash = ZERO_HASH;
        else
            hash = f->chunks[i];

        if (num_hashes < max_hashes)
            hashes[num_hashes] = hash;
        num_hashes++;
    }

    return num_hashes;
}

static string file_tree_strerror(int code)
{
    switch (code) {
        case FILETREE_NOMEM  : return S("Out of memory");
        case FILETREE_NOENT  : return S("No such file or directory");
        case FILETREE_NOTDIR : return S("Entity is not a directory");
        case FILETREE_ISDIR  : return S("Entity is a directory");
        case FILETREE_EXISTS : return S("File or directory already exists");
        case FILETREE_BADPATH: return S("Invalid path");
        case FILETREE_BADOP  : return S("Invalid operation");
        default:break;
    }
    return S("Unknown error");
}

#endif // BUILD_METADATA_SERVER
//////////////////////////////////////////////////////////////////////////
// METADATA SERVER
//////////////////////////////////////////////////////////////////////////
#ifdef BUILD_METADATA_SERVER

#define MAX_SERVER_ADDRS 8
#define MAX_CHUNK_SERVERS 32

#define CONNECTION_TAG_CLIENT  -1
#define CONNECTION_TAG_UNKNOWN -2

typedef struct {
    int count;
    int capacity;
    SHA256 *items;
    SHA256  items_hash;
} ChunkList;

typedef struct {

    bool auth;

    int num_addrs;
    Address addrs[MAX_SERVER_ADDRS];

    // Chunks held by the chunk server during
    // the last update
    ChunkList old_list;

    // Chunks added to the chunk server since
    // the last update
    ChunkList add_list;

    // Chunks removed from the chunk server
    // since the last update
    ChunkList rem_list;
} ChunkServer;

typedef struct {
    int num_chunk_servers;
    TCP tcp;
    FileTree file_tree;
    ChunkServer chunk_servers[MAX_CHUNK_SERVERS];
} ProgramState;

static void chunk_list_init(ChunkList *chunk_list)
{
    chunk_list->count = 0;
    chunk_list->capacity = 0;
    chunk_list->items = NULL;
    memset(&chunk_list->items_hash, 0, sizeof(SHA256));
}

static void chunk_list_free(ChunkList *chunk_list)
{
    free(chunk_list->items);
}

static int chunk_list_insert(ChunkList *chunk_list, SHA256 hash)
{
    // Avoid duplicates
    for (int i = 0; i < chunk_list->count; i++)
        if (!memcmp(&chunk_list->items[i], &hash, sizeof(SHA256)))
            return 0;  // Already present

    if (chunk_list->count == chunk_list->capacity) {

        int new_capacity = chunk_list->capacity ? chunk_list->capacity * 2 : 16;

        SHA256 *new_items = realloc(chunk_list->items, new_capacity * sizeof(SHA256));
        if (new_items == NULL)
            return -1;

        chunk_list->items = new_items;
        chunk_list->capacity = new_capacity;
    }

    chunk_list->items[chunk_list->count++] = hash;
    return 0;
}

static bool chunk_list_contains(ChunkList *chunk_list, SHA256 hash)
{
    for (int j = 0; j < chunk_list->count; j++)
        if (!memcmp(&hash, &chunk_list->items[j], sizeof(SHA256)))
            return true;
    return false;
}

static void chunk_server_init(ChunkServer *chunk_server)
{
    chunk_server->auth = false;
    chunk_server->num_addrs = 0;
    chunk_list_init(&chunk_server->old_list);
    chunk_list_init(&chunk_server->add_list);
    chunk_list_init(&chunk_server->rem_list);
}

static void chunk_server_free(ChunkServer *chunk_server)
{
    chunk_list_free(&chunk_server->rem_list);
    chunk_list_free(&chunk_server->add_list);
    chunk_list_free(&chunk_server->old_list);
}

// Look for a chunk server holding a chunk with the
// given hash. If no such chunk server exists, return -1.
static int choose_server_holding_chunk(ProgramState *state, SHA256 hash)
{
    for (int i = 0; i < state->num_chunk_servers; i++)
        if (chunk_list_contains(&state->chunk_servers[i].old_list, hash) ||
            chunk_list_contains(&state->chunk_servers[i].add_list, hash))
            return i;
    return -1;
}

// Return the index of the chunk server with less
// chunks, or -1 is no chunk servers are available.
static int choose_server_for_write(ProgramState *state)
{
    if (state->num_chunk_servers == 0)
        return -1;

    int chunk_count = state->chunk_servers[0].old_list.count + state->chunk_servers[0].add_list.count;
    int server_index = 0;

    for (int i = 1; i < state->num_chunk_servers; i++) {
        int tmp = state->chunk_servers[i].old_list.count + state->chunk_servers[i].add_list.count;
        if (tmp < chunk_count) {
            chunk_count = tmp;
            server_index = i;
        }
    }

    return server_index;
}

static int find_chunk_server_by_addr(ProgramState *state, Address addr)
{
    for (int i = 0; i < state->num_chunk_servers; i++)
        for (int j = 0; j < state->chunk_servers[i].num_addrs; j++)
            if (addr_eql(state->chunk_servers[i].addrs[j], addr))
                return j;
    return -1;
}

// Serialize the list of addresses for the specified
// chunk server.
static void
message_write_server_addr(MessageWriter *writer, ChunkServer *server)
{
    uint32_t num_ipv4 = 0;
    for (int i = 0; i < server->num_addrs; i++)
        if (server->addrs[i].is_ipv4)
            num_ipv4++;

    message_write(writer, &num_ipv4, sizeof(num_ipv4));
    for (int i = 0; i < server->num_addrs; i++)
        if (server->addrs[i].is_ipv4) {
            message_write(writer, &server->addrs[i].ipv4, sizeof(server->addrs[i].ipv4));
            message_write(writer, &server->addrs[i].port, sizeof(server->addrs[i].port));
        }

    uint32_t num_ipv6 = 0;
    for (int i = 0; i < server->num_addrs; i++)
        if (!server->addrs[i].is_ipv4)
            num_ipv6++;

    message_write(writer, &num_ipv6, sizeof(num_ipv6));
    for (int i = 0; i < server->num_addrs; i++)
        if (!server->addrs[i].is_ipv4) {
            message_write(writer, &server->addrs[i].ipv6, sizeof(server->addrs[i].ipv6));
            message_write(writer, &server->addrs[i].port, sizeof(server->addrs[i].port));
        }
}

static int
process_client_create(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint8_t is_dir;
    if (binary_read(&reader, &is_dir, sizeof(path_len)))
        return -1;

    uint32_t chunk_size;
    if (is_dir)
        chunk_size = 0;
    else {
        if (binary_read(&reader, &chunk_size, sizeof(chunk_size)))
            return -1;
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    int ret = file_tree_create_entity(&state->file_tree, path, is_dir, chunk_size);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_delete(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    int ret = file_tree_delete_entity(&state->file_tree, path);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_DELETE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_DELETE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_list(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_LIST_SIZE 128

    ListItem items[MAX_LIST_SIZE];
    int ret = file_tree_list(&state->file_tree, path, items, MAX_LIST_SIZE);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_LIST_SUCCESS);

        uint32_t item_count = ret;
        uint8_t truncated = 0;

        if (ret > MAX_LIST_SIZE) {
            truncated = 1;
            item_count = MAX_LIST_SIZE;
        }

        message_write(&writer, &item_count, sizeof(item_count));
        message_write(&writer, &truncated, sizeof(truncated));

        for (int i = 0; i < ret && i < MAX_LIST_SIZE; i++) {

            uint8_t is_dir = items[i].is_dir;
            message_write(&writer, &is_dir, sizeof(is_dir));

            if (items[i].name_len > UINT16_MAX)
                return -1;
            uint16_t name_len = items[i].name_len;
            message_write(&writer, &name_len, sizeof(name_len));

            message_write(&writer, items[i].name, name_len);
        }

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_read(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (binary_read(&reader, &length, sizeof(length)))
        return -1;

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    #define MAX_READ_HASHES 128

    uint64_t chunk_size;
    SHA256 hashes[MAX_READ_HASHES];
    int ret = file_tree_read(&state->file_tree, path, offset, length, &chunk_size, hashes, MAX_READ_HASHES);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_READ_SUCCESS);

        uint32_t tmp = chunk_size; // TODO: check overflow
        message_write(&writer, &tmp, sizeof(tmp));

        uint32_t num_hashes = ret;
        message_write(&writer, &num_hashes, sizeof(num_hashes));

        for (uint32_t i = 0; i < num_hashes; i++) {

            // TODO: This should write the address of 3 servers,
            //       not just 1.
            int j = choose_server_holding_chunk(state, hashes[i]);
            if (j < 0) {
                // TODO
            }

            ChunkServer *chunk_server = &state->chunk_servers[j];
            assert(chunk_server->auth);
            assert(chunk_server->num_addrs > 0);

            message_write(&writer, &hashes[i], sizeof(hashes[i]));
            message_write_server_addr(&writer, chunk_server);
        }

        // TODO: This should write the location of 3 servers,
        //       not just 1.
        int write_server_index = choose_server_for_write(state);
        if (write_server_index == -1) {
            // TODO
        }
        message_write_server_addr(&writer, &state->chunk_servers[write_server_index]);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_write(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    char     path_mem[1<<10];
    uint16_t path_len;

    if (binary_read(&reader, &path_len, sizeof(path_len)))
        return -1;

    if (path_len > sizeof(path_mem))
        return -2;

    if (binary_read(&reader, &path_mem, path_len))
        return -1;

    string path = { path_mem, path_len };

    uint32_t offset;
    if (binary_read(&reader, &offset, sizeof(offset)))
        return -1;

    uint32_t length;
    if (binary_read(&reader, &length, sizeof(length)))
        return -1;

    uint32_t num_chunks;
    if (binary_read(&reader, &num_chunks, sizeof(num_chunks)))
        return -1;

    #define MAX_CHUNKS_PER_WRITE 32

    Address addrs[MAX_CHUNKS_PER_WRITE];
    SHA256 new_hashes[MAX_CHUNKS_PER_WRITE];
    SHA256 old_hashes[MAX_CHUNKS_PER_WRITE];

    for (uint32_t i = 0; i < num_chunks; i++) {

        SHA256 old_hash;
        if (binary_read(&reader, &old_hash, sizeof(old_hash)))
            return -1;

        SHA256 new_hash;
        if (binary_read(&reader, &new_hash, sizeof(new_hash)))
            return -1;

        uint8_t is_ipv4;
        if (binary_read(&reader, &is_ipv4, sizeof(is_ipv4)))
            return -1;

        Address addr;
        addr.is_ipv4 = is_ipv4;

        if (is_ipv4) {
            if (binary_read(&reader, &addr.ipv4, sizeof(addr.ipv4)))
                return -1;
        } else {
            if (binary_read(&reader, &addr.ipv6, sizeof(addr.ipv6)))
                return -1;
        }

        if (binary_read(&reader, &addr.port, sizeof(addr.port)))
            return -1;

        addrs[i] = addr;
        new_hashes[i] = new_hash;
        old_hashes[i] = old_hash;
    }

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    int ret = file_tree_write(&state->file_tree, path, offset, length, old_hashes, new_hashes);

    if (ret < 0) {

        string desc = file_tree_strerror(ret);

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_WRITE_ERROR);

        uint16_t len = desc.len;
        message_write(&writer, &len, sizeof(len));
        message_write(&writer, desc.ptr, desc.len);

        if (!message_writer_free(&writer))
            return -1;

    } else {

        // TODO: need to check whether chunks that were overwritten
        //       should be removed or not

        for (uint32_t i = 0; i < num_chunks; i++) {

            int j = find_chunk_server_by_addr(state, addrs[i]);
            if (j == -1)
                return -1;

            if (!chunk_list_insert(&state->chunk_servers[j].add_list, new_hashes[i]))
                return -1;
        }

        MessageWriter writer;

        ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
        message_writer_init(&writer, output, MESSAGE_TYPE_WRITE_SUCCESS);

        if (!message_writer_free(&writer))
            return -1;
    }

    return 0;
}

static int
process_client_message(ProgramState *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_CREATE: return process_client_create(state, conn_idx, msg);
        case MESSAGE_TYPE_DELETE: return process_client_delete(state, conn_idx, msg);
        case MESSAGE_TYPE_LIST  : return process_client_list  (state, conn_idx, msg);
        case MESSAGE_TYPE_READ  : return process_client_read  (state, conn_idx, msg);
        case MESSAGE_TYPE_WRITE : return process_client_write (state, conn_idx, msg);
        default:break;
    }
    return -1;
}

static ChunkServer*
chunk_server_from_conn(ProgramState *state, int conn_idx)
{
    int tag = tcp_get_tag(&state->tcp, conn_idx);
    assert(tag >= 0);

    return &state->chunk_servers[tag];
}

static int process_chunk_server_auth(ProgramState *state,
    int conn_idx, ByteView msg)
{
    ChunkServer *chunk_server = chunk_server_from_conn(state, conn_idx);
    chunk_server->num_addrs = 0;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return -1;

    // Read IPv4s
    {
        uint32_t num_ipv4;
        if (!binary_read(&reader, &num_ipv4, sizeof(num_ipv4)))
            return -1;

        for (uint32_t i = 0; i < num_ipv4; i++) {

            IPv4 ipv4;
            if (!binary_read(&reader, &ipv4, sizeof(ipv4)))
                return -1;

            uint16_t port;
            if (!binary_read(&reader, &port, sizeof(port)))
                return -1;

            if (chunk_server->num_addrs < MAX_SERVER_ADDRS)
                chunk_server->addrs[chunk_server->num_addrs++] =
                    (Address) { .ipv4=ipv4, .is_ipv4=true, .port=port };
        }
    }

    // Read IPv6s
    {
        uint32_t num_ipv6;
        if (!binary_read(&reader, &num_ipv6, sizeof(num_ipv6)))
            return -1;

        for (uint32_t i = 0; i < num_ipv6; i++) {

            IPv6 ipv6;
            if (!binary_read(&reader, &ipv6, sizeof(ipv6)))
                return -1;

            uint16_t port;
            if (!binary_read(&reader, &port, sizeof(port)))
                return -1;

            if (chunk_server->num_addrs < MAX_SERVER_ADDRS)
                chunk_server->addrs[chunk_server->num_addrs++] =
                    (Address) { .is_ipv4=true, .ipv6=ipv6, .port=port };
        }
    }

    // No addresses were wpecified
    if (chunk_server->num_addrs == 0)
        return -1;

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return -1;

    chunk_server->auth = true; // TODO: Verify

    return 0;
}

static int
process_chunk_server_message(ProgramState *state,
    int conn_idx, uint8_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH      : return process_chunk_server_auth(state, conn_idx, msg);
        default:break;
    }
    return -1;
}

static bool is_chunk_server_message_type(uint16_t type)
{
    switch (type) {
        case MESSAGE_TYPE_AUTH:
        case MESSAGE_TYPE_STATE_UPDATE_ERROR:
        case MESSAGE_TYPE_STATE_UPDATE_SUCCESS:
        return true;

        default:
        break;
    }
    return false;
}

int program_init(ProgramState *state, int argc, char **argv)
{
    (void) argc;
    (void) argv;

    char addr[] = "127.0.0.1";
    uint16_t port = 8080;

    state->num_chunk_servers = 0;

    tcp_context_init(&state->tcp);

    int ret = tcp_listen(&state->tcp, addr, port);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    ret = file_tree_init(&state->file_tree);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    return 0;
}

int program_free(ProgramState *state)
{
    file_tree_free(&state->file_tree);
    tcp_context_free(&state->tcp);
    return 0;
}

int program_step(ProgramState *state)
{
    Event events[MAX_CONNS+1];
    int num_events = tcp_process_events(&state->tcp, events);

    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_CONNECT:
            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_UNKNOWN);
            break;

            case EVENT_DISCONNECT:
            {
                int tag = tcp_get_tag(&state->tcp, conn_idx);
                if (tag >= 0) {
                    chunk_server_free(&state->chunk_servers[tag]);
                    state->num_chunk_servers--;
                }
            }
            break;

            case EVENT_MESSAGE:
            {
                ByteView msg;
                uint16_t msg_type;
                while (tcp_next_message(&state->tcp, conn_idx, &msg, &msg_type)) {

                    if (tcp_get_tag(&state->tcp, conn_idx) == CONNECTION_TAG_UNKNOWN) {
                        if (is_chunk_server_message_type(msg_type)) {
                            int chunk_server_idx = state->num_chunk_servers++;
                            chunk_server_init(&state->chunk_servers[chunk_server_idx]);
                            tcp_set_tag(&state->tcp, conn_idx, chunk_server_idx);
                        } else {
                            tcp_set_tag(&state->tcp, conn_idx, CONNECTION_TAG_CLIENT);
                        }
                    }

                    int ret;
                    if (tcp_get_tag(&state->tcp, conn_idx) == CONNECTION_TAG_CLIENT)
                        ret = process_client_message(state, conn_idx, msg_type, msg);
                    else
                        ret = process_chunk_server_message(state, conn_idx, msg_type, msg);

                    if (ret < 0)
                        tcp_close(&state->tcp, conn_idx);

                    tcp_consume_message(&state->tcp, conn_idx);
                }
            }
            break;
        }
    }

    return 0;
}

#endif // BUILD_METADATA_SERVER
//////////////////////////////////////////////////////////////////////////
// CHUNK SERVER
//////////////////////////////////////////////////////////////////////////
#ifdef BUILD_CHUNK_SERVER

#define TAG_METADATA_SERVER 1
#define TAG_CHUNK_SERVER    2

#define CHUNK_SERVER_RECONNECT_TIME 10000

typedef struct {
    char path[PATH_MAX];
} ChunkStore;

typedef struct {
    Address addr;
    SHA256  hash;
} PendingDownload;

typedef struct {
    int count;
    int capacity;
    PendingDownload *items;
} PendingDownloadList;

typedef struct {
    Address    metadata_server_addr;
    Time       metadata_server_disconnect_time;
    TCP        tcp;
    ChunkStore store;

    bool downloading;
    PendingDownloadList pending_download_list;
} ProgramState;

static void
pending_download_list_init(PendingDownloadList *list)
{
    list->count = 0;
    list->capacity = 0;
    list->items = NULL;
}

static void
pending_download_list_free(PendingDownloadList *list)
{
    free(list->items);
}

static int
pending_download_list_add(PendingDownloadList *list, Address addr, SHA256 hash)
{
    // Avoid duplicates
    for (int i = 0; i < list->count; i++)
        if (addr_eql(list->items[i].addr, addr) && !memcmp(&list->items[i].hash, &hash, sizeof(SHA256)))
            return 0;

    if (list->count == list->capacity) {

        int new_capacity;
        if (list->capacity == 0) new_capacity = 8;
        else                     new_capacity = 2 * list->capacity;

        PendingDownload *new_items = malloc(new_capacity * sizeof(PendingDownload));
        if (new_items == NULL)
            return -1;

        if (list->capacity > 0) {
            memcpy(new_items, list->items, list->count * sizeof(list->items[0]));
            free(list->items);
        }

        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = (PendingDownload) { addr, hash };
    return 0;
}

static int chunk_store_init(ChunkStore *store, string path)
{
    if (create_dir(path) && errno != EEXIST)
        return -1;

    if (get_full_path(path, store->path) < 0)
        return -1;

    return 0;
}

static void chunk_store_free(ChunkStore *store)
{
    (void) store;
}

static void append_hex_as_str(char *out, SHA256 hash)
{
    char table[] = "0123456789abcdef";
    for (int i = 0; i < (int) sizeof(hash); i++) {
        out[(i << 1) + 0] = table[hash.data[i] >> 4];
        out[(i << 1) + 1] = table[hash.data[i] & 0xF];
    }
}

static string hash2path(ChunkStore *store, SHA256 hash, char *out)
{
    strcpy(out, store->path);
    strcat(out, "/");

    size_t tmp = strlen(out);

    append_hex_as_str(out + tmp, hash);

    out[tmp + 64] = '\0';

    return (string) { out, strlen(out) };
}

static int load_chunk(ChunkStore *store, SHA256 hash, string *data)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);
    return file_read_all(path, data);
}

static int store_chunk(ChunkStore *store, string data, SHA256 *hash)
{
    sha256(data.ptr, data.len, (uint8_t*) hash->data);
    char buf[PATH_MAX];
    string path = hash2path(store, *hash, buf);
    return file_write_atomic(path, data);
}

static int chunk_store_get(ChunkStore *store, SHA256 hash, string *data)
{
    return load_chunk(store, hash, data);
}

static int chunk_store_add(ChunkStore *store, string data)
{
    SHA256 dummy;
    return store_chunk(store, data, &dummy);
}

static void chunk_store_remove(ChunkStore *store, SHA256 hash)
{
    char buf[PATH_MAX];
    string path = hash2path(store, hash, buf);

    remove_file_or_dir(path);
}

static int chunk_store_patch(ChunkStore *store, SHA256 target_chunk,
	uint64_t patch_off, string patch, SHA256 *new_hash)
{
    string data;
    int ret = load_chunk(store, target_chunk, &data);
    if (ret < 0)
        return -1;

    if (patch_off > SIZE_MAX - patch.len) {
        free(data.ptr);
        return -1;
    }

    if (patch_off + (size_t) patch.len > (size_t) data.len) {
        free(data.ptr);
        return -1;
    }

    memcpy(data.ptr + patch_off, patch.ptr, patch.len);

    ret = store_chunk(store, data, new_hash);
    if (ret < 0) {
        free(data.ptr);
        return -1;
    }

    free(data.ptr);
    return 0;
}

static int send_error(TCP *tcp, int conn_idx,
    bool close, uint16_t type, string msg)
{
    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(tcp, conn_idx);
    message_writer_init(&writer, output, type);

    uint16_t len = MIN(msg.len, UINT16_MAX);
    message_write(&writer, &len, sizeof(len));
    message_write(&writer, msg.ptr, len);
    if (!message_writer_free(&writer))
        return -1;
    if (close)
        return -1;
    return 0;
}

static void start_download_if_necessary(ProgramState *state)
{
    if (state->pending_download_list.count == 0 || state->downloading)
        return;

    ByteQueue *output;
    if (tcp_connect(&state->tcp, state->pending_download_list.items[0].addr, TAG_CHUNK_SERVER, &output) < 0) {
        // TODO
    }

    MessageWriter writer;
    message_writer_init(&writer, output, xxx);

    // TODO

    if (!message_writer_free(&writer)) {
        // TODO
    }
}

static int
process_metadata_server_state_update(ProgramState *state, int conn_idx, ByteView msg)
{
    uint32_t add_count;
    uint32_t rem_count;

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    if (!binary_read(&reader, &add_count, sizeof(add_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    if (!binary_read(&reader, &rem_count, sizeof(rem_count)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));

    SHA256 *add_list = malloc(add_count * sizeof(SHA256));
    SHA256 *rem_list = malloc(rem_count * sizeof(SHA256));
    if (add_list == NULL || rem_list == NULL) {
        free(add_list);
        free(rem_list);
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Out of memory"));
    }

    for (uint32_t i = 0; i < add_count; i++) {
        if (!binary_read(&reader, &add_list[i], sizeof(SHA256))) {
            free(add_list);
            free(rem_list);
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
        }
    }

    for (uint32_t i = 0; i < rem_count; i++) {
        if (!binary_read(&reader, &rem_list[i], sizeof(SHA256))) {
            free(add_list);
            free(rem_list);
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
        }
    }

    if (binary_read(&reader, NULL, 1)) {
        free(add_list);
        free(rem_list);
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_STATE_UPDATE_ERROR, S("Invalid message"));
    }

    // TODO:
    //   - Move chunks in the remove list from the main directory to the orphaned directory
    //   - Check that chunks in the add list are either in the main directory or the orphaned
    //     directory. If they are in the orphaned directory, move them to the main directory.
    //   - If one or more chunks in the add list were not present in the main or orphaned
    //     directory, send an error to the metadata server with the list of missing chunks.
    //     If all chunks were present, send a success message.

    free(add_list);
    free(rem_list);
    return 0;
}

static int
process_metadata_server_download_locations(ProgramState *state, int conn_idx, ByteView msg)
{
    // The metadata server wants us to download chunks from other chunk servers

    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

    // The message layout is this:
    //
    //   struct IPv4Pair {
    //     IPv4     addr;
    //     uint16_t port;
    //   }
    //
    //   struct IPv6Pair {
    //     IPv6     addr;
    //     uint16_t port;
    //   }
    //
    //   struct AddressList {
    //     uint8_t  num_ipv4;
    //     uint8_t  num_ipv6;
    //     IPv4Pair ipv4[num_ipv4];
    //     IPv6Pair ipv6[num_ipv6];
    //   }
    //
    //   struct Group {
    //     AddressList address_list;
    //     uint32_t num_hashes;
    //     SHA256 hashes[num_hashes];
    //   }
    //
    //   struct Message {
    //     uint16_t num_groups;
    //     Group    groups[num_groups]
    //   }

    uint16_t num_groups;
    if (binary_read(&reader, &num_groups, sizeof(num_groups)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

    for (uint16_t i = 0; i < num_groups; i++) {

        uint8_t num_ipv4;
        if (binary_read(&reader, &num_ipv4, sizeof(num_ipv4)))
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

        uint8_t num_ipv6;
        if (binary_read(&reader, &num_ipv6, sizeof(num_ipv6)))
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

        IPv4     ipv4[UINT8_MAX];
        IPv6     ipv6[UINT8_MAX];
        uint8_t  ipv4_port[UINT8_MAX];
        uint16_t ipv6_port[UINT8_MAX];

        for (uint8_t j = 0; j < num_ipv4; j++) {
            if (binary_read(&reader, &ipv4[i], sizeof(ipv4[i])))
                return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));
            if (binary_read(&reader, &ipv4_port[i], sizeof(ipv4_port[i])))
                return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));
        }

        for (uint8_t j = 0; j < num_ipv6; j++) {
            if (binary_read(&reader, &ipv6[i], sizeof(ipv6[i])))
                return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));
            if (binary_read(&reader, &ipv6_port[i], sizeof(ipv6_port[i])))
                return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));
        }

        uint32_t num_hashes;
        if (binary_read(&reader, &num_hashes, sizeof(num_hashes)))
            return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

        for (uint32_t j = 0; j < num_hashes; j++) {

            SHA256 hash;
            if (binary_read(&reader, &hash, sizeof(hash)))
                return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

            for (uint8_t k = 0; k < num_ipv4; k++)
                pending_download_list_add(
                    &state->pending_download_list,
                    (Address) { .is_ipv4=true, .ipv4=ipv4[k], .port=ipv4_port[i] },
                    hash
                );

            for (uint8_t k = 0; k < num_ipv6; k++)
                pending_download_list_add(
                    &state->pending_download_list,
                    (Address) { .is_ipv4=false, .ipv6=ipv6[k], .port=ipv6_port[i] },
                    hash
                );
        }
    }

    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_XXX, S("Invalid message"));

    start_download_if_necessary(state);

    // There is no need to respond here
    return 0;
}

static int
process_metadata_server_message(ProgramState *state, int conn_idx, uint16_t type, ByteView msg)
{
    switch (type) {

        case MESSAGE_TYPE_STATE_UPDATE:
        return process_metadata_server_state_update(state, conn_idx, msg);

        case MESSAGE_TYPE_DOWNLOAD_LOCATIONS:
        return process_metadata_server_download_locations(state, conn_idx, msg);
    }

    return -1;
}

static int
process_chunk_server_download_error(ProgramState *state, int conn_idx, ByteView msg)
{
    // TODO
}

static int
process_chunk_server_download_success(ProgramState *state, int conn_idx, ByteView msg)
{
    // TODO
}

static int
process_chunk_server_message(ProgramState *state, int conn_idx, uint16_t msg_type, ByteView msg)
{
    switch (msg_type) {

        case MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR:
        return process_chunk_server_download_error(state, conn_idx, msg);

        case MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS:
        return process_chunk_server_download_success(state, conn_idx, msg);
    }

    return -1;
}

static int
process_client_create_chunk(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t chunk_size;
    if (!binary_read(&reader, &chunk_size, sizeof(chunk_size)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_len;
    if (!binary_read(&reader, &target_len, sizeof(target_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    string data = { reader.src + reader.cur, target_len };
    if (!binary_read(&reader, NULL, target_len))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Invalid message"));

    char *mem = malloc(chunk_size);
    if (mem == NULL)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("Out of memory"));

    assert(target_off + data.len <= chunk_size);

    memset(mem, 0, chunk_size);
    memcpy(mem + target_off, data.ptr, data.len);

    SHA256 new_hash;
    sha256(mem, chunk_size, (uint8_t*) new_hash.data);

    int ret = chunk_store_add(&state->store, (string) { mem, chunk_size });

    free(mem);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_CREATE_CHUNK_ERROR, S("I/O error"));

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_CREATE_CHUNK_SUCCESS);

    message_write(&writer, &new_hash, sizeof(new_hash));

    if (!message_writer_free(&writer))
        return -1;

    return 0;
}

static int
process_client_upload_chunk(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 target_hash;
    if (!binary_read(&reader, &target_hash, sizeof(target_hash)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t data_len;
    if (!binary_read(&reader, &data_len, sizeof(data_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    string data = { reader.src + reader.cur, data_len };

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 new_hash;
    int ret = chunk_store_patch(&state->store, target_hash, target_off, data, &new_hash);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_UPLOAD_CHUNK_ERROR, S("I/O error"));

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_UPLOAD_CHUNK_SUCCESS);

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int
process_client_download_chunk(ProgramState *state, int conn_idx, ByteView msg)
{
    BinaryReader reader = { msg.ptr, msg.len, 0 };

    // Read header
    if (!binary_read(&reader, NULL, sizeof(MessageHeader)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    SHA256 target_hash;
    if (!binary_read(&reader, &target_hash, sizeof(target_hash)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_off;
    if (!binary_read(&reader, &target_off, sizeof(target_off)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    uint32_t target_len;
    if (!binary_read(&reader, &target_len, sizeof(target_len)))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    // Check that there are no more bytes to read
    if (binary_read(&reader, NULL, 1))
        return send_error(&state->tcp, conn_idx, true, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid message"));

    string data;
    int ret = chunk_store_get(&state->store, target_hash, &data);

    if (ret < 0)
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("I/O error"));

    if (target_off >= (size_t) data.len || target_len > (size_t) data.len - target_off) {
        free(data.ptr);
        return send_error(&state->tcp, conn_idx, false, MESSAGE_TYPE_DOWNLOAD_CHUNK_ERROR, S("Invalid range"));
    }
    string slice = { data.ptr + target_off, target_len };

    MessageWriter writer;

    ByteQueue *output = tcp_output_buffer(&state->tcp, conn_idx);
    message_writer_init(&writer, output, MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS);

    message_write(&writer, &target_len, sizeof(target_len));

    message_write(&writer, slice.ptr, slice.len);

    free(data.ptr);

    if (!message_writer_free(&writer))
        return -1;
    return 0;
}

static int
process_client_message(ProgramState *state, int conn_idx, uint16_t type, ByteView msg)
{
    switch (type) {
        case MESSAGE_TYPE_CREATE_CHUNK: return process_client_create_chunk(state, conn_idx, msg);
        case MESSAGE_TYPE_UPLOAD_CHUNK: return process_client_upload_chunk(state, conn_idx, msg);
        case MESSAGE_TYPE_DOWNLOAD_CHUNK: return process_client_download_chunk(state, conn_idx, msg);
        default:break;
    }
    return -1;
}

int program_init(ProgramState *state, int argc, char **argv)
{
    (void) argc;
    (void) argv;

    char addr[] = "127.0.0.1";
    uint16_t port = 8080;
    string path = S("chunk_server_data_0/");

    char     metadata_server_addr[] = "127.0.0.1";
    uint16_t metadata_server_port = 8081;

    tcp_context_init(&state->tcp);

    int ret = tcp_listen(&state->tcp, addr, port);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    ret = chunk_store_init(&state->store, path);
    if (ret < 0) {
        tcp_context_free(&state->tcp);
        return -1;
    }

    state->downloading = false;
    pending_download_list_init(&state->pending_download_list);

    // Initialize metadata server address
    // // TODO: This should also support IPv6
    state->metadata_server_addr.is_ipv4 = true;
    if (inet_pton(AF_INET, metadata_server_addr, &state->metadata_server_addr.ipv4) != 1) {
        tcp_context_free(&state->tcp);
        chunk_store_free(&state->store);
        return -1;
    }
    state->metadata_server_addr.port = metadata_server_port;

    state->metadata_server_disconnect_time = 0;

    return 0;
}

int program_free(ProgramState *state)
{
    pending_download_list_free(&state->pending_download_list);
    chunk_store_free(&state->store);
    tcp_context_free(&state->tcp);
    return 0;
}

int program_step(ProgramState *state)
{
    Event events[MAX_CONNS+1];
    int num_events = tcp_process_events(&state->tcp, events);

    Time current_time = get_current_time();
    if (current_time == INVALID_TIME)
        return -1;

    for (int i = 0; i < num_events; i++) {
        int conn_idx = events[i].conn_idx;
        switch (events[i].type) {

            case EVENT_CONNECT:
            if (tcp_get_tag(&state->tcp, conn_idx) == TAG_METADATA_SERVER)
                state->metadata_server_disconnect_time = 0;
            break;

            case EVENT_DISCONNECT:
            switch (tcp_get_tag(&state->tcp, conn_idx)) {
                case TAG_METADATA_SERVER:
                state->metadata_server_disconnect_time = current_time;
                break;

                case TAG_CHUNK_SERVER:
                assert(state->downloading);
                // TODO
                break;
            }
            break;

            case EVENT_MESSAGE:
            {
                ByteView msg;
                uint16_t msg_type;
                while (tcp_next_message(&state->tcp, conn_idx, &msg, &msg_type)) {

                    int ret;
                    switch (tcp_get_tag(&state->tcp, conn_idx)) {
                        case TAG_METADATA_SERVER:
                        ret = process_metadata_server_message(state, conn_idx, msg_type, msg);
                        break;

                        case TAG_CHUNK_SERVER:
                        ret = process_chunk_server_message(state, conn_idx, msg_type, msg);
                        break;

                        default:
                        ret = process_client_message(state, conn_idx, msg_type, msg);
                        break;
                    }

                    if (ret < 0) {
                        tcp_close(&state->tcp, conn_idx);
                        break;
                    }

                    tcp_consume_message(&state->tcp, conn_idx);
                }
            }
            break;
        }
    }

    // TODO: periodically look for chunks that have their hashes messed up and delete them

    // TODO: periodically start downloads if some are pending and weren't started yet
    // start_download_if_necessary(state);

    if (state->metadata_server_disconnect_time > 0 && current_time - state->metadata_server_disconnect_time > CHUNK_SERVER_RECONNECT_TIME) {
        ByteQueue *output;
        if (tcp_connect(&state->tcp, state->metadata_server_addr, TAG_METADATA_SERVER, &output) < 0)
            state->metadata_server_disconnect_time = current_time;
        else {
            state->metadata_server_disconnect_time = 0;
            // TODO: need to send the AUTH message here
        }
    }

    return 0;
}

#endif // BUILD_CHUNK_SERVER
//////////////////////////////////////////////////////////////////////////
// ENTRY POINT FOR METADATA AND CHUNK SERVER
//////////////////////////////////////////////////////////////////////////
#if defined(BUILD_METADATA_SERVER) || defined(BUILD_CHUNK_SERVER)

int main(int argc, char **argv)
{
    int ret;
    ProgramState state;

    ret = program_init(&state, argc, argv);
    if (ret < 0) return -1;

    for (;;) {
        ret = program_step(&state);
        if (ret < 0) return -1;
    }

    return program_free(&state);
}

#endif
//////////////////////////////////////////////////////////////////////////
// CLIENT
//////////////////////////////////////////////////////////////////////////
#if !defined(BUILD_METADATA_SERVER) && !defined(BUILD_CHUNK_SERVER)

#include "TinyDFS.h"

#define MAX_OPERATIONS 128
#define MAX_REQUESTS_PER_QUEUE 128

typedef enum {
    RESULT_TYPE_EMPTY,
    RESULT_TYPE_CREATE_ERROR,
    RESULT_TYPE_CREATE_SUCCESS,
    RESULT_TYPE_DELETE_ERROR,
    RESULT_TYPE_DELETE_SUCCESS,
    RESULT_TYPE_LIST_ERROR,
    RESULT_TYPE_LIST_SUCCESS,
    RESULT_TYPE_READ_ERROR,
    RESULT_TYPE_READ_SUCCESS,
    RESULT_TYPE_WRITE_ERROR,
    RESULT_TYPE_WRITE_SUCCESS,
} ResultType;

typedef struct {
    ResultType type;
} Result;

typedef struct {
    SHA256   hash;
    char*    dst;
    uint32_t offset_within_chunk;
    uint32_t length_within_chunk;
} Range;

typedef enum {
    OPERATION_TYPE_FREE,
    OPERATION_TYPE_CREATE,
    OPERATION_TYPE_DELETE,
    OPERATION_TYPE_LIST,
    OPERATION_TYPE_READ,
    OPERATION_TYPE_WRITE,
} OperationType;

typedef struct {

    OperationType type;

    void *ptr;
    int   len;

    Range *ranges;
    int ranges_head;
    int ranges_count;
    int num_pending;

    Result result;
} Operation;

typedef struct {
    int tag;
    int operation_index;
} Request;

typedef struct {
    int     head;
    int     count;
    Request items[MAX_REQUESTS_PER_QUEUE];
} RequestQueue;

typedef struct {
    bool         used;
    Address      addr;
    RequestQueue reqs;
} MetadataServer;

typedef struct {
    bool         used;
    Address      addr;
    RequestQueue reqs;
} ChunkServer;

typedef struct {

    TCP tcp;

    MetadataServer metadata_server;

    int num_chunk_servers;
    ChunkServer chunk_servers[MAX_CHUNK_SERVERS];

    int num_operations;
    Operation operations[MAX_OPERATIONS];

} Client;

static int client_init(Client *client)
{
    tcp_context_init(&client->tcp);

    if (tcp_connect(&client->tcp, addr, TAG_METADATA_SERVER) < 0) {
        tcp_context_free(&client->tcp);
        return -1;
    }

    client->num_operations = 0;

    for (int i = 0; i < MAX_OPERATIONS; i++)
        client->operations[i].type = OPERATION_TYPE_FREE;

    return 0;
}

static void client_free(Client *client)
{
    tcp_context_free(&client->tcp);
}

static int
alloc_operation(Client *client, OperationType type, void *ptr, int len)
{
    if (client->num_operations == MAX_OPERATIONS)
        return -1;
    Operation *o = client->operations;
    while (o->type != OPERATION_TYPE_FREE)
        o++;
    o->type = type;
    o->ptr  = ptr;
    o->len  = len;
    o->result = (Result) { RESULT_TYPE_EMPTY };

    client->num_operations++;
    return o - client->operations;
}

static void free_operation(Client *client, int opidx)
{
    client->operations[opidx].type = OPERATION_TYPE_FREE;
    client->num_operations--;
}

static void
request_queue_init(RequestQueue *reqs)
{
    reqs->head = 0;
    reqs->count = 0;
}

static int
request_queue_push(RequestQueue *reqs, Request req)
{
    if (reqs->count == MAX_REQUESTS_PER_QUEUE)
        return -1;
    int tail = (reqs->head + reqs->count) % MAX_REQUESTS_PER_QUEUE;
    reqs->items[tail] = req;
    reqs->count++;
    return 0;
}

static int
request_queue_pop(RequestQueue *reqs, Request *req)
{
    if (reqs->count == 0)
        return -1;
    if (req) *req = reqs->items[reqs->head];
    reqs->head = (reqs->head + 1) % MAX_REQUESTS_PER_QUEUE;
    reqs->count--;
    return 0;
}

static void
metadata_server_request_start(Client *client, Writer *writer, uint16_t type)
{
    int conn_idx = tcp_index_from_tag(&client->tcp, TAG_METADATA_SERVER);
    ByteQueue *output = &tcp_output_buffer(&client->tcp, conn_idx);
    message_writer_init(&writer, output, type);
}

static int
metadata_server_request_end(Client *client, Writer *writer, int opidx, int tag)
{
    if (!message_writer_free(writer))
        return -1;

    RequestQueue *reqs = &client->metadata_server.reqs;
    if (request_queue_push(reqs, (Request) { tag, opidx }) < 0)
        return -1;

    return 0;
}

static int
client_submit_create(Client *client, string path, bool is_dir, uint32_t chunk_size)
{
    OperationType type = OPERATION_TYPE_CREATE;

    int opidx = alloc_operation(client, type, NULL, 0);
    if (opidx < 0) return -1;

    Writer writer;
    metadata_server_request_start(client, &writer, MESSAGE_TYPE_CREATE);

    if (path.len > UINT16_MAX) {
        free_operation(client, opidx);
        return -1;
    }
    uint16_t path_len = path.len;
    message_write(&writer, &path_len, sizeof(path_len));

    message_write(&writer, path.ptr, path.len);

    uint8_t tmp_u8 = is_dir;
    message_write(&writer, &tmp_u8, sizeof(tmp_u8));

    if (!is_dir) {
        if (chunk_size == 0 || chunk_size > UINT32_MAX) {
            free_operation(client, opidx);
            return -1;
        }
        uint32_t tmp_u32 = chunk_size;
        message_write(&writer, &tmp_u32, sizeof(tmp_u32));
    }

    if (metadata_server_request_end(client, &writer, opidx, 0) < 0) {
        free_operation(client, opidx);
        return -1;
    }

    return 0;
}

static int
client_submit_delete(Client *client, string path)
{
    OperationType type = OPERATION_TYPE_DELETE;

    int opidx = alloc_operation(client, type, NULL, 0);
    if (opidx < 0) return -1;

    Writer writer;
    metadata_server_request_start(client, &writer, MESSAGE_TYPE_DELETE);

    if (path.len > UINT16_MAX) {
        free_operation(client, opidx);
        return -1;
    }
    uint16_t path_len = path.len;
    message_write(&writer, &path_len, sizeof(path_len));

    message_write(&writer, path.ptr, path.len);

    if (metadata_server_request_end(client, &writer, opidx, 0) < 0) {
        free_operation(client, opidx);
        return -1;
    }

    return 0;
}

static int
client_submit_list(Client *client, string path)
{
    OperationType type = OPERATION_TYPE_LIST;

    int opidx = alloc_operation(client, type, NULL, 0);
    if (opidx < 0) return -1;

    Writer writer;
    metadata_server_request_start(client, &writer, MESSAGE_TYPE_LIST);

    if (path.len > UINT16_MAX) {
        free_operation(client, opidx);
        return -1;
    }
    uint16_t path_len = path.len;
    message_write(&writer, &path_len, sizeof(path_len));

    message_write(&writer, path.ptr, path.len);

    if (metadata_server_request_end(client, &writer, opidx, 0) < 0) {
        free_operation(client, opidx);
        return -1;
    }

    return 0;
}

static int send_read_message(Client *client, int opidx, int tag, string path, uint32_t offset, uint32_t length)
{
    if (path.len > UINT16_MAX)
        return -1;
    uint16_t path_len = path.len;

    Writer writer;
    metadata_server_request_start(client, &writer, MESSAGE_TYPE_READ);
    message_write(&writer, &path_len, sizeof(path_len));
    message_write(&writer, path.ptr,  path.len);
    message_write(&writer, &offset,   sizeof(offset));
    message_write(&writer, &length,   sizeof(length));
    if (metadata_server_request_end(client, &writer, opidx, tag) < 0)
        return -1;
    return 0;
}

static int
client_submit_read(Client *client, string path, void *dst, int len)
{
    OperationType type = OPERATION_TYPE_READ;

    int opidx = alloc_operation(client, type, NULL, 0);
    if (opidx < 0) return -1;

    if (send_read_message(client, opidx, TAG_RETRIEVE_METADATA_FOR_READ, path, off, len) < 0) {
        free_operation(client, opidx);
        return -1;
    }

    return 0;
}

static int
client_submit_write(Client *client, string path, void *src, int len)
{
    OperationType type = OPERATION_TYPE_WRITE;

    int opidx = alloc_operation(client, type, NULL, 0);
    if (opidx < 0) return -1;

    if (send_read_message(client, opidx, TAG_RETRIEVE_METADATA_FOR_WRITE, path, off, len) < 0) {
        free_operation(client, opidx);
        return -1;
    }

    return 0;
}

static void process_event_for_create(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    Reader reader = { msg.ptr, msg.len, 0 };

    // version;
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_CREATE_SUCCESS) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_ERROR };
        return;
    }

    client->operations[opidx].result = (Result) { RESULT_TYPE_CREATE_SUCCESS };
}

static void process_event_for_delete(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    Reader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_DELETE_SUCCESS) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_ERROR };
        return;
    }

    client->operations[opidx].result = (Result) { RESULT_TYPE_DELETE_SUCCESS };
}

static void process_event_for_list(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    Reader reader = { msg.ptr, msg.len, 0 };

    // version
    if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    uint16_t type;
    if (!binary_read(&reader, &type, sizeof(type))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    // length
    if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    if (type != MESSAGE_TYPE_LIST_SUCCESS) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    // TODO: read list

    // Check there is nothing else to read
    if (binary_read(&reader, NULL, 1)) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
        return;
    }

    client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_SUCCESS };
}

static void process_event_for_read(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
        return;
    }

    switch (request_tag) {

        case TAG_RETRIEVE_METADATA_FOR_READ:
        {
            Reader reader = { msg.ptr, msg.len, 0 };

            // version
            if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            uint16_t type;
            if (!binary_read(&reader, &type, sizeof(type))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            if (type != MESSAGE_TYPE_READ_SUCCESS) {
                // TODO
            }

            // length
            if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            uint32_t chunk_size;
            if (!binary_read(&reader, &chunk_size, sizeof(chunk_size))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            uint32_t first_byte = off;
            uint32_t  last_byte = off + len - 1; // TODO: what if len=0 ?

            uint32_t first_chunk = first_byte / chunk_size;
            uint32_t  last_chunk =  last_byte / chunk_size;

            uint32_t num_chunks = 1 + last_chunk - first_chunk;

            uint32_t num_hashes;
            if (!binary_read(&writer, &num_hashes, sizeof(num_hashes))) {
                // TODO
            }

            Range *ranges = malloc(num_hashes * sizeof(Range));
            if (ranges == NULL) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            char *ptr = client->operations[opidx].ptr;
            for (uint32_t i = first_chunk; i <= last_chunk; i++) {

                uint32_t first_byte_within_chunk = 0;
                uint32_t  last_byte_within_chunk = chunk_size-1; // TODO: what if chunk size is 0 ?

                if (i == first_chunk) first_byte_within_chunk = first_byte % chunk_size;
                if (i ==  last_chunk)  last_byte_within_chunk =  last_byte % chunk_size;

                uint32_t length_within_chunk = 1 + last_byte_within_chunk - first_byte_within_chunk;

                if (i - first_chunk < num_hashes) {

                    SHA256 hash;
                    if (!binary_read(&writer, &hash, sizeof(hash))) {
                        // TODO
                    }

                    ranges[i - first_chunk] = (Range) {
                        .hash = hash,
                        .dst = ptr,
                        .offset_within_chunk = offset_within_chunk,
                        .length_within_chunk = length_within_chunk,
                    };

                } else {
                    memset(ptr, 0, length_within_chunk);
                }

                ptr += length_within_chunk;
            }

            // Check there is nothing else to read
            if (binary_read(&reader, NULL, 1)) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
                return;
            }

            client->operations[opidx].ranges = ranges;
            client->operations[opidx].ranges_head = 0;
            client->operations[opidx].ranges_count = num_hashes;
            client->operations[opidx].num_pending = 0;

            // TODO: start N downloads
        }
        break;

        default:
        {
            Reader reader = { msg.ptr, msg.len, 0 };

            // version
            if (!binary_read(&reader, NULL, sizeof(uint16_t))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            uint16_t type;
            if (!binary_read(&reader, &type, sizeof(type))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            if (type != MESSAGE_TYPE_DOWNLOAD_CHUNK_SUCCESS) {
                // TODO
            }

            // length
            if (!binary_read(&reader, NULL, sizeof(uint32_t))) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_ERROR };
                return;
            }

            // TODO

            // Check there is nothing else to read
            if (binary_read(&reader, NULL, 1)) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_LIST_ERROR };
                return;
            }

            memcpy(client->operations[opidx].ranges[request_tag].dst, xxx, yyy);
            client->operations[opidx].num_pending--;

            if (client->operations[opidx].num_pending == 0) {
                client->operations[opidx].result = (Result) { RESULT_TYPE_READ_SUCCESS };
            } else {
                // TODO: start operation
            }
        }
        break;
    }
}

static void process_event_for_write(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    if (msg.len == 0) {
        client->operations[opidx].result = (Result) { RESULT_TYPE_WRITE_ERROR };
        return;
    }

    switch (request_tag) {

        case TAG_RETRIEVE_METADATA_FOR_WRITE:
        break;

    }

    // TODO
}

static void process_event(Client *client,
    int opidx, int request_tag, ByteView msg)
{
    switch (client->operations[opidx].type) {
        case OPERATION_TYPE_CREATE: process_event_for_create(client, opidx, request_tag, msg); break;
        case OPERATION_TYPE_DELETE: process_event_for_delete(client, opidx, request_tag, msg); break;
        case OPERATION_TYPE_LIST  : process_event_for_list  (client, opidx, request_tag, msg); break;
        case OPERATION_TYPE_READ  : process_event_for_read  (client, opidx, request_tag, msg); break;
        case OPERATION_TYPE_WRITE : process_event_for_write (client, opidx, request_tag, msg); break;
        default: UNREACHABLE;
    }
}

static bool
translate_operation_into_result(Client *client, int opidx, Result *result)
{
    if (client->operations[opidx].result.type == RESULT_TYPE_EMPTY)
        return false;
    *result = client->operations[opidx].result;
    client->operations[opidx].type = OPERATION_TYPE_FREE;
    client->num_operations--;
    return true;
}

static void client_wait(Client *client, int opidx, Result *result, int timeout)
{
    for (;;) {

        if (opidx < 0) {
            for (int i = 0, j = 0; j < client->num_operations; i++) {

                if (client->operations[i].type == OPERATION_TYPE_FREE)
                    continue;
                j++;

                if (translate_operation_into_result(client, i, result))
                    return;
            }
        } else {
            if (translate_operation_into_result(client, opidx, result))
                return;
        }

        int num_events;
        Event events[MAX_CONNS+1];

        num_events = tcp_process_events(&client->tcp, events);
        for (int i = 0; i < num_events; i++) {
            int conn_idx = events[i].conn_idx;
            switch (events[i].type) {

                case EVENT_CONNECT:
                break;

                case EVENT_DISCONNECT:
                {
                    RequestQueue *reqs;

                    int tag = tcp_get_tag(&client->tcp, conn_idx);
                    if (tag == TAG_METADATA_SERVER_TO_CLIENT)
                        reqs = &client->metadata_server.reqs;
                    else {
                        assert(tag > -1);
                        reqs = &client->chunk_servers[tag].reqs;
                    }

                    for (Request req; request_queue_pop(reqs, &req) == 0; )
                        process_event(client, req.opidx, (ByteView) { NULL, 0 });
                }
                break;

                case EVENT_MESSAGE:
                {
                    RequestQueue *reqs;

                    int tag = tcp_get_tag(&client->tcp, conn_idx);
                    if (tag == TAG_METADATA_SERVER_TO_CLIENT)
                        reqs = &client->metadata_server.reqs;
                    else {
                        assert(tag > -1);
                        reqs = &client->chunk_servers[tag].reqs;
                    }

                    Request req;
                    if (request_queue_pop(reqs, &req) < 0) {
                        UNREACHABLE;
                    }
                    process_event(client, req.opidx, req.tag, events[i].msg);
                }
                break;
            }
        }
    }
}

struct TinyDFS {
    Client client;
};

TinyDFS *tinydfs_init(void)
{
    TinyDFS *tdfs = malloc(sizeof(TinyDFS));
    if (tdfs == NULL)
        return NULL;

    if (client_init(&tdfs->client) < 0) {
        free(tdfs);
        return NULL;
    }

    return tdfs;
}

void tinydfs_free(TinyDFS *tdfs)
{
    client_free(&tdfs->client);
    free(tdfs);
}

int tinydfs_wait(TinyDFS *tdfs, TinyDFS_Handle handle,
    TinyDFS_Result *result, int timeout)
{
    // TODO
}

TinyDFS_Handle tinydfs_submit_create(TinyDFS *tdfs,
    char *path, int path_len, bool is_dir, unsigned int chunk_size)
{
    // TODO
}

TinyDFS_Handle tinydfs_submit_delete(TinyDFS *tdfs,
    char *path, int path_len)
{
    // TODO
}

TinyDFS_Handle tinydfs_submit_list(TinyDFS *tdfs,
    char *path, int path_len)
{
    // TODO
}

TinyDFS_Handle tinydfs_submit_read(TinyDFS *tdfs,
    char *path, int path_len, void *dst, int len)
{
    // TODO
}

TinyDFS_Handle tinydfs_submit_write(TinyDFS *tdfs,
    char *path, int path_len, void *src, int len)
{
    // TODO
}

#endif
//////////////////////////////////////////////////////////////////////////
// THE END
//////////////////////////////////////////////////////////////////////////
