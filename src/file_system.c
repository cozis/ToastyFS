#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <assert.h>

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

#include "file_system.h"

int rename_file_or_dir(string oldpath, string newpath);

int file_open(string path, Handle *fd)
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

void file_close(Handle fd)
{
#ifdef __linux__
    close((int) fd.data);
#endif

#ifdef _WIN32
    CloseHandle((HANDLE) fd.data);
#endif
}

int file_lock(Handle fd)
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

int file_unlock(Handle fd)
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

int file_sync(Handle fd)
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

int file_read(Handle fd, char *dst, int max)
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

int file_write(Handle fd, char *src, int len)
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

int file_size(Handle fd, size_t *len)
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

int file_write_atomic(string path, string content)
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

int create_dir(string path)
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

int rename_file_or_dir(string oldpath, string newpath)
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

int remove_file_or_dir(string path)
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

int get_full_path(string path, char *dst)
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

int file_read_all(string path, string *data)
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
