#include <limits.h>
#include <string.h>
#include <assert.h>

#include "system.h"
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

    int ret = sys_open(zt, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (ret < 0)
        return -1;

    *fd = (Handle) { (uint64_t) ret };
    return 0;
#endif

#ifdef _WIN32
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path.ptr, path.len, wpath, MAX_PATH);
    wpath[path.len] = L'\0';

    HANDLE h = sys_CreateFileW(
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
    sys_close((int) fd.data);
#endif

#ifdef _WIN32
    sys_CloseHandle((HANDLE) fd.data);
#endif
}

int file_set_offset(Handle fd, int off)
{
#ifdef __linux__
    off_t ret = lseek((int) fd.data, off, SEEK_SET);
    if (ret < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    LARGE_INTEGER distance;
    distance.QuadPart = off;
    if (!SetFilePointer((HANDLE) fd.data, distance.LowPart, &distance.HighPart, FILE_BEGIN))
        if (GetLastError() != NO_ERROR)
            return -1;
    return 0;
#endif
}

int file_get_offset(Handle fd, int *off)
{
#ifdef __linux__
    off_t ret = lseek((int) fd.data, 0, SEEK_CUR);
    if (ret < 0)
        return -1;
    *off = (int) ret;
    return 0;
#endif

#ifdef _WIN32
    DWORD pos = SetFilePointer((HANDLE) fd.data, 0, NULL, FILE_CURRENT);
    if (pos == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
        return -1;
    *off = (int) pos;
    return 0;
#endif
}

int file_lock(Handle fd)
{
#ifdef __linux__
    if (sys_flock((int) fd.data, LOCK_EX) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!sys_LockFile((HANDLE) fd.data, 0, 0, MAXDWORD, MAXDWORD))
        return -1;
    return 0;
#endif
}

int file_unlock(Handle fd)
{
#ifdef __linux__
    if (sys_flock((int) fd.data, LOCK_UN) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!sys_UnlockFile((HANDLE) fd.data, 0, 0, MAXDWORD, MAXDWORD))
        return -1;
    return 0;
#endif
}

int file_sync(Handle fd)
{
#ifdef __linux__
    if (sys_fsync((int) fd.data) < 0)
        return -1;
    return 0;
#endif

#ifdef _WIN32
    if (!sys_FlushFileBuffers((HANDLE) fd.data))
        return -1;
    return 0;
#endif
}

int file_read(Handle fd, char *dst, int max)
{
#ifdef __linux__
    return sys_read((int) fd.data, dst, max);
#endif

#ifdef _WIN32
    DWORD num;
    if (!sys_ReadFile((HANDLE) fd.data, dst, max, &num, NULL))
        return -1;
    if (num > INT_MAX)
        return -1;
    return num;
#endif
}

int file_write(Handle fd, char *src, int len)
{
#ifdef __linux__
    return sys_write((int) fd.data, src, len);
#endif

#ifdef _WIN32
    DWORD num;
    if (!sys_WriteFile((HANDLE) fd.data, src, len, &num, NULL))
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
    if (sys_fstat((int) fd.data, &buf) < 0)
        return -1;
    if (buf.st_size < 0 || (uint64_t) buf.st_size > SIZE_MAX)
        return -1;
    *len = (size_t) buf.st_size;
    return 0;
#endif

#ifdef _WIN32
    LARGE_INTEGER buf;
    if (!sys_GetFileSizeEx((HANDLE) fd.data, &buf))
        return -1;
    if (buf.QuadPart < 0 || (uint64_t) buf.QuadPart > SIZE_MAX)
        return -1;
    *len = buf.QuadPart;
    return 0;
#endif
}

int create_dir(string path)
{
    char zt[PATH_MAX];
    if (path.len >= (int) sizeof(zt))
        return -1;
    memcpy(zt, path.ptr, path.len);
    zt[path.len] = '\0';

#ifdef _WIN32
    if (sys__mkdir(zt) < 0)
        return -1;
#else
    if (sys_mkdir(zt, 0766))
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

    if (sys_rename(oldpath_zt, newpath_zt))
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

    if (sys_remove(path_zt))
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
    if (sys_realpath(path_zt, dst) == NULL)
        return -1;
#endif

#ifdef _WIN32
    if (sys__fullpath(path_zt, dst, PATH_MAX) == NULL)
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

    char *dst = sys_malloc(len);
    if (dst == NULL) {
        file_close(fd);
        return -1;
    }

    int copied = 0;
    while ((size_t) copied < len) {
        ret = file_read(fd, dst + copied, len - copied);
        if (ret < 0) {
            sys_free(dst);
            file_close(fd);
            return -1;
        }
        copied += ret;
    }

    *data = (string) { dst, len };
    file_close(fd);
    return 0;
}

#ifdef _WIN32

int directory_scanner_init(DirectoryScanner *scanner, string path)
{
    char pattern[PATH_MAX];
    int ret = snprintf(pattern, sizeof(pattern), "%.*s\\*", path.len, path.ptr);
    if (ret < 0 || ret >= (int) sizeof(pattern))
        return -1;

    scanner->handle = sys_FindFirstFileA(pattern, &scanner->find_data);
    if (scanner->handle == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            scanner->done = true;
            return 0;
        }
        return -1;
    }

    scanner->done = false;
    scanner->first = true;
    return 0;
}

int directory_scanner_next(DirectoryScanner *scanner, string *name)
{
    if (scanner->done)
        return 1;

    if (!scanner->first) {
        BOOL ok = sys_FindNextFileA(scanner->handle, &scanner->find_data);
        if (!ok) {
            scanner->done = true;
            if (GetLastError() == ERROR_NO_MORE_FILES)
                return 1;
            return -1;
        }
    } else {
        scanner->first = false;
    }

    char *p = scanner->find_data.cFileName;
    *name = (string) { p, strlen(p) };
    return 0;
}

void directory_scanner_free(DirectoryScanner *scanner)
{
    sys_FindClose(scanner->handle);
}

#else

int directory_scanner_init(DirectoryScanner *scanner, string path)
{
    char path_copy[PATH_MAX];
    if (path.len >= PATH_MAX)
        return -1;
    memcpy(path_copy, path.ptr, path.len);
    path_copy[path.len] = '\0';

    scanner->d = sys_opendir(path_copy);
    if (scanner->d == NULL) {
        scanner->done = true;
        return -1;
    }

    scanner->done = false;
    return 0;
}

int directory_scanner_next(DirectoryScanner *scanner, string *name)
{
    if (scanner->done)
        return 1;

    scanner->e = sys_readdir(scanner->d);
    if (scanner->e == NULL) {
        scanner->done = true;
        return 1;
    }

    *name = (string) { scanner->e->d_name, strlen(scanner->e->d_name) };
    return 0;
}

void directory_scanner_free(DirectoryScanner *scanner)
{
    sys_closedir(scanner->d);
}

#endif
