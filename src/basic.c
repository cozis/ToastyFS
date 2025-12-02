#include <string.h>

#include "basic.h"
#include "system.h"

bool streq(string s1, string s2)
{
    if (s1.len != s2.len)
        return false;
    for (int i = 0; i < s1.len; i++)
        if (s1.ptr[i] != s2.ptr[i])
            return false;
    return true;
}

// Returns the current time in nanoseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = sys_QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = sys_QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000000000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (sys_clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000000000)
            return INVALID_TIME;
        res = sec * 1000000000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec)
            return INVALID_TIME;
        res += nsec;

        return res;
    }
#endif
}

void nearest_deadline(Time *a, Time b)
{
    if (*a == INVALID_TIME || *a > b)
        *a = b;
}

int deadline_to_timeout(Time deadline, Time current_time)
{
    if (deadline == INVALID_TIME)
        return -1;
    return (deadline - current_time) / 1000000;
}

bool getargb(int argc, char **argv, char *name)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], name))
            return true;
    return false;
}

string getargs(int argc, char **argv, char *name, char *fallback)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], name)) {
            i++;
            if (i == argc)
                break;
            return (string) { argv[i], strlen(argv[i]) };
        }
    return (string) { fallback, strlen(fallback) };
}

int getargi(int argc, char **argv, char *name, int fallback)
{
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], name)) {

            i++;
            if (i == argc)
                break;

            int tmp = atoi(argv[i]);
            if (tmp == 0 && argv[i][0] != '0') // best effort
                break;

            return tmp;
        }
    return fallback;
}

void append_hex_as_str(char *out, SHA256 hash)
{
    char table[] = "0123456789abcdef";
    for (int i = 0; i < (int) sizeof(hash); i++) {
        out[(i << 1) + 0] = table[(uint8_t) hash.data[i] >> 4];
        out[(i << 1) + 1] = table[(uint8_t) hash.data[i] & 0xF];
    }
}
