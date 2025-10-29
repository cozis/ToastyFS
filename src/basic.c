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

// Returns the current time in milliseconds since
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

        uint64_t res = 1000 * (double) count / freq;
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
        res = sec * 1000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}
