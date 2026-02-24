#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <stdint.h>
#include <quakey.h>

#include "basic.h"

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

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000000000 * (double) count / freq;
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

            errno = 0;
            char *end;
            long val = strtol(argv[i], &end, 10);

            if (end == argv[i] || *end != '\0' || errno == ERANGE)
                break;

            if (val < INT_MIN || val > INT_MAX)
                break;

            return (int) val;
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

// TODO: check this function
bool addr_lower(Address a, Address b)
{
    if (a.is_ipv4) {

        if (!b.is_ipv4)
            return true;

        if (a.ipv4.data < b.ipv4.data)
            return true;

        if (a.ipv4.data == b.ipv4.data &&
            a.port < b.port)
            return true;

        return false;

    } else {

        if (b.is_ipv4)
            return false;

        for (int i = 0; i < 8; i++) {

            if (a.ipv6.data[i] < b.ipv6.data[i])
                return true;

            if (a.ipv6.data[i] > b.ipv6.data[i])
                return false;
        }

        if (a.port < b.port)
            return true;

        return false;
    }
}

bool addr_eql(Address a, Address b)
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

int parse_addr_arg(char *arg, Address *out)
{
    int len = strlen(arg);

    int i = 0;
    while (i < len && arg[i] != ':')
        i++;

    if (i == len)
        return -1; // No ':' character.
    arg[i] = '\0';

    IPv4 ipv4;
    int ret = inet_pton(AF_INET, arg, &ipv4);
    arg[i] = ':';

    if (ret != 1)
        return -1;

    errno = 0;
    ret = atoi(arg + i + 1);
    if (ret == 0 && errno != 0)
        return -1;

    out->ipv4 = ipv4;
    out->is_ipv4 = true;
    out->port = ret;

    return 0;
}

void addr_sort(Address *addrs, int count)
{
    for (int i = 0; i < count; i++) {

        int k = i; // Index of the lowest address in [i, num_nodes-1]
        for (int j = i+1; j < count; j++) {
            if (addr_lower(addrs[j], addrs[k]))
                k = j;
        }

        Address tmp = addrs[i];
        addrs[i] = addrs[k];
        addrs[k] = tmp;
    }
}