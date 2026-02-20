#ifndef BASIC_INCLUDED
#define BASIC_INCLUDED

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char data[32];
} SHA256;

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
    char *ptr;
    int   len;
} string;

typedef uint64_t Time;
#define INVALID_TIME ((Time) -1)

#define S(X) ((string) { (X), (int) sizeof(X)-1 })

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

#define UNREACHABLE __builtin_trap();

bool streq(string s1, string s2);

Time get_current_time(void);
void nearest_deadline(Time *a, Time b);
int  deadline_to_timeout(Time deadline, Time current_time);

bool   getargb(int argc, char **argv, char *name);
string getargs(int argc, char **argv, char *name, char *fallback);
int    getargi(int argc, char **argv, char *name, int fallback);

void append_hex_as_str(char *out, SHA256 hash);

bool addr_eql(Address a, Address b);
bool addr_lower(Address a, Address b);

int parse_addr_arg(char *arg, Address *out);
void addr_sort(Address *addrs, int count);

#endif // BASIC_INCLUDED
