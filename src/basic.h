#ifndef BASIC_INCLUDED
#define BASIC_INCLUDED

#include <stdint.h>
#include <stdbool.h>

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

bool streq(string s1, string s2);
Time get_current_time(void);

#endif // BASIC_INCLUDED
