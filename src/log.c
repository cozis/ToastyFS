#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>

#include "log.h"

void log_init(Log *log)
{
    log->count = 0;
    log->capacity = 0;
    log->entries = NULL;
}

int log_init_from_network(Log *log, void *src, int num)
{
    log->count = num;
    log->capacity = num;
    log->entries = malloc(num * sizeof(LogEntry));
    if (log->entries == NULL)
        return -1;
    memcpy(log->entries, src, num * sizeof(LogEntry));
    return 0;
}

void log_free(Log *log)
{
    free(log->entries);
}

void log_move(Log *dst, Log *src)
{
    log_free(dst);
    *dst = *src;
    log_init(src);
}

int log_append(Log *log, LogEntry entry)
{
    if (log->count == log->capacity) {
        int n= 2 * log->capacity;
        if (n < 8)
            n = 8;
        LogEntry *p = realloc(log->entries, n * sizeof(LogEntry));
        if (p == NULL)
            return -1;

        log->entries = p;
        log->capacity = n;
    }

    log->entries[log->count++] = entry;
    return 0;
}