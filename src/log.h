#if 0
#ifndef LOG_INCLUDED
#define LOG_INCLUDED

#include "metadata.h"

#include "config.h"

typedef struct {
    MetaOper oper;
    uint32_t votes;
    int view_number;
    uint64_t client_id;
    uint64_t request_id;
} LogEntry;

_Static_assert(NODE_LIMIT <= 32, "");

typedef struct {
    int count;
    int capacity;
    LogEntry *entries;
} Log;

void log_init(Log *log);
int  log_init_from_network(Log *log, void *src, int num);
void log_free(Log *log);
void log_move(Log *dst, Log *src);
int  log_append(Log *log, LogEntry entry);

#endif // LOG_INCLUDED
#endif