#ifndef CLIENT_TABLE_INCLUDED
#define CLIENT_TABLE_INCLUDED

#include <stdint.h>

#include "metadata.h"

typedef struct {
    uint64_t        client_id;
    uint64_t        last_request_id;
    MetaResult      last_result;
    bool            pending; // Only meaningful on the leader that received
                             // the REQUEST. After a view change, a new leader
                             // may find stale entries with pending=false from
                             // a previous view when it was leader before.
    int             conn_tag;
} ClientTableEntry;

typedef struct {
    int count;
    int capacity;
    ClientTableEntry *entries;
} ClientTable;

void client_table_init(ClientTable *client_table);
void client_table_free(ClientTable *client_table);
ClientTableEntry *client_table_find(ClientTable *client_table, uint64_t client_id);
int client_table_add(ClientTable *client_table, uint64_t client_id, uint64_t request_id, int conn_tag);
int client_table_insert(ClientTable *client_table, uint64_t client_id, uint64_t request_id);

#endif // CLIENT_TABLE_INCLUDED