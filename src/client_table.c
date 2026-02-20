#if defined(MAIN_SIMULATION) || defined(MAIN_TEST)
#define QUAKEY_ENABLE_MOCKS
#endif

#include <quakey.h>
#include <stdbool.h>

#include "client_table.h"

void client_table_init(ClientTable *client_table)
{
    client_table->count = 0;
    client_table->capacity = 0;
    client_table->entries = NULL;
}

void client_table_free(ClientTable *client_table)
{
    free(client_table->entries);
}

ClientTableEntry *client_table_find(ClientTable *client_table, uint64_t client_id)
{
    for (int i = 0; i < client_table->count; i++) {
        if (client_table->entries[i].client_id == client_id)
            return &client_table->entries[i];
    }
    return NULL;
}

int client_table_add(ClientTable *client_table, uint64_t client_id, uint64_t request_id, int conn_tag)
{
    if (client_table->count == client_table->capacity) {
        int n = 2 * client_table->capacity;
        if (n == 0) n = 8;
        void *p = realloc(client_table->entries, n * sizeof(ClientTableEntry));
        if (p == NULL)
            return -1;
        client_table->capacity = n;
        client_table->entries = p;
    }

    client_table->entries[client_table->count++] = (ClientTableEntry) {
        .client_id = client_id,
        .last_request_id = request_id,
        .pending = true,
        .conn_tag = conn_tag,
    };
    return 0;
}

int client_table_insert(ClientTable *client_table, uint64_t client_id, uint64_t request_id)
{
    if (client_table->count == client_table->capacity) {
        int n = 2 * client_table->capacity;
        if (n == 0) n = 8;
        void *p = realloc(client_table->entries, n * sizeof(ClientTableEntry));
        if (p == NULL)
            return -1;
        client_table->capacity = n;
        client_table->entries = p;
    }

    client_table->entries[client_table->count++] = (ClientTableEntry) {
        .client_id=client_id,
        .last_request_id=request_id,
        .pending=true,
    };
    return 0;
}
