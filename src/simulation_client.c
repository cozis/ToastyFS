#ifdef BUILD_TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "simulation_client.h"
#include "tcp.h"

// Helper function to parse address and port from command line
static bool parse_server_addr(int argc, char **argv, char **addr, uint16_t *port)
{
    // Default to metadata server
    *addr = "127.0.0.1";
    *port = 8080;

    for (int i = 0; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--server") || !strcmp(argv[i], "-s")) {
            *addr = argv[i + 1];
            if (i + 2 < argc) {
                *port = (uint16_t)atoi(argv[i + 2]);
                return true;
            }
        }
    }
    return true;
}

int simulation_client_init(SimulationClient *client, int argc, char **argv,
                          void **contexts, struct pollfd *polled, int *timeout)
{
    char *addr;
    uint16_t port;
    parse_server_addr(argc, argv, &addr, &port);

    client->toasty = toasty_connect((ToastyString) { addr, strlen(addr) }, port);
    if (client->toasty == NULL)
        return -1;

    client->num_pending = 0;

    printf("Client set up (remote=%s:%d)\n", addr, port);

    *timeout = 0;
    return toasty_process_events(client->toasty, contexts, polled, 0);
}

static int random_in_range(int min, int max)
{
    uint64_t n = simulation_random_number();
    return min + n % (max - min + 1);
}

int simulation_client_step(SimulationClient *client, void **contexts,
                          struct pollfd *polled, int num_polled, int *timeout)
{
    // Process any pending events from the network and get new poll descriptors
    num_polled = toasty_process_events(client->toasty, contexts, polled, num_polled);

    for (int i = 0; i < client->num_pending; i++) {

        ToastyResult result;
        if (toasty_get_result(client->toasty, client->pending[i].handle, &result) != 0)
            continue;

        PendingOperation pending = client->pending[i];
        switch (result.type) {

            case TOASTY_RESULT_EMPTY:
            assert(0);
            break;

            case TOASTY_RESULT_CREATE_ERROR:
            assert(pending.type == PENDING_OPERATION_CREATE);
            //printf("[Client] create error\n");
            break;

            case TOASTY_RESULT_CREATE_SUCCESS:
            assert(pending.type == PENDING_OPERATION_CREATE);
            //printf("[Client] create success\n");
            break;

            case TOASTY_RESULT_DELETE_ERROR:
            assert(pending.type == PENDING_OPERATION_DELETE);
            //printf("[Client] delete error\n");
            break;

            case TOASTY_RESULT_DELETE_SUCCESS:
            assert(pending.type == PENDING_OPERATION_DELETE);
            //printf("[Client] delete success\n");
            break;

            case TOASTY_RESULT_LIST_ERROR:
            assert(pending.type == PENDING_OPERATION_LIST);
            //printf("[Client] list error\n");
            break;

            case TOASTY_RESULT_LIST_SUCCESS:
            assert(pending.type == PENDING_OPERATION_LIST);
            //printf("[Client] list success\n");
            break;

            case TOASTY_RESULT_READ_ERROR:
            assert(pending.type == PENDING_OPERATION_READ);
            //printf("[Client] read error\n");
            break;

            case TOASTY_RESULT_READ_SUCCESS:
            assert(pending.type == PENDING_OPERATION_READ);
            //printf("[Client] read success\n");
            break;

            case TOASTY_RESULT_WRITE_ERROR:
            assert(pending.type == PENDING_OPERATION_WRITE);
            //printf("[Client] write error\n");
            break;

            case TOASTY_RESULT_WRITE_SUCCESS:
            assert(pending.type == PENDING_OPERATION_WRITE);
            //printf("[Client] write success\n");
            break;
        }
        free(pending.ptr);
        toasty_free_result(&result);
        client->pending[i--] = client->pending[--client->num_pending];
    }

    while (client->num_pending < MAX_PENDING_OPERATION) {

        typedef struct {
            ToastyString path;
            bool is_dir;
        } TableEntry;

        static const TableEntry table[] = {
            { TOASTY_STR("/f0"),    false },
            { TOASTY_STR("/f1"),    false },
            { TOASTY_STR("/d0"),    true  },
            { TOASTY_STR("/d1"),    true  },
            { TOASTY_STR("/d0/f1"), false },
            { TOASTY_STR("/d0/f2"), false },
            { TOASTY_STR("/d0/d0"), true  },
            { TOASTY_STR("/d0/d1"), true  },
            { TOASTY_STR("/d1/f1"), false },
            { TOASTY_STR("/d1/f2"), false },
            { TOASTY_STR("/d1/d0"), true  },
            { TOASTY_STR("/d1/d1"), true  },
        };
        static const int table_len = sizeof(table) / sizeof(table[0]);

        static const PendingOperationType type_table[] = {
            PENDING_OPERATION_CREATE,
            PENDING_OPERATION_DELETE,
            PENDING_OPERATION_LIST,
            PENDING_OPERATION_READ,
            PENDING_OPERATION_WRITE,
        };
        static const int type_table_len = sizeof(type_table)/sizeof(type_table[0]);

        void *ptr = NULL;
        int off = 0;
        int len = 0;
        ToastyHandle handle;

        PendingOperationType type = type_table[random_in_range(0, type_table_len-1)];
        switch (type) {

            TableEntry entry;
            uint32_t chunk_size;

            case PENDING_OPERATION_CREATE:
            entry = table[random_in_range(0, table_len-1)];
            if (entry.is_dir) {
                handle = toasty_begin_create_dir(client->toasty, entry.path);
            } else {
                chunk_size = random_in_range(0, 5000);
                handle = toasty_begin_create_file(client->toasty, entry.path, chunk_size);
            }
            //printf("[Client] submit create (path=%s, is_dir=%s, chunk_size=%d)\n", entry.path, entry.is_dir ? "true" : "false", chunk_size);
            break;

            case PENDING_OPERATION_DELETE:
            entry = table[random_in_range(0, table_len-1)];
            handle = toasty_begin_delete(client->toasty, entry.path);
            //printf("[Client] submit delete (path=%s)\n", entry.path);
            break;

            case PENDING_OPERATION_LIST:
            entry = table[random_in_range(0, table_len-1)];
            handle = toasty_begin_list(client->toasty, entry.path);
            //printf("[Client] submit list   (path=%s)\n", entry.path);
            break;

            case PENDING_OPERATION_READ:
            entry = table[random_in_range(0, table_len-1)];
            off = random_in_range(0, 10000);
            len = random_in_range(0, 5000);
            ptr = malloc(len);
            if (ptr == NULL) assert(0);
            handle = toasty_begin_read(client->toasty, entry.path, off, ptr, len);
            //printf("[Client] submit read   (path=%s, off=%d, len=%d)\n", entry.path, off, len);
            break;

            case PENDING_OPERATION_WRITE:
            entry = table[random_in_range(0, table_len-1)];
            off = random_in_range(0, 10000);
            len = random_in_range(0, 5000);
            ptr = malloc(len);
            if (ptr == NULL) assert(0);
            memset(ptr, 'a', len);
            handle = toasty_begin_write(client->toasty, entry.path, off, ptr, len);
            //printf("[Client] submit write  (path=%s, off=%d, len=%d)\n", entry.path, off, len);
            break;
        }
        if (handle == TOASTY_INVALID)
            break;
        client->pending[client->num_pending++] = (PendingOperation) { .type=type, .handle=handle, .ptr=ptr };
    }

    if (client->num_pending == 0)
        *timeout = 10;
    else
        *timeout = -1;
    return toasty_process_events(client->toasty, contexts, polled, 0);
}

void simulation_client_free(SimulationClient *client)
{
    toasty_disconnect(client->toasty);
}

#endif // BUILD_TEST
