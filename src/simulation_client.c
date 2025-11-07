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

    client->tdfs = tinydfs_init(addr, port);
    if (client->tdfs == NULL) {
        return -1;
    }

    client->state = CLIENT_STATE_INIT;
    client->step = 0;
    client->create_dir_op = -1;
    client->create_file_op = -1;
    client->write_op = -1;
    client->read_op = -1;
    client->list_op = -1;
    client->delete_op = -1;

    printf("Client set up (remote=%s:%d)\n", addr, port);

    *timeout = 0;  // Wake up immediately to start processing
    return tinydfs_process_events(client->tdfs, contexts, polled, 0);
}

int simulation_client_step(SimulationClient *client, void **contexts,
                          struct pollfd *polled, int num_polled, int *timeout)
{
    TinyDFS_Result result;

    // Process any pending events from the network and get new poll descriptors
    num_polled = tinydfs_process_events(client->tdfs, contexts, polled, num_polled);

    // State machine for running test operations
    switch (client->step) {
        case 0:
            // Step 0: Create a directory
            printf("[Client] Step 0: Creating directory /test_dir\n");
            client->create_dir_op = tinydfs_submit_create(client->tdfs, "/test_dir", -1, true, 0);
            if (client->create_dir_op < 0) {
                fprintf(stderr, "[Client] Failed to submit create directory operation\n");
                client->state = CLIENT_STATE_DONE;
                break;
            }
            client->step++;
            break;

        case 1:
            // Step 1: Wait for directory creation to complete
            if (tinydfs_isdone(client->tdfs, client->create_dir_op, &result)) {
                if (result.type == TINYDFS_RESULT_CREATE_SUCCESS) {
                    printf("[Client] Step 1: Directory created successfully\n");
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 1: Failed to create directory\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 2:
            // Step 2: Create a file
            printf("[Client] Step 2: Creating file /test_dir/test_file.txt\n");
            client->create_file_op = tinydfs_submit_create(client->tdfs, "/test_dir/test_file.txt", -1, false, 1024);
            if (client->create_file_op < 0) {
                fprintf(stderr, "[Client] Failed to submit create file operation\n");
                client->state = CLIENT_STATE_DONE;
                break;
            }
            client->step++;
            break;

        case 3:
            // Step 3: Wait for file creation to complete
            if (tinydfs_isdone(client->tdfs, client->create_file_op, &result)) {
                if (result.type == TINYDFS_RESULT_CREATE_SUCCESS) {
                    printf("[Client] Step 3: File created successfully\n");
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 3: Failed to create file\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 4:
            // Step 4: Write data to the file
            printf("[Client] Step 4: Writing data to /test_dir/test_file.txt\n");
            {
                const char *data = "Hello, TinyDFS! This is a test.";
                client->write_op = tinydfs_submit_write(client->tdfs, "/test_dir/test_file.txt", -1, 0, (void *)data, strlen(data));
                if (client->write_op < 0) {
                    fprintf(stderr, "[Client] Failed to submit write operation\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
            }
            client->step++;
            break;

        case 5:
            // Step 5: Wait for write to complete
            if (tinydfs_isdone(client->tdfs, client->write_op, &result)) {
                if (result.type == TINYDFS_RESULT_WRITE_SUCCESS) {
                    printf("[Client] Step 5: Data written successfully\n");
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 5: Failed to write data\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 6:
            // Step 6: Read data from the file
            printf("[Client] Step 6: Reading data from /test_dir/test_file.txt\n");
            memset(client->read_buffer, 0, sizeof(client->read_buffer));
            client->read_op = tinydfs_submit_read(client->tdfs, "/test_dir/test_file.txt", -1, 0, client->read_buffer, sizeof(client->read_buffer) - 1);
            if (client->read_op < 0) {
                fprintf(stderr, "[Client] Failed to submit read operation\n");
                client->state = CLIENT_STATE_DONE;
                break;
            }
            client->step++;
            break;

        case 7:
            // Step 7: Wait for read to complete
            if (tinydfs_isdone(client->tdfs, client->read_op, &result)) {
                if (result.type == TINYDFS_RESULT_READ_SUCCESS) {
                    printf("[Client] Step 7: Data read successfully: '%s'\n", client->read_buffer);
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 7: Failed to read data\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 8:
            // Step 8: List directory contents
            printf("[Client] Step 8: Listing /test_dir\n");
            client->list_op = tinydfs_submit_list(client->tdfs, "/test_dir", -1);
            if (client->list_op < 0) {
                fprintf(stderr, "[Client] Failed to submit list operation\n");
                client->state = CLIENT_STATE_DONE;
                break;
            }
            client->step++;
            break;

        case 9:
            // Step 9: Wait for list to complete
            if (tinydfs_isdone(client->tdfs, client->list_op, &result)) {
                if (result.type == TINYDFS_RESULT_LIST_SUCCESS) {
                    printf("[Client] Step 9: Directory listing:\n");
                    for (int i = 0; i < result.num_entities; i++) {
                        printf("[Client]   - %s %s\n",
                               result.entities[i].is_dir ? "[DIR]" : "[FILE]",
                               result.entities[i].name);
                    }
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 9: Failed to list directory\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 10:
            // Step 10: Delete the file
            printf("[Client] Step 10: Deleting /test_dir/test_file.txt\n");
            client->delete_op = tinydfs_submit_delete(client->tdfs, "/test_dir/test_file.txt", -1);
            if (client->delete_op < 0) {
                fprintf(stderr, "[Client] Failed to submit delete operation\n");
                client->state = CLIENT_STATE_DONE;
                break;
            }
            client->step++;
            break;

        case 11:
            // Step 11: Wait for delete to complete
            if (tinydfs_isdone(client->tdfs, client->delete_op, &result)) {
                if (result.type == TINYDFS_RESULT_DELETE_SUCCESS) {
                    printf("[Client] Step 11: File deleted successfully\n");
                    client->step++;
                } else {
                    fprintf(stderr, "[Client] Step 11: Failed to delete file\n");
                    client->state = CLIENT_STATE_DONE;
                    break;
                }
                tinydfs_result_free(&result);
            }
            break;

        case 12:
            // All operations complete
            printf("[Client] All operations completed successfully!\n");
            client->state = CLIENT_STATE_DONE;
            client->step++;
            break;

        default:
            // Stay in DONE state
            break;
    }

    // If we're done, no need to wake up again
    if (client->state == CLIENT_STATE_DONE) {
        *timeout = -1;
    } else {
        // Wake up soon to continue processing
        //*timeout = 10;  // 10ms
        *timeout = -1; // TODO
    }

    // Return the poll array from the TinyDFS client
    return tinydfs_process_events(client->tdfs, contexts, polled, 0);
}

void simulation_client_free(SimulationClient *client)
{
    if (client->tdfs) {
        tinydfs_free(client->tdfs);
        client->tdfs = NULL;
    }
}

#endif // BUILD_TEST
