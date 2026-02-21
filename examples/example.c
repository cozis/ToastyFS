/*
 * example.c - Minimal ToastyFS client example.
 *
 * Connects to a running 3-node cluster (ports 8081-8083 on localhost),
 * performs a PUT, a GET, and a DELETE using the synchronous API, then
 * verifies the results.
 *
 * Build & run against a live cluster:
 *   ./cluster.sh run examples/example.c
 *
 * Or manually:
 *   make lib
 *   gcc -Wall -Wextra -o example examples/example.c \
 *       -Iinclude -L. -ltoastyfs
 *   LD_LIBRARY_PATH=. ./example
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <toastyfs.h>

static const char *error_name(ToastyFS_Error e)
{
    switch (e) {
    case TOASTYFS_ERROR_VOID:               return "OK";
    case TOASTYFS_ERROR_OUT_OF_MEMORY:      return "OUT_OF_MEMORY";
    case TOASTYFS_ERROR_UNEXPECTED_MESSAGE:  return "UNEXPECTED_MESSAGE";
    case TOASTYFS_ERROR_REJECTED:            return "REJECTED";
    case TOASTYFS_ERROR_FULL:               return "FULL";
    case TOASTYFS_ERROR_NOT_FOUND:          return "NOT_FOUND";
    case TOASTYFS_ERROR_TRANSFER_FAILED:    return "TRANSFER_FAILED";
    }
    return "UNKNOWN";
}

int main(void)
{
    srand(time(NULL));

    /* Cluster addresses (mapped via docker-compose ports).
     * These must be writable char arrays because parse_addr_arg
     * temporarily modifies the string in-place. */
    char addr1[] = "127.0.0.1:8081";
    char addr2[] = "127.0.0.1:8082";
    char addr3[] = "127.0.0.1:8083";
    char *addrs[] = { addr1, addr2, addr3 };

    printf("Connecting to cluster...\n");
    ToastyFS *tfs = toastyfs_init(rand(), addrs, 3);
    if (tfs == NULL) {
        fprintf(stderr, "toastyfs_init failed\n");
        return 1;
    }

    ToastyFS_Result res;
    int ret;

    ////////////////////////////////////////////////////////////////////
    // PUT

    char key[]  = "hello";
    char data[] = "world";

    printf("PUT key=\"%s\" data=\"%s\" (%d bytes)\n", key, data, (int)strlen(data));

    ret = toastyfs_put(tfs, key, strlen(key), data, strlen(data), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_put returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }
    printf("  result: %s\n", error_name(res.error));

    ////////////////////////////////////////////////////////////////////
    // GET

    printf("GET key=\"%s\"\n", key);

    ret = toastyfs_get(tfs, key, strlen(key), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_get returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }
    printf("  result: %s\n", error_name(res.error));

    if (res.error == TOASTYFS_ERROR_VOID && res.data) {
        printf("  data:   \"%.*s\" (%d bytes)\n", res.size, res.data, res.size);
        if (res.size == (int)strlen(data) &&
            memcmp(res.data, data, res.size) == 0) {
            printf("  PASS - data matches\n");
        } else {
            printf("  FAIL - data mismatch\n");
        }
        free(res.data);
    }

    ////////////////////////////////////////////////////////////////////
    // DELETE

    printf("DELETE key=\"%s\"\n", key);

    ret = toastyfs_delete(tfs, key, strlen(key), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_delete returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }
    printf("  result: %s\n", error_name(res.error));

    ////////////////////////////////////////////////////////////////////
    // GET (2)

    printf("GET key=\"%s\" (after delete)\n", key);

    ret = toastyfs_get(tfs, key, strlen(key), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_get returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }

    printf("  result: %s\n", error_name(res.error));
    if (res.error == TOASTYFS_ERROR_NOT_FOUND) {
        printf("  PASS - key not found as expected\n");
    } else {
        printf("  FAIL - expected NOT_FOUND\n");
        free(res.data);
    }

    ////////////////////////////////////////////////////////////////////
    // DONE

    printf("Done.\n");

    toastyfs_free(tfs);
    return 0;
}
