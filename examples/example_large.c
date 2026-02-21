/*
 * example_large.c - Test with data larger than CHUNK_SIZE (32 bytes).
 *
 * This tests multi-chunk PUT/GET to expose potential bugs in
 * chunk transfer logic.
 */

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
    char addr1[] = "127.0.0.1:8081";
    char addr2[] = "127.0.0.1:8082";
    char addr3[] = "127.0.0.1:8083";
    char *addrs[] = { addr1, addr2, addr3 };

    printf("Connecting to cluster...\n");
    ToastyFS *tfs = toastyfs_init(1, addrs, 3);
    if (tfs == NULL) {
        fprintf(stderr, "toastyfs_init failed\n");
        return 1;
    }

    ToastyFS_Result res;
    int ret;

    // Create 100-byte test data (4 chunks: 32+32+32+4)
    char data[100];
    for (int i = 0; i < 100; i++)
        data[i] = 'A' + (i % 26);

    char key[] = "testkey";

    printf("PUT key=\"%s\" data_len=%d (should be 4 chunks of 32 bytes)\n",
        key, (int)sizeof(data));

    ret = toastyfs_put(tfs, key, strlen(key), data, sizeof(data), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_put returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }
    printf("  result: %s\n", error_name(res.error));
    if (res.error != TOASTYFS_ERROR_VOID) {
        fprintf(stderr, "PUT failed: %s\n", error_name(res.error));
        toastyfs_free(tfs);
        return 1;
    }

    printf("GET key=\"%s\"\n", key);

    ret = toastyfs_get(tfs, key, strlen(key), &res);
    if (ret < 0) {
        fprintf(stderr, "toastyfs_get returned %d\n", ret);
        toastyfs_free(tfs);
        return 1;
    }
    printf("  result: %s\n", error_name(res.error));

    if (res.error == TOASTYFS_ERROR_VOID && res.data) {
        printf("  size: %d (expected %d)\n", res.size, (int)sizeof(data));

        if (res.size != (int)sizeof(data)) {
            printf("  FAIL - size mismatch\n");
        } else if (memcmp(res.data, data, res.size) == 0) {
            printf("  PASS - data matches\n");
        } else {
            printf("  FAIL - data mismatch!\n");
            printf("  First differing byte:\n");
            for (int i = 0; i < res.size; i++) {
                if (res.data[i] != data[i]) {
                    printf("    offset %d: got 0x%02x ('%c'), expected 0x%02x ('%c')\n",
                        i,
                        (unsigned char)res.data[i], res.data[i],
                        (unsigned char)data[i], data[i]);
                    break;
                }
            }
        }
        free(res.data);
    } else {
        printf("  FAIL - error or no data: %s\n", error_name(res.error));
    }

    printf("Done.\n");
    toastyfs_free(tfs);
    return 0;
}
