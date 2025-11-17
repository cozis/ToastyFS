#include <stdio.h>
#include <ToastyFS.h>

int main(void)
{
    ToastyString remote_addr = TOASTY_STR("127.0.0.1");
    uint16_t     remote_port = 8080;

    ToastyFS *toasty = toasty_connect(remote_addr, remote_port);
    if (toasty == NULL) {
        printf("Couldn't connect to metadata server");
        return -1;
    }

    ToastyString path_1 = TOASTY_STR("/first_file");
    ToastyString path_2 = TOASTY_STR("/second_file");

    // Begin creation operation. This does not block.
    ToastyHandle create_handle_1 = toasty_begin_create_file(toasty, path_1, 1024);
    if (create_handle_1 == TOASTY_INVALID) {
        printf("Couldn't create file 1");
        return -1;
    }

    // This doesn't block either.
    ToastyHandle create_handle_2 = toasty_begin_create_file(toasty, path_2, 1024);
    if (create_handle_2 == TOASTY_INVALID) {
        printf("Couldn't create file 2");
        return -1;
    }

    // Now block execution by overlapping the waiting
    // times for both file creations.

    ToastyResult result;
    int ret = toasty_wait_result(toasty, create_handle_1, &result, -1);
    if (ret < 0) {
        printf("Couldn't wait for completion\n");
        return -1;
    }
    if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
        printf("Couldn't create file 1\n");
        return -1;
    }

    ret = toasty_wait_result(toasty, create_handle_2, &result, -1);
    if (ret < 0) {
        printf("Couldn't wait for completion\n");
        return -1;
    }
    if (result.type != TOASTY_RESULT_CREATE_SUCCESS) {
        printf("Couldn't create file 2\n");
        return -1;
    }

    printf("All files were created!\n");

    toasty_disconnect(toasty);
    return 0;
}
