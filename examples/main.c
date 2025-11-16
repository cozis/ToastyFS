#include <stddef.h>
#include <ToastyFS.h>

int main(void)
{
    ToastyFS *tfs = toastyfs_init("127.0.0.1", 8080);
    if (tfs == NULL)
        return -1;

    if (toastyfs_submit_create(tfs, "/my_file_1", -1, false, 1024) < 0) {
        toastyfs_free(tfs);
        return -1;
    }

    if (toastyfs_submit_create(tfs, "/my_file_2", -1, false, 1024) < 0) {
        toastyfs_free(tfs);
        return -1;
    }

    char buff_1[] = "This is file 1";
    if (toastyfs_submit_write(tfs, "/my_file_1", -1, 0, buff_1, sizeof(buff_1)-1) < 0) {
        toastyfs_free(tfs);
        return -1;
    }

    char buff_2[] = "This is file 2";
    if (toastyfs_submit_write(tfs, "/my_file_1", -1, 0, buff_2, sizeof(buff_2)-1) < 0) {
        toastyfs_free(tfs);
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        ToastyFS_Result result;
        toastyfs_wait(tfs, -1, &result, -1);
    }

    toastyfs_free(tfs);
    return 0;
}
