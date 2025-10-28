#include <stddef.h>
#include <TinyDFS.h>

int main(void)
{
    TinyDFS *tdfs = tinydfs_init("127.0.0.1", 8080);
    if (tdfs == NULL)
        return -1;

    if (tinydfs_submit_create(tdfs, "/my_file_1", -1, false, 1024) < 0) {
        tinydfs_free(tdfs);
        return -1;
    }

    if (tinydfs_submit_create(tdfs, "/my_file_2", -1, false, 1024) < 0) {
        tinydfs_free(tdfs);
        return -1;
    }

    char buff_1[] = "This is file 1";
    if (tinydfs_submit_write(tdfs, "/my_file_1", -1, 0, buff_1, sizeof(buff_1)-1) < 0) {
        tinydfs_free(tdfs);
        return -1;
    }

    char buff_2[] = "This is file 1";
    if (tinydfs_submit_write(tdfs, "/my_file_1", -1, 0, buff_2, sizeof(buff_2)-1) < 0) {
        tinydfs_free(tdfs);
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        TinyDFS_Result result;
        tinydfs_wait(tdfs, -1, &result, -1);
    }

    tinydfs_free(tdfs);
    return 0;
}
