#include <stddef.h>
#include <MouseFS.h>

int main(void)
{
    MouseFS *mfs = mousefs_init("127.0.0.1", 8080);
    if (mfs == NULL)
        return -1;

    if (mousefs_submit_create(mfs, "/my_file_1", -1, false, 1024) < 0) {
        mousefs_free(mfs);
        return -1;
    }

    if (mousefs_submit_create(mfs, "/my_file_2", -1, false, 1024) < 0) {
        mousefs_free(mfs);
        return -1;
    }

    char buff_1[] = "This is file 1";
    if (mousefs_submit_write(mfs, "/my_file_1", -1, 0, buff_1, sizeof(buff_1)-1) < 0) {
        mousefs_free(mfs);
        return -1;
    }

    char buff_2[] = "This is file 2";
    if (mousefs_submit_write(mfs, "/my_file_1", -1, 0, buff_2, sizeof(buff_2)-1) < 0) {
        mousefs_free(mfs);
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        MouseFS_Result result;
        mousefs_wait(mfs, -1, &result, -1);
    }

    mousefs_free(mfs);
    return 0;
}
