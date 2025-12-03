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

    ToastyString path = TOASTY_STR("/first_file");

    int ret = toasty_create_file(toasty, path, 1024, NULL);
    if (ret < 0) {
        printf("Couldn't create file\n");
        toasty_disconnect(toasty);
        return -1;
    }

    char data[] = "Hello, world!";
    ret = toasty_write(toasty, path, 0, data, sizeof(data)-1, NULL, 0);
    if (ret < 0) {
        printf("Couldn't write to file\n");
        toasty_disconnect(toasty);
        return -1;
    }

    toasty_disconnect(toasty);
    return 0;
}
