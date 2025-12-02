#include "config.h"

void parse_config_or_exit(ProxyConfig *config,
    int argc, char **argv)
{
    config->upstream_addr = TOASTY_STR("127.0.0.1");
    config->upstream_port = 9000;

    config->local_addr = HTTP_STR("127.0.0.1");
    config->local_port = 8080;

    config->reuse_addr = false;
    config->trace_bytes = false;

    for (int i = 1; i < argc; i++) {

        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("TODO: print help\n");
            exit(0);
        }

        if (!strcmp(argv[i], "--upstream-addr")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                exit(-1);
            }
            config->upstream_addr = (ToastyString) { argv[i], strlen(argv[i]) };

        } else if (!strcmp(argv[i], "--upstream-port")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                exit(-1);
            }
            int tmp = atoi(argv[i]);
            if (tmp < 1 || tmp > UINT16_MAX) {
                fprintf(stderr, "Error: Invalid port %s\n", argv[i]);
                exit(-1);
            }
            config->upstream_port = (uint16_t) tmp;

        } else if (!strcmp(argv[i], "--local-addr")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                exit(-1);
            }
            config->local_addr = (HTTP_String) { argv[i], strlen(argv[i]) };

        } else if (!strcmp(argv[i], "--local-port")) {

            i++;
            if (i == argc) {
                fprintf(stderr, "Error: Missing value after %s\n", argv[i-1]);
                exit(-1);
            }
            int tmp = atoi(argv[i]);
            if (tmp < 1 || tmp > UINT16_MAX) {
                fprintf(stderr, "Error: Invalid port %s\n", argv[i]);
                exit(-1);
            }
            config->local_port = (uint16_t) tmp;
        } else if(!strcmp(argv[i], "--reuse-addr")) {
            config->reuse_addr = true;
        } else if(!strcmp(argv[i], "--trace-bytes")) {
            config->trace_bytes = true;
        } else {
            fprintf(stderr, "Error: Invalid option %s\n", argv[i]);
            exit(-1);
        }
    }
}
