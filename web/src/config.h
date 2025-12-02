#ifndef CONFIG_INCLUDED
#define CONFIG_INCLUDED

#include <chttp.h>
#include <ToastyFS.h>

typedef struct {
    ToastyString upstream_addr;
    uint16_t     upstream_port;

    HTTP_String  local_addr;
    uint16_t     local_port;

    bool         reuse_addr;
    bool         trace_bytes;
} ProxyConfig;

void parse_config_or_exit(ProxyConfig *config,
    int argc, char **argv);

#endif // CONFIG_INCLUDED
