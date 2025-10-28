#ifndef SHA256_INCLUDED
#define SHA256_INCLUDED

#include <stddef.h>
#include <stdint.h>

void sha256(const void *data, size_t len, uint8_t *hash);

#endif // SHA256_INCLUDED
