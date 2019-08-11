#include <stdint.h>
#include "endian.h"

void put_bigendian( void *target, uint_fast64_t value, size_t bytes ) {
    unsigned char *b = target;
    int i;

    for (i = bytes-1; i >= 0; i--) {
        b[i] = value & 0xff;
        value >>= 8;
    }
}
