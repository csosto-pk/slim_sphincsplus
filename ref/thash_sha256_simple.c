#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "sha256.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[SPX_SHA256_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    SHA256_CTX sha2ctx;
    SHA256_Init(&sha2ctx); // Initialize (to prevent segmentation fault).
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    uint8_t sha2_state[40];
    // sha256_inc_init(sha2_state); // Initialize the state 
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */
    /* Retrieve precomputed state containing pub_seed */
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    memcpy(&sha2ctx, &sha2ctx_seeded, 10*sizeof(unsigned long)+sizeof(unsigned));
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    memcpy(sha2_state, state_seeded, 40 * sizeof(uint8_t));
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)

    compress_address(buf, addr);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    SHA256_Update(&sha2ctx, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    SHA256_Final(outbuf, &sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    memcpy(out, outbuf, SPX_N);
}
