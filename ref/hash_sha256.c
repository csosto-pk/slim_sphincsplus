#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "sha256.h"

/* For SHA256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(const unsigned char *pub_seed,
                              const unsigned char *sk_seed)
{
    seed_state(pub_seed);
    (void)sk_seed; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
#ifndef BUILD_SLIM_VERIFIER // Don't use in verifier to keep it slim
void prf_addr(unsigned char *out, const unsigned char *key,
              const uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, key, SPX_N);
    compress_address(buf + SPX_N, addr);

    sha256(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    memcpy(out, outbuf, SPX_N);
}
#endif

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least SPX_SHA256_BLOCK_BYTES + SPX_N space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */

#ifndef BUILD_SLIM_VERIFIER // Don't use in verifier to keep it slim   
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen)
{
    unsigned char buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES];
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    SHA256_CTX sha2ctx;
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    uint8_t state[40];
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    int i;

#if SPX_N > SPX_SHA256_BLOCK_BYTES
    #error "Currently only supports SPX_N of at most SPX_SHA256_BLOCK_BYTES"
#endif

    /* This implements HMAC-SHA256 */
    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHA256_BLOCK_BYTES - SPX_N);

#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    SHA256_Init(&sha2ctx);
    SHA256_Update(&sha2ctx, buf, 64);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    sha256_inc_init(state);
    sha256_inc_blocks(state, buf, 1);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    memcpy(buf, optrand, SPX_N);

    /* If optrand + message cannot fill up an entire block */
    if (SPX_N + mlen < SPX_SHA256_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, mlen);
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, buf, mlen + SPX_N);
        SHA256_Final(buf + SPX_SHA256_BLOCK_BYTES, &sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, state,
                            buf, mlen + SPX_N);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(buf + SPX_N, m, SPX_SHA256_BLOCK_BYTES - SPX_N);
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, buf, 64);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_blocks(state, buf, 1);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)

        m += SPX_SHA256_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHA256_BLOCK_BYTES - SPX_N;
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, m, mlen);
        SHA256_Final(buf + SPX_SHA256_BLOCK_BYTES, &sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, state, m, mlen);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    }

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256(buf, buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}
#endif // #ifndef BUILD_SLIM_VERIFIER

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen)
{
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char seed[SPX_SHA256_OUTPUT_BYTES];

    /* Round to nearest multiple of SPX_SHA256_BLOCK_BYTES */
#if (SPX_SHA256_BLOCK_BYTES & (SPX_SHA256_BLOCK_BYTES-1)) != 0
    #error "Assumes that SPX_SHA256_BLOCK_BYTES is a power of 2"
#endif
#define SPX_INBLOCKS (((SPX_N + SPX_PK_BYTES + SPX_SHA256_BLOCK_BYTES - 1) & \
                        -SPX_SHA256_BLOCK_BYTES) / SPX_SHA256_BLOCK_BYTES)
    unsigned char inbuf[SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
    SHA256_CTX sha2ctx;
    SHA256_Init(&sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
    uint8_t state[40];
    sha256_inc_init(state);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)

    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    /* If R + pk + message cannot fill up an entire block */
    if (SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, inbuf, SPX_N + SPX_PK_BYTES + mlen);
        SHA256_Final(seed, &sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_finalize(seed, state, inbuf, SPX_N + SPX_PK_BYTES + mlen);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m,
               SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES);
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, inbuf, 64*SPX_INBLOCKS);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_blocks(state, inbuf, SPX_INBLOCKS);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)

        m += SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        mlen -= SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
#if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256) /* If using 
a SHA256 implementation with the OpenSSL API */
        SHA256_Update(&sha2ctx, m, mlen);
        SHA256_Final(seed, &sha2ctx);
#else // Or if using a SHA256 implementation from crypto_hash/sha512/ref/
        sha256_inc_finalize(seed, state, m, mlen);
#endif // #if defined(USE_OPENSSL_SHA256) || defined(USE_OPENSSL_API_SHA256)
    }

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1(bufp, SPX_DGST_BYTES, seed, SPX_SHA256_OUTPUT_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
