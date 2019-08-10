/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "sha256.h"

#ifndef BUILD_SLIM_VERIFIER // Or if code size is not a concern use the old SPHINCS+ 
static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
           (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
           (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
           (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}

static void store_bigendian_32(uint8_t *x, uint64_t u) {
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

static void store_bigendian_64(uint8_t *x, uint64_t u) {
    x[7] = (uint8_t) u;
    u >>= 8;
    x[6] = (uint8_t) u;
    u >>= 8;
    x[5] = (uint8_t) u;
    u >>= 8;
    x[4] = (uint8_t) u;
    u >>= 8;
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

#define SHR(x, c) ((x) >> (c))
#define ROTR_32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define ROTR_64(x, c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_32(x) (ROTR_32(x, 2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define Sigma1_32(x) (ROTR_32(x, 6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define sigma0_32(x) (ROTR_32(x, 7) ^ ROTR_32(x,18) ^ SHR(x, 3))
#define sigma1_32(x) (ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10))

#define M_32(w0, w14, w9, w1) w0 = sigma1_32(w14) + (w9) + sigma0_32(w1) + (w0);

#define EXPAND_32           \
    M_32(w0, w14, w9, w1)   \
    M_32(w1, w15, w10, w2)  \
    M_32(w2, w0, w11, w3)   \
    M_32(w3, w1, w12, w4)   \
    M_32(w4, w2, w13, w5)   \
    M_32(w5, w3, w14, w6)   \
    M_32(w6, w4, w15, w7)   \
    M_32(w7, w5, w0, w8)    \
    M_32(w8, w6, w1, w9)    \
    M_32(w9, w7, w2, w10)   \
    M_32(w10, w8, w3, w11)  \
    M_32(w11, w9, w4, w12)  \
    M_32(w12, w10, w5, w13) \
    M_32(w13, w11, w6, w14) \
    M_32(w14, w12, w7, w15) \
    M_32(w15, w13, w8, w0)

#define F_32(w, k)                                   \
    T1 = h + Sigma1_32(e) + Ch(e, f, g) + (k) + (w); \
    T2 = Sigma0_32(a) + Maj(a, b, c);                \
    h = g;                                           \
    g = f;                                           \
    f = e;                                           \
    e = d + T1;                                      \
    d = c;                                           \
    c = b;                                           \
    b = a;                                           \
    a = T1 + T2;


static size_t crypto_hashblocks_sha256(uint8_t *statebytes,
                                       const uint8_t *in, size_t inlen) {
    uint32_t state[8];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t T1;
    uint32_t T2;

    a = load_bigendian_32(statebytes + 0);
    state[0] = a;
    b = load_bigendian_32(statebytes + 4);
    state[1] = b;
    c = load_bigendian_32(statebytes + 8);
    state[2] = c;
    d = load_bigendian_32(statebytes + 12);
    state[3] = d;
    e = load_bigendian_32(statebytes + 16);
    state[4] = e;
    f = load_bigendian_32(statebytes + 20);
    state[5] = f;
    g = load_bigendian_32(statebytes + 24);
    state[6] = g;
    h = load_bigendian_32(statebytes + 28);
    state[7] = h;

    while (inlen >= 64) {
        uint32_t w0  = load_bigendian_32(in + 0);
        uint32_t w1  = load_bigendian_32(in + 4);
        uint32_t w2  = load_bigendian_32(in + 8);
        uint32_t w3  = load_bigendian_32(in + 12);
        uint32_t w4  = load_bigendian_32(in + 16);
        uint32_t w5  = load_bigendian_32(in + 20);
        uint32_t w6  = load_bigendian_32(in + 24);
        uint32_t w7  = load_bigendian_32(in + 28);
        uint32_t w8  = load_bigendian_32(in + 32);
        uint32_t w9  = load_bigendian_32(in + 36);
        uint32_t w10 = load_bigendian_32(in + 40);
        uint32_t w11 = load_bigendian_32(in + 44);
        uint32_t w12 = load_bigendian_32(in + 48);
        uint32_t w13 = load_bigendian_32(in + 52);
        uint32_t w14 = load_bigendian_32(in + 56);
        uint32_t w15 = load_bigendian_32(in + 60);

        F_32(w0, 0x428a2f98)
        F_32(w1, 0x71374491)
        F_32(w2, 0xb5c0fbcf)
        F_32(w3, 0xe9b5dba5)
        F_32(w4, 0x3956c25b)
        F_32(w5, 0x59f111f1)
        F_32(w6, 0x923f82a4)
        F_32(w7, 0xab1c5ed5)
        F_32(w8, 0xd807aa98)
        F_32(w9, 0x12835b01)
        F_32(w10, 0x243185be)
        F_32(w11, 0x550c7dc3)
        F_32(w12, 0x72be5d74)
        F_32(w13, 0x80deb1fe)
        F_32(w14, 0x9bdc06a7)
        F_32(w15, 0xc19bf174)

        EXPAND_32

        F_32(w0, 0xe49b69c1)
        F_32(w1, 0xefbe4786)
        F_32(w2, 0x0fc19dc6)
        F_32(w3, 0x240ca1cc)
        F_32(w4, 0x2de92c6f)
        F_32(w5, 0x4a7484aa)
        F_32(w6, 0x5cb0a9dc)
        F_32(w7, 0x76f988da)
        F_32(w8, 0x983e5152)
        F_32(w9, 0xa831c66d)
        F_32(w10, 0xb00327c8)
        F_32(w11, 0xbf597fc7)
        F_32(w12, 0xc6e00bf3)
        F_32(w13, 0xd5a79147)
        F_32(w14, 0x06ca6351)
        F_32(w15, 0x14292967)

        EXPAND_32

        F_32(w0, 0x27b70a85)
        F_32(w1, 0x2e1b2138)
        F_32(w2, 0x4d2c6dfc)
        F_32(w3, 0x53380d13)
        F_32(w4, 0x650a7354)
        F_32(w5, 0x766a0abb)
        F_32(w6, 0x81c2c92e)
        F_32(w7, 0x92722c85)
        F_32(w8, 0xa2bfe8a1)
        F_32(w9, 0xa81a664b)
        F_32(w10, 0xc24b8b70)
        F_32(w11, 0xc76c51a3)
        F_32(w12, 0xd192e819)
        F_32(w13, 0xd6990624)
        F_32(w14, 0xf40e3585)
        F_32(w15, 0x106aa070)

        EXPAND_32

        F_32(w0, 0x19a4c116)
        F_32(w1, 0x1e376c08)
        F_32(w2, 0x2748774c)
        F_32(w3, 0x34b0bcb5)
        F_32(w4, 0x391c0cb3)
        F_32(w5, 0x4ed8aa4a)
        F_32(w6, 0x5b9cca4f)
        F_32(w7, 0x682e6ff3)
        F_32(w8, 0x748f82ee)
        F_32(w9, 0x78a5636f)
        F_32(w10, 0x84c87814)
        F_32(w11, 0x8cc70208)
        F_32(w12, 0x90befffa)
        F_32(w13, 0xa4506ceb)
        F_32(w14, 0xbef9a3f7)
        F_32(w15, 0xc67178f2)

        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }

    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);

    return inlen;
}

static const uint8_t iv_256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};

void sha256_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}

void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);

    crypto_hashblocks_sha256(state, in, 64 * inblocks);
    bytes += 64 * inblocks;

    store_bigendian_64(state + 32, bytes);
}

void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;

    crypto_hashblocks_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; ++i) {
            padded[i] = 0;
        }
        padded[56] = (uint8_t) (bytes >> 53);
        padded[57] = (uint8_t) (bytes >> 45);
        padded[58] = (uint8_t) (bytes >> 37);
        padded[59] = (uint8_t) (bytes >> 29);
        padded[60] = (uint8_t) (bytes >> 21);
        padded[61] = (uint8_t) (bytes >> 13);
        padded[62] = (uint8_t) (bytes >> 5);
        padded[63] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha256(state, padded, 64);
    } else {
        for (size_t i = inlen + 1; i < 120; ++i) {
            padded[i] = 0;
        }
        padded[120] = (uint8_t) (bytes >> 53);
        padded[121] = (uint8_t) (bytes >> 45);
        padded[122] = (uint8_t) (bytes >> 37);
        padded[123] = (uint8_t) (bytes >> 29);
        padded[124] = (uint8_t) (bytes >> 21);
        padded[125] = (uint8_t) (bytes >> 13);
        padded[126] = (uint8_t) (bytes >> 5);
        padded[127] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < 32; ++i) {
        out[i] = state[i];
    }
}
#endif //#ifndef BUILD_SLIM_VERIFIER 

void sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
#ifdef BUILD_SLIM_VERIFIER // Call the OpenSSL style SHA256 to slim down client 
    SHA256((void *)in, (unsigned int)inlen, (unsigned char *)out);
#else // Or if code size is not a concern use the old SPHINCS+ 
    uint8_t state[40];
    sha256_inc_init(state);
    sha256_inc_finalize(out, state, in, inlen);
#endif // #ifdef BUILD_SLIM_VERIFIER

}

#ifdef BUILD_SLIM_VERIFIER // Don't use in verifier to keep it slim 
#ifndef USE_OPENSSL_SHA256 // If not using OpenSSL for SHA256
/* If we don't have OpenSSL, here's a SHA256 implementation a la OpenSSL */
#define SHA256_FINALCOUNT_SIZE  8
#define SHA256_K_SIZE	        64
static const unsigned long K[SHA256_K_SIZE] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

void put_bigendian_4( void *target, unsigned long value ) {
    unsigned char *b = target;
    unsigned bytes = 4;
    int i;

    for (i = bytes-1; i >= 0; i--) {
        b[i] = value & 0xff;
        value >>= 8;
    }
}
    
uint32_t get_bigendian_4( const void *target ) {
    const unsigned char *b = target;
    uint32_t result = 0;
    unsigned bytes = 4;
    int i;

    for (i=0; i<bytes; i++) {
        result = 256 * result + (b[i] & 0xff);
    }

    return result;
}

/* Various logical functions */

/* Rotate x right by rot bits */
static unsigned long RORc(unsigned long x, int rot) {
    rot &= 31; if (rot == 0) return x;
    unsigned long right = ((x&0xFFFFFFFFUL)>>rot );
    unsigned long left  = ((x&0xFFFFFFFFUL)<<(32-rot) );
    return (right|left) & 0xFFFFFFFFUL;
}
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y)) 
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

static void sha256_compress (SHA256_CTX * ctx, const void *buf)
{
    unsigned long S0, S1, S2, S3, S4, S5, S6, S7, W[SHA256_K_SIZE], t0, t1, t;
    int i;
    const unsigned char *p;

    /* copy state into S */
    S0 = ctx->h[0];
    S1 = ctx->h[1];
    S2 = ctx->h[2];
    S3 = ctx->h[3];
    S4 = ctx->h[4];
    S5 = ctx->h[5];
    S6 = ctx->h[6];
    S7 = ctx->h[7];

    /*
     * We've been asked to perform the hash computation on this 512-bit string.
     * SHA256 interprets that as an array of 16 bigendian 32 bit numbers; copy
     * it, and convert it into 16 unsigned long's of the CPU's native format
     */
    p = buf;
    for (i=0; i<16; i++) {
        W[i] = get_bigendian_4( p );
        p += 4;
    }

    /* fill W[16..63] */
    for (i = 16; i < SHA256_K_SIZE; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }        

    /* Compress */
#define RND(a,b,c,d,e,f,g,h,i)                         \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h  = t0 + t1;

     for (i = 0; i < SHA256_K_SIZE; ++i) {
         RND(S0,S1,S2,S3,S4,S5,S6,S7,i);
         t = S7; S7 = S6; S6 = S5; S5 = S4; 
         S4 = S3; S3 = S2; S2 = S1; S1 = S0; S0 = t;
     }
#undef RND     
 
    /* feedback */
    ctx->h[0] += S0;
    ctx->h[1] += S1;
    ctx->h[2] += S2;
    ctx->h[3] += S3;
    ctx->h[4] += S4;
    ctx->h[5] += S5;
    ctx->h[6] += S6;
    ctx->h[7] += S7;
}

void SHA256_Init (SHA256_CTX *ctx)
{
    ctx->Nl = 0;
    ctx->Nh = 0;
    ctx->num = 0;
    ctx->h[0] = 0x6A09E667UL;
    ctx->h[1] = 0xBB67AE85UL;
    ctx->h[2] = 0x3C6EF372UL;
    ctx->h[3] = 0xA54FF53AUL;
    ctx->h[4] = 0x510E527FUL;
    ctx->h[5] = 0x9B05688CUL;
    ctx->h[6] = 0x1F83D9ABUL;
    ctx->h[7] = 0x5BE0CD19UL;
}

void SHA256_Update (SHA256_CTX *ctx, const void *src, unsigned int count)
{
    unsigned new_count = (ctx->Nl + (count << 3)) & 0xffffffff;
    if (new_count < ctx->Nl) {
        ctx->Nh += 1;
    }
    ctx->Nl = new_count;

    while (count) {
        unsigned int this_step = 64 - ctx->num;
        if (this_step > count) this_step = count;
        memcpy( ctx->data + ctx->num, src, this_step);

        if (this_step + ctx->num < 64) {
            ctx->num += this_step;
            break;
        }

        src = (const unsigned char *)src + this_step;
        count -= this_step;
        ctx->num = 0;

        sha256_compress( ctx, ctx->data );
    }
}

/*
 * Add padding and return the message digest.
 */
void SHA256_Final (unsigned char *digest, SHA256_CTX *ctx)
{
    unsigned int i;
    unsigned char finalcount[SHA256_FINALCOUNT_SIZE];

    put_bigendian_4( &finalcount[0], ctx->Nh );
    put_bigendian_4( &finalcount[4], ctx->Nl );

    SHA256_Update(ctx, "\200", 1);

    if (ctx->num > 56) {
        SHA256_Update(ctx, "\0\0\0\0\0\0\0\0", 8);
    }
    memset( ctx->data + ctx->num, 0, 56 - ctx->num );
    ctx->num = 56;
    SHA256_Update(ctx, finalcount, SHA256_FINALCOUNT_SIZE);  /* Should cause a sha256_compress() */

    /*
     * The final state is an array of unsigned long's; place them as a series
     * of bigendian 4-byte words onto the output
     */ 
    for (i=0; i<8; i++) {
        put_bigendian_4( digest + 4*i, ctx->h[i] );
    }
}

void SHA256(const void *image, unsigned int len, unsigned char *result) {
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, image, len);
    SHA256_Final(result, &ctx);
}
#endif // #ifndef USE_OPENSSL_SHA256 
#endif //#ifdef BUILD_SLIM_VERIFIER 


/*
 * Compresses an address to a 22-byte sequence.
 * This reduces the number of required SHA256 compression calls, as the last
 * block of input is padded with at least 65 bits.
 */
void compress_address(unsigned char *out, const uint32_t addr[8])
{
    ull_to_bytes(out,      1, addr[0]); /* drop 3 bytes of the layer field */
    ull_to_bytes(out + 1,  4, addr[2]); /* drop the highest tree address word */
    ull_to_bytes(out + 5,  4, addr[3]);
    ull_to_bytes(out + 9,  1, addr[4]); /* drop 3 bytes of the type field */
    ull_to_bytes(out + 10, 4, addr[5]);
    ull_to_bytes(out + 14, 4, addr[6]);
    ull_to_bytes(out + 18, 4, addr[7]);
}

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    unsigned char inbuf[inlen + 4];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        ull_to_bytes(inbuf + inlen, 4, i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA256_OUTPUT_BYTES) {
        ull_to_bytes(inbuf + inlen, 4, i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded, which can then be reused in thash
 **/
void seed_state(const unsigned char *pub_seed) {
    uint8_t block[SPX_SHA256_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA256_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }

#ifdef BUILD_SLIM_VERIFIER // Call the OpenSSL style SHA256 to slim down client 
    SHA256_Init(&sha2ctx_seeded);
    SHA256_Update(&sha2ctx_seeded, block, 64);
#else // Or if code size is not a concern use the old SPHINCS+ 
    sha256_inc_init(state_seeded);
    sha256_inc_blocks(state_seeded, block, 1);
#endif 
}

