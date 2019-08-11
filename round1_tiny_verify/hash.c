#include "hash.h"
#include "sha256.h"
#include <stdbool.h>
#include <stdint.h>

/*
 * This defines the various internal functions that Sphincs+ relies on
 *
 * Random musing: we could rearchitecture this to use function pointers,
 * rather than passing a hash_t around (and using switch statements based
 * on the hash type).  I suspect that function pointers would not give us
 * much performance gain at all, and so it'd not be worth it
 */

int hash_len( hash_t hash ) {
    static int hash_len[4] = { 16,  /* 128 bits */
                               24,  /* 192 bits */
                               32,  /* 256 bits */
                               0    /* error */
    };
    return hash_len[ hash & HASH_LEN_MASK ];
}

/* len is in bytes */
/* Note: for n=32, this can be optimized (as the first hash compression */
/* computation is constant); we're not that concerned with the n=32 case */
/* for now */
static void xor_mask_sha256(uint32_t *dest, const uint32_t *src,
                 int len /* in bytes */, hash_t hash,
                 const void *pk_seed, adr_t adr, SHA256_CTX *ctx, int n) {
    int i;
    unsigned char preimage[ MAX_HASH_LEN + LEN_ADR + 4 ];
    memcpy( preimage, pk_seed, n );
    memcpy( preimage+n, adr, LEN_ADR );
    memset( preimage+n+LEN_ADR, 0, 4 );
    int len_preimage = n + LEN_ADR + 4;
    uint32_t buffer[SHA256_LEN/4];
    for (i=0; len > 0; i++) {
        preimage[len_preimage-1] = i; /* We assume that the mask will */
                                      /* always be shorter than 8k */
        SHA256_Init( ctx );
        SHA256_Update( ctx, preimage, len_preimage );
        SHA256_Final( (void *)buffer, ctx );
        int this_len = len;
        if (this_len > SHA256_LEN) this_len = SHA256_LEN;
        len -= this_len;
        int j;
        for (j=0; j*4<this_len; j++) {
            *dest++ = *src++ ^ buffer[j];
        }
    }
}

/*
 * The F function from Sphincs+
 * It assumes that the message m is n bytes long 
 */
bool do_F( void *dest, hash_t hash, const void *pk_seed, adr_t adr,
    const void *m ) {
    int n = hash_len(hash);
    if (!n) return false;

    uint32_t mask[MAX_HASH_LEN/4];

    switch (hash >> HASH_TYPE_SHIFT) {
//    case HASH_TYPE_SHAKE256 >> HASH_TYPE_SHIFT:
// TO DO: IMPLEMENT THIS CASE

    case HASH_TYPE_SHA256 >> HASH_TYPE_SHIFT: {
        SHA256_CTX ctx;
        xor_mask_sha256( mask, m, n, hash, pk_seed, adr, &ctx, n ); 
        SHA256_Init( &ctx );
        SHA256_Update( &ctx, pk_seed, n );
        SHA256_Update( &ctx, adr, LEN_ADR );
        SHA256_Update( &ctx, mask, n );
        SHA256_Final( (void *)mask, &ctx );
        break;
    }

//    case HASH_TYPE_HARAKA >> HASH_TYPE_SHIFT:
// TO DO: IMPLEMENT THIS CASE

    default:
        return false;
    }

    memcpy( dest, mask, n );

    return true;
}

/*
 * The H function from Sphincs+
 * It assumes that the messages m1, m2 are n bytes long 
 */
bool do_H( void *dest, hash_t hash, const void *pk_seed, adr_t adr,
    const void *m1, const void *m2 ) {
    int n = hash_len(hash);
    if (!n) return false;

    uint32_t messages[MAX_HASH_LEN/2];
    memcpy( messages+0, m1, n );
    memcpy( messages+n/4, m2, n );

    return do_thash( dest, hash, pk_seed, adr, messages, 2*n );
}

/*
 * Grumble, the documents don't actually describe this.
 * This was rederived by looking at the reference source
 */
bool do_thash( unsigned char *dest, hash_t hash, 
               const void *pk_seed, adr_t adr,
               const uint32_t *in, size_t in_len ) {
    int n = hash_len(hash);
    if (!n) return false;

    unsigned char output[ MAX_HASH_LEN ];

    switch (hash >> HASH_TYPE_SHIFT) {
//    case HASH_TYPE_SHAKE256 >> HASH_TYPE_SHIFT:
// TO DO: IMPLEMENT THIS CASE

    case HASH_TYPE_SHA256 >> HASH_TYPE_SHIFT: {
        SHA256_CTX ctx;
        uint32_t masked[ in_len / 4 ];
        xor_mask_sha256(masked, in, in_len, hash, 
                 pk_seed, adr, &ctx, n);
        SHA256_Init( &ctx );
        SHA256_Update( &ctx, pk_seed, n );
        SHA256_Update( &ctx, adr, LEN_ADR );
        SHA256_Update( &ctx, masked, in_len );
        SHA256_Final( (void *)output, &ctx );
        break;
    }
//    case HASH_TYPE_HARAKA >> HASH_TYPE_SHIFT:
// TO DO: IMPLEMENT THIS CASE

    default:
        return false;
    }

    memcpy( dest, output, n );
    return true;
}

struct bit_extract {
    const unsigned char *p;
    int len;      /* Number of bytes remaining */
    int bit_pos;  /* Current bit position */
}; 
static void init_bit_extract( struct bit_extract *bit,
                              const unsigned char *p, int len ) {
    bit->p = p;
    bit->len = len;
    bit->bit_pos = 8;
}
#include <stdio.h>
static unsigned char reverse_byte(unsigned char c) {
    c = ((c << 1) & 0xaa) | ((c >> 1) & 0x55);
    c = ((c << 2) & 0xcc) | ((c >> 2) & 0x33);
    c = ((c << 4) & 0xf0) | ((c >> 4) & 0x0f);
    return c;
}

/*
 * This extracts the next 'num_bits' from the bitstream, returning those
 * bits as an int (uint64_t)
 * However, when they did the Sphincs+ reference implementation, they reversed
 * the bits on some of the bytes.  Given that's the standard (at least for
 * now, hopefully they'll change it), we also sometimes reverse the bits in
 * the byte as well
 */
static uint64_t do_bit_extract( struct bit_extract *bit, int num_bit, bool reverse ) {
    uint64_t r = 0;
    while (num_bit >= bit->bit_pos) {
        if (bit->len == 0) { printf( "FATAL ERROR IN BIT_EXTRACT\n" ); }
        num_bit -= bit->bit_pos;
        int mask = (1 << bit->bit_pos) - 1;
        unsigned char c = *bit->p;
        if (reverse) c = reverse_byte(c);
        r += (uint64_t)(c & mask) << num_bit;
        bit->p += 1;
        bit->len -= 1;
        bit->bit_pos = 8;
    }
    if (num_bit > 0) {
        if (bit->len == 0) { printf( "FATAL ERROR IN BIT_EXTRACT\n" ); }
        bit->bit_pos -= num_bit;
        int mask = (1 << num_bit) - 1;
        unsigned char c = *bit->p;
        if (reverse) c = reverse_byte(c);
        r += (uint64_t)((c >> bit->bit_pos) & mask);
    }
    return r;
}
/*
 * This skips the bitstream ahead to the next byte boundary
 */
static void round_bit_extract( struct bit_extract *bit ) {
    if (bit->bit_pos != 8) {
        bit->p += 1;
        bit->len -= 1;
        bit->bit_pos = 8;
    }
} 

/*
 * This converts the message (and randomizer) into FORS/Hypertree parameters
 * This uses the message to select both a random set of FORS digits, plus
 * a random FORS public key (whihc is the leaf in the hypertree)
 *
 * Both the signer and the verifier need this
 * 
 * The results:
 * - md - the array of SPH_K values from 0 and 2**SPH_A - 1; these are the
 *        leaves in the FORS tree that are revealed for this message
 * - idx_leaf - the leaf in the bottom-most Merkle tree that the FORS tree
 *        hangs off of
 * - idx_tree - the index (distance from the left-most edge of the entire
 *        hypertree) of the bottom-most Merkle tree.  This contains all the
 *        indicies of the trees above it.
 */
void do_compute_digest_index( uint32_t *md, uint64_t *idx_tree,
            unsigned *idx_leaf,
            int n, const unsigned char *r, const unsigned char *seed, 
            const unsigned char *root, const void *message, size_t len_message,
            int k, int a, int h, int d) {
    unsigned char hash[32];
    SHA256_CTX ctx;

    /* Do the initial hash */
    SHA256_Init( &ctx );
    SHA256_Update( &ctx, r, n );
    SHA256_Update( &ctx, seed, n );
    SHA256_Update( &ctx, root, n );
    SHA256_Update( &ctx, message, len_message );
    SHA256_Final( hash, &ctx );

    /* Number of bytes of H_msg output we'll need */
    int m = (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8;
    unsigned char buffer[ m + 31 ];

    /* Generate the MGF1-output into buffer, producing a long output */
    int i, index;
    unsigned char count[4] = { 0 };
    for (i=0, index = 0; i<m; i+=32, index++) {
        SHA256_Init( &ctx );
        SHA256_Update( &ctx, hash, 32 );
        count[3] = index;  /* We never need 8k of output, hence setting */
                           /* the lsbyte sufficies */
        SHA256_Update( &ctx, count, 4 );
        SHA256_Final( &buffer[i], &ctx );
    }

    /* Now, parse that output into the individual values */
    struct bit_extract bit;
    init_bit_extract( &bit, buffer, m );
    /* The first k*a bits are the digits of the FORS trees */
    /* Note that the bit ordering is reversed; that's what the Sphincs+ */
    /* reference code does */
    for (i=0; i<k; i++) {
        md[i] = do_bit_extract( &bit, a, true );
    }

    /* We step to the next byte boundery for the next output */
    round_bit_extract( &bit );
    /* The next bits specify which bottom level Merkle tree we're in */
    *idx_tree = do_bit_extract( &bit, h - h/d, false );

    round_bit_extract( &bit );
    /* The next bits specify which leaf of the bottom level tree we're in */
    *idx_leaf = do_bit_extract( &bit, h/d, false );
} 
