#if !defined( HASH_H_ )
#define HASH_H_

#include "adr.h"
#include <stdbool.h>
#include <string.h>

typedef unsigned hash_t;
#define HASH_LEN_128  0x00
#define HASH_LEN_192  0x01
#define HASH_LEN_256  0x02
#define HASH_LEN_MASK 0x03
#define HASH_TYPE_SHAKE256 0x00
#define HASH_TYPE_SHA256   0x04
#define HASH_TYPE_HARAKA   0x08
#define HASH_TYPE_SHIFT  2

int hash_len( hash_t hash );
#define MAX_HASH_LEN 32

bool do_F( void *dest, hash_t hash, const void *pk_seed, adr_t adr,
           const void *m ); 
bool do_H( void *dest, hash_t hash, const void *pk_seed, adr_t adr,
           const void *m1, const void *m2 );
bool do_thash( unsigned char *dest, hash_t hash, 
           const void *pk_seed, adr_t adr,
           const uint32_t *in, size_t in_len );
void do_compute_digest_index( uint32_t *md, uint64_t *idx_tree, 
            unsigned *idx_leaf,
            int n, const unsigned char *r, const unsigned char *seed,
            const unsigned char *root, const void *message, size_t len_message,
            int k, int a, int h, int d);

#endif /* HASH_H_ */
