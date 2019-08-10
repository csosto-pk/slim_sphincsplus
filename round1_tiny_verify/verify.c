#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include "sphincs-verify.h"
#include "endian.h"
#include "hash.h"
#include "adr.h"
#include "wots.h"

/*
 * Verify a signature
 */
bool sphincs_plus_verify( const void *message, size_t len_message,
                const void *sphincs_sig, size_t len_signature,
                const void *public_key ) {
    unsigned n = 24;  /* All defined parameter sets currently use n=24 */

    /* Verify that the signature is the correct size */
    if (len_signature < LEN_SPHINCSPLUS_SIG) return false;

    /*
     * Now, start on the verification of the Sphincs+ signature
     */
    const unsigned char *r = sphincs_sig + 0;  /* The randomizer used to */
                /* hash the message that was signed (the LMS public key) */
    sphincs_sig += n;
    const unsigned char *s_pk_seed = (unsigned char *)public_key + 4;
    const unsigned char *s_root = (unsigned char *)public_key + 4 + n;
    /* We use the 192-S parameter set, summarized by these settings */
#define SPH_K    14   /* Number of FORS trees */
#define SPH_A    16   /* Height of each FORS tree */
#define SPH_H    64   /* Total hypertree height */
#define SPH_D     8   /* Number of tree layers */
#define SPH_T    (SPH_H / SPH_D) /* Height of each Merkle tree */
#define SPH_DLEN (SPH_D * 51) /* Total number of hashes in the WOTS sigs */
#define LEN_LMS_PUBLIC_KEY (4 + 4 + 4 + 16 + 24)
    uint32_t buffer2[SPH_K];
    uint64_t idx_tree;
    unsigned idx_leaf;

    /* Convert the message (and the random vector r) into the set of */
    /* revealed FORS digits, and the exact branch in the hypertree that */
    /* the FORS trees hang off of */
    do_compute_digest_index( buffer2, &idx_tree, &idx_leaf,
               24, r, s_pk_seed, s_root,
               message, len_message,
               SPH_K, SPH_A, SPH_H, SPH_D);

    /* Now, walk up the FORS trees */
    unsigned char buffer[ MAX_HASH_LEN ];
    {
        uint32_t fors_roots[SPH_K*(24/4)];
        unsigned char adr[LEN_ADR];
        set_layer_address( adr, 0 );
        set_tree_address( adr, idx_tree );
        set_type( adr, FORS_TREE_ADDRESS );
        set_key_pair_address( adr, idx_leaf );
        int i;
        for (i=0; i < SPH_K; i++) {
            int node = buffer2[i];
            node += (i << SPH_A);
            uint32_t *buffer = &fors_roots[ i * 24/4 ];
            set_tree_index( adr, node );
            set_tree_height( adr, 0 );
            do_F( buffer, HASH_TYPE_SHA256 | HASH_LEN_192, s_pk_seed, adr,
                 sphincs_sig );
            sphincs_sig += 24;
            int level;
            for (level = 0; level < SPH_A; level++, node >>= 1) {
                set_tree_index( adr, node >> 1 );
                set_tree_height( adr, level+1 );
                if (node & 1) {
                    do_H( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                          s_pk_seed, adr, sphincs_sig, buffer );
                } else {
                    do_H( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                          s_pk_seed, adr, buffer, sphincs_sig );
                }
                sphincs_sig += n;
             }
         }

         /* Hash all the roots together to come up with the FORS public key */
         set_type( adr, FORS_TREE_ROOT_COMPRESS );
         set_key_pair_address( adr, idx_leaf );
         do_thash( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                      s_pk_seed, adr, fors_roots, SPH_K * 24 );
    }

        /* Now, step up the hypertree */
    {
        int level;
        unsigned char adr[LEN_ADR];
        for (level = 0; level < SPH_D; level++) {
            unsigned char digits[51];
            expand_wots_digits( digits, 51, buffer, 24 );

            set_layer_address( adr, level );
            set_tree_address( adr, idx_tree );
            set_type( adr, WOTS_HASH_ADDRESS );
            set_key_pair_address( adr, idx_leaf );
            uint32_t wots_root[51 * 24/4];
            int i;
            for (i = 0; i<51; i++) {
                uint32_t *p = &wots_root[ i * 24/4 ];
                memcpy( p, sphincs_sig, 24 );
                sphincs_sig += 24;
                set_chain_address( adr, i );
                int j;
                for (j = digits[i]; j < 15; j++) {
                    set_hash_address( adr, j );
                    do_F( p, HASH_TYPE_SHA256|HASH_LEN_192,
                          s_pk_seed, adr, p );
                }
            }
            set_type( adr, WOTS_KEY_COMPRESSION );
            set_key_pair_address( adr, idx_leaf );
            do_thash( buffer, HASH_TYPE_SHA256|HASH_LEN_192, s_pk_seed,
                      adr, wots_root, 24 * 51 );

            set_type( adr, HASH_TREE_ADDRESS );
            for (i = 0; i < SPH_D; i++, idx_leaf >>= 1) {
                set_tree_height(adr, i+1 );
                set_tree_index(adr, idx_leaf >> 1 );
                if (idx_leaf & 1) {
                    do_H(buffer, HASH_TYPE_SHA256|HASH_LEN_192, s_pk_seed,
                             adr, sphincs_sig, buffer );
                } else {
                    do_H(buffer, HASH_TYPE_SHA256|HASH_LEN_192, s_pk_seed,
                             adr, buffer, sphincs_sig );
                }
                sphincs_sig += 24;
             }

             idx_leaf = (unsigned)idx_tree & ((1 << SPH_T) - 1);
             idx_tree >>= SPH_T;
        }
    }

    /*
     * Now, check if the top level Merkle root we computed matches what's in
     * the Sphincs+ public key
     */
    if (0 == memcmp( buffer, s_root, n)) {
        return true;   /* The Sphinc+ signature validates; everything */
                       /* checks out */
    } else {
        return false;  /* Oops, something's wrong */
    }
}

