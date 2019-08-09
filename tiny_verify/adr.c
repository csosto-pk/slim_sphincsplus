#include "adr.h"
#include "endian.h"
#include <string.h>

/* Possible alternative design: we could make adr an array of 8 uint32_t's */
/* and use htonl to write into them */
/* This would be closer to the spirit of the spec; my only concern is the */
/* ubiquity of the htonl function */

/* This sets which layer of Merkle trees within the hypertree we are */
/* working on; 0 is the bottom most */
void set_layer_address( adr_t adr, unsigned layer_address ) {
    memset( adr, 0, 3 );
    adr[3] = layer_address;  /* We never have more than 8 layers of trees */
}

/* This sets which tree within a layer we are working on */
/* 0 is the leftmost */
void set_tree_address( adr_t adr, uint_fast64_t tree_address ) {
    memset( adr+4, 0, 4 ); /* We never deal with more than 2**64 trees */
                           /* in a single layer */
    put_bigendian( adr+8, tree_address, 8 );
}

/* This sets the type of hash we're doing */
/* See enum adr_type for the various possible types */
/* This also implicitly clears out the remaining values (the ones other */
/* than layer address and tree address) */
void set_type( adr_t adr, enum adr_type type ) {
    memset( adr+16, 0, 16 );
    adr[19] = type;
}

/* This sets which WOTS leaf within the tree we're working on */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_key_pair_address( adr_t adr, unsigned key_pair_address ) {
    adr[23] = key_pair_address;  /* We never have trees with height > 8 */
}

/* This sets which WOTS digit we're working on */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_chain_address( adr_t adr, unsigned chain_address ) {
    adr[27] = chain_address; /* We never have 256 digits in a WOTS */
}

/* This sets where in the WOTS chain we're working on */
/* 0 is the lowest */
/* This assumes that we've already called set_type */
void set_hash_address( adr_t adr, unsigned hash_address ) {
    adr[29] = adr[30] = 0;
    adr[31] = hash_address; /* We never have W > 8 */
}

/* This sets the height of the Merkle node within the tree */
/* 0 is the leaf, 1 is the lowest binary node in the tree */
/* This assumes that we've already called set_type */
void set_tree_height( adr_t adr, unsigned tree_height ) {
    adr[27] = tree_height; /* We never have more than 8 levels within a tree */
}

/* This sets the index of the FORS node or the Merkle node within the tree */
/* For FORS, the higher order bits indicate the FORS tree # */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_tree_index( adr_t adr, uint_fast32_t tree_index ) {
    adr[29] = tree_index >> 16;
    adr[30] = tree_index >> 8;
    adr[31] = tree_index;
}
