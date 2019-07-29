#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define MAX_MSG_SIZE 32 // We only sign 256-bit hashes for image signing 
#define MAX_PK_SIZE 64 /* SPHINCS+ PK size for SPHINCS+ image 
			signing parameters can be 48 or 64 bytes. */
#define MAX_SIG_SIZE 25000 /* SPHINCS+ Signature size for SPHINCS+
			image signing parameters can't be > 25KB */

//TODO: Delete this, we don't need it. 
#define SPX_MLEN 32 // We only sign 256-bit hashes for image signing



static int read_file( const char *filename, void *mem, unsigned max_len,
                      unsigned long long *len ) {
    *len = 0;
    FILE *f = fopen( filename, "r" );
    if (!f) {
        fprintf( stderr, "Unable to open file %s for reading.\n", filename );
        return 0;
    }

    //printf("Reading from file %s... ", filename);
    unsigned num_byte = fread(mem, 1, max_len, f);
    fclose(f);
    if (num_byte <= 0 || num_byte > max_len) {
        fprintf( stderr, "Error reading %d,%d  bytes from file %s \n", (int)num_byte, (int)max_len, filename);
        return 0;
    }

    *len = num_byte;
    //printf("Successful.\n");
    return 1;
}

int main(int argc, char **argv)
{
    int ret = 0;
    int i;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    if (argc != 4 ) {
        fprintf( stderr, "Usage: %s [msg file] [pk file] [sig file]\n", argv[0] );
        return -1;
    }

/*    randombytes(m, SPX_MLEN);

    printf("Generating keypair.. ");

    if (crypto_sign_keypair(pk, sk)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");

        printf("  - iteration #%d:\n", i);

        crypto_sign(sm, &smlen, m, SPX_MLEN, sk);

        if (smlen != SPX_BYTES + SPX_MLEN) {
            printf("  X smlen incorrect [%llu != %u]!\n",
                   smlen, SPX_BYTES);
            ret = -1;
        }
        else {
            printf("    smlen as expected [%llu].\n", smlen);
        }
*/

//TODO: Remove pk, amd mout since they are probably not necessary.
    unsigned char sk[SPX_SK_BYTES];
    unsigned char pk[MAX_PK_SIZE];
    unsigned char m[MAX_MSG_SIZE];
    unsigned char sm[MAX_SIG_SIZE]; 
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    unsigned long long smlen; 
    unsigned long long mlen;
    unsigned long long pklen; 
    /* Test if signature is valid. */
    // Read message from file 
//TODO: Catch return code from read
    read_file(argv[1], m, MAX_MSG_SIZE, &mlen); 
    // Read public key from file. 
//TODO: Catch return code from read
    read_file(argv[2], pk, MAX_PK_SIZE, &pklen); 
//printf("****** Read1: %20x\n", sm);
    // Read signature from file. 
//TODO: Catch return code from read
    read_file(argv[3], sm, MAX_SIG_SIZE, &smlen); 
    // Verify signature 
    if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
        printf("  X verification failed!\n");
        ret = -1;
    }
    else {
        printf("    verification succeeded.\n");
    }

//TODO: Don't assume you know SPX_MLEN in order to check it. 
        /* Test if the correct message was recovered. */
        if (mlen != SPX_MLEN) {
            printf("  X mlen incorrect [%llu != %u]!\n", mlen, SPX_MLEN);
            ret = -1;
        }
        else {
            printf("    mlen as expected [%llu].\n", mlen);
        }
        if (memcmp(m, mout, SPX_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    output message as expected.\n");
        }

        /* Test if signature is valid when validating in-place. */
        if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
            printf("  X in-place verification failed!\n");
            ret = -1;
        }
        else {
            printf("    in-place verification succeeded.\n");
        }

//TODO: Don't test flipping bits in message, the verifier should do that. 
        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        sm[smlen - 1] ^= 1;
        if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
            ret = -1;
        }
        else {
            printf("    flipping a bit of m invalidates signature.\n");
        }
        sm[smlen - 1] ^= 1;

//TODO: Don't test flipping bits in signature the verifier should do that. 
#ifdef SPX_TEST_INVALIDSIG
        int j;
        /* Flip one bit per hash; the signature is entirely hashes. */
        for (j = 0; j < (int)(smlen - SPX_MLEN); j += SPX_N) {
            sm[j] ^= 1;
            if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sm[j] ^= 1;
                ret = -1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - SPX_MLEN)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
#endif

    free(mout);

    return ret;
}
