#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32 // We only sign 256-bit hashes for image signing
#define SPX_TEST_INVALIDSIG // Only when we want to generate and store an invalid sig for the verifier to fail on

static int write_file(const char *filename, void *mem, unsigned long long len ) { 

   FILE *f = fopen( filename, "w" );
   if (!f) {
       fprintf( stderr, "Unable to open file %s for writing.\n", filename );
       return 0;
   }

   //printf("Writing to file %s... ", filename);
   unsigned num_byte = fwrite(mem,1,(size_t)len,f);
   fclose(f); 
   if (num_byte != (size_t)len) {
       fprintf( stderr, "Error writing %d bytes to file %s.\n", 
					(int)len, filename);
       return 0;
   }
   //printf("Successful.");

   return 1; 
} 


int main(int argc, char **argv)
{
    int ret = 0;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    if (argc != 4 ) {
        fprintf( stderr, "Usage: %s [msg file] [pk file] [sig file]\n", argv[0] );
        return -1;
    }

    printf("Generating message to be signed... ");
    randombytes(m, SPX_MLEN);
    /* Write message to file */
//TODO: Catch return code from write
    write_file(argv[1], m, SPX_MLEN); 
    printf("Successful.\n");
//printf("****** write1: %10x\n", sm);

    printf("Generating keypair... ");
    if (crypto_sign_keypair(pk, sk)) {
        printf("failed!\n");
        return -1;
    }
    /* Write public key to file */ 
//TODO: Catch return code from write
//printf("****** write2: %10x\n", pk);
    write_file(argv[2], pk, SPX_PK_BYTES); 
    printf("Successful.\n");

    printf("Generating signature... ");
    crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
    printf("Successful.\n");
    if (smlen != SPX_BYTES + SPX_MLEN) {
        printf("    X smlen incorrect [%llu != %u]!\n",
               smlen, SPX_BYTES);
        ret = -1;
    }
    /* else {
         printf("    smlen as expected [%llu].\n", smlen);
    } */
    /* Write signature to file */
//TODO: Catch return code from write
    write_file(argv[3], sm, smlen); 
//printf("****** write2: %10x\n", pk);

//TODO: Don't test that. The verifier tests it. 
    /* Test if signature is valid. */
    if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
        printf("    X verification failed!\n");
        ret = -1;
    }
    else {
        printf("    verification succeeded.\n");
    }

    /* Test if the correct message was recovered. */
/*    if (mlen != SPX_MLEN) {
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
*/
    /* Test if signature is valid when validating in-place. */
/*    if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
        printf("  X in-place verification failed!\n");
        ret = -1;
    }
    else {
        printf("    in-place verification succeeded.\n");
    }
*/

    /* Test if flipping bits invalidates the signature (it should). */

    /* Flip the first bit of the message. Should invalidate. */
/*    sm[smlen - 1] ^= 1;
    if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
        printf("  X flipping a bit of m DID NOT invalidate signature!\n");
        ret = -1;
    }
    else {
        printf("    flipping a bit of m invalidates signature.\n");
    }
    sm[smlen - 1] ^= 1;
*/

#ifdef SPX_TEST_INVALIDSIG
//TODO: Test with an extra argument passed create a flipped bit in message and in signature hash to ensure the signature verification fails. 
//    int j;
    /* Flip one bit per hash; the signature is entirely hashes. */
/*    for (j = 0; j < (int)(smlen - SPX_MLEN); j += SPX_N) {
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
*/
#endif

    free(m);
    free(sm);
    free(mout);

    return ret;
}
