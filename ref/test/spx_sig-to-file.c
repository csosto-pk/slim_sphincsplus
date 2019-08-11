#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32 // We only sign 256-bit hashes for image signing
//#define SPX_TEST_INVALIDSIG // Only when we want to generate and store 
		// an invalid sig for the verifier to fail on
//#define DEBUG // Only for debugging


/* Write len bytes of data from mem pointer in memory into the file 
   named filename */
static int write_file(const char *filename, void *mem, unsigned long long len ) { 
   FILE *f = fopen( filename, "w" );
   if (!f) {
       fprintf( stderr, "Unable to open file %s for writing.\n", filename );
       return -1;
   }

   //printf("Writing to file %s... ", filename);
   unsigned num_byte = fwrite(mem,1,(size_t)len,f);
   fclose(f); 
   if (num_byte != (size_t)len) {
       fprintf( stderr, "Error writing %d bytes to file %s.\n", 
					(int)len, filename);
       return -1;
   }
   //printf("Successful.");

   return 0; 
} 


/* Generates a random message to sign, generates keys, signs the 
   message and stores all three in the files provided as input arguments. */
int main(int argc, char **argv)
{

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    unsigned long long smlen;
#ifdef DEBUG
    unsigned long long mlen;
#endif

    if (argc != 4 ) {
        fprintf( stderr, "Usage: %s [msg file] [pk file] [sig file]\n", argv[0] );
        return -1;
    }

    printf("Generating message to be signed \n     and writing to file... ");
    randombytes(m, SPX_MLEN);
    /* Write message to file */
    if (!write_file(argv[1], m, SPX_MLEN)) 
       printf("Successful.\n");
    else 
       return -1; 

    printf("Generating keypair... \n     and writing to file... ");
    if (crypto_sign_keypair(pk, sk)) {
        printf("failed!\n");
        return -1;
    }
    /* Write public key to file */ 
    if (!write_file(argv[2], pk, SPX_PK_BYTES)) 
       printf("Successful.\n");
    else 
       return -1; 

    printf("Generating signature \n     and writing to file... ");
    crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
    if (smlen != SPX_BYTES + SPX_MLEN) {
        printf("    smlen incorrect [%llu != %u]!\n",
               smlen, SPX_BYTES);
        return -1;
    }
    /* else {
         printf("    smlen as expected [%llu].\n", smlen);
    } */

#ifdef SPX_TEST_INVALIDSIG
    /* Test if flipping bits invalidates the signature (it should). */  
    sm[smlen - 1] ^= 1; /* Flip the first bit of the message. 
			Should invalidate. */
    /* Alternatively, for testing we could flip one bit per hash; 
    the signature is entirely hashes.*/
    /*for (j = 0; j < (int)(smlen - SPX_MLEN); j += SPX_N)
       sm[j] ^= 1; */
#endif

    /* Write signature to file */
    if (write_file(argv[3], sm, smlen)==-1)
       return -1; 
    printf("Successful.\n"); 

#ifdef DEBUG
    /* Only for debugging. Test if signature is valid. */
    if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
        printf("Tried to verify signature. Verification failed!\n");
#ifdef SPX_TEST_INVALIDSIG
        printf("    (We intentionally generated an invalid signature.)\n");
#endif
    }
    else {
        printf("Verification succeeded.\n");
    }
#endif

    free(m);
    free(sm);
    free(mout);

    return 0; 
}
