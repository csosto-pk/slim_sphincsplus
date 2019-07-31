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

#define TEST_MSG_RECOVERY // Only if we want to check the recovered 
			// is the same as the one stored in the file.


/* Read up to max_len bytes of data from the file named filename and 
   put the data in mem pointer in memory and their length in the len pointer */
static int read_file(const char *filename, void *mem, unsigned max_len,
                      unsigned long long *len ) {
    *len = 0;
    FILE *f = fopen( filename, "r" );
    if (!f) {
        fprintf( stderr, "Unable to open file %s for reading.\n", filename );
        return -1;
    }

    //printf("Reading from file %s... ", filename);
    unsigned num_byte = fread(mem, 1, max_len, f);
    fclose(f);
    if (num_byte <= 0 || num_byte > max_len) {
        fprintf( stderr, "Error reading %d,%d  bytes from file %s \n", (int)num_byte, (int)max_len, filename);
        return -1;
    }

    *len = num_byte;
    //printf("Successful.\n");
    return 0;
}



/* Verify the SPHINCS+ signatures from the message, public key and 
   signature files provided as input arguments. */
int main(int argc, char **argv)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    if (argc != 4 ) {
        fprintf( stderr, "Usage: %s [msg file] [pk file] [sig file]\n", argv[0] );
        return -1;
    }

    unsigned char pk[MAX_PK_SIZE];
    unsigned char m[MAX_MSG_SIZE];
    unsigned char sm[MAX_SIG_SIZE]; 
#ifdef TEST_MSG_RECOVERY
    unsigned char *mout = malloc(MAX_SIG_SIZE);
#endif
    unsigned long long smlen; 
    unsigned long long mlen;
    unsigned long long pklen; 
    /* Test if signature is valid. */
    // Read message from file 
    printf("Loading message, public key and signature from files... ");
    if (read_file(argv[1], m, MAX_MSG_SIZE, &mlen)==-1) 
       return -1; 
    // Read public key from file. 
    if (read_file(argv[2], pk, MAX_PK_SIZE, &pklen)==-1) 
       return -1; 
    // Read signature from file. 
    if (read_file(argv[3], sm, MAX_SIG_SIZE, &smlen)==-1) 
       return -1;
    printf("Successful.\n");

    // Verify signature in-place.
#ifdef TEST_MSG_RECOVERY
        // Store the signed message to check message recovery below.
        memcpy(mout, sm, MAX_MSG_SIZE);
#endif
#ifndef TEST_MSG_RECOVERY
    if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
        printf("In-place verification failed!\n");
    }
    else {
        printf("In-place verification succeeded.\n");
    }
#endif

#ifdef TEST_MSG_RECOVERY
    /* Restore the signed message */
    memcpy(sm, mout, MAX_MSG_SIZE);
    // And verify again the signature and recover the message.
    if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
       printf("Verification failed!\n");
    }
    else {
       printf("Verification succeeded. \n");
       if (memcmp(m, mout, MAX_MSG_SIZE)) 
          printf("   But output message retrieved from signature incorrectly! \n");
       else 
          printf("   And output message retrieved from signature correctly. \n");
    }
#endif

#ifdef TEST_MSG_RECOVERY
    free(mout);
#endif

    return 0;
}
