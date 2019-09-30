#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"

#define MAX_MSG_SIZE 32 // We only sign 256-bit hashes for image signing 
#define MAX_PK_SIZE 64 /* SPHINCS+ PK size for SPHINCS+ image 
			signing parameters can be 48 or 64 bytes. */
#define MAX_SIG_SIZE 20000 /* SPHINCS+ Signature size for SPHINCS+
			image signing parameters can't be > 25KB */
//#define TEST_MSG_RECOVERY // Only if we want to check the recovered 
			// is the same as the one stored in the file.
#define PRINT_STACK_SIZE_USED // If you also want to print the stack used. 

#ifdef PRINT_STACK_SIZE_USED
#define BIGGEST_STACK_SIZE_EXPECTED 20000
void clear_stack() {
    volatile unsigned char x[BIGGEST_STACK_SIZE_EXPECTED];
    int i;
    for (i=0; i<BIGGEST_STACK_SIZE_EXPECTED; i++) x[i]=0xfa;
    if (x[0]!=0) return; // Just to supprer compiler warning
    //memset((void*) x, 0xfa, sizeof x ); // Instead of the for loop above, but was not working
    //printf("Stack-%x-%x-%x\n",x[0],x[10000],x[19999]); //Only for troubleshooting
}

int get_stack() {
    volatile unsigned char x[BIGGEST_STACK_SIZE_EXPECTED];
    int i;
    for (i=0; i<BIGGEST_STACK_SIZE_EXPECTED; i++) {
        if (x[i] != 0xfa) break;
    }
    return BIGGEST_STACK_SIZE_EXPECTED-i;
}
#endif 

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

    static unsigned char pk[MAX_PK_SIZE]; // Statics so they don't count against the stack. 
    static unsigned char m[MAX_MSG_SIZE]; // Statics
    static unsigned char sm[MAX_SIG_SIZE]; // Statics
#ifdef TEST_MSG_RECOVERY
    static unsigned char *mout = malloc(MAX_SIG_SIZE); // Statics
#endif
    static unsigned long long smlen; // Statics
    static unsigned long long mlen; // Statics
    static unsigned long long pklen; // Statics 
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

#ifdef TEST_MSG_RECOVERY
    // Verify the signature and recover the message.
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
    free(mout);
#else
    // Verify signature in-place.
#ifdef PRINT_STACK_SIZE_USED
    clear_stack();
#endif // #ifdef PRINT_STACK_SIZE_USED
    if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
        printf("   In-place verification failed!\n");
    }
    else {
        printf("   In-place verification succeeded.\n");
    }
#ifdef PRINT_STACK_SIZE_USED
    int tmp = get_stack();
    printf( "Stack used = %d bytes\n", tmp);
#endif // #ifdef PRINT_STACK_SIZE_USED
#endif // #ifdef TEST_MSG_RECOVERY
    return 0;
}
