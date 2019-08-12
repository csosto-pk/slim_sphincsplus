#ifndef SPX_RANDOMBYTES_H
#define SPX_RANDOMBYTES_H

#ifndef BUILD_SLIM_VERIFIER // Don't use in verifier to keep it slim
extern void randombytes(unsigned char * x,unsigned long long xlen);
#endif

#endif
