## SPHINCS+ [![Build Status](https://travis-ci.org/sphincs/sphincsplus.svg?branch=master)](https://travis-ci.org/sphincs/sphincsplus)

This repository is a fork of the [SPHINCS+ repository](https://github.com/sphincs/sphincsplus). It is a slimmed down version of SPHINCS+ with custom parameters for security levels of 192 and 256-bits. It only uses the 'simple' SHA256 versions of SPHINCS+. The slim verifier links to OpenSSL and uses its SHA256 impelementation. 

The parameters are in the ref/params folder and symbolic link is used from there in the ref diretory pointing to the right parameters file. 

It includes testing code with a seperate signer and verifier that use three files to store the message the public key and the signature.

To build and run the separate signer and verifier you can run `make sig-ver` in the `ref` directory. To run the signer and verifier separately you can use `make test/spx_sig-to-file.exec` and `make test/spx_slim-ver-from-file.exec` in the `ref` directory. The slim verifier links to OpenSSL's SHA256 implementation. To run the slim verifier that includes its own SHA256 implementation (same API as OpenSSL but not linked to OpenSSL) use `make test/spx_ver-from-file.exec`. To run the bloated verifier that includes all code and djb's SHA256 implementation run `make test/spx_bloated-ver-from-file.exec`.

A new shell script called `sw_sig_bench.sh` runs the benchmark `make benchmark` in the `ref` and `sha256-avx2` directories for the parameters in the `ref/params.h` file. The benchmark in `ref` uses OpenSSL's SHA256 implementation that includes ASM optimizations and performs better for verification. If OpenSSL is not present, then tweak the `Makefile` to use `-DUSE_OPENSSL_API_SHA256` for a SHA256 implementation with the same API as OpenSSL or do not use any definitions in order to use djb's SHA256 implementation. The benchmark in `sha256-avx2` is optimized and uses paralellization. It performs better for key generation and signing.  

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication. 
