## SPHINCS+ [![Build Status](https://travis-ci.org/sphincs/sphincsplus.svg?branch=master)](https://travis-ci.org/sphincs/sphincsplus)

This repository is a fork of the [SPHINCS+ repository](https://github.com/sphincs/sphincsplus). It is a slimmed down version of SPHINCS+ with custom parameters for security levels of 192 and 256-bits. It only uses the 'simple' SHA256 versions of SPHINCS+. 

The parameters are in the ref/params folder and symbolic link is used from there in the ref diretory pointing to the right parameters file. 

It includes testing code with a seperate signer and verifier that use three files to store the message the public key and the signature.

To build and run the separate signer and verifier you can run `make test/sig-ver`.

To run the signer and verifier separately you can use `make test/spx_sig-to-file.exec` and `make test/spx_slim-ver-from-file.exec`. 

A new shell script called `sw_sig_bench.sh` runs the benchmark `ref/make benchmark` for the parameters we chose and produces results

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication, with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST.
