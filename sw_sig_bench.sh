#/usr/bin/sh 

# Run as ./sw_sig_bench.sh sw_sig_bench.results 

cd ref

rm params.h 
ln -s params/params-sphincs-sha256-192-h15-w16.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-192-h15-w256.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-192-h20-w16.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-192-h20-w256.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-192-h35-w16.h params.h 
make clean
make benchmark

rm params.h
ln -s params/params-sphincs-sha256-192-h35-w256.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h15-w16.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h15-w256.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h20-w16.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h20-w256.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h35-w16.h params.h 
make clean
make benchmark

rm params.h 
ln -s params/params-sphincs-sha256-256-h35-w256.h params.h 
make clean
make benchmark

cd test 
