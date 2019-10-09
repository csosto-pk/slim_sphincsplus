#/usr/bin/sh 

# Run as ./sw_sig_bench.sh > sw_sig_bench.results 
# We run it twice, once from the ref directory and once from the sha256-avx2 
# directory. We do that because we found that the the sha256-avx2 code 
# offers faster keygen and signing and the ref code runs faster verification 
# when using SHA256 from OpenSSL. 

echo ------------------
cd ref && rm params.h 
ln -s params/params-sphincs-sha256-192-h15-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-192-h15-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-192-h20-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-192-h20-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-192-h35-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h 
ln -s params/params-sphincs-sha256-192-h35-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h15-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h15-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h20-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h20-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h35-w16.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

rm params.h  
ln -s params/params-sphincs-sha256-256-h35-w256.h params.h 
make clean && make sig-ver && nm test/spx_slim-ver-from-file | sort | egrep "(frame_dummy|read_file)"
echo ------------------

