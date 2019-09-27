CC = /usr/bin/gcc
CFLAGS = -Wall -Os -march=native -fomit-frame-pointer -flto

SOURCES = randombytes.c address.c wots.c utils.c fors.c sign.c hash_sha256.c thash_sha256_simple.c sha256.c
HEADERS = randombytes.h params.h address.h wots.h utils.h fors.h api.h hash.h thash.h sha256.h

TESTS = test/wots \
	test/fors \
	test/spx \

.PHONY: clean test benchmark test/benchmark.exec2 sig-ver test/spx_sig-to-file.exec test/spx_slim-ver-from-file.exec test/spx_ver-from-file.exec test/spx_bloated-ver-from-file.exec 

default: benchmark

all: test benchmark 

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmark: test/benchmark.exec2

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<

test/benchmark.exec2: test/benchmarkwopenssl 
	@$<

test/benchmarkwopenssl: test/benchmark.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -DUSE_OPENSSL_SHA256 -lcrypto -lm $< $(LDLIBS)

SIG_FILES = test/spx_msg~ test/spx_pk~ test/spx_sig~ 

test/spx_sig-to-file.exec: test/spx_sig-to-file
	touch ${SIG_FILES}
	@$< ${SIG_FILES} 

test/spx_slim-ver-from-file: test/spx_slim-ver-from-file.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DBUILD_SLIM_VERIFIER -DUSE_OPENSSL_SHA256 -o $@ $(SOURCES) -lcrypto $< $(LDLIBS) 

test/spx_slim-ver-from-file.exec: test/spx_slim-ver-from-file
	@$< ${SIG_FILES} 

sig-ver: test/spx_sig-to-file.exec test/spx_slim-ver-from-file.exec 

test/spx_ver-from-file: test/spx_slim-ver-from-file.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DBUILD_SLIM_VERIFIER -DUSE_OPENSSL_API_SHA256 -o test/spx_ver-from-file $(SOURCES) $< $(LDLIBS) 

test/spx_ver-from-file.exec: test/spx_ver-from-file
	@$< ${SIG_FILES} 

test/spx_bloated-ver-from-file: test/spx_slim-ver-from-file.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o test/spx_bloated-ver-from-file $(SOURCES) $< $(LDLIBS) 

test/spx_bloated-ver-from-file.exec: test/spx_bloated-ver-from-file 
	@$< ${SIG_FILES} 

clean:
	-$(RM) $(TESTS)
	-$(RM) test/benchmark test/benchmarkwopenssl
	-$(RM) test/spx_sig-to-file test/spx_*-from-file ${SIG_FILES} 

