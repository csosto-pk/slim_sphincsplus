CC = /usr/bin/gcc
CFLAGS = -Wall -Os 

SOURCES = address.c randombytes.c wots.c utils.c fors.c sign.c hash_sha256.c thash_sha256_simple.c sha256.c
HEADERS = params.h address.h randombytes.h wots.h utils.h fors.h api.h hash.h thash.h sha256.h

TESTS = test/wots \
	test/fors \
	test/spx \

.PHONY: clean test benchmark sig-ver test/spx_slim-ver-from-file.exec test/spx_sig-to-file.exec

default: benchmark

all: tests benchmarks 

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmark: test/benchmark.exec 

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<



SIG_FILES = test/spx_msg~ test/spx_pk~ test/spx_sig~ 

test/spx_sig-to-file.exec: test/spx_sig-to-file
	touch ${SIG_FILES}
	@$< ${SIG_FILES} 

test/spx_slim-ver-from-file: test/spx_slim-ver-from-file.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o test/spx_bloated_ver-from-file $(SOURCES) $< $(LDLIBS) 
	$(CC) $(CFLAGS) -DBUILD_SLIM_VERIFIER -o test/spx_ver-from-file $(SOURCES) $< $(LDLIBS) 
	$(CC) $(CFLAGS) -DBUILD_SLIM_VERIFIER -DUSE_OPENSSL_SHA256 -o $@ $(SOURCES) -lcrypto $< $(LDLIBS) 

test/spx_slim-ver-from-file.exec: test/spx_slim-ver-from-file
	test/spx_bloated_ver-from-file ${SIG_FILES} 
	test/spx_ver-from-file ${SIG_FILES} 
	@$< ${SIG_FILES} 

test/sig-ver: test/spx_sig-to-file.exec test/spx_slim-ver-from-file.exec 

clean:
	-$(RM) $(TESTS)
	-$(RM) test/benchmark
	-$(RM) test/spx_sig-to-file test/spx_*-from-file ${SIG_FILES} 

