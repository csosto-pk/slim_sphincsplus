AR = /usr/bin/ar
CC = /usr/bin/gcc
CFLAGS = -Wall -Os

test: test.c verify.c hash.c adr.c endian.c wots.c tune.h
	$(CC) $(CFLAGS) -o test test.c verify.c hash.c adr.c endian.c wots.c -lcrypto
