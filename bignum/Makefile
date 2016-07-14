CC	= cc
#CFLAGS	= -g -Wid-clash-6
CFLAGS	= -O


default: bignum.o

all:	bignum.o bigtest pi

bigtest: bigtest.o bignum.o
	$(CC) -o bigtest bigtest.o bignum.o

bigtest.o: bigtest.c bignum.h internal.h Makefile
	$(CC) $(CFLAGS) -c bigtest.c

pi:	pi.o bignum.o
	$(CC) -o pi pi.o bignum.o

pi.o:	pi.c bignum.h internal.h
	$(CC) $(CFLAGS) -c pi.c

bignum.o: bignum.c bignum.h internal.h
	$(CC) $(CFLAGS) -c bignum.c

internal.h: mkhdr
	mkhdr


# If your compiler can't handle long identifiers (> 6 chars), move the `#' to
# the other line.

mkhdr: mkhdr.c Makefile
#	$(CC) $(CFLAGS) -DBIG_SHORT_NAMES -o mkhdr mkhdr.c
	$(CC) $(CFLAGS) -o mkhdr mkhdr.c

clean:
	/bin/rm -f mkhdr bigtest pi *.o
