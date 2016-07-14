PROGS:=		des-certify des des-ktest test-crypt
ELIBS:=		-ldes -lhut
include Makerules

CFLAGS:=	$(CFLAGS) -I../lib

foobar: des-certify
	echo x $(CFLAGS)
