CC=cc
LDFLAGS=-g -Llibdir 
CFLAGS=-g -O -Ilibdir  -I../lib
LIBS=
ELIBS=-ldes -lhut
OBJS=des-certify.o des.o des-ktest.o test-crypt.o test-crypt2.o des-probe.o random-key.o
PROGS=des-certify des des-ktest test-crypt test-crypt2 des-probe random-key
all:	$(PROGS)
des-certify:	des-certify.o $(LIBS)
	$(CC) $(LDFLAGS) -o des-certify des-certify.o $(LIBS) $(ELIBS)
des:	des.o $(LIBS)
	$(CC) $(LDFLAGS) -o des des.o $(LIBS) $(ELIBS)
des-ktest:	des-ktest.o $(LIBS)
	$(CC) $(LDFLAGS) -o des-ktest des-ktest.o $(LIBS) $(ELIBS)
test-crypt:	test-crypt.o $(LIBS)
	$(CC) $(LDFLAGS) -o test-crypt test-crypt.o $(LIBS) $(ELIBS)
test-crypt2:	test-crypt2.o $(LIBS)
	$(CC) $(LDFLAGS) -o test-crypt2 test-crypt2.o $(LIBS) $(ELIBS)
des-probe:	des-probe.o $(LIBS)
	$(CC) $(LDFLAGS) -o des-probe des-probe.o $(LIBS) $(ELIBS)
random-key:	random-key.o $(LIBS)
	$(CC) $(LDFLAGS) -o random-key random-key.o $(LIBS) $(ELIBS)
clean::
	rm -f $(PROGS) $(OBJS)
