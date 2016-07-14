CC=cc
CFLAGS=-O -Ilibdir 
LIBNAME=libdes.a
O_FILES=cbc-cksum.o cbc-encrypt.o des-bitrev.o des-data.o des-expand.o des-fun.o des-hash.o des-hex.o des-perms.o des-reverse.o des-sun-key.o ecb-encrypt.o ksched-fast.o ksched.o new-crypt.o pcbc-encrypt.o str-to-key.o sun-cbc-crypt.o sun-ecb-crypt.o sun-setpar.o

all:	$(LIBNAME)

$(LIBNAME): $(O_FILES)
	ar ru $(LIBNAME) $?
	ranlib $(LIBNAME)

clean::
	rm -f $(LIBNAME) $(O_FILES)
