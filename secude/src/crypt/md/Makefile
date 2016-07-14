OBJS    =       md4.o md4_if.o md2.o md2_if.o md5.o md5_if.o
PGM     =       mddriver
DAFDB =
DD      = ../

MD = 2
#MD = 4

all:            $(LIBSECUDE)

mddriver:       mddriver.o md2.o md4.o md5.o
	        $(CC) $(LFLAGS) -o $@ mddriver.o md2.o md4.o md5.o

#mddriver.o:	mddriver.c
#	        $(CC) mddriver.c -c $(CFLAGS) "-DMD=$(MD)"

mddriver.o:     global.h md2.h md4.h md5.h mddriver.c
	        $(CC) mddriver.c -c $(CFLAGS) "-DMD=$(MD)"

md2.o:          global.h md2.h md2.c
md4.o:          global.h md4.h md4.c
md5.o:          global.h md5.h md5.c

trace:	; make "OPT=$(OPT) -DTRACE"
