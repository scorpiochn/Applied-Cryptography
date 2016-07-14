OBJS    =       sha.o sha_if.o
PGM     =       shadriver

DD      = ../

DAFDB =


all:            $(LIBSECUDE)

shadriver:       shadriver.o sha.o
	        $(CC) $(LFLAGS) -o $@ shadriver.o sha.o
shadriver.o:	shadriver.c
	        $(CC) shadriver.c -c $(CFLAGS) 

shadriver.o:    sha.h shadriver.c

sha.o:          sha.h sha.c

trace:	; make "OPT=$(OPT) -DTRACE"
 
