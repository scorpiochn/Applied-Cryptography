#
#  SecuDE Release 4.1 (GMD)
#
OBJS = des_if.o des.o
PGM  = descert certify
DAFDB =

DD      = ../

all: $(LIBSECUDE)

des: main.o des.o misc.o
	$(LD) -o des main.o des.o misc.o

benchmark: benchmark.o des.o
	$(LD) -o benchmark benchmark.o des.o

radlogin: radlogin.o des.o
	$(LD) -o radlogin radlogin.o des.o

descert: descert.o des.o
	$(LD) -o descert descert.o des.o

descalc: descalc.o des.o
	$(LD) -o descalc descalc.o des.o

descycle: descycle.o des.o
	$(LD) -o descycle descycle.o des.o

certify: descert testdata
	descert < testdata
	touch certify

des.o: des.c
	${CC} -c $(CFLAGS) $(ENDIAN)  des.c

radlogin.o: radlogin.c
	${CC} -c -O -DUTMP_FILE=\"/etc/utmp\" radlogin.c

uuencode: uuencode.o
	$(LD) -o uuencode uuencode.o

uudecode: uudecode.o
	$(LD) -o uudecode uudecode.o

dummy: dummy.o
	$(LD) -o dummy dummy.o

