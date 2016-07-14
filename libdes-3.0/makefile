# Turn this option on if using a SGI Iris running IRIX.
# IRIX does not appear to define sgttyb anywhere :-(
#OPTS0= -D_IRIX 

# Version 1.94 has changed the strings_to_key function so that it is
# now compatible with MITs when the string is longer than 8 characters.
# If you wish to keep the old version, uncomment the following line.
# This will affect the -E/-D options on des(1).
#OPTS1= -DOLD_STR_TO_KEY

# This #define specifies the use of an alternative D_ENCRYPT macro in
# ecb_encrypt.  The choice of macro can make a %20 difference in the
# speed.  Unfortunatly the choise of the best macro appears to be very
# dependant on the compiler and the machine in question.
# For the following combinations use the ALT_ECB option.
# Sparc 2 (cc -O4), sun 3/260 (cc -O4)
# For the following combinations do not use the ALT_ECB option.
# Sparc 2 (gcc2 -O2), sun 3/260 (cc -O2), mvax2 (cc -O), MSDOS (Turbo Cv2)
# For other machines, experiment with changing the option and run
# ./speed to see which is faster.
# DO NOT TURN THIS OPTION ON WHEN COMPILING THIS CODE ON A 64 BIT MACHINE
#OPTS2= -DALT_ECB

OPTS= $(OPTS0) $(OPTS1) $(OPTS2)
#CC=cc
#CFLAGS= -g $(OPTS)
CC=gcc
CFLAGS= -O2 $(OPTS)

LIBDIR=/usr/local/lib
BINDIR=/usr/local/bin
INCDIR=/usr/include
MANDIR=/usr/local/man
MAN1=1
MAN3=3
SHELL=/bin/sh

OBJS=	cbc_cksm.o cbc_enc.o ecb_enc.o pcbc_enc.o \
	qud_cksm.o rand_key.o read_pwd.o set_key.o str2key.o \
	enc_read.o enc_writ.o fcrypt.o cfb_enc.o \
	3ecb_enc.o ofb_enc.o 3cbc_enc.o

GENERAL=ARTISTIC COPYING FILES INSTALL Imakefile README VERSION makefile times \
	vms.com KERBEROS MODES.DES CHANGES
DES=	des.c des.man
TESTING=destest.c speed.c rpw.c
LIBDES=	des_crypt.man des.h cbc_cksm.c cbc_enc.c ecb_enc.c \
	enc_read.c enc_writ.c pcbc_enc.c qud_cksm.c rand_key.c \
	read_pwd.c set_key.c str2key.c fcrypt.c des_locl.h \
	podd.h sk.h spr.h cfb_enc.c 3ecb_enc.c \
	ofb_enc.c 3cbc_enc.c

PERL=	des.pl testdes.pl doIP doPC1 doPC2 PC1 PC2 shifts.pl

ALL=	$(GENERAL) $(DES) $(TESTING) $(LIBDES) $(PERL)

LIB=	libdes.a

all: $(LIB) destest rpw des speed

$(LIB):	$(OBJS)
	/bin/rm -f $(LIB)
	ar cr $(LIB) $(OBJS)
	-if test -s /bin/ranlib; then /bin/ranlib $(LIB); \
	else if test -s /usr/bin/ranlib; then /usr/bin/ranlib $(LIB); \
	else exit 0; fi; fi

destest: destest.o libdes.a
	$(CC) $(CFLAGS) -o destest destest.o libdes.a

rpw: rpw.o libdes.a
	$(CC) $(CFLAGS) -o rpw rpw.o libdes.a

speed: speed.o libdes.a
	$(CC) $(CFLAGS) -o speed speed.o libdes.a

des: des.o libdes.a
	$(CC) $(CFLAGS) -o des des.o libdes.a

tar:
	tar cf libdes.tar $(ALL)

shar:
	shar $(ALL) >libdes.shar

clean:
	/bin/rm -f *.o rpw destest des speed $(LIB)

install: $(LIB) des
	cp $(LIB) $(LIBDIR)/$(LIB)
	-if test -s /bin/ranlib; then /bin/ranlib $(LIBDIR)/$(LIB); \
	else if test -s /usr/bin/ranlib; then /usr/bin/ranlib $(LIBDIR)/$(LIB); \
	fi; fi
	chmod 644 $(LIBDIR)/$(LIB)
	cp des $(BINDIR)/des
	chmod 711 $(BINDIR)/des
	cp des_crypt.man $(MANDIR)/man$(MAN3)/des_crypt.$(MAN3)
	chmod 644 $(MANDIR)/man$(MAN3)/des_crypt.$(MAN3)
	cp des.man $(MANDIR)/man$(MAN1)/des.$(MAN1)
	chmod 644 $(MANDIR)/man$(MAN1)/des.$(MAN1)
	cp des.h $(INCDIR)/des.h
	chmod 644 $(INCDIR)/des.h
# DO NOT DELETE THIS LINE -- make depend depends on it.
