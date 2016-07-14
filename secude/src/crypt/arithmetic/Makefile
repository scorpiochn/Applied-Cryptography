#
#  SecuDE Release 4.1 (GMD)
#
#
#    Copyright (C) 1991, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

#
# Makefile:     arithmetic for long numbers
#

OBJS =  lnutil.o \
	bool.o  \
	modarit.o \
        comp.o \
	genprime.o random.o primes.o
#       trace.o

DD      = ../
DFLAGS  = -DWLNG32 $(ENDIAN)      # Wortlaenge  32
 
LINCL   = arithmetic.h
 
all: $(LIBSECUDE)
	cd $(ARCH); ./make

$(LIBSECUDE): $(OBJS)
	ar $(ARFLAGS) $@ $?

lib: $(OBJS)
	ar $(ARFLAGS) $(LIBSECUDE) $(OBJS)
	cd $(ARCH); ./make lib

clean:
	rm -f *.o *.bak *%
	cd $(ARCH); ./make clean

genprime.o:     ../rsa/rsa.h ../rsa/rsa_debug.h genprime.c
random.o:       ../rsa/rsa.h ../rsa/rsa_debug.h random.c
primes.o:       primes.h
lnutil.o:  lnutil.c
modarit.o: modarit.c
bool.o:    bool.c
comp.o:    comp.c
trace.o:   trace.c

trace:	trace.o
	./make	"CC=$(CC)" "OPT=$(OPT) -DTRACE"
