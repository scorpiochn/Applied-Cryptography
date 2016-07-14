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

ASMOBJS =  add.o sub.o cadd.o mult.o div.o dmult.o shift.o
OBJS    =  arintf.o
 
INCL=	../
 
DD     = ../../
DFLAGS  = -DWLNG32 $(ENDIAN)      # Wortlaenge  32
IFLAGS = -I.. -I$(INCL)

all: $(LIBSECUDE)
 
arintf.o: $(ASMOBJS)
	${LD} ${LDFLAGS} -r ${ASMOBJS} -o arintf.o

 
LINCL=	../arithmetic.h
 

add.o:   $(LINCL)  add.c
sub.o:   $(LINCL)  sub.c
div.o:   $(LINCL)  div.c
mult.o:  $(LINCL)  mult.c
shift.o: $(LINCL)  shift.c
dmult.o: dmult.c

