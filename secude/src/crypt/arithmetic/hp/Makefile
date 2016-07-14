#
#    Copyright (C) 1993, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

# Makefile to produce arintf.o Module 

ASMOBJS =	add.o mult.o div.o shift.o
OBJS    =       arintf.o

DAFDB =
AS = as +z
DD     = ../../

.SUFFIXES:	.m .s .o

.m.s:	;	/lib/cpp	$< >$@

all: $(LIBSECUDE)

arintf.o:  ${ASMOBJS}
	${LD} -r ${LDFLAGS} ${ASMOBJS} -o arintf.o

add.o: add.s
	$(AS) add.s 

mult.o: mult.s
	$(AS) mult.s 

div.o: div.s
	$(AS) div.s 

shift.o: shift.s
	$(AS) shift.s 

