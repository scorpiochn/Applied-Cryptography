#
#    Copyright (C) 1991, GMD Darmstadt
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

DD     = ../../

.SUFFIXES:	.m .s .o

.m.s:	;	m4	$< >$@

all: $(LIBSECUDE)

arintf.o:  ${ASMOBJS}
	${LD} -r ${LDFLAGS} ${ASMOBJS} -o arintf.o

add.o: add.s
	$(CC) add.s $(CFLAGS) -c

mult.o: mult.s
	$(CC) mult.s $(CFLAGS) -c

div.o: div.s
	$(CC) div.s -w $(CFLAGS) -c

shift.o: shift.s
	$(CC) shift.s $(CFLAGS) -c
