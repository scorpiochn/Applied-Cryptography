#
#    Copyright (C) 1991, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

OBJS = add.o sub.o mult.o div.o shift.o
 
DD     = ../../
DFLAGS = -DWLNG32       # Wortlaenge  32
IFLAGS = -I.. -I$(INCL)
 
arintf.o: $(OBJS)
	${LD}	${LDFLAGS} -r ${OBJS}	-o ../arintf.o


add.o: add.asm
	asm add.asm
	mv add.bin add.o

sub.o: sub.asm
	asm sub.asm
	mv sub.bin sub.o

mult.o: mult.asm
	asm mult.asm
	mv mult.bin mult.o

div.o: div.asm
	asm div.asm
	mv div.bin div.o

shift.o: shift.asm
	asm shift.asm
	mv shift.bin shift.o
