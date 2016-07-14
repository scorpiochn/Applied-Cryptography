#
#    Copyright (C) 1991, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

OBJS = add.o sub.o cadd.o mult.o div.o shift.o
 
DD     = ../../
DFLAGS  = -DWLNG32       # Wortlaenge  32
IFLAGS = -I.. -I$(INCL)

arintf.o: $(OBJS)
	${LD} ${LDFLAGS} -r ${OBJS}	-o ../arintf.o	

# notice: there is a bug in sub.c. this is a workaround to use the
# std/sub.c module, which needs std/cadd.c as well.
sub.o: sub.c
cadd.o: cadd.c
# notice end
add.o: add.s
mult.o: mult.s
div.o: div.s
shift.o: shift.s
