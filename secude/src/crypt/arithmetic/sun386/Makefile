ASMOBJS = add.o sub.o mult.o div.o shift.o
OBJS = arintf.o
 
DD     = ../../
DFLAGS  = -DWLNG32       # Wortlaenge  32
IFLAGS = -I.. -I$(INCL)
 
arintf.o: $(ASMOBJS)
	${LD}	${LDFLAGS} -r ${ASMOBJS} -o arintf.o

add.o: add.s
sub.o: sub.s
mult.o: mult.s
div.o: div.s
shift.o: shift.s

