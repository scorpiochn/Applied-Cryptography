#
#  SecuDE Release 4.1 (GMD)
#
#
#    Copyright (C) 1993, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#


.c.o:;		$(CC) $*.c -c $(CFLAGS)

.c.ln:;		$(LINT) $(LINTFLAGS) $*.c

all:  $(LIBSECUDE)

inst-all: all

lib: $(OBJS)
	ar $(ARFLAGS) $(LIBSECUDE) $(OBJS)

$(LIBSECUDE): $(OBJS)
	ar $(ARFLAGS) $@ $?

clean:
	rm -f *.o *.bak *% core $(PGM)
