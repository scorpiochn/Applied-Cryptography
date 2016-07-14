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
#    Make shared libraries:

DD =
LIBISODESO = libisode.so.80.1
LIBDSAPSO = libdsap.so.80.1


all: $(LIBSECUDESO)

$(LIBSECUDESO): libsecude.a
	ranlib libsecude.a
	ar x libsecude.a
	ld -o $(LIBSECUDESO) $(SL_OPTIONS) *.o
	rm -f *.o *SYM*

$(LIBISODESO): libisode.a
	ar x libisode.a
	ld -o $(LIBISODESO) $(SL_OPTIONS) *.o
	rm -f *.o *SYM*

$(LIBDSAPSO): libdsap.a
	ar x libdsap.a
	ld -o $(LIBDSAPSO) $(SL_OPTIONS) *.o
	rm -f *.o *SYM*

clean:
	rm lib*
