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

inst-all: all

clean:
	rm -f *% *.bak
	cd config; rm -f *% *.bak
	cd af; ./make clean
	cd secure; ./make clean
	cd aux; ./make clean
	cd crypt; make clean
	cd pem; ./make clean
	cd sca; ./make clean $(DSCA)
	cd isode; ./make clean $(DISODE)
	cd util; ./make clean
	cd sectool; ./make clean
	cd secxlock; ./make clean
	cd ../lib; rm -f lib* *.o *% *SYM*
	cd ../bin; rm -f *

all:
	cd af; ./make
	cd secure; ./make
	cd aux; ./make
	cd crypt; make
	cd pem; ./make
	cd sca; ./make all $(DSCA)
	cd isode; ./make all $(DISODE)
	cd ../lib; ./make $(LIBSECUDESO) $(LIBIMPORTS)
	cd util; ./make
	cd sectool; ./make
	cd secxlock; ./make

lib:
	cd af; ./make lib
	cd secure; ./make lib
	cd aux; ./make lib
	cd crypt; make lib
	cd pem; ./make lib
	cd sca; ./make lib $(DSCA)
	cd isode; ./make lib $(DISODE)
	cd ../lib; ./make $(LIBSECUDESO) $(LIBIMPORTS)


