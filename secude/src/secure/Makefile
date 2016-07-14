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

#.SUFFIXES:	.py .c

#.py.c:	; pepy	-o $@	$*.py


#PEPYPATH=	../isode

DAFDB =
PROCDAT = -DPROCDAT

OBJS    =       sec_init.o secure.o sec_ed.o sec_rand.o SEC.o  \
                secsc_init.o secsc.o readconf.o               

all: $(LIBSECUDE)

sec_init.o: sec_init.c
	$(CC) -c sec_init.c $(CFLAGS) $(DVERSION)

secsc.o: secsc.c
	$(CC) -c secsc.c $(CFLAGS) $(PROCDAT)

readconf.o: readconf.c
	$(CC) -c readconf.c $(CFLAGS) $(DSCINIT)
