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

#.py.c:	;	pepy -o $@	$*.py

PEPYPATH = ../isode

#INCL      = $(DD)../include
#ISODEINCL = $(DD)../include/isode
#IFLAGS    = -I$(INCL) -I$(ISODEINCL)

OBJS    =       AF.o IF_types.o af_init.o strong_init.o af_ed.o \
                CADB.o af_cadb.o cadb_ed.o \
		af_crypt.o af_util.o af_pse.o \
                af_dir.o af_dirop.o af_sntx.o if_init.o \
		STRONG.o secude_int.o strong_util.o strong_ed.o strong_print.o strong_free.o

all: $(LIBSECUDE)

af_crypt.o: af_crypt.c
	$(CC) af_crypt.c -c $(CFLAGS) $(DTIME)

af_dir.o:	af_dir.c
	$(CC) af_dir.c -c $(CFLAGS) -DPEPYPATH

af_sntx.o:	af_sntx.c
	$(CC) af_sntx.c -c $(CFLAGS) -DPEPYPATH

af_cadb.o:	af_cadb.c
	$(CC) af_cadb.c -c $(CFLAGS) $(DBMVERS) 

# Strong Authentication
secude_int.o:	secude_int.c
	$(CC) secude_int.c -c $(CFLAGS) -DPEPYPATH

strong_util.o:	strong_util.c
	$(CC) strong_util.c -c $(CFLAGS) -DPEPYPATH
