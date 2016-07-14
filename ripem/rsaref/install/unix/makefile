# This is a makefile for UNIX

# extension for object files
O = o

# commands
CC = cc
LIB = ar
ASM = masm

# name of temporary library script
TEMPFILE = $(TEMP)\temp.mak

# standard include directory
STDINCDIR=/usr/include

# The places to look for include files (in order).
INCL =  -I. -I$(SRCDIR) -I$(STDINCDIR)

# name of main executable to build
PROG = rdemo

# Normal C flags.
CFLAGS = $(INCL) -O -c -DPROTOTYPES=0
MFLAGS = -I. -I$(SRCDIR)

# The location of the common source directory.
SRCDIR = ../source/
SRCLIB = rsaref.a

# The location of the demo source directory.
RDEMODIR = ../rdemo/

rdemo : rdemo.$(O) $(SRCLIB)
	cc -o $@ rdemo.$(O) $(SRCLIB)

$(SRCLIB) : desc.$(O) digit.$(O) md2c.$(O) md5c.$(O) nn.$(O) prime.$(O)\
  rsa.$(O) r_encode.$(O) r_enhanc.$(O) r_keygen.$(O) r_random.$(O)\
  r_stdlib.$(O)
	$(LIB) r $@ $?
	ranlib $@

rdemo.$(O) : $(RDEMODIR)rdemo.c global.h $(SRCDIR)rsaref.h
	$(CC) $(CFLAGS) $(RDEMODIR)rdemo.c

include $(SRCDIR)targets.mak
