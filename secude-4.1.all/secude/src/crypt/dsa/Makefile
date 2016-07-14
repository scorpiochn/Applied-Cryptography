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

OBJS    = dsablock.o dsa.o dsagen.o dsamoduli.o
DAFDB =
DD      = ../
DFLAGS  = -DWLNG32 -DPAD  # -DTEST

all: $(LIBSECUDE)

trace:	; ./make "OPT=$(OPT) -DTRACE"

dsablock.o:     dsa.h dsablock.c
dsa.o:          dsa.h dsa.c
dsagen.o:       dsa.h dsagen.c
dsamoduli.o:   dsa.h dsamoduli.c

