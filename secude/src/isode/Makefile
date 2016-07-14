###############################################################################
#
# Revision 7.0  89/11/23  21:25:38  mrose
# Release 6.0
# 
###############################################################################

###############################################################################
#
#				 NOTICE
#
#    Acquisition, use, and distribution of this module and related
#    materials are subject to the restrictions of a license agreement.
#    Consult the Preface in the User's Manual for the full terms of
#    this agreement.
#
###############################################################################


###############################################################################
# Options
###############################################################################


#OPTIONS	=	-I. -I../include/isode


###############################################################################
# Programs and Libraries
###############################################################################

MAKE	=	./make DESTDIR=$(DESTDIR) $(MFLAGS) -k
SHELL	=	/bin/sh

###############################################################################
# Generation Rules for library modules
###############################################################################

.c.o:;		$(CC) $*.c $(CFLAGS) $(OPTIONS) -c 


OBJS    = UPEPY_01.o UPEPY_02.o UPEPY_07.o UPEPY_08.o UPEPY_25.o UPEPY_26.o \
          UPEPY-31.o UPEPY-32.o UPEPY_34.o UPEPY_35.o UPEPY_52.o asprintf.o bit2prim.o bit_ops.o \
          bitstr2strb.o chrcnv.o lexequ.o num2prim.o obj2prim.o oid_cpy.o \
          oid_free.o pe2pl.o pe2ps.o pe_alloc.o pe_cmp.o pe_cpy.o pe_error.o pe_free.o pepsy_str.o \
          pl_tables.o prim2bit.o prim2num.o prim2oid.o prim2set.o prim2str.o flag2prim.o ps2pe.o \
          ps_alloc.o ps_error.o ps_flush.o ps_free.o ps_get_abs.o ps_io.o ps_prime.o \
          py_advise.o qbuf2pe_f.o seq_add.o seq_addon.o serror.o set_add.o \
          set_addon.o sprintoid.o std2ps.o str2prim.o str2ps.o str2vec.o strb2bitstr.o

DAFDB =

all: $(LIBSECUDE)

