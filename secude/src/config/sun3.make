#
#  SecuDE Release 4.1 (GMD)
#
#
#    Copyright GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

#
#    Template of CONFIG.make for SUN/4 SunOS 4.1
#

# ARCH selects rsa-long arithmetic assembler routines
# Possible values:
# Possible values:
# mc68apollo:   Apollo MC680x0 assembler
# mc68sun:      Sun MC680x0 assembler
# mc68munix:    PCS Munix V3 assembler
# sparc:        SUN SPARC assembler
# std:          C-routines 
# sun386:       Sun 386i assembler
# ms-dos:       MS-DOS assembler
ARCH        = mc68sun

#ENDIAN      = -DLITTLE_ENDIAN  # for LITTLE_ENDIAN architecture (e.g. Intel)


DBMVERS     = -DNDBM       # if ndbm database functions are available

# Check TOP !!:
TOP         = /usr/local/secude  # Path of the top-level-directory of secude-4.0

# Check LDL!!:  Library path. See also ISODE-support below
LDL         = -L$(TOP)/lib

# Check location of .af-db (which is also the local substitute for X.500 Dir)
AFDBFILE    = $(TOP)/.af-db/

CC          = cc
LD          = ld
OPT         = -g
DD          =
FLOAT       = # -f68881
INCL        = $(DD)../include
INCLISODE   = $(DD)../include/isode
DFLAGS      = $(DX500) $(DSTRONG) $(DSCA) $(DCOSINE) $(DAFDB) $(DTEST) $(SPECIALS)
IFLAGS      = -I$(INCL) -I$(INCLISODE) $(ISCA)
AFLAGS      = -g
#AFLAGS      = -s -x
CFLAGS	    = -pic $(OPT) $(DFLAGS) $(IFLAGS) $(FLOAT)
LFLAGS      = $(AFLAGS) $(LDL)
ARFLAGS     = ruv
BINDIR      = $(DD)../../bin

LIBDIR      = $(DD)../../lib
LIBSECUDE   = $(LIBDIR)/libsecude.a
LSECUDE     = -lsecude
LM          = -lm
LDBM        =


#---------Smartcard Support---------------------------------------------
#
# Set DSCA to -DSCA and ISCA, SCINITFILE and DSCINIT to the indicated 
# values for the use of the GMD/GAO SmartCard Application Package STARCOS 
# and the interface software contained in subdirectory sca:
#
DSCA        = -DSCA
ISCA        = -I$(DD)../include/sca

# default SC configuration file
SCINITFILE  = $(TOP)/.scinit
DSCINIT     = -DSCINIT=\"${SCINITFILE}\"
SYSTEM      = SUN  # This is for the sca/t1 subdirectory only. 
#
# If you want to use software PSEs only, DSCA and LIBSCA must be empty.
# No additional software and hardware is required in this case,
# and the sca subdirectory is not made.
#-----------------------------------------------------------------------

#---------ISODE-Support-------------------------------------------------
#
# SecuDE needs two subsets of ISODE subroutines:
#  
# 1. Subroutines necessary for the SecuDE ASN.1 encoding/decoding 
#    functions, 
# 2. Subroutines necessary for the SecuDE X.500 DUA functionality 
#    required for security related attributes.
#
# If you have already an ISODE-8.0 installation on your system, you
# can use its libisode.a and libdsap.a libraries when binding SecuDE
# utilities.
#
# For the case that you have no ISODE-8.0 installation on your system,
# SecuDE contains a subset of ISODE-8.0 sources in its src/isode sub-
# directory which comprises the first subset. With this subset it is 
# possible to install all SecuDE functions except the use of X.500 
# directories (see below) without complete ISODE-8.0 installation.
#
# Set DISODE to -DSECISODE and unset LISODE if you have no ISODE-8.0 
# installation on your system; the SecuDE-subdirectory isode is made in 
# this case, and the corresponding functions are put into libsecude.a.
#
# If DISODE is not set and LISODE is set instead, the SecuDE subdirectory
# isode is not made, and the libraries of your ISODE installation must 
# be included, instead. Add the library path (where the ISODE libraries 
# can be found) to LDL above.
#
LISODE      = -lisode
#DISODE   = -DSECISODE
#
#-----------------------------------------------------------------------

#---------X.500-Support-------------------------------------------------
# 
# Obtaining public keys and certificates from other persons is normally
# done by X.500 directory access. This is provided by SecuDE, but
# requires a full ISODE-8.0/QUIPU installation on your system, i.e.
# the ISODE library libdsap.a is necessary.
# In this mode, utilities like psemaint, pkadd and revoke, for instance,
# interwork with an X.500 directory via X.500 DAP (Directory Access
# protocol). The X.500 directory is accessible via the af_dir_enter_* 
# and af_dir_retrieve_* functions (for instance af_dir_enter_Certificate(),
# af_dir_retrieve_Certificate()).
#
# As an alternative, SecuDE provides a local directory for that purpose.
# The local substitute is realized with ndbm in the Unix-directory .af-db,
# which can be placed anywhere in the Unix file system. It's pathname must
# be given to the programs through variable AFDBFILE in config/CONFIG.make.
# This local directory is accessible via corresponding af_afdb_enter_* and
# af_afdb_retrieve_* functions (for instance af_afdb_enter_Certificate(),
# af_afdb_retrieve_Certificate()), but no X.500 DAP is used.
#
# The decision whether an X.500 directory or the local substitute is used 
# is done either at compile time through variables DX500, LX500 and DAFDB
# in config/CONFIG.make (DX500 and LX500 must be defined for the case of the 
# X.500 directory, DAFDB must be set to the pathname of the .af-db directory
# in case of the local substitute), or at run time (which makes only sense
# if both types of directories are generated at compile time, i.e. if all
# DX500, LX500 and DAFDB are defined).
#
# If both directory types are generated at compile time, public security
# information is always stored in the local substitute. If the file
# ${AFDBFILE}/X500 exists, such information is additionally stored in
# the X.500 directory. When retrieving information from a directory,
# the X.500 directory is used if ${AFDBFILE}/X500 exists, the local
# substitute is used otherwise.
#
# If X.500 is being used, DSTRONG can be used to indicate that directory
# access via DAP is done using strong authentication and signed operations.
# This requires, however, an enhanced QUIPU version (available from GMD).
# If only the standard ISODE-8.0/QUIPU version is available, DSTRONG
# must not be set.
#
#######################################################################
# Use of a local (ndbm) database for storing and retrieving 
# public certificates (does not require ISODE-8.0 QUIPU):
#
DAFDB     = -DAFDBFILE=\"${AFDBFILE}\"
#######################################################################
# Use of X.500 directories for storing and retrieving public 
# certificates (requires ISODE-8.0 QUIPU installation):
#
DX500     = -DX500
LX500   = -ldsap
LISODE  = -lisode  # if DX500 is set, you need LISODE, too
#DSTRONG = -DSTRONG
#######################################################################
#-----------------------------------------------------------------------

#--------- Shared Libraries --------------------------------------------
# If you want to produce libsecude.a as shared library, set LIBSECUDESO
# to libsecude.so.41.1. Version number 41 indicates SecuDE 4.1.
# Otherwise, set LIBSECUDESO to static.
#
LIBSECUDESO = static
#LIBSECUDESO  = libsecude.so.41.1
SL_OPTIONS = -assert pure-text
#
#-----------------------------------------------------------------------

#----------- Imported .o files -----------------------------------------
# If you have imported .o files in lib/IMPORTS, set LIBIMPORTS to yes.
# Otherwise, comment it out.
#LIBIMPORTS = yes
#
#-----------------------------------------------------------------------

# COSINE extensions !!!
#DCOSINE      = -DCOSINE
#

#DTEST        = -DTEST

LIB = $(LSECUDE) $(LX500) $(LISODE) $(LDBM) $(LM)
