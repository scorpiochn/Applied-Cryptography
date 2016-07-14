#########################################################################
#                                                                       #
#  Projectname          :       STAPAC                                  #
#                                                                       #
#  Date                 :       November 1990                           #
#                                                                       #
#  Author               :       L. Eckstein                             #
#                                                                       #
#  Programmname         :       Makefile                                #
#				create libary Slibsm			#
#				The source files are compiled with the  #
#				option STREAM				#
#                                                                       #
#  Description          :       this makefile generates the             #
#                               - sctint.o                              #
#                               - sctloc.o                              #
#                               - sctmem.o                              #
#                               - sccom.o                               #
#				- sta_init.o				#
#				- sta_rand.o				#
#				- stadev.o				#
#				- stasc.o				#
#				- sta_r_w.o				#
#				- staauth.o				#
#				- stacrypt.o				#
#				- staprint.o				#
#				- sta_free.o				#
#				- sta_resp.o				#
#				- sta_xdmp.o				#
#									#
#                                                                       #
#  Important            :                                               #
#  Set Environment Varibale STAMOD:                                     #
#  under DOS     : set STAMOD=filename      (../install/ustamod.gen)    #
#  under C-SHELL : setenv STAMOD filename                               #
#  Length of Filename : max 40 characters.                              #
#                                                                       #
#                                                                       #
#  DFLAGS = MEM  STREAM SYSTEM  MEMTRACE (for sctint.c)                 #
#      MEM    = MALLOC   : must be always set                           #
#									#
#      STREAM =      : if not set => no TRACE of SCT-APDU               #
#                      if set     => Trace of SCT-APDU's in file        #
#                                    SCTINT.TRC                         #
#      SYSTEM =								#
#           DOS      : if set     => compute baudrate for DOS           #
#           BSD      : if set     => compute baudrate for Berkley       #
#           SYSTEMV  : if set     => compute baudrate for System V      #
#									#
#      MEMTRACE =    : if not set => no TRACE of element                #
#                      if set     => Trace of element    in file        #
#                                    SCTINT.TRC                         #
#				     (only allowed, if STREAM set )     #
#  DFLAGS = MEM  STREAM SYSTEM      (for sctloc.c)                      #
#      MEM    = MALLOC   : must be always set                           #
#									#
#      STREAM =      : if not set => no TRACE of SCT-APDU               #
#                      if set     => Trace of SCT-APDU's in file        #
#                                    SCTINT.TRC                         #
#      SYSTEM =								#
#           DOS      : if set     => Systemcall TIME will be used       #
#                      if not set => Systemcall SLEEP will be used      #
#                                                                       #
#                                                                       #
#  DFLAGS = MEM  TRACE  SYSTEM     (for sctmem.c)                       #
#      MEM    = MALLOC   : must be always set                           #
#									#
#      TRACE  =      : if not set => no trace of memory-element         #
#                      if set     => Trace of memory-element on terminal#
#      SYSTEM =								#
#           DOS      : if set     => compute baudrate for DOS           #
#           BSD      : if set     => compute baudrate for Berkley       #
#           SYSTEMV  : if set     => compute baudrate for System V      #
#                                                                       #
#                                                                       #
#  DFLAGS = MEM STREAM              (for sccom.c )                      #
#      MEM    = MALLOC   : must be always set                           #
#									#
#      STREAM =      : if not set => Trace of SC-APDU                   #
#                      if set     => Trace of SC-APDU's in file         #
#                                    SCCOM.TRC                          #
#                                                                       #
#                                                                       #
#                                                                       #
#                                                                       #
#  DFLAGS = VERSION10  RSA         (for stacrypt.c)                     #
#      VERSION10  =  : padding of hash-string and signature		#
#									#
#      RSA    =      							#
#          ASSEMBLER : if set, then sca_sign, sca_verify  and           #
#                      sca_hash are compiled => assembler routines are  #
#                      used for hash function sqmodn                    #	
#                                                                       #
#  DFLAGS = TEST               (for stadev.o stasc.o sta_r_w.o          #
#                                   staauth.o stacrypt.o staprint.o)    #
#      TEST =								#
#           TEST      : if set => test output                           #
#                                                                       #
#                                                                       #
#  DFLAGS = TRACE              (for sta_free.c)                         #
#           TRACE    : if not set => no TEST output                     #
#                      if set     => TEST output                        #
#########################################################################

MEM       =  MALLOC          # malloc is used
SYSTEM    =  BSD             # BSD ; DOS; SYSTEMV
RSA	  =  ASSEMBLER	     #   
VERSION10 =  VERSION10
TEST      =  # -DTEST            
STREAM    =  #-DSTREAM          # for test purpose
MEMTRACE  =  # -DMEMTRACE       
TRACE     =  #-DTRACE
PROCDAT   = -DPROCDAT
#DFLAGS    =
DSCA = 

SPECIALS    =  -D$(MEM)  -D$(SYSTEM)  -D$(RSA) -D$(VERSION10) $(PROCDAT) $(STREAM) $(TEST) $(MEMTRACE) $(TRACE)


OBJS       =  sctint.o sctloc.o sctmem.o \
              sccom.o \
	      sta_free.o sta_xdmp.o sta_resp.o \
              stadev.o \
              stasc.o sta_r_w.o staauth.o stacrypt.o staprint.o

DD         = ../

all: $(LIBSECUDE)

trace:	; make "OPT=$(OPT) -DTRACE"


