# This is a makefile for UNIX for the RSAREF crypto toolkit library.
#
# If you need to change anything, most likely it'll be:
#
#   CC, which should probably be cc, gcc, acc, or (for AIX) xlc.
#   CFLAGS, which may need -O or -O3 (for instance).
#           RSAREF does benefit from optimization, so it's worth it to get
#           the optimization option right.
#   For gcc, Mark Henderson says that
#    -m486 -O -fomit-frame-pointer -finline -finline-functions
#   works better than -O4.
# 
# Makefile by RSADSI, Mark Riordan, & Greg Onufer.

# commands
CC = cc
LIB = ar
RANLIB = ranlib
MAKE = make
TARGS = rsaref.a endmsg

# standard include directory
STDINCDIR=/usr/include
# The places to look for include files (in order).
INCL =  -I. -I$(SRCDIR) -I$(STDINCDIR)
# Normal C flags.
COPTS = -O
CFLAGS_ALL = $(INCL) -DPROTOTYPES=1 -c
CFLAGS_GEN = $(CFLAGS_ALL) -DUSE_BIGNUM -DUSE_2MODEXP 
MFLAGS = -I. -I$(SRCDIR)

# extension for object files
O = o

# name of temporary library script
TEMPFILE = $(TEMP)\temp.mak

# name of main executable to build
PROG = rdemo

# The location of the common source directory.
SRCDIR = ../source/
SRCLIB = rsaref.a

# The location of the demo source directory.
RDEMODIR = ../rdemo/

target : 
	@echo " "
	@echo "           Makefile for RSAREF crypto library."
	@echo " "
	@echo "For MS-DOS, use cl /f rsaref.mak for vanilla MS-DOS or"
	@echo "do_djgcc.bat for 386-extender version."
	@echo " "
	@echo "For Unix, check the makefile (esp. CC and CFLAGS) and when it is " 
	@echo "set up properly, make one of the following targets:"
	@echo " "
	@echo "  make generic      Uses C version only; works for most machines."
	@echo "  make gcc          Same thing; uses gcc instead of cc."
	@echo "  make sun4cc       SunOS 4.x, SPARC assembler + Sun cc."
	@echo "  make sun4acc      SunOS 4.x, SPARC assembler + Sun ANSI acc."
	@echo "  make sun4gcc      SunOS 4.x, SPARC assembler + GNU gcc."
	@echo "  make solaris2     Sun Solaris 2.x, SPARC assembler + Sun cc."
	@echo "  make solaris2gcc  Sun Solaris 2.x, SPARC assembler + Gnu cc."
	@echo "  make aix          IBM RS/6000 AIX, w/ xlc."
	@echo "  make aixgcc       IBM RS/6000 AIX w/ xlc & gcc (faster)."
	@echo "  make aix386       IBM PS/2    AIX."
	@echo "  make aix370       IBM 3090    AIX."
	@echo "  make aixesa       IBM 390     AIX/ESA (OSF/1)."
	@echo "  make sysv386      Unix System V.3.2/386 with GCC."
	@echo "  make next         NeXTStep 2.x & 3.0, 68040 assembler + cc."
	@echo "  make next486      NeXTStep 3.1 for 486, 486 asm + cc."
	@echo "  make hp           HP 9000/700 HP/UX cc."
	@echo "  make dec          DECstation running ULTRIX."
	@echo "  make aux3.0       Macintosh A/UX 3.0 "
	@echo "  make linux        Linux 0.98 "
	@echo "  make mips         MIPS running RISC/os 4.52."
	@echo " "
	
clean :
	rm -f *.o rsaref.a nn.s

# For most Unix machines.
generic :
	@$(MAKE) CC=$(CC) CFLAGS='$(COPTS) $(CFLAGS_ALL)' \
		$(TARGS)

# Apple A/UX
aux3.0 :
	@$(MAKE) CC=$(CC) CFLAGS='-c $(INCL) -DPROTOTYPES=0 -DUSE_BIGNUM' \
		$(TARGS)

# GCC, most machines.
gcc :
	@$(MAKE) CC=gcc CFLAGS="-O4 $(CFLAGS_GEN) -Wall" \
		$(TARGS)

# Sun's CC compiler, Solaris 1.x (SunOS 4.x), w/ assembler.
sun4cc :
	cp ../source/nn-sparc.s ../source/nn.s
	cc -c ../source/nn.s
	@$(MAKE) CC=cc CFLAGS='-c -O3 $(INCL) -DPROTOTYPES=0' \
	 $(TARGS)

# Sun's ANSI-CC compiler, Solaris 1.x (SunOS 4.x), w/ assembler.
#
# Notes: If this will be *running* *only* on Sparc 10 class machines
#        (SuperSPARC) add -cg92 to the beginning of CFLAGS below.
#        It will speed up the benchmark by 40%, however if you
#        run -cg92 code on a non-SuperSPARC machine it will run
#        *twice* as slow (compared to leaving the -cg92 off).
#
#        Choose WISELY!
#
sun4acc :
	cp ../source/nn-sparc.s ../source/nn.s
	acc -c ../source/nn.s
	@$(MAKE) CC=acc CFLAGS="-O3 $(CFLAGS_GEN)" \
	 $(TARGS)

# Sun 4, GNU gcc, w/ assembler.
sun4gcc:
	cp ../source/nn-sparc.s ../source/nn.s
	gcc -c ../source/nn.s
	@$(MAKE) CC=gcc CFLAGS="-O3 $(CFLAGS_GEN)" \
		$(TARGS)

# Solaris 2.x, SPARCompilers 2.x
solaris2 :
	sed -e 's/\<_//g' < ../source/nn-sparc.s > ../source/nn.s
	cc -c ../source/nn.s
	@$(MAKE) CC=cc CFLAGS="-fast -xO4 $(CFLAGS_GEN)" \
		$(TARGS)

# Solaris 2.x, GNU C 2.x
solaris2gcc :
	sed -e 's/\<_//g' < ../source/nn-sparc.s > ../source/nn.s
	gcc -c ../source/nn.s
	@$(MAKE) CC=gcc CFLAGS="-g -O4 -finline-functions $(CFLAGS_GEN)" \
		$(TARGS)

# IBM RS/6000, AIX, xlc compiler.
aix :
	@$(MAKE) CC=xlc CFLAGS="-Q=75 -DDIGIT_IN_NN -O $(CFLAGS_GEN)" \
		$(TARGS)

# IBM RS/6000, AIX, gcc + xlc compiler.
aixgcc :
	gcc -O4 -DRS6000 -DGCC -DDIGIT_IN_NN $(CFLAGS_GEN) $(SRCDIR)digitas.c
	@$(MAKE) CC=xlc CFLAGS="-Q=75 -DDIGIT_IN_NN -O $(CFLAGS_GEN)" \
		$(TARGS)

# IBM PS/2, AIX, Metaware HighC compiler
aix386:
	cp ../source/nn-386aix.s ../source/nn.s
	$(CC) -c ../source/nn.s
	@$(MAKE) CC=cc CFLAGS="-O $(CFLAGS_GEN)" \
		$(TARGS)

# linux 0.98
linux:
	gcc -c -O -m486 -Di386 -DGCC -DDIGIT_IN_NN $(CFLAGS_GEN) \
	-fomit-frame-pointer -finline -finline-functions  $(SRCDIR)digitas.c 
	@$(MAKE) CC=gcc CFLAGS="-m486 -O -DDIGIT_IN_NN $(CFLAGS_GEN) -fomit-frame-pointer -finline -finline-functions" \
		$(TARGS)

#IBM 3090, AIX/370, Metaware High-C compiler
aix370:
	@$(MAKE) CC=cc CFLAGS="-O -Hxa $(CFLAGS_ALL) -DUSE_BIGNUM" \
		$(TARGS)

#IBM 390, AIX/ESA (OSF/1), Metaware High-C compiler
aixesa:
	@$(MAKE) CC=cc CFLAGS="-O -D_BSD -Hxa $(CFLAGS_ALL) -DUSE_BIGNUM" \
		$(TARGS)

# Unix System V.3.2/386 with nn-386.s
sysv386:
	cp ../source/nn-386aix.s ../source/nn.s
	gcc -c ../source/nn.s
	@$(MAKE) CC=gcc CFLAGS="-O $(CFLAGS_GEN) -DSYSV -DUSG" \
		$(TARGS)
		
# NeXTStep, cc compiler, w/ assembler
next :
	cp ../source/nn-m68k.s ../source/nn.s
	cc -c ../source/nn.s
	@$(MAKE) CC=cc CFLAGS="-O $(CFLAGS_GEN)" \
		$(TARGS)

# NeXTStep 486, cc compiler, w/ assembler
next486 :
	cp ../source/nn-386.s ../source/nn.s
	cc -c ../source/nn.s
	@$(MAKE) CC=cc CFLAGS="-O4 $(CFLAGS_GEN)" \
	 $(TARGS)

# MIPS-based DECstation, w/ cc compiler (from MIPS)
dec :
	@$(MAKE) CC=cc CFLAGS="-O2 $(CFLAGS_GEN)" \
		$(TARGS)

# MIPS running RISC/os
mips :
	@$(MAKE) CC=/usr/bsd43/bin/cc CFLAGS="-O $(CFLAGS_GEN)" \
		$(TARGS)

# HP 9000/700 HP/UX  cc (Much faster than gcc for this architecture)
hp :
	@$(MAKE) CC=cc CFLAGS="+O3 -c $(INCL) -DUSE_BIGNUM -DPROTOTYPES=0 -DUSE_2MODEXP" \
		$(TARGS)



rdemo.$(O) : $(RDEMODIR)rdemo.c global.h $(SRCDIR)rsaref.h
	$(CC) $(CFLAGS_GEN) $(RDEMODIR)rdemo.c
rdemo: 	rdemo.$(O) $(SRCLIB)
	$(CC) -o $@ rdemo.$(O) $(SRCLIB)
$(SRCLIB) : desc.$(O) digit.$(O) digitas.$(O) md2c.$(O) md5c.$(O) nn.$(O) \
	prime.$(O) rsa.$(O) r_encode.$(O) r_enhanc.$(O) r_keygen.$(O) \
	r_random.$(O) r_stdlib.$(O)
	$(LIB) r $@ $?
	$(RANLIB) $@

endmsg :
	@echo " "
	@echo "Now do:"
	@echo "  cd ../../main"
	@echo "  make         (This will tell you do to a make <machine_name>)"


include $(SRCDIR)targets.mak
