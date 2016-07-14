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
#
#			SECTOOL 2.1 (Demo version)
#
#	special SecTool paths:
#				SECTOOL_GLYPHS = <path to images *icon *glyph included at compiling time>
#				HELP_PATH = <path to sectool.info online help file>
#				in shell environment: setenv HELPPATH = <path to sectool.info online help file>


SECTOOL_GLYPHS = /renne/secure/lib/images
HELP_PATH = $(OPENWINHOME)/lib/help

CPPFLAGS += -I$(OPENWINHOME)/include # -I$(SECTOOL_GLYPHS)
LDFLAGS  += -L$(OPENWINHOME)/lib
LDLIBS   += -lxview -lolgx -lX

IFLAGS	 += $(CPPFLAGS)


SECTOOLOBJS    = sectool.o sect_init.o sect_util.o sect_create.o sect_pse.o sect_ca.o sect_dir.o sect_alias.o sect_props.o

PGM     = sectool

.c.o:;		$(CC) $*.c $(CFLAGS) -c
.c.ln:;		$(LINT) $(LINTFLAGS) $*.c

inst-all : all

all:    $(BINDIR)


$(BINDIR): $(PGM)
	cp sectool $(BINDIR)
	rm -f $(BINDIR)/aliastool
	rm -f $(BINDIR)/directorytool
	ln -s sectool $(BINDIR)/aliastool
	ln -s sectool $(BINDIR)/directorytool
#	cp sectool.info $(HELP_PATH)
#	cp sect*.glyph sect*.icon $(SECTOOL_GLYPHS)


sectool:	$(SECTOOLOBJS)
	$(CC) -o $@ $(CPPFLAGS) $(SECTOOLOBJS) $(LFLAGS) $(LIB) $(LDFLAGS) $(LDLIBS) 
	
