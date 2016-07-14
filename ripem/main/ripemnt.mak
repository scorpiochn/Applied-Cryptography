# Microsoft Visual C++ generated build script - Do not modify

PROJ = RIPEM
DEBUG = 0
PROGTYPE = 2
CALLER = 
ARGS = 
DLLS = 
ORIGIN = MSVCNT
ORIGIN_VER = 1.00
PROJPATH = C:\CIP\RIPEM\MAIN\ 
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = ADDUSER.C
FIRSTCPP = 
RC = rc
CFLAGS_D_DEXE32 = /nologo /W3 /Zi /YX /D "_X86_" /D "_DEBUG" /D "_CONSOLE" /FR /ML /Fd"RIPEM.PDB" /Fp"RIPEM.PCH"
CFLAGS_R_DEXE32 = /nologo /Za /W3 /YX /O2 /Op- /Ox /Ob2 /D "_X86_" /D "NDEBUG" /D "_CONSOLE" /D "WINNT" /I "..\rsaref\source" /ML /Fp"RIPEM.PCH"
LFLAGS_D_DEXE32 = /NOLOGO /DEBUG /DEBUGTYPE:cv /SUBSYSTEM:console netapi32.lib
LFLAGS_R_DEXE32 = /NOLOGO /SUBSYSTEM:console netapi32.lib
LFLAGS_D_LIB32 = /NOLOGO
LFLAGS_R_LIB32 = /NOLOGO
LIBS_D_DEXE32 = 
LIBS_R_DEXE32 = 
RCFLAGS32 = 
D_RCDEFINES32 = -d_DEBUG
R_RCDEFINES32 = -dNDEBUG
OBJS_EXT = 
LIBS_EXT = ..\rsaref\test\RSAREF.LIB 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_DEXE32)
LFLAGS = $(LFLAGS_D_DEXE32)
LIBS = $(LIBS_D_DEXE32)
LFLAGS_LIB=$(LFLAGS_D_LIB32)
MAPFILE_OPTION = 
RCDEFINES = $(D_RCDEFINES32)
!else
CFLAGS = $(CFLAGS_R_DEXE32)
LFLAGS = $(LFLAGS_R_DEXE32)
LIBS = $(LIBS_R_DEXE32)
MAPFILE_OPTION = 
LFLAGS_LIB=$(LFLAGS_R_LIB32)
RCDEFINES = $(R_RCDEFINES32)
!endif
SBRS = ADDUSER.SBR \
      BEMPARSE.SBR \
      CERTUTIL.SBR \
      CRACKHED.SBR \
      DERKEY.SBR \
      GETOPT.SBR \
      GETSYS.SBR \
      HEXBIN.SBR \
      KEYDER.SBR \
      KEYMAN.SBR \
      LIST.SBR \
      PARSIT.SBR \
      PRENCODE.SBR \
      PUBINFO.SBR \
      RDWRMSG.SBR \
      RIPEMMAI.SBR \
      RIPEMSOC.SBR \
      STRUTIL.SBR \
      USAGE.SBR \
      USAGEMSG.SBR


RSAREF_DEP = 

ADDUSER_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\listprot.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\adduserp.h


BEMPARSE_DEP =  \
   c:\cip\ripem\main\bemparse.h \
   c:\cip\ripem\main\p.h


CERTUTIL_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\certder.h \
   c:\cip\ripem\main\keyderpr.h \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\rdwrmsgp.h \
   c:\cip\ripem\main\pubinfop.h \
   c:\cip\ripem\main\ripempro.h \
   c:\cip\ripem\main\certutil.h \
   c:\cip\ripem\main\keymanpr.h \
   c:\cip\ripem\main\p.h


CRACKHED_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\ripemglo.h \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\crackhpr.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\hexbinpr.h \
   c:\cip\ripem\main\derkeypr.h \
   c:\cip\ripem\main\listprot.h


DERKEY_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\derkeypr.h \
   c:\cip\ripem\main\certder.h


GETOPT_DEP =  \
   c:\cip\ripem\main\getoptpr.h


GETSYS_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\getsyspr.h \
   c:\cip\ripem\main\strutilp.h


HEXBIN_DEP =  \
   c:\cip\ripem\main\hexbinpr.h


KEYDER_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\keyderpr.h \
   c:\cip\ripem\main\certder.h


KEYMAN_DEP =  \
   c:\cip\ripem\main\p.h \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   C:\CIP\RIPEM\rsaref\source\md5.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\ripemglo.h \
   C:\CIP\RIPEM\rsaref\source\des.h \
   c:\cip\ripem\main\keymanpr.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\derkeypr.h \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\hexbinpr.h \
   c:\cip\ripem\main\getsyspr.h \
   c:\cip\ripem\main\ripemsop.h \
   c:\cip\ripem\main\pubinfop.h \
   c:\cip\ripem\main\keyderpr.h \
   c:\cip\ripem\main\rdwrmsgp.h \
   c:\cip\ripem\main\ripempro.h \
   c:\cip\ripem\main\certder.h \
   c:\cip\ripem\main\certutil.h \
   c:\cip\ripem\main\bemparse.h


LIST_DEP =  \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\listprot.h \
   c:\cip\ripem\main\strutilp.h


PARSIT_DEP =  \
   c:\cip\ripem\main\parsitpr.h


PRENCODE_DEP =  \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\prencode.h


PUBINFO_DEP =  \
   c:\cip\ripem\main\boolean.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\pubinfop.h \
   c:\cip\ripem\main\global.h \
   c:\cip\ripem\main\protserv.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\strutilp.h


RDWRMSG_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\ripemglo.h \
   c:\cip\ripem\main\rdwrmsgp.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\listprot.h \
   c:\cip\ripem\main\adduserp.h \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\ripempro.h


RIPEMMAI_DEP =  \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\ripemglo.h \
   c:\cip\ripem\main\prcodepr.h \
   c:\cip\ripem\main\usagepro.h \
   c:\cip\ripem\main\getoptpr.h \
   c:\cip\ripem\main\ripempro.h \
   c:\cip\ripem\main\getsyspr.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\keyderpr.h \
   c:\cip\ripem\main\derkeypr.h \
   c:\cip\ripem\main\keymanpr.h \
   c:\cip\ripem\main\listprot.h \
   c:\cip\ripem\main\adduserp.h \
   C:\CIP\RIPEM\rsaref\source\r_random.h \
   c:\cip\ripem\main\bemparse.h \
   c:\cip\ripem\main\p.h \
   c:\cip\ripem\main\hexbinpr.h \
   c:\cip\ripem\main\crackhpr.h \
   c:\cip\ripem\main\rdwrmsgp.h \
   c:\cip\ripem\main\parsitpr.h \
   c:\cip\ripem\main\certder.h \
   c:\cip\ripem\main\certutil.h


RIPEMSOC_DEP =  \
   d:\msvcnt\include\unistd.h \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h \
   c:\cip\ripem\main\ripem.h \
   c:\cip\ripem\main\list.h \
   c:\cip\ripem\main\keyfield.h \
   c:\cip\ripem\main\headers.h \
   c:\cip\ripem\main\ripemsop.h \
   c:\cip\ripem\main\ripemglo.h \
   c:\cip\ripem\main\protserv.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\pubinfop.h \
   c:\cip\ripem\main\p.h


STRUTIL_DEP =  \
   c:\cip\ripem\main\boolean.h \
   c:\cip\ripem\main\strutilp.h \
   c:\cip\ripem\main\hexbinpr.h \
   c:\cip\ripem\main\global.h \
   C:\CIP\RIPEM\rsaref\source\rsaref.h


USAGE_DEP =  \
   c:\cip\ripem\main\usagepro.h


USAGEMSG_DEP = 

all:  $(PROJ).EXE

ADDUSER.OBJ:   ADDUSER.C $(ADDUSER_DEP)
   $(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ADDUSER.C

BEMPARSE.OBJ:  BEMPARSE.C $(BEMPARSE_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c BEMPARSE.C

CERTUTIL.OBJ:  CERTUTIL.C $(CERTUTIL_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CERTUTIL.C

CRACKHED.OBJ:  CRACKHED.C $(CRACKHED_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CRACKHED.C

DERKEY.OBJ: DERKEY.C $(DERKEY_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c DERKEY.C

GETOPT.OBJ: GETOPT.C $(GETOPT_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETOPT.C

GETSYS.OBJ: GETSYS.C $(GETSYS_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETSYS.C

HEXBIN.OBJ: HEXBIN.C $(HEXBIN_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c HEXBIN.C

KEYDER.OBJ: KEYDER.C $(KEYDER_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c KEYDER.C

KEYMAN.OBJ: KEYMAN.C $(KEYMAN_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c KEYMAN.C

LIST.OBJ:   LIST.C $(LIST_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIST.C

PARSIT.OBJ: PARSIT.C $(PARSIT_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PARSIT.C

PRENCODE.OBJ:  PRENCODE.C $(PRENCODE_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PRENCODE.C

PUBINFO.OBJ:   PUBINFO.C $(PUBINFO_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PUBINFO.C

RDWRMSG.OBJ:   RDWRMSG.C $(RDWRMSG_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RDWRMSG.C

RIPEMMAI.OBJ:  RIPEMMAI.C $(RIPEMMAI_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RIPEMMAI.C

RIPEMSOC.OBJ:  RIPEMSOC.C $(RIPEMSOC_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RIPEMSOC.C

STRUTIL.OBJ:   STRUTIL.C $(STRUTIL_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c STRUTIL.C

USAGE.OBJ:  USAGE.C $(USAGE_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c USAGE.C

USAGEMSG.OBJ:  USAGEMSG.C $(USAGEMSG_DEP)
   $(CC) $(CFLAGS) $(CUSEPCHFLAG) /c USAGEMSG.C

$(PROJ).EXE:   ADDUSER.OBJ BEMPARSE.OBJ CERTUTIL.OBJ CRACKHED.OBJ DERKEY.OBJ GETOPT.OBJ \
   GETSYS.OBJ HEXBIN.OBJ KEYDER.OBJ KEYMAN.OBJ LIST.OBJ PARSIT.OBJ PRENCODE.OBJ PUBINFO.OBJ \
   RDWRMSG.OBJ RIPEMMAI.OBJ RIPEMSOC.OBJ STRUTIL.OBJ USAGE.OBJ USAGEMSG.OBJ $(OBJS_EXT) $(LIBS_EXT)
   echo >NUL @<<$(PROJ).CRF
ADDUSER.OBJ 
BEMPARSE.OBJ 
CERTUTIL.OBJ 
CRACKHED.OBJ 
DERKEY.OBJ 
GETOPT.OBJ 
GETSYS.OBJ 
HEXBIN.OBJ 
KEYDER.OBJ 
KEYMAN.OBJ 
LIST.OBJ 
PARSIT.OBJ 
PRENCODE.OBJ 
PUBINFO.OBJ 
RDWRMSG.OBJ 
RIPEMMAI.OBJ 
RIPEMSOC.OBJ 
STRUTIL.OBJ 
USAGE.OBJ 
USAGEMSG.OBJ 
$(OBJS_EXT)
-OUT:$(PROJ).EXE
$(MAPFILE_OPTION)
..\rsaref\test\RSAREF.LIB
$(LIBS)
$(LIBS_EXT)
$(DEFFILE_OPTION) -implib:$(PROJ).lib
<<
   link $(LFLAGS) @$(PROJ).CRF

run: $(PROJ).EXE
   $(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
   bscmake @<<
/o$@ $(SBRS)
<<
