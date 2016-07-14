# Microsoft Visual C++ generated build script - Do not modify

PROJ = RSAREF
DEBUG = 0
PROGTYPE = 3
CALLER = 
ARGS = 
DLLS = 
ORIGIN = MSVCNT
ORIGIN_VER = 1.00
PROJPATH = C:\CIP\RIPEM\RSAREF\TEST\ 
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = DESC.C
FIRSTCPP = 
RC = rc
CFLAGS_D_LIB32 = /nologo /W3 /Z7 /YX /D "_X86_" /D "_DEBUG" /D "_WINDOWS" /FR /ML /Fp"RSAREF.PCH"
CFLAGS_R_LIB32 = /nologo /W3 /YX /O2 /Ox /Ob2 /D "_X86_" /D "NDEBUG" /D "_WINDOWS" /D "USE_386_ASM" /D "USE_2MODEXP" /ML /Fp"RSAREF.PCH"
LFLAGS_D_LIB32 = /NOLOGO
LFLAGS_R_LIB32 = /NOLOGO
RCFLAGS32 = 
D_RCDEFINES32 = -d_DEBUG
R_RCDEFINES32 = -dNDEBUG
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_LIB32)
LFLAGS = 
LIBS = 
LFLAGS_LIB=$(LFLAGS_D_LIB32)
MAPFILE_OPTION = 
RCDEFINES = $(D_RCDEFINES32)
!else
CFLAGS = $(CFLAGS_R_LIB32)
LFLAGS = 
LIBS = 
MAPFILE_OPTION = 
LFLAGS_LIB=$(LFLAGS_R_LIB32)
RCDEFINES = $(R_RCDEFINES32)
!endif
SBRS = DESC.SBR \
		DIGIT.SBR \
		DIGITAS.SBR \
		MD2C.SBR \
		MD5C.SBR \
		NN.SBR \
		PRIME.SBR \
		R_ENCODE.SBR \
		R_ENHANC.SBR \
		R_KEYGEN.SBR \
		R_RANDOM.SBR \
		R_STDLIB.SBR \
		RSA.SBR


DESC_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\des.h


DIGIT_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\nn.h \
	c:\cip\ripem\rsaref\source\digit.h


DIGITAS_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\nn.h \
	c:\cip\ripem\rsaref\source\digit.h


MD2C_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\md2.h


MD5C_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\md5.h


NN_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\nn.h \
	c:\cip\ripem\rsaref\source\digit.h \
	c:\cip\ripem\rsaref\source\digitas.h


PRIME_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\nn.h \
	c:\cip\ripem\rsaref\source\prime.h


R_ENCODE_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\r_encode.h


R_ENHANC_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\r_encode.h \
	c:\cip\ripem\rsaref\source\r_random.h \
	c:\cip\ripem\rsaref\source\rsa.h \
	c:\cip\ripem\rsaref\source\md2.h \
	c:\cip\ripem\rsaref\source\md5.h \
	c:\cip\ripem\rsaref\source\des.h


R_KEYGEN_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\r_random.h \
	c:\cip\ripem\rsaref\source\nn.h \
	c:\cip\ripem\rsaref\source\prime.h


R_RANDOM_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\r_random.h \
	c:\cip\ripem\rsaref\source\md5.h


R_STDLIB_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h


RSA_DEP =  \
	c:\cip\ripem\rsaref\source\global.h \
	c:\cip\ripem\rsaref\source\rsaref.h \
	c:\cip\ripem\rsaref\source\r_random.h \
	c:\cip\ripem\rsaref\source\rsa.h \
	c:\cip\ripem\rsaref\source\nn.h


all:  $(PROJ).LIB

DESC.OBJ:   ..\SOURCE\DESC.C $(DESC_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ..\SOURCE\DESC.C

DIGIT.OBJ:  ..\SOURCE\DIGIT.C $(DIGIT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\DIGIT.C

DIGITAS.OBJ:   ..\SOURCE\DIGITAS.C $(DIGITAS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\DIGITAS.C

MD2C.OBJ:   ..\SOURCE\MD2C.C $(MD2C_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\MD2C.C

MD5C.OBJ:   ..\SOURCE\MD5C.C $(MD5C_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\MD5C.C

NN.OBJ:  ..\SOURCE\NN.C $(NN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\NN.C

PRIME.OBJ:  ..\SOURCE\PRIME.C $(PRIME_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\PRIME.C

R_ENCODE.OBJ:  ..\SOURCE\R_ENCODE.C $(R_ENCODE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\R_ENCODE.C

R_ENHANC.OBJ:  ..\SOURCE\R_ENHANC.C $(R_ENHANC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\R_ENHANC.C

R_KEYGEN.OBJ:  ..\SOURCE\R_KEYGEN.C $(R_KEYGEN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\R_KEYGEN.C

R_RANDOM.OBJ:  ..\SOURCE\R_RANDOM.C $(R_RANDOM_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\R_RANDOM.C

R_STDLIB.OBJ:  ..\SOURCE\R_STDLIB.C $(R_STDLIB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\R_STDLIB.C

RSA.OBJ: ..\SOURCE\RSA.C $(RSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SOURCE\RSA.C

$(PROJ).LIB:   DESC.OBJ DIGIT.OBJ DIGITAS.OBJ MD2C.OBJ MD5C.OBJ NN.OBJ PRIME.OBJ R_ENCODE.OBJ \
	R_ENHANC.OBJ R_KEYGEN.OBJ R_RANDOM.OBJ R_STDLIB.OBJ RSA.OBJ $(OBJS_EXT) $(LIBS_EXT)
	echo >NUL @<<$(PROJ).CRF
DESC.OBJ 
DIGIT.OBJ 
DIGITAS.OBJ 
MD2C.OBJ 
MD5C.OBJ 
NN.OBJ 
PRIME.OBJ 
R_ENCODE.OBJ 
R_ENHANC.OBJ 
R_KEYGEN.OBJ 
R_RANDOM.OBJ 
R_STDLIB.OBJ 
RSA.OBJ 


<<
	if exist $@ del $@
	link -LIB /out:rsaref.lib @$(PROJ).CRF

$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
