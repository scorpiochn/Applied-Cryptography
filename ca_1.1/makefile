SOURCE_DIR = .

OBJECTS = \
$(SOURCE_DIR)/crypt.o \
$(SOURCE_DIR)/crinit.o \
$(SOURCE_DIR)/crutil.o \
$(SOURCE_DIR)/crperm.o \
$(SOURCE_DIR)/crdfus.o \
$(SOURCE_DIR)/crlink.o \
/lib/libm.a


HEADERS =  \
$(SOURCE_DIR)/crtype.h \
$(SOURCE_DIR)/crutil.h \
$(SOURCE_DIR)/crperm.h \
$(SOURCE_DIR)/crinit.h \
$(SOURCE_DIR)/crlink.h \
$(SOURCE_DIR)/crdfus.h

crypt: ${OBJECTS}
	cc  ${OBJECTS} -o crypt


crypt.o:  ${HEADERS}
	cc -c crypt.c

crinit.o:  ${HEADERS}
	cc -c crinit.c

crutil.o:  ${HEADERS}
	cc -c crutil.c

crperm.o:  ${HEADERS}
	cc -c crperm.c

crlink.o:  ${HEADERS}
	cc -c crlink.c


crdfus.o:  ${HEADERS}
	cc -c crdfus.c




