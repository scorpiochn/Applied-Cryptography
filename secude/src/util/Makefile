#
#  SecuDE Release 4.1 (GMD)
#
#
#    Copyright (C) 1993, GMD Darmstadt
#
#                         NOTICE
#
#    Acquisition, use, and distribution of this module 
#    and related materials are subject to restrictions 
#    mentioned in each volume of the documentation.
#

PGM     = encrypt sign verify hsh pem psemaint algs show sc_eject encode decode \
          getpkroot getfcpath instfcpath instpkroot instcert pkadd pkdel \
          psecreate genkey getkey cacreate certify revoke chpin gen_pse \
          showdir pklist \
          secude create_TestTree delete_TestTree inst_pse inst_ca g te tec \
	  secudeversion


DTESTKEYS = -DTESTKEYS_PSE=\"$(TOP)/lib/.testkeys\"


all: $(BINDIR)

algs.o: algs.c
	$(CC) algs.c -c $(CFLAGS) $(DTIME) $(DTESTKEYS)

sign.o: sign.c
	$(CC) sign.c -c $(CFLAGS) $(DTIME)

verify.o: verify.c
	$(CC) verify.c -c $(CFLAGS) $(DTIME)

encrypt.o: encrypt.c
	$(CC) encrypt.c -c $(CFLAGS) $(DTIME)

cacreate.o:	cacreate.c
	$(CC) cacreate.c -c $(CFLAGS) $(DBMVERS) 

gen_pse.o:	gen_pse.c
	$(CC) gen_pse.c -c $(CFLAGS) $(DBMVERS) 

$(BINDIR): $(PGM)
	cp $? $(BINDIR)
	rm -f $(BINDIR)/decrypt
	ln -s encrypt $(BINDIR)/decrypt
	chmod a+x $(BINDIR)/create_TestTree $(BINDIR)/delete_TestTree $(BINDIR)/g $(BINDIR)/te
	chmod a+x $(BINDIR)/inst_ca $(BINDIR)/inst_pse $(BINDIR)/chpin $(BINDIR)/tec


psemaint: psemaint.o
	$(CC) psemaint.o -o $@ $(LFLAGS) $(LIB)

sc_eject: sc_eject.o
	$(CC) sc_eject.o -o $@ $(LFLAGS) $(LIB)

sign: sign.o
	$(CC) sign.o -o $@ $(LFLAGS) $(LIB)

verify: verify.o
	$(CC) verify.o -o $@ $(LFLAGS) $(LIB)

show: show.o
	$(CC) show.o -o $@ $(LFLAGS) $(LIB)

hsh: hsh.o
	$(CC) hsh.o -o $@ $(LFLAGS) $(LIB)

algs: algs.o
	$(CC) algs.o -o $@ $(LFLAGS) $(LIB)

encrypt: encrypt.o
	$(CC) encrypt.o -o $@ $(LFLAGS) $(LIB)

encode: encode.o
	$(CC) encode.o -o $@ $(LFLAGS) $(LIB)

decode: decode.o
	$(CC) decode.o -o $@ $(LFLAGS) $(LIB)

pem:    pem.o
	$(CC) pem.o -o $@ $(LFLAGS) $(LIB)

gen_pse: gen_pse.o
	$(CC) gen_pse.o -o $@ $(LFLAGS) $(LIB)

instcert: instcert.o
	$(CC) instcert.o -o $@ $(LFLAGS) $(LIB)

instpkroot: instpkroot.o
	$(CC) instpkroot.o -o $@ $(LFLAGS) $(LIB)

instfcpath: instfcpath.o
	$(CC) instfcpath.o -o $@ $(LFLAGS) $(LIB)

getpkroot: getpkroot.o
	$(CC) getpkroot.o -o $@ $(LFLAGS) $(LIB)

getfcpath: getfcpath.o
	$(CC) getfcpath.o -o $@ $(LFLAGS) $(LIB)

getkey: getkey.o
	$(CC) getkey.o -o $@ $(LFLAGS) $(LIB)

psecreate: psecreate.o
	$(CC) psecreate.o -o $@ $(LFLAGS) $(LIB)

genkey: genkey.o
	$(CC) genkey.o -o $@ $(LFLAGS) $(LIB)

certify: certify.o
	$(CC) certify.o -o $@ $(LFLAGS) $(LIB)

cacreate: cacreate.o
	$(CC) cacreate.o -o $@ $(LFLAGS) $(LIB)

showdir: showdir.o
	$(CC) showdir.o -o $@ $(LFLAGS) $(LIB)

revoke: revoke.o
	$(CC) revoke.o -o $@ $(LFLAGS) $(LIB)

pklist: pklist.o
	$(CC) pklist.o -o $@ $(LFLAGS) $(LIB)

pkadd:  pkadd.o
	$(CC) pkadd.o -o $@ $(LFLAGS) $(LIB)

pkdel: pkdel.o
	$(CC) pkdel.o -o $@ $(LFLAGS) $(LIB)

secudeversion: secudeversion.o
	$(CC) secudeversion.o -o $@ $(LFLAGS) $(LIB)

create_TestTree: create_TestTree.sh
	cp create_TestTree.sh create_TestTree

delete_TestTree: delete_TestTree.sh
	cp delete_TestTree.sh delete_TestTree

chpin: chpin.sh
	cp chpin.sh chpin

secude: secude.sh
	cp secude.sh secude

g: g.sh
	cp g.sh g

te: te.sh
	cp te.sh te

tec: tec.sh
	cp tec.sh tec

inst_pse: inst_pse.sh
	cp inst_pse.sh inst_pse

inst_ca: inst_ca.sh
	cp inst_ca.sh inst_ca

