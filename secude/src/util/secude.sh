#!/bin/csh

alias htxt '\!* -h;echo "";echo "************************************************************************************************";echo ""'

if( "$1" == "-q") then
	echo ""
	echo "General User Utilities:"
	echo "======================="
	echo ""
	htxt sign
	htxt verify
	htxt encrypt
	htxt decrypt
	htxt pem
	htxt hsh
	htxt encode
	htxt decode
	htxt algs
	htxt secxlock
	echo ""
	echo "Utilities to Create and Maintain your Personal Security Environment (PSE)"
	echo "========================================================================="
	echo ""
	htxt psecreate
	htxt sectool
	htxt psemaint
	htxt instpkroot
	htxt instfcpath
	htxt instcert
	htxt genkey
	htxt getkey
	htxt pkadd
	htxt pkdel
	htxt pklist
	htxt showdir
	htxt show
	echo ""
	echo "Utilities for the Operation of Certification Authorities (X.509)"
	echo "================================================================"
	echo ""
	htxt cacreate
	htxt certify
	htxt revoke
	htxt getpkroot
	htxt getfcpath
	htxt gen_pse
	echo ""
	echo "Test"
	echo "===="
	echo ""
	htxt create_TestTree
endif
if( "$1" == "-h") then
	echo ""
	echo "General User Utilities:"
	echo "======================="
	echo ""
	echo "sign        sign files"
	echo "verify      verify signatures of files"
	echo "encrypt     encrypt files"
	echo "decrypt     decrypt files"
	echo "pem         RFC 1421 - 1424 PEM filter"
	echo "hsh         hash a file"
	echo "encode      encode a file to ASCII (RFC 1421 or [0-9,A-F} style)"
	echo "decode      decode a file" 
	echo "algs        print information on available algorithms"
	echo "secxlock    lock the local X display using strong authentication with your PSE"
	echo ""
	echo "Utilities to Create and Maintain your Personal Security Environment (PSE)"
	echo "========================================================================="
	echo ""
	echo "psecreate   create a prototype user PSE"
	echo "sectool     maintain your PSE (Openwindow)"
	echo "psemaint    maintain your PSE (line-oriented)"
	echo "instpkroot  install public root key"
	echo "instfcpath  install forward certification path"
	echo "instcert    install user certificate"
	echo "genkey      generate prototype certificate with new asym keys"
	echo "getkey      generate prototype certificate on existing public key (from Cert)"
	echo "pkadd       retrieve certificate from Directory and add PK to the cache of trusted keys"
	echo "pkdel       delete PK from the cache of trusted keys"
	echo "pklist      show cache of trusted keys"
	echo "showdir     retrieve and show security attributes from Directory"
	echo "show        show ASN.1-encoded SecuDE object in suitable form"
	echo "inst_pse    install a PSE previously generated with gen_pse"
	echo ""
	echo "Utilities for the Operation of Certification Authorities (X.509)"
	echo "================================================================"
	echo ""
	echo "cacreate    create CA (including CA prototype PSE)"
	echo "certify     certify prototype certificate"
	echo "revoke      revoke certificate"
	echo "sectool -c <cadir>    maintain CA PSE and CA database (Openwindow)"
	echo "psemaint -c <cadir>    maintain CA PSE and CA database (line-oriented)"
	echo "getpkroot   get public root key from CA PSE"
	echo "getfcpath   get forward certification path from CA PSE"
	echo "gen_pse     generate a user PSE at CA site"
	echo "inst_ca     install a CA directory previously generated with gen_pse"
	echo ""
endif



