#!/bin/sh
set -e
#
# SecuDE Release 4.1 (GMD) 
#

helptext="\nSecuDE-4.1  \t\t\t\t\t\t                (c)1993 GMD Darmstadt \n
\ncreate_TestTree \t Create a test certification tree and test users \n
\nusage: \n
\ncreate_TestTree [-v] [-p] [-D] [-t] [-q] \n
\nwith: \n
\n-v \t	  verbose
\n-p \t	  use PEM RFC 1424 certification procedures,
\n   \t   otherwise use KM utilities for certification
\n-D \t	  enter certificates into Directory (X.500 or .af-db),
\n-t \t   Enable checking of malloc/free behaviour
\n-q \t   create PSEs with separate key pairs for SIGNATURE/ENCRYPTION purposes,
\n   \t   otherwise create 'one key pair' PSEs\n
\nThis shell-script creates, for test purposes, the following tree of
\ncertification authorities and users: \n
\n \t\t\t                          Root-CA
\n \t\t                         /     \t\t\t        \ 
\n         \t             ORG-1-CA         \t\t\t            ORG-2-CA
\n      \t             /   \t     \     \t\t\t              /   \t     \ 
\n               ORG-1-User-1   ORG-1-User-2  \t ORG-2-User-1   ORG-2-User-2 \n
\n
\nIt creates the directory TestTree under the home directory and the following directories
\nunder TestTree: \n

\nRoot-CA \t        CA directory of the root ca, CA-PSE is .capse, PIN = test
\nORG-1-CA \t       CA directory of the ca ORG-1-CA under Root-CA, CA-PSE is .capse, PIN = test
\nORG-2-CA \t       CA directory of the ca ORG-2-CA under Root-CA, CA-PSE is .capse, PIN = test
\nORG-1-User-1 \t   PSE of user ORG-1-User-1 under ca ORG-1-CA, PIN = test
\nORG-1-User-2 \t   PSE of user ORG-1-User-2 under ca ORG-1-CA, PIN = test
\nORG-2-User-1 \t   PSE of user ORG-2-User-1 under ca ORG-2-CA, PIN = test
\nORG-2-User-2 \t   PSE of user ORG-2-User-2 under ca ORG-2-CA, PIN = test\n
\ncreate_test_tree needs about 100 sec on a Sun SPARC10-41\n"

q=

for par do case $par in
        -P)
                p=pem;;
        -D)
		D=$par;;
        -v)
		v=$par;;
	-q)
		q=$par;;
	-t)
		t=$par;;
        -h)
                echo $helptext
                exit;;
esac done

cd
mkdir TestTree
cd TestTree
HOME=`pwd`
export HOME

CAPIN=test
USERPIN=test
export USERPIN CAPIN

echo ""
echo "******* Create Root-CA *******:"
echo "Create prototype CA <C=DE; O=Root-CA>"
cacreate $v $q $t -c Root-CA "C=DE; O=Root-CA"
echo "done."
if [ "$p" != "pem" ]
then
	getpkroot -c Root-CA $v > PKRoot
fi



echo ""
echo "******* Create ORG-1 CA under Root-CA *******:"
echo "Create prototype CA <C=DE; O=ORG-1>"
cacreate $v $q $t $D-c ORG-1-CA "C=DE; O=ORG-1"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-1>"
	pem mic-clear $v $t -C -i certreq -o ORG-1-CA.pem.proto -c ORG-1-CA
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=Root-CA>"
	pem certify $v $t -i ORG-1-CA.pem.proto -o ORG-1-CA.pem.cert -c Root-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-1>"
	pem $v $t $D -i ORG-1-CA.pem.cert -o certreply -c ORG-1-CA -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-1>"
	instpkroot -c ORG-1-CA $v < PKRoot
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-1>"
	getkey -c ORG-1-CA -s $v > ORG-1-CA.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-1> by <C=DE; O=Root-CA>"
	certify -c Root-CA $v < ORG-1-CA.sign.proto > ORG-1-CA.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-1>"
	instcert -c ORG-1-CA $v -H < ORG-1-CA.sign.cert
	echo "done."
	getfcpath -c ORG-1-CA $v > ORG-1-CA.FCPath
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-1>"
	getkey -c ORG-1-CA -e $v > ORG-1-CA.encr.proto
	certify -c Root-CA $v < ORG-1-CA.encr.proto > ORG-1-CA.encr.cert
	instcert $D -c ORG-1-CA $v -He < ORG-1-CA.encr.cert
	echo "done."
fi
echo "PSE of CA <C=DE; O=ORG-1> O.K."
rm -f *.proto *.cert



echo ""
echo "******* Create ORG-2 CA under Root-CA *******:"
echo "Create prototype CA <C=DE; O=ORG-2>"
cacreate $v $q $t -c ORG-2-CA "C=DE; O=ORG-2"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-2>"
	pem mic-clear $v $t -C -i certreq -o ORG-2-CA.pem.proto -c ORG-2-CA
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=Root-CA>"
	pem certify $v $t -i ORG-2-CA.pem.proto -o ORG-2-CA.pem.cert -c Root-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-2>"
	pem $v $t $D -i ORG-2-CA.pem.cert -o certreply -c ORG-2-CA -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-2>"
	instpkroot -c ORG-2-CA $v < PKRoot
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-2>"
	getkey -c ORG-2-CA -s $v > ORG-2-CA.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-2> by <C=DE; O=Root-CA>"
	certify -c Root-CA $v < ORG-2-CA.sign.proto > ORG-2-CA.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-2>"
	instcert $D -c ORG-2-CA $v -H < ORG-2-CA.sign.cert
	echo "done."
	getfcpath -c ORG-2-CA $v > ORG-2-CA.FCPath
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-2>"
	getkey -c ORG-2-CA -e $v > ORG-2-CA.encr.proto
	certify -c Root-CA $v < ORG-2-CA.encr.proto > ORG-2-CA.encr.cert
	instcert $D -c ORG-2-CA $v -He < ORG-2-CA.encr.cert
	echo "done."
fi
echo "PSE of CA <C=DE; O=ORG-2> O.K."
rm -f *.proto *.cert



echo ""
echo "******* Create User-1 of ORG-1 *******:"
echo "Create prototype PSE for  <C=DE; O=ORG-1; CN=User-1>"
psecreate -p ORG-1-User-1 $v $q $t "C=DE; O=ORG-1; CN=ORG-1-User-1"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-1; CN=User-1>"
	pem mic-clear $v $t -C -i certreq -o ORG-1-User-1.pem.proto -p ORG-1-User-1
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=ORG-1>"
	pem certify $v $t -i ORG-1-User-1.pem.proto -o ORG-1-User-1.pem.cert -c ORG-1-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-1; CN=User-1>"
	pem $v $t $D -i ORG-1-User-1.pem.cert -o certreply -p ORG-1-User-1 -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-1; CN=User-1>"
	instpkroot -p ORG-1-User-1 $v < PKRoot
	echo "done."
	echo "Install FCPath in PSE of <C=DE; O=ORG-1; CN=User-1>"
	instfcpath -p ORG-1-User-1 $v < ORG-1-CA.FCPath
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-1; CN=User-1>"
	getkey -p ORG-1-User-1 -s $v > ORG-1-User-1.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-1; CN=User-1> by <C=DE; O=ORG-1>"
	certify -c ORG-1-CA $v < ORG-1-User-1.sign.proto > ORG-1-User-1.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-1; CN=User-1>"
	instcert $D -p ORG-1-User-1 $v -H < ORG-1-User-1.sign.cert
	echo "done."
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-1; CN=User-1>"
	getkey -p ORG-1-User-1 -e $v > ORG-1-User-1.encr.proto
	certify -c ORG-1-CA $v < ORG-1-User-1.encr.proto > ORG-1-User-1.encr.cert
	instcert $D -p ORG-1-User-1 $v -He < ORG-1-User-1.encr.cert
	echo "done."
fi
echo "PSE of user <C=DE; O=ORG-1; CN=User-1> O.K."
rm -f *.proto *.cert



echo ""
echo "******* Create User-2 of ORG-1 *******:"
echo "Create prototype PSE for  <C=DE; O=ORG-1; CN=User-2>"
psecreate -p ORG-1-User-2 $v $q $t "C=DE; O=ORG-1; CN=ORG-1-User-2"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-1; CN=User-2>"
	pem mic-clear $v $t -C -i certreq -o ORG-1-User-2.pem.proto -p ORG-1-User-2
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=ORG-1>"
	pem certify $v $t -i ORG-1-User-2.pem.proto -o ORG-1-User-2.pem.cert -c ORG-1-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-1; CN=User-2>"
	pem $v $t $D -i ORG-1-User-2.pem.cert -o certreply -p ORG-1-User-2 -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-1; CN=User-2>"
	instpkroot -p ORG-1-User-2 $v < PKRoot
	echo "done."
	echo "Install FCPath in PSE of <C=DE; O=ORG-1; CN=User-2>"
	instfcpath -p ORG-1-User-2 $v < ORG-1-CA.FCPath
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-1; CN=User-2>"
	getkey -p ORG-1-User-2 -s $v > ORG-1-User-2.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-1; CN=User-2> by <C=DE; O=ORG-1>"
	certify -c ORG-1-CA $v < ORG-1-User-2.sign.proto > ORG-1-User-2.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-1; CN=User-2>"
	instcert $D -p ORG-1-User-2 $v -H < ORG-1-User-2.sign.cert
	echo "done."
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-1; CN=User-2>"
	getkey -p ORG-1-User-2 -e $v > ORG-1-User-2.encr.proto
	certify -c ORG-1-CA $v < ORG-1-User-2.encr.proto > ORG-1-User-2.encr.cert
	instcert $D -p ORG-1-User-2 $v -He < ORG-1-User-2.encr.cert
	echo "done."
fi
echo "PSE of user <C=DE; O=ORG-1; CN=User-2> O.K."
rm -f *.proto *.cert



echo ""
echo "******* Create User-1 of ORG-2 *******:"
echo "Create prototype PSE for  <C=DE; O=ORG-2; CN=User-1>"
psecreate -p ORG-2-User-1 $v $q $t "C=DE; O=ORG-2; CN=ORG-2-User-1"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-2; CN=User-1>"
	pem mic-clear $v $t -C -i certreq -o ORG-2-User-1.pem.proto -p ORG-2-User-1
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=ORG-2>"
	pem certify $v $t -i ORG-2-User-1.pem.proto -o ORG-2-User-1.pem.cert -c ORG-2-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-2; CN=User-1>"
	pem $v $t $D -i ORG-2-User-1.pem.cert -o certreply -p ORG-2-User-1 -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-2; CN=User-1>"
	instpkroot -p ORG-2-User-1 $v < PKRoot
	echo "done."
	echo "Install FCPath in PSE of <C=DE; O=ORG-2; CN=User-1>"
	instfcpath -p ORG-2-User-1 $v < ORG-2-CA.FCPath
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-2; CN=User-1>"
	getkey -p ORG-2-User-1 -s $v > ORG-2-User-1.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-2; CN=User-1> by <C=DE; O=ORG-2>"
	certify -c ORG-2-CA $v < ORG-2-User-1.sign.proto > ORG-2-User-1.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-2; CN=User-1>"
	instcert $D -p ORG-2-User-1 $v -H < ORG-2-User-1.sign.cert
	echo "done."
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-2; CN=User-1>"
	getkey -p ORG-2-User-1 -e $v > ORG-2-User-1.encr.proto
	certify -c ORG-2-CA $v <ORG-2-User-1.encr.proto > ORG-2-User-1.encr.cert
	instcert $D -p ORG-2-User-1 $v -He < ORG-2-User-1.encr.cert
	echo "done."
fi
echo "PSE of user <C=DE; O=ORG-2; CN=User-1> O.K."
rm -f *.proto *.cert



echo ""
echo "******* Create User-2 of ORG-2 *******:"
echo "Create prototype PSE for  <C=DE; O=ORG-2; CN=User-2>"
psecreate -p ORG-2-User-2 $v $q $t "C=DE; O=ORG-2; CN=User-2"
echo "done."
if [ "$p" = "pem" ]
then
	echo "Certification Request" > certreq
	echo "Create PEM certification request of <C=DE; O=ORG-2; CN=User-2>"
	pem mic-clear $v $t -C -i certreq -o ORG-2-User-2.pem.proto -p ORG-2-User-2
	echo "done."
	echo "Create PEM certification reply by <C=DE; O=ORG-2>"
	pem certify $v $t -i ORG-2-User-2.pem.proto -o ORG-2-User-2.pem.cert -c ORG-2-CA
	echo "Install PEM certification reply for <C=DE; O=ORG-2; CN=User-2>"
	pem $v $t $D -i ORG-2-User-2.pem.cert -o certreply -p ORG-2-User-2 -u yes
	cmp certreq certreply
	rm certreq certreply
else 
	echo "Install PKRoot in PSE of <C=DE; O=ORG-2; CN=User-2>"
	instpkroot -p ORG-2-User-2 $v < PKRoot
	echo "done."
	echo "Install FCPath in PSE of <C=DE; O=ORG-2; CN=User-2>"
	instfcpath -p ORG-2-User-2 $v < ORG-2-CA.FCPath
	echo "done."
	echo "Create prototype certificate of <C=DE; O=ORG-2; CN=User-2>"
	getkey -p ORG-2-User-2 -s $v > ORG-2-User-2.sign.proto
	echo "done."
	echo "Sign certificate of <C=DE; O=ORG-2; CN=User-2> by <C=DE; O=ORG-2>"
	certify -c ORG-2-CA $v < ORG-2-User-2.sign.proto > ORG-2-User-2.sign.cert
	echo "done."
	echo "Install certificate in PSE of <C=DE; O=ORG-2; CN=User-2>"
	instcert $D -p ORG-2-User-2 $v -H < ORG-2-User-2.sign.cert
	echo "done."
fi
if [ "$q" = "-q" ] 
then
	echo "Same for encryption certificate of <C=DE; O=ORG-2; CN=User-2>"
	getkey -p ORG-2-User-2 -e $v > ORG-2-User-2.encr.proto
	certify -c ORG-2-CA $v < ORG-2-User-2.encr.proto > ORG-2-User-2.encr.cert
	instcert $D -p ORG-2-User-2 $v -He < ORG-2-User-2.encr.cert
	echo "done."
fi
echo "PSE of user <C=DE; O=ORG-2; CN=User-2> O.K."
rm -f *.proto *.cert *FCPath PKRoot
