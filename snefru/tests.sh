#! /bin/sh
##
##  This is Snefru, derived from the Xerox Secure Hash Function.
##  Snefru is a one-way hash function that provides authentication.
##  It does not provide secrecy.
##
##  Snefru is named after a Pharaoh of ancient Egypt.
##
##  It is based on code that is:
##      Copyright (c) Xerox Corporation 1989.  All rights reserved.
##
##      License to copy and use this software is granted provided that it
##      is identified as the 'Xerox Secure Hash Function' in all material
##      mentioning or referencing this software or this hash function.
##
##      License is also granted to make and use derivative works provided
##      that such works are identified as 'derived from the Xerox Secure
##      Hash Function' in all material mentioning or referencing the
##      derived work.
##
##      Xerox Corporation makes no representations concerning either the
##      merchantability of this software or the suitability of this
##      software for any particular purpose.  It is provided "as is"
##      without express or implied warranty of any kind.
##
##      These notices must be retained in any copies of any part of this
##      software.
##
##  Based on the reference implementation (no algorithm changes) of
##  version 2.0, July 31, 1989.  Implementor:  Ralph C. Merkle.
##  This edition is by Rich $alz, <rsalz@bbn.com>.
##  $Header: tests.sh,v 1.1 90/03/22 13:01:34 rsalz Exp $
##
##  Script to test SNEFRU one-way hash program.
##

##  This is a pain in the neck; we (portably) want a file with only a newline
##  in it.
T=snefruT$$
cat <<\EOF >$T

EOF

trap 'exec rm -f snefru?$$' 1 2 3 15
I=snefruI$$
O=snefruO$$

echo 'Testing SNEFRU...'
echo 'If you see any unusual output, examine this script to see what failed.'
echo ''
./testboxes

echo ''
echo 'Testing known hashes...'
./snefru <$T >$O
echo '13af7619 ab98d4b5 f5e0a9e6 b26b5452' >$I
diff $O $I

echo 1 | ./snefru >$O
echo '578c83f8 8fe1f6a8 c119d2ba 3a9256c2' >$I
diff $O $I

echo 12 | ./snefru >$O
echo '255468d4 b4bd985b 696a7313 6027fc80' >$I
diff $O $I

echo 123 | ./snefru >$O
echo 'f5339a52 9c4dafc5 34fe3f0d 7a66baf7' >$I
diff $O $I

echo 1234 | ./snefru >$O
echo '2645ff86 9a6c0ec6 5c49c20d d9050165' >$I
diff $O $I

echo 12345 | ./snefru >$O
echo '387d2929 8ed52ece 88e64f38 fe4fdb11' >$I
diff $O $I

echo 123456 | ./snefru >$O
echo 'f29f8915 d23a0e02 838cc2e2 75f5dfe7' >$I
diff $O $I

echo 1234567 | ./snefru >$O
echo '4fb0f76e 9af16a2d 61844b9c e833e18f' >$I
diff $O $I

echo 12345678 | ./snefru >$O
echo 'aacc56fc 85910fef e81fc697 6b061f4e' >$I
diff $O $I

echo 123456789 | ./snefru >$O
echo 'e6997849 44ed68a1 c762ea1e 90c77967' >$I
diff $O $I

./snefru -l4 -o8 <$T >$O
echo \
 '6c504351 ce7f4b7a 93adb29a f9781ff9 2150f157 fee18661 eef511a3 0fc83ddf' >$I
diff $O $I

echo '1' | ./snefru -l4 -o8 >$O
echo \
 '65d657f8 85ad8b4a b35999cc 3ded8b82 7cf71fa4 25424750 35778910 d6c2e320' >$I
diff $O $I

echo '12' | ./snefru -l4 -o8 >$O
echo \
 '7636f3d1 af139cf9 58f46f99 66221282 a444732a 7de59da5 d3481c6b bd6e7092' >$I
diff $O $I

echo '123' | ./snefru -l4 -o8 >$O
echo \
 'cd3c7163 5b14c7c2 c24be864 4baab592 b8ab5b99 91ee5ee5 b3cf7a7f c6426ad7' >$I
diff $O $I

echo '1234' | ./snefru -l4 -o8 >$O
echo \
 '9ba783a1 290cb21e fe196a02 3286ece5 49394c75 1ddd607e 5d67c4dc 549c62eb' >$I
diff $O $I

echo '12345' | ./snefru -l4 -o8 >$O
echo \
 'c9680da8 ef00d2f8 4459a8e9 b50ada71 c63cae6f dcb6f774 f6998783 30a4a1f4' >$I
diff $O $I

echo '123456' | ./snefru -l4 -o8 >$O
echo \
 '7656d389 f980bbe8 94152abe c6dc5f16 faf21c60 3b8f5098 861acf3c c059467b' >$I
diff $O $I

echo '1234567' | ./snefru -l4 -o8 >$O
echo \
 'd96eb599 8377bb1d 74a02a2f 00ac9a85 3175250e 4796af36 36609747 372bba80' >$I
diff $O $I

echo '12345678' | ./snefru -l4 -o8 >$O
echo \
 'b7818f09 2118e98a 140af09a 6cca4e6f 1eba88e7 52c20174 653637c9 d628f33f' >$I
diff $O $I

echo '123456789' | ./snefru -l4 -o8 >$O
echo \
 'c2242249 1187baaa 94725400 08dffd5b 38f01557 9f3f2390 50969991 fdc1a810' >$I
diff $O $I


echo ''
echo 'Testing hashnews...'
cat TestArticle >snefruA$$
./hashnews -n snefruA$$
echo 'X-Checksum-Snefru: 1cb551db 1a84ad94 3d5d4267 571a9efd' >$I
grep '^X-Checksum-Snefru: ' snefruA$$ >$O
diff $O $I
./hashnews -n <TestArticle >$O
diff snefruA$$ $O

echo ''
echo 'Testing checkhash...'
checkhash snefruA$$

rm -f snefru?$$
echo ''
echo 'Done.'
