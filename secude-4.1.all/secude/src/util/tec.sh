#!/bin/csh -f

#-------------------------------------------------------------------------------------------
# Edit encrypted file with textedit
#-------------------------------------------------------------------------------------------

stty -echo

cp $1.enc $1.zw.enc
if ( "$status" != "0" ) then
       	stty echo
	exit
endif
cp $1.key $1.zw.key
if ( "$status" != "0" ) then
	rm -f $1.zw*
       	stty echo
	exit
endif

echo -n Enter PSE PIN': '

set fbz="0"

capinagain:

set capin=$<
echo ""
if ( "$capin" == "exit" ) then
        stty echo
	rm -f zw_script*
        exit
endif
setenv USERPIN $capin
decrypt -c .ca $1.zw >& /dev/null 
if ( "$status" != "0" ) then
	if ( "$fbz" == "1" ) then
		echo "Sorry\!"
		rm -f $1.zw*
        	stty echo
		exit
	endif
	set fbz="1"
	echo "Wrong PIN"
	echo -n Reenter PSE PIN': '
        goto capinagain
endif
stty echo
textedit $1.zw
encrypt -c .ca $1.zw
cp $1.zw.enc $1.enc
cp $1.zw.key $1.key
rm -f $1.zw*
