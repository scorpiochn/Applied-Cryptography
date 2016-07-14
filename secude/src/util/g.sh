#!/bin/csh -f

#-------------------------------------------------------------------------------------------
# Call gen_pse with encrypted scriptfile
#-------------------------------------------------------------------------------------------

stty -echo

echo -n Enter CA PIN': '

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
cp gen_script.enc gen_script.zw.enc
cp gen_script.key gen_script.zw.key
decrypt -p .ca/.capse gen_script.zw >& /dev/null 
if ( "$status" != "0" ) then
	if ( "$fbz" == "1" ) then
		echo "Sorry\!"
		rm -f gen_script.zw*
        	stty echo
		exit
	endif
	set fbz="1"
	echo "Wrong PIN"
	echo -n Reenter PSE PIN': '
        goto capinagain
endif
stty echo
setenv CAPIN $USERPIN
setenv USERPIN ""
gen_pse -c .ca -i gen_script.zw $*
rm -f gen_script.zw*
