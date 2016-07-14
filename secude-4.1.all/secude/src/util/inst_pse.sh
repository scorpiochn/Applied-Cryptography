#!/bin/csh -f -e
#
#  SecuDE Release 4.1 (GMD)
#
# inst_pse - installs a PSE which was previously generated with gen_pse

umask 0077

if ( "$1" != "" ) then
        set dir=`decode -r <"$1" | uncompress | tar tf - | line`
else
        echo Error: file argument missing
        exit
endif
echo $dir
if ( -f ~/$dir || -d ~/$dir ) then
        echo $dir exists already in the home directory
        echo -n Overwrite \? \(y/n\)': '
        set answer=$<
        if ( "$answer" != "y" ) then
                echo $dir unchanged
                exit
        endif
        rm -rf ~/$dir
endif

decode -r <"$1" | uncompress | ( cd ~; tar xvf - )

echo PSE $dir installed in the home directory. 
#echo Now change the transport PIN to your personal PIN
#psemaint -p $dir challpin
