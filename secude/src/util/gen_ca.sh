#!/bin/csh -f -e
#
#  SecuDE Release 4.0 (GMD)
#
#-------------------------------------------------------------------------------------------
#	gen_pse	-	generate CA directory including PSE
#-------------------------------------------------------------------------------------------

set subjects
set current=`pwd`
set cadir=`basename $current`
set capsename=.pse
set cadirflag
set capseflag
set interactive
set v
set par
set s
foreach par ($*) 
        switch($par)
           case -i:
                set interactive=$par
                breaksw
           case -v:
                set v=$par
                breaksw
           case -c:
                set cadirflag=y
                breaksw
           case -p:
                set capseflag=y
                breaksw
           case subjectlist:
                set s=$par
                breaksw
           default:
                if ( $cadirflag == y ) then
                        set cadir=$par
                        set cadirflag
                else if ( $capseflag == y ) then
                        set capsename=$par
                        set capseflag
                else
                        set subjects=$par
                endif
        endsw
end
again:

cd $HOME

echo Generating CA directory ...

cadiragain:

#-------------------------------------------------------------------------------------------
# Check and cd to $cadir, create genpse, if necessary
# Default: .ca under $HOME
#-------------------------------------------------------------------------------------------
 
if (! -d $cadir ) then
	echo CA directory $cadir does not exist.
	exit
endif
cd $cadir

if (! -d genpse ) then
        mkdir genpse
endif
cd genpse

#-------------------------------------------------------------------------------------------
# Enter the PIN of the CA's PSE
# and print CA Name
#-------------------------------------------------------------------------------------------

if ( $s != subjectlist ) then
        stty -echo

capinagain:

        echo -n Enter CA PIN of $cadir': '
        set capin=$<
        echo ""
        if ( "$capin" == "exit" ) then
                stty echo
                exit
        endif
        setenv USERPIN $capin
        set caname=`psemaint -p $cadir/.pse sh Name`
        if ( "$status" != "0" ) then
                goto capinagain
        endif
        stty echo
        setenv USERPIN ""
        setenv CAPIN "$capin"
        setenv CANAME "$caname"

        echo CA Name: \<$caname\>
endif

#-------------------------------------------------------------------------------------------
# Enter the name of the issuer's signature algorithm (default: md5WithRsa)
# Algorithm is read from genpse/.issueralg, if existing, or stdin
# Option -i allows updating of genpse/.issueralg and genpse/.keysize
# Issueralg is only necessary if the issuer's signature key (i. e. the issuer's SignSK)
# has RSA as algorithm identifier. Otherwise, i.e. if the issuer's signature key has one
# of the signature algorithms md2WithRsa, md4WithRsa etc., that algorithm is used
# for producing the issuer's signature in the certificates.
#-------------------------------------------------------------------------------------------

if ( -f .issueralg ) then
        set issueralg=`cat .issueralg`
endif
if ( ! -f .issueralg || "$interactive" == "-i" ) then
        if ( -f .issueralg ) then
                echo Change the issuer\'s signature algorithm $issueralg \(CR for unchanged\). Enter one of
        else
                echo Enter the issuer\'s signature algorithm \(CR for md5WithRsa\). Enter one of
                set issueralg="md5WithRsa"
        endif
        algs -t SIG
        echo -n ': '
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set issueralg="$answer"
        endif
        echo $issueralg >.issueralg
endif


#-------------------------------------------------------------------------------------------
# Enter the name of the subject's signature algorithm (default: RSA)
# and set keysize (default: 512)
# Algorithm is read from genpse/.subjalg, if existing, or stdin
# Keysize is read from genpse/.keysize, if existing, or stdin
# Option -i allows updating of genpse/.subjalg and genpse/.keysize
#-------------------------------------------------------------------------------------------

if ( -f .subjalg ) then
        set subjalg=`cat .subjalg`
endif
if ( ! -f .subjalg || "$interactive" == "-i" ) then
        if ( -f .subjalg ) then
                echo Change the subject\'s signature algorithm $subjalg \(CR for unchanged\). Enter one of
        else
                echo Enter the subject\'s signature algorithm \(CR for RSA\). Enter one of
                set subjalg="RSA"
        endif
	algs -t ASYM_ENC
        algs -t SIG
        echo -n ': '
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set subjalg="$answer"
        endif
        echo $subjalg >.subjalg
endif

if ( -f .keysize ) then
        set keysize=`cat .keysize`
endif
if ( ! -f .keysize  || "$interactive" == "-i" ) then
        if ( -f .keysize ) then
                echo -n Change the subject\'s signature keysize $keysize \(CR for unchanged\)': '
        else
                echo -n Enter the subject\'s signature keysize \(CR for 512\)': '
                set keysize=512
        endif
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set keysize="$answer"
        endif
        echo $keysize >.keysize
endif

set encalg=RSA

#-------------------------------------------------------------------------------------------
# Enter the name of the subject's CA directory (read from genpse/.cadir, if existing, or stdin)
# Default: .ca
#-------------------------------------------------------------------------------------------

if ( -f .cadir ) then
        set scadir=`cat .cadir`
endif
if ( ! -f .cadir || "$interactive" == "-i" ) then
        if ( -f .cadir ) then
                echo -n Change the name of subject\'s CA directory "$scadir" \(CR for unchanged\)': '
        else
                echo -n Enter the name of subject\'s CA directory \(CR for .ca\)': '
                set scadir=.ca
        endif
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set scadir="$answer"
        endif
        echo $scadir >.cadir
endif

#-------------------------------------------------------------------------------------------
# Enter the name of the subject's PSE (read from genpse/.psename, if existing, or stdin)
# Default: .pse
#-------------------------------------------------------------------------------------------

if ( -f .psename ) then
        set psename=`cat .psename`
endif
if ( ! -f .psename  || "$interactive" == "-i" ) then
        if ( -f .psename ) then
                echo -n Change the name of subject\'s PSE "$psename" \(CR for unchanged\)': '
        else
                echo -n Enter the name of subject\'s PSE \(CR for .pse\)': '
                set psename=.pse
        endif
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set psename="$answer"
        endif
        echo $psename >.psename
endif

#-------------------------------------------------------------------------------------------
# Enter the subject's Name
# This is divided into a prefix (read from from genpse/.nameprefix, if existing, or stdin)
# and a suffix (e.g. the common name or surname)
# Option -i allows updating of genpse/.nameprefix
#-------------------------------------------------------------------------------------------


set nameprefix=""
if ( -f .nameprefix) then
        set nameprefix=`cat .nameprefix`
endif

nextsubject:

if ( ! -f .nameprefix || "$interactive" == "-i" ) then
        if ( -f .nameprefix) then
                echo Change prefix of the subject\'s directory name "$nameprefix" \(CR for unchanged\)': '
        else
                echo -n Enter prefix of the subject\'s directory name \(e.g. C=DE\; O=GMD\; CN=\)': '
        endif
        set answer=$<
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "" ) then
                set nameprefix="$answer"
        endif
        echo $nameprefix >.nameprefix
endif

if ( "$subjects" != "" ) then
        if ( -f "$subjects" ) then
                echo exit >> $subjects
                sh -c "gen_pse -c $cadir -p $capsename subjectlist $v" < $subjects
                exit
        else
                echo Can\'t open $subjects
                exit
        endif
endif
if ( $s != subjectlist ) then
        echo -n Complete subject\'s directory name \<$nameprefix
endif

set namesuffix=$<

if ( "$namesuffix" == "exit" ) then
        exit
endif
set Name="$nameprefix$namesuffix"
set SName=\'"$Name"\'

#-------------------------------------------------------------------------------------------
# Enter the transport PIN of the user PSE
#-------------------------------------------------------------------------------------------

stty -echo
if ( $s != subjectlist ) then
        echo -n Enter subject\'s transport PIN': '
endif

set userpin=$<

echo ""
if ( "$userpin" == "exit" ) then
        stty echo
        exit
endif
stty echo

#-------------------------------------------------------------------------------------------
# Ask if all is o.k. (if option -i)
#-------------------------------------------------------------------------------------------
                     
echo ""
echo Generating CA directory $scadir for \<$Name\> with PSE $scadir/$psename
echo Subject\'s signature algorithm is $subjalg
echo Public keys will be certified by CA \<$CANAME\> with PSE $cadir/.pse
if ( "$interactive" == "-i" ) then
        echo -n Correct \(y/n/exit\)'? '
        set answer=$< 
        if ( "$answer" == "exit" ) then
                exit
        endif
        if ( "$answer" != "y" ) then
                goto again
        endif
else
	echo ' '
endif

setenv USERPIN $userpin

set pwd=`pwd`
if ( -d $scadir ) then
        rm -rf $scadir
endif

#-------------------------------------------------------------------------------------------
# Create subject's CA directory under $cadir/genpse (temporary)
#-------------------------------------------------------------------------------------------

sh -c "HOME=$pwd cacreate -c $scadir -p $psename $v $SName"

#-------------------------------------------------------------------------------------------
# Get PKRoot from CA's PSE and install it on subject's PSE
#-------------------------------------------------------------------------------------------

getpkroot -c $cadir -p $capsename $v | sh -c "HOME=$pwd instpkroot -c $scadir -p $psename $v"

#-------------------------------------------------------------------------------------------
# Get FCPath from CA's PSE and install it on subject's PSE
#-------------------------------------------------------------------------------------------

if ( -f ../$capsename/SignCSet || -f ../$capsename/SignCSet.sf ) then
        getfcpath -c $cadir -p $capsename $v | sh -c "HOME=$pwd instfcpath -c $scadir -p $psename $v"
endif

#-------------------------------------------------------------------------------------------
# Generate subject's signature keys
# Certify by CA
# Install SignCert and SignCSet in subject's PSE
#-------------------------------------------------------------------------------------------

sh -c "HOME=$pwd genkey -s $subjalg -k $keysize -c $scadir -p $psename $v" | certify -c $cadir -p $capsename $v -a $issueralg | sh -c "HOME=$pwd instcert -c $scadir -p $psename -h $v"

#-------------------------------------------------------------------------------------------
# Generate subject's encryption keys
# Certify by CA
# Install EncCert and EncCSet in subject's PSE
#-------------------------------------------------------------------------------------------

sh -c "HOME=$pwd genkey -e $encalg -k $keysize -c $scadir -p $psename $v" | certify -c $cadir -p $capsename $v -a $issueralg | sh -c "HOME=$pwd instcert -c $scadir -p $psename -he $v"

#-------------------------------------------------------------------------------------------
# Generate encoded tar-file of subject's PSE
#-------------------------------------------------------------------------------------------

tar cf - $scadir | compress | encode -r >"$namesuffix"
chmod a+r "$namesuffix"
echo The CA directory for \<$Name\> is in file $cadir/genpse/\"$namesuffix\" as encoded tar file.

#-------------------------------------------------------------------------------------------
# Generation successful
# Next subject
#-------------------------------------------------------------------------------------------

rm -rf $scadir
if ( $s != subjectlist ) then
        echo ""
        echo Next subject ...
endif
goto nextsubject

