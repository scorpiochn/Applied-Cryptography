rem Batch file to compile RIPEM vanilla DOS version w/ MS C 7.0
rem Run this from the RIPEM directory.
cd rsaref\test
nmake -f rsaref.mak
if errorlevel 1 goto err
cd ..\..\main
nmake -f ripem.mak
if errorlevel 1 goto err
cd ..\test
call dostest
goto done
:err
echo *** Unsuccessful build of RIPEM!
:done
