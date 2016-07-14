gcc -c -O3 -I../source ../source/desc.c
gcc -c -O3 -I../source ../source/digit.c
gcc -c -O3 -I../source ../source/md2c.c
gcc -c -O3 -I../source ../source/md5c.c
copy ..\source\nn-386.s ..\source\nn.s
gcc -c -O3 -I../source ../source/nn.s
gcc -c -O3 -I../source ../source/prime.c
gcc -c -O3 -I../source ../source/r_encode.c
gcc -c -O3 -I../source ../source/r_enhanc.c
gcc -c -O3 -I../source ../source/r_keygen.c
gcc -c -O3 -I../source ../source/r_random.c
gcc -c -O3 -I../source ../source/r_stdlib.c
gcc -c -O3 -I../source ../source/rsa.c
ar rvs rsaref.a *.o
