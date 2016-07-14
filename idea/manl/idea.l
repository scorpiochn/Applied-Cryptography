.TH IDEA 1 "April 16, 1992"
.GN 2
.SH NAME
idea \- encrypt and decrypt using IDEA
.SH SYNOPSIS
.TP
.B idea
[
.B \-e
|
.B \-d
] [
.B \-r
] [
.B \-ecb
|
.B \-cbc\c
.I N
|
.B \-cfb\c
.I N
|
.B \-ofb\c
.I N
] 
.br
(
.B \-k
.I keyString
|
.B \-K
.I keyHexString
) 
.br
[
.I inputFile
[
.I ouputFile
] ]
.TP
.B idea
[
.B \-h
|
.B \-H
] [
.B \-tan
|
.B \-abr
] 
.br
[
.B \-k
.I keyString
|
.B \-K
.I keyHexString
] 
.br
[
.I inputFile
[ [
.I ouputFile
]
.I hashvalFile
]
.SH DESCRIPTION
.I Idea
reads
.I inputFile
and writes the en/decrypted data to
.I outputFile
or writes the hash value to
.I hashvalFile\c
\&.
If file name is not given in command line, 
.I idea 
uses standard input or output.
If the input file name is given as '-', 
.I idea 
reads from the standard input.
.br

.br
.B IDEA 
(International Data Encryption Algorithm) is a block cipher developed
by Xuejia Lai and Prof. Dr. J. L. Massey at the Swiss Federal Institute of Technology.
.SH OPTIONS
.TP
.B \-e
Encrypt data. (default)
.TP
.B \-d 
Decrypt data.
.TP
.B \-r 
.I InputFile 
is a raster-file.
.TP
.B \-k 
Key is specified with 
.I keyString\c
\&.
.TP
.B \-K 
Key and initial values are specified with 
.I keyHexString\c
\&.
.TP
.B \-h 
Compute a 128 bit hash value from the input data. The
hash value is written to 
.I hashvalFile
(or standard output).
.TP
.B \-H 
Compute a 128 bit hash value from the input data. The input is copied to 
.I outputFile
(or standard output) and the hash value is written to 
.I hashvalFile
(or standard error).
.TP
.B Notation:
.br
N           = interleave factor (1 is default)
.br
z           = 128 bit key
.br
x[i]        = 64 bit plaintext block
.br
y[i]        = 64 bit ciphertext block
.br
x[1]..x[L]  = plaintext (last block is filled with zeros)
.br
x[L+1]      = length of plaintext in bits
.br
y[1]..y[L+1]= ciphertext
.br
IDEA(z, .)  = encryption function
.br
IIDEA(z, .) = decryption function
.br
x = IIDEA(z, IDEA(z ,x))          
.TP
.B Encryption / Decrypion Modes:
.TP
.B \-ecb 
electronic code book mode
.br
y[i] = IDEA(z, x[i])
.br
x[i] = IIDEA(z, y[i])
.TP
.B \-cbc 
cipher block chaining mode (cbc1 is default)
.br
y[i] = IDEA(z, x[i] ^ y[i-N])
.br
x[i] = IIDEA(z, y[i]) ^ y[i-N]
.TP
.B \-cfb 
ciphertext feedback mode
.br
y[i] = x[i] ^ IDEA(z, y[i-N])
.br
x[i] = y[i] ^ IDEA(z, y[i-N])
.TP
.B \-ofb 
output feedback mode
.br
h[i] = IDEA(z, h[i-N])
.br
y[i] = x[i] ^ h[i]
.br
x[i] = y[i] ^ h[i]
.TP
.B Hash Functions:
.br
If no key is given, 
.I idea 
uses the all zero key.
.br
hash value = h[L+1] * 2**64 + g[L+1]
.br
h[0] = z / 2**64
.br
g[0] = z % 2**64
.TP
.B \-tan 
tandem DM-scheme (default)
.br
w = IDEA(g[i-1] * 2**64 + x[i], h[i-1])
.br
h[i] = h[i-1] ^ w
.br
g[i] = g[i-1] ^ IDEA(x[i] * 2**64 + w, g[i-1])
.TP
.B \-abr 
abreast DM-scheme
.br
h[i] = h[i-1] ^ IDEA(g[i-1] * 2**64 + x[i], h[i-1])
.br
g[i] = g[i-1] ^ IDEA(x[i] * 2**64 + h[i-1], ~ g[i-1])
.TP
.B Key Formats:
.br
.I keyHexString
= { '0'..'9' | 'a'..'f' | 'A'..'F' | ':' } 
.br
.I keyHexString
= z:y[1-N]:y[2-N]:y[3-N]..
.br
.I keyString
= { '!'..'~' } = z
.SH EXAMPLES
To encrypt and decrypt a file in cipher block chaining mode with 
an interleave factor of 8:
.LP
.RS
.nf
.ft B
idea -e -cbc8 -K 12345:67:89::ab:cDEf data data.cr
idea -d -cbc8 -K 12345:67:89::ab:cDef data.cr data.ori
data and data.ori are identical
.ft R
.fi
.RE
.br
.ne 10
.LP
To compute the hash value with tandem DM-scheme:
.LP
.RS
.nf
.ft B
idea -h data
.ft R
.fi
.RE
.br
.ne 10
.LP
To compute the hash value and encrypt the data in one step:
.LP
.RS
.nf
.ft B
idea -Hk "k e y" data | idea -K 123:9a::eF - data.cr
.ft R
.fi
.RE
.SH PATENT
IDEA is registered as the international patent WO 91/18459 
"Device for Converting a Digital Block and the Use thereof". 
For commercial use of IDEA, one should contact
.br

.br
ASCOM TECH AG
.br
Freiburgstrasse 370
.br
CH-3018 Bern, Switzerland
.SH AUTHOR
Richard De Moliner (demoliner@isi.ethz.ch)
.br
Signal and Information Processing Laboratory
.br
Swiss Federal Institute of Technology
.br
CH-8092 Zurich, Switzerland
.SH BUGS
This program is at most as strong as IDEA itself. So, we urge the user to 
use this program only after he has assured himself that IDEA is strong 
enough AND he has read the source code of this program and its libraries AND 
he has compiled the program himself with a troyan-free compiler. WE DO NOT 
GUARANTEE THAT THIS PROGRAM IS A DECENT ENCRYPTION PROGRAM.
