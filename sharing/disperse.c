/* DISPERSE.C - Program to "disperse" the information from an
input file into a number of output files.
Author: Peter Pearson.
Version of 93.02.15.

This program implements a "Threshhold Information Protection Scheme",
as described in D.E.R. Denning, Cryptography and Data Security, pp. 179 -
182. Since I had a byte-oriented mind, I chose to use arithmetic
over 4-bit entities (GF(2^4)), which allows dispersal into as many
as 15 files but still allows multiplication and division to be performed
by table lookup.

So, the general scheme is this: From the original plaintext file,
W "shadow" files are produced, any T of which can be "combined" to
reproduce the original plaintext file. (W and T are integers of the
user's choice, not to exceed 15.) The assertion of this package is that
it is impossible to derive the original plaintext file from any T-1
of the "shadow" files. (The validity of that assertion depends solely
and vitally on the inscrutability of the random numbers used by the
dispersal algorithm.)

At a more detailed level: The plaintext file is read nibble-by-nibble,
a nibble being 4 bits. For each nibble P read from the plaintext file,
one nibble is written into each "shadow" file, according to this recipe:
T-1 4-bit coefficients C(i), 0 < i < T, are chosen randomly. For "shadow"
file number j, 0 < j <= W, we compute the polynomial

        y = P + C(1) * j + C(2) * j**2 + ... + C(T-1) * j**(T-1),

using GF(2^4) arithmetic, and write it into the "shadow" file.
Reconstruction of the plaintext file is possible because, given the
corresponding nibble from each of T of the shadow files, you have T
(j, y) points on a polynomial of degree T-1, and can determine the
polynomial completely. (GF(2^4) arithmetic has the attractive features
of limiting all numbers to 4 bits while preserving all the algebraic
properties necessary for familiar polynomial interpolation.)

Final detail: Each shadow file must include two crucial parameters
of the particular "dispersal": (1) the number, T, of shadow files
needed for reconstruction; and (2) the index "j" that was used in
computing the nibbles written into that particular shadow file.
These two values are written into the first two bytes of the shadow
file.

Revision history:
        87.07.06 - Initial version.
        93.02.15 - Moved arg types into function definitions.

*/

#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "g13.h"

#define BOOLEAN int
#define FALSE   0
#define TRUE    (1==1)

void main( int argc, char *argv[] )
{
    BOOLEAN Help ;
    char FileName[100] ;
    int  Total ;
    int  Required ;
    void Disperse( char *FileName, int Total, int Required ) ;

    srand((unsigned)(time(0) & 0xffff));
    FileName[0] = '\0' ;
    Total = 0 ;
    Required = 0 ;

    Help = ( argc != 4 ) ;
    if ( Help == FALSE )
    {
        strcpy( FileName, *++argv ) ;
        if ( sscanf( *++argv, "%d", &Total ) != 1 
        ||   sscanf( *++argv, "%d", &Required ) != 1 )
                        Help = TRUE ;
    }
    if ( Help )
    {
     fprintf( stderr, 
              "Usage:\n    DISPERSE filename 5 3\n" ) ;
     fprintf( stderr, 
              "where\n    filename is the name of the input file,\n" ) ;
     fprintf( stderr, 
              "    5 is the total number of files to be output,\n" ) ;
     fprintf( stderr, 
              "    3 is the number of files required for reconstruction.\n" ) ;
    }
    else
    {
        if ( Total < Required )
        {
            int Temp ;

            Temp = Total ;
            Total = Required ;
            Required = Temp ;
            fprintf( stderr,
                "(I assume you mean %d files total and", Total ) ;
            fprintf( stderr,
                " %d files required for reconstruction.)\r\n", Required ) ;
        }
        Disperse( FileName, Total, Required ) ;
    }
}

BOOLEAN ArgsOK( char *FileName, int Total, int Required )
{
    BOOLEAN ArgError ;

    ArgError = FALSE ;
    if ( FileName[0] == '\0' )
    {
        ArgError = TRUE ;
        fprintf( stderr, "You must specify a non-null file name.\n" ) ;
    }
    if ( Total < 2 || Total > 15 || Required < 2 || Required > 15 )
    {
        ArgError = TRUE ;
        fprintf( stderr,
            "Both Total and Required file numbers must be in 2 .. 15.\n" ) ;
    }
    if ( Total < Required )
    {
        ArgError = TRUE ;
        fprintf( stderr,
            "Required File Number cannot exceed Total File Number.\n" ) ;
    }
    return ( ArgError == FALSE ) ;
}

BOOLEAN CreatedOutput( char *FileName, int Number, FILE *FileList[] )
/*
        Create several output files with names derived from one
        specified name.

Returns:
        TRUE if everything went OK,
        FALSE if something went wrong. (An error message has been issued.)

Algorithm:
        We strip the FileName of any leading "\xxx\xxx" and any
        trailing ".ext", and append .f0, .f1, .f2, et cetera.

        If a file exists already with any of these names, it will
        be overwritten.
*/
{
    int  i ;
    char Stripped[100] ;
    char NewName[100] ;
    void Strip( char *Stripped, char *Full ) ;

    Strip( Stripped, FileName ) ;
    if ( Stripped[0] == '\0' )
    {
        fprintf( stderr,
            "There's something wrong with the input file name.\n" ) ;
        return FALSE ;
    }

    for ( i = 0; i < Number; i++ )
    {
        sprintf( NewName, "%s.f%d", Stripped, i+1 ) ;
        fprintf( stderr, "Creating file %s.\n", NewName ) ;
        FileList[i] = fopen( NewName, "w" ) ;
        if ( FileList[i] == NULL )
        {
            fprintf( stderr,
                "Sorry, I had trouble creating the %dth output file.\n",
                i ) ;
            return FALSE ;
        }
        setmode( fileno( FileList[i] ), O_BINARY ) ;
    }
    return TRUE ;
}

void Disperse( char *FileName, int Total, int Required )
{
    int Byte ;
    G13 HighNibble[15] ;
    G13 LowNibble[15] ;
    int i ;
    FILE *OutFile[15] ;
    FILE *InFile ;
    long StartTime ;
    long EndTime ;
    long ByteCount ;
    BOOLEAN ArgsOK( char *FileName, int Total, int Required ) ;
    FILE *OpenedInput( char * ) ;
    BOOLEAN CreatedOutput( char *, int, FILE * * ) ;
    void Process( int Nibble, int *OutArray, int Total, int Required ) ;

    if ( ArgsOK( FileName, Total, Required )
    &&   ( InFile = OpenedInput( FileName ) ) != NULL
    &&   CreatedOutput( FileName, Total, OutFile ) )
    {
        ByteCount = 0 ;
        StartTime = time( NULL ) ;

        for ( i = 0; i < Total; i++ )
        {
            putc( Required, OutFile[i] ) ; /* Say how many files required. */
            putc( i+1     , OutFile[i] ) ; /* Say which file this is.      */
        }

        while ( ( Byte = getc( InFile ) ) != EOF )
        {
            ++ByteCount ;
            Process( Byte >> 4, HighNibble, Total, Required ) ;
            Process( Byte     , LowNibble,  Total, Required ) ;
            for ( i = 0; i < Total; i++ )
                putc( ( HighNibble[i] << 4 ) + LowNibble[i], OutFile[i] ) ;
        }
        EndTime = time( NULL ) ;
        if ( EndTime > StartTime )
            fprintf( stderr, "\
%ld seconds elapsed time.\r\n\
%ld bytes read, %ld bytes written.\r\n\
%d bytes read per second, %d bytes written per second.\r\n",
                EndTime - StartTime,
                ByteCount, Total * ByteCount,
                (int) ( ByteCount / ( EndTime - StartTime ) ),
                (int) ( ( Total * ByteCount ) / ( EndTime - StartTime ) ) ) ;
    }
}

FILE *OpenedInput( char *FileName )
{
    FILE *F ;

    if ( ( F = fopen( FileName, "r" ) ) == NULL )
        fprintf( stderr, "Error opening file \"%s\" for input.\n",
            FileName ) ;
    setmode( fileno( F ), O_BINARY ) ;
    return F ;
}

void Process( int Nibble, int *OutArray, int Total, int Required )
/*
        Given one nibble of the input file, fill an array with
        the values that go into the output files.
*/
{
    G13 C[15] ;
    int i ;
    int j ;
    G13 y ;
    G13 Rand4( void ) ;

    C[0] = Nibble & 0xF ;
    for ( i = 1; i < Required; i++ ) C[i] = Rand4() ;
    for ( i = 1; i <= Total; i++ )
    {
        y = C[ Required-1 ] ;
        for ( j = Required-2 ; j >= 0 ; j-- ) y = C[j] ^ Mult( i, y ) ;
        *OutArray++ = y ;
    }
}

G13 Rand4( void )
/*
        Return a random G13-thing (4-bits).

Important note:
        The output from this program will resist intelligent, informed
        cryptanalysis only to the extent that the random number sequence
        resists analysis. If the random number sequence is truly random,
        as could be achieved by attaching special hardware to your
        computer, then the output from this program will resist decryption
        even by an infinitely-intelligent cryptanalyst knowing all the
        algorithms involved.
            Such perfection is not likely to be achieved. Second-best is
        a pseudorandom-number generator whose future outputs cannot be
        predicted even when given a long sequence of past outputs. Any
        encryption scheme (e.g. DES) resistant to known-plaintext attack
        might be harnessed to this purpose.

            This version of this program, however, settles for a very
        predictable pseudorandom-number generator.
*/
{
    return ( rand() >> 11 ) & 0xF ;
}

void Strip( char *Stripped, char *Full )
/*
        Strip a file name of preceding directory-path information
        (\xxxx\xxxx\xxx\) and trailing "extension" information (.ext).

        Stripped : output
        Full     : input
*/
{
    char *fp ;
    char *sp ;

    sp = Full ;
    for ( fp = Full ; *fp ; ) if ( *fp++ == '\\' ) sp = fp ;
    while ( *sp && *sp != '.' ) *Stripped++ = *sp++ ;
    *Stripped = '\0' ;
}
