/* COMBINE.C - Program to "combine" the files of a Threshhold Information
        Protection Scheme.
Author: Peter Pearson.
Version of 93.02.15.

This program is the complement of DISPERSE. See DISPERSE.C for literature
references.

This program EXITs with errorlevel 0 normally,
                                   2 if it couldn't find enough files.

Revision history:
        87.07.06 - Initial version.
        93.02.15 - Move argument names into function definitions.
*/


#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <string.h>
#include "g13.h"

#define BOOLEAN int
#define FALSE   0
#define TRUE    (1==1)

void main( int argc, char *argv[] )
{
    FILE *InputFiles[15] ;
    int Positions[15] ;
    int NumberInputs ;
    BOOLEAN InputsOK( char *FamilyName, int Positions[], FILE *InputFiles[],
                      int *RequiredPtr ) ;
    void Combine( int Positions[], FILE *InputFiles[], int NumberInputs ) ;
    int ExitCode ;

    ExitCode = 2 ;      /* Unless things go just right, return an unhappy
                           exit code.  */
    if ( argc != 2 )
    {
        fprintf( stderr,
            "Usage: COMBINE filename\n" ) ;
        fprintf( stderr,
            "where 'filename' identifies a family of files named\n" ) ;
        fprintf( stderr,
            "filename.f0, filename.f4, etc.\n" ) ;
    }
    else
    {
        if ( InputsOK( argv[1], Positions, InputFiles, &NumberInputs ) )
        {
            Combine( Positions, InputFiles, NumberInputs ) ;
            ExitCode = 0 ;
        }
    }
    exit( ExitCode ) ;
}

BOOLEAN InputsOK( char *FamilyName,     /* Input. */
                  int   Positions[],    /* Output. */
                  FILE *InputFiles[],   /* Output. */
                  int  *RequiredPtr )   /* Output. */
/*
        Try to open as many files of the input "family" as are necessary
        to reconstitute the output file.

Returns with a list of open files in the InputFiles array, and the
number in *RequiredPtr. The array Positions returns the "sequence number"
of each file within the family.

Returns:
        TRUE if everything goes OK,
        FALSE if there aren't enough input files, or some inconsistency
                is found.

Details:
        Files of the input family are expected to have names of the form
        FAMILYNAME.F1, FAMILYNAME.F2, ..., FAMILYNAME.F15.
        The first byte of each input file contains the number of files
        required to reconstitute the output file. These first bytes must all
        agree.

        The second byte of each input file gives the "sequence number"
        of that file in the family. It must be greater than zero, and must not
        be greater than the first byte.
        Neither the first byte nor the second byte may exceed 15.
        The first two bytes are read from each input file inside this
        routine.
*/
{
    char TryName[100] ;
    char FirstName[100] ;
    BOOLEAN FoundSequence[16] ;
    int i ;
    int Count ;
    int Required ;
    BOOLEAN Acceptable ;

    Count = 0 ;
    for ( i = 0; i < 16; i++ ) FoundSequence[i] = FALSE ;
    for ( i = 1; i <= 15; i++ )
    {
        sprintf( TryName, "%s.f%d", FamilyName, i ) ;
        if ( ( *InputFiles = fopen( TryName, "r" ) ) != NULL )
        {
            Acceptable = TRUE ;
            setmode( fileno( *InputFiles ), O_BINARY ) ;
            if ( Count == 0 )
            {
                if ( ( Required = getc( *InputFiles ) ) > 15
                || Required < 2 )
                {
                    fprintf( stderr,
                        "The first byte of '%s' is not what I expect."
                        " '%s' will be ignored.\n",
                        TryName, TryName ) ;
                    Acceptable = FALSE ;
                }
            }
            else if ( Required != getc( *InputFiles ) )
            {
                fprintf( stderr,
                    "Input files '%s' and '%s' come from different sets.\n",
                    FirstName, TryName ) ;
                fprintf( stderr, "'%s' will be ignored.\n", TryName ) ;
                Acceptable = FALSE ;
            }
            if ( Acceptable )
            {
                *Positions = getc( *InputFiles ) ;
                if ( *Positions < 1 || *Positions > 15 )
                {
                    fprintf( stderr,
                        "The second byte of '%s' isn't what I expect."
                        " I'll ignore '%s'.\n",
                        TryName, TryName ) ;
                    Acceptable = FALSE ;
                }
                else if ( FoundSequence[ *Positions ] )
                {
                    fprintf( stderr,
                        "'%s' has the same sequence number as somebody else."
                        " I'll ignore '%s'.\n",
                        TryName, TryName ) ;
                    Acceptable = FALSE ;
                }
            }
            if ( Acceptable )
            {
                if ( Count == 0 ) strcpy( FirstName, TryName ) ;
                FoundSequence[ *Positions ] = TRUE ;
                ++Positions ;
                ++InputFiles ;
                ++Count ;
            }
            else
            {
                fclose( *InputFiles ) ;
            }
        }
        if ( Count > 2 && Count >= Required ) break ;
    }

    if ( Count <= 0 )
    {
        fprintf( stderr, "Didn't find any input files. Sorry.\n" ) ;
        return FALSE ;
    }
    else if ( Count < Required )
    {
        fprintf( stderr, "I have %d of the %d files needed.\n",
            Count, Required ) ;
        return FALSE ;
    }
    else
    {
        *RequiredPtr = Required ;
        return TRUE ;
    }
}

void Combine( int Positions[], FILE *InputFiles[], int NumberInputs )
{
    int OddNibble ;
    BOOLEAN Odd ;
    int i ;
    int j ;
    G13 C[15] ;
    G13 c ;
    G13 Y[15] ;
    BOOLEAN FillNibbles( G13 *Nibbles, FILE *InputFiles[], int NumberInputs );

    setmode( fileno( stdout ), O_BINARY ) ;

    /* Compute the coefficients by which the nibbles from the
     * various input files can be combined to produce the output
     * file.
     *     If X(i) is the "position" of the ith input file, and
     * Y(i) is the value of a particular nibble in the ith file,
     * we will find coefficients C(i) such that
     * 
     *     p = C(1) * Y(1) + C(2) * Y(2) + ...
     * 
     * where p is the appropriate nibble for the output file.
     * 
     *     The formula for the Cs is:
     * 
     *     C(i) = product of (   X(j) / ( X(i) - X(j) )   ) for all j != i .
     * 
     * 
     */

    for ( i = 0; i < NumberInputs; i++ )
    {
        c = 1 ;
        for ( j = 0; j < NumberInputs; j++ )
            if ( j != i )
                c = Mult( c,
                        Div( Positions[j], Positions[i] ^ Positions[j] ) ) ;
        C[i] = c ;
    }

    /*
     *  Now, process the input files:
     */

    Odd = TRUE ;
    while ( FillNibbles( Y, InputFiles, NumberInputs ) )
    {
        c = 0 ;
        for ( i = 0; i < NumberInputs; i++ )
            c ^= Mult( C[i], Y[i] ) ;

        if ( Odd )
            OddNibble = c ;
        else
            putchar( ( OddNibble << 4 ) | c ) ;

        Odd = !Odd ;
    }
}

BOOLEAN FillNibbles( G13  *Nibbles,       /* Output. */
                     FILE *InputFiles[],  /* Input. */
                     int   NumberInputs ) /* Input. */
/*
        Fill the output array with nibbles, one from each
        input file.

Returns
        TRUE  normally,
        FALSE if an error or end-of-file condition is encountered.
*/
{
    static BOOLEAN Odd = TRUE ;
    static G13 Holdover[15] ;
    int c ;
    int i ;

    if ( Odd )
    {
        for ( i = 0; i < NumberInputs; i++, InputFiles++ )
        {
            if ( ( c = getc( *InputFiles ) ) == EOF )
            {
                if ( i != 0 ) fprintf( stderr,
                    "Warning: Input files weren't all the same length!\n" ) ;
                return FALSE ;
            }
            else
            {
                *Nibbles++ = ( c >> 4 ) & 0xF ;
                Holdover[i] = c & 0xF ;
            }
        }
    }
    else
    {
        for ( i = 0; i < NumberInputs; i++ )
            *Nibbles++ = Holdover[i] ;
    }
    Odd = !Odd ;
    return TRUE ;
}
