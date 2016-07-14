/*
 *  SecuDE Release 4.1 (GMD)
 */
/********************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

/*------------------------------------------------------------+-----*/
/*                                                            ! GMD */
/*   ARITHMETIC for LONG INTEGER    V2.0                      +-----*/
/*                                                                  */
/*------------------------------------------------------------------*/
/*                                                                  */
/*    INCLUDE  <arithmetic.h>                                       */
/*                                        DATE 01.06.90             */
/*                                                                  */
/*    Note:                                                         */
/*      arithmetic.h uses option                                    */
/*      -DWLNGxx (xx = 16 bzw 32) (word length of the processor)    */
/*                                                                  */
/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/
/* L_NUMBER definition                                              */
/*------------------------------------------------------------------*/

#ifndef MAC
typedef unsigned  L_NUMBER;
#else
typedef unsigned long L_NUMBER;
#endif /* MAC */

/*------------------------------------------------------------------*
 *      A multi-precision integer number is stored and processed in *
 *      an array of unsigned long integers. The maximum length of   *
 *      the array is MAXLGTH.                                       *
 *                                                                  *
 *      MP Integer ::=  L_NUMBER [MAXLGTH]                          *
 *                                                                  *
 *      The first element (L_NUMBER[0]) indicates the number of     *
 *      following words which contain the MP integer, starting with *
 *      with MSBYTE and MSBIT left.                                 *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 * Definitions of constants depending on the worg length            *
 *------------------------------------------------------------------*/

#define  BYTEL          8       /* bits per byte                    */

#ifdef WLNG32                   /* word length 32 bits              */
 
#define  MAXGENL        132     /* Maximum L_NUMBER used during 
                                   key generation (in words)        */
#define  MAXLGTH        66      /* Maximum L_NUMBER else            */
#define  WLNG           32      /* word length in bits              */
#define  WBYTES         4       /* bytes per word                   */
#define  SWBYTES        2       /* << SWBYTES = WBYTES  times 4     */
#define  SWBITS         5       /* << SWBITS = WLNG                 */
#define  HSBIT  0x80000000
#define  HSBYTE 0xFF000000

#endif

#ifdef WLNG16                   /* word length 16 bits              */

#define  MAXGENL        132     /* Maximum L_NUMBER used during 
                                   key generation (in words)        */
#define  MAXLGTH        264     /* Maximum L_NUMBER else            */
#define  WLNG           16      /* word length in bits              */
#define  WBYTES         2       /* bytes per word                   */
#define  SWBYTES        1       /* << SWBYTES = WBYTES  times 2     */
#define  SWBITS         4       /* << SWBITS = WLNG                 */
#define  HSBIT  0x8000
#define  HSBYTE 0xFF00

#endif


#ifndef WLNG
#include "-DWLNGxx Option fehlt!" /* Test ob die -DWLNGxx          */
                                  /* Option  gesetzt wurde         */
#endif                            /* (siehe Header)                */



/*-----------------------------------------------------------------*
 * Definition of shift factors                                     *
 *-----------------------------------------------------------------*/

#define    R1   - 1
#define    R4   - 4
#define    R8   - 8
#define    R16  -16
#define    L1     1
#define    L4     4
#define    L8     8
#define    L16   16



#define   LNUMBER



/*---------------------------------------------------------------*
 *  Global L_NUMBERs                                             *
 *---------------------------------------------------------------*/

#define   LZ_NULL     { 0 }
#define   LZ_EINS     { 1, 1 }
#define   LZ_ZWEI     { 1, 2 }
extern    L_NUMBER    lz_null[];
extern    L_NUMBER    lz_eins[];
extern    L_NUMBER    lz_zwei[];

#ifdef WLNG32
#define   LZ_FERMAT5  { 1, 0x10001 }
#endif

#ifdef WLNG16
#define   LZ_FERMAT5  { 2, 1, 1 }
#endif


/*-------------------------------------------------------------*
 *  Function declarations                                      *
 *-------------------------------------------------------------*/

int             lngtouse();

/*
 *      L_NUMBER addition/subtraction/division
 *
 */

#define ALU_exception(x)        (x%0)   /* TRAP */

#define trans(From,To)  _trans(From,To)
#define comp(A,B)               _comp(A,B)
#ifndef MS_DOS
#define add(A,B,Sum)    _add(A,B,Sum)
#define sub(A,B,Diff)   _sub(A,B,Diff)
#define mult(A,B,AB)    _mult(A,B,AB)
#define div(A,B,Q,R)    _div(A,B,Q,R)
#define normalize(N)    { L_NUMBER zero = 0; _sub(N,&zero,N); }
#else
/* skip defines for asm routines **
define add             ADD
define sub             SUB
define mult            MULT
define div             DIV
define shift           SHIFT
*/
#define normalize(N)    { L_NUMBER zero = 0; SUB(N,&zero,N); }
#endif
#define cadd(A,B,A_B,c) _cadd(A,B,A_B,c)
#define dmult(a,b,ab0,ab1)      _dmult(a,b,ab0,ab1)
#define ddiv(a1,a0,b,q,r)       _ddiv(a1,a0,b,q,r)
#define xor(a,b,x)      _xor(a,b,x)
#define shift(A,I,B)    _shift(A,I,B)


/*      define _trans macro inline expanded */
#define _trans(src,dst) { register L_NUMBER *stop,*dp = (dst), *sp = (src); \
                          if( sp != dp ) {stop = sp;    \
                          for( dp = dp+*sp, sp = sp+*sp; sp >= stop; ) *dp-- = *sp--; \
                        } }
#define inttoln(I,LI)   ( (I)? ( *(LI) = 1, *((LI)+1) = (I) ) : (*(LI) = 0) )
#define lntoint(L)      (*(L)? ( *((L)+1) ) : 0)
#define checkln(L)      (*(L)? (-(*((L)+*(L))==0) : 0)
#define lngofln(L)      (*(L))
#define lntoINTEGER(L,I)        lntoctets(L,I,0)
#define INTEGERtoln(I,L)        octetstoln(I,L,0,(*(I)).noctets)

