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

/* SecuDE extensions for MS-DOS */

#include "arithmetic.h"

void    add( A, B, R )
L_NUMBER        A[], B[], R[];
{
        A[0] <<= 1;
        if (B != A) B[0] <<= 1;

        ADD(A,B,R);

        A[0] >>= 1;
        if (B != A) B[0] >>= 1;
        if ((R != A) && (R != B)) R[0] >>= 1;
}


void    sub( A, B, R )
L_NUMBER        A[], B[], R[];
{
        A[0] <<= 1;
        if (B != A) B[0] <<= 1;

        SUB(A,B,R);

        A[0] >>= 1;
        if (B != A) B[0] >>= 1;
        if ((R != A) && (R != B)) R[0] >>= 1;

}

void    mult( A, B, R )
L_NUMBER        A[], B[], R[];
{
        A[0] <<= 1;
        if (B != A) B[0] <<= 1;

        MULT(A,B,R);

        A[0] >>= 1;
        if (B != A) B[0] >>= 1;
        if ((R != A) && (R != B)) R[0] >>= 1;
}


void    div( A, B, Q, R )
L_NUMBER        A[], B[], Q[], R[];
{
        A[0] <<= 1;
        if (B != A) B[0] <<= 1;

        DIV(A,B,Q,R);

        A[0] >>= 1;
        if (B != A) B[0] >>= 1;
        if ((Q != A) && (Q != B)) Q[0] >>= 1;
        if ((R != A) && (R != B) && (R != Q)) R[0] >>= 1;
}

/*
void    shift( A, B, R )
L_NUMBER        A[], R[];
int             B;
{
        A[0] <<= 1;

        SHIFT(A,B,R);

        A[0] >>= 1;
        if (R != A) R[0] >>= 1;
}

*/
