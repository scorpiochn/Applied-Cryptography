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

/*
 *	L_NUMBER subtraction

 *
 */

#include	"arithmetic.h"

/*	A - B	*/
void 
_sub(Ap, Bp, Diff)
	register L_NUMBER *Ap, *Bp, *Diff;
{
	register L_NUMBER *opA = Ap, *Dp = Diff;
	register int    cnt, carry = 1;
	int             residual;

	if (lngofln(Ap) < lngofln(Bp))
		ALU_exception(carry);

	cnt = lngofln(Bp);
	residual = lngofln(Ap) - lngofln(Bp);

	for (; cnt > 0; cnt--)
		carry = cadd(*++Ap, ~(*++Bp), ++Diff, carry);

	for (; !carry && (residual > 0); residual--)
		carry = cadd(*++Ap, ~(0), ++Diff, 0);

	if (Diff != Ap)
		for (; residual > 0; residual--)
			*++Diff = *++Ap;

	if (carry)		/* OK */
		;
	else
		ALU_exception(carry);

	cnt = lngofln(opA);
	Diff = Dp + cnt;
	for (; (Diff > Dp) && !*Diff; Diff--)
		cnt--;

	lngofln(Dp) = cnt;

	return;
}
