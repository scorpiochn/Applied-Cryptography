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
 *	L_NUMBER addition
 *
 */

#include	"arithmetic.h"

/*	A + B	*/
void
_add(Ap, Bp, Sum)
	register L_NUMBER *Ap, *Bp, *Sum;
{
	register L_NUMBER *Sp;
	register int    cnt, carry = 0;
	int             residual;

	if (lngofln(Ap) < lngofln(Bp))
		Sp = Bp, Bp = Ap, Ap = Sp;	/* swap operands */

	cnt = lngofln(Bp);
	residual = lngofln(Ap) - lngofln(Bp);
	Sp = Sum;
	lngofln(Sum) = lngofln(Ap);

	for (; cnt > 0; cnt--)
		carry = cadd(*++Ap, *++Bp, ++Sp, carry);

	for (; carry && (residual > 0); residual--)
		carry = cadd(*++Ap, 0, ++Sp, 1);

	if (Sp != Ap)
		for (; residual > 0; residual--)
			*++Sp = *++Ap;

	if (carry)
		(lngofln(Sum))++, Sum[lngofln(Sum)] = 1;

	return;
}
