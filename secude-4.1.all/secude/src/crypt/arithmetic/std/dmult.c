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

#include "double.h"

void 
_dmult(a, b, high, low)
	L_NUMBER        a, b;
	L_NUMBER       *high, *low;
{
	/* split words input parm */
	Word            A, B;

	/* split words of multiplikation */
	Word            mult, mult_0, mult_16, mult_32;

	/* move parameter */
	W(A) = a;
	W(B) = b;

	/* 1. product */
	W(mult) = LSW(A) * LSW(B);
	W(mult_0) = LSW(mult);
	W(mult_16) = HSW(mult);
	W(mult_32) = 0;

	/* 2. product, shift 16 */
	HSW(mult_32) = _cadd(LSW(A) * HSW(B),
			     HSW(A) * LSW(B),
			     &W(mult), 0
		);
	HSW(mult_32) += _cadd(W(mult), W(mult_16), &W(mult), 0);

	HSW(mult_0) = LSW(mult);
	LSW(mult_32) = HSW(mult);

	/* 3. product, shift 32 */
	W(mult_32) += HSW(A) * HSW(B);

	/* result is catenation of mult_32|mult_0 */
	*high = W(mult_32);
	*low = W(mult_0);

	return;
}
