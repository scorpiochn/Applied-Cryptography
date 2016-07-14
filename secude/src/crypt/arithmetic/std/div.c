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
 *	division for LNUMBERs
 *
 *	div(A,B,Q,R)
 *
 *	exceptions for zero divide
 *	benoetigt dw division cdiv(dw,d,q,r)
 */

#include	"arithmetic.h"


void 
_div(A, B, Q, R)
	L_NUMBER        A[], B[], Q[], R[];
{
	L_NUMBER        runA[MAXGENL];	/* acc for the R */
	L_NUMBER        local[MAXGENL];	/* prepare result */
	register L_NUMBER w, *Qp = Q;
	register int    i;


	if (!*B)
		ALU_exception(*B);	/* zero divide */

	i = lngtouse(A) - lngtouse(B);
	if (i < 0) {
		trans(A, R);
		if (Q != R)
			inttoln(0, Q);
		return;
	}
	trans(A, runA);
	shift(B, i, local);
	lngofln(Qp) = i / WLNG + 1;
	w = 1 << (i % WLNG);
	Qp += lngofln(Qp);
	for (; Qp > Q; Qp--) {
		*Qp = 0;
		for (; w; w >>= 1, shift(local, R1, local)) {
			if (comp(runA, local) >= 0) {
				*Qp |= w;
				sub(runA, local, runA);
			}
		}
		w = HSBIT;
	}

	normalize(Q);
	trans(runA, R);

	return;
}
