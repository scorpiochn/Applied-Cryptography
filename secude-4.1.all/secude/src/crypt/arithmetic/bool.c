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

/*      xor()           exclusiv oder zweier 'Langer Zahlen'   */

#include "arithmetic.h"

#define  XOR  ^


void  _xor (op1,op2,erg)

register L_NUMBER   op1[];
register L_NUMBER   op2[];
register L_NUMBER   erg[];

{

   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/

	register int i;  /* Schleifenzaehler                   */
	register int l,r;
	register L_NUMBER *erg_p = erg;
	L_NUMBER     *cp;

	/* make op1 longer as op2 */
	if (lngofln(op1) < lngofln(op2))
	    { cp = op1; op1 = op2; op2 = cp; }

	l = lngofln(op2);
	r = lngofln(op1) - l;

	for (i = 0; i < l; i++) {
		erg++, op1++, op2++;
		*erg = *op1 XOR *op2;
	}

	for (i = 0; i < r; i++) {
		erg++, op1++;
		*erg = *op1;
	}

	while((erg>erg_p) && !*erg) erg--;
	lngofln(erg_p) = erg - erg_p;

	return;
}
