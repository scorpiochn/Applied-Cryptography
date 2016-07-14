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

/*	addition/subtraktion mit carry
 *
 *	cadd(A,B,A+B,carry) RETURNS carry
 */

#include	"arithmetic.h"


int	_cadd(opa,opb,opa_b,carry)
L_NUMBER	opa,opb;
register L_NUMBER *opa_b,carry;
{
	register   L_NUMBER zulu = opb + carry;
	register   L_NUMBER sum;
	/* NOTE: optimized to achieve best result for subtraktion of small int */

	if(zulu) { /* means no carry at all */
		sum = opa + zulu;
		zulu |= opa;
		*opa_b = sum;
		return ( zulu > sum );
	}
	else	{  /* propagate carry */
		*opa_b = opa;
		return carry;
	}
}
