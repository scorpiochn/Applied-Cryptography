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

 
#include	"arithmetic.h"

/*	sign(A-B)	*/
int	_comp(Ap,Bp)
register L_NUMBER *Ap, *Bp;
{
	register int	s = *Ap - *Bp;
	
	if (s>0)	return 1;
	if (s<0)	return -1;
	
	{	register L_NUMBER	*stop = Ap;
		
		Ap += lngofln(Ap); Bp += lngofln(Bp);
		for ( ; Ap>stop; Ap--, Bp-- ) {
			if (*Ap > *Bp)	return 1;
			if (*Ap < *Bp)	return -1;
		}
	}
	return 0;
}
