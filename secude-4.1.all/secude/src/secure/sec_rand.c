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

/*-----------------------------------------------------------------------*/
/* sec_random.c: Funktionen sec_random_*()                               */
/*-----------------------------------------------------------------------*/

#include "secure.h"
#ifdef TEST
#include <stdio.h>
#endif

extern int      errno;


OctetString    *
sec_random_ostr(noctets)
	unsigned int    noctets;
{
	OctetString    *p;
	char           *proc = "sec_random_ostr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (noctets <= 0)
		return (NULLOCTETSTRING);
	if (!(p = (OctetString *) malloc(sizeof(OctetString)))) {
		aux_add_error(EMALLOC, "p", CNULL, 0, proc);
		return (NULLOCTETSTRING);
	}
	if (!(p->octets = malloc(noctets))) {
		aux_add_error(EMALLOC, "p->octets", CNULL, 0, proc);
		return (NULLOCTETSTRING);
	}
	p->noctets = noctets;
	{
		int             i;
		char           *cp;

		for (i = noctets, cp = p->octets; i > 0; i--, cp++)
			*cp = sec_random_int(0, 0xFF);
	}
	return p;
}


BitString      *
sec_random_bstr(nbits)
	unsigned int    nbits;
{
	OctetString    *p;
	char           *proc = "sec_random_ostr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (nbits <= 0)
		return (NULLBITSTRING);
	if (NULLOCTETSTRING == (p = sec_random_ostr((nbits + 7) / 8)))
		return (NULLBITSTRING);
	if (nbits & 7)
		p->octets[p->noctets - 1] &= 0xFF00 >> (nbits & 7);
	p->noctets = nbits;
	return (BitString *) p;
}



char           *
sec_random_str(nchars, chars)
 /*unsigned*/ 
	int             nchars;	/* negative numbers would be too BIG */
	char           *chars;
{
	char           *p;
	char           *proc = "sec_random_ostr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (nchars <= 0)
		return (CNULL);
	if (!(p = malloc(nchars))) {
		aux_add_error(EMALLOC, "p", CNULL, 0, proc);
		return (CNULL);
	} {
		int             i, s = 0;
		char           *cp;

		if (chars)
			s = strlen(chars);

		for (i = nchars, cp = p; i > 0; i--, cp++)
			*cp = (s ? chars[sec_random_int(1, s) - 1] : sec_random_int(' ' + 1, 0x7E));
	}
	return p;
}


static void 
init_rndm()
{
	static long     rseed = 0;	/* static seed value */

	/* init, if equal 0 */
	if (rseed == 0) {
		time(&rseed);
		srand(rseed);
	}
	return;
}

int
sec_random_int(r1, r2)
	int             r1, r2;
{
	int             ret;

	if (r1 >= r2)
		return 0;
	init_rndm();

	ret = rand() % (r2 - r1 + 1) + r1;
	return (ret);
}


long
sec_random_long(r1, r2)
	int             r1, r2;
{
	long            ret;

	if (r1 >= r2)
		return 0;
	init_rndm();

	ret = rand() % (r2 - r1) + r1;
	return (ret);
}
