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


#include "arithmetic.h"

#ifdef MAC
#include "Mac.h"
#endif /* MAC */


#include <memory.h>

/*-------------------------------------------------------------*/
/*   globale Variablen - Definitionen                          */
/*-------------------------------------------------------------*/


L_NUMBER  lz_null    [] = LZ_NULL   ;
L_NUMBER  lz_eins    [] = LZ_EINS   ;
L_NUMBER  lz_zwei    [] = LZ_ZWEI   ;
L_NUMBER  lz_fermat5 [] = LZ_FERMAT5;


/* function intlog2() ==  int( log2() )
 */

int intlog2(v)
L_NUMBER v;
{
	int     ret;
	for( ret = -1; v; v>>=1, ret++) ;
	return ret;
}


/*
 * function lngtouse(modul) RETURNS BITLEN
 *
 * ::= mu(y: 2*2^y > modul)
 *
 */


int lngtouse(modul)

L_NUMBER modul [];

{
	register L_NUMBER	x;
	register int	i;
	
	i = (modul[0]-1)<<SWBITS;
	x = modul[modul[0]];

	return i + intlog2(x);
}


/*
 *      lntoINTEGER ( LNUMBER, INTEGER )
 *      INTEGERtoln ( INTEGER, LNUMBER )
 *      lntoctets ( LNUMBER, OctetString, size ) append
 *      octetstoln ( OctetString, LNUMBER, offset, size )
 *      lntobits ( LNUMBER, BitString, size ) append
 *      bitstoln ( BitString, LNUMBER, offset, size )
 *
 */

#include "secure.h"

/* excerpt from <netinet/in.h> */

#if !defined(vax) && !defined(ntohl) && !defined(lint) && !defined(i386) && !defined(MS_DOS)
/*
 * Macros for number representation conversion.
 */
#define ntohl(x)        (x)
#define ntohs(x)        (x)
#define htonl(x)        (x)
#define htons(x)        (x)
#else
L_NUMBER ntohl();	/* is self inverse : x == (ntohl o ntohl) (x) */
unsigned short ntohs();
#define htonl(x)        ntohl(x)
unsigned short htons();
#endif




void
octetstoln( octs, lnum, offset, size )
OctetString       *octs;
L_NUMBER        lnum[];
int             offset, size;
{
	int	length;		/* number of words */
	L_NUMBER *wp, c;
	char	*in;
	int     r;

	in = octs->octets + offset;
	length = (size + WBYTES-1)/WBYTES;
	lnum[0] = length;

	wp = lnum+length;
	r  = size%WBYTES;
	if ( r > 0 ) {
		c = 0;
		memcpy(&c, in, r);      in += r;
		c = ntohl(c) >> ((WBYTES-r)*BYTEL);
		*wp-- = c;
	}

	while( wp > lnum ) {
		memcpy(&c, in, WBYTES);
		*wp-- = ntohl(c);
		in += WBYTES;
	}

	normalize(lnum);
	return;
}


void
lntoctets( lnum, octs, size )
OctetString       *octs;
L_NUMBER        lnum[];
int             size;
{
	int     nw, r;
	char	*out;
	L_NUMBER *wp, c;

	if (size == 0) {
		size = (lngtouse(lnum) + BYTEL)/BYTEL;
		out = octs->octets;
		octs->noctets = size;
	}
	else {
		out = octs->octets + octs->noctets;     /* append */
		octs->noctets += size;
	}
	nw = size/WBYTES;

	c = 0;
	for( ; nw > lngofln(lnum); nw-- ){      /* fill zero */
		memcpy(out, &c, WBYTES);
		out += WBYTES;
	}

	wp = lnum + nw;
	r = size%WBYTES;
	if (r>0) {
		if (nw<lngofln(lnum))
			c = htonl(*(wp+1));
		else    c = 0;
		memcpy(out, (char*)&c+WBYTES-r, r);       out += r;
	}

	while( wp > lnum )  { /* copy all except the length field */
		c = htonl( *wp-- );
		memcpy(out, &c, WBYTES);
		out += WBYTES;
	}

	return;
}

void
bitstoln( bits, lnum, offset, size )
BitString       *bits;
L_NUMBER        lnum[];
int             offset, size;
{
	OctetString     b;
	char    save;           /* 1. octet may be masked */
	int     r;

	b.noctets = (offset + size + BYTEL - 1)/BYTEL
		   - offset/BYTEL;
	b.octets = bits->bits + offset/BYTEL;

	r = offset%BYTEL;
	if (r>0) {
		save = *b.octets;
		*b.octets &= 0xFF>>r;
	}
	INTEGERtoln(&b,lnum);
	if(r>0) *b.octets = save;       /* restore */

	r = (offset + size)%BYTEL;      /* adjust */
	if (r>0) shift(lnum, r-BYTEL, lnum);
	return;
}

void
lntobits( lnum, bits, size )
L_NUMBER  lnum[];         /* of [MAXLGTH] */
BitString*   bits;
int     size;
{
	OctetString     b;
	int     r,c;
	char    save;

	b.noctets = 0;
	b.octets = bits->bits + bits->nbits/BYTEL;

	r = (bits->nbits + size)%BYTEL; /* adjust */
	if (r>0) shift(lnum, BYTEL-r, lnum);

	r = bits->nbits%BYTEL;
	if (r>0) save = *b.octets;

	c = (bits->nbits + size + BYTEL -1)/BYTEL - bits->nbits/BYTEL;
	lntoctets(lnum,&b,c);
	bits->nbits += size;
	if (r>0) *b.octets = (*b.octets & 0xFF>>r) | save;

	return;
}

#ifdef MS_DOS
/* has need for ntohl(), htonl() functions */

#ifdef WLNG16
L_NUMBER ntohl(x)
L_NUMBER x;
{
union {
	L_NUMBER i;
	unsigned char s[2];
}	v;
unsigned char	b;

	v.i = x;
	/* swap byte order */
	b = v.s[0];
	v.s[0] = v.s[1];
	v.s[1] = b;

	return v.i;
}
#endif /* WLNG16 */
#endif



