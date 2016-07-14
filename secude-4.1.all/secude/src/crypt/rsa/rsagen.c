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
 * RSA - module for RSA key generation
 * 
 * rsa_gen_key()
 */

#include "arithmetic.h"
#include "rsa.h"
#include "rsa_debug.h"
#include "secure.h"

/*----------------------------------------------rsa_gen_key---*/
#define MINKEYSIZE      64
#define MAXKEYSIZE      (MAXLGTH<<SWBITS)

RC
rsa_gen_key(keysize,skey,pkey)
int     keysize;
BitString  **skey, **pkey;
{
	Skeys   rsaparm;
	rndmstart zufall;
	L_NUMBER        a[MAXGENL];
	L_NUMBER        b[MAXGENL/2];
	int     repeat;


	if ((keysize<MINKEYSIZE) || (keysize>MAXKEYSIZE)) return -1;

	PrintSTART("RSA genkey Prolog ...    ",6);

	primzahl(zufall.p,a,(keysize+11)/2);
	primzahl(zufall.q,b,(keysize+11)/2);
	mult (zufall.p,zufall.q,zufall.modul);

	mult(a,b,a);
	start (zufall.p,a,zufall.modul);
	start (zufall.q,a,zufall.modul);

	repeat = 1;
	for( ; repeat; ){
		repeat = genrsa (&rsaparm,keysize,&zufall);
		/* weitersetzen der Zufallswerte */
		mmult (zufall.p,zufall.p,zufall.p,zufall.modul);
		mmult (zufall.q,zufall.q,zufall.q,zufall.modul);
	}
	{       /* return generated key pair */
	KeyBits         Kbits;
	char    k1[MAXLGTH*WBYTES], k2[MAXLGTH*WBYTES];
	L_NUMBER modul[MAXGENL];
extern  L_NUMBER lz_fermat5[];  /* 5. Fermatzahl F4 */

	Kbits.part1.octets = k1;
	Kbits.part2.octets = k2;
	Kbits.part3.noctets = 0;
	Kbits.part4.noctets = 0;
	lntoINTEGER(rsaparm.p,&Kbits.part1);
	lntoINTEGER(rsaparm.q,&Kbits.part2);
	*skey = e_KeyBits(&Kbits);
	mult (rsaparm.p,rsaparm.q,modul);
	/* ERASE SECRET KEY */
	bzero(&rsaparm,sizeof(rsaparm));
	lntoINTEGER(modul,&Kbits.part1);
	lntoINTEGER(lz_fermat5,&Kbits.part2);
	*pkey = e_KeyBits(&Kbits);
	}

	return 0;
}
