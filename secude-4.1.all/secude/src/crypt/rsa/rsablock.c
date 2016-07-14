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
 *	RSA - one block encryption / decryption
 *
 *	it depends on the calling algorithm (resp type of key), which
 *	method is used for computing the block.
 *
 *	rsa_sign, rsa_decrypt: (secure)private key is CARDINFO
 *	rsa_auth, rsa_encrypt: public key is exp, modul
 */

#include "arithmetic.h"
#include  "rsa.h"

void rsa_encblock(in,enc,pk)
register L_NUMBER       in[], enc[];
Pkeys   *pk;
{
extern  L_NUMBER   lz_fermat5[];
register int       i;

	if (comp(pk->e,lz_fermat5)){ /* then use mexp */
		mexp(in,pk->e,enc,pk->n);
	} else {/* exp == lz_fermat5 */
		mmult(in,in,enc,pk->n);
		for(i=2; i<=16; i++)
		    mmult(enc,enc,enc,pk->n);
		mmult(enc,in,enc,pk->n);
	}

	return;
}


void rsa_decblock(in,dec,sk)
register L_NUMBER in[], dec[];
register Skeys    *sk;      /* for efficiency, precomputed values */
{
	extern  L_NUMBER        lz_eins[];
	extern  L_NUMBER        lz_fermat5[];

		L_NUMBER	messq[MAXLGTH];
		L_NUMBER	acc[MAXLGTH];

	/* compute values, if necessary */
	if (!lngofln(sk->u)) {
		sub(sk->p,lz_eins,acc);
		mdiv(lz_eins,lz_fermat5,sk->sp,acc);
		sub(sk->q,lz_eins,acc);
		mdiv(lz_eins,lz_fermat5,sk->sq,acc);
		mdiv(lz_eins,sk->q,sk->u,sk->p);
	}

	/* decrypt signature */
	div   (in,sk->q,messq,messq);
	div   (in,sk->p,dec,dec);
	mexp  (messq,sk->sq,messq,sk->q);
	mexp  (dec,sk->sp,dec,sk->p);

	/* apply chinese residual lemma */
	msub  (dec,messq,dec,sk->p);
	mmult (dec,sk->u,dec,sk->p);
	mult  (dec,sk->q,dec);
	add   (dec,messq,dec);

	return;
}
