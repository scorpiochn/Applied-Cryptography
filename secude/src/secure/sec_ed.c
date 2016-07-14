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

/*-----------------------sec-encdec.c-------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990                                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   encode-decode   VERSION   1.3                          */
/*                              DATE   27.09.1990                   */
/*                                BY   Nausester/Grimm              */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This modul presents     functions to encode and                */
/*   decode X509-Octetstrings into/from C-structures                */
/*   ``Encode'': C-structure ---> ASN.1-Octetstring                 */
/*   ``Decode'': ASN.1-Octetstring ---> C-structure                 */
/*                                                                  */
/*                                                                  */
/*                                                                  */
/* EXPORT                    DESCRIPTION                            */
/*                                                                  */
/*  e_AlgId()                  Encodes an algorithm id              */
/*  d_AlgId()                  Decodes an algorithm id              */
/*  d2_AlgId()                 Decodes an algorithm id              */
/*                             into a given struct AlgId            */
/*                                                                  */
/*  e_KeyInfo()                Encodes a KeyInfo                    */
/*  d_KeyInfo()                Decodes a KeyInfo                    */
/*  d2_KeyInfo()               Decodes a KeyInfo into a             */
/*                             given struct KeyInfo                 */
/*                                                                  */
/*  e_DigestInfo()             Encodes a DigestInfo                 */
/*  d_DigestInfo()             Decodes a DigestInfo                 */
/*  d2_DigestInfo()            Decodes a DigestInfo into a          */
/*                             given struct DigestInfo              */
/*                                                                  */
/*  e_Signature()              Encodes a Signature                  */
/*  d_Signature()              Decodes a Signature                  */
/*  d2_Signature()             Decodes a Signature into a           */
/*                             given struct Signature               */
/*                                                                  */
/*  e_KeyBits()                Encodes KeyBits                      */
/*  e2_KeyBits()               Encodes KeyBits into a               */
/*                             given BitString                      */
/*  d_KeyBits()                Decodes KeyBits                      */
/*                                                                  */
/*  e_PSEToc()                  Encodes PSEToc table                */
/*  d_PSEToc()                  Decodes PSEToc table                */
/*                                                                  */
/*  free_Octetstring()         Releases Octetstring memory          */
/*  free_Certificates()        Releases Certificates mem.           */
/*  err_Certficates()          error diagnostic                     */
/*                                                                  */
/*                                                                  */
/*  more encode-decode functions are defined                        */
/*  in af-encdec.c:                                                 */
/*                                                                  */
/*  e_Certificates()           Encodes certificates                 */
/*  d_Certificates()           Decodes certificates                 */
/*                                                                  */
/*  e_Certificate ()           Encodes one certiciate               */
/*  d_Certificate ()           Decodes one certificate              */
/*                                                                  */
/*  e_FCPath()                 Encodes an FCPath                    */
/*  d_FCPath()                 Decodes an FCPath                    */
/*                                                                  */
/*  e_PKRoot()                 Encodes a PKRoot table               */
/*  d_PKRoot()                 Decodes a PKRoot table               */
/*                                                                  */
/*  e_PKList()                 Encodes a PKList table               */
/*  d_PKList()                 Decodes a PKList table               */
/*                                                                  */
/*  e_ToBeSigned()             Encodes the ToBeSigned               */
/*                             subfield of a Certificate            */
/*                                                                  */
/*                                                                  */
/* IMPORT                    DESCRIPTION                            */
/*                                                                  */
/*  build_..., parse_...       ISODE-PEPY resulted                  */
/*                             encode-decode functions              */
/*                             from: SEC.py                         */
/*                                                                  */
/*  aux_DName2Name()          Map between ISODE-PEPY                */
/*  aux_Name2DName()          defined C-structures and              */
/*                             "C=de;..." printable                 */
/*                             representations of Names             */
/*                             from: aux-encdec.c                   */
/*                                                                  */
/*  aux_PE2OctetString(),             Map between ISODE-PE          */
/*  aux_OctetString2PE()              (presentation elements)       */
/*                             and ASN.1 Octetstrings               */
/*                             from: aux-encdec.c                   */
/*                                                                  */
/*                                                                  */
/*------------------------------------------------------------------*/


#include <stdio.h>
#include "psap.h"
#include "secure.h"

OctetString    *aux_PE2OctetString( /* PE */ );
PE              aux_OctetString2PE( /* (OctetString *) */ );


OctetString    *
e_AlgId(algid)
	AlgId          *algid;
{
	PE              P_AlgId;
	OctetString    *ret;
	char           *proc = "e_AlgId";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (algid == (AlgId *) 0)
		return (OctetString *) 0;

	if (build_SEC_AlgorithmIdentifier(&P_AlgId, 1, 0, CNULL, algid) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_AlgId);
	pe_free(P_AlgId);

	return (ret);
}


AlgId          *
d_AlgId(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_AlgId;
	AlgId          *ret;	/* return value */
	int             result;
	char           *proc = "d_AlgId";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (AlgId *) 0;

	P_AlgId = aux_OctetString2PE(asn1_string);

	if (P_AlgId == NULLPE)
		return (AlgId *) 0;

	result = parse_SEC_AlgorithmIdentifier(P_AlgId, 1, NULLIP, NULLVP, &ret);
	pe_free(P_AlgId);

	return (result ? (AlgId *) 0 : ret);
}

int 
d2_AlgId(asn1_string, aid)
	OctetString    *asn1_string;
	AlgId          *aid;	/* To be filled. Space given by calling
				 * routine */
{
	PE              P_AlgId;
	int             result;
	char           *proc = "d2_AlgId";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (-1);

	P_AlgId = aux_OctetString2PE(asn1_string);

	if (P_AlgId == NULLPE)
		return (-1);

/*
      Space for AlgId structure is given by calling routine.

      space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier .
*/

	result = parse_SEC_AlgorithmIdentifier(P_AlgId, 1, NULLIP, NULLVP, &aid);
	pe_free(P_AlgId);

/*    no evaluation of "result".
*/
	return (0);
}

OctetString    *
e_KeyInfo(ki)
	KeyInfo        *ki;
{
	PE              P_KeyInfo;
	OctetString    *ret;
	char           *proc = "e_KeyInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (ki == (KeyInfo *) 0)
		return (OctetString *) 0;

	if (build_SEC_KeyInfo(&P_KeyInfo, 1, 0, CNULL, ki) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_KeyInfo);
	pe_free(P_KeyInfo);

	return (ret);
}


KeyInfo        *
d_KeyInfo(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_KeyInfo;
	KeyInfo        *ret;	/* return value */
	int             result;
	char           *proc = "d_KeyInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (KeyInfo *) 0;

	P_KeyInfo = aux_OctetString2PE(asn1_string);

	if (P_KeyInfo == NULLPE)
		return (KeyInfo *) 0;

	/* allocate space for KeyInfo structure: */
	if ((ret = (KeyInfo *) malloc(sizeof(KeyInfo)))
	    == (KeyInfo *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (KeyInfo *) 0;
	}
/*    space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier !

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_KeyInfo.
*/
	/* NOTE: ret parameter is of type KeyInfo * (not **!) */
	result = parse_SEC_KeyInfo(P_KeyInfo, 1, NULLIP, NULLVP, ret);
	pe_free(P_KeyInfo);

	return (result ? (KeyInfo *) 0 : ret);
}


int 
d2_KeyInfo(asn1_string, ki)
	OctetString    *asn1_string;
	KeyInfo        *ki;	/* To be filled. Space given by calling
				 * routine */
{
	PE              P_KeyInfo;
	int             result;
	char           *proc = "d2_KeyInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (-1);

	P_KeyInfo = aux_OctetString2PE(asn1_string);

	if (P_KeyInfo == NULLPE)
		return (-1);

/*
      Space for KeyInfo structure is given by calling routine.

      space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier.

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_KeyInfo.
*/

	result = parse_SEC_KeyInfo(P_KeyInfo, 1, NULLIP, NULLVP, ki);
	pe_free(P_KeyInfo);

/*    no evaluation of "result".
*/
	return (0);
}


OctetString    *
e_EncryptedKey(enki)
	EncryptedKey   *enki;
{
	PE              P_EncryptedKey;
	OctetString    *ret;
	char           *proc = "e_EncryptedKey";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (enki == (EncryptedKey *) 0)
		return (OctetString *) 0;

	if (build_SEC_EncryptedKey(&P_EncryptedKey, 1, 0, CNULL, enki) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_EncryptedKey);
	pe_free(P_EncryptedKey);

	return (ret);
}


EncryptedKey   *
d_EncryptedKey(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_EncryptedKey;
	EncryptedKey   *ret;	/* return value */
	int             result;
	char           *proc = "d_EncryptedKey";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (EncryptedKey *) 0;

	P_EncryptedKey = aux_OctetString2PE(asn1_string);

	if (P_EncryptedKey == NULLPE)
		return (EncryptedKey *) 0;

	/* allocate space for EncryptedKey structure: */
	if ((ret = (EncryptedKey *) malloc(sizeof(EncryptedKey)))
	    == (EncryptedKey *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (EncryptedKey *) 0;
	}
/*    space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier !

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_EncryptedKey.
*/
	/* NOTE: ret parameter is of type EncryptedKey * (not **!) */
	result = parse_SEC_EncryptedKey(P_EncryptedKey, 1, NULLIP, NULLVP, ret);
	pe_free(P_EncryptedKey);

	return (result ? (EncryptedKey *) 0 : ret);
}


int 
d2_EncryptedKey(asn1_string, enki)
	OctetString    *asn1_string;
	EncryptedKey   *enki;	/* To be filled. Space given by calling
				 * routine */
{
	PE              P_EncryptedKey;
	int             result;
	char           *proc = "d2_EncryptedKey";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (-1);

	P_EncryptedKey = aux_OctetString2PE(asn1_string);

	if (P_EncryptedKey == NULLPE)
		return (-1);

/*
      Space for EncryptedKey structure is given by calling routine.

      space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier.

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_EncryptedKey.
*/

	result = parse_SEC_EncryptedKey(P_EncryptedKey, 1, NULLIP, NULLVP, enki);
	pe_free(P_EncryptedKey);

/*    no evaluation of "result".
*/
	return (0);
}


OctetString    *
e_Signature(sig)
	Signature      *sig;
{
	PE              P_KeyInfo;
	OctetString    *ret;
	char           *proc = "e_Signature";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (sig == (Signature *) 0)
		return (OctetString *) 0;

	if (build_SEC_KeyInfo(&P_KeyInfo, 1, 0, CNULL, (KeyInfo *) sig) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_KeyInfo);
	pe_free(P_KeyInfo);

	return (ret);
}

Signature      *
d_Signature(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_KeyInfo;
	Signature      *ret;	/* return value */
	int             result;
	char           *proc = "d_Signature";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (Signature *) 0;

	P_KeyInfo = aux_OctetString2PE(asn1_string);

	if (P_KeyInfo == NULLPE)
		return (Signature *) 0;

	/* allocate space for Signature structure: */

	if ((ret = (Signature *) malloc(sizeof(Signature)))
	    == (Signature *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (Signature *) 0;
	}
/*    space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier !

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_KeyInfo.
*/
	/* NOTE: ret parameter is of type Signature * (not **!) */
	result = parse_SEC_KeyInfo(P_KeyInfo, 1, NULLIP, NULLVP, ret);
	pe_free(P_KeyInfo);

	return (result ? (Signature *) 0 : ret);
}

int 
d2_Signature(asn1_string, sig)
	OctetString    *asn1_string;
	Signature      *sig;	/* To be filled. Space given by calling
				 * routine */
{
	PE              P_KeyInfo;
	int             result;
	char           *proc = "d2_Signature";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (-1);

	P_KeyInfo = aux_OctetString2PE(asn1_string);

	if (P_KeyInfo == NULLPE)
		return (-1);

/*
      Space for KeyInfo structure is given by calling routine.

      space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier.

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_KeyInfo.
*/

	result = parse_SEC_KeyInfo(P_KeyInfo, 1, NULLIP, NULLVP, sig);
	pe_free(P_KeyInfo);

/*    no evaluation of "result".
*/
	return (0);
}

BitString      *
e_KeyBits(kb)			/* !!! returns a BitString !!! */
	KeyBits        *kb;
{
	PE              P_KeyBits;

	/*
	 * OctetString *tempret;
	 */
	BitString      *ret;
	char           *proc = "e_KeyBits";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (kb == (KeyBits *) 0)
		return (BitString *) 0;

	if (build_SEC_KeyBits(&P_KeyBits, 1, 0, CNULL, kb) == NOTOK)
		return (BitString *) 0;

	ret = (BitString *) aux_PE2OctetString(P_KeyBits);
	ret->nbits = ret->nbits * 8;
	pe_free(P_KeyBits);

	return (ret);
}


int 
e2_KeyBits(kb, bstr)		/* fills preallocated bstr */
	KeyBits        *kb;
	BitString      *bstr;	/* to be filled: space allocated by calling
				 * routine */
{
	PE              P_KeyBits;
	OctetString    *ostr;
	int             i;
	char           *proc = "e2_KeyBits";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (kb == (KeyBits *) 0)
		return (-1);

	if (build_SEC_KeyBits(&P_KeyBits, 1, 0, CNULL, kb) == NOTOK)
		return (-1);

	ostr = aux_PE2OctetString(P_KeyBits);
	bstr->bits = ostr->octets;
	bstr->nbits = ostr->noctets * 8;
	free(ostr);

	pe_free(P_KeyBits);

	return (0);
}


KeyBits        *
d_KeyBits(asn1_bstr)
	BitString      *asn1_bstr;	/* !!! input is a BitString !!! */
{
	PE              P_KeyBits;
	KeyBits        *ret;	/* return value */
	int             result;
	OctetString    *asn1_ostr;	/* !!! input is a BitString !!! */
	char           *proc = "d_KeyBits";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_bstr == (BitString *) 0)
		return (KeyBits *) 0;

	if ((asn1_ostr = (OctetString *) malloc(sizeof(OctetString)))
	    == (OctetString *) 0) {
		aux_add_error(EMALLOC, "asn1_ostr", CNULL, 0, proc);
		return (KeyBits *) 0;
	}
	asn1_ostr->octets = asn1_bstr->bits;
	asn1_ostr->noctets = asn1_bstr->nbits / 8;
	P_KeyBits = aux_OctetString2PE(asn1_ostr);

	if (P_KeyBits == NULLPE)
		return (KeyBits *) 0;

	/* allocate space for KeyBits structure: */
	if ((ret = (KeyBits *) malloc(sizeof(KeyBits)))
	    == (KeyBits *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (KeyBits *) 0;
	}
	/* NOTE: ret parameter is of type KeyBits * (not **!) */
	result = parse_SEC_KeyBits(P_KeyBits, 1, NULLIP, NULLVP, ret);
	pe_free(P_KeyBits);

	return (result ? (KeyBits *) 0 : ret);
}


OctetString    *
e_PSEToc(toc)
	PSEToc         *toc;
{
	PE              P_PSEToc;
	OctetString    *ret;
	char           *proc = "e_PSEToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (toc == (PSEToc *) 0)
		return (OctetString *) 0;

	if (build_SEC_PSEToc(&P_PSEToc, 1, 0, CNULL, toc) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_PSEToc);
	pe_free(P_PSEToc);

	return (ret);
}


PSEToc         *
d_PSEToc(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_PSEToc;
	PSEToc         *ret;	/* return value */
	int             result;
	char           *proc = "d_PSEToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (PSEToc *) 0;

	P_PSEToc = aux_OctetString2PE(asn1_string);

	if (P_PSEToc == NULLPE)
		return (PSEToc *) 0;

	/* allocate space for PSEToc structure: */
	if ((ret = (PSEToc *) malloc(sizeof(PSEToc)))
	    == (PSEToc *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (PSEToc *) 0;
	}
	/* NOTE: ret parameter is of type PSEToc * (not **!) */
	result = parse_SEC_PSEToc(P_PSEToc, 1, NULLIP, NULLVP, ret);
	pe_free(P_PSEToc);

	return (result ? (PSEToc *) 0 : ret);
}

OctetString    *
e_PSEObject(objectType, objectValue)
	ObjId          *objectType;
	OctetString    *objectValue;
{
	PE              P_PSEObject;
	OctetString    *ret;
	PSEObject      *pse_obj;
	int             i;
	char           *proc = "e_PSEObject";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (objectType == (ObjId *) 0)
		return (OctetString *) 0;

	if (!objectValue || !objectValue->octets)
		return (OctetString *) 0;

	/* allocate space for PSEObject structure: */
	if ((pse_obj = (PSEObject *) malloc(sizeof(PSEObject)))
	    == (PSEObject *) 0) {
		aux_add_error(EMALLOC, "pse_obj", CNULL, 0, proc);
		return (OctetString *) 0;
	}
	pse_obj->objectType = aux_cpy_ObjId(objectType);
	if (!(pse_obj->objectValue = (OctetString *) malloc(sizeof(OctetString)))) {
		aux_add_error(EMALLOC, "pse_obj->objectValue", CNULL, 0, proc);
		return (OctetString *) 0;
	}
	pse_obj->objectValue->noctets = objectValue->noctets;
	if ((pse_obj->objectValue->octets = (char *) malloc(pse_obj->objectValue->noctets)) == (char *) 0) {
		aux_add_error(EMALLOC, "pse_obj->objectValue->octets", CNULL, 0, proc);
		return (OctetString *) 0;
	}
	for (i = 0; i < pse_obj->objectValue->noctets; i++) {
		pse_obj->objectValue->octets[i] = objectValue->octets[i];
	}

	if (build_SEC_PSEObject(&P_PSEObject, 1, 0, CNULL, pse_obj) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_PSEObject);
	pe_free(P_PSEObject);

	return (ret);
}

OctetString    *
d_PSEObject(objectType, asn1_string)
	ObjId          *objectType;
	OctetString    *asn1_string;
{
	PE              P_PSEObject;
	PSEObject      *pse_obj;
	int             result;
	int             i;
	char           *proc = "d_PSEObject";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (objectType == (ObjId *) 0)
		return (OctetString *) 0;

	if (asn1_string == (OctetString *) 0)
		return (OctetString *) 0;

	/* allocate space for PSEObject structure: */
	if ((pse_obj = (PSEObject *) malloc(sizeof(PSEObject)))
	    == (PSEObject *) 0) {
		aux_add_error(EMALLOC, "pse_obj", CNULL, 0, proc);
		return (OctetString *) 0;
	}
	P_PSEObject = aux_OctetString2PE(asn1_string);

	if (P_PSEObject == NULLPE)
		return (OctetString *) 0;

	result = parse_SEC_PSEObject(P_PSEObject, 1, NULLIP, NULLVP, pse_obj);
	pe_free(P_PSEObject);

	if (result)
		return (OctetString *) 0;

	aux_cpy2_ObjId(objectType, pse_obj->objectType);

	return (pse_obj->objectValue);
}


OctetString    *
e_OctetString(ostr)
	OctetString    *ostr;
{
	PE              P_OctetString;
	OctetString    *ret;
	char           *proc = "e_OctetString";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (ostr == (OctetString *) 0)
		return (OctetString *) 0;

	if (build_SEC_OctetString(&P_OctetString, 1, 0, CNULL, ostr) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_OctetString);
	pe_free(P_OctetString);

	return (ret);
}


OctetString    *
d_OctetString(asn1_string)
	OctetString    *asn1_string;
{
	PE              P_OctetString;
	OctetString    *ret;	/* return value */
	int             result;
	char           *proc = "d_OctetString";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (OctetString *) 0;

	P_OctetString = aux_OctetString2PE(asn1_string);

	if (P_OctetString == NULLPE)
		return (OctetString *) 0;

	/* allocate space for OctetString structure: */
	if ((ret = (OctetString *) malloc(sizeof(OctetString)))
	    == (OctetString *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (OctetString *) 0;
	}
	/* NOTE: ret parameter is of type OctetString * (not **!) */
	result = parse_SEC_OctetString(P_OctetString, 1, NULLIP, NULLVP, ret);
	pe_free(P_OctetString);

	return (result ? (OctetString *) 0 : ret);
}


OctetString    *
e_DigestInfo(di)
	DigestInfo     * di;
{
	PE               P_DigestInfo;
	OctetString    * ret;
	char           * proc = "e_DigestInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (di == (DigestInfo *) 0)
		return (OctetString *) 0;

	if (build_SEC_DigestInfo(&P_DigestInfo, 1, 0, CNULL, di) == NOTOK)
		return (OctetString *) 0;

	ret = aux_PE2OctetString(P_DigestInfo);
	pe_free(P_DigestInfo);

	return (ret);
}


DigestInfo        *
d_DigestInfo(asn1_string)
	OctetString    * asn1_string;
{
	PE               P_DigestInfo;
	DigestInfo     * ret;	/* return value */
	int              result;
	char           * proc = "d_DigestInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (DigestInfo *) 0;

	P_DigestInfo = aux_OctetString2PE(asn1_string);

	if (P_DigestInfo == NULLPE)
		return (DigestInfo *) 0;

	/* allocate space for DigestInfo structure: */
	if ((ret = (DigestInfo *) malloc(sizeof(DigestInfo)))
	    == (DigestInfo *) 0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return (DigestInfo *) 0;
	}
/*    space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier !

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_DigestInfo.
*/
	/* NOTE: ret parameter is of type DigestInfo * (not **!) */
	result = parse_SEC_DigestInfo(P_DigestInfo, 1, NULLIP, NULLVP, ret);
	pe_free(P_DigestInfo);

	return (result ? (DigestInfo *) 0 : ret);
}


int 
d2_DigestInfo(asn1_string, di)
	OctetString    * asn1_string;
	DigestInfo     * di;	/* To be filled. Space given by calling
				 * routine */
{
	PE               P_DigestInfo;
	int              result;
	char           * proc = "d2_DigestInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (asn1_string == (OctetString *) 0)
		return (-1);

	P_DigestInfo = aux_OctetString2PE(asn1_string);

	if (P_DigestInfo == NULLPE)
		return (-1);

/*
      Space for DigestInfo structure is given by calling routine.

      space for objid's is allocated by oid_cpy in
      parse_SEC_AlgorithmIdentifier.

      space for Bitstring is allocated by bitstr2strb in
      parse_SEC_DigestInfo.
*/

	result = parse_SEC_DigestInfo(P_DigestInfo, 1, NULLIP, NULLVP, di);
	pe_free(P_DigestInfo);

/*    no evaluation of "result".
*/
	return (0);
}


RC dec_RSAAlgorithm(pe, keybits)
PE pe;
KeyBits * keybits;
{
	int result;

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (pe == NULLPE || ! keybits)
		return (- 1);

	result = parse_SEC_RSAAlgorithm(pe, 1, NULLIP, NULLVP, keybits);

	return (result);
}

RC dec_DSAAlgorithm(pe, keybits)
PE pe;
KeyBits * keybits;
{
	int result;

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (pe == NULLPE || ! keybits)
		return (- 1);

	result = parse_SEC_DSAAlgorithm(pe, 1, NULLIP, NULLVP, keybits);

	return (result);
}


OctetString *
e_GRAPHICString(string)
char * string;
{
	PE               P_GRAPHICString;
	OctetString    * ret;
	char           * proc = "e_GRAPHICString";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (! string)
		return (NULLOCTETSTRING);

	if (build_SEC_GRAPHICString(&P_GRAPHICString, 1, 0, CNULL, string) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_GRAPHICString);
	pe_free(P_GRAPHICString);

	return (ret);
}


char *
d_GRAPHICString(asn1_string)
OctetString * asn1_string;
{
	PE               P_GRAPHICString;
	char	      ** value;
	char           * ret = CNULL;	/* return value */
	int              result;
	char           * proc = "d_GRAPHICString";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (! asn1_string)
		return (CNULL);

	P_GRAPHICString = aux_OctetString2PE(asn1_string);

	if (P_GRAPHICString == NULLPE)
		return (CNULL);

	value = (char **) calloc(1, sizeof(char * ));

	result = parse_SEC_GRAPHICString(P_GRAPHICString, 1, NULLIP, NULLVP, value);
	pe_free(P_GRAPHICString);

	if(result == NOTOK)
		return (CNULL);

	if (strlen(*value)) {
		ret = (char *)malloc(strlen(*value) + 1);
		strcpy(ret, *value);
	}

	free(*value);
	free(value);

	return (ret);
}
