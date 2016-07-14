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

#ifdef X500
#include <stdio.h>

#include "psap.h"
#include "af.h"

#include "UNIV-types.h"
#include "config.h"
#include "isoaddrs.h"
#include "logger.h"
#include "quipu/attr.h"
#include "quipu/config.h"
#include "quipu/dsp.h"
#include "quipu/oid.h"
#include "x500as/AF-types.h"
#include "x500as/af-cdefs.h"
#include "x500as/if-cdefs.h"
#include "x500as/nrs-cdefs.h"
#include "x500as/qu-cdefs.h"
#include "quipu/syntaxes.h"
#include "quipu/authen.h"

/* from /usr/local/isode/share/src/dsap/common/certificate.c: */
extern void print_algid();
extern void print_encrypted();
extern void str2alg();
extern void str2encrypted();
extern int	cert_cmp();
extern struct certificate *cert_dec();
extern struct certificate *str2cert();
extern PE cert_enc();

/* from /usr/local/isode/share/src/dsap/common/dn_str.c: */
extern DN dn_dec();
extern DN str2dn();
extern PE dn_enc();

/* from /usr/local/isode/share/src/dsap/common/dn_print.c: */
extern void	dn_print();

extern int	dn_free();
extern int	dn_cmp();

extern OIDentifier *name2oid();


/************* local functions: ******************************/

int	aux_cert_cmp(a, b)
Certificate *a, *b;
{
	struct certificate * quipu_a, * quipu_b;
	PE		     pe;
	int		     ret;
	char		   * proc = "aux_cert_cmp";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	build_AF_Certificate (&pe, 0, 0, NULLCP, a);
	quipu_a = cert_dec(pe);
	pe_free(pe);

	build_AF_Certificate (&pe, 0, 0, NULLCP, b);
	quipu_b = cert_dec(pe);
	pe_free(pe);

	ret = cert_cmp(quipu_a, quipu_b);

	cert_free(quipu_a);
	cert_free(quipu_b);

	return (ret);
}


PE AlgId_enc(parm)
AlgId *parm;
{
	PE pe;
	(void) build_SEC_AlgorithmIdentifier(&pe, 1, 0, NULLCP, parm);
	return (pe);
}


AlgId *AlgId_dec(pe)
PE pe;
{
	AlgId * ret;  /*return value*/
	int	result;

	if ( pe == NULLPE )
		return ( (AlgId * )0 );

	result = parse_SEC_AlgorithmIdentifier (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (AlgId * )0 : ret);
}


/*******************************************************************************
 *
 *      Attribute Syntax RevCert (revoked certificate according to X.500)
 *
 *******************************************************************************/


PE revcert_enc(parm)
RevCert *parm;
{
	PE pe;

	if ( parm == (RevCert * )0 )
		return (NULLPE);

	(void) build_AF_RevCert (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


RevCert *revcert_dec(pe)
PE pe;
{
	RevCert * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (RevCert * )0 );

	/*NOTE: parameter is of type RevCert ** (not *!) */
	result = parse_AF_RevCert (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (RevCert * )0 : ret);
}


PE revcerttbs_enc(parm)
RevCertTBS *parm;
{
	PE pe;

	(void) build_AF_TBSRevCert (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


RevCertTBS *revcerttbs_dec(pe)
PE pe;
{
	RevCertTBS * ret;
	int	result;
	char	*proc = "revcerttbs_dec";

	if ( pe == NULLPE )
		return ( (RevCertTBS * )0 );

	/* allocate space for RevCertTBS structure: */
	if ( (ret = (RevCertTBS * )malloc(sizeof(RevCertTBS)))
	     == (RevCertTBS * )0 ) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return ( (RevCertTBS * )0 );
	}
	/*NOTE: parameter is of type RevCertTBS * (not **!) */
	result = parse_AF_TBSRevCert (pe, 1, NULLIP, NULLCP, ret);

	return (result ? (RevCertTBS * )0 : ret);
}


print_revcert(ps, parm, format)
PS ps;
RevCert *parm;
int	format;
{
	struct alg_id * alg;
	PE 		pe;
	DN 		dn;
	int		result;
	char	      * proc = "print_revcert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	/*  dn_dec() from  /isode/share/src/dsap/common/dn_str.c
	 */

	pe = AlgId_enc(parm->sig->signAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free ( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	print_encrypted(ps, parm->sig->signature.bits, parm->sig->signature.nbits,
	    format);

	pe = AlgId_enc(parm->tbs->signatureAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free ( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	build_IF_Name(&pe, 1, 0, NULLCP, parm->tbs->issuer);
	dn = dn_dec(pe);
	dn_print(ps, dn, EDBOUT);
	ps_printf(ps, "#");
	pe_free(pe);
	dn_free(dn);

	ps_printf(ps, "%d#", parm->tbs->subject);   /* CertificateSerialNumber */

	ps_printf(ps, "%s#", parm->tbs->revocationdate);
}


int	aux_revcert_cmp(a, b)
RevCert *a;
RevCert *b;
{
	int	ret;
	PE pe;
	DN dn_a;
	DN dn_b;

	/* In the directory black lists the certificate serial number of a certificate
	 * in combination with the name of the issuer of a certificate identifies a
	 * certificate universally.
	 */

	build_IF_Name(&pe, 1, 0, NULLCP, a->tbs->issuer);
	dn_a = dn_dec(pe);
	pe_free(pe);

	build_IF_Name(&pe, 1, 0, NULLCP, b->tbs->issuer);
	dn_b = dn_dec(pe);
	pe_free(pe);

	ret = dn_cmp(dn_a, dn_b);

	dn_free(dn_a);
	dn_free(dn_b);

	if ( ret != 0 )
		return (ret);

	if ( a->tbs->subject > b->tbs->subject )
		return (1);
	if ( a->tbs->subject < b->tbs->subject )
		return (-1);

	return (0);
}


/*******************************************************************************
 *
 *      Attribute Syntax for SEQUENCE of Revoked Certificates
 *
 *******************************************************************************/


PE revcertseq_enc(parm)
SEQUENCE_OF_RevCert *parm;
{
	PE pe;

	(void) build_AF_RevCertSequence (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


SEQUENCE_OF_RevCert *revcertseq_dec(pe)
PE pe;
{
	SEQUENCE_OF_RevCert * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (SEQUENCE_OF_RevCert * )0 );
	/*NOTE:								*/
	/*space for SEQUENCE_OF_RevCert structure allocated  */
	/*by parse_AF_RevCertSequence(), parameter is of     */
	/*type SEQUENCE_OF_RevCert ** (not *!)		*/

	result = parse_AF_RevCertSequence (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (SEQUENCE_OF_RevCert * )0 : ret);
}


/*******************************************************************************
 *
 *      Attribute Syntax for Crl (revocation list according to X.500)
 *
 *******************************************************************************/


PE certlist_enc(parm)
Crl *parm;
{
	PE pe;

	if ( parm == (Crl * )0 )
		return (NULLPE);

	(void) build_AF_Crl (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


Crl *certlist_dec(pe)
PE pe;
{
	Crl * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (Crl * )0 );

	/*NOTE: parameter is of type Crl ** (not *!) */
	result = parse_AF_Crl (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (Crl * )0 : ret);
}


PE certlisttbs_enc(parm)
CrlTBS *parm;
{
	PE pe;

	(void) build_AF_TBSCrl (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


CrlTBS *certlisttbs_dec(pe)
PE pe;
{
	CrlTBS * ret;
	int	     result;
	char	   * proc = "certlisttbs_dec";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif	

	if ( pe == NULLPE )
		return ( (CrlTBS * )0 );

	/* allocate space for CrlTBS structure: */
	if ( (ret = (CrlTBS * )malloc(sizeof(CrlTBS))) == (CrlTBS * )0 ) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return ( (CrlTBS * )0 );
	}
	/*NOTE: parameter is of type CrlTBS * (not **!) */
	result = parse_AF_TBSCrl (pe, 1, NULLIP, NULLCP, ret);

	return (result ? (CrlTBS * )0 : ret);
}


Crl *str2certlist(str)
char	*str;
{
	Crl * result;
	SEQUENCE_OF_RevCert * seq;
	SEQUENCE_OF_RevCert * save_seq;
	struct alg_id alg;
	char	*ptr;
	int	first_elem = 1;
	PE pe;
	DN dn;
	OIDentifier * oid;
	char	*proc = "str2certlist";

	/*    OID = ObjId*
	 *    s. /isode/share/include/psap.h
 	 */

	/*    dn_enc() from  /isode/share/src/dsap/common/dn_str.c
	 */

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !(result = (Crl * )malloc(sizeof(Crl))) ) {
		aux_add_error(EMALLOC, "result", CNULL, 0, proc);
		return( (Crl * )0 );
	}
	result->tbs_DERcode = (OctetString * )0;

	result->tbs = (CrlTBS * )malloc(sizeof(CrlTBS));
	if (!result->tbs) {
		aux_add_error(EMALLOC, "result", CNULL, 0, proc);
		return( (Crl * )0 );
	}


	result->sig = (Signature * )malloc(sizeof(Signature));
	if (!result->sig) {
		aux_add_error(EMALLOC, "result", CNULL, 0, proc);
		return( (Crl * )0 );
	}


	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Algorithm not present", NULLCP);
		aux_add_error(EINVALID, "Algorithm not present", CNULL, 0, proc);
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	oid = name2oid(str);
	if ( oid == NULLOID) {
		parse_error("Bad algorithm identifier", NULLCP);
		aux_add_error(EINVALID, "Bad algorithm identifier", CNULL, 0, proc);
		free( (Crl * )result );
		return( (Crl * )0 );
	}

	alg.algorithm = oid;

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Parameters not present", NULLCP);
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2alg(str, &alg);
	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
	result->sig->signAI = AlgId_dec(pe);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Signature not present", NULLCP);
		aux_add_error(EINVALID, "Signature not present", CNULL, 0, proc);
		aux_free_AlgId( &(result->sig->signAI) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2encrypted (str, &(result->sig->signature.bits), &(result->sig->signature.nbits));

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Algorithm not present", NULLCP);
		aux_add_error(EINVALID, "Algorithm not present", CNULL, 0, proc);
		aux_free_KeyInfo( &(result->sig) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	oid = name2oid(str);
	if (oid == NULLOID ) {
		parse_error("Bad algorithm identifier", NULLCP);
		aux_add_error(EINVALID, "Bad algorithm identifier", CNULL, 0, proc);
		aux_free_KeyInfo( &(result->sig) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}

	alg.algorithm = oid;

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Parameters not present", NULLCP);
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		aux_free_KeyInfo( &(result->sig) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2alg(str, &alg);
	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
	result->tbs->signatureAI = AlgId_dec(pe);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Issuer not present", NULLCP);
		aux_add_error(EINVALID, "Issuer not present", CNULL, 0, proc);
		aux_free_AlgId( &(result->tbs->signatureAI) );
		aux_free_KeyInfo( &(result->sig) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;

	dn = str2dn(str);
	pe = dn_enc(dn);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &result->tbs->issuer);
	pe_free(pe);
	dn_free(dn);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Lastupdate time not present", NULLCP);
		aux_add_error(EINVALID, "Lastupdate time not present", CNULL, 0, proc);
		aux_free_DName( &(result->tbs->issuer) );
		aux_free_AlgId( &(result->tbs->signatureAI) );
		aux_free_KeyInfo( &(result->sig) );
		free( (Crl * )result );
		return( (Crl * )0 );
	}
	*ptr = '\0';
	ptr++;
	/* This may be the end of the string */

	result->tbs->lastupdate = strdup(str);

	while ( str = ptr, ((ptr = strchr(str, '#')) != NULLCP) ) {

		*ptr = '\0';
		ptr++;

		if ( !(seq = (SEQUENCE_OF_RevCert * )malloc(sizeof(SEQUENCE_OF_RevCert))) ) {
			free( (char *)result->tbs->lastupdate );
			aux_add_error(EMALLOC, "seq", CNULL, 0, proc);
			aux_free_DName( &(result->tbs->issuer) );
			aux_free_AlgId( &(result->tbs->signatureAI) );
			aux_free_KeyInfo( &(result->sig) );
			free( (Crl * )result );
			return( (Crl * )0 );
		}

		if ( first_elem ) {
			result->tbs->revokedcertificates = seq;
			first_elem = 0;
		} else
			save_seq->next = seq;

		save_seq = seq;
		seq->next = (SEQUENCE_OF_RevCert * )0;

		if ( !(seq->element = (RevCert * )malloc(sizeof(RevCert))) ) {
			aux_add_error(EMALLOC, "seq->element", CNULL, 0, proc);
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}

		seq->element->tbs_DERcode = (OctetString * )0;

		seq->element->tbs = (RevCertTBS * )malloc(sizeof(RevCertTBS));
		if (!seq->element->tbs) {
			aux_add_error(EMALLOC, "seq->element->tbs", CNULL, 0, proc);
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}

		seq->element->sig = (Signature * )malloc(sizeof(Signature));
		if (!seq->element->sig) {
			aux_add_error(EMALLOC, "seq->element->sig", CNULL, 0, proc);
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}

		oid = name2oid(str);
		if ( oid == NULLOID ) {
			parse_error("Bad algorithm identifier", NULLCP);
			aux_add_error(EINVALID, "Bad algorithm identifier", CNULL, 0, proc);
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}

		alg.algorithm = oid;

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Parameters not present", NULLCP);
			aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		str2alg(str, &alg);
		encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
		seq->element->sig->signAI = AlgId_dec(pe);

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Signature not present", NULLCP);
			aux_add_error(EINVALID, "Signature not present", CNULL, 0, proc);
			aux_free_AlgId( &(seq->element->sig->signAI) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		str2encrypted (str, &(seq->element->sig->signature.bits),
		    &(seq->element->sig->signature.nbits));

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Algorithm not present", NULLCP);
			aux_add_error(EINVALID, "Algorithm not present", CNULL, 0, proc);
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		oid = name2oid(str);
		if (oid == NULLOID ) {
			parse_error("Bad algorithm identifier", NULLCP);
			aux_add_error(EINVALID, "Bad algorithm identifier", CNULL, 0, proc);
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}

		alg.algorithm = oid;

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Parameters not present", NULLCP);
			aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		str2alg(str, &alg);
		encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
		seq->element->tbs->signatureAI = AlgId_dec(pe);

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Issuer not present", NULLCP);
			aux_add_error(EINVALID, "Issuer not present", CNULL, 0, proc);
			aux_free_AlgId( &(seq->element->tbs->signatureAI) );
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		dn = str2dn(str);
		pe = dn_enc(dn);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &seq->element->tbs->issuer);
		pe_free(pe);
		dn_free(dn);

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Subject not present", NULLCP);
			aux_add_error(EINVALID, "Subject not present", CNULL, 0, proc);
			aux_free_DName( &(seq->element->tbs->issuer) );
			aux_free_AlgId( &(seq->element->tbs->signatureAI) );
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;

		seq->element->tbs->subject = atoi(str);     /* CertificateSerialNumber */

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Revocation date not present", NULLCP);
			aux_add_error(EINVALID, "Revocation date not present", CNULL, 0, proc);
			aux_free_DName( &(seq->element->tbs->issuer) );
			aux_free_AlgId( &(seq->element->tbs->signatureAI) );
			aux_free_KeyInfo( &(seq->element->sig) );
			free( (RevCert * )seq->element );
			seq->element = (RevCert * ) 0;
			aux_free_Crl(&result);
			return( (Crl * )0 );
		}
		*ptr = '\0';
		ptr++;
		/* This may be the end of the string */

		seq->element->tbs->revocationdate = strdup(str);

	}    /* while */

	if ( first_elem ) {		/*Schwarze Liste ist leer, sonst waere first_elem
						  naemlich auf Null gesetzt worden!*/
		result->tbs->revokedcertificates = (SEQUENCE_OF_RevCert * )0;
	}

	return (result);
}


/* The  *tbs_DERcode-component within Crl is constructed in the
	 * DECODER-parse-section of pepy:
	 *
	 *      parm->tbs_DERcode = aux_PE2OctetString($$)                                
	 */


/* The  *tbs_DERcode-component within RevCert is constructed in 
	 * the DECODER-parse-section of pepy:
	 *
	 *	parm->tbs_DERcode = aux_PE2OctetString($$)
	 */

printcertlist(ps, parm, format)
PS ps;
Crl *parm;
int	format;
{
	struct alg_id	    * alg;
	PE		      pe;
	DN 		      dn;
	SEQUENCE_OF_RevCert * seq;
	int		      result;
	char	      	    * proc = "printcertlist";

	/*  Abfrage in calling routine
 	 */

	/*  dn_dec() from  /isode/share/src/dsap/common/dn_str.c
 	 */

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	pe = AlgId_enc(parm->sig->signAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	print_encrypted(ps, parm->sig->signature.bits, parm->sig->signature.nbits, 
	    format);

	pe = AlgId_enc(parm->tbs->signatureAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	build_IF_Name(&pe, 1, 0, NULLCP, parm->tbs->issuer);
	dn = dn_dec(pe);
	dn_print(ps, dn, EDBOUT);
	ps_printf(ps, "#");
	pe_free(pe);
	dn_free(dn);

	ps_printf(ps, "%s#", parm->tbs->lastupdate);

	seq = parm->tbs->revokedcertificates;

	while ( seq ) {
		print_revcert(ps, seq->element, format);
		seq = seq->next;
	}
}


int	aux_certlist_cmp(a, b)
Crl *a;
Crl *b;
{
	int	ret;
	PE pe;
	DN dn_a;
	DN dn_b;

	/*
	 *  It is sufficient to compare the issuer- and lastupdate-components
	 *  ( see also /usr/local/isode/share/src/dsap/common/revoke.c )
 	 */

	build_IF_Name(&pe, 1, 0, NULLCP, a->tbs->issuer);
	dn_a = dn_dec(pe);
	pe_free(pe);

	build_IF_Name(&pe, 1, 0, NULLCP, b->tbs->issuer);
	dn_b = dn_dec(pe);
	pe_free(pe);

	ret = dn_cmp(dn_a, dn_b);

	dn_free(dn_a);
	dn_free(dn_b);

	if ( ret != 0 )
		return (ret);

	ret = strcmp(a->tbs->lastupdate, b->tbs->lastupdate);
	if ( ret != 0 )
		return (ret);

	return (0);
}


revoke_syntax() 
{
	(void) add_attribute_syntax(
	    "BlackList",
	    (IFP) certlist_enc,       (IFP) certlist_dec,
	    (IFP) str2certlist,       (IFP) printcertlist,
	    (IFP) aux_cpy_Crl ,  (IFP) aux_certlist_cmp,
	    NULLIFP, 		  NULLCP,
	    NULLIFP, 	          TRUE);
}


/*******************************************************************************
 *
 *      Attribute Syntax for OldCertificates
 *
 *******************************************************************************/


PE oclist_enc(parm)
OCList *parm;
{
	PE pe;

	(void) build_AF_OldCertificateList (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


OCList *oclist_dec(pe)
PE pe;
{
	OCList * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (OCList * )0 );

	/*NOTE:								*/
	/*space for OCList structure allocated by                       */
	/*parse_AF_OldCertificateList(), parameter is of                */
	/*type OCList ** (not *!)					*/

	result = parse_AF_OldCertificateList (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (OCList * )0 : ret);
}


OCList *str2ocl(str)
char	*str;
{
	OCList			 * ret;
	OCList			 * ocl;
	OCList			 * save_ocl;
	struct certificate 	 * quipu_cert;
	PE 			   pe;
	char			 * ptr;
	char			 * tmp_ptr;
	int			   i;
	char			 * proc = "str2ocl";

	/*  If the "Old Certificates"-list is not empty, it contains at least
	 *  two cross-certificates
	 */

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !(ret = (OCList * )malloc(sizeof(OCList))) ) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return( (OCList * )0 );
	}
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("serialNumber not present", NULLCP);
		aux_add_error(EINVALID, "serialNumber not present", CNULL, 0, proc);
		free( (OCList * )ret );
		return( (OCList * )0 );
	}
	*ptr = '\0';
	ptr++;

	ret->serialnumber = atoi(str);

	str = ptr;

	/* The printable representation of a certificate is subdivided by 14 '#'-symbols */
	for (tmp_ptr = str, i = 0; i < 14; i++) {
		ptr = strchr(tmp_ptr, '#');
		if ( ptr == NULLCP ) {
			parse_error("error in printable representation of cross-certificate", NULLCP);
			aux_add_error(EINVALID, "error in printable representation of cross-certificate", CNULL, 0, proc);
			free( (OCList * )ret );
			return( (OCList * )0 );
		}
		tmp_ptr = ptr + 1;
	}

	*(tmp_ptr - 1) = '\0'; /* replacing the last '#' of the first cross-certificate
					by '\0' */

	quipu_cert = str2cert(str);
	if ( quipu_cert == (struct certificate *)0 ) {
		free( (OCList * )ret );
		aux_add_error(EINVALID, "str2cert(str) empty", CNULL, 0, proc);
		return( (OCList * )0 );
	}

	pe = cert_enc(quipu_cert);
	if ( pe == NULLPE ) {
		free( (OCList * )ret );
		aux_add_error(EINVALID, "cert_enc failed", CNULL, 0, proc);
		cert_free(quipu_cert);
		return( (OCList * )0 );
	}
	ret->ccert = certificate_dec(pe);
	pe_free(pe);
	if ( ret->ccert == (Certificate * )0 ) {
		free( (OCList * )ret );
		aux_add_error(EINVALID, "certificate_dec failed", CNULL, 0, proc);
		cert_free(quipu_cert);
		return( (OCList * )0 );
	}
	cert_free(quipu_cert);

	if ( !(ocl = (OCList * )malloc(sizeof(OCList))) ) {
		aux_add_error(EMALLOC, "ocl", CNULL, 0, proc);
		free( (Certificate * )ret->ccert );
		free( (OCList * )ret );
		return( (OCList * )0 );
	}


	ret->next = ocl;
	ocl->next = (OCList * )0;
	ocl->ccert = (Certificate * )0;


	str = tmp_ptr;

	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("serialNumber of second list element not present", NULLCP);
		aux_add_error(EINVALID, "serialNumber of second list element not present", CNULL, 0, proc);
		aux_free_OCList(&ret);
		return( (OCList * )0 );
	}
	*ptr = '\0';
	ptr++;

	ocl->serialnumber = atoi(str);

	str = ptr;

	for (tmp_ptr = str, i = 0; i < 14; i++) {
		ptr = strchr(tmp_ptr, '#');
		if ( ptr == NULLCP ) {
			parse_error("error in printable representation of cross-certificate", NULLCP);
			aux_add_error(EINVALID, "error in printable representation of cross-certificate", CNULL, 0, proc);
			free( (OCList * )ret );
			return( (OCList * )0 );
		}
		tmp_ptr = ptr + 1;
	}

	*(tmp_ptr - 1) = '\0'; /* replacing the last '#' of the second cross-certificate
					by '\0' */

	quipu_cert = str2cert(str);
	if ( quipu_cert == (struct certificate *)0 ) {
		aux_free_OCList(&ret);
		aux_add_error(EINVALID, "str2cert(str) empty", CNULL, 0, proc);
		return( (OCList * )0 );
	}

	pe = cert_enc(quipu_cert);
	if ( pe == NULLPE ) {
		aux_free_OCList(&ret);
		cert_free(quipu_cert);
		aux_add_error(EINVALID, "cert_enc failed", CNULL, 0, proc);
		return( (OCList * )0 );
	}
	ocl->ccert = certificate_dec(pe);
	pe_free(pe);
	if ( ocl->ccert == (Certificate * )0 ) {
		aux_free_OCList(&ret);
		aux_add_error(EINVALID, "certificate_dec failed", CNULL, 0, proc);
		cert_free(quipu_cert);
		return( (OCList * )0 );
	}
	cert_free(quipu_cert);


	save_ocl = ocl;


	str = tmp_ptr;


	while ( (ptr = strchr(str, '#')) != NULLCP ) {

		if ( !(ocl = (OCList * )malloc(sizeof(OCList))) ) {
			aux_add_error(EMALLOC, "ocl", CNULL, 0, proc);
			aux_free_OCList(&ret);
			return( (OCList * )0 );
		}

		save_ocl->next = ocl;
		save_ocl = ocl;
		ocl->next = (OCList * )0;
		ocl->ccert = (Certificate * )0;

		*ptr = '\0';
		ptr++;

		ocl->serialnumber = atoi(str);

		str = ptr;

		for (tmp_ptr = str, i = 0; i < 14; i++) {
			ptr = strchr(tmp_ptr, '#');
			if ( ptr == NULLCP ) {
				parse_error("error in printable representation of cross-certificate", NULLCP);
				aux_add_error(EINVALID, "error in printable representation of cross-certificate", CNULL, 0, proc);
				free( (OCList * )ret );
				return( (OCList * )0 );
			}
			tmp_ptr = ptr + 1;
		}

		*(tmp_ptr - 1) = '\0'; /* replacing the last '#' of the second cross-certificate
							by '\0' */

		quipu_cert = str2cert(str);
		if ( quipu_cert == (struct certificate *)0 ) {
			aux_add_error(EINVALID, "str2cert(str) empty", CNULL, 0, proc);
			aux_free_OCList(&ret);
			return( (OCList * )0 );
		}

		pe = cert_enc(quipu_cert);
		if ( pe == NULLPE ) {
			aux_free_OCList(&ret);
			aux_add_error(EINVALID, "cert_enc failed", CNULL, 0, proc);
			cert_free(quipu_cert);
			return( (OCList * )0 );
		}
		ocl->ccert = certificate_dec(pe);
		pe_free(pe);
		if ( ocl->ccert == (Certificate * )0 ) {
			aux_free_OCList(&ret);
			aux_add_error(EINVALID, "certificate_dec failed", CNULL, 0, proc);
			cert_free(quipu_cert);
			return( (OCList * )0 );
		}
		cert_free(quipu_cert);

		str = tmp_ptr;

	}    /* while */

	return (ret);
}


printocl(ps, parm, format)
PS ps;
OCList *parm;
int	format;
{
	PE 		     pe;
	struct certificate * quipu_cert;
	OCList 		   * ocl;
	char	  	   * proc = "printocl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( parm ) {

		ps_printf(ps, "%d#", parm->serialnumber);

		if ( parm->ccert ) {
			build_AF_Certificate (&pe, 0, 0, NULLCP, parm->ccert);
			quipu_cert = cert_dec(pe);
			pe_free(pe);
			if ( quipu_cert ) {
				printcert(ps, quipu_cert, format);
				cert_free(quipu_cert);
			}
		}

		/*  Notice: printcert() appends a "#" to the printed certificate.
	 */

		ocl = parm->next;

		while ( ocl ) {
			ps_printf(ps, "%d#", ocl->serialnumber);

			if ( ocl->ccert ) {
				build_AF_Certificate (&pe, 0, 0, NULLCP, ocl->ccert);
				quipu_cert = cert_dec(pe);
				pe_free(pe);
				if ( quipu_cert ) {
					printcert(ps, quipu_cert, format);
					cert_free(quipu_cert);
				}
			}

			ocl = ocl->next;
		}  /*while*/

	}  /*if*/
}


int	aux_oclist_cmp(a, b)
OCList *a, *b;
{
	int	ret;

	if ( a->serialnumber > b->serialnumber )
		return (1);
	if ( a->serialnumber < b->serialnumber )
		return (-1);

	if ( a->ccert == (Certificate * )0 ) {
		if ( b->ccert == (Certificate * )0 )
			ret = 0;
		else
			ret = 1;
	} else {
		if ( b->ccert == (Certificate * )0 )
			ret = -1;
		else
			ret = aux_cert_cmp(a->ccert, b->ccert);
	}

	if ( ret != 0 )
		return (ret);

	a = a->next;
	b = b->next;

	while ( a && b ) {
		if ( a->serialnumber > b->serialnumber )
			return (1);
		if ( a->serialnumber < b->serialnumber )
			return (-1);

		if ( a->ccert == (Certificate * )0 ) {
			if ( b->ccert == (Certificate * )0 )
				ret = 0;
			else
				ret = 1;
		} else {
			if ( b->ccert == (Certificate * )0 )
				ret = -1;
			else
				ret = aux_cert_cmp(a->ccert, b->ccert);
		}

		if ( ret != 0 )
			return (ret);

		a = a->next;
		b = b->next;
	}    /*while*/

	if ( a == (OCList * )0 ) {
		if ( b == (OCList * )0 )
			ret = 0;
		else
			ret = 1;
	} else /*  b = (OCList *)0  */
		ret = -1;

	return (ret);
}


oclist_syntax() 
{
	(void) add_attribute_syntax(
	    "OldCertificateList",
	    (IFP) oclist_enc,       (IFP) oclist_dec,
	    (IFP) str2ocl,          (IFP) printocl,
	    (IFP) aux_cpy_OCList,   (IFP) aux_oclist_cmp,
	    aux_free_OCList,        NULLCP,
	    NULLIFP, 	        TRUE);
}


/*******************************************************************************
 *
 *      Attribute Syntax for RevCertPem (revoked certificate according to PEM)
 *
 *******************************************************************************/



PE revcertpem_enc(parm)
RevCertPem *parm;
{
	PE pe;

	if ( parm == (RevCertPem * )0 )
		return (NULLPE);

	(void) build_AF_RevCertPem (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


RevCertPem *revcertpem_dec(pe)
PE pe;
{
	RevCertPem * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (RevCertPem * )0 );

	/*NOTE: parameter is of type RevCertPem ** (not *!) */
	result = parse_AF_RevCertPem (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (RevCertPem * )0 : ret);
}


print_revcertpem(ps, parm, format)
PS ps;
RevCertPem *parm;
int	format;
{
	ps_printf(ps, "%d#", parm->serialnumber);
	ps_printf(ps, "%s#", parm->revocationDate);
}


int	aux_revcertpem_cmp(a, b)
RevCertPem *a;
RevCertPem *b;
{
	/* It is assumed that a and b are contained in the same PEM revocation list, 
	 * that is, have the same issuer.
	 */

	if ( a->serialnumber > b->serialnumber )
		return (1);
	if ( a->serialnumber < b->serialnumber )
		return (-1);

	return (0);
}


/*******************************************************************************
 *
 *      Attribute Syntax for SEQUENCE of Revoked Certificates
 *
 *******************************************************************************/


PE revcertpemseq_enc(parm)
SEQUENCE_OF_RevCertPem *parm;
{
	PE pe;

	(void) build_AF_RevCertPemSequence (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


SEQUENCE_OF_RevCertPem *revcertpemseq_dec(pe)
PE pe;
{
	SEQUENCE_OF_RevCertPem * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (SEQUENCE_OF_RevCertPem * )0 );
	/*NOTE:							*/
	/*space for SEQUENCE_OF_RevCertPem structure allocated  */
	/*by parse_AF_RevCertPemSequence(), parameter is of     */
	/*type SEQUENCE_OF_RevCertPem ** (not *!)		*/

	result = parse_AF_RevCertPemSequence (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (SEQUENCE_OF_RevCertPem * )0 : ret);
}


/*******************************************************************************
 *
 *      Attribute Syntax for PemCrl (revocation list according to PEM)
 *
 *******************************************************************************/


PE pemcrl_enc(parm)
PemCrl *parm;
{
	PE pe;

	if ( parm == (PemCrl * )0 )
		return (NULLPE);

	(void) build_AF_PemCrl (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


PemCrl *pemcrl_dec(pe)
PE pe;
{
	PemCrl * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (PemCrl * )0 );

	/*NOTE: parameter is of type PemCrl ** (not *!) */
	result = parse_AF_PemCrl (pe, 1, NULLIP, NULLCP, &ret);

	return (result ? (PemCrl * )0 : ret);
}


PE pemcrltbs_enc(parm)
PemCrlTBS *parm;
{
	PE pe;

	(void) build_AF_TBSPemCrl (&pe, 0, 0, NULLCP, parm);
	return (pe);
}


PemCrlTBS *pemcrltbs_dec(pe)
PE pe;
{
	PemCrlTBS * ret;
	int	result;

	if ( pe == NULLPE )
		return ( (PemCrlTBS * )0 );

	/* allocate space for PemCrlTBS structure: */
	if ( (ret = (PemCrlTBS * )malloc(sizeof(PemCrlTBS))) == (PemCrlTBS * )0 )
		return ( (PemCrlTBS * )0 );

	/*NOTE: parameter is of type PemCrlTBS * (not **!) */
	result = parse_AF_TBSPemCrl (pe, 1, NULLIP, NULLCP, ret);

	return (result ? (PemCrlTBS * )0 : ret);
}


PemCrl *str2pemcrl(str)
char	*str;
{
	PemCrl		 * result;
	SEQUENCE_OF_RevCertPem 	 * seq;
	SEQUENCE_OF_RevCertPem   * save_seq;
	struct alg_id 		   alg;
	char			 * ptr;
	int			   first_elem = 1;
	PE 			   pe;
	DN			   dn;
	OIDentifier		 * oid;
	char			 * proc = "str2pemcrl";

	/*    OID = ObjId*
	 *    s. /isode/share/include/psap.h
 	 */

	/*    dn_enc() from  /isode/share/src/dsap/common/dn_str.c
	 */

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !(result = (PemCrl * )malloc(sizeof(PemCrl))) )
		return( (PemCrl * )0 );

	result->tbs_DERcode = (OctetString * )0;

	result->tbs = (PemCrlTBS * )malloc(sizeof(PemCrlTBS));
	if (!result->tbs)
		return ((PemCrl * ) 0);

	result->sig = (Signature * )malloc(sizeof(Signature));
	if (!result->sig)
		return( (PemCrl * )0 );

	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Algorithm not present", NULLCP);
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	oid = name2oid(str);
	if ( oid == NULLOID) {
		parse_error("Bad algorithm identifier", NULLCP);
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}

	alg.algorithm = oid;

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Parameters not present", NULLCP);
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2alg(str, &alg);
	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
	result->sig->signAI = AlgId_dec(pe);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Signature not present", NULLCP);
		aux_free_AlgId( &(result->sig->signAI) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2encrypted (str, &(result->sig->signature.bits), &(result->sig->signature.nbits));

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Algorithm not present", NULLCP);
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	oid = name2oid(str);
	if (oid == NULLOID ) {
		parse_error("Bad algorithm identifier", NULLCP);
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}

	alg.algorithm = oid;

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Parameters not present", NULLCP);
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	str2alg(str, &alg);
	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &alg);
	result->tbs->signatureAI = AlgId_dec(pe);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Issuer not present", NULLCP);
		aux_free_AlgId( &(result->tbs->signatureAI) );
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	dn = str2dn(str);
	pe = dn_enc(dn);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &result->tbs->issuer);
	pe_free(pe);
	dn_free(dn);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Lastupdate time not present", NULLCP);
		aux_free_DName( &(result->tbs->issuer) );
		aux_free_AlgId( &(result->tbs->signatureAI) );
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;

	result->tbs->lastUpdate = strdup(str);

	str = ptr;
	ptr = strchr(str, '#');
	if ( ptr == NULLCP ) {
		parse_error("Nextupdate time not present", NULLCP);
		aux_free_DName( &(result->tbs->issuer) );
		aux_free_AlgId( &(result->tbs->signatureAI) );
		aux_free_KeyInfo( &(result->sig) );
		free( (PemCrl * )result );
		return( (PemCrl * )0 );
	}
	*ptr = '\0';
	ptr++;
	/* This may be the end of the string */

	result->tbs->nextUpdate = strdup(str);

	while ( str = ptr, ((ptr = strchr(str, '#')) != NULLCP) ) {

		*ptr = '\0';
		ptr++;

		if ( !(seq = (SEQUENCE_OF_RevCertPem * )malloc(sizeof(SEQUENCE_OF_RevCertPem))) ) {
			free( (char *)result->tbs->lastUpdate );
			aux_free_DName( &(result->tbs->issuer) );
			aux_free_AlgId( &(result->tbs->signatureAI) );
			aux_free_KeyInfo( &(result->sig) );
			free( (PemCrl * )result );
			return( (PemCrl * )0 );
		}

		if ( first_elem ) {
			result->tbs->revokedCertificates = seq;
			first_elem = 0;
		} else
			save_seq->next = seq;

		save_seq = seq;
		seq->next = (SEQUENCE_OF_RevCertPem * )0;

		if ( !(seq->element = (RevCertPem * )malloc(sizeof(RevCertPem))) ) {
			aux_free_PemCrl(&result);
			return( (PemCrl * )0 );
		}

		seq->element->serialnumber = atoi(str);     /* CertificateSerialNumber */

		str = ptr;
		ptr = strchr(str, '#');
		if ( ptr == NULLCP ) {
			parse_error("Revocation date not present", NULLCP);
			free( (RevCertPem * )seq->element );
			seq->element = (RevCertPem * ) 0;
			aux_free_PemCrl(&result);
			return( (PemCrl * )0 );
		}
		*ptr = '\0';
		ptr++;
		/* This may be the end of the string */

		seq->element->revocationDate = strdup(str);

	}    /* while */

	if ( first_elem ) {		/*Schwarze Liste ist leer, sonst waere first_elem
						  naemlich auf Null gesetzt worden!*/
		result->tbs->revokedCertificates = (SEQUENCE_OF_RevCertPem * )0;
	}

	return (result);
}


/* The  *tbs_DERcode-component within PemCrl is constructed in the
	 * DECODER-parse-section of pepy:
	 *
	 *      parm->tbs_DERcode = aux_PE2OctetString($$)                                
	 */


/* The  *tbs_DERcode-component within RevCertPem is constructed in 
	 * the DECODER-parse-section of pepy:
	 *
	 *	parm->tbs_DERcode = aux_PE2OctetString($$)
	 */

printpemcrl(ps, parm, format)
PS ps;
PemCrl *parm;
int	format;
{
	struct alg_id 		* alg;
	PE 			  pe;
	DN 			  dn;
	SEQUENCE_OF_RevCertPem  * seq;
	int			  result;
	char		  	* proc = "printpemcrl";

	/*  Abfrage in calling routine
 	 */

	/*  dn_dec() from  /isode/share/src/dsap/common/dn_str.c
 	 */

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	pe = AlgId_enc(parm->sig->signAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	print_encrypted(ps, parm->sig->signature.bits, parm->sig->signature.nbits, 
	    format);

	pe = AlgId_enc(parm->tbs->signatureAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &alg);
	print_algid(ps, alg, format);
	pe_free(pe);
	free( (struct alg_id *)alg );
	alg = (struct alg_id *) 0;

	build_IF_Name(&pe, 1, 0, NULLCP, parm->tbs->issuer);
	dn = dn_dec(pe);
	dn_print(ps, dn, EDBOUT);
	ps_printf(ps, "#");
	pe_free(pe);
	dn_free(dn);

	ps_printf(ps, "%s#", parm->tbs->lastUpdate);
	ps_printf(ps, "%s#", parm->tbs->nextUpdate);

	seq = parm->tbs->revokedCertificates;

	while ( seq ) {
		print_revcertpem(ps, seq->element, format);
		seq = seq->next;
	}
}


int	aux_pemcrl_cmp(a, b)
PemCrl *a;
PemCrl *b;
{
	int ret;

	ret = aux_cmp_DName(a->tbs->issuer, b->tbs->issuer);
	if ( ret != 0 )
		return (ret);

	return(strcmp(a->tbs->lastUpdate, b->tbs->lastUpdate));
}


pemcrl_syntax() 
{
	(void) add_attribute_syntax(
	    "pemCRL_syntax",
	    (IFP) pemcrl_enc,       (IFP) pemcrl_dec,
	    (IFP) str2pemcrl,       (IFP) printpemcrl,
	    (IFP) aux_cpy_PemCrl ,  (IFP) aux_pemcrl_cmp,
	    NULLIFP, 		  NULLCP,
	    NULLIFP, 	          TRUE);
}


#else

aux_cert_cmp() 
{
	return(0);
}

#endif
