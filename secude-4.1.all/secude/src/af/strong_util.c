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
/*------------------------------------------------------------------*/
/*-----------Functions for Strong Authentication support------------*/

/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``PASSWORD'' 1993                                        */
/*------------------------------------------------------------------*/


#ifdef X500
#ifdef STRONG

#include "psap.h"
#include "af.h"
#include "secude-stub.h"
#include "x500as/AF-types.h"
#include "quipu/common.h"
#include "quipu/DAS-types.h"  /* for definition of encode_DAS_PartialOutcomeQualifier() */
#include "quipu/Quipu-types.h"  /* for definition of decode_Quipu_ACLSyntax() */
#include "quipu/attrvalue.h"
#include "quipu/authen.h"

extern AlgId              * AlgId_dec();
extern PE		    AlgId_enc();
extern PE 		    cert_enc();
extern struct certificate * cert_dec();
extern Certificate        * certificate_dec();
extern PE 		    dn_enc ();
extern void                 encode_IF_RelativeDistinguishedName ();  /* from ISODE */
extern PE	            pe_cpy ();	   /* from isode/psap.h */
extern void  		    aux_xdump2();
extern PE 	            grab_pe();
extern 			    test_acl_default();


PE 	              	    aux_OctetString2PE();


Signature * aux_QUIPUsign2SECUDEsign(quipusign)
struct signature * quipusign;
{

	Signature        * sig;
	PE 	           pe;
	int	           i, nob;
	char	         * proc = "aux_QUIPUsign2SECUDEsign";

	if(! quipusign){
		aux_add_error(EINVALID, "No parameter provided (quipusign)", CNULL, 0, proc);
		return((Signature * )0);
	}

/*
	quipusign->alg.asn = NULLPE;
*/

	sig = (Signature * )malloc(sizeof(Signature));

	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &(quipusign->alg));
	sig->signAI = AlgId_dec(pe);
	if(pe) pe_free (pe);
	if(! sig->signAI){
		aux_add_error(EDECODE, "AlgId_dec failed", CNULL, 0, proc);
		return((Signature * )0);
	}

	sig->signature.nbits = quipusign->n_bits;
	nob = sig->signature.nbits / 8;
	if(sig->signature.nbits % 8 )
		nob++;
	sig->signature.bits = (char * )malloc(nob);

	for ( i = 0; i < nob; i++) {
		sig->signature.bits[i] = quipusign->encrypted[i];
	}

	return(sig);
 
}


struct signature * aux_SECUDEsign2QUIPUsign(secudesign)
Signature * secudesign;
{
	
	struct signature          * quipusign;
	PE	                    pe;
	struct alg_id             * quipu_alg;
	int		            result, i, nob;
	char	                  * proc = "aux_SECUDEsign2QUIPUsign";

	if(! secudesign){
		aux_add_error(EINVALID, "No parameter provided (secudesign)", CNULL, 0, proc);
		return((struct signature * )0);
	}

	quipusign = (struct signature * )malloc(sizeof(struct signature));

	pe = AlgId_enc(secudesign->signAI);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &quipu_alg);
	pe_free(pe);
	if(result == NOTOK) {
		aux_add_error(EDECODE, "ret", CNULL, 0, proc);
		return((struct signature * )0);
	}
	alg_cpy(&(quipusign->alg), quipu_alg);

	quipusign->n_bits = secudesign->signature.nbits;
	nob = quipusign->n_bits / 8;
	if(quipusign->n_bits % 8 )
		nob++;
	quipusign->encrypted = (char * )malloc(nob);

	for ( i = 0; i < nob; i++)
		quipusign->encrypted[i] = secudesign->signature.bits[i];

	quipusign->encoded = NULLPE;

	return(quipusign);

}



struct certificate_list * aux_SECUDEocert2QUIPUcertlist(certs)
Certificates * certs;
{

	struct certificate_list        * ret;
	SET_OF_Certificate             * certset;
	PE	                         pe;
	char	                       * proc = "aux_SECUDEocert2QUIPUcertlist";

	if(! certs){
		aux_add_error(EINVALID, "No parameter provided (certs)", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}

	ret = (struct certificate_list * )malloc(sizeof(struct certificate_list));

	if((pe = certificate_enc(certs->usercertificate)) == NULLPE){
		aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}
	if((ret->cert = cert_dec(pe)) == (struct certificate * )0) {
		pe_free(pe);
		aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}
	pe_free(pe);

	ret->reverse = (struct certificate *)0;
	ret->next = ret->prev = (struct certificate_list *)0;
	ret->superior = aux_SECUDEfcpath2QUIPUcertlist(certs->forwardpath);

	return(ret);

}



struct certificate_list * aux_SECUDEfcpath2QUIPUcertlist(fcpath)
FCPath * fcpath;
{

	struct certificate_list        * ret, * same_level;
	SET_OF_Certificate             * certset;
	PE	                         pe;
	char	                       * proc = "aux_SECUDEfcpath2QUIPUcertlist";

	if(! fcpath){
		aux_add_error(EINVALID, "No parameter provided (fcpath)", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}

	ret = (struct certificate_list * )malloc(sizeof(struct certificate_list));

	certset = fcpath->liste;

	if((pe = certificate_enc(certset->element)) == NULLPE){
		aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}
	if((ret->cert = cert_dec(pe)) == (struct certificate * )0) {
		pe_free(pe);
		aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
		return((struct certificate_list * )0);
	}
	pe_free(pe);

	ret->reverse = (struct certificate *)0;
	ret->next = ret->prev = (struct certificate_list *)0;

	same_level = ret;
	certset = certset->next;

	while (certset) {
		same_level->next = (struct certificate_list * )malloc(sizeof(struct certificate_list));
			
		same_level = same_level->next;

		if((pe = certificate_enc(certset->element)) == NULLPE){
			aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
			return((struct certificate_list * )0);
		}
		if((same_level->cert = cert_dec(pe)) == (struct certificate * )0) {
			pe_free(pe);
			aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
			return((struct certificate_list * )0);
		}
		pe_free(pe);

		same_level->reverse = (struct certificate *)0;
		same_level->next = same_level->prev = same_level->superior = (struct certificate_list *)0;

		certset = certset->next;
	} /*while*/

	ret->superior = aux_SECUDEfcpath2QUIPUcertlist(fcpath->next_forwardpath);

	return(ret);

}



Certificates * aux_QUIPUcertlist2SECUDEocert(certlist)
struct certificate_list * certlist;
{
	Certificates        * ret;
	PE                    pe;
	char	            * proc = "aux_QUIPUcertlist2SECUDEocert";

	if(! certlist){
		aux_add_error(EINVALID, "No parameter provided (certlist)", CNULL, 0, proc);
		return((Certificates * )0);
	}

	if((ret = (Certificates * )malloc(sizeof(Certificates))) == (Certificates * )0) 
		return((Certificates * )0);

	if((pe = cert_enc(certlist->cert)) == NULLPE ) 
		return((Certificates * )0);

	if((ret->usercertificate = certificate_dec(pe)) == (Certificate * )0) {
		pe_free (pe);
		return((Certificates * )0);
	}

	pe_free (pe);

	ret->forwardpath = aux_QUIPUcertlist2SECUDEfcpath(certlist->superior);

	return(ret);
}



FCPath * aux_QUIPUcertlist2SECUDEfcpath(certlist)
struct certificate_list  * certlist;
{
	FCPath                     * ret;
	PE                           pe;
	SET_OF_Certificate         * tmp_certset;
	struct certificate_list    * same_level;
	char                       * proc = "aux_QUIPUcertlist2SECUDEfcpath";

	if(! certlist){
		aux_add_error(EINVALID, "No parameter provided (certlist)", CNULL, 0, proc);
		return((FCPath * )0);
	}

	if((ret = (FCPath * )malloc(sizeof(FCPath))) == (FCPath * )0) {
		return((FCPath * )0);
	}

	if((ret->liste = (SET_OF_Certificate * )
				malloc(sizeof(SET_OF_Certificate))) == (SET_OF_Certificate * )0) {
		return((FCPath * )0);
	}
	
	tmp_certset = ret->liste;

	if((pe = cert_enc(certlist->cert)) == NULLPE)
		return((FCPath * )0);

	if((ret->liste->element = certificate_dec(pe)) == (Certificate * )0) {
		pe_free (pe);
		return((FCPath * )0);
	}
	ret->liste->next = (SET_OF_Certificate * )0;

	pe_free (pe);

	same_level = certlist->next;

	while (same_level) {
		if((tmp_certset->next = (SET_OF_Certificate * )
				malloc(sizeof(SET_OF_Certificate))) == (SET_OF_Certificate * )0) {
			return((FCPath * )0);
		}
		tmp_certset = tmp_certset->next;
		if((pe = cert_enc(same_level->cert)) == NULLPE){
			return((FCPath * )0);
		}

		if((tmp_certset->element = certificate_dec(pe)) == (Certificate * )0) {
			pe_free (pe);
			return((FCPath * )0);
		}
		tmp_certset->next = (SET_OF_Certificate *)0;
		pe_free (pe);
		same_level = same_level->next;
	}
	
	ret->next_forwardpath = aux_QUIPUcertlist2SECUDEfcpath(certlist->superior);

	return(ret);
}


CertificationPath * aux_QUIPUcertlist2SECUDEcertpath(certlist)
struct certificate_list * certlist;
{
	CertificationPath        * ret;
	PE                         pe;
	char	                 * proc = "aux_QUIPUcertlist2SECUDEcertpath";

	if(! certlist){
		aux_add_error(EINVALID, "No parameter provided (certlist)", CNULL, 0, proc);
		return((CertificationPath * )0);
	}

	if((ret = (CertificationPath * )
				malloc(sizeof(CertificationPath))) == (CertificationPath * )0) 
		return((CertificationPath * )0);

	if((pe = cert_enc(certlist->cert)) == NULLPE ) 
		return((CertificationPath * )0);

	if((ret->userCertificate = certificate_dec(pe)) == (Certificate * )0) {
		pe_free (pe);
		return((CertificationPath * )0);
	}
	pe_free (pe);

	ret->theCACertificates = aux_QUIPUcertlist2SECUDEcertificatepairs(certlist->superior);

	return(ret);
}



CertificatePairs * aux_QUIPUcertlist2SECUDEcertificatepairs(certlist)
struct certificate_list  * certlist;
{
	CertificatePairs               * ret;
	SEQUENCE_OF_CertificatePair    * tmp;
	struct certificate_list        * same_level;
	PE                               pe;
	char                           * proc = "aux_QUIPUcertlist2SECUDEcertificatepairs";

	if(! certlist){
		aux_add_error(EINVALID, "No parameter provided (certlist)", CNULL, 0, proc);
		return((CertificatePairs * )0);
	}

	if((ret = (CertificatePairs * ) malloc(sizeof(CertificatePairs))) == (CertificatePairs * )0) {
		return((CertificatePairs * )0);
	}

	if((ret->liste = (SEQUENCE_OF_CertificatePair * )
			malloc(sizeof(SEQUENCE_OF_CertificatePair))) == (SEQUENCE_OF_CertificatePair * )0) {
		return((CertificatePairs * )0);
	}

	tmp = ret->liste;

	if((tmp->element = (CertificatePair * )
				malloc(sizeof(CertificatePair))) == (CertificatePair * )0) {
		return((CertificatePairs * )0);
	}

	tmp->element->forward = (Certificate *)0;
	tmp->element->reverse = (Certificate *)0;
	tmp->next = (SEQUENCE_OF_CertificatePair *)0;

	if(certlist->cert){
		if((pe = cert_enc(certlist->cert)) == NULLPE){
			return((CertificatePairs * )0);
		}
		if((tmp->element->forward = certificate_dec(pe)) == (Certificate * )0) {
			pe_free (pe);
			return((CertificatePairs * )0);
		}
		pe_free (pe);
	}

	if(certlist->reverse){
		if((pe = cert_enc(certlist->reverse)) == NULLPE){
			return((CertificatePairs * )0);
		}
		if((tmp->element->reverse = certificate_dec(pe)) == (Certificate * )0) {
			pe_free (pe);
			return((CertificatePairs * )0);
		}
		pe_free (pe);
	}

	same_level = certlist->next;

	while (same_level) {
		if((tmp->next = (SEQUENCE_OF_CertificatePair * )
				malloc(sizeof(SEQUENCE_OF_CertificatePair))) == (SEQUENCE_OF_CertificatePair * )0) {
			return((CertificatePairs * )0);
		}

		tmp = tmp->next;

		if((tmp->element = (CertificatePair * )
					malloc(sizeof(CertificatePair))) == (CertificatePair * )0) {
			return((CertificatePairs * )0);
		}

		tmp->element->forward = (Certificate *)0;
		tmp->element->reverse = (Certificate *)0;
		tmp->next = (SEQUENCE_OF_CertificatePair *)0;

		if(same_level->cert){
			if((pe = cert_enc(same_level->cert)) == NULLPE){
				return((CertificatePairs * )0);
			}
			if((tmp->element->forward = certificate_dec(pe)) == (Certificate * )0) {
				pe_free (pe);
				return((CertificatePairs * )0);
			}
			pe_free (pe);
		}

		if(same_level->reverse){
			if((pe = cert_enc(same_level->reverse)) == NULLPE){
				return((CertificatePairs * )0);
			}
			if((tmp->element->reverse = certificate_dec(pe)) == (Certificate * )0) {
				pe_free (pe);
				return((CertificatePairs * )0);
			}
			pe_free (pe);
		}

		same_level = same_level->next;
	}
	
	ret->superior = aux_QUIPUcertlist2SECUDEcertificatepairs(certlist->superior);

	return(ret);
}


ObjId * aux_QUIPUAttributeType2SECUDEObjId (parm)
oid_table_attr * parm;
{
	ObjId * oid;
	int     i;
	char  * proc = "aux_QUIPUAttributeType2SECUDEObjId";


	if(! parm || (parm->oa_ot.ot_oid == (OIDentifier * )0) || 
	    ((parm->oa_ot.ot_oid->oid_nelem > 0) && (parm->oa_ot.ot_oid->oid_elements == (unsigned int * )0))){
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return(NULLOBJID);
	}

	oid = (ObjId * )malloc(sizeof(ObjId));

	oid->oid_nelem = parm->oa_ot.ot_oid->oid_nelem;
	if(! oid->oid_nelem){
		oid->oid_nelem = 0;
		oid->oid_elements = (unsigned * )0;
	} 
	else {
		oid->oid_elements = (unsigned int * )malloc(parm->oa_ot.ot_oid->oid_nelem * sizeof(unsigned int));
		for ( i = 0; i < parm->oa_ot.ot_oid->oid_nelem; i++)
			oid->oid_elements[i] = parm->oa_ot.ot_oid->oid_elements[i];
	}
	return(oid);
}


SET_OF_Attr * aux_QUIPUAttrSequence2SECUDESETOFAttr (parm)
Attr_Sequence parm;
{
	SET_OF_Attr                    * ret, * ret_tmp;
	Attr_Sequence  	                 parm_tmp;
	PE			         pe;
	AV_Sequence                      avseq = NULLAV;
	struct type_IF_AttributeValues * attrvalues;
	AccessControlList	       * acl;
	struct acl		       * quipu_acl;
	OctetString		       * ostr;
	int			         rc;
	char         	               * proc = "aux_QUIPUAttrSequence2SECUDESETOFAttr";


	if(! parm || ! parm->attr_type){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_Attr * )0);
	}

	ret = (SET_OF_Attr * )malloc(sizeof(SET_OF_Attr));

	ret->element = (Attr * )malloc(sizeof(Attr));

	ret->element->type = (OIDentifier * ) aux_QUIPUAttributeType2SECUDEObjId (parm->attr_type);
	if(! ret->element->type){
		aux_add_error(EINVALID, "parm->attr_type", CNULL, 0, proc);
		return((SET_OF_Attr * )0);
	}
	if(parm->attr_value){
		avseq = parm->attr_value;
		ret->element->values = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));

		if (! aux_cmp_ObjId(ret->element->type, Acl_OID)) {
			pe = grab_pe(avseq->avseq_av);
			rc = decode_Quipu_ACLSyntax(pe, 0, NULLIP, NULLVP, &quipu_acl);
			if(rc == OK){
				acl = aux_QUIPUacl2SECUDEacl(quipu_acl);
				ostr = e_ACL(acl);
				ret->element->values->member_IF_1 = aux_OctetString2PE(ostr);
				aux_free_OctetString(&ostr);
			}
			else {
				ret->element->values->member_IF_1 = pe_cpy(pe);
			}
			if(pe) pe_free(pe);
		}
		else
			ret->element->values->member_IF_1 = grab_pe(avseq->avseq_av);

		ret->element->values->next = (struct type_IF_AttributeValues * )0;
		attrvalues = ret->element->values;

		avseq = avseq->avseq_next;
		while(avseq){
			attrvalues->next = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));

			attrvalues = attrvalues->next;
			attrvalues->member_IF_1 = grab_pe(avseq->avseq_av);
			attrvalues->next = (struct type_IF_AttributeValues * )0;

			avseq = avseq->avseq_next;
		}
	}
	else ret->element->values = (struct type_IF_AttributeValues * )0;

	ret->next = (SET_OF_Attr *)0;

	for (ret_tmp = ret, parm_tmp = parm->attr_link; parm_tmp; parm_tmp = parm_tmp->attr_link) {
		ret_tmp->next = (SET_OF_Attr * )malloc(sizeof(SET_OF_Attr));

		ret_tmp = ret_tmp->next;

		ret_tmp->element = (Attr * )malloc(sizeof(Attr));

		ret_tmp->element->type = (OIDentifier * ) aux_QUIPUAttributeType2SECUDEObjId (parm_tmp->attr_type);
		if(! ret_tmp->element->type){
			aux_add_error(EINVALID, "parm_tmp->attr_type", CNULL, 0, proc);
			return((SET_OF_Attr * )0);
		}

		if(parm_tmp->attr_value){
			avseq = parm_tmp->attr_value;
			ret_tmp->element->values = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));

			if (! aux_cmp_ObjId(ret_tmp->element->type, Acl_OID)) {
				pe = grab_pe(avseq->avseq_av);
				rc = decode_Quipu_ACLSyntax(pe, 0, NULLIP, NULLVP, &quipu_acl);
				if(rc == OK){
					acl = aux_QUIPUacl2SECUDEacl(quipu_acl);
					ostr = e_ACL(acl);
					ret_tmp->element->values->member_IF_1 = aux_OctetString2PE(ostr);
					aux_free_OctetString(&ostr);
				}
				else {
					ret_tmp->element->values->member_IF_1 = pe_cpy(pe);
				}
				if(pe) pe_free(pe);
			}
			else
				ret_tmp->element->values->member_IF_1 = grab_pe(avseq->avseq_av);

			ret_tmp->element->values->next = (struct type_IF_AttributeValues * )0;
			attrvalues = ret_tmp->element->values;

			avseq = avseq->avseq_next;
			while(avseq){
				attrvalues->next = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));

				attrvalues = attrvalues->next;
				attrvalues->member_IF_1 = grab_pe(avseq->avseq_av);
				attrvalues->next = (struct type_IF_AttributeValues * )0;

				avseq = avseq->avseq_next;
			}
		}
		else ret_tmp->element->values = (struct type_IF_AttributeValues * )0;

		ret_tmp->next = (SET_OF_Attr *)0;
	} 

	return(ret);
}


Attr * aux_QUIPUAttrSequence2SECUDEAttr (parm)  /* consider first element of Attr_Sequence only */
Attr_Sequence parm;
{
	Attr                           * ret;
	AV_Sequence         	         avseq = NULLAV;
	struct type_IF_AttributeValues * attrvalues;
	char         	               * proc = "aux_QUIPUAttrSequence2SECUDEAttr";


	if(! parm || ! parm->attr_type){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((Attr * )0);
	}

	ret = (Attr * )malloc(sizeof(Attr));

	ret->type = (OIDentifier * ) aux_QUIPUAttributeType2SECUDEObjId (parm->attr_type);
	if(! ret->type){
		aux_add_error(EINVALID, "parm->attr_type", CNULL, 0, proc);
		return((Attr * )0);
	}
	if(parm->attr_value){
		avseq = parm->attr_value;
		ret->values = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));
		ret->values->member_IF_1 = grab_pe(avseq->avseq_av);
		ret->values->next = (struct type_IF_AttributeValues * )0;
		attrvalues = ret->values;

		avseq = avseq->avseq_next;
		while(avseq){
			attrvalues->next = (struct type_IF_AttributeValues * )malloc(sizeof(struct type_IF_AttributeValues));
			attrvalues = attrvalues->next;
			attrvalues->member_IF_1 = grab_pe(avseq->avseq_av);
			attrvalues->next = (struct type_IF_AttributeValues * )0;

			avseq = avseq->avseq_next;
		}
	}
	else ret->values = (struct type_IF_AttributeValues * )0; 

	return(ret);
}


struct type_IF_AttributeValueAssertion * aux_QUIPUAVA2SECUDEAttrValAssert (parm)
AVA * parm;
{
	struct type_IF_AttributeValueAssertion  * ret;
	char      			        * proc = "aux_QUIPUAVA2SECUDEAttrValAssert";

	if(! parm || ! parm->ava_type || ! parm->ava_value){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((struct type_IF_AttributeValueAssertion * )0);
	}

	ret = (struct type_IF_AttributeValueAssertion * )malloc(sizeof(struct type_IF_AttributeValueAssertion));	
	ret->element_IF_0 = (OIDentifier * ) aux_QUIPUAttributeType2SECUDEObjId (parm->ava_type);
	ret->element_IF_1 = grab_pe(parm->ava_value);

	return(ret);
}


SET_OF_ObjId * aux_QUIPUAttrSequence2SECUDESETOFObjId (parm)
Attr_Sequence parm;
{
	SET_OF_ObjId          * ret, * ret_tmp;
	Attr_Sequence  	        parm_tmp;
	char         	      * proc = "aux_QUIPUAttrSequence2SECUDESETOFObjId";


	if(! parm || ! parm->attr_type){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_ObjId * )0);
	}

	ret = (SET_OF_ObjId * )malloc(sizeof(SET_OF_ObjId));

	ret->element = aux_QUIPUAttributeType2SECUDEObjId (parm->attr_type);
	if(! ret->element){
		aux_add_error(EINVALID, "parm->attr_type", CNULL, 0, proc);
		return((SET_OF_ObjId * )0);
	}
	ret->next = (SET_OF_ObjId *)0;

	for (ret_tmp = ret, parm_tmp = parm->attr_link; parm_tmp; parm_tmp = parm_tmp->attr_link) {
		ret_tmp->next = (SET_OF_ObjId * )malloc(sizeof(SET_OF_ObjId));

		ret_tmp = ret_tmp->next;

		ret_tmp->element = aux_QUIPUAttributeType2SECUDEObjId (parm_tmp->attr_type);
		if(! ret_tmp->element){
			aux_add_error(EINVALID, "parm_tmp->attr_type", CNULL, 0, proc);
			return((SET_OF_ObjId * )0);
		}

		ret_tmp->next = (SET_OF_ObjId *)0;
	} 

	return(ret);
}


ObjId * aux_QUIPUAttrSequence2SECUDEObjId (parm)  /* consider first element of Attr_Sequence only */
Attr_Sequence parm;
{
	ObjId          * ret;
	char           * proc = "aux_QUIPUAttrSequence2SECUDEObjId";


	if(! parm || ! parm->attr_type){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return(NULLOBJID);
	}

	ret = aux_QUIPUAttributeType2SECUDEObjId (parm->attr_type);
	if(! ret){
		aux_add_error(EINVALID, "parm->attr_type", CNULL, 0, proc);
		return(NULLOBJID);
	}

	return(ret);
}


BitString *aux_cpy_random(random)
struct random_number *random;
{
	BitString      bstr;
	char	     * proc = "aux_cpy_random";


	if(! random){
		aux_add_error(EINVALID, "No parameter provided (random)", CNULL, 0, proc);
		return(NULLBITSTRING);
	}

	bstr.nbits = random->n_bits;
	bstr.bits = random->value;

	return(aux_cpy_BitString(&bstr));
}


TokenTBS * aux_extract_TokenTBS_from_BindArg(ds_bindarg)
struct ds_bind_arg * ds_bindarg;
{
	TokenTBS       * tok_tbs;
	PE    	         pe;
	char	       * proc = "aux_extract_TokenTBS_from_BindArg";


	if(! ds_bindarg){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((TokenTBS * )0);
	}

	tok_tbs = (TokenTBS * )malloc(sizeof(TokenTBS));

	encode_AF_AlgorithmIdentifier(&pe, 0, 0, NULLCP, &(ds_bindarg->dba_alg));
	tok_tbs->signatureAI = AlgId_dec(pe);
	if(pe)
		pe_free(pe);
	if(! tok_tbs->signatureAI){
		aux_add_error(EDECODE, "AlgId_dec failed", CNULL, 0, proc);
		return((TokenTBS * )0);
	}

	pe = dn_enc(ds_bindarg->dba_dn);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &tok_tbs->dname);
	pe_free(pe);

	tok_tbs->time = aux_cpy_Name(ds_bindarg->dba_time1);
	tok_tbs->random = aux_cpy_random(&ds_bindarg->dba_r1);

	return(tok_tbs);
}


AddArgumentTBS * aux_extract_AddArgumentTBS_from_AddArg(ds_addarg)
struct ds_addentry_arg * ds_addarg;
{
	AddArgumentTBS  * addarg_tbs;
	PE    	          pe;
	char	        * proc = "aux_extract_AddArgumentTBS_from_AddArg";

	/* ada_object and ada_entry are MANDATORY */
	if(! ds_addarg || ! ds_addarg->ada_object || ! ds_addarg->ada_entry){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((AddArgumentTBS * )0);
	}

	addarg_tbs = (AddArgumentTBS * )malloc(sizeof(AddArgumentTBS));

	pe = dn_enc(ds_addarg->ada_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &addarg_tbs->ada_object);
	pe_free(pe);

	addarg_tbs->ada_entry = aux_QUIPUAttrSequence2SECUDESETOFAttr(ds_addarg->ada_entry);
	addarg_tbs->ada_common = aux_cpy_CommonArguments (& ds_addarg->ada_common);

	return(addarg_tbs);
}


CompareArgumentTBS * aux_extract_CompareArgumentTBS_from_CompareArg(ds_comparearg)
struct ds_compare_arg * ds_comparearg;
{
	CompareArgumentTBS * comparearg_tbs;
	PE    	             pe;
	char	           * proc = "aux_extract_CompareArgumentTBS_from_CompareArg";


	/* cma_object and cma_purported are MANDATORY */
	if(! ds_comparearg || ! ds_comparearg->cma_object){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((CompareArgumentTBS * )0);
	}

	comparearg_tbs = (CompareArgumentTBS * )malloc(sizeof(CompareArgumentTBS));

	pe = dn_enc(ds_comparearg->cma_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &comparearg_tbs->cma_object);
	pe_free(pe);

	comparearg_tbs->cma_purported = aux_QUIPUAVA2SECUDEAttrValAssert(& ds_comparearg->cma_purported);
	comparearg_tbs->cma_common = aux_cpy_CommonArguments (& ds_comparearg->cma_common);

	return(comparearg_tbs);
}


CompareResultTBS * aux_extract_CompareResultTBS_from_CompareRes(ds_compareres)
struct ds_compare_result * ds_compareres;
{
	CompareResultTBS * compareres_tbs;
	PE    	           pe;
	char	         * proc = "aux_extract_CompareResultTBS_from_CompareRes";


	if(! ds_compareres){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((CompareResultTBS * )0);
	}

	compareres_tbs = (CompareResultTBS * )malloc(sizeof(CompareResultTBS));

	if(! ds_compareres->cmr_object)   /* cmr_object is OPTIONAL */
		compareres_tbs->cmr_object = NULLDNAME;
	else {
		pe = dn_enc(ds_compareres->cmr_object);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &compareres_tbs->cmr_object);
		pe_free(pe);
	}

	compareres_tbs->cmr_matched = ds_compareres->cmr_matched;

	/* from das.py */
	if(ds_compareres->cmr_iscopy == INFO_MASTER)
		ds_compareres->cmr_pepsycopy = TRUE;
	else
		ds_compareres->cmr_pepsycopy = FALSE;
	compareres_tbs->cmr_fromEntry = ds_compareres->cmr_pepsycopy;

	compareres_tbs->cmr_common = aux_cpy_CommonRes (& ds_compareres->cmr_common);

	return(compareres_tbs);
}


ListArgumentTBS * aux_extract_ListArgumentTBS_from_ListArg(ds_listarg)
struct ds_list_arg * ds_listarg;
{
	ListArgumentTBS * listarg_tbs;
	PE    	          pe;
	char	        * proc = "aux_extract_ListArgumentTBS_from_ListArg";


	if(! ds_listarg){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ListArgumentTBS * )0);
	}

	listarg_tbs = (ListArgumentTBS * )malloc(sizeof(ListArgumentTBS));

	pe = dn_enc(ds_listarg->lsa_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &listarg_tbs->object);
	pe_free(pe);

	listarg_tbs->lsa_common = aux_cpy_CommonArguments (& ds_listarg->lsa_common);

	return(listarg_tbs);
}


ListResultTBS * aux_extract_ListResultTBS_from_ListRes(ds_listres)
struct ds_list_result * ds_listres;
{
	ListResultTBS * listres_tbs;
	PE    	          pe;
	char	        * proc = "aux_extract_ListResultTBS_from_ListRes";


	if(! ds_listres){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ListResultTBS * )0);
	}

	listres_tbs = (ListResultTBS * )malloc(sizeof(ListResultTBS));

	/* Note uncorrelated will need to be    */
	/* added in to do the secure stuff      */
	/* in a distributed manner              */
	/* this also applies to search          */

	listres_tbs->lsr_type = LSR_INFO;
	listres_tbs->lsrtbs_un.listinfo = aux_cpy_ListInfo (ds_listres);

	return(listres_tbs);
}


ModifyEntryArgumentTBS * aux_extract_ModifyEntryArgumentTBS_from_ModifyEntryArg(ds_modifyentryarg)
struct ds_modifyentry_arg * ds_modifyentryarg;
{
	ModifyEntryArgumentTBS * modifyentryarg_tbs;
	PE    	                 pe;
	char	               * proc = "aux_extract_ModifyEntryArgumentTBS_from_ModifyEntryArg";


	/* mea_object is MANDATORY */
	if(! ds_modifyentryarg || ! ds_modifyentryarg->mea_object){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ModifyEntryArgumentTBS * )0);
	}

	modifyentryarg_tbs = (ModifyEntryArgumentTBS * )malloc(sizeof(ModifyEntryArgumentTBS));

	pe = dn_enc(ds_modifyentryarg->mea_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &modifyentryarg_tbs->mea_object);
	pe_free(pe);

	modifyentryarg_tbs->mea_changes = aux_cpy_SEQUENCE_OF_EntryModification(ds_modifyentryarg->mea_changes);
	modifyentryarg_tbs->mea_common = aux_cpy_CommonArguments (& ds_modifyentryarg->mea_common);

	return(modifyentryarg_tbs);
}


PE rdn_enc (rdn)
RDN rdn;
{
	PE ret_pe;

	(void) encode_IF_RelativeDistinguishedName (&ret_pe,0,0,NULLCP,rdn);
	return(ret_pe);
}


ModifyRDNArgumentTBS * aux_extract_ModifyRDNArgumentTBS_from_ModifyRDNArg(ds_modifyrdnarg)
struct ds_modifyrdn_arg * ds_modifyrdnarg;
{
	ModifyRDNArgumentTBS * modifyrdnarg_tbs;
	PE    	               pe;
	char	             * proc = "aux_extract_ModifyRDNArgumentTBS_from_ModifyRDNArg";


	/* mra_object and mra_newrdn are MANDATORY */
	if(! ds_modifyrdnarg || ! ds_modifyrdnarg->mra_object || ! ds_modifyrdnarg->mra_newrdn){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ModifyRDNArgumentTBS * )0);
	}

	modifyrdnarg_tbs = (ModifyRDNArgumentTBS * )malloc(sizeof(ModifyRDNArgumentTBS));

	pe = dn_enc(ds_modifyrdnarg->mra_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &modifyrdnarg_tbs->mra_object);
	pe_free(pe);

	pe = rdn_enc(ds_modifyrdnarg->mra_newrdn);
	parse_IF_RelativeDistinguishedName(pe, 1, NULLIP, NULLCP, &modifyrdnarg_tbs->mra_newrdn);
	pe_free(pe);

	modifyrdnarg_tbs->deleterdn = ds_modifyrdnarg->deleterdn;
	modifyrdnarg_tbs->mra_common = aux_cpy_CommonArguments (& ds_modifyrdnarg->mra_common);

	return(modifyrdnarg_tbs);
}


ReadArgumentTBS * aux_extract_ReadArgumentTBS_from_ReadArg (ds_readarg)
struct ds_read_arg * ds_readarg;
{
	ReadArgumentTBS * readarg_tbs;
	PE    	          pe;
	char	        * proc = "aux_extract_ReadArgumentTBS_from_ReadArg";


	if(! ds_readarg){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ReadArgumentTBS * )0);
	}

	readarg_tbs = (ReadArgumentTBS * )malloc(sizeof(ReadArgumentTBS));

	pe = dn_enc(ds_readarg->rda_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &readarg_tbs->object);
	pe_free(pe);

	readarg_tbs->rda_common = aux_cpy_CommonArguments (&ds_readarg->rda_common);
	readarg_tbs->rda_eis = aux_cpy_EntryInfoSelection(&ds_readarg->rda_eis);

	return(readarg_tbs);
}


ReadResultTBS * aux_extract_ReadResultTBS_from_ReadRes (ds_readres)
struct ds_read_result * ds_readres;
{
	ReadResultTBS   * readres_tbs;
	PE    	          pe;
	char	        * proc = "aux_extract_ReadResultTBS_from_ReadRes";


	if(! ds_readres){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ReadResultTBS * )0);
	}

	readres_tbs = (ReadResultTBS * )malloc(sizeof(ReadResultTBS));

	readres_tbs->rdr_common = aux_cpy_CommonRes(&ds_readres->rdr_common);
	readres_tbs->rdr_entry = aux_cpy_EntryINFO(&ds_readres->rdr_entry);
	
	return(readres_tbs);
}


RemoveArgumentTBS * aux_extract_RemoveArgumentTBS_from_RemoveArg (ds_removearg)
struct ds_removeentry_arg * ds_removearg;
{
	RemoveArgumentTBS * removearg_tbs;
	PE    	            pe;
	char	          * proc = "aux_extract_RemoveArgumentTBS_from_RemoveArg";


	/* rma_object is MANDATORY */
	if(! ds_removearg || ! ds_removearg->rma_object){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((RemoveArgumentTBS * )0);
	}

	removearg_tbs = (RemoveArgumentTBS * )malloc(sizeof(RemoveArgumentTBS));

	pe = dn_enc(ds_removearg->rma_object);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &removearg_tbs->rma_object);
	pe_free(pe);

	removearg_tbs->rma_common = aux_cpy_CommonArguments (&ds_removearg->rma_common);

	return(removearg_tbs);
}


SearchArgumentTBS * aux_extract_SearchArgumentTBS_from_SearchArg (ds_searcharg)
struct ds_search_arg * ds_searcharg;
{
	SearchArgumentTBS * searcharg_tbs;
	PE    	            pe;
	char	          * proc = "aux_extract_SearchArgumentTBS_from_SearchArg";


	if(! ds_searcharg){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SearchArgumentTBS * )0);
	}

	searcharg_tbs = (SearchArgumentTBS * )malloc(sizeof(SearchArgumentTBS));

	pe = dn_enc(ds_searcharg->sra_baseobject);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &searcharg_tbs->baseobject);
	pe_free(pe);

	searcharg_tbs->subset = ds_searcharg->sra_subset;
	searcharg_tbs->sra_common = aux_cpy_CommonArguments (&ds_searcharg->sra_common);
	searcharg_tbs->sra_eis = aux_cpy_EntryInfoSelection(&ds_searcharg->sra_eis);
	searcharg_tbs->filter = aux_cpy_SFilter (ds_searcharg->sra_filter);
	searcharg_tbs->searchaliases = ds_searcharg->sra_searchaliases;

	return(searcharg_tbs);
}


SearchResultTBS * aux_extract_SearchResultTBS_from_SearchRes (ds_searchres)
struct ds_search_result * ds_searchres;
{
	SearchResultTBS   * searchres_tbs;
	PE    	            pe;
	char	          * proc = "aux_extract_SearchResultTBS_from_SearchArg";


	if(! ds_searchres){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SearchResultTBS * )0);
	}

	searchres_tbs = (SearchResultTBS * )malloc(sizeof(SearchResultTBS));

	/* Note uncorrelated will need to be    */
	/* added in to do the secure stuff      */
	/* in a distributed manner              */
	/* this also applies to search          */

	searchres_tbs->srr_correlated = ds_searchres->srr_correlated;

	if (searchres_tbs->srr_correlated == FALSE) {
		searchres_tbs->srrtbs_un.uncorrel_searchinfo = (SET_OF_SearchResult * )malloc(sizeof(SET_OF_SearchResult));
		/* uncorrelated stuff needs to be added here */
	}
	else
		searchres_tbs->srrtbs_un.searchinfo = aux_cpy_SearchInfo (ds_searchres);

	return(searchres_tbs);
}


SFilter * aux_cpy_SFilter (QUIPUfilter)
Filter QUIPUfilter;
{
	SFilter  * SECUDEfilter;
	char	 * proc = "aux_cpy_SFilter";

	if(! QUIPUfilter){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SFilter * )0);
	}

	SECUDEfilter = (SFilter * )malloc(sizeof(SFilter));

	SECUDEfilter->flt_type = QUIPUfilter->flt_type;

	switch(SECUDEfilter->flt_type){
	case FILTER_ITEM:
		SECUDEfilter->flt_un.flt_un_item = aux_cpy_SFilterItem(&QUIPUfilter->flt_un.flt_un_item);
		break;
	case FILTER_AND:
		SECUDEfilter->flt_un.flt_un_filterset = aux_cpy_SET_OF_SFilter(QUIPUfilter->flt_un.flt_un_filter);
		break;
	case FILTER_OR:
		SECUDEfilter->flt_un.flt_un_filterset = aux_cpy_SET_OF_SFilter(QUIPUfilter->flt_un.flt_un_filter);
		break;
	case FILTER_NOT:
		SECUDEfilter->flt_un.flt_un_filter = aux_cpy_SFilter(QUIPUfilter->flt_un.flt_un_filter);
		break;
	default:
		aux_add_error(EINVALID, "QUIPUfilter->flt_type has bad value", CNULL, 0, proc);
		return((SFilter * )0);
	}

	return(SECUDEfilter);
}


SET_OF_SFilter *aux_cpy_SET_OF_SFilter(QUIPUfilter)
Filter QUIPUfilter;
{
	SET_OF_SFilter     * filterset;
	char		   * proc = "aux_cpy_SET_OF_SFilter";

	if(! QUIPUfilter){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_SFilter * )0);
	}

	filterset = (SET_OF_SFilter * )malloc(sizeof(SET_OF_SFilter));

	filterset->element = aux_cpy_SFilter(QUIPUfilter);
	filterset->next = aux_cpy_SET_OF_SFilter(QUIPUfilter->flt_next);

	return(filterset);
}


SEQUENCE_OF_StringsCHOICE * aux_cpy_SEQUENCE_OF_StringsCHOICE (QUIPUfilsubstrgs)
Filter_Substrings * QUIPUfilsubstrgs;
{
	SEQUENCE_OF_StringsCHOICE  * SECUDEfilsubstrgs;
	char	                   * proc = "aux_cpy_SEQUENCE_OF_StringsCHOICE";


	if(! QUIPUfilsubstrgs){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SEQUENCE_OF_StringsCHOICE * )0);
	}

	SECUDEfilsubstrgs = (SEQUENCE_OF_StringsCHOICE * )malloc(sizeof(SEQUENCE_OF_StringsCHOICE));

	SECUDEfilsubstrgs->element = (StringsCHOICE * )malloc(sizeof(StringsCHOICE));

	if(QUIPUfilsubstrgs->fi_sub_initial){ 
		SECUDEfilsubstrgs->element->strings_type = STRINGS_INITIAL;
		SECUDEfilsubstrgs->element->strings_un.initial = grab_pe(QUIPUfilsubstrgs->fi_sub_initial->avseq_av);
	}
	else if(QUIPUfilsubstrgs->fi_sub_any){
		SECUDEfilsubstrgs->element->strings_type = STRINGS_ANY;
		SECUDEfilsubstrgs->element->strings_un.any = grab_pe(QUIPUfilsubstrgs->fi_sub_any->avseq_av);
	}
	else if(QUIPUfilsubstrgs->fi_sub_final){
		SECUDEfilsubstrgs->element->strings_type = STRINGS_FINAL;
		SECUDEfilsubstrgs->element->strings_un.final = grab_pe(QUIPUfilsubstrgs->fi_sub_final->avseq_av);
	}
	else {
		aux_add_error(EINVALID, "strings_type", CNULL, 0, proc);
		return((SEQUENCE_OF_StringsCHOICE * )0);
	}

	SECUDEfilsubstrgs->next = (SEQUENCE_OF_StringsCHOICE * )0;
	/* because of QUIPU simplification */

	return(SECUDEfilsubstrgs);
}


SFilterSubstrings * aux_cpy_SFilterSubstrings (QUIPUfilsubstrgs)
Filter_Substrings * QUIPUfilsubstrgs;
{
	SFilterSubstrings  * SECUDEfilsubstrgs;
	char	           * proc = "aux_cpy_SFilterSubstrings";

	if(! QUIPUfilsubstrgs){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SFilterSubstrings * )0);
	}

	SECUDEfilsubstrgs = (SFilterSubstrings * )malloc(sizeof(SFilterSubstrings));

	SECUDEfilsubstrgs->type = (OIDentifier * ) aux_QUIPUAttributeType2SECUDEObjId (QUIPUfilsubstrgs->fi_sub_type);
	SECUDEfilsubstrgs->seq = aux_cpy_SEQUENCE_OF_StringsCHOICE (QUIPUfilsubstrgs);

	return(SECUDEfilsubstrgs);
}


SFilterItem * aux_cpy_SFilterItem (QUIPUitem)
struct filter_item * QUIPUitem;
{
	SFilterItem        * SECUDEitem;
	char	           * proc = "aux_cpy_SFilterItem";

	if(! QUIPUitem){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SFilterItem * )0);
	}

	SECUDEitem = (SFilterItem * )malloc(sizeof(SFilterItem));
	
	SECUDEitem->fi_type = QUIPUitem->fi_type;

	switch(SECUDEitem->fi_type){
	case FILTERITEM_EQUALITY:
		SECUDEitem->fi_un.fi_un_ava = aux_QUIPUAVA2SECUDEAttrValAssert(&QUIPUitem->fi_un.fi_un_ava);
		break;
	case FILTERITEM_SUBSTRINGS:
		SECUDEitem->fi_un.fi_un_substrings = aux_cpy_SFilterSubstrings(&QUIPUitem->fi_un.fi_un_substrings);
		break;
	case FILTERITEM_GREATEROREQUAL:
		SECUDEitem->fi_un.fi_un_ava = aux_QUIPUAVA2SECUDEAttrValAssert(&QUIPUitem->fi_un.fi_un_ava);
		break;
	case FILTERITEM_LESSOREQUAL:
		SECUDEitem->fi_un.fi_un_ava = aux_QUIPUAVA2SECUDEAttrValAssert(&QUIPUitem->fi_un.fi_un_ava);
		break;
	case FILTERITEM_PRESENT:
		SECUDEitem->fi_un.fi_un_type = (OIDentifier * )aux_QUIPUAttributeType2SECUDEObjId (QUIPUitem->fi_un.fi_un_type);
		break;
	case FILTERITEM_APPROX:
		SECUDEitem->fi_un.fi_un_ava = aux_QUIPUAVA2SECUDEAttrValAssert(&QUIPUitem->fi_un.fi_un_ava);
		break;
	default:
		aux_add_error(EINVALID, "QUIPUitem->fi_type has bad value", CNULL, 0, proc);
		return((SFilterItem * )0);
	}

	return(SECUDEitem);
}


CommonArguments * aux_cpy_CommonArguments (QUIPUca)
CommonArgs * QUIPUca;
{
	CommonArguments * SECUDEca;
	PE 		  pe;
	char	        * proc = "aux_cpy_CommonArguments";


	if(! QUIPUca){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((CommonArguments * )0);
	}

	SECUDEca = (CommonArguments * )malloc(sizeof(CommonArguments));

/* The fields ca_ext, ca_progress, ca_requestor and ca_aliased_rdns are provided
   as they are defined within X.500. Neither the QUIPU DSA or DUA use these
   fields (see Volume 5, section 17.2.1)
*/

	SECUDEca->ext = (SET_OF_SECExtension *)0;
	SECUDEca->aliasedRDNs = QUIPUca->ca_aliased_rdns;

	if(! QUIPUca->ca_requestor) 
		SECUDEca->requestor = NULLDNAME;
	else {
		pe = dn_enc(QUIPUca->ca_requestor);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDEca->requestor);
		pe_free(pe);
	}

	
	/* OperationProgress section */

	if(QUIPUca->ca_progress.op_resolution_phase > 1){
		SECUDEca->progress = (OperationProgress * )malloc(sizeof(OperationProgress));
		SECUDEca->progress->opResolutionPhase = QUIPUca->ca_progress.op_resolution_phase;
		SECUDEca->progress->opNextRDNToBeResolved = QUIPUca->ca_progress.op_nextrdntoberesolved;
	}
	else
		SECUDEca->progress = (OperationProgress * )0;


	/* ServiceControls section */

	if((QUIPUca->ca_servicecontrol.svc_options != 0) ||
            (QUIPUca->ca_servicecontrol.svc_prio != SVC_PRIO_MED) ||
            (QUIPUca->ca_servicecontrol.svc_timelimit != SVC_NOTIMELIMIT) ||
	    (QUIPUca->ca_servicecontrol.svc_sizelimit != SVC_NOSIZELIMIT) ||
	    (QUIPUca->ca_servicecontrol.svc_scopeofreferral != SVC_REFSCOPE_NONE)){
		SECUDEca->svc = (ServiceControls * )malloc(sizeof(ServiceControls));
		SECUDEca->svc->svc_options = QUIPUca->ca_servicecontrol.svc_options;
		SECUDEca->svc->svc_prio = QUIPUca->ca_servicecontrol.svc_prio;
		SECUDEca->svc->svc_timelimit = QUIPUca->ca_servicecontrol.svc_timelimit;
		SECUDEca->svc->svc_sizelimit = QUIPUca->ca_servicecontrol.svc_sizelimit;
		SECUDEca->svc->svc_scopeofreferral = QUIPUca->ca_servicecontrol.svc_scopeofreferral;
		SECUDEca->svc->svc_tmp = CNULL;
		SECUDEca->svc->svc_len = 0;
	}
	else
		SECUDEca->svc = (ServiceControls * )0;


	/* SecurityParameters section */

	SECUDEca->sec_parm = aux_cpy_SecurityParameters(QUIPUca->ca_security);

	return(SECUDEca);
}


SecurityParameters * aux_cpy_SecurityParameters (QUIPUsp)
struct security_parms * QUIPUsp;
{
	SecurityParameters    * SECUDEsp;
	PE 		        pe;
	char	              * proc = "aux_cpy_SecurityParameters";


	if(! QUIPUsp){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SecurityParameters * )0);
	}

	SECUDEsp = (SecurityParameters * )malloc(sizeof(SecurityParameters));

	SECUDEsp->certPath = aux_QUIPUcertlist2SECUDEcertpath(QUIPUsp->sp_path);
	if(! QUIPUsp->sp_name )
		SECUDEsp->name = NULLDNAME;
	else {
		pe = dn_enc(QUIPUsp->sp_name);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDEsp->name);
		pe_free(pe);
	}
	SECUDEsp->time = aux_cpy_Name(QUIPUsp->sp_time);
	SECUDEsp->random = aux_cpy_random(QUIPUsp->sp_random);
	SECUDEsp->target = QUIPUsp->sp_target;

	return(SECUDEsp);
}


CommonRes * aux_cpy_CommonRes (QUIPUcr)
CommonResults * QUIPUcr;
{
	CommonRes       * SECUDEcr;
	PE 		  pe;
	char	        * proc = "aux_cpy_CommonRes";


	if(! QUIPUcr){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((CommonRes * )0);
	}

	SECUDEcr = (CommonRes * )malloc(sizeof(CommonRes));

	if(! QUIPUcr->cr_requestor) 
		SECUDEcr->performer = NULLDNAME;
	else {
		pe = dn_enc(QUIPUcr->cr_requestor);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDEcr->performer);
		pe_free(pe);
	}

	SECUDEcr->aliasDereferenced = QUIPUcr->cr_aliasdereferenced;

	/* SecurityParameters section */
	SECUDEcr->sec_parm = aux_cpy_SecurityParameters(QUIPUcr->cr_security);

	return(SECUDEcr);
}


SubordEntry * aux_cpy_SubordEntry (QUIPUsubordinates)
struct subordinate * QUIPUsubordinates;
{
	SubordEntry * SECUDEsubordentry;
	PE 	      pe; 
	char	    * proc = "aux_cpy_SubordEntry";


	if(! QUIPUsubordinates || ! QUIPUsubordinates->sub_rdn){  /*sub_rdn is MANDATORY*/
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SubordEntry * )0);
	}

	SECUDEsubordentry = (SubordEntry * )malloc(sizeof(SubordEntry));

	SECUDEsubordentry->sub_aliasentry = QUIPUsubordinates->sub_aliasentry;
	SECUDEsubordentry->sub_copy = QUIPUsubordinates->sub_copy;

	pe = rdn_enc(QUIPUsubordinates->sub_rdn);
	parse_IF_RelativeDistinguishedName(pe, 1, NULLIP, NULLCP, &SECUDEsubordentry->sub_rdn);
	pe_free(pe);

	return(SECUDEsubordentry);
}


SET_OF_SubordEntry * aux_cpy_SET_OF_SubordEntry (QUIPUsubordinates)
struct subordinate * QUIPUsubordinates;
{
	SET_OF_SubordEntry * SECUDEsubordinates; 
	char	           * proc = "aux_cpy_SET_OF_SubordEntry";


	if(! QUIPUsubordinates){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_SubordEntry * )0);
	}

	SECUDEsubordinates = (SET_OF_SubordEntry * )malloc(sizeof(SET_OF_SubordEntry));

	SECUDEsubordinates->element = aux_cpy_SubordEntry(QUIPUsubordinates);
	SECUDEsubordinates->next = aux_cpy_SET_OF_SubordEntry(QUIPUsubordinates->sub_next);

	return(SECUDEsubordinates);
}


EntryModification * aux_cpy_EntryModification (QUIPUem)
struct entrymod * QUIPUem;
{
	EntryModification * SECUDEem;
	PE 	            pe; 
	char	          * proc = "aux_cpy_EntryModification";


	if(! QUIPUem){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((EntryModification * )0);
	}

	SECUDEem = (EntryModification * )malloc(sizeof(EntryModification));
	
	SECUDEem->em_type = QUIPUem->em_type;

	switch (SECUDEem->em_type) {
	case EM_ADDATTRIBUTE:
		SECUDEem->em_un.em_un_attr = aux_QUIPUAttrSequence2SECUDEAttr(QUIPUem->em_what);
		break;
	case EM_REMOVEATTRIBUTE:
		SECUDEem->em_un.em_un_attrtype = aux_QUIPUAttrSequence2SECUDEObjId(QUIPUem->em_what);
		break;
	case EM_ADDVALUES:
		SECUDEem->em_un.em_un_attr = aux_QUIPUAttrSequence2SECUDEAttr(QUIPUem->em_what);
		break;
	case EM_REMOVEVALUES:
		SECUDEem->em_un.em_un_attr = aux_QUIPUAttrSequence2SECUDEAttr(QUIPUem->em_what);
		break;
	default:
		aux_add_error(EINVALID, "QUIPUem->em_type has bad value", CNULL, 0, proc);
		return((EntryModification * )0);
	}  /* switch */

	return(SECUDEem);
}


SEQUENCE_OF_EntryModification * aux_cpy_SEQUENCE_OF_EntryModification (parm)
struct entrymod * parm;
{
	SEQUENCE_OF_EntryModification * ret; 
	char	                      * proc = "aux_cpy_SEQUENCE_OF_EntryModification";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SEQUENCE_OF_EntryModification * )0);
	}

	ret = (SEQUENCE_OF_EntryModification * )malloc(sizeof(SEQUENCE_OF_EntryModification));

	ret->element = aux_cpy_EntryModification(parm);
	ret->next = aux_cpy_SEQUENCE_OF_EntryModification(parm->em_next);

	return(ret);
}


ListInfo * aux_cpy_ListInfo (QUIPUlsr)
struct ds_list_result * QUIPUlsr;
{
	ListInfo * SECUDElistinfo;
	PE	   pe; 
	char	 * proc = "aux_cpy_ListInfo";


	if(! QUIPUlsr){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ListInfo * )0);
	}

	SECUDElistinfo = (ListInfo * )malloc(sizeof(ListInfo));

	if(! QUIPUlsr->lsr_object)  /* OPTIONAL */
		SECUDElistinfo->lsr_object = NULLDNAME;
	else {
		pe = dn_enc(QUIPUlsr->lsr_object);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDElistinfo->lsr_object);
		pe_free(pe);
	}

	SECUDElistinfo->lsr_subordinates = aux_cpy_SET_OF_SubordEntry(QUIPUlsr->lsr_subordinates);
	SECUDElistinfo->lsr_common = aux_cpy_CommonRes(&QUIPUlsr->lsr_common);

	if((QUIPUlsr->lsr_poq.poq_limitproblem != LSR_NOLIMITPROBLEM) || (QUIPUlsr->lsr_poq.poq_cref != NULLCONTINUATIONREF))
		SECUDElistinfo->lsr_poq = aux_QUIPUpoq2SECUDEpoq(&QUIPUlsr->lsr_poq);
	else SECUDElistinfo->lsr_poq = (PartialOutQual * )0;

	return(SECUDElistinfo);
}


SearchInfo * aux_cpy_SearchInfo (QUIPUsrr)
struct ds_search_result * QUIPUsrr;
{
	SearchInfo * SECUDEsearchinfo; 
	PE           pe;
	char	   * proc = "aux_cpy_SearchInfo";


	if(! QUIPUsrr){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SearchInfo * )0);
	}

	SECUDEsearchinfo = (SearchInfo * )malloc(sizeof(SearchInfo));

	if(! QUIPUsrr->CSR_object)  /* OPTIONAL */
		SECUDEsearchinfo->srr_object = NULLDNAME;
	else {
		pe = dn_enc(QUIPUsrr->CSR_object);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDEsearchinfo->srr_object);
		pe_free(pe);
	}

	SECUDEsearchinfo->srr_common = aux_cpy_CommonRes(&QUIPUsrr->CSR_common);
	SECUDEsearchinfo->srr_entries = aux_cpy_SET_OF_EntryINFO (QUIPUsrr->CSR_entries);

	if((QUIPUsrr->CSR_limitproblem != LSR_NOLIMITPROBLEM) || (QUIPUsrr->CSR_cr != NULLCONTINUATIONREF))
		SECUDEsearchinfo->srr_poq = aux_QUIPUpoq2SECUDEpoq(&QUIPUsrr->srr_un.srr_unit->srr_poq);
	else SECUDEsearchinfo->srr_poq = (PartialOutQual * )0;

	return(SECUDEsearchinfo);
}


EntryInfoSEL * aux_cpy_EntryInfoSelection (QUIPUeis)
EntryInfoSelection * QUIPUeis;
{
	EntryInfoSEL * SECUDEeis;
	char	     * proc = "aux_cpy_EntryInfoSelection";


	if(! QUIPUeis){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((EntryInfoSEL * )0);
	}

	if((QUIPUeis->eis_allattributes != TRUE) || (QUIPUeis->eis_infotypes != EIS_ATTRIBUTESANDVALUES)){
		SECUDEeis = (EntryInfoSEL * )malloc(sizeof(EntryInfoSEL));
		if(QUIPUeis->eis_allattributes == TRUE){
			SECUDEeis->eis_allattributes = TRUE;
			SECUDEeis->eis_select = (SET_OF_AttrType *)0;
		}
		else {
			SECUDEeis->eis_allattributes = FALSE;
			SECUDEeis->eis_select = aux_QUIPUAttrSequence2SECUDESETOFObjId (QUIPUeis->eis_select);
		}
		SECUDEeis->eis_infotypes = QUIPUeis->eis_infotypes;
	
		return(SECUDEeis);
	}

	return((EntryInfoSEL * )0);
}


EntryINFO * aux_cpy_EntryINFO (QUIPUei)
EntryInfo * QUIPUei;
{
	EntryINFO    * SECUDEei;
	PE 	       pe;
	char	     * proc = "aux_cpy_EntryINFO";


	/* ent_dn is MANDATORY */
	if(! QUIPUei || ! QUIPUei->ent_dn){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((EntryINFO * )0);
	}

	SECUDEei = (EntryINFO * )malloc(sizeof(EntryINFO));

	pe = dn_enc(QUIPUei->ent_dn);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &SECUDEei->ent_dn);
	pe_free(pe);	

	/* from das.py */
	if(QUIPUei->ent_iscopy == INFO_MASTER)
		QUIPUei->ent_pepsycopy = TRUE;	
	else
		QUIPUei->ent_pepsycopy = FALSE;
	SECUDEei->ent_fromentry = QUIPUei->ent_pepsycopy;

	SECUDEei->ent_attr = aux_cpy_SET_OF_AttrAttrTypeCHOICE(QUIPUei->ent_attr);

	return(SECUDEei);
}


SET_OF_EntryINFO * aux_cpy_SET_OF_EntryINFO (QUIPUei)
EntryInfo * QUIPUei;
{
	SET_OF_EntryINFO   * ret; 
	char	           * proc = "aux_cpy_SET_OF_EntryINFO";


	if(! QUIPUei){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_EntryINFO * )0);
	}

	ret = (SET_OF_EntryINFO * )malloc(sizeof(SET_OF_EntryINFO));

	ret->element = aux_cpy_EntryINFO(QUIPUei);
	ret->next = aux_cpy_SET_OF_EntryINFO(QUIPUei->ent_next);

	return(ret);
}


AttrAttrTypeCHOICE * aux_cpy_AttrAttrTypeCHOICE(parm)
Attr_Sequence  parm;
{
	AttrAttrTypeCHOICE     * ret;
	PE 	       	         pe;
	char	    	       * proc = "aux_cpy_AttrAttrTypeCHOICE";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((AttrAttrTypeCHOICE * )0);
	}

	ret = (AttrAttrTypeCHOICE * )malloc(sizeof(AttrAttrTypeCHOICE));

	if(parm->attr_value == NULLAV){
		ret->offset = 1;
		ret->choice_un.choice_un_attrtype = aux_QUIPUAttributeType2SECUDEObjId (parm->attr_type);
	}
	else{
		ret->offset = 2;
		ret->choice_un.choice_un_attr = aux_QUIPUAttrSequence2SECUDESETOFAttr(parm);
	}

	return(ret);
}


SET_OF_AttrAttrTypeCHOICE * aux_cpy_SET_OF_AttrAttrTypeCHOICE(parm)
Attr_Sequence  parm;
{
	SET_OF_AttrAttrTypeCHOICE     * ret;
	PE 	       			pe;
	char	    		      * proc = "aux_cpy_SET_OF_AttrAttrTypeCHOICE";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_AttrAttrTypeCHOICE * )0);
	}

	ret = (SET_OF_AttrAttrTypeCHOICE * )malloc(sizeof(SET_OF_AttrAttrTypeCHOICE));

	ret->element = aux_cpy_AttrAttrTypeCHOICE(parm);
	ret->next = aux_cpy_SET_OF_AttrAttrTypeCHOICE(parm->attr_link);

	return(ret);
}


struct random_number * get_random()
{
	BitString            * random_bstr;
	int                    i, nob;
	struct random_number * ret;
	char	             * proc = "get_random";


	ret = (struct random_number * )malloc(sizeof(struct random_number));

	random_bstr = sec_random_bstr(64);

	ret->n_bits = random_bstr->nbits;
	nob = ret->n_bits / 8;
	if(ret->n_bits % 8 )
		nob++;
	ret->value = (char *)malloc(nob);

	for(i = 0; i < nob; i++) {
		ret->value[i] = random_bstr->bits[i];
	}
	aux_free_BitString(&random_bstr);

	return(ret);
}


SET_OF_DName * aux_QUIPUdnseq2SECUDESETOFDName (parm)
struct dn_seq * parm;
{
	SET_OF_DName            * ret, * ret_tmp;
	struct dn_seq 		* parm_tmp;
	PE			  pe;
	char         	        * proc = "aux_QUIPUdnseq2SECUDESETOFDName";


	if(! parm || ! parm->dns_dn){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_DName * )0);
	}

	ret = (SET_OF_DName * )malloc(sizeof(SET_OF_DName));

	pe = dn_enc(parm->dns_dn);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &ret->element);
	pe_free(pe);

	ret->next = (SET_OF_DName *)0;

	for (ret_tmp = ret, parm_tmp = parm->dns_next; parm_tmp; parm_tmp = parm_tmp->dns_next) {
		ret_tmp->next = (SET_OF_DName * )malloc(sizeof(SET_OF_DName));
		ret_tmp = ret_tmp->next;
		pe = dn_enc(parm_tmp->dns_dn);
		parse_IF_Name(pe, 1, NULLIP, NULLCP, &ret_tmp->element);
		pe_free(pe);
		ret_tmp->next = (SET_OF_DName *)0;
	} 

	return(ret);
}


SET_OF_ObjId * aux_QUIPUoidseq2SECUDEsetofobjid(parm)
struct oid_seq * parm;
{
	SET_OF_ObjId		* ret, * ret_tmp;
	struct oid_seq 		* parm_tmp;
	char         	        * proc = "aux_QUIPUoidseq2SECUDEsetofobjid";


	if(! parm || ! parm->oid_oid){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_ObjId * )0);
	}

	ret = (SET_OF_ObjId * )malloc(sizeof(SET_OF_ObjId));
	ret->element = aux_cpy_ObjId(parm->oid_oid);
	ret->next = (SET_OF_ObjId *)0;

	for (ret_tmp = ret, parm_tmp = parm->oid_next; parm_tmp; parm_tmp = parm_tmp->oid_next) {
		ret_tmp->next = (SET_OF_ObjId * )malloc(sizeof(SET_OF_ObjId));
		ret_tmp = ret_tmp->next;
		ret_tmp->element = aux_cpy_ObjId(parm_tmp->oid_oid);
		ret_tmp->next = (SET_OF_ObjId *)0;
	} 

	return(ret);
}


SET_OF_aclAttr * aux_QUIPUaclattr2SECUDEsetofaclattr(parm)
struct acl_attr * parm;
{
	SET_OF_aclAttr		* ret, * ret_tmp;
	struct acl_attr 	* parm_tmp;
	char         	        * proc = "aux_QUIPUaclattr2SECUDEsetofaclattr";


	if(! parm || ! parm->aa_types){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_aclAttr * )0);
	}

	ret = (SET_OF_aclAttr * )malloc(sizeof(SET_OF_aclAttr));
	ret->element = (aclAttr * )malloc(sizeof(aclAttr));
	ret->element->aa_types = aux_QUIPUoidseq2SECUDEsetofobjid(parm->aa_types);

	if (test_acl_default(parm->aa_acl) != OK)
		ret->element->aa_un.aa_un_acl = aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm->aa_acl);
	else
		ret->element->aa_un.aa_un_acl = (SET_OF_aclInfo * )0;

	ret->next = (SET_OF_aclAttr *)0;

	for (ret_tmp = ret, parm_tmp = parm->aa_next; parm_tmp; parm_tmp = parm_tmp->aa_next) {
		ret_tmp->next = (SET_OF_aclAttr * )malloc(sizeof(SET_OF_aclAttr));
		ret_tmp = ret_tmp->next;
		ret_tmp->element = (aclAttr * )malloc(sizeof(aclAttr));
		ret_tmp->element->aa_types = aux_QUIPUoidseq2SECUDEsetofobjid(parm_tmp->aa_types);

		if (test_acl_default(parm->aa_acl) != OK)
			ret_tmp->element->aa_un.aa_un_acl = aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm_tmp->aa_acl);
		else
			ret_tmp->element->aa_un.aa_un_acl = (SET_OF_aclInfo * )0;

		ret_tmp->next = (SET_OF_aclAttr *)0;
	} 

	return(ret);
}


SET_OF_aclInfo * aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm)
struct acl_info * parm;
{
	SET_OF_aclInfo		* ret, * ret_tmp;
	struct acl_info 	* parm_tmp;
	char         	        * proc = "aux_QUIPUaclinfo2SECUDEsetofaclinfo";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_aclInfo * )0);
	}

	ret = (SET_OF_aclInfo * )malloc(sizeof(SET_OF_aclInfo));
	ret->element = (aclInfo * )malloc(sizeof(aclInfo));
	ret->element->acl_categories = parm->acl_categories;
	ret->element->acl_selector_type = parm->acl_selector_type;
	ret->element->acl_name = aux_QUIPUdnseq2SECUDESETOFDName(parm->acl_name);
	ret->next = (SET_OF_aclInfo *)0;

	for (ret_tmp = ret, parm_tmp = parm->acl_next; parm_tmp; parm_tmp = parm_tmp->acl_next) {
		ret_tmp->next = (SET_OF_aclInfo * )malloc(sizeof(SET_OF_aclInfo));
		ret_tmp = ret_tmp->next;
		ret_tmp->element = (aclInfo * )malloc(sizeof(aclInfo));
		ret_tmp->element->acl_categories = parm_tmp->acl_categories;
		ret_tmp->element->acl_selector_type = parm_tmp->acl_selector_type;
		ret_tmp->element->acl_name = aux_QUIPUdnseq2SECUDESETOFDName(parm_tmp->acl_name);
		ret_tmp->next = (SET_OF_aclInfo *)0;
	} 

	return(ret);
}


AccessControlList * aux_QUIPUacl2SECUDEacl(parm)
struct acl * parm;
{
	AccessControlList	* ret;
	char         	        * proc = "aux_QUIPUacl2SECUDEacl";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((AccessControlList * )0);
	}

	ret = (AccessControlList * )malloc(sizeof(AccessControlList));

	if (test_acl_default(parm->ac_child) != OK)
		ret->ac_child = aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm->ac_child);
	else
		ret->ac_child = (SET_OF_aclInfo * )0;

	if (test_acl_default(parm->ac_entry) != OK)
		ret->ac_entry = aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm->ac_entry);
	else
		ret->ac_entry = (SET_OF_aclInfo * )0;

	if (test_acl_default(parm->ac_default) != OK)
		ret->ac_default = aux_QUIPUaclinfo2SECUDEsetofaclinfo(parm->ac_default);
	else
		ret->ac_default = (SET_OF_aclInfo * )0;

	ret->ac_attributes = aux_QUIPUaclattr2SECUDEsetofaclattr(parm->ac_attributes);

	return(ret);
}


AccessPoint * aux_QUIPUaccpoint2SECUDEaccpoint(parm)
struct access_point * parm;
{
	AccessPoint	* ret;
	PE	          pe;
	int	 	  rc;
	char		* proc = "aux_QUIPUaccpoint2SECUDEaccpoint";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((AccessPoint * )0);
	}

	ret = (AccessPoint * )malloc(sizeof(AccessPoint));

	pe = dn_enc(parm->ap_name);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &ret->ap_name);
	pe_free(pe);

	rc = enc_ipa(parm, &pe);
	ret->ap_address = PSAPaddr_dec(pe);

	return(ret);
}


SET_OF_AccessPoint * aux_QUIPUaccpoint2SECUDESETOFaccpoint(parm)
struct access_point * parm;
{
	SET_OF_AccessPoint	* ret;
	char			* proc = "aux_QUIPUaccpoint2SECUDESETOFaccpoint";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_AccessPoint * )0);
	}

	ret = (SET_OF_AccessPoint * )malloc(sizeof(SET_OF_AccessPoint));

	ret->element = aux_QUIPUaccpoint2SECUDEaccpoint(parm);
	ret->next = aux_QUIPUaccpoint2SECUDESETOFaccpoint(parm->ap_next);

	return(ret);
}


OperationProgress * aux_QUIPUop2SECUDEop(parm)
struct op_progress * parm;
{
	OperationProgress	* ret;
	char		  	* proc = "aux_QUIPUop2SECUDEop";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((OperationProgress * )0);
	}

	ret = (OperationProgress * )malloc(sizeof(OperationProgress));

	ret->opResolutionPhase = parm->op_resolution_phase;
	ret->opNextRDNToBeResolved = parm->op_nextrdntoberesolved;

	return(ret);
}


ContReference * aux_QUIPUcref2SECUDEcref(parm)
ContinuationRef parm;
{
	ContReference	* ret;
	PE		  pe;
	char            * proc = "aux_QUIPUcref2SECUDEcref";


	if(! parm || ! parm->cr_name){
		/* cr_name is MANDATORY */
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((ContReference * )0);
	}

	ret = (ContReference * )malloc(sizeof(ContReference));

	pe = dn_enc(parm->cr_name);
	parse_IF_Name(pe, 1, NULLIP, NULLCP, &ret->cr_name);
	pe_free(pe);

	ret->cr_progress = aux_QUIPUop2SECUDEop(&parm->cr_progress);
	ret->cr_rdn_resolved = parm->cr_rdn_resolved;
	ret->cr_aliasedRDNs = parm->cr_aliasedRDNs;
	ret->cr_reftype = parm->cr_reftype;
	ret->cr_accesspoints = aux_QUIPUaccpoint2SECUDESETOFaccpoint(parm->cr_accesspoints);

	return(ret);
}


SET_OF_ContReference * aux_QUIPUcref2SECUDESETOFcref(parm)
ContinuationRef parm;
{
	SET_OF_ContReference	* ret;
	char         		* proc = "aux_QUIPUcref2SECUDESETOFcref";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((SET_OF_ContReference * )0);
	}

	ret = (SET_OF_ContReference * )malloc(sizeof(SET_OF_ContReference));

	ret->element = aux_QUIPUcref2SECUDEcref(parm);
	ret->next = aux_QUIPUcref2SECUDESETOFcref(parm->cr_next);

	return(ret);
}


PartialOutQual * aux_QUIPUpoq2SECUDEpoq(parm)
POQ * parm;
{
	PartialOutQual	* ret;
	char         	* proc = "aux_QUIPUpoq2SECUDEpoq";


	if(! parm){
		aux_add_error(EINVALID, "Parameters not present", CNULL, 0, proc);
		return((PartialOutQual * )0);
	}

	ret = (PartialOutQual * )malloc(sizeof(PartialOutQual));

	ret->poq_limitproblem = parm->poq_limitproblem;
	ret->poq_no_ext = parm->poq_no_ext;
	ret->poq_cref = aux_QUIPUcref2SECUDESETOFcref(parm->poq_cref);

	return(ret);
}


#endif

#else
/* dummy */
strong_util_dummy() 
{
	return(0);
}

#endif
