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
#include "psap.h"
#include "af.h"
#include <fcntl.h>
#include <stdio.h>

#define BUFLEN 4096

extern int	errno;
extern OctetString *e_CrlTBS();
extern OctetString *e_RevCertTBS();
extern Crl *af_dir_retrieve_Crl();

static char	buf[BUFLEN];

#else
#include "af.h"
#include <fcntl.h>
#include <stdio.h>
#endif

extern UTCTime *aux_current_UTCTime(), *aux_delta_UTCTime();


PemCrl *af_create_PemCrl(lastUpdate, nextUpdate)
UTCTime *lastUpdate;
UTCTime *nextUpdate;
{

	PemCrl  *new_pemcrl;
	ObjId	    *oid;
	char	    *proc = "af_create_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	new_pemcrl = (PemCrl * )malloc(sizeof(PemCrl));
	if (!new_pemcrl) {
		aux_add_error(EMALLOC, "new_pemcrl", CNULL, 0, proc);
		return ((PemCrl * ) 0);
	}

	new_pemcrl->tbs = (PemCrlTBS * )malloc(sizeof(PemCrlTBS));
	if (!new_pemcrl->tbs) {
		aux_add_error(EMALLOC, "new_pemcrl->tbs", CNULL, 0, proc);
		return ((PemCrl * ) 0);
	}

	if (!(new_pemcrl->tbs->issuer = af_pse_get_Name())) {
		aux_add_error(EREADPSE, "af_pse_get_Name failed", CNULL, 0, proc);
		return ((PemCrl * ) 0);
	}

	if (!lastUpdate)
		new_pemcrl->tbs->lastUpdate = aux_current_UTCTime();
	else {
		new_pemcrl->tbs->lastUpdate = (char *) malloc (18);   /* TX_MAXLEN = 17 */
		strcpy(new_pemcrl->tbs->lastUpdate, lastUpdate);
	}
	if (!nextUpdate) 
		new_pemcrl->tbs->nextUpdate = aux_delta_UTCTime(new_pemcrl->tbs->lastUpdate);
	else {
		new_pemcrl->tbs->nextUpdate = (char *) malloc (18);   /* TX_MAXLEN = 17 */
		strcpy(new_pemcrl->tbs->nextUpdate, nextUpdate);
	}
	
	new_pemcrl->tbs->revokedCertificates = (SEQUENCE_OF_RevCertPem * )0;

	new_pemcrl->sig = (Signature * )malloc(sizeof(Signature));
	if (!new_pemcrl->sig) {
		aux_add_error(EMALLOC, "new_pemcrl->sig", CNULL, 0, proc);
		return ((PemCrl * ) 0);
	}
	new_pemcrl->sig->signature.nbits = 0;
	new_pemcrl->sig->signature.bits = CNULL;

	new_pemcrl->sig->signAI = af_pse_get_signAI();
	if ( aux_ObjId2AlgType(new_pemcrl->sig->signAI->objid) == ASYM_ENC )
		new_pemcrl->sig->signAI = aux_cpy_AlgId(md5WithRsa);

	new_pemcrl->tbs->signatureAI = aux_cpy_AlgId(new_pemcrl->sig->signAI);

	if ((new_pemcrl->tbs_DERcode = e_PemCrlTBS(new_pemcrl->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_PemCrlTBS failed", CNULL, 0, proc);
		return( (PemCrl * )0);
	}

	fprintf(stderr, "\nThe following empty PemCrl is to be signed. Please check it:\n\n");
	aux_fprint_PemCrlTBS(stderr, new_pemcrl->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed PemCrl?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	/*oid = af_get_objoid(SignSK_name);
	af_pse_close (oid);*/
	af_pse_close (NULLOBJID);
	if (af_sign(new_pemcrl->tbs_DERcode, new_pemcrl->sig, END) < 0 ) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return( (PemCrl * )0 );
	}
	return (new_pemcrl);

}


RevCertPem *af_create_RevCertPem(serial)
int serial;
{

	RevCertPem *ret;
	char	   *proc = "af_create_RevCertPem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	ret = (RevCertPem * )malloc(sizeof(RevCertPem));
	if (!ret) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return ((RevCertPem * ) 0);
	}

	ret->serialnumber = serial;
	ret->revocationDate = aux_current_UTCTime();

	return(ret);
}


RC af_search_RevCertPem(pemcrl, revcertpem)
PemCrl *pemcrl;
RevCertPem *revcertpem;
{
	SEQUENCE_OF_RevCertPem *seq;
	int		        found;
	char	               *proc = "af_search_RevCertPem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !pemcrl || !revcertpem ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	seq = pemcrl->tbs->revokedCertificates;
	found = 0;
	while ( seq && !found ) {
		if (seq->element->serialnumber == revcertpem->serialnumber) {
			found = 1;
			break;
		}
		seq = seq->next;
	}

	return(found);
}


#ifdef X500
RC af_dir_add_RevCert(type, revcert, o_certificate)
RevokeType type;
RevCert *revcert;
Certificates *o_certificate;   /*Originator Certificate of revoking CA, may be the own*/
{

	Crl * rclist;
	Certificates * certs;  /*own Originator Certificate*/
	SEQUENCE_OF_RevCert * list;
	DName * dname;
	char	*proc = "af_dir_add_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ARL) && (type != CRL)) || !revcert || (type == ARL && !o_certificate) ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	dname = af_pse_get_Name();

	fprintf(stderr, "\nRetrieve Crl...\n");

	if ( !(rclist = af_dir_retrieve_Crl(dname, type)))  {
		aux_add_error(EINVALID, "af_dir_retrieve_Crl failed", dname, DName_n, proc);
		return (-1);
	}

	if ( !(certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME)) ) {
		aux_add_error(EINVALID, "af_pse_get_Certificates failed", CNULL, 0, proc);
		return (-1);
	}

	fprintf(stderr, "\nVerify Crl...\n");

	if ( af_verify(rclist->tbs_DERcode, rclist->sig, END, certs, (UTCTime * )0, (PKRoot * )0) < 0 ) {
		aux_add_error(EINVALID, "af_verify failed", CNULL, 0, proc);
		return (-1);
	}

	fprintf(stderr, "\nRetrieved Crl successfully verified!\n\n");


	/*Only in case of an ARL the signed reference to the revoked certificate being added    */
	/*to the black list has to be verified;						        */
	/*only in case of the verification being successful the signed reference		*/
	/*of the revoked certificate in question may be added to the ARL:			*/

	if ( type == ARL ) {
		if ( af_verify(revcert->tbs_DERcode, revcert->sig, END, o_certificate, (UTCTime * )0, (PKRoot * )0) < 0 ) {
			aux_add_error(EINVALID, "af_verify failed (type == ARL)", CNULL, 0, proc);
			return (-1);
		}
	}

	if ( aux_cmp_DName(revcert->tbs->issuer, o_certificate->usercertificate->tbs->subject) ) {  /*not equal*/
		aux_add_error(EINVALID, "WARNING:COMPROMISED CA DETECTED", CNULL, 0, proc);
		return (-1);
	}

	if ( af_search_RevCert(rclist, revcert) ) {  /*FOUND*/

		aux_add_error(ECREATEOBJ, "Revoked Certificate already contained in black list!", CNULL, 0, proc);
		return (-1);
	}  /*no changes to rclist*/

	if ( !(list = (SEQUENCE_OF_RevCert * )malloc(sizeof(SEQUENCE_OF_RevCert))) ) {
		aux_add_error(EMALLOC, "list", CNULL, 0, proc);
		return (-1);
	}

	list->element = aux_cpy_RevCert(revcert);
	list->next = rclist->tbs->revokedcertificates;  /* existing or NULL pointer */
	rclist->tbs->revokedcertificates = list;

	rclist->tbs->lastupdate = aux_current_UTCTime();

	if ((rclist->tbs_DERcode = e_CrlTBS(rclist->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_CrlTBS failed", CNULL, 0, proc);
		return (-1);
	}

	fprintf(stderr, "\nThe following Crl is to be signed. Please check it:\n\n");
	aux_fprint_CrlTBS(stderr, rclist->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed Crl?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close (NULLOBJID);
	if ( af_sign(rclist->tbs_DERcode, rclist->sig, END) < 0 )  /*sign with OWN signature key*/ {
		aux_add_error(ESIGN, "af_sign failed", rclist, Crl_n, proc);
		return (-1);
	}


	if ( af_dir_enter_Crl(type, rclist, dname) < 0 ) {
		aux_add_error(EINVALID, "af_dir_enter_Crl failed", rclist, Crl_n, proc);
		return (-1);
	}


	return(0);
}


RevCert *af_create_RevCert(cert)
Certificate *cert;
{

	RevCert    * ret;
	OctetString  nullocts;
	char	   * proc = "af_create_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !cert ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return ((RevCert * ) 0);
	}

	fprintf(stderr, "\nCreating Revoked Certificate...\n");

	ret = (RevCert * )malloc(sizeof(RevCert));
	if (!ret) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return ((RevCert * ) 0);
	}

	ret->tbs = (RevCertTBS * )malloc(sizeof(RevCertTBS));
	if (!ret->tbs) {
		aux_add_error(EMALLOC, "ret->tbs", CNULL, 0, proc);
		return ((RevCert * ) 0);
	}

	ret->tbs->issuer = aux_cpy_DName(cert->tbs->issuer);
	/*Do not replace the certificate's serial number, just copy it:*/
	ret->tbs->subject = cert->tbs->serialnumber;
	ret->tbs->revocationdate = aux_current_UTCTime();

	ret->sig = (Signature * )malloc(sizeof(Signature));
	if (!ret->sig) {
		aux_add_error(EMALLOC, "ret->sig", CNULL, 0, proc);
		return ((RevCert * ) 0);
	}

	ret->sig->signAI = NULLALGID;
	nullocts.noctets = 0;
	nullocts.octets = CNULL;

	af_pse_close (NULLOBJID);

	if ( af_sign(&nullocts, ret->sig, END) < 0) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return ( (RevCert * )0 );
	}
	ret->tbs->signatureAI = aux_cpy_AlgId(ret->sig->signAI);

	/*Damit der Benutzer bei dem naechsten Unterschriften-Vorgang
	  wieder seine PIN eingeben muss:*/
	aux_free2_KeyInfo(ret->sig);

	if ((ret->tbs_DERcode = e_RevCertTBS(ret->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_RevCertTBS failed", CNULL, 0, proc);
		return ( (RevCert * )0 );
	}

	fprintf(stderr, "\nThe following Revoked Certificate is to be signed. Please check it:\n\n");
	aux_fprint_RevCertTBS(stderr, ret->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed Revoked Certificate?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close (NULLOBJID);
	if ( af_sign(ret->tbs_DERcode, ret->sig, END) < 0 )  /*sign with OWN signature key*/ {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);

		return( (RevCert * )0 );
	}
	return(ret);
}


RC af_search_RevCert(rclist, revcert)
Crl *rclist;
RevCert *revcert;
{
	SEQUENCE_OF_RevCert * revcertseq;
	int	found;
	char	*proc = "af_search_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !rclist || !revcert ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	revcertseq = rclist->tbs->revokedcertificates;
	found = 0;
	while ( revcertseq && !found ) {
		if ( !aux_revcert_cmp(revcertseq->element, revcert) )
			found = 1;
		revcertseq = revcertseq->next;
	}

	return(found);
}




RC af_dir_delete_RevCert(serialnumber, issuer, type)
int	serialnumber;	/*serial number of revoked certificate*/
DName *issuer;		/*issuer of revoked certificate*/
RevokeType type;
{

	Certificates * certs;  /*own Originator Certificate*/
	SEQUENCE_OF_RevCert * np, *ahead_np;
	int	found;
	DName * dname;
	Crl * rclist;
	char	*proc = "af_dir_delete_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ARL) && (type != CRL)) || !issuer ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	fprintf(stderr, "\nRetrieve Crl...\n");

	if ( type == CRL ) {
		if ( !(rclist = af_dir_retrieve_Crl(issuer, type)) ) {
			aux_add_error(EINVALID, "af_dir_retrieve_Crl failed", issuer, DName_n, proc);

			return(-1);
		}
	} else {
		dname = af_pse_get_Name();
		if ( !(rclist = af_dir_retrieve_Crl(dname, type)) ) {
			aux_add_error(EINVALID, "af_dir_retrieve_Crl failed", dname, DName_n, proc);

			return(-1);
		}

	}

	if ( !(certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME)) ) {
		aux_add_error(EINVALID, "af_pse_get_Certificates failed", CNULL, 0, proc);

		return(-1);
	}			/*Bis ganz nach oben, oder soll Name belegt sein?*/

	fprintf(stderr, "\nVerify Crl...\n");

	if ( af_verify(rclist->tbs_DERcode, rclist->sig, END, certs, (UTCTime * )0, (PKRoot * )0) < 0 )  {
		aux_add_error(EINVALID, "af_verify failed", rclist, Crl_n, proc);

		return(-1);
	}

	fprintf(stderr, "\nRetrieved Crl successfully verified!\n\n");

	found = 0;
	for ( np = rclist->tbs->revokedcertificates, ahead_np = (SEQUENCE_OF_RevCert *) 0; 
	    np; 
	    ahead_np = np,
	    np = np->next
	    ) {
		if ( (aux_cmp_DName(np->element->tbs->issuer, issuer) == 0) && 
		    ((serialnumber < 0) || (serialnumber == np->element->tbs->subject)) ) {  /*FOUND*/
			found = 1;
			if ( !ahead_np )     /*erstes Listenelement*/
				rclist->tbs->revokedcertificates = np->next;
			else
				ahead_np->next = np->next;
			aux_free_RevCert(&np->element);
			if ( serialnumber >= 0 )
				break;
		}
	} /*for*/

	if ( !found ) { 	       /*keine Uebereinstimmung gefunden, no changes to rclist*/
		aux_add_error(EOBJNAME, "Specified revoked certificate NOT CONTAINED in black list", CNULL, 0, proc);
		return(-1);
	}

	rclist->tbs->lastupdate = aux_current_UTCTime();

	if ((rclist->tbs_DERcode = e_CrlTBS(rclist->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_CrlTBS failed", CNULL, 0, proc);
		return(-1);
	}

	fprintf(stderr, "\nThe following Crl is to be signed. Please check it:\n\n");
	aux_fprint_CrlTBS(stderr, rclist->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed Crl?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close (NULLOBJID);
	if ( af_sign(rclist->tbs_DERcode, rclist->sig, END) < 0 )  /*sign with OWN signature key*/ {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return (-1);
	}


	if ( type == CRL ) {
		if ( af_dir_enter_Crl(type, rclist, issuer) < 0 ) {
			aux_add_error(EINVALID, "af_dir_enter_Crl failed", issuer, DName_n, proc);
			return (-1);
		}

	} else {
		if ( af_dir_enter_Crl(type, rclist, dname) < 0 ) {
			aux_add_error(EINVALID, "af_dir_enter_Crl failed", dname, DName_n, proc);
			return (-1);
		}

	}

	return(0);
}


OCList *af_create_OCList(new_pubkey)
KeyInfo *new_pubkey;
{

	OCList      * ret;		 /*return value, newly created first line of "Old Certificates"*/
	Certificate * newcert;    /*cross certificate in first line of "Old Certificates"*/
	OctetString   nullocts;
	char	    * proc = "af_create_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!new_pubkey) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return ((OCList * ) 0);
	}

	fprintf(stderr, "\nCreating (new) first line of OldCertificates table...\n");

	if ( !(ret = (OCList * )malloc(sizeof(OCList))) ) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return ((OCList * ) 0);
	}

	/*create cross certificate which will be recorded in the right column of        */
	/*the new first line within the Root CA's directory table "Old Certificates":	*/
	newcert = (Certificate * )malloc(sizeof(Certificate));
	if (!newcert) {
		aux_add_error(EMALLOC, "newcert", CNULL, 0, proc);
		return ((OCList * ) 0);
	}

	newcert->tbs = (ToBeSigned * )malloc(sizeof(ToBeSigned));
	if (!newcert->tbs) {
		aux_add_error(EMALLOC, "newcert->tbs", CNULL, 0, proc);
		return ((OCList * ) 0);
	}

	newcert->tbs->version = 0;    /* default version */
	newcert->tbs->serialnumber = af_pse_incr_serial();
	newcert->tbs->issuer = af_pse_get_Name();
	newcert->tbs->notbefore = aux_current_UTCTime();   /*????*/
	newcert->tbs->notafter = aux_delta_UTCTime(newcert->tbs->notbefore);  /*????*/
	newcert->tbs->subject = aux_cpy_DName(newcert->tbs->issuer);
	newcert->tbs->subjectPK = aux_cpy_KeyInfo(new_pubkey);

	newcert->sig = (Signature * )malloc(sizeof(Signature));
	if (!newcert->sig) {
		aux_add_error(EMALLOC, "newcert->sig", CNULL, 0, proc);
		return ((OCList * ) 0);
	}

	newcert->sig->signAI = NULLALGID;
	nullocts.noctets = 0;
	nullocts.octets = CNULL;
	af_pse_close (NULLOBJID);
	if ( af_sign(&nullocts, newcert->sig, END) < 0) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return ( (OCList * )0 );
	}
	newcert->tbs->signatureAI = aux_cpy_AlgId(newcert->sig->signAI);
	aux_free2_KeyInfo(newcert->sig);

	if ((newcert->tbs_DERcode = e_ToBeSigned(newcert->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_ToBeSigned failed", CNULL, 0, proc);
		return ( (OCList * )0 );
	}

	fprintf(stderr, "\nThe following Cross Certificate is to be signed.\n");
	fprintf(stderr, "It will be published in the newly created first line ");
	fprintf(stderr, "of the OldCertificates table.\n");
	fprintf(stderr, "Please check it:\n\n");
	aux_fprint_ToBeSigned(stderr, newcert->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed Cross Certificate?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close (NULLOBJID);
	if ( af_sign(newcert->tbs_DERcode, newcert->sig, END) < 0 )  /*sign with OWN signature key*/ {
		aux_add_error(ESIGN, "af_sign failed", newcert, Certificate_n, proc);
		return( (OCList * )0 );
	}


	/*left column of newly created first line, assuming that the certificate	*/
	/*number is a number smaller than 1 million:					*/
	ret->serialnumber = ((newcert->tbs->serialnumber + 1000000) / 1000000) * 1000000;

	ret->ccert = aux_cpy_Certificate(newcert);
	aux_free_Certificate(&newcert);
	ret->next = (OCList * )0;

	return(ret);
}




/* Assumptions made by af_dir_update_OCList():				                */
/* - The Root CA has changed her signature key.					       	*/
/* - The Root CA has already cross-certified her newly created public key with her 	*/
/*   expiring signature key by invoking af_create_OCList().				*/
/* - The new signature key has already been installed on the Root CA's chipcard.	*/
/* - The chipcard entry "Public Root-CA-Keys" has NOT YET been updated after the change */
/*   of the Root CA-key (see steps 1-4, 6.2.4 ("Change of a Root CA key"), p.25, Vol.1).*/

RC af_dir_update_OCList(first_line)
OCList *first_line; 	/* returned from af_create_OCList() */
{

	DName       * dname;
	OCList      * oclist;
	PKRoot      * pkroot;
	Certificate * newcert;
	Key	      vkey;		                /* verifykey, the public key */
	HashInput   * vhashin = (HashInput *) 0;	/* hashinput pointer used for verifying, hash input in case of sqmodn*/
	int	      rc;
	AlgHash       alghash;
	OctetString   nullocts;
	AlgId       * save_signAI;
	char	    * proc = "af_dir_update_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!first_line) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	dname = af_pse_get_Name();

	fprintf(stderr, "\nSee if the directory entry associated with the Root CA already contains\n");
	fprintf(stderr, "an attribute of type OldCertificates...\n\n");

	if ( !(oclist = af_dir_retrieve_OCList(dname)) && (err_stack->e_number != EATTRDIR) ) {
		aux_add_error(EINVALID, "af_dir_retrieve_OCList failed", dname, DName_n, proc);
		return (-1);
	}
	if ( !(pkroot = af_pse_get_PKRoot()) ) {
		aux_add_error(EINVALID, "af_pse_get_PKRoot failed", CNULL, 0, proc);

		return (-1);
	}

	if ( !oclist ) {  	/*first change of Root CA-key*/

		fprintf(stderr, "\n\nThe Root CA is changing its signature key ");
		fprintf(stderr, "for the first time.\n\n");

		/* creating second line of OldCertificates table: */

		fprintf(stderr, "\nCreating second line of OldCertificates table...\n");

		oclist = (OCList * )malloc(sizeof(OCList));
		if (!oclist) {
			aux_add_error(EMALLOC, "oclist", CNULL, 0, proc);
			return (-1);
		}

		newcert = (Certificate * )malloc(sizeof(Certificate));
		if (!newcert) {
			aux_add_error(EMALLOC, "newcert", CNULL, 0, proc);
			return (-1);
		}

		newcert->tbs = (ToBeSigned * )malloc(sizeof(ToBeSigned));
		if (!newcert->tbs) {
			aux_add_error(EMALLOC, "newcert->tbs", CNULL, 0, proc);
			return (-1);
		}

		newcert->tbs->version = 0;
		newcert->tbs->serialnumber = af_pse_incr_serial();
		newcert->tbs->issuer = aux_cpy_DName(dname);
		newcert->tbs->notbefore = aux_current_UTCTime();
		newcert->tbs->notafter = aux_delta_UTCTime(newcert->tbs->notbefore);
		newcert->tbs->subject = aux_cpy_DName(dname);
		newcert->tbs->subjectPK = aux_cpy_KeyInfo(pkroot->newkey->key);  /*expired public key*/


		newcert->sig = (Signature * )malloc(sizeof(Signature));
		if (!newcert->sig) {
			aux_add_error(EMALLOC, "newcert->sig", CNULL, 0, proc);
			return (-1);
		}

		newcert->sig->signAI = NULLALGID;
		nullocts.noctets = 0;
		nullocts.octets = CNULL;
		af_pse_close (NULLOBJID);
		if ( af_sign(&nullocts, newcert->sig, END) < 0) {
			aux_add_error(ESIGN, "can't get AlgId if SignSK", CNULL, 0, proc);
			return (-1);
		}
		newcert->tbs->signatureAI = aux_cpy_AlgId(newcert->sig->signAI);
		aux_free2_KeyInfo(newcert->sig);

		if ((newcert->tbs_DERcode = e_ToBeSigned(newcert->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ToBeSigned failed", CNULL, 0, proc);
			return (-1);
		}

		fprintf(stderr, "\nThe following Cross Certificate is to be signed.\n");
		fprintf(stderr, "It will be published in the second line ");
		fprintf(stderr, "of the OldCertificates table.\n");
		fprintf(stderr, "Please check it:\n\n");
		aux_fprint_ToBeSigned(stderr, newcert->tbs);
		fprintf(stderr, "\nDo you want to sign the displayed Cross Certificate?\n");
		fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

		af_pse_close (NULLOBJID);
		if ( af_sign(newcert->tbs_DERcode, newcert->sig, END) < 0 ) {
			aux_add_error(ESIGN, "af_sign failed", newcert, Certificate_n, proc);
			return(-1);
		}

		oclist->ccert = aux_cpy_Certificate(newcert);
		aux_free_Certificate(&newcert);
		oclist->serialnumber = 0;
		oclist->next = (OCList * )0;
		first_line->next = oclist;
	} 
	else {
		first_line->next = oclist;

		/* verify cross certificate in first line of obsolete directory table   */
		/* "Old Certificates":							*/

		fprintf(stderr, "\nVerifying cross certificate in first line of obsolete ");
		fprintf(stderr, "directory table\n `OldCertificates` by applying PKRoot.oldkey...\n\n");

		vkey.key = aux_cpy_KeyInfo(pkroot->oldkey->key);
		vkey.keyref = 0;
		vkey.pse_sel = (PSESel *) 0;

		alghash = aux_ObjId2AlgHash(oclist->ccert->sig->signAI->objid);
		/* needs HashInput parameter set */
		if (alghash == SQMODN) {
			vhashin = (HashInput * ) & vkey.key->subjectkey;
		}

		rc = sec_verify(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END, &vkey, vhashin);
		if ( rc < 0 ) {
			aux_add_error(EVERIFY, "sec_verify failed for cross certificate", CNULL, 0, proc);
			return (-1);
		}

		/* Replace the certificates' signatures and serial numbers, whereby other	*/
		/* certificate attributes including certified keys and validity values		*/
		/* remain unchanged. Of course, the table's serial numbers of those lines 	*/
		/* remain the same, too.							*/

		oclist->ccert->tbs->serialnumber = af_pse_incr_serial();

		oclist->ccert->sig->signAI = NULLALGID;
		nullocts.noctets = 0;
		nullocts.octets = CNULL;
		af_pse_close (NULLOBJID);
		if ( af_sign(&nullocts, oclist->ccert->sig, END) < 0) {
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return (-1);
		}
		oclist->ccert->tbs->signatureAI = aux_cpy_AlgId(oclist->ccert->sig->signAI);
		save_signAI = aux_cpy_AlgId(oclist->ccert->sig->signAI);
		aux_free2_KeyInfo(oclist->ccert->sig);

		if ((oclist->ccert->tbs_DERcode = e_ToBeSigned(oclist->ccert->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ToBeSigned failed", CNULL, 0, proc);
			return (-1);
		}

		fprintf(stderr, "\nThe following Cross Certificate is to be signed. Please check it:\n\n");
		aux_fprint_ToBeSigned(stderr, oclist->ccert->tbs);
		fprintf(stderr, "\nDo you want to sign the displayed Cross Certificate?\n");
		fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

		af_pse_close (NULLOBJID);
		if ( af_sign(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END) < 0 ) {
			aux_add_error(ESIGN, "af_sign failed", oclist->ccert, Certificate_n, proc);
			return(-1);
		}

		if ( (oclist = oclist->next) == (OCList * )0 ) {
			aux_add_error(EINVALID, "oclist->next empty", CNULL, 0, proc);
			return (-1);
		}
		/*Directory table "Old Certificates" must be composed of at least two lines*/

		/* verify cross certificate in second line of obsolete directory table   */
		/* "Old Certificates":							 */

		vkey.key = aux_cpy_KeyInfo(pkroot->newkey->key);
		vkey.keyref = 0;
		vkey.pse_sel = (PSESel *) 0;

		/**vhashin = 0;*/
		alghash = aux_ObjId2AlgHash(oclist->ccert->sig->signAI->objid);
		/* needs HashInput parameter set */
		if (alghash == SQMODN) {
			vhashin = (HashInput * ) & vkey.key->subjectkey;
		}

		rc = sec_verify(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END, &vkey, vhashin);
		if ( rc < 0 ) {
			aux_add_error(EVERIFY, "sec_verify failed for cross certificate", CNULL, 0, proc);
			return - 1;
		}

		oclist->ccert->tbs->serialnumber = af_pse_incr_serial();
		oclist->ccert->tbs->signatureAI = aux_cpy_AlgId(save_signAI);

		if ((oclist->ccert->tbs_DERcode = e_ToBeSigned(oclist->ccert->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ToBeSigned failed", oclist->ccert, Certificate_n, proc);
			return (-1);
		}

		fprintf(stderr, "\nThe following Cross Certificate is to be signed. Please check it:\n\n");
		aux_fprint_ToBeSigned(stderr, oclist->ccert->tbs);
		fprintf(stderr, "\nDo you want to sign the displayed Cross Certificate?\n");
		fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

		af_pse_close (NULLOBJID);
		if ( af_sign(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END) < 0 ) {
			aux_add_error(ESIGN, "af_sign failed", oclist->ccert, Certificate_n, proc);
			return(-1);
		}

		oclist = oclist->next;

		while ( oclist ) {
			rc = sec_verify(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END, &vkey, vhashin);
			if ( rc < 0 ) {
				aux_add_error(EVERIFY, "sec_verify failed for cross certificate", CNULL, 0, proc);
				return - 1;
			}

			oclist->ccert->tbs->serialnumber = af_pse_incr_serial();
			oclist->ccert->tbs->signatureAI = aux_cpy_AlgId(save_signAI);

			if ((oclist->ccert->tbs_DERcode = e_ToBeSigned(oclist->ccert->tbs)) == NULLOCTETSTRING) {
				aux_add_error(EENCODE, "e_ToBeSigned failed", CNULL, 0, proc);
				return (-1);
			}

			fprintf(stderr, "\nThe following Cross Certificate is to be signed. Please check it:\n\n");
			aux_fprint_ToBeSigned(stderr, oclist->ccert->tbs);
			fprintf(stderr, "\nDo you want to sign the displayed Cross Certificate?\n");
			fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

			af_pse_close (NULLOBJID);
			if ( af_sign(oclist->ccert->tbs_DERcode, oclist->ccert->sig, END) < 0 ) {
				aux_add_error(ESIGN, "af_sign failed", oclist->ccert, Certificate_n, proc);
				return(-1);
			}

			oclist = oclist->next;
		}  /*while*/

		aux_free_AlgId(&save_signAI);

	}  /*else*/

	if ( af_dir_enter_OCList(first_line, dname) < 0 ) {
		aux_add_error(EINVALID, "af_dir_enter_OCList failed", dname, DName_n, proc);
		return(-1);
	}


	return(0);

}


Crl *af_create_Crl()
{

	Crl    * new_rclist;
	OctetString  nullocts;
	char	   * proc = "af_create_Crl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	new_rclist = (Crl * )malloc(sizeof(Crl));
	if (!new_rclist) {
		aux_add_error(EMALLOC, "new_rclist", CNULL, 0, proc);
		return ((Crl * ) 0);
	}

	new_rclist->tbs = (CrlTBS * )malloc(sizeof(CrlTBS));
	if (!new_rclist->tbs) {
		aux_add_error(EMALLOC, "new_rclist->tbs", CNULL, 0, proc);
		return ((Crl * ) 0);
	}

	new_rclist->tbs->issuer = af_pse_get_Name();
	new_rclist->tbs->lastupdate = aux_current_UTCTime();
	new_rclist->tbs->revokedcertificates = (SEQUENCE_OF_RevCert * )0;

	new_rclist->sig = (Signature * )malloc(sizeof(Signature));
	if (!new_rclist->sig) {
		aux_add_error(EMALLOC, "new_rclist->sig", CNULL, 0, proc);
		return ((Crl * ) 0);
	}

	new_rclist->sig->signAI = NULLALGID;
	nullocts.noctets = 0;
	nullocts.octets = CNULL;
	af_pse_close (NULLOBJID);
	if ( af_sign(&nullocts, new_rclist->sig, END) < 0) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return ( (Crl * )0 );
	}
	new_rclist->tbs->signatureAI = aux_cpy_AlgId(new_rclist->sig->signAI);
	aux_free2_KeyInfo(new_rclist->sig);

	if ((new_rclist->tbs_DERcode = e_CrlTBS(new_rclist->tbs)) == NULLOCTETSTRING) {
		aux_add_error(EENCODE, "e_CrlTBS failed", CNULL, 0, proc);
		return( (Crl * )0);
	}

	fprintf(stderr, "\nThe following empty Crl is to be signed. Please check it:\n\n");
	aux_fprint_CrlTBS(stderr, new_rclist->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed Crl?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close (NULLOBJID);
	if ( af_sign(new_rclist->tbs_DERcode, new_rclist->sig, END) < 0 ) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return( (Crl * )0 );
	}
	return (new_rclist);

}
#endif


