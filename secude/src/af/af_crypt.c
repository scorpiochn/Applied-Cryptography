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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include "af.h"

#define MAXCERT 125


static int             get_path();
static int             certs_at_one_level();
static int	       verify_CertificateWithPkroot();
static void 	       get_path_finish();
static UTCTime       * check_black_list();
static Certificate   * check_CrossCertificates(); 
static RC              complete_FCPath_from_Directory();
static KeyInfo 	     * LookupPK();
static KeyInfo       * LookupPK_in_FCPath();

static Boolean	       call_af_verify = FALSE;

static Boolean	       crosscert_appended_to_certs = FALSE;
static Boolean	       crosscert_from_Directory = FALSE;

static Boolean 	       certs_from_directory = FALSE;

static PKRoot        * own_pkroot;
static FCPath	     * own_fcpath, * reduced_fcpath;
static int	       usercert_crlcheck;

RC
af_encrypt(inoctets, outbits, more, key, dname)
OctetString	* inoctets;
BitString	* outbits;
More		  more;
Key		* key;
DName		* dname;
{
	static Certificate  * encrCert = (Certificate * ) 0;
	static Key            encrkey = { (KeyInfo * ) 0, 0, (PSESel * ) 0, NULLALGID };
	int	              ret;
	char	            * proc = "af_encrypt";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (encrkey.key == (KeyInfo * ) 0)
		if ( (key == (Key * ) 0) && !dname ) {
			/* use own key */
			encrCert = af_pse_get_Certificate(ENCRYPTION, NULLDNAME, 0);
			if (!encrCert)	 {
				aux_add_error(EREADPSE, "af_pse_get_Certificate failed", CNULL, 0, proc);
				return - 1;
			}
			key = &encrkey;
			encrkey.key = encrCert->tbs->subjectPK;
		} 
		else if (dname) {
			/* use EKList */
			key = &encrkey;
			encrkey.key = af_pse_get_PK(ENCRYPTION, dname, NULLDNAME, 0);
			if (!encrkey.key)	 {
				aux_add_error(EREADPSE, "af_pse_get_PK failed", CNULL, 0, proc);
				return - 1;
			}

		}
	/* key is defined */

	ret = sec_encrypt(inoctets, outbits, more, key);
	if (more == END) {
		if (encrCert) {
			aux_free_Certificate(&encrCert);
			encrkey.key = (KeyInfo * ) 0;
		} else if (encrkey.key)
			aux_free_KeyInfo(&encrkey.key);
		else 
			encrkey.key = (KeyInfo * ) 0;
	}
	if (ret < 0) {
		aux_add_error(EENCRYPT, "sec_encrypt failed", CNULL, 0, proc);
	}
	return ret;

}	/* af_encrypt() */


/*********************************************************************************************/


RC
af_decrypt(inbits, outoctets, more, key)
BitString	*inbits;
OctetString	*outoctets;
More		more;
Key		*key;
{
	static Key	deckey;
	static PSESel	pse;
	RC		ret;
	Boolean         onekeypaironly = FALSE;

	char	      * proc = "af_decrypt";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!key) {
		/* use PSE decrypt key */
		key = &deckey;
		deckey.key = (KeyInfo * ) 0;
		deckey.keyref = 0;
		deckey.pse_sel = &pse;
		pse.app_name = AF_pse.app_name;
		pse.pin      = AF_pse.pin;

		if(af_check_if_onekeypaironly(&onekeypaironly)){
			aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
			return(- 1);
		}

		if(onekeypaironly == TRUE){
			pse.object.name = SKnew_name;
			pse.object.pin = getobjectpin(SKnew_name);
		}
		else{
			pse.object.name = DecSKnew_name;
			pse.object.pin = getobjectpin(DecSKnew_name);
		}
	}

	if ( (ret = sec_decrypt(inbits, outoctets, more, key)) < 0) {
		aux_add_error(EDECRYPT, "sec_decrypt failed", CNULL, 0, proc);
		return(- 1);
	}
	return (ret);

}	/* af_decrypt() */


/*********************************************************************************************/


RC
af_sign(inoctets, signature, more)
OctetString	* inoctets;
Signature	* signature;
More		  more;
{
	int	             ret;
	static PSESel	     pse;
	static Key           skey;                                    /* signkey refers to PSE Signature_Key */
	static HashInput   * hashin;	                        /* hashinput pointer */
	static Certificate * signCert = (Certificate *) 0;	/* signkey Certificate */
	static int	     first = 0;
	Boolean  	     onekeypaironly = FALSE;

	char		   * proc = "af_sign";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!first)  {
		first = 1;
		skey.key = (KeyInfo * ) 0;
		skey.keyref = 0;
		skey.pse_sel = &pse;
		/* sign key resides on PSE */
		pse.app_name = AF_pse.app_name;
		pse.pin      = AF_pse.pin;
		skey.alg = signature->signAI;

		if(af_check_if_onekeypaironly(&onekeypaironly)){
			aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
			return (- 1);
		}

		if(onekeypaironly == TRUE){
			pse.object.name = SKnew_name;
			pse.object.pin = getobjectpin(SKnew_name);
		}
		else{
			pse.object.name = SignSK_name;
			pse.object.pin = getobjectpin(SignSK_name);
		}
		pse.pin      = AF_pse.pin; /* if PSE was closed before call of getobjectpin */
		if (inoctets->noctets && signature->signAI)
			if (aux_ObjId2AlgHash(signature->signAI->objid) == SQMODN) {
				if ((signCert = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0)) == (Certificate *) 0) {
					aux_add_error(EREADPSE, "af_pse_get_Certificate failed", CNULL, 0, proc);
					return - 1;
				}

				hashin = (HashInput * ) & signCert->tbs->subjectPK->subjectkey;
			}
			else 
				hashin = (HashInput * ) 0;
	}

	ret = sec_sign(inoctets, signature, more, &skey, hashin);

	if (more == END) {
		if (signCert) 
			aux_free_Certificate(&signCert);
		first = 0;
	}

	if (ret < 0) {
		aux_add_error(ESIGN, "sec_sign failed", CNULL, 0, proc);
	}
	return(ret);

}	/* af_sign() */


/*********************************************************************************************/


RC
af_verify(inocts, sign, more, or_cert, time, pkroot)
OctetString    * inocts;
Signature      * sign;
More             more;
Certificates   * or_cert;
UTCTime        * time;
PKRoot         * pkroot;
{
	static HashInput  * hashin = (HashInput * ) 0;         /* hash input in case of sqmodn */
	static Key          key;                  	       /* the public key */
        static PKRoot     * lpkroot;
        static char         first = TRUE;
	static Boolean      freetime = FALSE;      
	int		    pkroot_mall = 0;
	Certificate	  * cert;
	int	            rc;
#ifdef TIMEMEASURE
	long                hash_secs, hash_microsecs, rsa_secs, rsa_microsecs;
#endif
	AlgHash             alghash;
	UTCTime           * timedate;
	char	          * proc = "af_verify";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(inocts && sign && sign->signAI)) {
		aux_add_error(EINVALID, "one parameter empty", CNULL, 0, proc);
		return - 1;
	}

	if (or_cert && !or_cert->usercertificate) {
		aux_add_error(EINVALID, "no user certificate provided", CNULL, 0, proc);
		return - 1;
	}

        if(first) {
		if(own_pkroot) aux_free_PKRoot(&own_pkroot);
		if (!time) {
			time = aux_current_UTCTime();
			freetime = TRUE;
		}

		call_af_verify = TRUE;

                lpkroot = pkroot;
                if(! or_cert) {
                        if(!lpkroot) {
                                lpkroot = af_pse_get_PKRoot();
                                pkroot_mall = 1;
                        }
                        if(!lpkroot) {
                		aux_add_error(EROOTKEY, "Can't get PKRoot", CNULL, 0, proc);
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
                                return(-1);
                        }
			own_pkroot = aux_cpy_PKRoot(lpkroot);
                        key.key = lpkroot->newkey->key;
                }
                else {
			key.key = or_cert->usercertificate->tbs->subjectPK;
		}

        	key.keyref = 0;
        	key.pse_sel = (PSESel *) 0;

        	/* needs HashInput parameter set */
        	alghash = aux_ObjId2AlgHash(sign->signAI->objid);
        	if (alghash == SQMODN) hashin = (HashInput * ) & key.key->subjectkey;

                first = FALSE;
        }

	if (more == END) {
		first = TRUE;

		/* Free VerificationResult-structure filled by previous verification process */
		if(verifresult){
			aux_free_VerificationResult(&verifresult);
			verifresult = (VerificationResult * )0;
		}
	
		verifresult = (VerificationResult *)calloc(1, sizeof(VerificationResult) );
		if (! verifresult) {
			aux_add_error(EMALLOC, "verifresult", CNULL, 0, proc);
			return (- 1);
		}
		verifresult->verifstep = (VerificationStep ** )0;
		verifresult->top_name = CNULL;
		verifresult->top_serial = 0;
		verifresult->trustedKey = - 1;
		if(pkroot_mall == 1) verifresult->trustedKey = 0;
		verifresult->date = (UTCTime * )0;
		verifresult->textverified = TRUE;
		verifresult->success = TRUE;

		if (lpkroot){
			/* Check Validity of Root Info */
			if (af_check_validity_of_PKRoot(time, lpkroot)) {
				/* Root Info has expired ! */
				aux_add_error(EVALIDITY, "Root Info has expired", lpkroot, PKRoot_n, proc);
				verifresult->top_serial = lpkroot->newkey->serial;
				verifresult->top_name = aux_DName2Name(lpkroot->ca);
				verifresult->date = aux_cpy_Name(lpkroot->newkey->notafter);
				verifresult->trustedKey = - 2;
				verifresult->success = FALSE;
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				if(pkroot_mall) aux_free_PKRoot(&lpkroot);
				call_af_verify = FALSE;
				return(- 1);
			}
		}

		if(or_cert){
			/* Check Validity of usercertificate */
			if (af_check_validity_of_Certificate(time, or_cert->usercertificate)) {
				/* User Certificate has expired ! */
				aux_add_error(EVALIDITY, "Certificate has expired", or_cert->usercertificate, Certificate_n, proc);
				verifresult->verifstep = (VerificationStep **)calloc(2, sizeof(VerificationStep * ));
				if (! verifresult->verifstep) {
					aux_add_error(EMALLOC, "verifresult->verifstep", CNULL, 0, proc);
					return (- 1);
				}
		
				verifresult->verifstep[1] = (VerificationStep * )0;
				/* required for while loop in aux_fprint_VerificationResult */
	
				verifresult->verifstep[0] = (VerificationStep *)malloc(sizeof(VerificationStep) );
				if (! verifresult->verifstep[0]) {
					aux_add_error(EMALLOC, "verifresult->verifstep[0]", CNULL, 0, proc);
					return (- 1);
				}
				verifresult->verifstep[0]->date = aux_cpy_Name(or_cert->usercertificate->tbs->notafter);
				verifresult->trustedKey = - 2;
				verifresult->success = FALSE;
				verifresult->verifstep[0]->cert = aux_cpy_Certificate(or_cert->usercertificate);
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				call_af_verify = FALSE;
				return (- 1);
			}

		}
	}

	if ((rc = sec_verify(inocts, sign, more, &key, hashin)) < 0) {

		if (more == END) {
			verifresult->success = FALSE;
	
			if (or_cert){
				verifresult->top_serial = or_cert->usercertificate->tbs->serialnumber;
				verifresult->top_name = aux_DName2Name(or_cert->usercertificate->tbs->subject);
	
				verifresult->verifstep = (VerificationStep **)calloc(2, sizeof(VerificationStep * ));
				if (! verifresult->verifstep) {
					aux_add_error(EMALLOC, "verifresult->verifstep", CNULL, 0, proc);
					return (- 1);
				}
		
				verifresult->verifstep[1] = (VerificationStep * )0;
				/* required for while loop in aux_fprint_VerificationResult */
	
				verifresult->verifstep[0] = (VerificationStep *)malloc(sizeof(VerificationStep) );
				if (! verifresult->verifstep[0]) {
					aux_add_error(EMALLOC, "verifresult->verifstep[0]", CNULL, 0, proc);
					return (- 1);
				}
				verifresult->verifstep[0]->date = (UTCTime * )0;
				verifresult->verifstep[0]->supplied = 0;
				verifresult->verifstep[0]->crlcheck = 0;
	
				verifresult->verifstep[0]->cert = aux_cpy_Certificate(or_cert->usercertificate);
		
				aux_add_error(ESIGNATURE, "Verification of text signature failed", or_cert->usercertificate, Certificate_n, proc);
			}
			else {
				verifresult->top_serial = lpkroot->newkey->serial;
				verifresult->top_name = aux_DName2Name(lpkroot->ca);
				aux_add_error(ESIGNATURE, "Verification of text signature failed", lpkroot->newkey->key, KeyInfo_n, proc);
			}
		}
		
                if(pkroot_mall) aux_free_PKRoot(&lpkroot);
                lpkroot = (PKRoot *)0;
		call_af_verify = FALSE;

		if(freetime) {
			free(time);
			freetime = FALSE;
		}
		return (- 1);
	}
#ifdef TIMEMEASURE
	rsa_secs = rsa_sec;
	rsa_microsecs = rsa_usec;
	hash_secs = hash_sec;
	hash_microsecs = hash_usec;
#endif

	/* text has been verified, so verify or_cert */

	timedate = sec_SignatureTimeDate;

	if (more == END) {
                if(or_cert) {
			if(!or_cert->forwardpath){
				cert = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0);
				if(! cert){
					aux_add_error(EREADPSE, "af_pse_get_Certificate failed", CNULL, 0, proc);
					call_af_verify = FALSE;
					return (- 1);
				}
				if(!aux_cmp_Certificate(or_cert->usercertificate, cert)) {
					verifresult->trustedKey = 4;
					verifresult->top_serial = or_cert->usercertificate->tbs->serialnumber;
					verifresult->top_name = aux_DName2Name(or_cert->usercertificate->tbs->subject);
		
					verifresult->verifstep = (VerificationStep **)calloc(2, sizeof(VerificationStep * ));
					if (! verifresult->verifstep) {
						aux_add_error(EMALLOC, "verifresult->verifstep", CNULL, 0, proc);
						call_af_verify = FALSE;
						return (- 1);
					}
			
					verifresult->verifstep[1] = (VerificationStep * )0;
					/* required for while loop in aux_fprint_VerificationResult */
		
					verifresult->verifstep[0] = (VerificationStep *)malloc(sizeof(VerificationStep) );
					if (! verifresult->verifstep[0]) {
						aux_add_error(EMALLOC, "verifresult->verifstep[0]", CNULL, 0, proc);
						call_af_verify = FALSE;
						return (- 1);
					}
					verifresult->verifstep[0]->date = (UTCTime * )0;
					verifresult->verifstep[0]->supplied = 0;
					verifresult->verifstep[0]->crlcheck = 0;
		
					verifresult->verifstep[0]->cert = aux_cpy_Certificate(or_cert->usercertificate);
					if(freetime) {
						free(time);
						freetime = FALSE;
					}
					call_af_verify = FALSE;
					return(0);
				}
			}
        		rc = af_verify_Certificates(or_cert, time, lpkroot);
			call_af_verify = FALSE;
        		if (rc < 0) 
				aux_add_error(EVERIFICATION, "Incomplete verification path in originator certificate", or_cert, Certificates_n, proc);
                }
                else {
			if(pkroot_mall) 
				aux_free_PKRoot(&lpkroot);
			verifresult->top_serial = lpkroot->newkey->serial;
			verifresult->top_name = aux_DName2Name(lpkroot->ca);
		}
                lpkroot = (PKRoot *)0;
		call_af_verify = FALSE;
	}
	sec_SignatureTimeDate = timedate;
	call_af_verify = FALSE;

#ifdef TIMEMEASURE
	rsa_sec = rsa_secs;
	rsa_usec = rsa_microsecs;
	hash_sec = hash_secs;
	hash_usec = hash_microsecs;
#endif

	if(freetime) {
		free(time);
		freetime = FALSE;
	}
	return(rc);

}	/* af_verify() */


/*********************************************************************************************/


RC af_verify_Certificates(or_cert, time, pkroot)
Certificates    *or_cert;
UTCTime         *time;
PKRoot          *pkroot;
{


/*
      - verifresult->success = TRUE

	Verification of "Certificates" succeeded ...

		... with PKRoot(new) 
                    (verifresult->trustedKey = 0)

		... with PKRoot(old) 
                    (verifresult->trustedKey = 1)

		... with PKList      
                    (verifresult->trustedKey = 2)

		... with FCPath      
                    (verifresult->trustedKey = 3)

		... with own SIGNATURE certificate      
                    (verifresult->trustedKey = 4)


      - verifresult->success = FALSE

	Verification of "Certificates" failed ...

		... with PKRoot(new) 				
                    (verifresult->trustedKey = 0)

		... with PKRoot(old) 				
		    (verifresult->trustedKey = 1)

		... with PKList      				
		    (verifresult->trustedKey = 2)

		... with FCPath      				
                    (verifresult->trustedKey = 3)

		... with certificate at next level above (verification failure)	
		    (verifresult->trustedKey = - 1, crlcheck = 0)

		... as certificate at next level above was revoked	
		    (verifresult->trustedKey = - 1, crlcheck = REVOKED)

		... as certificate provided at next level was expired
		    (verifresult->trustedKey = - 2)

		... as there was no certificate available at next level
		    (verifresult->trustedKey = - 3)

		... as PEM name subordination rule has been violated
		    (verifresult->trustedKey = - 4, crlcheck = 0)
	
*/

	
	static Boolean  freetime = FALSE;      
	HashInput     * hashin = (HashInput * ) 0;         /* hash input in case of sqmodn */
	Key    	        key;                               /* the public key */
	KeyInfo	        topkey;
        int             topkey_serial, key_serial, pkroot_mall = 0;
	int	        rc = 0;
	AlgHash         alghash;
	Certificate * * certList;                          /* certificate array from get path */
	Certificate   * C, * CC, * cert;
	FCPath	      * path;
	PKList	      * pklist = (PKList * )0;
	int 		count, index, ret;
	UTCTime	      * date;
	Certificates  * reduced_or_cert = (Certificates * )0;
	int	        c, cc;

	char	      * proc = "af_verify_Certificates";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif


	if(call_af_verify == FALSE){
		if(own_pkroot) aux_free_PKRoot(&own_pkroot);

		/* Free VerificationResult-structure filled by previous verification process */
		if(verifresult){
			aux_free_VerificationResult(&verifresult);
			verifresult = (VerificationResult * )0;
		}
	}

	if(own_fcpath) aux_free_FCPath(&own_fcpath);
	if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);

	crosscert_appended_to_certs = crosscert_from_Directory = FALSE;
	certs_from_directory = FALSE;

        if(! or_cert) 
		return(0);

	if (! or_cert->usercertificate) {
		aux_add_error(EINVALID, "No user certificate provided", CNULL, 0, proc);
		return (- 1);
	}

        if(! pkroot) {
                pkroot = af_pse_get_PKRoot();
                if(! pkroot) {
        		aux_add_error(EROOTKEY, "Can't get PKRoot", CNULL, 0, proc);
                        return(-1);
                }
                pkroot_mall = 1;
		own_pkroot = aux_cpy_PKRoot(pkroot);
        }

	key.keyref = 0;
	key.pse_sel = (PSESel *) 0;


	cert = or_cert->usercertificate;


	if(call_af_verify == FALSE){
		/* Allocate memory for VerificationResult structure */
		verifresult = (VerificationResult *)malloc(sizeof(VerificationResult) );
		if (! verifresult) {
			aux_add_error(EMALLOC, "verifresult", CNULL, 0, proc);
			return (- 1);
		}
		verifresult->verifstep = (VerificationStep ** )0;
		verifresult->top_name = CNULL;
		verifresult->top_serial = 0;
		verifresult->trustedKey = - 1;
		verifresult->date = (UTCTime * )0;
		verifresult->textverified = FALSE;
		verifresult->success = TRUE;
	}

	if (! time) {
		time = aux_current_UTCTime();
		freetime = TRUE;
	}

	/* Check Validity of PKRoot */
	if (af_check_validity_of_PKRoot(time, pkroot)) {
		/* Root Info has expired ! */
		aux_add_error(EVALIDITY, "Root Info has expired", pkroot, PKRoot_n, proc);
		verifresult->top_serial = pkroot->newkey->serial;
		verifresult->top_name = aux_DName2Name(pkroot->ca);
		verifresult->date = aux_cpy_Name(pkroot->newkey->notafter);
		verifresult->trustedKey = - 2;
		verifresult->success = FALSE;

		if(freetime) {
			free(time);
			freetime = FALSE;
		}
		if (pkroot_mall) aux_free_PKRoot(&pkroot);
		return(- 1);
	}

	verifresult->verifstep = (VerificationStep **)calloc(MAXCERT, sizeof(VerificationStep * ));
	if (! verifresult->verifstep) {
		aux_add_error(EMALLOC, "verifresult->verifstep", CNULL, 0, proc);
		return (- 1);
	}
	for(index = 0; index < MAXCERT; index++)
		verifresult->verifstep[index] = (VerificationStep * )0;


	verifresult->verifstep[0] = (VerificationStep *)malloc(sizeof(VerificationStep) );
	if (! verifresult->verifstep[0]) {
		aux_add_error(EMALLOC, "verifresult->verifstep[0]", CNULL, 0, proc);
		return (- 1);
	}
	verifresult->verifstep[0]->date = (UTCTime * )0;
	verifresult->verifstep[0]->supplied = 0;
	verifresult->verifstep[0]->crlcheck = 0;

	verifresult->verifstep[0]->cert = aux_cpy_Certificate(cert);


	/* Check Validity of usercertificate */
	if (af_check_validity_of_Certificate(time, verifresult->verifstep[0]->cert)) {
		/* User Certificate has expired ! */
		aux_add_error(EVALIDITY, "Certificate has expired", or_cert->usercertificate, Certificate_n, proc);
		verifresult->verifstep[0]->date = aux_cpy_Name(or_cert->usercertificate->tbs->notafter);
		verifresult->trustedKey = - 2;
		verifresult->success = FALSE;

		if(freetime) {
			free(time);
			freetime = FALSE;
		}
		if(pkroot_mall) aux_free_PKRoot(&pkroot);
		return (- 1);
	}


	/* Check against revocation list */
	if (af_chk_crl){
		date = check_black_list(verifresult->verifstep[0]->cert, time);
		if (! date) {
			if (err_stack->e_number == EAVAILABLE)
				verifresult->verifstep[0]->crlcheck = CRL_NOT_AVAILABLE;
			else 
				verifresult->verifstep[0]->crlcheck = NOT_REVOKED;
		}
		else{
			verifresult->verifstep[0]->date = aux_cpy_Name(date);
			if (err_stack->e_number == EREVOKE) {
				verifresult->verifstep[0]->crlcheck = REVOKED; 
				verifresult->success = FALSE;
				verifresult->trustedKey = - 1;
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				return(- 1);
			}
			else if (err_stack->e_number == EVALIDITY)
				verifresult->verifstep[0]->crlcheck = CRL_OUT_OF_DATE; 
		}
	}
	else verifresult->verifstep[0]->crlcheck = NOT_REQUESTED;


	if (af_chk_crl == FALSE) {
		pklist = af_pse_get_PKList(SIGNATURE);
		aux_free_error();

		if (af_FCPath_is_trusted == TRUE) {	
			own_fcpath = af_pse_get_FCPath(NULLDNAME);
			aux_free_error();
		
			if(own_fcpath){
				reduced_fcpath = reduce_FCPath_to_HierarchyPath(own_fcpath);
				aux_free_FCPath(&own_fcpath);
				if(! reduced_fcpath){
					aux_add_error(EDAMAGE, "FCPath does not fit to PKRoot", CNULL, 0, proc);
					aux_free_VerificationResult(&verifresult);
					return(- 1);
				}
			}
		}
	}


	if(call_af_verify == TRUE && af_chk_crl == FALSE){
		/* Check user certificate against PKList */
		if(pklist){
			if (LookupPK(cert->tbs->subject, cert->tbs->subjectPK, pklist, time) != 0){

				verifresult->top_name = aux_DName2Name(cert->tbs->issuer);
				verifresult->top_serial = cert->tbs->serialnumber;
				verifresult->trustedKey = 2;

				if(pklist) aux_free_PKList(&pklist);
				if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				return(0); /* verification successfully completed */
			}
		}
	
		/* Check user certificate against FCPath */
		if (reduced_fcpath && af_FCPath_is_trusted == TRUE) {
			if (LookupPK_in_FCPath(cert->tbs->subject, cert->tbs->subjectPK, reduced_fcpath, time) != 0){

				verifresult->top_name = aux_DName2Name(cert->tbs->issuer);
				verifresult->top_serial = cert->tbs->serialnumber;
				verifresult->trustedKey = 3;

				if(pklist) aux_free_PKList(&pklist);
				if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				return(0); /* verification successfully completed */
			}
		}
	}


	path = or_cert->forwardpath; 
	count = certs_at_one_level(path);

	index = 0;

	while (count == 1) {

		index++;

		/* Verify with certificate of next level above */

		cert = path->liste->element;


		/* Check validity of certificate at next level above */

		if (af_check_validity_of_Certificate(time, cert)) {

			aux_add_error(EVALIDITY, "Certificate has expired", cert, Certificate_n, proc);
	
			verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
			if (! verifresult->verifstep[index]) {
				aux_add_error(EMALLOC, "verifresult->verifstep[index]", CNULL, 0, proc);
				return (- 1);
			}
			verifresult->verifstep[index]->date = aux_cpy_Name(cert->tbs->notafter);
			verifresult->verifstep[index]->supplied = 0;
			verifresult->verifstep[index]->crlcheck = 0;

			verifresult->verifstep[index]->cert = aux_cpy_Certificate(cert);

			verifresult->trustedKey = - 2;
			verifresult->success = FALSE;

			if(pklist) aux_free_PKList(&pklist);
			if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);

			if(freetime) {
				free(time);
				freetime = FALSE;
			}
			return (- 1);
		}


		/* Try to verify ... */

        	key.key = cert->tbs->subjectPK;  /* verification key of next level */
                key_serial = cert->tbs->serialnumber;

		/* needs HashInput parameter set */
		alghash = aux_ObjId2AlgHash(verifresult->verifstep[index - 1]->cert->sig->signAI->objid);
		if (alghash == SQMODN) 
			hashin = (HashInput * ) & key.key->subjectkey;
		else 
			hashin = (HashInput * ) 0;

		if (sec_verify(verifresult->verifstep[index - 1]->cert->tbs_DERcode, verifresult->verifstep[index - 1]->cert->sig, END, &key, hashin) < 0) {
			aux_add_error(EVERIFICATION, "Verification of certificate failed", verifresult->verifstep[index - 1]->cert, Certificate_n, proc);

			verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
			if (! verifresult->verifstep[index]) {
				aux_add_error(EMALLOC, "verifresult->verifstep[index]", CNULL, 0, proc);
				return (- 1);
			}
			verifresult->verifstep[index]->date = (UTCTime * )0;
			verifresult->verifstep[index]->supplied = 0;
			verifresult->verifstep[index]->crlcheck = 0;

			verifresult->verifstep[index]->cert = aux_cpy_Certificate(cert);

			verifresult->success = FALSE;

			if(pklist) aux_free_PKList(&pklist);
			if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
			if(freetime) {
				free(time);
				freetime = FALSE;
			}
			return (- 1);
		}


		/* Check for PEM subordination, if required */

		if (chk_PEM_subordination == TRUE) {
			ret = aux_checkPemDNameSubordination(verifresult->verifstep[index - 1]->cert->tbs->issuer,
							    verifresult->verifstep[index - 1]->cert->tbs->subject);

			if (ret == - 1) {
				if(pklist) aux_free_PKList(&pklist);
				if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
				if(freetime) {
					free(time);
					freetime = FALSE;
				}
				aux_add_error(EINVALID, "aux_checkPemDNameSubordination failed", CNULL, 0, proc);
				return (- 1);
			}
			if (ret == FALSE) {
				/* 'subject' NOT subordinate to 'issuer'                   */
				/* Check whether issuer's cert can be verified by 'pkroot' */
				ret = verify_CertificateWithPkroot(cert, pkroot);
				if (ret < 0) {
					verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );

					verifresult->verifstep[index]->date = (UTCTime * )0;
					verifresult->verifstep[index]->supplied = 0;
					verifresult->verifstep[index]->crlcheck = 0;

					verifresult->verifstep[index]->cert = aux_cpy_Certificate(cert);
		
					verifresult->trustedKey = - 4;
					verifresult->success = FALSE;
		
					if(pklist) aux_free_PKList(&pklist);
					if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
					if(freetime) {
						free(time);
						freetime = FALSE;
					}
					return (- 1);
				}
			}
		}  /* chk_PEM_subordination */					    


		/* Check certificate at next level above against revocation list */

		if (af_chk_crl == TRUE){
			date = check_black_list(cert, time);
			if (! date) {
				if (err_stack->e_number == EAVAILABLE)
					usercert_crlcheck = CRL_NOT_AVAILABLE;
				else 
					usercert_crlcheck = NOT_REVOKED;
			}
			else{
				if (err_stack->e_number == EREVOKE) {

					verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
					if (! verifresult->verifstep[index]) {
						aux_add_error(EMALLOC, "verifresult->verifstep[index]", CNULL, 0, proc);
						return (- 1);
					}
					verifresult->verifstep[index]->date = aux_cpy_Name(date);
					verifresult->verifstep[index]->supplied = 0;
					verifresult->verifstep[index]->crlcheck = REVOKED;

					verifresult->verifstep[index]->cert = aux_cpy_Certificate(cert);
		
					verifresult->success = FALSE;
					verifresult->trustedKey = - 1;
		
					if(pklist) aux_free_PKList(&pklist);
					if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);

					if(freetime) {
						free(time);
						freetime = FALSE;
					}
					return(- 1);
				}
				else if (err_stack->e_number == EVALIDITY)
					usercert_crlcheck = CRL_OUT_OF_DATE; 
			}
		}
		else {

			usercert_crlcheck = NOT_REQUESTED;

			/* Check against PKList */
			if(pklist){
				if (LookupPK(cert->tbs->subject,
					      cert->tbs->subjectPK, 
					      pklist, time) != 0){
	
					verifresult->top_name = aux_DName2Name(cert->tbs->issuer);
					verifresult->top_serial = cert->tbs->serialnumber;
					verifresult->trustedKey = 2;
	
					if(pklist) aux_free_PKList(&pklist);
					if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
					if(freetime) {
						free(time);
						freetime = FALSE;
					}
					return(0); /* verification successfully completed */
				}
			}
	
			/* Check against own FCPath */
			if (reduced_fcpath && af_FCPath_is_trusted == TRUE) {
				if (LookupPK_in_FCPath(cert->tbs->subject,
					      cert->tbs->subjectPK, 
					      reduced_fcpath, time) != 0) {
	
					verifresult->top_name = aux_DName2Name(cert->tbs->issuer);
					verifresult->top_serial = cert->tbs->serialnumber;
					verifresult->trustedKey = 3;
	
					if(pklist) aux_free_PKList(&pklist);
					if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
					if(freetime) {
						free(time);
						freetime = FALSE;
					}
					return(0); /* verification successfully completed */
				}
			}
		}

		verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
		if (! verifresult->verifstep[index]) {
			aux_add_error(EMALLOC, "verifresult->verifstep[index]", CNULL, 0, proc);
			return (- 1);
		}
		verifresult->verifstep[index]->date = (UTCTime * )0;
		verifresult->verifstep[index]->cert = aux_cpy_Certificate(cert);
		verifresult->verifstep[index]->supplied = 0;
		verifresult->verifstep[index]->crlcheck = usercert_crlcheck;

		path = path->next_forwardpath;
		count = certs_at_one_level(path);

	}  /* while */


	/* verifresult->verifstep[index]->cert is:	        				              */
	/* either top-level certificate								              */
	/* or the one and only certificate at the highest hierarchy level which contains one certificate only.*/
	/* It will be checked as usercertificate in get_path()				 	              */

	if (index > 0){
		/* originator certificate has been reduced */
		reduced_or_cert = (Certificates *)malloc(sizeof(Certificates) );
		if (! reduced_or_cert) {
			aux_add_error(EMALLOC, "reduced_or_cert", CNULL, 0, proc);
			if(pklist) aux_free_PKList(&pklist);
			if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);
			if(freetime) {
				free(time);
				freetime = FALSE;
			}
			return (- 1);
		}
	
		reduced_or_cert->usercertificate = verifresult->verifstep[index]->cert;
		reduced_or_cert->forwardpath = path;

		c = get_path(reduced_or_cert, pkroot, time, &certList, &topkey, &topkey_serial, FALSE);
	}
	else
		c = get_path(or_cert, pkroot, time, &certList, &topkey, &topkey_serial, TRUE);


	if (c < 0) {
		verifresult->success = FALSE;

                if(pkroot_mall) aux_free_PKRoot(&pkroot);

		if (err_stack->e_number == EPATH){
			verifresult->trustedKey = - 3;
			verifresult->top_name = aux_DName2Name(cert->tbs->issuer);
		}

		if(freetime) {
			free(time);
			freetime = FALSE;
		}
		return(- 1);
	}


        /* verify the chain of certificates in certList */

	/* N O  V A L I D I T Y  checks to be performed at this stage */ 

	/* The validity time frames of the certificates in certList have already been checked by the */
	/* routines certselect() and complete_FCPath_from_Directory().				     */
	/* If certselect() or complete_FCPath_from_Directory() find a certificate to have expired,   */
	/* they consider the "next" certificate available. If there is no "next" certificate 	     */
	/* available, they return error code EPATH.						     */

        for (cc = 1; cc <= c; ++cc, index++   ) {

		C = certList[cc-1];   /* certificate to be verified */

		if (cc > 1){
			verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
			verifresult->verifstep[index]->date = (UTCTime * )0;
			verifresult->verifstep[index]->cert = aux_cpy_Certificate(C);
	
			if (certs_from_directory == FALSE) 
				verifresult->verifstep[index]->supplied = 0;
			else if (cc == c && crosscert_appended_to_certs == TRUE) {
				if (crosscert_from_Directory == TRUE)
					verifresult->verifstep[index]->supplied = 1;
				else
					verifresult->verifstep[index]->supplied = 0;
			}
			else verifresult->verifstep[index]->supplied = 1;
	
			if (af_chk_crl){
				date = check_black_list(C, time);
				if (! date) {
					if (err_stack->e_number == EAVAILABLE)
						verifresult->verifstep[index]->crlcheck = CRL_NOT_AVAILABLE;
					else 
						verifresult->verifstep[index]->crlcheck = NOT_REVOKED;
				}
				else{
					verifresult->verifstep[index]->date = aux_cpy_Name(date);
					if (err_stack->e_number == EREVOKE) {
						verifresult->verifstep[index]->crlcheck = REVOKED; 
						verifresult->success = FALSE;
						verifresult->trustedKey = - 1;
						rc = - 1;
						break;
					}
					else if (err_stack->e_number == EVALIDITY)
						verifresult->verifstep[index]->crlcheck = CRL_OUT_OF_DATE; 
				}
			}
			else verifresult->verifstep[index]->crlcheck = NOT_REQUESTED;
		} /* if */


		CC = certList[cc];    /* certificate containing the verification key for C */
                if(cc == c) {
                	key.key = &topkey;               /* top verification key */
                        key_serial = topkey_serial;
			verifresult->top_serial = topkey_serial;
                }
                else {
        		key.key = CC->tbs->subjectPK;    /* verification key of next level */
                        key_serial = CC->tbs->serialnumber;
                }


		/* needs HashInput parameter set */
		alghash = aux_ObjId2AlgHash(C->sig->signAI->objid);
		if (alghash == SQMODN) 
			hashin = (HashInput * ) & key.key->subjectkey;
		else 
			hashin = (HashInput * ) 0;

		if (sec_verify(C->tbs_DERcode, C->sig, END, &key, hashin) < 0) {
			aux_add_error(EVERIFICATION, 
				      "Verification of certificate failed", 
				      C, Certificate_n, proc);

			verifresult->success = FALSE;
			verifresult->top_serial = key_serial;

			if(cc < c) {
				verifresult->top_name = aux_DName2Name(CC->tbs->subject);

				index++;

				verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
				verifresult->verifstep[index]->date = (UTCTime * )0;
				verifresult->verifstep[index]->cert = aux_cpy_Certificate(CC);

				if(certs_from_directory == FALSE) 
					verifresult->verifstep[index]->supplied = 0;
				else if (cc == c - 1 && crosscert_appended_to_certs == TRUE) {
					if (crosscert_from_Directory == TRUE)
						verifresult->verifstep[index]->supplied = 1;
					else
						verifresult->verifstep[index]->supplied = 0;
				}
				else verifresult->verifstep[index]->supplied = 1;

				verifresult->verifstep[index]->crlcheck = 0;

				verifresult->trustedKey = - 1;
			}
			else { /* c == cc */
				verifresult->top_name = aux_DName2Name(C->tbs->issuer);
			}
			rc = - 1;
                        break;
		}  /* sec_verify < 0 */


		/* Check for PEM subordination, if required */

		if (chk_PEM_subordination == TRUE && cc < c) {
			/* We are aware that condition (cc < c) reduces the validity of the name subordination check. */
			ret = aux_checkPemDNameSubordination(C->tbs->issuer, C->tbs->subject);

			if (ret == - 1) {
				aux_add_error(EINVALID, "aux_checkPemDNameSubordination failed", CNULL, 0, proc);
				aux_free_VerificationResult(&verifresult);
				rc = - 1;
				break;
			}
			if (ret == FALSE) {
				/* 'subject' NOT subordinate to 'issuer'                   */
				/* Check whether issuer's cert can be verified by 'pkroot' */
				ret = verify_CertificateWithPkroot(CC, pkroot);
				if (ret < 0) {
					index ++;
					verifresult->verifstep[index] = (VerificationStep *)malloc(sizeof(VerificationStep) );
					verifresult->verifstep[index]->date = (UTCTime * )0;
					verifresult->verifstep[index]->supplied = 0;
					verifresult->verifstep[index]->crlcheck = 0;

					verifresult->verifstep[index]->cert = aux_cpy_Certificate(CC);
		
					verifresult->success = FALSE;
					verifresult->trustedKey = - 4;
		
					rc = - 1;
					break;
				}
			}
		}  /* chk_PEM_subordination */

	}  /* for */


	aux_free2_KeyInfo(&topkey);
	if (certList) free(certList);
        if(pkroot_mall) aux_free_PKRoot(&pkroot);
	if(pklist) aux_free_PKList(&pklist);
	if(reduced_fcpath) aux_free_FCPath(&reduced_fcpath);

	if(freetime) {
		free(time);
		freetime = FALSE;
	}
	return(rc);

}	/* af_verify_Certificates() */


/*********************************************************************************************/


RC
af_check_validity_of_Certificate(time, cert)
UTCTime *time;
Certificate *cert;
{
	char	*proc = "af_check_validity_of_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(!cert) {
		aux_add_error(EINVALID, "no cert", (Certificate *)0, 0, proc);
		return (- 1);
	}
	if (aux_interval_UTCTime(time, cert->tbs->notbefore, cert->tbs->notafter)) {
		aux_add_error(EVALIDITY, "validity check failed", cert, Certificate_n, proc);
		return (- 1);
	}
	return 0;
}



RC
af_check_validity_of_PKRoot(time, pkroot)
UTCTime *time;
PKRoot *pkroot;
{
	char	*proc = "af_check_validity_of_PKRoot";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif
	if(!pkroot || !pkroot->newkey) {
		aux_add_error(EINVALID, "no PKRoot", (PKRoot *)0, 0, proc);
		return (- 1);
	}

	if (pkroot->newkey->notbefore && pkroot->newkey->notafter) {
		if (aux_interval_UTCTime(time, pkroot->newkey->notbefore, pkroot->newkey->notafter)) {
			aux_add_error(EVALIDITY, "validity check failed", pkroot, PKRoot_n, proc);
			return (- 1);
		}
	}
	return 0;
}



RC
af_check_validity_of_ToBeSigned(time, tbs)
UTCTime * time;
ToBeSigned * tbs;
{
	char	*proc = "af_check_validity_of_ToBeSigned";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(!tbs) {
		aux_add_error(EINVALID, "no TBS", (ToBeSigned *)0, 0, proc);
		return (- 1);
	}
	if (tbs->notbefore && tbs->notafter) {
		if (aux_interval_UTCTime(time, tbs->notbefore, tbs->notafter)) {
			aux_add_error(EVALIDITY, "validity check failed", tbs, ToBeSigned_n, proc);
			return (- 1);
		}
	}
	return 0;
}

/*********************************************************************************************/


FCPath * reduce_FCPath_to_HierarchyPath(fpath)
FCPath * fpath;
{
	SET_OF_Certificate * certset;
	FCPath		   * ret = (FCPath * )0, * tmp_fpath;

	char	           * proc = "reduce_FCPath_to_HierarchyPath";


	if (! fpath){
		aux_add_error(EINVALID, "No fcpath provided", CNULL, 0, proc);
		return((FCPath * )0);
	}

	certset = fpath->liste;
	if(! certset || ! certset->element){
		aux_add_error(EINVALID, "No certificates provided at very first level", CNULL, 0, proc);
		return((FCPath * ) 0);
	}

	if(! own_pkroot){
		own_pkroot = af_pse_get_PKRoot();
		if(! own_pkroot) {
			aux_add_error(EROOTKEY, "Can't get PKRoot", CNULL, 0, proc);
			return((FCPath * )0);
		}
	}

	for (fpath = fpath->next_forwardpath; fpath; fpath = fpath->next_forwardpath){
		if(! fpath->liste || ! fpath->liste->element){
			aux_add_error(EINVALID, "FCPath has level without any certificates", CNULL, 0, proc);
			if(ret) aux_free_FCPath(&ret);
			return ((FCPath * ) 0);
		}
		while (certset && 
	               aux_cmp_DName(certset->element->tbs->issuer, fpath->liste->element->tbs->subject))
		        /* different */
			certset = certset->next;

		if( ! certset){
			aux_add_error(EINVALID, "No hierarchy certificate", CNULL, 0, proc);
			if(ret)
				aux_free_FCPath(&ret);
			return ((FCPath * ) 0);
		}

		if(! ret){
			ret = tmp_fpath = (FCPath * )malloc(sizeof(FCPath));
			if(! ret) {
				aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
				return ((FCPath * ) 0);
			}
			ret->liste = (SET_OF_Certificate * )0;
			ret->next_forwardpath = (FCPath * )0;
		}
		else{
			tmp_fpath->next_forwardpath = (FCPath * )malloc(sizeof(FCPath));
			if(! tmp_fpath->next_forwardpath) {
				aux_add_error(EMALLOC, "tmp_fpath->next_forwardpath", CNULL, 0, proc);
				aux_free_FCPath(&ret);
				return ((FCPath * ) 0);
			}
			tmp_fpath = tmp_fpath->next_forwardpath;
		}

		tmp_fpath->liste = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate));
		if(! tmp_fpath->liste) {
			aux_add_error(EMALLOC, "tmp_fpath->liste", CNULL, 0, proc);
			aux_free_FCPath(&ret);
			return ((FCPath * ) 0);
		}
		tmp_fpath->next_forwardpath = (FCPath * )0;
		tmp_fpath->liste->element = aux_cpy_Certificate(certset->element);
		tmp_fpath->liste->next = (SET_OF_Certificate * )0;
 
		certset = fpath->liste;
	} /* for */
	
	
	/* certset points to the top level of fpath */
	/* check whether fpath terminates at pkroot */

	while (certset && aux_cmp_DName(certset->element->tbs->issuer, own_pkroot->ca))
		certset = certset->next;

	if( ! certset){
		aux_add_error(EINVALID, "No hierarchy certificate", CNULL, 0, proc);
		aux_free_FCPath(&ret);
		return ((FCPath * ) 0);
	}

	if(! ret){  /* fpath contains one level only */
		ret = (FCPath * )malloc(sizeof(FCPath));
		if(! ret) {
			aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
			return ((FCPath * ) 0);
		}
		ret->liste = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate));
		if(! ret->liste) {
			aux_add_error(EMALLOC, "ret->liste", CNULL, 0, proc);
			aux_free_FCPath(&ret);
			return ((FCPath * ) 0);
		}
		ret->next_forwardpath = (FCPath * )0;
		ret->liste->element = aux_cpy_Certificate(certset->element);
		ret->liste->next = (SET_OF_Certificate * )0;

		return(ret);
	}


	tmp_fpath->next_forwardpath = (FCPath * )malloc(sizeof(FCPath));
	if(! tmp_fpath->next_forwardpath) {
		aux_add_error(EMALLOC, "tmp_fpath->next_forwardpath", CNULL, 0, proc);
		aux_free_FCPath(&ret);
		return ((FCPath * ) 0);
	}
	tmp_fpath = tmp_fpath->next_forwardpath;

	tmp_fpath->liste = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate));
	if(! tmp_fpath->liste) {
		aux_add_error(EMALLOC, "tmp_fpath->liste", CNULL, 0, proc);
		aux_free_FCPath(&ret);
		return ((FCPath * ) 0);
	}
	tmp_fpath->next_forwardpath = (FCPath * )0;
	tmp_fpath->liste->element = aux_cpy_Certificate(certset->element);
	tmp_fpath->liste->next = (SET_OF_Certificate * )0;


	return(ret);

}	/* reduce_FCPath_to_HierarchyPath() */


/*********************************************************************************************/


Certificates * transform_reducedFCPath_into_Certificates(fpath)
FCPath * fpath;
{
	/* Each level of fpath contains one certificate only */

	Certificates 	   * certs;
	SET_OF_Certificate * certset;
	FCPath		   * certpath = (FCPath * )0;
	char	           * proc = "transform_FCPath_into_Certificates";
	

	if (! fpath){
		aux_add_error(EINVALID, "no parameter", CNULL, 0, proc);
		return((Certificates * )0);
	}

	certset = fpath->liste;
	if(! certset || ! certset->element){
		aux_add_error(EINVALID, "No certificates provided at very first level", CNULL, 0, proc);
		return((Certificates * ) 0);
	}

	if(certset->next){
		aux_add_error(EINVALID, "More than one certificate at very first level", CNULL, 0, proc);
		return((Certificates * ) 0);
	}

	certs = (Certificates * )malloc(sizeof(Certificates));
	if(! certs) {
		aux_add_error(EMALLOC, "certs", CNULL, 0, proc);
		return ((Certificates * ) 0);
	}

	certs->usercertificate = aux_cpy_Certificate(fpath->liste->element);
	certs->forwardpath = (FCPath * )0;


	for (fpath = fpath->next_forwardpath; fpath; fpath = fpath->next_forwardpath){
		certset = fpath->liste;
		if(! certset || ! certset->element){
			aux_add_error(EINVALID, "FCPath has level without any certificates", CNULL, 0, proc);
			aux_free_Certificates(&certs);
			return((Certificates * ) 0);
		}
	
		if(certset->next){
			aux_add_error(EINVALID, "More than one certificate provided at one level", CNULL, 0, proc);
			aux_free_Certificates(&certs);
			return((Certificates * ) 0);
		}

		if(! certs->forwardpath){
			certs->forwardpath = certpath = (FCPath * )malloc(sizeof(FCPath));
			if(! certs->forwardpath) {
				aux_add_error(EMALLOC, "certs->forwardpath", CNULL, 0, proc);
				aux_free_Certificates(&certs);
				return ((Certificates * ) 0);
			}
			certpath->liste = (SET_OF_Certificate * )0;
			certpath->next_forwardpath = (FCPath * )0;
		}
		else{
			certpath->next_forwardpath = (FCPath * )malloc(sizeof(FCPath));
			if(! certpath->next_forwardpath) {
				aux_add_error(EMALLOC, "certpath->next_forwardpath", CNULL, 0, proc);
				aux_free_Certificates(&certs);
				return ((Certificates * ) 0);
			}
			certpath = certpath->next_forwardpath;
		}

		certpath->liste = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate));
		if(! certpath->liste) {
			aux_add_error(EMALLOC, "certpath->liste", CNULL, 0, proc);
			aux_free_Certificates(&certs);
			return ((Certificates * ) 0);
		}
		certpath->next_forwardpath = (FCPath * )0;
		certpath->liste->element = aux_cpy_Certificate(certset->element);
		certpath->liste->next = (SET_OF_Certificate * )0;
 	} /* for */

	return(certs);

}	/* transform_reducedFCPath_into_Certificates() */


/*********************************************************************************************/


RC af_pse_install_keypair(cert, key, type)
Certificate *cert;
Key *key;
KeyType type;
{
	PSESel        pse_sel;
	OctetString * content;
	ObjId       * obj_type;
	char	    * newobj;
	KeyInfo     * keyinfo;
	Boolean       onekeypaironly = FALSE;

	char	    * proc = "af_pse_install_keypair";


#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != SIGNATURE) && (type != ENCRYPTION)) || !cert || (key->keyref < 0) ) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if ( (type == ENCRYPTION) && 
	     (aux_ObjId2AlgType(cert->tbs->subjectPK->subjectAI->objid) == SIG) ) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (- 1);
	}


	/* define new object */

	if(onekeypaironly == TRUE) newobj = SKnew_name;
	else{
		switch (type) {
		case SIGNATURE:
			newobj = SignSK_name;
			break;
		case ENCRYPTION:
			newobj = DecSKnew_name;
			break;
		}
	}

	if ( (key->keyref == 0) && (key->pse_sel == (PSESel *) 0) ) { /* set up default PSE objects */
		pse_sel.app_name = AF_pse.app_name;
		pse_sel.pin      = AF_pse.pin;
		pse_sel.app_id   = AF_pse.app_id;

		if(onekeypaironly == TRUE){
			pse_sel.object.name = PSE_tmpSK;
			pse_sel.object.pin = AF_pse.pin;
		}
		else{
			switch (type) {
			case SIGNATURE:
				pse_sel.object.name = PSE_tmpSignatureSK;
				pse_sel.object.pin = AF_pse.pin;
				break;
			case ENCRYPTION:
				pse_sel.object.name = PSE_tmpDecryptionSK;
				pse_sel.object.pin = AF_pse.pin;
				break;
			default:
				aux_add_error(EALGID, "Invalid algid", CNULL, 0, proc);
				return - 1;
			}
		}

		key->pse_sel = &pse_sel;
		if (sec_open(&pse_sel) < 0) {
			if (err_stack->e_number != EOBJNAME) {
				aux_add_error(EINVALID, "sec_open failed", key->pse_sel, PSESel_n, proc);
				return - 1;
			}
			/* use real objects */
			pse_sel.object.name = newobj;
		} 
		else sec_close(&pse_sel);
	}

	if ( sec_checkSK(key, cert->tbs->subjectPK) < 0 ) {
		aux_add_error(EINVALID, "sec_checkSK failed", CNULL, 0, proc);
		return - 1;
	}

	/* O.K., key is checked */

	 {
		Certificates    o_cert;

		o_cert.usercertificate = aux_cpy_Certificate(cert);
		o_cert.forwardpath = af_pse_get_FCPath (NULLDNAME);
		aux_free_error();

		if ( af_verify_Certificates (&o_cert, CNULL, (PKRoot *) 0) ) {
			if (o_cert.forwardpath) aux_free_FCPath(&o_cert.forwardpath);
			aux_add_error(EVERIFY, "af_verify_Certificates failed", &o_cert, Certificates_n, proc);
			return - 1;
		}
	}
	/* O.K. certificates valid */

	if (strcmp(key->pse_sel->object.name, newobj)) {	/* only if replacing */
		PSESel	pse_bup;

		pse_bup.app_name = AF_pse.app_name;
		pse_bup.pin = AF_pse.pin;
		pse_bup.app_id = AF_pse.app_id;

		if(onekeypaironly == TRUE){
			pse_bup.object.name = SKold_name;	/* 2 is old key */
			pse_bup.object.pin = getobjectpin(SKold_name);
		}
		else{
			switch (type) {
			case ENCRYPTION:
				pse_bup.object.name = DecSKold_name;	/* 2 is old decryption key */
				pse_bup.object.pin = getobjectpin(DecSKold_name);
				break;
			case SIGNATURE:
				pse_bup.object.name = SignSK_name;	/* 0 is old signature key */
				pse_bup.object.pin = getobjectpin(SignSK_name);
				break;
			}
		}

		/* delete obsolete key */

		sec_delete(&pse_bup);	/* ignore errors, sec_rename() will fail */

		if (onekeypaironly == TRUE) {
			pse_bup.object.name = SKnew_name;	/* 1 is new decryption key */
			pse_bup.object.pin = getobjectpin(SKnew_name);

			if (sec_rename(&pse_bup, SKold_name) < 0) /* will become old one */ {
				aux_add_error(EINVALID, "sec_rename failed", CNULL, 0, proc);
				return - 1;
			}
		}
		else if (type == ENCRYPTION) {
			pse_bup.object.name = DecSKnew_name;	/* 1 is new decryption key */
			pse_bup.object.pin = getobjectpin(DecSKnew_name);

			if (sec_rename(&pse_bup, DecSKold_name) < 0) /* will become old one */ {
				aux_add_error(EINVALID, "sec_rename failed", CNULL, 0, proc);
				return - 1;
			}
		}
	}

	if (key->keyref > 0) {
		if ( sec_get_key(keyinfo, key->keyref, (Key * )0) < 0 ){    /*Memory in keyinfo provided by the called program*/                                  									    							
			aux_add_error(EINVALID, "sec_get_key failed", CNULL, 0, proc);
			return (-1);
		}

		if (sec_del_key(key->keyref) < 0) {
			aux_add_error(EINVALID, "sec_del_key failed", CNULL, 0, proc);
			return (-1);
		}
		pse_sel.app_name = AF_pse.app_name;
		pse_sel.pin = AF_pse.pin;
		pse_sel.app_id = AF_pse.app_id;

		pse_sel.object.name = newobj;
		if (type == SIGNATURE) {
			pse_sel.object.pin = getobjectpin(SignSK_name);
			obj_type = aux_cpy_ObjId(SignSK_OID);
		} 
		else if(type == ENCRYPTION){
			pse_sel.object.pin = getobjectpin(DecSKnew_name);
			obj_type = aux_cpy_ObjId(DecSKnew_OID);
		}
		else{
			pse_sel.object.pin = getobjectpin(SKnew_name);
			obj_type = aux_cpy_ObjId(SKnew_OID);
		}

		if ( !(content = e_KeyInfo(keyinfo)) ) {
			aux_free_ObjId(&obj_type);
			aux_add_error(EENCODE, "e_KeyInfo failed", CNULL, 0, proc);
			return (-1);
		}

		if ( (sec_create(&pse_sel) < 0) || (sec_open(&pse_sel) < 0) ) {
			aux_free_OctetString(&content);
			aux_free_ObjId(&obj_type);
			aux_add_error(EINVALID, "sec_create failed", &pse_sel, PSESel_n, proc);
			return (-1);
		}

		if ( sec_write_PSE(&pse_sel, obj_type, content) < 0 ) {
			aux_free_OctetString(&content);
			aux_free_ObjId(&obj_type);
			aux_add_error(EWRITEPSE, "sec_write_PSE failed", &pse_sel, PSESel_n, proc);
			return (-1);
		}

		if ( sec_close(&pse_sel) < 0 ) {
			aux_free_OctetString(&content);
			aux_free_ObjId(&obj_type);
			aux_add_error(EACCPSE, "sec_close failed", &pse_sel, PSESel_n, proc);
			return (-1);
		}
	} 
	else {	/* real PSE object */
		if (sec_rename(key->pse_sel, newobj) < 0) {
			aux_add_error(EINVALID, "sec_rename failed", CNULL, 0, proc);
			return (-1);
		}
	}


	/* at least store certificate */
	if ( af_pse_update_Certificate(type, cert, TRUE) < 0 ) {
		aux_add_error(EWRITEPSE, "af_pse_update_Certificate failed", cert, Certificate_n, proc);
		return(-1);

	}

	return(0);

}   /*af_pse_install_keypair()*/


/*********************************************************************************************/


CrlPSE * PemCrl2CrlPSE (pemcrl)
PemCrl * pemcrl;
{
	CrlPSE                  * crlpse;
	SEQUENCE_OF_RevCertPem  * revokedCertificates, * seq;
	char	                * proc = "PemCrl2CrlPSE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(! pemcrl){
		aux_add_error(EINVALID, "no parameter", CNULL, 0, proc);
		return ((CrlPSE *)0);
	}

	crlpse = (CrlPSE *)malloc(sizeof(CrlPSE));
	if( !crlpse ) {
		aux_add_error(EMALLOC, "crlpse", CNULL, 0, proc);
		return ((CrlPSE *)0);
	}
	crlpse->issuer = aux_cpy_DName(pemcrl->tbs->issuer);
	crlpse->nextUpdate = aux_cpy_Name(pemcrl->tbs->nextUpdate);
	revokedCertificates = pemcrl->tbs->revokedCertificates;
	if (!revokedCertificates) {
		crlpse->revcerts = (SEQUENCE_OF_RevCertPem *)0;
		return (crlpse);
	}

	crlpse->revcerts = seq = (SEQUENCE_OF_RevCertPem *)malloc(sizeof(SEQUENCE_OF_RevCertPem));
	if( !crlpse->revcerts ) {
		aux_add_error(EMALLOC, "crlpse->revcerts", CNULL, 0, proc);
		aux_free_CrlPSE (&crlpse);
		return ((CrlPSE *)0);
	}

	/* copy first element: */
	crlpse->revcerts->element = aux_cpy_RevCertPem(revokedCertificates->element);
	crlpse->revcerts->next = (SEQUENCE_OF_RevCertPem *)0;
	revokedCertificates = revokedCertificates->next;
	while (revokedCertificates) {
		seq->next = (SEQUENCE_OF_RevCertPem * )malloc(sizeof(SEQUENCE_OF_RevCertPem));
		if(! seq->next) {
			aux_add_error(EMALLOC, "seq->next", CNULL, 0, proc);
			aux_free_CrlPSE (&crlpse);
			return ((CrlPSE *)0);
		}
		seq = seq->next;
		seq->next = (SEQUENCE_OF_RevCertPem * )0;
		seq->element = aux_cpy_RevCertPem(revokedCertificates->element);
		revokedCertificates = revokedCertificates->next;
	}

	return (crlpse);

} 	 /* PemCrl2CrlPSE() */











/*--------------------------------------------------------------------------------------------*/
/*--------------------------- I N T E R N A L    F U N C T I O N S ---------------------------*/
/*--------------------------------------------------------------------------------------------*/


/* stack element definition */
struct PathSTK {
	FCPath         *forwardpath;
	CrossCertificates * crosscertificates;
};


/*********************************************************************************************/


static int	
certselect(cSTK, cx, pathelem, time)
Certificate    *cSTK[];
int	cx;
struct PathSTK *pathelem;
UTCTime        *time;
{
	/* select a certificate from crosscertificates in pathelem
	 * and put it at the end of the stack cSTK.
	 */
	DName             * issuer;
	CrossCertificates * cross;
	char	          * proc = "certselect";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	issuer = cSTK[cx]->tbs->issuer;
	for (cross = pathelem->crosscertificates; 
	    cross; 
	    cross = cross->next
	    ) { /* check subject and validity */
		if (!aux_cmp_DName(issuer, cross->element->tbs->subject) && 
		    !af_check_validity_of_Certificate(time, cross->element))
			break;
	}
	if (cross) {
		pathelem->crosscertificates = cross->next;
		cSTK[++cx] = cross->element;
		return 1;
	}

	pathelem->crosscertificates = (CrossCertificates *) 0;
	return 0;
}


/*********************************************************************************************/


/* -finish cleans up temporary data */
static void
get_path_finish(fstk, cstk, pklist)
struct PathSTK  * fstk;
Certificate    ** cstk;
PKList          * pklist;
{
	char	* proc = "get_path_finish";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (fstk) free(fstk);
	if (cstk) free(cstk);
	if (pklist) aux_free_PKList(&pklist);
	return;
}


/*********************************************************************************************/


    /* get_path returns in certlist the chain of certificates to be verified. Return parameter c 
       indicates the number of certificates in the chain. 

       certlist[0]   is the user certificate.
       certlist[c-1] is the certificate which is to be verified by the top level verification key
		     returned in topkey. 
       topkey        is either pkroot (which in turn is either given to af_verify via parameter pkroot
				       or is taken from PSE object PKRoot) 
		     or a key found in PSE object PKList.
    */



static int	
get_path(orig_cert, rootinfo, time, cSTKp, topkey, topkey_serial, usercert)
Certificates   *orig_cert;
PKRoot         *rootinfo;
UTCTime        *time;
Certificate   **cSTKp[];
KeyInfo        *topkey;
int            *topkey_serial;
Boolean	        usercert;
{
	/*
	 * get path fills the certificate stack with the useable cross
	 * certificates from 'forwardpath' in orig_cert. They are selected
	 * with information from the certificate in orig_cert. If a PKList
	 * exists this information may be used to cut off the path up to an
	 * public key found in that list (may be the public key of the
	 * certificate in orig_cert itself).
	 */

	int	                 i, cindex = 0, cnt;
	FCPath                 * fpath, * path;
	Certificate           ** cSTK;
	Certificate           ** dir_cSTK;  /* stack of certificates retrieved from directory */
	Certificate	       * cert;
	struct PathSTK         * FCstk, * p;
	PKList	               * pklist = (PKList * )0;
	SET_OF_Certificate     * certpath, * certpath_tmp;
	int 		       * level;

	char	               * proc = "get_path";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (cSTKp)  *cSTKp = (Certificate * *) 0;     /* init return value */
	if (!(orig_cert && cSTKp && topkey))  
		return - 1;

	/* Validity time frame of orig_cert->usercertificate has already been checked */

	/* allocate array of cross certificates */
	for (cnt = 0, path = orig_cert->forwardpath; 
	    path; 
	    cnt++, path = path->next_forwardpath
	    ) /* count */;

	cSTK = (Certificate **) calloc(cnt + 2, sizeof(Certificate * )); 
	/* cSTK[0] shall hold usercertificate (+1), cSTK[cnt] shall hold potential cross-certificate (+1) */

	if (! cSTK) {
		aux_add_error(EMALLOC, "cSTK", CNULL, 0, proc);
		return - 1;
	}
	if (cnt > 0) {
		FCstk = (struct PathSTK *) calloc(cnt, sizeof(struct PathSTK ));
		if (!FCstk) {
			free(cSTK);
			aux_add_error(EMALLOC, "FCstk", CNULL, 0, proc);
			return - 1;
		}
	} 
	else FCstk = (struct PathSTK *) 0;

	*cSTKp = cSTK;
	cSTK[0] = orig_cert->usercertificate;
	fpath = orig_cert->forwardpath;

	pklist = af_pse_get_PKList(SIGNATURE);
	if(! pklist)
		aux_free_error();

	/* check first certificate */
	if(usercert == FALSE && af_chk_crl == FALSE){
		/* check if subjectkey may be found in PKList */
		if ( LookupPK(cSTK[0]->tbs->subject, cSTK[0]->tbs->subjectPK, pklist, time) != 0 ) {
			aux_cpy2_KeyInfo(topkey, cSTK[0]->tbs->subjectPK);
			*topkey_serial = cSTK[0]->tbs->serialnumber;
			verifresult->trustedKey = 2;
			verifresult->top_serial = cSTK[0]->tbs->serialnumber;
			verifresult->top_name = aux_DName2Name(cSTK[0]->tbs->issuer);
			get_path_finish(FCstk, cSTK, pklist);
			*cSTKp = (Certificate * *) 0;
			return  0;      /* no certificates to check */
		}
	
		/* check if subjectkey may be found in FCPath */
		if (reduced_fcpath && af_FCPath_is_trusted == TRUE) {
			if ( LookupPK_in_FCPath(cSTK[0]->tbs->subject, cSTK[0]->tbs->subjectPK, reduced_fcpath, time) != 0 ) {
				aux_cpy2_KeyInfo(topkey, cSTK[0]->tbs->subjectPK);
				*topkey_serial = cSTK[0]->tbs->serialnumber;
				verifresult->trustedKey = 3;
				verifresult->top_serial = cSTK[0]->tbs->serialnumber;
				verifresult->top_name = aux_DName2Name(cSTK[0]->tbs->issuer);
				get_path_finish(FCstk, cSTK, pklist);
				*cSTKp = (Certificate * *) 0;
				return  0;      /* no certificates to check */
			}
		}
	} /* if */

	/* check for issuer as Root CA */
	if (aux_cmp_DName(rootinfo->ca, cSTK[0]->tbs->issuer) == 0) { /* issuer is rootCA */
		int	rc = 1;
		if (cSTK[0]->tbs->serialnumber >= rootinfo->newkey->serial) /* newkey */ {
			aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
                        *topkey_serial = rootinfo->newkey->serial;
			verifresult->trustedKey = 0;
			verifresult->top_serial = rootinfo->newkey->serial;
			verifresult->top_name = aux_DName2Name(rootinfo->ca);
		} 
		else if (cSTK[0]->tbs->serialnumber >= rootinfo->oldkey->serial) /* oldkey */ {
			aux_cpy2_KeyInfo(topkey, rootinfo->oldkey->key);
                        *topkey_serial = rootinfo->oldkey->serial;
			verifresult->trustedKey = 1;
			verifresult->top_serial = rootinfo->oldkey->serial;
			verifresult->top_name = aux_DName2Name(rootinfo->ca);
		} 
		else {
			aux_add_error(EROOTKEY, "needs lower serial number", cSTK[0], Certificate_n, proc);
			get_path_finish(FCstk, cSTK, pklist);
			verifresult->trustedKey = - 1;
			return(-1);
		}
		get_path_finish(FCstk, (Certificate **)0, pklist);
		return  rc;
	}

	/* check if issuer of "orig_cert->usercertificate" is cross-certified by own Root CA */
	cert = check_CrossCertificates (rootinfo->ca, cSTK[0]->tbs->issuer);
	if (cert){
		int	rc = 2;
		crosscert_appended_to_certs = TRUE;
		cSTK[1] = aux_cpy_Certificate(cert);
		aux_free_Certificate(&cert);
		aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
		* topkey_serial = rootinfo->newkey->serial;
		get_path_finish(FCstk, (Certificate **)0, pklist);
		verifresult->trustedKey = 0;
		verifresult->top_serial = rootinfo->newkey->serial;
		verifresult->top_name = aux_DName2Name(rootinfo->ca);
		return(rc);
	}

	if((! fpath)){
		if (af_access_directory == TRUE)
			goto establish_certpath_from_directory;
		else {
			aux_add_error(EPATH, "chain of certificates incomplete", CNULL, 0, proc);
			get_path_finish(FCstk, cSTK, pklist);
			return(- 1);
		}
	}

	cindex = 0;
	p = &FCstk[cindex++];
	p->crosscertificates = fpath->liste;
	p->forwardpath = fpath;
	/* scan forwardpath list and set cSTK       */
	while (p->crosscertificates) {
		int	rcselect;

		fpath = fpath->next_forwardpath;

		while ((rcselect = certselect(cSTK, cindex - 1, p, time))) {
			/* check this for issuer root CA
			   or if found in pklist and return
			*/

			if (af_chk_crl == FALSE) {
				/* check if subjectkey is found in PKList */
				if ( LookupPK(cSTK[cindex]->tbs->subject, cSTK[cindex]->tbs->subjectPK, pklist, time) != 0 ) {
					get_path_finish(FCstk, (Certificate **)0, pklist);
					aux_cpy2_KeyInfo(topkey, cSTK[cindex]->tbs->subjectPK);
					*topkey_serial = cSTK[cindex]->tbs->serialnumber;
					verifresult->trustedKey = 2;
					verifresult->top_serial = cSTK[cindex]->tbs->serialnumber;
					verifresult->top_name = aux_DName2Name(cSTK[cindex]->tbs->issuer);
					return  cindex;
				}
	
				/* check if subjectkey is found in FCPath */
				if (reduced_fcpath && af_FCPath_is_trusted == TRUE) {
					if ( LookupPK_in_FCPath(cSTK[cindex]->tbs->subject, cSTK[cindex]->tbs->subjectPK, reduced_fcpath, time) != 0 ) {
						get_path_finish(FCstk, (Certificate **)0, pklist);
						aux_cpy2_KeyInfo(topkey, cSTK[cindex]->tbs->subjectPK);
						*topkey_serial = cSTK[cindex]->tbs->serialnumber;
						verifresult->trustedKey = 3;
						verifresult->top_serial = cSTK[cindex]->tbs->serialnumber;
						verifresult->top_name = aux_DName2Name(cSTK[cindex]->tbs->issuer);
						return  cindex;
					}
				}
			}

			/* check for issuer as rootCA */
			if (aux_cmp_DName(rootinfo->ca, cSTK[cindex]->tbs->issuer) == 0) {
				int	rc = cindex + 1;
				/* issuer is rootCA */
				if (cSTK[cindex]->tbs->serialnumber >= rootinfo->newkey->serial) /* newkey */ {
					aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
                                        *topkey_serial = rootinfo->newkey->serial;
					verifresult->trustedKey = 0;
					verifresult->top_serial = rootinfo->newkey->serial;
					verifresult->top_name = aux_DName2Name(rootinfo->ca);
				} 
				else if (cSTK[cindex]->tbs->serialnumber >= rootinfo->oldkey->serial) /* oldkey */ {
					aux_cpy2_KeyInfo(topkey, rootinfo->oldkey->key);
                                        *topkey_serial = rootinfo->oldkey->serial;
					verifresult->trustedKey = 1;
					verifresult->top_serial = rootinfo->oldkey->serial;
					verifresult->top_name = aux_DName2Name(rootinfo->ca);
				} 
				else {
					aux_add_error(EROOTKEY, "needs lower serial number", cSTK[cindex], Certificate_n, proc);
					get_path_finish(FCstk, cSTK, pklist);
					verifresult->trustedKey = - 1;
					return(-1);
				}
				get_path_finish(FCstk, (Certificate **)0, pklist);
				return(rc);
			}

			/* check if issuer of cert is cross-certified by own Root CA */
			cert = check_CrossCertificates (rootinfo->ca, cSTK[cindex]->tbs->issuer);
			if (cert){
				int	rc = cindex + 2;
				crosscert_appended_to_certs = TRUE;
				cSTK[cindex + 1] = aux_cpy_Certificate(cert);
				aux_free_Certificate(&cert);
				aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
				* topkey_serial = rootinfo->newkey->serial;
				get_path_finish(FCstk, (Certificate **)0, pklist);
				verifresult->trustedKey = 0;
				verifresult->top_serial = rootinfo->newkey->serial;
				verifresult->top_name = aux_DName2Name(rootinfo->ca);
				return(rc);
			}

			/* try next certificate of this level, if at top */
			if (fpath) break;
		}

		if (rcselect) {	/* got one certificate */
			p = &FCstk[cindex++];
			p->crosscertificates = fpath->liste;
			p->forwardpath = fpath;
		} 
		else if (cindex > 0) {	/* try backtrack */
			cSTK[cindex] = (Certificate *) 0;
			p = &FCstk[--cindex];
			fpath = p->forwardpath;	/* restore to next level below */
		}
		else break;
	}

	if(af_access_directory == FALSE){
		aux_add_error(EPATH, "chain of certificates incomplete", cSTK[cindex], Certificate_n, proc);
		get_path_finish(FCstk, cSTK, pklist);
		return - 1;
	}



establish_certpath_from_directory:

	/* Access a directory in order to complete originator's certification path ... */
	/* cindex = 0 */

	certs_from_directory = TRUE;

	certpath = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate ) );
	if (!certpath) {
		aux_add_error(EMALLOC, "certpath", CNULL, 0, proc);
		return (- 1);
	}
	certpath->element = aux_cpy_Certificate(orig_cert->usercertificate);
	certpath->next = (SET_OF_Certificate *)0;

	level = (int * )malloc(sizeof(int));
	if ( ! level ) {
		aux_add_error(EMALLOC, "level", CNULL, 0, proc);
		return (- 1);
	}
	*level = 0;

	if(complete_FCPath_from_Directory(orig_cert->usercertificate, certpath, level, topkey, topkey_serial, pklist, rootinfo, time)){
		/* Directory access failed */
		aux_add_error(EPATH, "Creation of certification path using X.500 or .af-db directory failed", CNULL, 0, proc);
		return(- 1);
	}

	/* The originator's certification path was successfully established from the directory */

	dir_cSTK = (Certificate **) calloc(*level, sizeof(Certificate * ));
	if (!dir_cSTK) {
		aux_add_error(EMALLOC, "dir_cSTK", CNULL, 0, proc);
		return(- 1);
	}

	*cSTKp = dir_cSTK;
	dir_cSTK[0] = aux_cpy_Certificate(orig_cert->usercertificate);
	for(i = 1, certpath_tmp = certpath->next; (i <= *level) && certpath_tmp; i ++, certpath_tmp = certpath_tmp->next)
		dir_cSTK[i] = aux_cpy_Certificate(certpath_tmp->element);
	aux_free_CertificateSet(&certpath);
	cindex = *level;
	free (level);

	get_path_finish(FCstk, cSTK, pklist);

	if(* level == 0) {
		aux_add_error(EPATH, "Creation of certification path using X.500 or .af-db directory failed", CNULL, 0, proc);
		return (- 1);
	}

	return(cindex);

}	/* get_path() */


/*********************************************************************************************/


static KeyInfo*
LookupPK(name, namePK, pklist, time)
DName          * name;
KeyInfo        * namePK;
PKList         * pklist;
UTCTime        * time;
{
	char   * proc = "LookupPK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! name)
		return ( (KeyInfo * ) 0);

	for (; pklist; pklist = pklist->next) {
		if (aux_cmp_DName(name, pklist->element->subject) == 0 && 
		    ! aux_cmp_KeyInfo(namePK, pklist->element->subjectPK)) {
			if (! af_check_validity_of_ToBeSigned(time, pklist->element))
				return (pklist->element->subjectPK);
		}
	}

	return ( (KeyInfo * ) 0);

}	/* LookupPK() */


/*********************************************************************************************/


static KeyInfo*
LookupPK_in_FCPath(name, namePK, fcpath, time)
DName          * name;
KeyInfo        * namePK;
FCPath         * fcpath;
UTCTime        * time;
{
	SET_OF_Certificate * set;
	char   		   * proc = "LookupPK_in_FCPath";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! name)
		return ( (KeyInfo * ) 0);

	for (; fcpath; fcpath = fcpath->next_forwardpath) {
		set = fcpath->liste;
		for (; set; set = set->next) {
			if (aux_cmp_DName(name, set->element->tbs->subject) == 0 && 
			    ! aux_cmp_KeyInfo(namePK, set->element->tbs->subjectPK)) {
				if (! af_check_validity_of_Certificate(time, set->element))
					return (set->element->tbs->subjectPK);
			}
		} /* for */
	} /* for */

	return ( (KeyInfo * ) 0);

}	/* LookupPK_in_FCPath() */


/*********************************************************************************************/


static UTCTime *
check_black_list(cert, time)
Certificate *cert;
UTCTime *time;
{
        CrlSet                  * crlset;
	PemCrl                  * pemcrl = (PemCrl * )0;
	CrlPSE                  * crlpse;
	Boolean 	          update = FALSE, found = FALSE, tried = FALSE;
	SEQUENCE_OF_RevCertPem  * revokedCertificates;
	HashInput               * hashin = (HashInput * ) 0;         /* hash input in case of sqmodn */
	Key                       key;                               /* the public key */
	KeyType         	  ktype = SIGNATURE;
	AlgHash                   alghash;
	SEQUENCE_OF_RevCertPem	* revcerts;
	ToBeSigned 	        * tbs;
        SET_OF_Certificate      * certset;
        int		          algtype;
	int 		          rcode = - 1, rc;
	char			  x500 = TRUE;
#ifdef AFDBFILE
	char			  afdb[256];
#endif
	char	                * proc = "check_black_list";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif
	
	
	if (! cert) {
		aux_add_error(EINVALID, "No certificate to check against black list", CNULL, 0, proc);
		return ((UTCTime * )0);
	}
 
#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

	crlset = af_pse_get_CrlSet();

	while ( crlset && (found == FALSE) ) {
		if (aux_cmp_DName(cert->tbs->issuer, crlset->element->issuer) == 0) {
		        /* issuer's revocation list stored locally */
			if (aux_cmp_UTCTime(time, crlset->element->nextUpdate) != 2) {
				/* revocation list stored in PSE is obsolete */
				aux_add_error(EVALIDITY, "Locally stored revocation list is out-of-date", CNULL, 0, proc);
				update = TRUE;
				break;
			}
			else {
				revcerts = crlset->element->revcerts;
				while (revcerts) {
					if (revcerts->element &&
					    (cert->tbs->serialnumber == revcerts->element->serialnumber)) {
						found = TRUE;
						break;
					}
					revcerts = revcerts->next;
				}
				if (! revcerts)    /* cert NOT contained in revocation list */
					return ((UTCTime * )0);
			} 
		}
		if (found == TRUE)
			break;
		crlset = crlset->next;
	} /* while */

	if (found == TRUE) {
		aux_add_error(EREVOKE, "Certificate has been revoked", cert, Certificate_n, proc);
		return (revcerts->element->revocationDate);
	}

	if(af_access_directory == FALSE){
		if(err_stack->e_number == EVALIDITY) 
			return(crlset->element->nextUpdate);
		aux_add_error(EAVAILABLE, "Revocation List is unavailable", CNULL, 0, proc);
		return ((UTCTime * )0);
	}


	/* Access Directory (X.500 or .af-db) */

	/* The following is valid: !crlset || (update == TRUE). In other words:
	 * Retrieve revocation list of cert->tbs->issuer from directory, as 
	 * 1. there is no revocation list of that issuer stored in the PSE, or 
	 * 2. the revocation list of that issuer stored in the PSE is out-of-date. */

	pemcrl = (PemCrl * ) 0;

#ifdef X500
	if (x500 && af_access_directory == TRUE) 
		pemcrl = af_dir_retrieve_PemCrl(cert->tbs->issuer);
#endif
#ifdef AFDBFILE
	if ( (!x500 || !af_x500) && af_access_directory == TRUE) 
		pemcrl = af_afdb_retrieve_PemCrl(cert->tbs->issuer);
#endif

	if (!pemcrl) {
		aux_add_error(EAVAILABLE, 
		"Revocation List is unavailable", CNULL, 0, proc);
		return ((UTCTime * )0);
	}

	/* Verifying the returned revocation list */
	if ( !(tbs = af_pse_get_TBS(SIGNATURE, cert->tbs->issuer, NULLDNAME, 0)) ) {

		certset = (SET_OF_Certificate * )0;

#ifdef X500
		if ( x500 && af_access_directory == TRUE && 
		     !(certset = af_dir_retrieve_Certificate(cert->tbs->issuer,cACertificate)) ) {
			aux_add_error(EVERIFICATION, 
			"Can't find public verification key of issuer", CNULL, 0, proc);
			aux_free_PemCrl (&pemcrl);
			return ((UTCTime * )0);
		}
#endif
#ifdef AFDBFILE
		if ( (!x500 || !af_x500) && af_access_directory == TRUE && 
		     !(certset = af_afdb_retrieve_Certificate(cert->tbs->issuer,ktype)) ) {
			aux_add_error(EVERIFICATION, 
			"Can't find public verification key of issuer", CNULL, 0, proc);
			aux_free_PemCrl (&pemcrl);
			return ((UTCTime * )0);
		}
#endif
	}

        key.keyref = 0;
        key.pse_sel = (PSESel *) 0;

	if (tbs){
		key.key = tbs->subjectPK;
        	alghash = aux_ObjId2AlgHash(pemcrl->sig->signAI->objid);
		if (alghash == SQMODN) hashin = (HashInput * ) & key.key->subjectkey;
		else hashin = (HashInput * ) 0;

		rcode = sec_verify(pemcrl->tbs_DERcode, pemcrl->sig, END, &key, hashin);
	}
	else{		
		while (certset) {
			/* compare, if ENCRYPTION or SIGNATURE object identifier: */
			algtype = aux_ObjId2AlgType(certset->element->tbs->subjectPK->subjectAI->objid);
			if ((algtype != SIG) && (algtype != ASYM_ENC)) certset = certset->next;
			else{
        			/* needs HashInput parameter set */
				tried = TRUE;
				key.key = certset->element->tbs->subjectPK;
        			alghash = aux_ObjId2AlgHash(pemcrl->sig->signAI->objid);
				if (alghash == SQMODN) hashin = (HashInput * ) & key.key->subjectkey;
				else hashin = (HashInput * ) 0;

				rcode = sec_verify(pemcrl->tbs_DERcode, pemcrl->sig, END, &key, hashin);
				if(rcode != 0) 
					certset = certset->next; /* Try verification by applying next certificate in set */
				else break;
			}
		} /* while */
		if (! certset && ! tried) {
			aux_add_error(EVERIFICATION, 
			"No SIGNATURE certificate in directory entry of issuer", CNULL, 0, proc);
			aux_free_PemCrl (&pemcrl);
			return ((UTCTime * )0);
		}
	}

	/* Verification of revocation list FAILED */

	if (rcode != 0) { 
		aux_add_error(EVERIFICATION, "Verification of revocation list failed", CNULL, 0, proc);
		aux_free_PemCrl (&pemcrl);
		return((UTCTime * )0);
	}


	/* Verification of revocation list SUCCEEDED */

	/* Revocation list has been verified, check if it is out-of-date: */
	rc = aux_cmp_UTCTime(time, pemcrl->tbs->nextUpdate);
	if(rc != 2){  /*obsolete*/
		aux_add_error(EVALIDITY, "Revocation list returned from directory is out-of-date", CNULL, 0, proc);
		aux_free_PemCrl (&pemcrl);
		return (pemcrl->tbs->nextUpdate);
	}

	/* Update of PSE object CrlSet */
	crlpse = PemCrl2CrlPSE(pemcrl);
	rcode = af_pse_add_PemCRL(crlpse);
	aux_free_CrlPSE (&crlpse);
	if (rcode != 0)
		aux_add_error(ECREATEOBJ, "Cannot update PSE object CrlSet", CNULL, 0, proc);

	revokedCertificates = pemcrl->tbs->revokedCertificates;
	while (revokedCertificates) {
		if (cert->tbs->serialnumber == revokedCertificates->element->serialnumber) {
			found = TRUE;
			break;
		}
		revokedCertificates = revokedCertificates->next;
	}

	if (found == TRUE) {   /* cert found in revocation list */
		aux_add_error(EREVOKE, "Certificate has been revoked", cert, Certificate_n, proc);
		aux_free_PemCrl(&pemcrl);
		return (revokedCertificates->element->revocationDate);
	}

	aux_free_PemCrl(&pemcrl);

	return ((UTCTime * )0);

} 	/* check_black_list() */


/*********************************************************************************************/


static
Certificate  * check_CrossCertificates (own_root, foreign_root)
DName * own_root;
DName * foreign_root;
{
	SET_OF_CertificatePair * cpairset, * local_cpairset, * tmp;
	Certificate	       * ret;
	char 			 x500 = TRUE;
#ifdef AFDBFILE
	char			 afdb[256];
#endif
	char                   * proc = "check_CrossCertificates";

#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

	local_cpairset = tmp = af_pse_get_CertificatePairSet();

	if(local_cpairset){
		while (tmp) {
			if ( ! aux_cmp_DName (foreign_root, tmp->element->reverse->tbs->subject) ) {
				ret = aux_cpy_Certificate(tmp->element->reverse);
				aux_free_CertificatePairSet(& local_cpairset);
				crosscert_from_Directory = FALSE;
				return (ret);
			}
			tmp = tmp->next;
		}
		aux_free_CertificatePairSet(& local_cpairset);
	}

	if (af_access_directory == FALSE)
		return ( (Certificate *) 0);
   
	/* no set of cross certificate pairs locally stored, or required cross certificate pair not found */
	/* within set of locally stored cross certificate pairs						  */

	cpairset = (SET_OF_CertificatePair * )0;

#ifdef X500
	if (x500 && af_access_directory == TRUE) 
		cpairset = tmp = af_dir_retrieve_CertificatePair(own_root);
#endif
#ifdef AFDBFILE
	if ( (!x500 || !af_x500) && af_access_directory == TRUE) 
		cpairset = tmp = af_afdb_retrieve_CertificatePair(own_root);
#endif

	if (! cpairset) {
		aux_add_error(err_stack->e_number, "No cross certificates returned from directory", CNULL, 0, proc);
		return ( (Certificate *)0 );
	}

	while (tmp) {
		if ( ! aux_cmp_DName (foreign_root, tmp->element->reverse->tbs->subject) ) {
			ret = aux_cpy_Certificate(tmp->element->reverse);
			if ( af_pse_update_CertificatePairSet(cpairset) < 0 ) {
				aux_add_error(EWRITEPSE, "af_pse_update_CertificatePairSet failed", cpairset, SET_OF_CertificatePair_n, proc);
				aux_free_CertificatePairSet(&cpairset);
				return ( (Certificate *) 0);
			}
			aux_free_CertificatePairSet(&cpairset);
			return (ret);
		}
		tmp = tmp->next;
	}

	if ( af_pse_update_CertificatePairSet(cpairset) < 0 ) {
		aux_add_error(EWRITEPSE, "af_pse_update_CertificatePairSet failed", cpairset, SET_OF_CertificatePair_n, proc);
		aux_free_CertificatePairSet(&cpairset);
		return ( (Certificate *) 0);
	}

	aux_free_CertificatePairSet(&cpairset);
	return ( (Certificate *) 0);

}	/* check_CrossCertificates() */


/*********************************************************************************************/


static
RC complete_FCPath_from_Directory(tobeverified_cert, certpath, level, topkey, topkey_serial, pklist, rootinfo, time)
Certificate 		* tobeverified_cert;
SET_OF_Certificate 	* certpath; /* certification path to be established by accessing the directory */
int 			* level;    /* indicates how many levels the certification path comprises */
KeyInfo 		* topkey;
int 			* topkey_serial;
PKList 			* pklist;
PKRoot 			* rootinfo;
UTCTime 		* time;
{
	SET_OF_Certificate * certset;
	HashInput          * hashin = (HashInput * ) 0;         /* hash input in case of sqmodn */
	Key    	             key;                               /* the public key */
	AlgHash              alghash;
	Name               * printrepr;
	Certificate	   * cross_cert;
	char 	             x500 = TRUE;
#ifdef AFDBFILE
	char	             afdb[256];
#endif

	char	           * proc = "complete_FCPath_from_Directory";

#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

	if(! tobeverified_cert || ! certpath || ! level || ! topkey_serial){
		aux_add_error(EINVALID, "no parameter", CNULL, 0, proc);
		return(- 1);
	}

	certset = (SET_OF_Certificate * )0;

#ifdef X500
	if (x500 && af_access_directory == TRUE) 
		certset = af_dir_retrieve_Certificate(tobeverified_cert->tbs->issuer, cACertificate);
#endif
#ifdef AFDBFILE
	if ((!x500 || !af_x500) && af_access_directory == TRUE) 
		certset = af_afdb_retrieve_Certificate(tobeverified_cert->tbs->issuer, SIGNATURE);
#endif

	if(! certset){
		aux_add_error(err_stack->e_number, "No set of certificates returned from directory", CNULL, 0, proc);
		return(- 1);
	}

	while(certset){

		if (af_check_validity_of_Certificate(time, certset->element)) {
			certset = certset->next;
			continue;	
		}

		key.key = certset->element->tbs->subjectPK;    /* verification key of next level */
		key.keyref = 0;
        	key.pse_sel = (PSESel *) 0;

		/* needs HashInput parameter set */
		alghash = aux_ObjId2AlgHash(tobeverified_cert->sig->signAI->objid);
		if (alghash == SQMODN) hashin = (HashInput * ) & key.key->subjectkey;
		else hashin = (HashInput * ) 0;

		if (sec_verify(tobeverified_cert->tbs_DERcode, tobeverified_cert->sig, END, &key, hashin) < 0) {
			aux_add_error(EVERIFICATION, "Verification of certificate failed", tobeverified_cert, Certificate_n, proc);
			certset = certset->next; /* Try to verify "tobeverified_cert" with the help of the next cert within set */
		}
		else{
			/* Verification  S U C C E S S F U L */

			if (af_chk_crl == FALSE) {
				/* check if subjectkey is contained in PKList */
				if ( LookupPK(certset->element->tbs->subject, certset->element->tbs->subjectPK, pklist, time) != 0 ) {
					aux_cpy2_KeyInfo(topkey, certset->element->tbs->subjectPK);
					*topkey_serial = certset->element->tbs->serialnumber;
					verifresult->trustedKey = 2;
					verifresult->top_serial = certset->element->tbs->serialnumber;
					verifresult->top_name = aux_DName2Name(certset->element->tbs->issuer);
					return(0);
				}
	
				/* check if subjectkey is found in own FCPath */
				if (reduced_fcpath && af_FCPath_is_trusted == TRUE) {
					if ( LookupPK_in_FCPath(certset->element->tbs->subject, certset->element->tbs->subjectPK, reduced_fcpath, time) != 0 ) {
						aux_cpy2_KeyInfo(topkey, certset->element->tbs->subjectPK);
						*topkey_serial = certset->element->tbs->serialnumber;
						verifresult->trustedKey = 3;
						verifresult->top_serial = certset->element->tbs->serialnumber;
						verifresult->top_name = aux_DName2Name(certset->element->tbs->issuer);
						return(0);
					}
				}
			} /* if */

			/* check for issuer as rootCA */
			if (aux_cmp_DName(rootinfo->ca, certset->element->tbs->issuer) == 0) {
				/* issuer is rootCA */
				certpath->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate ) );
				if (!certpath->next) {
					aux_add_error(EMALLOC, "certpath->next", CNULL, 0, proc);
					return (- 1);
				}
				certpath = certpath->next;
				certpath->element = aux_cpy_Certificate(certset->element);
				certpath->next = (SET_OF_Certificate *)0;
				(*level) ++;

				if (certset->element->tbs->serialnumber >= rootinfo->newkey->serial) /* newkey */ {
					aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
                                        * topkey_serial = rootinfo->newkey->serial;
					(*level) ++;  /* for Root key */
					verifresult->trustedKey = 0;
					verifresult->top_serial = rootinfo->newkey->serial;
					verifresult->top_name = aux_DName2Name(rootinfo->ca);
					return(0);
				} 
				else if (certset->element->tbs->serialnumber >= rootinfo->oldkey->serial) /* oldkey */ {
					aux_cpy2_KeyInfo(topkey, rootinfo->oldkey->key);
                                        * topkey_serial = rootinfo->oldkey->serial;
					(*level) ++;  /* for Root key */
					verifresult->trustedKey = 1;
					verifresult->top_serial = rootinfo->oldkey->serial;
					verifresult->top_name = aux_DName2Name(rootinfo->ca);
					return(0);
				} 

				aux_add_error(EROOTKEY, "needs lower serial number", certset->element, Certificate_n, proc);
				verifresult->trustedKey = - 1;
				return(- 1);
			}

			/* check if issuer is cross-certified by own Root CA */

			cross_cert = check_CrossCertificates (rootinfo->ca, certset->element->tbs->issuer);
			if (cross_cert){
				crosscert_appended_to_certs = TRUE;
				certpath->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate ) );
				if (!certpath->next) {
					aux_add_error(EMALLOC, "certpath->next", CNULL, 0, proc);
					return (- 1);
				}
				certpath = certpath->next;
				certpath->element = aux_cpy_Certificate(certset->element);
				certpath->next = (SET_OF_Certificate *)0;
				(*level) ++;

				aux_cpy2_KeyInfo(topkey, rootinfo->newkey->key);
                		* topkey_serial = rootinfo->newkey->serial;
				certpath->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate ) );
				if (!certpath->next) {
					aux_add_error(EMALLOC, "certpath->next", CNULL, 0, proc);
					return (- 1);
				}
				certpath = certpath->next;
				certpath->element = aux_cpy_Certificate(cross_cert);
				aux_free_Certificate(&cross_cert);
				certpath->next = (SET_OF_Certificate *)0;
				(*level) += 2;
				verifresult->trustedKey = 0;
				verifresult->top_serial = rootinfo->newkey->serial;
				verifresult->top_name = aux_DName2Name(rootinfo->ca);
				return(0);
			}

			/* Neither subjectkey was found in PKList nor does the issuer correspond to the own rootCA nor  */
			/* has the issuer been cross-certified by the own rootCA. 					*/
			/* Therefore, keep on accessing the directory ... */

			if(! complete_FCPath_from_Directory(certset->element, certpath, level, topkey, topkey_serial, pklist, rootinfo, time))  /* ok */
				return(0);
			aux_free_CertificateSet(&certpath->next);
			certpath->next = (SET_OF_Certificate *)0;
			(*level) --;
		}

	}  /* while */

	return(- 1);

}	/* complete_FCPath_from_Directory() */


/*********************************************************************************************/


static
int certs_at_one_level(path)
FCPath * path;
{
	SET_OF_Certificate * certset;
	int		     count;

	if (! path || ! path->liste)
		return(0);

	for (certset = path->liste, count = 0; certset; certset = certset->next, count++)
		/* count */;
		
	return(count);
}


/*********************************************************************************************/


static
int verify_CertificateWithPkroot(cert, pkroot)
Certificate * cert;
PKRoot * pkroot;
{
	HashInput     * hashin = (HashInput * ) 0;         /* hash input in case of sqmodn */
	Key    	        key;                               /* the public key */
	AlgHash         alghash;
	int		rc;

	char	      * proc = "verify_CertificateWithPkroot";


	if (cert->tbs->serialnumber >= pkroot->newkey->serial) /* newkey */
		key.key = pkroot->newkey->key;
	else if (cert->tbs->serialnumber >= pkroot->oldkey->serial) /* oldkey */
		key.key = pkroot->oldkey->key;
	else {
		aux_add_error(EROOTKEY, "needs lower serial number", cert, Certificate_n, proc);
		return(-1);
	}

	key.keyref = 0;
	key.pse_sel = (PSESel *) 0;

	/* needs HashInput parameter set */
	alghash = aux_ObjId2AlgHash(cert->sig->signAI->objid);
	if (alghash == SQMODN) 
		hashin = (HashInput * ) & key.key->subjectkey;
	else 
		hashin = (HashInput * ) 0;

	rc = sec_verify(cert->tbs_DERcode, cert->sig, END, &key, hashin);

	return(rc);

}
