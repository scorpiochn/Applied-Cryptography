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

/*-----------------------pem-crea.c---------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/* 	Grimm/Nausester/Schneider/Viebeg/Vollmer/                   */
/* 	Surkau/Reichelt/Kolletzki                     et alii       */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   pem             VERSION   3.0                          */
/*                              DATE   06.02.1992                   */
/*                                BY   Surkau/Grimm                 */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*------------------------------------------------------------------*/

#include "pem.h"
#include "cadb.h"
#include <stdio.h>

extern OctetString   *aux_create_OctetString(), *aux_64(), *aux_encrfc() ,
*aux_decrfc(), *aux_ostr_get64() , *aux_enchex(),
*aux_dechex(), *aux_canon();
extern char	*aux_ObjId2Name();
extern ObjId   *aux_Name2ObjId();


/************************************************************************/
/*      pem_cinfo                                                       */
/************************************************************************/
RC pem_cinfo( info )
PemInfo    *info;
{
	int	n, ec;
	AlgId         * algid, *algid2;
	Certificate   * dircert;
	RecpList      * recp, *recpold;
	EncryptedKey   encrypted_key;
	KeyInfo       * keyinfo;
	Key            encryption_key;
	char *proc = "pem_cinfo";


/* check parameters */
	if ( !info ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}

	/*-----step 1   origcert-------------------------------------------------*/
	if ( !info->origcert )
		if ( !(info->origcert = af_pse_get_Certificates(SIGNATURE, NULL)) ) {
			aux_add_error(EINVALID, "af_pse_get_Certificates failed", 0, 0, proc);
			return( -1 );
		}

	/*-----step 2   signAI---------------------------------------------------*/
	if ( !info->signAI ) {
		if (!(info->signAI =aux_cpy_AlgId(
		  info->origcert->usercertificate->tbs->subjectPK->subjectAI)) ) {
			aux_add_error(EINVALID, "aux_cpy_AlgId failed", 0, 0, proc);
			return( -1 );
		}

	}

	if ( !info->confidential ) {
		/* MIC-ONLY or MIC-clear: */
		info->encryptKEY = (Key * )0;
		/* Ignore info->recplist */
		return (0);
	}

	/*-- steps 3-5 only for encryption -------------------------------------*/

	/*-----step 3 DES_key---------------------------------------------------*/
	info->encryptKEY = (Key * )malloc(sizeof(Key));

	info->encryptKEY->key = (KeyInfo * )malloc(sizeof(KeyInfo));

	if ( !(info->encryptKEY->key->subjectAI = aux_Name2AlgId(MSG_ENC_ALG)) ) {
		aux_add_error(EINVALID, "aux_cpy_AlgId failed", 0, 0, proc);
		return( -1 );
	}

	info->encryptKEY->keyref = 0;
	info->encryptKEY->pse_sel = (PSESel * )0;
	info->encryptKEY->alg = (AlgId * )0;

	/* place generated DES-key into encryptKEY->key: */
	if (( ec = sec_gen_key(info->encryptKEY, TRUE))) {
		aux_add_error(EINVALID, "sec_gen_key failed for DES key", 0, 0, proc);
		return( -1 );
	}


        /* random initial vector for the DEK */
        info->encryptKEY->key->subjectAI->parm = (char *)sec_random_ostr(8);

	/*-----step 4   recplist-------------------------------------------------*/
	recpold = recp = info->recplist;
	while (recp) {
		if(recp->recpcert && recp->recpcert->tbs) {
			/*-----------------------get user subjectPK-------------------------------------*/
			if(!(dircert = af_search_Certificate(ENCRYPTION, recp->recpcert->tbs->subject))) {
				if(recp == info->recplist) info->recplist = recp->next;
				else recpold->next = recp->next;
				aux_add_error(EENCRBODY, "af_search_Certificate failed", 0, 0, proc);
			} else {
				/*-----step 5 encrypt DES_key-------------------------------------------*/

				recp->recpcert->tbs = dircert->tbs;
				free(dircert);
				aux_free_AlgId(&recp->recpcert->tbs->subjectPK->subjectAI);
				recp->recpcert->tbs->subjectPK->subjectAI = aux_Name2AlgId(DEK_ENC_ALG);
				encryption_key.key = recp->recpcert->tbs->subjectPK;
				encryption_key.keyref = 0;
				encryption_key.alg = aux_Name2AlgId(DEK_ENC_ALG);
				encryption_key.pse_sel = (PSESel * )0;
				if ((ec = af_get_EncryptedKey(&encrypted_key, info->encryptKEY, &encryption_key, (char *)0, 
										recp->recpcert->tbs->subjectPK->subjectAI))) {
					aux_add_error(EINVALID, "af_get_EncryptedKey failed", 0, 0, proc);
					return( -1 );
				}

					    
				recp->key = (OctetString * )malloc(sizeof(OctetString));

				recp->key->noctets = encrypted_key.subjectkey.nbits / 8;
				recp->key->octets  = (char *)malloc(recp->key->noctets);

				for ( n = 0; n < recp->key->noctets; n++) {
					recp->key->octets[n] = encrypted_key.subjectkey.bits[n];
				}
			}
		}
		recpold = recp;
		recp = recp->next;
	} /*end while over recp*/

	return( 0 );
}


/************************************************************************/
/*      pem_chd                                                         */
/*                                                                      */
/*      appends header field no. "xid" to "msgbuf"                      */
/************************************************************************/
RC pem_chd( msgbuf , xid )
OctetString         *msgbuf;
int	xid;
{
	int	ec;
	char *proc = "pem_chd";


	for(ec = 0; rXH_kwl[ec].name; ec++);

	if ((xid < 0) || ( xid >= ec )) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}


	if (( ec = aux_append_char( msgbuf , rXH_kwl[xid].name )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}



	if (( ec = aux_append_char( msgbuf , ": " )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	return( 0 );
}


/************************************************************************/
/*      pem_cend                                                        */
/************************************************************************/
RC pem_cend( msgbuf )
OctetString           *msgbuf;
{
	int	ec;
	char *proc = "pem_cend";


	if (( ec = aux_append_char( msgbuf , PEM_Boundary_End )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , "\n" ) )) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	return (ec);
}


/************************************************************************/
/*      pem_cinit                                                       */
/************************************************************************/
RC pem_cinit( msgbuf , confidential , clear, crl )
OctetString           *msgbuf;
Boolean               confidential, clear;
PEM_CRL_Mode		crl;
{
	int	ec;
	char *proc = "pem_cinit";
	char *type;


	if ( !msgbuf ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}


	msgbuf->noctets = 0;           /* initialisieren */
	msgbuf->octets = NULL;

	if (( ec = aux_append_char( msgbuf , PEM_Boundary_Begin )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , "\n" )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = pem_chd( msgbuf , PEM_PROC_TYPE )) ) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , "4," )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if ( crl ) type = ( crl == CRL_MESSAGE ) ? "CRL\n" : "CRL-RETRIEVAL-REQUEST\n";
	else
	if ( confidential ) type = "ENCRYPTED\n";
	else type = ( clear ) ? "MIC-CLEAR\n" : "MIC-ONLY";


	if (( ec = aux_append_char( msgbuf , type )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	return( 0 );
}

/************************************************************************/
/*      pem_ccd                                                         */
/************************************************************************/
RC pem_ccd( msgbuf , cd )
OctetString		*msgbuf;
PEM_Content_Domains	cd;
{
	int	ec;
	char *proc = "pem_ccd";


	if ( !msgbuf ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}

	if (( ec = pem_chd( msgbuf , PEM_CONTENT_DOMAIN )) ) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , content_domain[cd].name )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , "\n" )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}
	pem_content_domain = cd;

	return( 0 );
}


/************************************************************************/
/*      pem_cdek                                                        */
/************************************************************************/
RC pem_cdek( msgbuf , algid )
OctetString           *msgbuf;
AlgId                 *algid;
{
	OctetString       dp;
	int	ec;
	unsigned int	*elem;
	char	*oiname;
	ObjId       * oid;
	char *proc = "pem_cdek";


	if ( !algid ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}

	if (( ec = pem_chd( msgbuf , PEM_DEK_INFO )) ) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}



	/*--algorithm----------------------------------------------------------*/
	oid = algid->objid;
	if ( !(oiname = aux_ObjId2Name( oid )) ) {
		aux_add_error(EINVALID, "aux_ObjId2Name failed", algid, AlgId_n, proc);
		return( -1 );
	}


	if (( ec = aux_append_char( msgbuf , oiname )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if (( ec = aux_append_char( msgbuf , "," )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	/*--desCBC_parm--------------------------------------------------------------------*/

	/* add DES initialization vector in hexa code*/
	if ( (!algid->parm) || 
	    (((desCBC_pad_parm_type * )(algid->parm))->noctets == 0) ) {
		dp.noctets = 8;
		dp.octets  = "\0\0\0\0\0\0\0\0";
	} else {
		dp.noctets = ((desCBC_parm_type * )(algid->parm))->noctets;
		dp.octets  = ((desCBC_parm_type * )(algid->parm))->octets ;
	}
	if (( ec = aux_hex_append( msgbuf, &dp )) ) {
		aux_add_error(EINVALID, "aux_hex_append failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_char( msgbuf , "\n" )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}

	return( 0 );
}


/************************************************************************/
/*      pem_crec                                                        */
/************************************************************************/
RC pem_crec( msgbuf , recplist )
OctetString               *msgbuf;
RecpList                  *recplist;
{
	int	ec;
	char	*out;
	char	*oiname;
	char	sernr[9];
	ObjId           * oid;
	OctetString           *bst, *encoded, *blank, *printable, *u64bst;
	Name *printrepr;
	char *proc = "pem_crec";


	while (recplist) {
		if ( !recplist->recpcert ) {
			aux_add_error(EINVALID, "recplist->recpcert empty", 0, 0, proc);
			return( -1 );
		}


		/*--X-RECIPIENT-ID------------------------------------------------------*/
		if (( ec = pem_chd( msgbuf , PEM_RECIPIENT_ID )) ) {
			aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		/*--1.Parameter  (issuer)-----------------------------------------------*/
		if(!(encoded = e_DName(recplist->recpcert->tbs->issuer))) {
			aux_add_error(EINVALID, "e_DName failed", recplist->recpcert->tbs->issuer, DName_n, proc);
			return( -1 );
		}

		if(!(printable = aux_encrfc(encoded))) {
			aux_add_error(EINVALID, "aux_encrfc failed", encoded, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);

		if ( !(blank = aux_create_OctetString( " " )) ) {
			aux_free_OctetString( &printable );
			aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
			return( -1 );
		}

		if (!(encoded = aux_64( printable , blank ))) {
			aux_free_OctetString( &printable );
			aux_free_OctetString( &blank );
			aux_add_error(EINVALID, "aux_64 failed", printable, OctetString_n, proc);
			return( -1 );
		}
		aux_free_OctetString( &printable );
		aux_free_OctetString( &blank );

		if (( ec = aux_append_OctetString( msgbuf , encoded )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);

		/*--2.Parameter  (serial number)------------------------------------------*/
		if (( ec = aux_append_char( msgbuf , " ," ) )) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		/*  CA-Key-Nr */
		sprintf(sernr, "%02X", recplist->recpcert->tbs->serialnumber);
		if(strlen(sernr)%2) if (( ec = aux_append_char( msgbuf , "0" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , sernr )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if ( recplist->key ) {
			/*--X-KEY-INFO----------------------------------------------------------*/
			if (( ec = pem_chd( msgbuf , PEM_KEY_INFO )) ) {
				aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
				return( -1 );
			}


			/*--algorithm-----------------------------------------------------------*/
			oid = recplist->recpcert->tbs->subjectPK->subjectAI->objid;
			if ( !(oiname = aux_ObjId2Name( oid )) ) {
				aux_add_error(EINVALID, "aux_ObjId2Name failed", recplist->recpcert->tbs->subjectPK->subjectAI, AlgId_n, proc);
				return( -1 );
			}


			if (( ec = aux_append_char( msgbuf , oiname )) ) {
				aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
				return( -1 );
			}


			if (( ec = aux_append_char( msgbuf , ",\n" )) ) {
				aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
				return( -1 );
			}


			if ( !recplist->key || !recplist->key->octets ) {
				aux_add_error(EINVALID, "recplist->key empty", 0, 0, proc);
				return( -1 );
			}

			/*--Key-----------------------------------------------------------------*/
			if ( !( bst = aux_encrfc( recplist->key )) ) {
				aux_add_error(EINVALID, "aux_encrfc failed", recplist->key, OctetString_n, proc);
				return( -1 );
			}

			if ( !(blank = aux_create_OctetString( " " ) )) {
				aux_free_OctetString( &bst );
				aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
				return( -1 );
			}
			if (!(u64bst = aux_64( bst , blank ))) {
				aux_add_error(EINVALID, "aux_64 failed", bst, OctetString_n, proc);
				return( -1 );
			}


			aux_free_OctetString( &blank );
			aux_free_OctetString( &bst );

			if (( ec = aux_append_OctetString( msgbuf , u64bst )) ) {
				aux_free_OctetString( &u64bst );
				aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
				return( -1 );
			}
			aux_free_OctetString( &u64bst );
		} /* end if encryption required */

		/* no key info:
 *  else
 *     {
 *     if (( ec = aux_append_char( msgbuf , "\n" )) ) {
 *		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
 *		return( -1 );
 *	}
 *
 *     }
*/

		recplist = recplist->next;
	} /* end while recplist */
	return( 0 );
}


/************************************************************************/
/*      pem_cputcert                                                    */
/*                                                                      */
/*      appends single certificate "cert" to "msgbuf"                   */
/************************************************************************/
RC pem_cputcert( msgbuf , cert )
OctetString               *msgbuf;
Certificate               *cert;
{
	OctetString           * blank,
	    *ecert,
	    *bst,
	    *u64bst;
	int	ec,
	nbits;
	char	*out;
	char *proc = "pem_cputcert";



	if ( !cert ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}

	if (!(ecert = (OctetString * ) e_Certificate( cert ))) {
		aux_add_error(EENCODE, "e_Certificate failed", cert, Certificate_n, proc);
		return( -1 );
	}

	/*--encode--------------------------------------------------------------*/
	if ( !( bst = aux_encrfc( ecert )) ) {
		aux_add_error(EINVALID, "aux_encrfc failed", ecert, OctetString_n, proc);
		return( -1 );
	}		

	if ( !(blank = aux_create_OctetString( " " )) ) {
		aux_free_OctetString( &bst );
		aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
		return( -1 );
	}

	if (!(u64bst = aux_64( bst , blank ))) {
		aux_free_OctetString( &bst );
		aux_free_OctetString( &blank );
		aux_add_error(EINVALID, "aux_64 failed", bst, OctetString_n, proc);
		return( -1 );
	}
	aux_free_OctetString( &blank );
	aux_free_OctetString( &bst );

	if (( ec = aux_append_OctetString( msgbuf , u64bst )) ) {
		aux_free_OctetString( &u64bst );
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
	}
	aux_free_OctetString( &u64bst );

	return( 0 );
}


/************************************************************************/
/*      pem_csend                                                       */
/************************************************************************/
RC pem_csend( msgbuf , certs, info, ctbi )
OctetString	*msgbuf;
Certificates	*certs;
PemInfo		*info;
char		ctbi;
{
	FCPath			*cpath;
	CrossCertificates	*ccerts;
	Certificate		*cer;
	RecpList		*myself;
	EncryptedKey		encrypted_key;
	Key			encryption_key;
	OctetString		*encoded, *printable, *blank;
	int			n, ec;
	char			sernr[9];
	Name			*printrepr;
	char			*proc = "pem_csend";


	if ( !certs ) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}

	cer = certs->usercertificate;

	myself = (RecpList *)calloc(1, sizeof(RecpList));

	if(!ctbi) {
		/*--X-SENDER-ID---------------------------------------------------------*/
		if (( ec = pem_chd( msgbuf , PEM_SENDER_ID )) ) {
			aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		/*--1.Parameter  (issuer)-----------------------------------------------*/
		if(!(encoded = e_DName(cer->tbs->issuer))) {
			aux_add_error(EINVALID, "e_DName failed", cer->tbs->issuer, DName_n, proc);
			return( -1 );
		}

		if(!(printable = aux_encrfc(encoded))) {
			aux_add_error(EINVALID, "aux_encrfc failed", encoded, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);

		if ( !(blank = aux_create_OctetString( " " )) ) {
			aux_free_OctetString( &printable );
			aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
			return( -1 );
		}

		if (!(encoded = aux_64( printable , blank ))) {
			aux_free_OctetString( &printable );
			aux_free_OctetString( &blank );
			aux_add_error(EINVALID, "aux_64 failed", printable, OctetString_n, proc);
			return( -1 );
		}
		aux_free_OctetString( &printable );
		aux_free_OctetString( &blank );

		if (( ec = aux_append_OctetString( msgbuf , encoded )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);

		/*--2.Parameter  (serial number)------------------------------------------*/
		if (( ec = aux_append_char( msgbuf , " ," )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		/*  CA-Key-Nr */
		sprintf(sernr, "%02X", cer->tbs->serialnumber);
		if(strlen(sernr)%2) if (( ec = aux_append_char( msgbuf , "0" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , sernr )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

	} else {
		/*--X-CERTIFICATE-------------------------------------------------------*/
		if (( ec = pem_chd( msgbuf , PEM_CERTIFICATE )) ) {
			aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_char( msgbuf , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		/*--append certificate--------------------------------------------------*/
		if (( ec = pem_cputcert( msgbuf , cer )) ) {
			aux_add_error(EINVALID, "pem_cputcert failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}
	}

	if(!pem_option_K && info->confidential)  {
		if(!(myself->recpcert = af_pse_get_Certificate(ENCRYPTION, 0, 0))) {
			aux_add_error(EINVALID, "af_pse_get_Certificate failed", 0, 0, proc);
			aux_free_RecpList(&myself);
			return(-1);
		}

		aux_free_AlgId(&myself->recpcert->tbs->subjectPK->subjectAI);
		myself->recpcert->tbs->subjectPK->subjectAI = aux_Name2AlgId(DEK_ENC_ALG);
		encryption_key.key = myself->recpcert->tbs->subjectPK;
		encryption_key.keyref = 0;
		encryption_key.alg = aux_Name2AlgId(DEK_ENC_ALG);
		encryption_key.pse_sel = NULL;
		if(af_get_EncryptedKey(&encrypted_key, info->encryptKEY, &encryption_key, 0, myself->recpcert->tbs->subjectPK->subjectAI)) {
			aux_add_error(EINVALID, "af_get_EncryptedKey failed", 0, 0, proc);
			aux_free_RecpList(&myself);
			return(-1);
		}
	    
		myself->key = (OctetString *)malloc(sizeof(OctetString));

		myself->key->noctets = encrypted_key.subjectkey.nbits / 8;
		myself->key->octets = (char *)malloc(myself->key->noctets);

		for(n = 0; n < myself->key->noctets; n++) myself->key->octets[n] = encrypted_key.subjectkey.bits[n];
		if(pem_ckeyinf(msgbuf, myself)) {	
			aux_free_RecpList(&myself);
			aux_add_error(EINVALID, "pem_ckeyinf failed", msgbuf, OctetString_n, proc);
			return(-1);
		}
		aux_free_RecpList(&myself);
	}

	if(ctbi) {
		/*--X-ISSUER-CERTIFICATE------------------------------------------------*/
		cpath = certs->forwardpath;
		while(cpath && pem_cert_num) {
			ccerts = (cpath->liste);
			while ( ccerts ) {
				cer = ccerts->element;

				if (( ec = pem_chd( msgbuf , PEM_ISSUER_CERTIFICATE )) ) {
					aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
					return( -1 );
				}		

				if (( ec = aux_append_char( msgbuf , "\n" )) ) {
					aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
					return( -1 );
				}

				/*----------append certificate------------------------------------------*/
				if (( ec = pem_cputcert( msgbuf , cer )) ) {
					aux_add_error(EINVALID, "pem_cputcert failed", msgbuf, OctetString_n, proc);
					return( -1 );
				}

				ccerts = ccerts->next;
			}
			pem_cert_num--;
			cpath = cpath->next_forwardpath;
		}
	}

	return( 0 );
}



/************************************************************************/
/*      pem_ckeyinf                                                     */
/************************************************************************/
RC	pem_ckeyinf(msgbuf, recplist)
OctetString	*msgbuf;
RecpList	*recplist;
{
	char		*oiname;
	char		sernr[9];
	ObjId		*oid;
	OctetString	*bst, *encoded, *blank, *printable, *u64bst;
	char		*proc = "pem_ckeyinf";


	if(!msgbuf || !recplist || !recplist->recpcert || !recplist->recpcert->tbs || !recplist->recpcert->tbs->subjectPK || 
		!recplist->recpcert->tbs->subjectPK->subjectAI || !recplist->key || !recplist->key->octets) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return(-1);
	}

	/*--X-KEY-INFO----------------------------------------------------------*/
	if(pem_chd(msgbuf, PEM_KEY_INFO)) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return(-1);
	}

	/*--algorithm-----------------------------------------------------------*/
	oid = recplist->recpcert->tbs->subjectPK->subjectAI->objid;
	if(!(oiname = aux_ObjId2Name(oid))) {
		aux_add_error(EINVALID, "aux_ObjId2Name failed", recplist->recpcert->tbs->subjectPK->subjectAI, AlgId_n, proc);
		return(-1);
	}

	if(aux_append_char(msgbuf, oiname)) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return(-1);
	}

	if(aux_append_char(msgbuf, ",\n")) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return(-1);
	}

	/*--Key-----------------------------------------------------------------*/
	if(!(bst = aux_encrfc(recplist->key))) {
		aux_add_error(EINVALID, "aux_encrfc failed", recplist->key, OctetString_n, proc);
		return(-1);
	}
	if(!(blank = aux_create_OctetString(" "))) {
		aux_free_OctetString(&bst);
		aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
		return(-1);
	}

	if(!(u64bst = aux_64(bst , blank))) {
		aux_add_error(EINVALID, "aux_64 failed", bst, OctetString_n, proc);
		return(-1);
	}

	aux_free_OctetString(&blank);
	aux_free_OctetString(&bst);

	if(aux_append_OctetString(msgbuf, u64bst)) {
		aux_free_OctetString(&u64bst);
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return(-1);
	}
	aux_free_OctetString(&u64bst);

	return(0);
}



/************************************************************************/
/*      pem_cmic                                                        */
/************************************************************************/
RC pem_cmic(msgbuf, info, micalg, micencalg, signature)
OctetString    *msgbuf;
PemInfo        *info;
char           *micalg, *micencalg;
BitString      *signature;
{
	int	ec;
	char	*out;
	char	*oiname;
	ObjId    * oid;
	OctetString    * blank, *bst, *u64bst, sign;
	BitString       encr_mic;
	char *proc = "pem_cmic";



	if ( !signature || !signature->bits ) {
		aux_add_error(EINVALID, "invalid parameter (signature)", 0, 0, proc);
		return( -1 );
	}


	if (!micalg || !micencalg) {
		aux_add_error(EINVALID, "invalid parameter (micalg)", 0, 0, proc);
		return( -1 );
	}


	/*--X-MIC-INFO----------------------------------------------------------*/
	if (( ec = pem_chd( msgbuf , PEM_MIC_INFO )) ) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	/*--algorithm-----------------------------------------------------------*/

	if ((ec = aux_append_char(msgbuf, micalg))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_char(msgbuf, ","))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_char(msgbuf, micencalg))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_char(msgbuf, ",\n"))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	/*--Signature-----------------------------------------------------------*/

	sign.noctets = ( signature->nbits + 7 ) / 8;
	sign.octets = signature->bits;

	/*--encrypt MIC, if PEM status ENCRYPTED!-------------------------------*/
	if (info->confidential) {
		encr_mic.bits = (char *)malloc(sign.noctets + 8);

		encr_mic.nbits = 0;
		if ( af_encrypt(&sign, &encr_mic, END, info->encryptKEY, (DName *)0 ) < 0 ) {
			aux_add_error(EENCRMIC, "af_encrypt failed", 0, 0, proc);
			return( -1 );
		}

		sign.noctets = ( encr_mic.nbits + 7 ) / 8;
		sign.octets = encr_mic.bits;
	}

	if ( !( bst = aux_encrfc( &sign )) ) {
		aux_add_error(EINVALID, "aux_encrfc failed", &sign, OctetString_n, proc);
		return( -1 );
	}


	if (!( blank = aux_create_OctetString( " " )) ) {
		aux_free_OctetString( &blank );
		aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
		return( -1 );

	}
	if (!(u64bst = aux_64( bst , blank ))) {
		aux_add_error(EINVALID, "aux_64 failed", bst, OctetString_n, proc);
		return( -1 );
	}


	aux_free_OctetString( &bst );
	aux_free_OctetString( &blank );
	if (( ec = aux_append_OctetString( msgbuf , u64bst )) ) {
		aux_free_OctetString( &u64bst );
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}
	aux_free_OctetString( &u64bst );

	return( 0 );
}

/************************************************************************/
/*      pem_cmic                                                        */
/************************************************************************/
RC pem_cmic_for_certification(msgbuf, micalg, micencalg, signature_string)
OctetString    *msgbuf;
char           *micalg, *micencalg;
OctetString    *signature_string;
{
	int	ec;
	OctetString    * blank, *bst, *u64bst, sign;

	char *proc = "pem_cmic_for_certification";



	if (!micalg || !micencalg) {
		aux_add_error(EINVALID, "invalid parameter (micalg)", 0, 0, proc);
		return( -1 );
	}


	/*--X-MIC-INFO----------------------------------------------------------*/
	if (( ec = pem_chd( msgbuf , PEM_MIC_INFO )) ) {
		aux_add_error(EINVALID, "pem_chd failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	/*--algorithm-----------------------------------------------------------*/

	if ((ec = aux_append_OctetString(msgbuf, micalg))) {
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_char(msgbuf, ","))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_OctetString(msgbuf, micencalg))) {
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	if ((ec = aux_append_char(msgbuf, ",\n"))) {
		aux_add_error(EINVALID, "aux_append_char failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}



	if (!( blank = aux_create_OctetString( " " )) ) {
		aux_free_OctetString( &blank );
		aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
		return( -1 );

	}
	if (!(u64bst = aux_64( signature_string , blank ))) {
		aux_add_error(EINVALID, "aux_64 failed", signature_string, OctetString_n, proc);
		return( -1 );
	}

	if (( ec = aux_append_OctetString( msgbuf , u64bst )) ) {
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}
	aux_free_OctetString( &u64bst );
	aux_free_OctetString( &blank );

	return( 0 );
}



/************************************************************************/
/*      pem_cbody                                                       */
/************************************************************************/
RC pem_cbody(msgbuf, info, in)
OctetString *msgbuf;
PemInfo     *info;
OctetString *in;
{
	OctetString  indent;
	OctetString * pren, *form64, *buf;
	BitString    out_bits;
	int	k, nop;
	char *proc = "pem_cbody";

	extern OctetString *aux_canon(), *aux_encrfc(), *aux_64();
	extern RC aux_append_OctetString();



	if ( !in || !msgbuf || !info ) {
		aux_add_error(EINVALID, "one parameter empty", 0, 0, proc);
		return( -1 );
	}

	if(pem_verbose_1) fprintf(stderr, "canonicalize message input ...\n");
	if ( (buf = aux_canon(in)) == (OctetString * )0 ) {
		aux_add_error(EINVALID, "aux_canon failed", in, OctetString_n, proc);
		return( -1 );
	}


	/* ---------- MIC-CLEAR: ---------------------------------------*/
	if ( info->clear && !info->confidential ) {
		if(pem_verbose_1) fprintf(stderr, "append MIC-CLEAR message ...\n");
		k = aux_append_OctetString(msgbuf, buf);
		aux_free_OctetString(&buf);
		if ( k != 0 ) {
			aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
			return( -1 );
		}

		return(0);
	}
	/* ---------- MIC-CLEAR END - RETURNING ------------------------*/


	/* ---------- ENCRYPTED ONLY: ----------------------------------*/
	if ( info->confidential && (buf->noctets > 0) ) {
		if(pem_verbose_1) fprintf(stderr, "encrypt ENCRYPTED message ...\n");
		out_bits.bits = malloc(buf->noctets + 8);
		out_bits.nbits = 0;
		if ( af_encrypt(buf, &out_bits, END, info->encryptKEY, (DName *)0 ) == -1 ) {
			aux_free_OctetString(&buf);
			free(out_bits.bits);
			aux_add_error(EENCRBODY, "af_encrypt failed", 0, 0, proc);
			return( -1 );
		}
		/* write back encrypted data to buf: */
		free(buf->octets);
		buf->noctets = (out_bits.nbits + 7) / 8;
		buf->octets = out_bits.bits;
	}
	/* -----------ENCRYPTED ONLY END--------------------------------*/

	/* ---------- ENCRYPTED and MIC-ONLY: --------------------------*/
	if(pem_verbose_1) fprintf(stderr, "encode ENCRYPTED / MIC-ONLY message ...\n");
	pren = aux_encrfc (buf);
	aux_free_OctetString(&buf);
	if ( pren == (OctetString * )0 ) {
		aux_add_error(EINVALID, "aux_encrfc failed", buf, OctetString_n, proc);
		return( -1 );
	}


	/* no indent in encoded/encrypted body */
	indent.noctets = 0;
	indent.octets  = "";

	if(pem_verbose_1) fprintf(stderr, "form encoded ENCRYPTED / MIC-ONLY message ...\n");
	form64 = aux_64(pren, &indent);
	aux_free_OctetString(&pren);
	if ( form64 == (OctetString * )0 ) {
		aux_add_error(EINVALID, "aux_64 failed", pren, OctetString_n, proc);
		return( -1 );
	}


	if(pem_verbose_1) fprintf(stderr, "append formed & encoded ENCRYPTED / MIC-ONLY message ...\n");
	k = aux_append_OctetString(msgbuf, form64);
	aux_free_OctetString(&form64);
	if ( k != 0 ) {
		aux_add_error(EINVALID, "aux_append_OctetString failed", msgbuf, OctetString_n, proc);
		return( -1 );
	}


	return(0);
}



/************************************************************************/
/*      pem_crl                                                         */
/************************************************************************/
RC pem_crl(issuer, pem, cadir)
SET_OF_DName *issuer;
OctetString	*pem;
char		*cadir;
{
	char *proc = "pem_crl";
	int ec;
	PemCrlWithCerts      * pemcrlwithcerts;
	SET_OF_DName *issuer2;
	SET_OF_PemCrlWithCerts *setofpemcrlwithcerts2,*setofpemcrlwithcerts = 0;
	OctetString *blank, *encoded, *printable;
	Name *name;
	AlgId           *algorithm = DEF_ISSUER_ALGID;

	pem_option_K = TRUE;


	if((ec = pem_cinit(pem, FALSE, FALSE, CRL_MESSAGE))) {
		aux_add_error(EINVALID, "pem_cinit failed", pem, OctetString_n, proc);
		return( -1 );
	}
	if(issuer) {
		for (issuer2 = issuer; issuer2; issuer2 = issuer2->next) {
	
			if(issuer2->element) {
				if(!(name = aux_DName2Name(issuer2->element))) {
					aux_add_error(EINVALID, "aux_DName2Name failed", issuer2->element, DName_n, proc);
					return( -1 );
				}
			} else name = NULL;
			if((pemcrlwithcerts = af_cadb_get_PemCrlWithCerts(name, cadir))) {
				setofpemcrlwithcerts = (SET_OF_PemCrlWithCerts * )malloc(sizeof(SET_OF_PemCrlWithCerts));
				setofpemcrlwithcerts2->element = pemcrlwithcerts;
				setofpemcrlwithcerts2->next = setofpemcrlwithcerts;
				setofpemcrlwithcerts = setofpemcrlwithcerts2;

			}
			if(name) free(name);
		}
	} else setofpemcrlwithcerts = af_cadb_list_PemCrlWithCerts(cadir);

	for (setofpemcrlwithcerts2 = setofpemcrlwithcerts; setofpemcrlwithcerts2; setofpemcrlwithcerts2 = setofpemcrlwithcerts2->next) {

		pemcrlwithcerts = setofpemcrlwithcerts2->element;
	
		if (( ec = pem_chd( pem , PEM_CRL_ )) ) {
			aux_add_error(EINVALID, "pem_chd failed", pem, OctetString_n, proc);
			return( -1 );
		}
		if(!(encoded = e_PemCrl(pemcrlwithcerts->pemcrl))) {
			aux_add_error(EINVALID, "e_PemCrl failed", CNULL, 0, proc);
			return( -1 );
		}

		if(!(printable = aux_encrfc(encoded))) {
			aux_add_error(EINVALID, "aux_encrfc failed", encoded, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);

		if ( !(blank = aux_create_OctetString( " " )) ) {
			aux_free_OctetString( &printable );
			aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
			return( -1 );
		}

		if (!(encoded = aux_64( printable , blank ))) {
			aux_free_OctetString( &printable );
			aux_free_OctetString( &blank );
			aux_add_error(EINVALID, "aux_64 failed", printable, OctetString_n, proc);
			return( -1 );
		}
		aux_free_OctetString( &printable );
		aux_free_OctetString( &blank );

		if (( ec = aux_append_char( pem , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_OctetString( pem , encoded )) ) {
			aux_add_error(EINVALID, "aux_append_OctetString failed", pem, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);


		if(!pemcrlwithcerts->certificates) {


			aux_free_OctetString(&pemcrlwithcerts->pemcrl->tbs_DERcode);
			if (pemcrlwithcerts->pemcrl->sig) aux_free_KeyInfo( &pemcrlwithcerts->pemcrl->sig );
			pemcrlwithcerts->pemcrl->sig = (Signature * )malloc(sizeof(Signature));
		
			pemcrlwithcerts->pemcrl->sig->signAI = af_pse_get_signAI();
			if ( ! pemcrlwithcerts->pemcrl->sig->signAI ) {
				fprintf(stderr, "Cannot determine the algorithm associated to your own secret signature key\n");
				aux_add_error(EREADPSE, "af_pse_get_signAI failed", CNULL, 0, proc);
				if (pem_verbose_1) aux_fprint_error(stderr, 0);
				return (-1);
			}
		
			if (aux_ObjId2AlgType(pemcrlwithcerts->pemcrl->sig->signAI->objid) == ASYM_ENC )
				pemcrlwithcerts->pemcrl->sig->signAI = aux_cpy_AlgId(algorithm);
		
			pemcrlwithcerts->pemcrl->tbs->signatureAI = aux_cpy_AlgId(pemcrlwithcerts->pemcrl->sig->signAI);
			pemcrlwithcerts->pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrlwithcerts->pemcrl->tbs);
			   
			if (!pemcrlwithcerts->pemcrl->tbs_DERcode || (af_sign(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END) < 0)) {
				fprintf(stderr, "AF Error with CA Signature\n");
				aux_add_error(EINVALID, "AF Error with CA Signature", CNULL, 0, proc);
				if(pem_verbose_1) aux_fprint_error(stderr, 0);
				return (-1);
			}





			if(!(pemcrlwithcerts->certificates = af_pse_get_Certificates(SIGNATURE, 0))) {
				aux_add_error(EINVALID, "af_pse_get_Certificates failed", 0, 0, proc);
				return( -1 );
			}
		}
		if((ec = pem_csend(pem, pemcrlwithcerts->certificates, 0, pem_insert_cert))) {
			aux_add_error(EINVALID, "pem_csend failed", pem, OctetString_n, proc);
			return( -1 );
		}
		
		
	}
	aux_free_SET_OF_PemCrlWithCerts( &setofpemcrlwithcerts2 );
	
	if (( ec = aux_append_char( pem , "\n" )) ) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return( -1 );
	}
	if(aux_append_char(pem, PEM_Boundary_End)) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return(-1);
	}
	return(0);

}


/************************************************************************/
/*      pem_crl                                                         */
/************************************************************************/
RC pem_crl_retrieval_request(issuer, pem)
SET_OF_DName *issuer;
OctetString	*pem;
{
	char *proc = "pem_crl_retrieval_request";
	int ec;
	OctetString *blank, *encoded, *printable;


	if((ec = pem_cinit(pem, FALSE, FALSE, CRL_RETRIEVAL_REQUEST_MESSAGE))) {
		aux_add_error(EINVALID, "pem_cinit failed", pem, OctetString_n, proc);
		return( -1 );
	}

	for ( ;issuer; issuer = issuer->next) {
		if (( ec = pem_chd( pem , PEM_ISSUER )) ) {
			aux_add_error(EINVALID, "pem_chd failed", pem, OctetString_n, proc);
			return( -1 );
		}
		if(!(encoded = e_DName(issuer->element))) {
			aux_add_error(EINVALID, "e_DName failed", issuer->element, DName_n, proc);
			return( -1 );
		}
	
		if(!(printable = aux_encrfc(encoded))) {
			aux_add_error(EINVALID, "aux_encrfc failed", encoded, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);
	
		if ( !(blank = aux_create_OctetString( " " )) ) {
			aux_free_OctetString( &printable );
			aux_add_error(EINVALID, "aux_create_OctetString failed", 0, 0, proc);
			return( -1 );
		}
	
		if (!(encoded = aux_64( printable , blank ))) {
			aux_free_OctetString( &printable );
			aux_free_OctetString( &blank );
			aux_add_error(EINVALID, "aux_64 failed", printable, OctetString_n, proc);
			return( -1 );
		}
		aux_free_OctetString( &printable );
		aux_free_OctetString( &blank );
	
		if (( ec = aux_append_char( pem , "\n" )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
			return( -1 );
		}

		if (( ec = aux_append_OctetString( pem , encoded )) ) {
			aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
			aux_free_OctetString(&encoded);
			return( -1 );
		}
		aux_free_OctetString(&encoded);
	}
	if(aux_append_char(pem, PEM_Boundary_End)) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return(-1);
	}

	return(0);
}



/************************************************************************/
/*      pem_create                                                      */
/************************************************************************/
RC pem_create(info, in, pem)
OctetString       *in, *pem;
PemInfo           *info;
{
	int	n, ec, index_1, index_2;
	Key           key;
	Signature     signature;
	OctetString  * canon;
	char *proc = "pem_create";


	if(!info) {
		aux_add_error(EINVALID, "invalid parameter", 0, 0, proc);
		return( -1 );
	}


	if((ec = pem_cinit(pem, info->confidential, info->clear, NO_CRL_MESSAGE))) {
		aux_add_error(EINVALID, "pem_cinit failed", pem, OctetString_n, proc);
		return( -1 );
	}

	if((ec = pem_ccd(pem, PEM_RFC822))) {
		aux_add_error(EINVALID, "pem_ccd failed", pem, OctetString_n, proc);
		return( -1 );
	}


	if(info->encryptKEY)
		if(info->encryptKEY->key)
			if((ec = pem_cdek(pem, info->encryptKEY->key->subjectAI))) {
				aux_add_error(EINVALID, "pem_cdek failed", pem, OctetString_n, proc);
				return( -1 );
			}


	if((ec = pem_csend(pem, info->origcert, info, pem_insert_cert))) {
		aux_add_error(EINVALID, "pem_csend failed", pem, OctetString_n, proc);
		return( -1 );
	}

	if(mic_for_certification) {
		if(pem_cmic_for_certification(pem, mic_for_certification[0], mic_for_certification[1], mic_for_certification[2])) {
			aux_add_error(EINVALID, "pem_cmic failed", pem, OctetString_n, proc);
			return(-1);
		}
		aux_free_OctetString(&(mic_for_certification[0]));
		aux_free_OctetString(&(mic_for_certification[1]));
		aux_free_OctetString(&(mic_for_certification[2]));
		free(mic_for_certification);
		mic_for_certification = 0;
	} else {
		/* sign canonicalized message input: */
		if(pem_verbose_1) fprintf(stderr, "canonicalize copy of message of any type for signing ...\n");
		if ( (canon = aux_canon(in)) == (OctetString * )0 ) {
			aux_add_error(EINVALID, "aux_canon failed", in, OctetString_n, proc);
			return( -1 );
		}
	
	
		/* MIC_ALG and MIC_ENC_ALG from pem.h */
		if(pem_verbose_1) fprintf(stderr, "getting MIC_ALG and MIC_ENC_ALG ...\n");
		if(strcmp(MIC_ALG, "RSA-MD2") == 0) {
			if(strcmp(MIC_ENC_ALG, "RSA") == 0) signature.signAI = md2WithRsaEncryption;
			else signature.signAI = md2WithRsa;
		} 
	
		if(strcmp(MIC_ALG, "RSA-MD5") == 0) {
			if(strcmp(MIC_ENC_ALG, "RSA") == 0) signature.signAI = md5WithRsaEncryption;
			else signature.signAI = md5WithRsa;
		}
 
		if(PEM_Conformance_Requested == FALSE)	if(strcmp(MIC_ALG, "NIST-SHA") == 0) {
			if(strcmp(MIC_ENC_ALG, "NIST-DSA") == 0) signature.signAI = dsaWithSHA;
		}

		if(pem_verbose_1) fprintf(stderr, "sign canonicalized message ...\n");
		ec = af_sign(canon, &signature, END);
	
		aux_free_OctetString (&canon);
	
		if(ec) {
			aux_add_error(EINVALID, "af_sign failed", 0, 0, proc);
			return( -1 );
		}
	
	
		if(pem_cmic(pem, info, MIC_ALG, MIC_ENC_ALG, &signature.signature)) {
			aux_add_error(EINVALID, "pem_cmic failed", pem, OctetString_n, proc);
			return(-1);
		}
	}
	if(info->recplist) if((ec = pem_crec(pem, info->recplist))) {
		aux_add_error(EINVALID, "pem_crec failed", pem, OctetString_n, proc);
		return(-1);
	}

	if(aux_append_char(pem, "\n")) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return(-1);
	}

	if(pem_cbody(pem, info , in)) {
		aux_add_error(EINVALID, "pem_cbody failed", pem, OctetString_n, proc);
		return(-1);
	}

	if(aux_append_char(pem, PEM_Boundary_End)) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return(-1);
	}

	if(aux_append_char(pem, "\n")) {
		aux_add_error(EINVALID, "aux_append_char failed", pem, OctetString_n, proc);
		return(-1);
	}

	return(0);
}


