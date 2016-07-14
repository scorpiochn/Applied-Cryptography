/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   SCTLOC                  VERSION 2.0            */
/*                                         DATE                */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME                                                 */
/*      sctloc.c                                               */
/*                                                             */
/*    DESCRIPTION                                              */
/*      Procedures for SCTINT                                  */
/*                                                             */
/*    IMPORT                DESCRIPTION                        */
/*                                                             */
/*      sta_aux_sct_apdu      dump sct-apdu in file            */
/*                                                             */
/*      sta_aux_bytestr_free  release bytes - pointer          */
/*                                                             */
/*      sta_aux_elemlen       eleminate length field in        */
/*                            response buffer                  */
/*      e_KeyAttrList         create datafield for             */
/*                            S_INST_USER_KEY, S_INST_DEV_KEY  */
/*                            S_INST_PIN                       */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*      SCTcreate             create S-Command                 */
/*                                                             */
/*      SCTerr                error-handling                   */
/*                                                             */
/*      SCTstatus             send status                      */
/*                                                             */
/*      SCTcheck              check 1 or 3 bytes               */
/*                                                             */
/*      SCTresponse           analyse response                 */
/*                                                             */
/*      SCTenc                encrypt SCT command              */
/*                                                             */
/*      SCTdec                decrypt SCT response             */
/*                                                             */
/*    INTERNAL              DESCRIPTION                        */
/*      SCTalloc              allocate buffer for command      */
/*                                                             */
/*      SCTbytestring         create datafield of command      */
/*                                                             */
/*      SCTparam              create parameter in command      */
/*                                                             */
/*      SCTplength            create lengthfield in apdu       */
/*                                                             */
/*      SCTppublic            create parameter 'public' in cmd */
/*                                                             */
/*      SCTwithNMdata         create command with not mandatory*/
/*                            datafield                        */
/*      SCTwithMdata          create command with mandatory    */
/*                            datafield                        */
/*      SCTnodata             create command with no datafield */
/*                                                             */
/*      LofPublic             calculate length of public       */
/*                            structure                        */
/*      LofKeycard            calculate length of WriteKeycard */
/*                            structure                        */
/*      SCTssc                in case of secure messaging      */
/*                            create ssc field in apdu         */
/*                                                             */
/*      SCTdevkeyinfo         create datafield for             */
/*                            S_GEN_DEV_KEY                    */
/*                                                             */
/*      SCTpininfo            create datafield for             */
/*                            S_INST_PIN                       */
/*                                                             */
/*      SCTclass              create class-byte                */
/*                                                             */
/*      SCTpurpose            create purpose-byte              */
/*                                                             */
/*      SCTsessionkey         create datafield for             */
/*                            S_GEN_SESSION_KEY                */
/*                                                             */
/*      SCTwritekeycard       create datafield for WRITE_KEYCARD*/
/*                                                             */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/
#include <stdio.h>
#ifndef MAC
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <signal.h>
#include "sca.h"
#include "sctint.h"
#include "sctrc.h"
#include "sctloc.h"
#include "sctport.h"
#include "sctmem.h"
#include "error.h"		/* transmission module */



/*-------------------------------------------------------------*/
/*   extern declarations                                       */
/*-------------------------------------------------------------*/

extern void     sta_aux_sct_resp();
extern int      sta_aux_sct_apdu();
extern int      cr_sctlist();

extern unsigned int tp1_err;	/* error-variable from transmission module */
extern unsigned int sct_errno;	/* error variable               */
extern char    *sct_errmsg;	/* address of error message */
extern SCTerror sct_error[TABLEN];	/* message table */
extern void     sta_aux_bytestr_free();
extern void     sta_aux_elemlen();

extern void     e_KeyAttrList();

#ifdef STREAM
extern FILE    *sct_trfp;	/* Filepointer of trace file    */

#endif

/*-------------------------------------------------------------*/
/*   globale forward declarations                              */
/*-------------------------------------------------------------*/
char           *SCTcreate();
int             SCTstatus();
int             SCTcheck();
int             SCTresponse();
int             SCTenc();

/*-------------------------------------------------------------*/
/*   internal forward declarations                             */
/*-------------------------------------------------------------*/
static void     SCTbytestring();
static void     SCTparam();
static void     SCTplength();
static void     SCTbinval();
static void     SCTppublic();
static char    *SCTwithNMdata();
static char    *SCTwithMdata();
static char    *SCTnodata();
static char    *SCTalloc();
static unsigned int LofPublic();
static unsigned int LofKeycard();
static void     SCTssc();
static void     SCTdevkeyinfo();
static void     SCTpininfo();
static void     SCTsessionkey();
static unsigned int SCTclass();
static void     SCTwritekeycard();
static unsigned int SCTpurpose();

/*-------------------------------------------------------------*/
/*   type definitions                                          */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/* Signal - Routine                                 +-----*/
/*                                                        */
/*--------------------------------------------------------*/
static
time_int()
{
/* Signal SIGALRM received      */
}



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTcreate           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create s_apdu                                         */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   p_elem                   pointer of portparam struct.*/
/*							  */
/*   command                  instruction code            */
/*                                                        */
/*   request                  address of request structure*/
/*                                                        */
/* OUT                                                    */
/*   lapdu                    length of apdu              */
/*                                                        */
/*   flag                     flag for S_STATUS           */
/*                            set by S_REQUEST_SC         */
/*                                   S_CHANGE_PIN         */
/*                                   S_AUTH(ACP='21'/'31' */
/*                                   S_READ_KEYCARD       */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   pointer                   o.k (address of apdu )     */
/*                                                        */
/*   NULL                      error                      */
/*                             EPARMISSED                 */
/*                             EINVPAR                    */
/*                             EINVINS                    */
/*			       EMEMAVAIL                  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   SCTalloc                                             */
/*   SCTbytestring                                        */
/*   SCTparam                                             */
/*   SCTplength                                           */
/*   SCTppublic                                           */
/*   SCTwithNMdata                                        */
/*   SCTwithMdata                                         */
/*   SCTnodata                                            */
/*   LofPublic                                            */
/*   LofKeycard                                           */
/*   SCTssc                                               */
/*   SCTdevkeyinfo                                        */
/*   SCTpininfo                                           */
/*   SCTclass                                             */
/*   SCTpurpose                                           */
/*   SCTsessionkey                                        */
/*   SCTwritekeycard                                      */
/*   e_KeyAttrList                                        */
/*   sta_aux_sct_apdu                                     */
/*--------------------------------------------------------*/
char           *
SCTcreate(p_elem, command, request, lapdu, flag)
	struct s_portparam *p_elem;	/* portparam structure */
	unsigned int    command;/* instruction code */
	Request        *request;/* request structure */
	unsigned int   *lapdu;	/* length of apdu   */
	BOOL           *flag;	/* flag for S_STATUS */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *s_apdu;
	char           *ptr;
	unsigned int    ldata;
	unsigned int    lenofpublic;
	unsigned int    class;
	unsigned int    purpose;
	int             rc;
	BitString       sec_key;
	Bytestring      in_apdu;
	Bytestring      out_apdu;
	Boolean         no_secure_cmd = FALSE;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	/*------------------------------------*/
	/* Initialisation                     */
	/*------------------------------------*/
	*flag = FALSE;
	sct_errno = 0;

	/*------------------------------------*/
	/* Build S_APDU without CLASS / INS   */
	/*------------------------------------*/

	switch (command) {
		/*--------------------------*/
		/* create S_REQUEST_SC      */
		/*--------------------------*/
	case S_REQUEST_SC:
		p_elem->sc_request = FALSE;
		s_apdu = SCTwithNMdata(p_elem, S_NOTUSED, RQP2.time,
				       RQDATA.outtext, lapdu);
		*flag = TRUE;
		break;

		/*--------------------------*/
		/* create S_DISPLAY         */
		/*--------------------------*/
	case S_DISPLAY:
		s_apdu = SCTwithNMdata(p_elem, S_NOTUSED, (unsigned) RQP2.time,
				       RQDATA.outtext, lapdu);
		break;

		/*--------------------------*/
		/* create S_EJECT_SC        */
		/*--------------------------*/
	case S_EJECT_SC:
		s_apdu = SCTwithNMdata(p_elem, S_NOTUSED, (unsigned) RQP2.signal,
				       RQDATA.outtext, lapdu);
		break;

		/*---------------------------------------------------------*/
		/* create S_STATUS- should only be called by the procedure */
		/* sct_interface                          */
		/*---------------------------------------------------------*/
	case S_STATUS:
		s_apdu = SCTnodata(p_elem, S_NOTUSED, S_NOTUSED, lapdu);
		break;
		/*---------------------------------------------------------*/
		/* create S_RESET - should only be called by the procedure */
		/* sct_reset                              */
		/* this command will always be send in plaintext           */
		/*---------------------------------------------------------*/
	case S_RESET:
		ldata = 0;
		no_secure_cmd = TRUE;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);

		ptr = s_apdu + 2;
		*ptr++ = S_NOTUSED;
		*ptr++ = S_NOTUSED;
		*ptr = ldata;
		if (p_elem->secure_messaging.command != SEC_NORMAL)
			*lapdu = *lapdu - 1;
		break;

		/*------------------------------------------------------*/
		/* create S_TRANS                                       */
		/* the secure - parameter defines the secure messaging  */
		/* between SCT and SC                                   */
		/*------------------------------------------------------*/
	case S_TRANS:
		if ((RQP1.secmode != TRANSP) &&
		    (RQP1.secmode != SECURE)) {
			sct_errno = EINVPAR;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		if ((RQDATA.sccommand == BYTENULL) ||
		    (RQDATA.sccommand->nbytes == 0) ||
		    (RQDATA.sccommand->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		s_apdu = SCTwithMdata(p_elem, (unsigned) RQP1.secmode, S_NOTUSED,
				      RQDATA.sccommand, lapdu);
		break;

		/*--------------------------*/
		/* create S_GEN_USER_KEY    */
		/*--------------------------*/
	case S_GEN_USER_KEY:
		if (RQP2.algid == S_RSA_F4) {
			if (RQDATA.keylen == 0) {
				sct_errno = EPARMISSED;
				sct_errmsg = sct_error[sct_errno].msg;
				return (NULL);
			} else {
				if (RQDATA.keylen < 255)
					ldata = 1;
				else
					ldata = 2;
			}
		} else
			ldata = 0;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);

		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, RQP2.algid);
		SCTplength(&ptr, ldata);
		SCTssc(&ptr, p_elem);
		if (ldata > 0)
			SCTbinval(&ptr, RQDATA.keylen);
		break;

		/*----------------------------*/
		/* create S_INST_USER_KEY     */
		/*----------------------------*/
	case S_INST_USER_KEY:

		if (RQDATKEYATTR == KEYATTRNULL) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};
		if (RQDATKEYATTR->key_attr.MAC_length > 8) {
			sct_errno = EINVPAR;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = 5;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, S_NOTUSED);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTbinval(&ptr, RQDATKEYATTR->key_inst_mode);

		e_KeyAttrList(&ptr, RQDATKEYATTR, NOT_DEFINED);

		break;



		/*--------------------------*/
		/* create S_DEL_USER_KEY    */
		/*--------------------------*/
	case S_DEL_USER_KEY:
		s_apdu = SCTnodata(p_elem, RQP1.kid, S_NOTUSED, lapdu);
		break;

		/*----------------------------*/
		/* create S_GET_RNO           */
		/*----------------------------*/
	case S_GET_RNO:
		if (RQP1.lrno > 255) {
			sct_errno = EINVPAR;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		s_apdu = SCTnodata(p_elem, RQP1.lrno, S_NOTUSED, lapdu);
		break;

		/*----------------------------*/
		/* create S_RSA_SIGN          */
		/*----------------------------*/
	case S_RSA_SIGN:

		s_apdu = SCTwithMdata(p_elem, RQP1.kid, S_NOTUSED,
				      RQDATA.hash, lapdu);

		break;

		/*----------------------------*/
		/* create S_RSA_VERIFY        */
		/*----------------------------*/
	case S_RSA_VERIFY:
		if ((RQDATVERIFY == VERNULL) ||
		    (RQDATVERIFY->public == PUBNULL) ||
		    (RQDATVERIFY->public->modulus == BYTENULL) ||
		    (RQDATVERIFY->public->modulus->nbytes == 0) ||
		    (RQDATVERIFY->public->modulus->bytes == NULL) ||
		    (RQDATVERIFY->signature == BYTENULL) ||
		    (RQDATVERIFY->signature->nbytes == 0) ||
		    (RQDATVERIFY->signature->bytes == NULL) ||
		    (RQDATVERIFY->hash == BYTENULL) ||
		    (RQDATVERIFY->hash->nbytes == 0) ||
		    (RQDATVERIFY->hash->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = LofPublic(RQDATVERIFY->public);

		ldata += RQDATVERIFY->signature->nbytes;
		ldata++;
		if (RQDATVERIFY->signature->nbytes >= 255)
			ldata += 2;


		ldata += RQDATVERIFY->hash->nbytes;
		ldata++;
		if (RQDATVERIFY->hash->nbytes >= 255)
			ldata += 2;


		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, S_NOTUSED);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTppublic(&ptr, RQDATVERIFY->public);

		SCTplength(&ptr, RQDATVERIFY->signature->nbytes);
		SCTbytestring(&ptr, RQDATVERIFY->signature);

		SCTplength(&ptr, RQDATVERIFY->hash->nbytes);
		SCTbytestring(&ptr, RQDATVERIFY->hash);


		break;

		/*----------------------------*/
		/* create S_DES_ENC           */
		/*----------------------------*/
	case S_DES_ENC:
		s_apdu = SCTwithMdata(p_elem, RQP1.kid, (unsigned) RQP2.more,
				      RQDATA.plaintext, lapdu);
		break;


		/*----------------------------*/
		/* create S_RSA_ENC           */
		/*----------------------------*/
	case S_RSA_ENC:
		if ((RQDATENC == ENCNULL) ||
		    (RQDATENC->plaintext == BYTENULL) ||
		    (RQDATENC->plaintext->nbytes == 0) ||
		    (RQDATENC->plaintext->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		ldata = LofPublic(RQDATENC->public);
		if (ldata == 2)
			ldata = 0;

		lenofpublic = ldata;
		ldata += RQDATENC->plaintext->nbytes;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, (unsigned) RQP2.more);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		if (lenofpublic > 2)
			SCTppublic(&ptr, RQDATENC->public);

		SCTbytestring(&ptr, RQDATENC->plaintext);
		break;

		/*----------------------------*/
		/* create S_RSA_DEC           */
		/* create S_DES_DEC           */
		/*----------------------------*/
	case S_RSA_DEC:
	case S_DES_DEC:
		if ((RQDATA.chiffrat == BYTENULL) ||
		    (RQDATA.chiffrat->nbytes == 0) ||
		    (RQDATA.chiffrat->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};
		s_apdu = SCTwithMdata(p_elem, RQP1.kid, (unsigned) RQP2.more,
				      RQDATA.chiffrat, lapdu);
		break;


		/*----------------------------*/
		/* create S_ENC_DES_KEY       */
		/*----------------------------*/
	case S_ENC_DES_KEY:
		if ((RQDATPUB == PUBNULL) ||
		    (RQDATPUB->modulus == BYTENULL) ||
		    (RQDATPUB->modulus->nbytes == 0) ||
		    (RQDATPUB->modulus->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		ldata = LofPublic(RQDATPUB);

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, S_NOTUSED);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTppublic(&ptr, RQDATPUB);

		break;


		/*----------------------------*/
		/* create S_DEC_DES_KEY       */
		/*----------------------------*/
	case S_DEC_DES_KEY:
		if ((RQDATDESKEY == DESKNULL) ||
		    (RQDATDESKEY->chiffrat == BYTENULL) ||
		    (RQDATDESKEY->chiffrat->nbytes == 0) ||
		    (RQDATDESKEY->chiffrat->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = 1 + RQDATDESKEY->chiffrat->nbytes;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, RQP2.kid);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		*ptr++ = RQDATDESKEY->algid;
		SCTbytestring(&ptr, RQDATDESKEY->chiffrat);

		break;

		/*----------------------------*/
		/* create S_GEN_DEV_KEY       */
		/*----------------------------*/
	case S_GEN_DEV_KEY:
		if (RQDATDEV == DEVNULL) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = 3;


		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, RQP2.algid);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTdevkeyinfo(&ptr, RQDATDEV);

		break;

		/*----------------------------*/
		/* create S_INST_DEV_KEY      */
		/*----------------------------*/
	case S_INST_DEV_KEY:

		if (RQDATKEYATTR == KEYATTRNULL) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		if (RQDATKEYATTR->key_attr.MAC_length > 8) {
			sct_errno = EINVPAR;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		ldata = 5;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		if (RQP2.status == DEV_OWN) {
			purpose = SCTpurpose(&RQP1.dev_inst_key->pval.purpose);
			SCTparam(&ptr, purpose, RQP2.status);
		} else
			SCTparam(&ptr, RQP1.dev_inst_key->pval.kid, RQP2.status);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTbinval(&ptr, RQDATKEYATTR->key_inst_mode);

		e_KeyAttrList(&ptr, RQDATKEYATTR, NOT_DEFINED);

		break;

		/*--------------------------*/
		/* create S_DEL_DEV_KEY     */
		/*--------------------------*/
	case S_DEL_DEV_KEY:
		if (RQP2.status == DEV_OWN) {
			purpose = SCTpurpose(&RQP1.dev_inst_key->pval.purpose);
			s_apdu = SCTnodata(p_elem, purpose, RQP2.status, lapdu);
		} else
			s_apdu = SCTnodata(p_elem, RQP1.dev_inst_key->pval.kid,
					   RQP2.status, lapdu);
		break;

		/*----------------------------*/
		/* create S_INST_PIN          */
		/*----------------------------*/
	case S_INST_PIN:

		if ((RQDATPIN == PINNULL) ||
		    (RQDATPIN->pin_attr == KEYATTRNULL) ||
		    (RQDATPIN->pin_record == BYTENULL) ||
		    (RQDATPIN->pin_record->nbytes == 0) ||
		    (RQDATPIN->pin_record->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};

		if (RQDATPIN->pin_attr->key_attr.MAC_length > 8) {
			sct_errno = EINVPAR;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = 6 + RQDATPIN->pin_record->nbytes;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, S_NOTUSED);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTpininfo(&ptr, RQDATPIN);

		break;

		/*--------------------------------*/
		/* create S_CHANGE_PIN            */
		/* the parameter 2 will be coded  */
		/* by this procedure              */
		/*--------------------------------*/
	case S_CHANGE_PIN:
		class = SCTclass(RQP2.sec_mode);


		s_apdu = SCTnodata(p_elem, RQP1.kid, class, lapdu);
		*flag = TRUE;
		break;



		/*----------------------------*/
		/* create S_AUTH              */
		/*----------------------------*/
	case S_AUTH:
		if ((RQP2.acp == PIN_USER) || (RQP2.acp == PUK_CHECK)) {
			ldata = 1;
			class = SCTclass(RQDATA.auth_secmode);

		} else
			ldata = 0;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);

		ptr = s_apdu + 2;

		SCTparam(&ptr, RQP1.kid, RQP2.acp);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);


		if ((RQP2.acp == PIN_USER) || (RQP2.acp == PUK_CHECK)) {
			SCTbinval(&ptr, class);
			*flag = TRUE;
		}
		break;


		/*---------------------------------------------------------*/
		/* create S_GET_TRANSPORT_KEY                              */
		/* this command will always be send in plaintext           */
		/*---------------------------------------------------------*/
	case S_GET_TRANSPORT_KEY:
		ldata = 0;
		no_secure_cmd = TRUE;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);

		ptr = s_apdu + 2;
		*ptr++ = S_NOTUSED;
		*ptr++ = RQP2.algid;
		*ptr = ldata;
		if (p_elem->secure_messaging.command != SEC_NORMAL)
			*lapdu = *lapdu - 1;
		break;

		/*----------------------------*/
		/* create S_GEN_SESSION_KEY  */
		/*---------------------------*/
	case S_GEN_SESSION_KEY:
		no_secure_cmd = TRUE;

		if ((RQDATSESS == SESSNULL) ||
		    (RQDATSESS->session_key == BYTENULL) ||
		    (RQDATSESS->session_key->nbytes == 0) ||
		    (RQDATSESS->session_key->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = 3 + RQDATSESS->session_key->nbytes;

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);


		ptr = s_apdu + 2;

		SCTparam(&ptr, S_NOTUSED, RQP2.algid);

		SCTplength(&ptr, ldata);

		SCTsessionkey(&ptr, RQDATSESS);

		if (p_elem->secure_messaging.command != SEC_NORMAL)
			*lapdu = *lapdu - 1;
		break;

		/*----------------------------*/
		/* create S_WRITE_KEYCARD    */
		/*---------------------------*/
	case S_WRITE_KEYCARD:

/* old implementation */

#ifdef OLDIMPL

		if ((RQDATWRITE == WRITENULL) ||
		    (RQDATWRITE->pin_record == BYTENULL) ||
		    (RQDATWRITE->pin_record->nbytes == 0) ||
		    (RQDATWRITE->pin_record->bytes == NULL)) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};


		ldata = LofKeycard(RQDATWRITE);

		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;

		if (RQP2.status == DEV_OWN) {
			purpose = SCTpurpose(&RQP1.dev_inst_key->pval.purpose);
			SCTparam(&ptr, purpose, RQP2.status);
		} else
			SCTparam(&ptr, RQP1.dev_inst_key->pval.kid, RQP2.status);

		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);

		SCTwritekeycard(&ptr, RQDATWRITE, RQP2.status);
#endif

		if (RQDATWRITE == WRITENULL) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};
		ldata = 0;
		if (RQDATWRITE->auth_keyid != 0x00)
			ldata++;
		if (RQDATWRITE->sec_auth_keyid != 0x00)
			ldata++;
		if (RQDATWRITE->sec_con_keyid != 0x00)
			ldata++;
		if (ldata == 0) {
			sct_errno = EPARMISSED;
			sct_errmsg = sct_error[sct_errno].msg;
			return (NULL);
		};




		if ((s_apdu = SCTalloc(ldata, &p_elem->secure_messaging,
				       lapdu)) == NULL)
			return (NULL);
		ptr = s_apdu + 2;
		SCTparam(&ptr, 0x00, RQP2.status);


		SCTplength(&ptr, ldata);

		SCTssc(&ptr, p_elem);


		if (RQDATWRITE->auth_keyid != 0x00)
			SCTplength(&ptr, RQDATWRITE->auth_keyid & 0xFF);

		if (RQDATWRITE->sec_auth_keyid != 0x00)
			SCTplength(&ptr, RQDATWRITE->sec_auth_keyid & 0xFF);

		if (RQDATWRITE->sec_con_keyid != 0x00)
			SCTplength(&ptr, RQDATWRITE->sec_con_keyid & 0xFF);

		break;

		/*----------------------------*/
		/* create S_READ_KEYCARD      */
		/*----------------------------*/
	case S_READ_KEYCARD:
		s_apdu = SCTnodata(p_elem, S_NOTUSED, RQP2.status, lapdu);
		break;




		/*----------------------------*/
		/* DEFAULT                    */
		/*----------------------------*/
	default:
		sct_errno = EINVINS;
		sct_errmsg = sct_error[sct_errno].msg;
		return (NULL);
		break;
	};

	if (s_apdu == NULL)
		return (NULL);


	/*------------------------------------*/
	/* create CLASS / INS       in s_apdu */
	/*------------------------------------*/
	if (no_secure_cmd == TRUE)
		class = NON_INTER;
	else
		class = SCTclass(&p_elem->secure_messaging);
	*s_apdu = class;
	*(s_apdu + 1) = command;

	/*------------------------------------*/
	/* print s_apdu                       */
	/*------------------------------------*/

#ifdef STREAM
	sta_aux_sct_apdu(sct_trfp, s_apdu, *lapdu);
#endif


	/*------------------------------------*/
	/* Execute Secure Messaging           */
	/*------------------------------------*/
	if (no_secure_cmd == FALSE) {
		if (p_elem->secure_messaging.command == CONCEALED) {
			in_apdu.nbytes = *lapdu;
			in_apdu.bytes = s_apdu;
			sec_key.nbits = p_elem->session_key.subjectkey.nbits;
			sec_key.bits = p_elem->session_key.subjectkey.bits;
			out_apdu.nbytes = 0;
			out_apdu.bytes = NULL;
			rc = SCTenc(&sec_key, &in_apdu, &out_apdu, DES);
			free(s_apdu);
			if (rc < 0)
				return (NULL);

			s_apdu = out_apdu.bytes;
			*lapdu = out_apdu.nbytes;
		}
	}
	return (s_apdu);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTcreate              */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTerr              VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Error - handling                                      */
/*  Search in sct_error - list sw1 / sw2;                 */
/*  return index in sct_errno                             */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sw1                       SW1                        */
/*                                                        */
/*   sw2                       SW2                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   -1                       error                       */
/*--------------------------------------------------------*/
int
SCTerr(sw1, sw2)
	unsigned int    sw1;
	unsigned int    sw2;
{


	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    index = 0;
	unsigned int    listlen = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	listlen = sizeof(sct_error) / sizeof(SCTerror);
	for (index = 0; index < listlen; index++) {

		if ((sct_error[index].sw1 == sw1) && (sct_error[index].sw2 == sw2)) {
			sct_errno = index;
			sct_errmsg = sct_error[sct_errno].msg;
			return (S_ERR);
		}
	}
	/* sw1 + sw2 not found */
	sct_errno = index - 1;	/* last element in error-list */
	sct_errmsg = sct_error[sct_errno].msg;
	return (S_ERR);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTerr                 */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTstatus           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Send   S_STATUS-command, until SW1 / SW2 <> 0x40/0x41 */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  lastcmd                   last command                */
/*                                                        */
/*  p_elem                    pointer of portparam struct.*/
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*  response.bytes            pointer of response.bytes   */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k.                       */
/*                                                        */
/*   -1                        error                      */
/*                             EPARMISSED                 */
/*                             EINVPAR                    */
/*                             EINVINS                    */
/*			       EMEMAVAIL                  */
/*                             ETOOLONG                   */
/*                             sw1/sw2 from SCT response  */
/*                             T1 - ERROR                 */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTcreate                                            */
/*   COMtrans                                             */
/*   SCTresponse                                          */
/*   sta_aux_bytestr_free                                 */
/*                                                        */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
int
SCTstatus(lastcmd, p_elem, resp)
	unsigned int    lastcmd;
	struct s_portparam *p_elem;
	Bytestring     *resp;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *s_apdu;
	unsigned int    lapdu;
	unsigned int    sw1;
	unsigned int    sw2;
	int             i;
	BOOL            flag = FALSE;	/* FLAG, if S_STATUS must be send */
	Request         request;

#ifdef DOS
	long            time1;
	long            time2;

#else
#if defined(MAC) || defined(__HP__)
   time_t time1, time2;
#else 
	struct itimerval value;
	struct itimerval ovalue;
#endif /* MAC */
#endif

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	/*------------------------------------*/
	/* Initialisation                     */
	/*------------------------------------*/


	/*------------------------------------*/
	/* Create s_apdu                      */
	/*------------------------------------*/
	if ((s_apdu = SCTcreate(p_elem, S_STATUS, &request, &lapdu, &flag)) == NULL)
		return (S_ERR);

	if (lapdu > p_elem->apdusize) {	/* test apdusize */
		sct_errno = ETOOLONG;
		sct_errmsg = sct_error[sct_errno].msg;
		free(s_apdu);
		return (S_ERR);
	};




	/*------------------------------------*/
	/* allocate response-buffer           */
	/*------------------------------------*/


#ifdef MALLOC
	resp->bytes = malloc(p_elem->apdusize);
#endif

	if (resp->bytes == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		free(s_apdu);
		return (S_ERR);
	};

	do {
		/*------------------------------------*/
		/* wait 1 sec, till next S_STATUS     */
		/* will be send                       */
		/*------------------------------------*/

#ifdef DOS
		time(&time1);
		do {
			time(&time2);
		} while ((time2 - time1) < 4);
#else
#if defined(MAC) || defined(__HP__)
      time(&time1);
      do
         time(&time2);
      while ((time2 - time1) < 1);
#else

      signal(SIGALRM,time_int);
      getitimer(ITIMER_REAL,&value);
      value.it_value.tv_sec = 1;    /* geaendert: 2.7.91 5 nach 1 */
      setitimer(ITIMER_REAL,&value,&ovalue);
      pause();
#endif /* !MAC */
#endif
		/*---------------------------------------*/
		/* repeat, until SW1 / SW2 <> SCT waiting */
		/*---------------------------------------*/
		resp->nbytes = 0;
		for (i = 0; i < p_elem->apdusize; i++)
			*(resp->bytes + i) = 0x00;


		/*------------------------------------*/
		/* call transmission-procedure        */
		/*------------------------------------*/

		if (COMtrans(p_elem, s_apdu, lapdu, resp->bytes, &resp->nbytes) == -1) {
			free(s_apdu);
			sta_aux_bytestr_free(resp);
			return (SCTerr(0, tp1_err));
		}
		/*------------------------------------*/
		/* analyse response                   */
		/*------------------------------------*/

		if (SCTresponse(p_elem, S_STATUS, resp, &sw1, &sw2) == -1) {

			free(s_apdu);
			return (S_ERR);
		}
		/*------------------------------------*/
		/* Create s_apdu,if command=concealed */
		/*------------------------------------*/
		if (sw1 == OKSCT && sw2 == SCTWAIT) {
			if (p_elem->secure_messaging.command != SEC_NORMAL) {
				free(s_apdu);
				if ((s_apdu = SCTcreate(p_elem, S_STATUS, &request, &lapdu, &flag)) == NULL) {
					sta_aux_bytestr_free(resp);
					return (S_ERR);
				}
			} else {

#ifdef STREAM
				sta_aux_sct_apdu(sct_trfp, s_apdu, lapdu);
#endif
			}
			/*-----------------------------------------------------------------*/

			/*
			 * allocate new response-buffer, if response =
			 * CONCEALED
			 */
			/*-----------------------------------------------------------------*/

			if (p_elem->secure_messaging.response != SEC_NORMAL) {

				sta_aux_bytestr_free(resp);

#ifdef MALLOC
				resp->bytes = malloc(p_elem->apdusize);
#endif

				if (resp->bytes == NULL) {
					sct_errno = EMEMAVAIL;
					sct_errmsg = sct_error[sct_errno].msg;
					free(s_apdu);
					return (S_ERR);
				};
			}
		}
	} while (sw1 == OKSCT && sw2 == SCTWAIT);

	/*------------------------------------*/
	/* S-STATUS ended;                    */
	/* if lastcmd = S_REQUEST_SC, then    */
	/* store SC-historical characters in  */
	/* p_elem and set sc_request = TRUE in */
	/* p_elem                             */
	/*------------------------------------*/
	/* release old schistory buffer */
	if (lastcmd == S_REQUEST_SC) {
		if (p_elem->schistory != NULL) {
			free(p_elem->schistory);
			p_elem->schistory = NULL;
		}
		/*------------------------------------*/
		/* allocate schistory buffer          */
		/*------------------------------------*/

#ifdef MALLOC
		p_elem->schistory = malloc(resp->nbytes + 1);
#endif

		if (p_elem->schistory == NULL) {
			sct_errno = EMEMAVAIL;
			sct_errmsg = sct_error[sct_errno].msg;
			free(s_apdu);
			sta_aux_bytestr_free(resp);
			return (S_ERR);
		};
		/*------------------------------------*/
		/* store history in p_elem            */
		/*------------------------------------*/
		for (i = 0; i < resp->nbytes; i++)
			*(p_elem->schistory + i) = *(resp->bytes + i);
		*(p_elem->schistory + resp->nbytes) = '\0';

		/*------------------------------------*/
		/* set sc_request in p_elem           */
		/*------------------------------------*/
		p_elem->sc_request = TRUE;

	}
	/*------------------------------------*/
	/* release s_apdu                     */
	/*------------------------------------*/
	free(s_apdu);
	return (S_NOERR);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTstatus              */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTcheck            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check field, if 1 or 3 Bytes and return integer value */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INOUT                     DESCRIPTION                  */
/*  buffer                    pointer to buffer           */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   size                      integer value              */
/*                                                        */
/*--------------------------------------------------------*/
int
SCTcheck(buffer)
	char          **buffer;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	int             size;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *buffer;
	if ((size = ((int) *p++) & 0xFF) >= 255) {
		size = ((((int) *p++) & 0xff) << 8);
		size += (((int) *p++) & 0xFF);
	};
	*buffer = p;
	return (size);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTcheck               */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTresponse         VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/* Execute secure messaging for response and check        */
/* sw1 / sw2 .                                            */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  p_elem                    pointer of portparam struct.*/
/*                                                        */
/*  command		      executed command		  */
/*							  */
/*  response		      pointer of response buffer  */
/*                                                        */
/* OUT                                                    */
/*  sw1		              sw1 - value                 */
/*                                                        */
/*  sw2		              sw2 - value                 */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k.                       */
/*                                                        */
/*   -1                        error                      */
/*                              sw1/sw2 from SCT response */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   sta_aux_sct_resp                                     */
/*   sta_aux_elemlen                                      */
/*   sta_aux_bytestr_free                                 */
/*                                                        */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
int
SCTresponse(p_elem, command, response, sw1, sw2)
	struct s_portparam *p_elem;
	unsigned int    command;
	Bytestring     *response;
	unsigned int   *sw1;
	unsigned int   *sw2;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	BitString       sec_key;
	Bytestring      out_apdu;
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/


	/*------------------------------------*/
	/* test secure messaging for response */
	/*------------------------------------*/

	if (p_elem->secure_messaging.response != SEC_NORMAL) {
		if ((command != S_RESET) &&
		    (command != S_GET_TRANSPORT_KEY) &&
		    (command != S_GEN_SESSION_KEY)) {
			if (response->nbytes != 3) {
				/* Call SCTdec */
				sec_key.nbits = p_elem->session_key.subjectkey.nbits;
				sec_key.bits = p_elem->session_key.subjectkey.bits;
				out_apdu.nbytes = 0;
				out_apdu.bytes = NULL;
				rc = SCTdec(&sec_key, p_elem->ssc, response, &out_apdu, DES);
				sta_aux_bytestr_free(response);
				/*------------------------------------*/
				/* set ssc                            */
				/*------------------------------------*/
				p_elem->ssc++;
				if (rc < 0) {
					if (command == S_EJECT_SC)
						p_elem->sc_request = FALSE;
					return (-1);
				}
				response->nbytes = out_apdu.nbytes;
				response->bytes = out_apdu.bytes;
			}
		}
	}
	/*------------------------------------*/
	/* print response			 */
	/*------------------------------------*/

#ifdef STREAM
	sta_aux_sct_resp(sct_trfp, response->bytes, response->nbytes);
#endif

	/*------------------------------------*/
	/* eleminate Length-field in Response */
	/*------------------------------------*/
	sta_aux_elemlen(response);


	/*------------------------------------*/
	/* check SW1/SW2			 */
	/*------------------------------------*/
	*sw1 = *(response->bytes + (response->nbytes - 2)) & 0xFF;
	*sw2 = *(response->bytes + (response->nbytes - 1)) & 0xFF;

	/* delete sw1/sw2 in response-buffer */
	*(response->bytes + (response->nbytes - 2)) = 0x00;
	*(response->bytes + (response->nbytes - 1)) = 0x00;
	response->nbytes -= 2;


	/*------------------------------------*/
	/* if sw1 indicates an error, then	 */
	/* search in sct_error list sw1/sw2	 */
	/* and return index in sct_errno to	 */
	/* calling procedure 		 */
	/*------------------------------------*/
	if ((*sw1 != OKSC) && (*sw1 != OKSCT)) {
		sta_aux_bytestr_free(response);
		return (SCTerr(*sw1, *sw2));
	};

	return (S_NOERR);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTresponse            */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTenc               VERSION   2.0               */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Encrypt SCT-COMMAND-APDU (without CLA-Byte)           */
/*  This Procedure can be called in case of               */
/*  secure messaging = CONCEALED .			  */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   in_apdu		       Pointer of SCT-APDU        */
/*                             The SC-APDU must have the  */
/*                             structur:                  */
/*			       __________________________ */
/*			      | CLA,INS,P1,P2,L,SSC,DATA |*/
/*			       __________________________ */
/*			      (= output of the procedure  */
/*				 SCTcreate)		  */
/*							  */
/*   algenc		       Encryption method          */
/*							  */
/* OUT                                                    */
/*   out_apdu                  Pointer of SEC-APDU        */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*                             The SEC-APDU has the       */
/*                             structure:                 */
/*		           _____________________          */
/*			  | CLA,ENCRYPTED DATA  |         */
/*		           _____________________          */
/*							  */
/*

/*

*/
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESENC  		  */
/*				EALGO    		  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_encrypt                                          */
/*   aux_fxdump                                       */
/*   aux_free2_BitString                                  */
/*							  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
SCTenc(sec_key, in_apdu, out_apdu, algenc)
	BitString      *sec_key;/* secure messaging key */
	Bytestring     *in_apdu;/* SCT-APDU		 */
	Bytestring     *out_apdu;	/* SCT-SEC-APDU		 */
	AlgEnc         algenc;	/* encryption method		 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     in_octets;
	char           *ptr;
	int             i;
	int             memolen;
	BitString       out_bits;
	KeyInfo         key_info;
	More            more;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	out_apdu->nbytes = 0;
	out_apdu->bytes = NULL;
	in_octets.noctets = in_apdu->nbytes;
	in_octets.octets = in_apdu->bytes;

	/*---------------------------------------------------------*/
	/* encrypt data (INS,P1,P2,L,SSC,DATA)                     */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/
	in_octets.noctets -= 1;
	in_octets.octets++;

#ifdef STREAM
	fprintf(sct_trfp, "TRACE in SCTenc\n");
	fprintf(sct_trfp, "   sec_key.nbits     = %d\n", sec_key->nbits);
	fprintf(sct_trfp, "   sec_key.bits      = \n");
	aux_fxdump(sct_trfp, sec_key->bits, sec_key->nbits / 8, 0);
	fprintf(sct_trfp, "   in_octets.noctets = %d\n", in_octets.noctets);
	fprintf(sct_trfp, "   in_octets.octets  = \n");
	aux_fxdump(sct_trfp, in_octets.octets, in_octets.noctets, 0);
#endif

	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		sct_errno = EALGO;
		sct_errmsg = sct_error[sct_errno].msg;
		return (-1);
		break;
	}
	more = END;
	/* allocate memory for out_bits  */
	/* the memory must be a multiple of 8 Bytes */
	if ((in_octets.noctets % 8) != 0)
		memolen = (in_octets.noctets - (in_octets.noctets % 8)) + 8;
	else
		memolen = in_octets.noctets;

	out_bits.nbits = 0;

#ifdef STREAM
	fprintf(sct_trfp, "   allocate out_bits = %d\n", memolen);
#endif

#ifdef MALLOC
	out_bits.bits = malloc(memolen);	/* will be set free in this
						 * proc. */
	if (out_bits.bits == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		return (-1);
	}
#endif



	memolen = des_encrypt(&in_octets, &out_bits, more, &key_info);
	if (memolen == -1) {
		sct_errno = EDESENC;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#ifdef STREAM
	fprintf(sct_trfp, "   out_bits.nbits    = %d\n", out_bits.nbits);
	fprintf(sct_trfp, "   out_bits.bits     = \n");
	aux_fxdump(sct_trfp, out_bits.bits, out_bits.nbits / 8, 0);
#endif


	memolen = (out_bits.nbits / 8) + 1;

#ifdef MALLOC
	out_apdu->bytes = malloc(memolen);	/* if no error => return	  */
	/* else will gbe set free in this proc. */
	if (out_apdu->bytes == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#endif

	out_apdu->nbytes = memolen;
	ptr = out_apdu->bytes;
	*ptr = *in_apdu->bytes;	/* transfer CLA-Byte */
	ptr++;
	for (i = 0; i < (out_bits.nbits / 8); i++) {
		*ptr = *(out_bits.bits + i);
		ptr++;
	};
	aux_free2_BitString(&out_bits);

#ifdef STREAM
	fprintf(sct_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sct_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sct_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sct_trfp, "TRACE-END in SCTenc\n");
#endif


	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTenc                 */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTdec              VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Decrypt SEC-RESPONSE-APDU                             */
/*  This procedure can be called in case of               */
/*  secure messaging = CONCEALED.                         */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   ssc		       Send Sequence Counter      */
/*							  */
/*   in_apdu		       Pointer of SEC-APDU        */
/*			       The SEC-APDU have the      */
/*			       structure	          */
/*		               _________________          */
/*			      | ENCRYPTED DATA  |         */
/*		               _________________          */
/*			       or			  */
/*		                _________________         */
/*			       | L = 0,SW1,SW2   |        */
/*		                _________________         */
/*   algenc		       Encryption method	  */
/*							  */
/*							  */
/* OUT                                                    */
/*   out_apdu                  Pointer of SC-APDU         */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*			       The APDU has the structure:*/
/*		                _________________         */
/*			       | L,DATA,SW1,SW2  |        */
/*		                _________________         */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESDEC  		  */
/*				ESSC			  */
/*				EALGO			  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_decrypt                                          */
/*   aux_fxdump                                       */
/*   sta_aux_bytestr_free			          */
/*   aux_free2_OctetString				  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
SCTdec(sec_key, ssc, in_apdu, out_apdu, algenc)
	BitString      *sec_key;/* secure messaging key */
	int             ssc;	/* Send sequence Counter */
	Bytestring     *in_apdu;/* SEC-APDU		 */
	Bytestring     *out_apdu;	/* SC-APDU		 */
	AlgEnc         algenc;	/* encryption method		 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     out_octets;
	char           *ptr, *apdu_ptr;
	int             i;
	int             memolen;
	BitString       in_bits;
	KeyInfo         key_info;
	More            more;
	int             rec_ssc, data_len;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

#ifdef STREAM
	fprintf(sct_trfp, "TRACE in SCTdec\n");
	fprintf(sct_trfp, "   sec_key.nbits     = %d\n", sec_key->nbits);
	fprintf(sct_trfp, "   sec_key.bits      = \n");
	aux_fxdump(sct_trfp, sec_key->bits, sec_key->nbits / 8, 0);
	fprintf(sct_trfp, "   in_apdu->nbytes   = %d\n", in_apdu->nbytes);
	fprintf(sct_trfp, "   in_apdu->bytes    = \n");
	aux_fxdump(sct_trfp, in_apdu->bytes, in_apdu->nbytes, 0);
#endif

	/*---------------------------------------------------------*/
	/* decrypt data                                            */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/
	/* allocate memory for out_octets  */
	out_octets.noctets = 0;

#ifdef MALLOC
	out_octets.octets = malloc(in_apdu->nbytes);	/* will be set free in
							 * this proc. */
	if (out_octets.octets == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		return (-1);
	}
#endif

	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		aux_free2_OctetString(&out_octets);
		sct_errno = EALGO;
		sct_errmsg = sct_error[sct_errno].msg;
		return (-1);
		break;
	}
	more = END;

	in_bits.nbits = in_apdu->nbytes * 8;
	in_bits.bits = in_apdu->bytes;
	more = END;
	memolen = des_decrypt(&in_bits, &out_octets, more, &key_info);

	if (memolen == -1) {
		sct_errno = EDESDEC;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&out_octets);
		return (-1);
	}
#ifdef STREAM
	fprintf(sct_trfp, "   out_octets.noctets= %d\n", out_octets.noctets);
	fprintf(sct_trfp, "   out_octets.octets = \n");
	aux_fxdump(sct_trfp, out_octets.octets, out_octets.noctets, 0);
#endif

	/* CONCEALED-Mode -> Test SSC; return L,DATA,SW1,SW2 */
	/* allocate out_data->bytes */
	out_apdu->nbytes = *out_octets.octets + 3;	/* 4 = L,DATA,SW1,SW2 */

#ifdef MALLOC
	out_apdu->bytes = malloc(out_apdu->nbytes);	/* if no error => return */
	/* else will be set free in this proc. */
	if (out_apdu->bytes == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&out_octets);
		return (-1);
	}
#endif

	/* copy L,DATA,SW1,SW2 from out_octets.octets into out_apdu->bytes */
	ptr = out_apdu->bytes;
	apdu_ptr = out_octets.octets;
	*ptr = *apdu_ptr++;	/* Length-field */
	data_len = *ptr;
	ptr++;
	rec_ssc = *apdu_ptr++ & 0xFF;	/* SSC		 */

#ifdef STREAM
	fprintf(sct_trfp, "   rec_ssc           = %x\n", (rec_ssc & 0xFF));
	fprintf(sct_trfp, "   akt_ssc           = %x\n", (ssc & 0xFF));
#endif

	/* check SSC	 */
	if (rec_ssc != (ssc & 0xFF)) {
		sct_errno = ESCT_SSC;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&out_octets);
		sta_aux_bytestr_free(out_apdu);
		return (-1);
	}
	for (i = 0; i < data_len + 2; i++) {	/* Data, SW1, SW2 */
		*ptr = *apdu_ptr++;
		ptr++;
	}

	aux_free2_OctetString(&out_octets);

#ifdef STREAM
	fprintf(sct_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sct_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sct_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sct_trfp, "TRACE-END in SCTdec\n");
#endif

	return (0);



}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTdec                 */
/*-------------------------------------------------------------*/





/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTalloc            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Allocate buffer                                       */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   datalen                   length of datafield        */
/*                                                        */
/*   secure                    secure messaging           */
/*                                                        */
/* OUT                                                    */
/*   pdulen                     length of s_apdu          */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   pointer                   o.k.                       */
/*                                                        */
/*   NULL                      error                      */
/*                              EMEMAVAIL;                */
/*--------------------------------------------------------*/
static char    *
SCTalloc(datalen, secure, pdulen)
	unsigned int    datalen;
	SecMess        *secure;
	unsigned int   *pdulen;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *buffer = NULL;
	unsigned int    modulus;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if (datalen < 255)
		*pdulen = datalen + LHEADER + LEN1;
	else
		*pdulen = datalen + LHEADER + LEN3;

	/*--------------------------------------------------*/
	/* test secure messaging			       */
	/*--------------------------------------------------*/
	if (secure->command != SEC_NORMAL)
		(*pdulen)++;	/* 1 Byte for SSC */



#ifdef MALLOC
	buffer = malloc(*pdulen);	/* if no error => return 		 */
	if (buffer == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
	}
#endif

#ifdef MEMTRACE
	fprintf(sct_trfp, "PDULEN in SCTalloc = %d\n", *pdulen);
#endif


	return (buffer);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTalloc               */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTbytestring       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create datafield in APDU                              */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                       Pointer of APDU-buffer    */
/*                                                        */
/*   data                       Pointer of data           */
/*                                                        */
/*   len                        length  of data           */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
SCTbytestring(apdu, data)
	char          **apdu;
	Bytestring     *data;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	int             i;
	char           *p;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	if (data != BYTENULL) {
		for (i = 0; i < data->nbytes; i++) {
			*p = *(data->bytes + i);
			p++;
		};
	}
	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTbytestring          */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTparam            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create Parameter in APDU                              */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                       Pointer of APDU-buffer    */
/*                                                        */
/*   p1                         first parameter           */
/*                                                        */
/*   p2                         second parameter          */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
SCTparam(apdu, p1, p2)
	char          **apdu;
	unsigned int    p1;
	unsigned int    p2;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;

	*p++ = p1;
	*p++ = p2;
	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTparam               */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTplength          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create Length in APDU                                 */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                       Pointer of APDU-buffer    */
/*                                                        */
/*   datalen                    length of datafield       */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
SCTplength(apdu, ldata)
	char          **apdu;
	unsigned int    ldata;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	if (ldata < 255)
		*p++ = ldata;
	else {
		*p++ = 0xFF;
		*p++ = ldata >> 8;
		*p++ = ldata;
	};
	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTplength             */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTbinval           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create binary value in APDU                           */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                       Pointer of APDU-buffer    */
/*                                                        */
/*   value                      integer value             */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*                                                        */
/*--------------------------------------------------------*/
static void
SCTbinval(apdu, binval)
	char          **apdu;
	unsigned int    binval;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	if (binval < 255)
		*p++ = binval;
	else {
		*p++ = binval >> 8;
		*p++ = binval;
	};
	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTbinval              */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTppublic          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter public in APDU                       */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   public                    Pointer of public structure*/
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTplength                                           */
/*   SCTbytestring                                        */
/*--------------------------------------------------------*/
static void
SCTppublic(apdu, public)
	char          **apdu;
	Public         *public;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	if (public != PUBNULL) {
		if (public->modulus == BYTENULL)
			SCTplength(&p, S_NOTUSED);
		else
			SCTplength(&p, public->modulus->nbytes);
		SCTbytestring(&p, public->modulus);
		if (public->exponent == BYTENULL)
			SCTplength(&p, S_NOTUSED);
		else
			SCTplength(&p, public->exponent->nbytes);
		SCTbytestring(&p, public->exponent);
	};

	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTppublic             */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTdevkeyinfo       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter DevKeyInfo  in APDU                  */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   devkeyinfo                Pointer of DevKeyInfo      */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
SCTdevkeyinfo(apdu, devkeyinfo)
	char          **apdu;
	DevKeyInfo     *devkeyinfo;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	unsigned        purpose;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;

	purpose = (unsigned) devkeyinfo->purpose.sec_mess_con << 3 |
		((unsigned) devkeyinfo->purpose.sec_mess_auth << 1) |
		(unsigned) devkeyinfo->purpose.authenticate;
	*p++ = (char) purpose;

	*p++ = (char) devkeyinfo->status;

	*p++ = (char) devkeyinfo->type;

	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTdevkeyinfo          */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTpininfo          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter PINinfo  in APDU                     */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   pininfo                   Pointer of PINinfo         */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTbinval                                            */
/*   e_KeyAttrList                                        */
/*   SCTplength                                           */
 /* SCTbytestring                                        *//*--------------------------------------------------------*/
static void
SCTpininfo(apdu, pininfo)
	char          **apdu;
	PINRecord      *pininfo;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;

	SCTbinval(&p, pininfo->pin_attr->key_inst_mode);

	e_KeyAttrList(&p, pininfo->pin_attr, pininfo->key_algid);


	SCTplength(&p, pininfo->pin_record->nbytes);


	SCTbytestring(&p, pininfo->pin_record);



	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTpininfo             */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTsessionkey       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter SessionKey  in APDU                  */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   sessionkey                Pointer of SessionKey      */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTplength                                           */
 /* SCTbytestring                                        *//*--------------------------------------------------------*/
static void
SCTsessionkey(apdu, sessionkey)
	char          **apdu;
	SessionKey     *sessionkey;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;

	*p++ = (char) sessionkey->sec_mode;

	*p++ = (char) sessionkey->com_line;

	SCTplength(&p, sessionkey->session_key->nbytes);

	SCTbytestring(&p, sessionkey->session_key);

	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTsessionkey          */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTwritekeycard     VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter WriteKeycard  in APDU                */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   keycard                   Pointer of WriteKeycard    */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTpurpose                                           */
/*   SCTplength                                           */
 /* SCTbytestring                                        *//*--------------------------------------------------------*/
static void
SCTwritekeycard(apdu, keycard, status)
	char          **apdu;
	WriteKeycard   *keycard;
	KeyDevStatus    status;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	unsigned        purpose1;
	unsigned        purpose2;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

#ifdef OLDIMPL
	p = *apdu;
	if (status == DEV_OWN) {
		purpose1 = SCTpurpose(&keycard->key2->pval.purpose);
		purpose2 = SCTpurpose(&keycard->key3->pval.purpose);
	} else {
		purpose1 = (unsigned) keycard->key2->pval.kid;
		purpose2 = (unsigned) keycard->key3->pval.kid;
	};


	SCTplength(&p, keycard->pin_record->nbytes);

	SCTbytestring(&p, keycard->pin_record);

	if (keycard->key2_status == TRUE) {
		*p++ = purpose1;
		if (keycard->key3_status == TRUE)
			*p++ = purpose2;
	};


	*apdu = p;
#endif
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTwritekeycard        */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTpurpose          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter purpose                              */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   purpose                   Pointer of purpose structure*/
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   purpose                   value of purpose byte      */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
static unsigned int
SCTpurpose(key_purpose)
	KeyPurpose     *key_purpose;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned        purpose;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	purpose = (unsigned) key_purpose->sec_mess_con << 3 |
		((unsigned) key_purpose->sec_mess_auth << 1) |
		(unsigned) key_purpose->authenticate;


	return (purpose);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTpurpose             */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTssc              VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  if secure messaging -> then create ssc in APDU        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   p_elem                    Pointer of portparam       */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
SCTssc(apdu, p_elem)
	char          **apdu;
	struct s_portparam *p_elem;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	if (p_elem->secure_messaging.command != SEC_NORMAL) {
		if (p_elem->ssc != 0)
			p_elem->ssc = p_elem->ssc % 256;

		*p++ = p_elem->ssc;
		p_elem->ssc++;
	}
	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTssc                 */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTclass            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  generate class byte for the SCT commands      /       */
/*  the security parameter for S_CHANGE_PIN, S_AUTH       */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   p_elem                    Pointer of portparam       */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   class-byte                value of the class-byte    */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
static unsigned int
SCTclass(security)
	SecMess        *security;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    class;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	class = NON_INTER;

	if (security->command != SEC_NORMAL)
		class |= (unsigned) security->command << 2;

	if (security->response != SEC_NORMAL)
		class |= (unsigned) security->response;


	return (class);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCTclass               */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTwithNMdata       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create APDU (P1,P2,Data); Datafield ist not mandatory */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   p_elem                   pointer of portparam struct.*/
/*                                                        */
/*   p1                         Parameter 1               */
/*                                                        */
/*   p2                         parameter 2               */
/*                                                        */
/*   data                       datafield (Bytestring)    */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*   lapdu                      length of APDU-Buffer     */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   Pointer                   Pointer to APDU-buffer     */
/*                                                        */
/*   NULL                      error                      */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTalloc                  ERROR-Codes                */
/*                              EMEMAVAIL;                */
/*   SCTparam                                             */
/*   SCTplength                                           */
/*   SCTssc                                               */
/*   SCTbytestring                                        */
/*--------------------------------------------------------*/
static char    *
SCTwithNMdata(p_elem, p1, p2, data, lapdu)
	struct s_portparam *p_elem;
	unsigned int    p1;
	unsigned int    p2;
	Bytestring     *data;
	unsigned int   *lapdu;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *apdu;
	char           *p;
	unsigned int    ldata;
	unsigned int    len;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((data == BYTENULL) || (data->bytes == NULL))
		ldata = 0;
	else
		ldata = data->nbytes;

	if ((apdu = SCTalloc(ldata, &p_elem->secure_messaging, &len)) != NULL) {

		p = apdu + 2;

		SCTparam(&p, p1, p2);

		SCTplength(&p, ldata);
		SCTssc(&p, p_elem);
		SCTbytestring(&p, data);

		*lapdu = len;
	};
	return (apdu);

}



/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       SCTwithNMdata         */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCTwithMdata        VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create APDU (P1,P2,Data); datafield ist mandatory     */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   p_elem                   pointer of portparam struct.*/
/*                                                        */
/*   p1                         Parameter 1               */
/*                                                        */
/*   p2                         parameter 2               */
/*                                                        */
/*   data                       datafield (Bytestring)    */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*   lapdu                      length of APDU-Buffer     */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   Pointer                   Pointer to APDU-buffer     */
/*                                                        */
/*   NULL                      error                      */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTalloc                  ERROR-Codes                */
/*                              EMEMAVAIL;                */
/*   SCTparam                                             */
/*   SCTplength                                           */
/*   SCTssc                                               */
/*   SCTbytestring                                        */
/*--------------------------------------------------------*/
static char    *
SCTwithMdata(p_elem, p1, p2, data, lapdu)
	struct s_portparam *p_elem;
	unsigned int    p1;
	unsigned int    p2;
	Bytestring     *data;
	unsigned int   *lapdu;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *apdu;
	char           *p;
	unsigned int    ldata;
	unsigned int    len;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((data == BYTENULL) || (data->bytes == NULL) || (data->nbytes == 0)) {
		sct_errno = EPARMISSED;
		sct_errmsg = sct_error[sct_errno].msg;
		return (NULL);
	};
	ldata = data->nbytes;


	if ((apdu = SCTalloc(ldata, &p_elem->secure_messaging, &len)) != NULL) {
		p = apdu + 2;

		SCTparam(&p, p1, p2);

		SCTplength(&p, ldata);
		SCTssc(&p, p_elem);
		SCTbytestring(&p, data);

		*lapdu = len;
	};
	return (apdu);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       SCTwithMdata          */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC   SCTnodata          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create APDU without datafield                         */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   p_elem                   pointer of portparam struct.*/
/*                                                        */
/*   p1                         Parameter 1               */
/*                                                        */
/*   p2                         parameter 2               */
/*                                                        */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*   lapdu                      length of APDU-Buffer     */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   Pointer                   Pointer to APDU-buffer     */
/*                                                        */
/*   NULL                      error                      */
/*                                                        */
/* CALLED FUNCTIONS                                       */
/*   SCTalloc                  ERROR-Codes                */
/*                              EMEMAVAIL;                */
/*   SCTssc                                               */
/*--------------------------------------------------------*/
static char    *
SCTnodata(p_elem, p1, p2, lapdu)
	struct s_portparam *p_elem;
	unsigned int    p1;
	unsigned int    p2;
	unsigned int   *lapdu;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *apdu;
	char           *p;
	unsigned int    ldata = 0;
	unsigned int    len;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((apdu = SCTalloc(ldata, &p_elem->secure_messaging, &len)) != NULL) {

		p = apdu + 2;
		*p++ = p1;
		*p++ = p2;
		*p++ = ldata;

		SCTssc(&p, p_elem);

		*lapdu = len;
	};
	return (apdu);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       SCTnodata             */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  LofPublic           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  calculate length of public - structure                */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   public                    Pointer of public structure*/
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   len                       length of data             */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
static unsigned int
LofPublic(public)
	Public         *public;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    len = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if (public == PUBNULL)
		return (len);

	if (public->modulus != BYTENULL) {
		len += public->modulus->nbytes;
		if (len >= 255)
			len += 2;
	};
	len++;
	if (public->exponent != BYTENULL) {
		if (public->exponent->nbytes >= 255)
			len += 2;
		len += public->exponent->nbytes;
	};
	len++;

	return (len);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      LofPublic              */
/*-------------------------------------------------------------*/

#ifdef OLDIMPL


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  LofKeycard          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  calculate length of datafield                         */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*                                                        */
/*   keycard                   Pointer of WriteKeycard    */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   len                        length                    */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
static unsigned int
LofKeycard(keycard)
	WriteKeycard   *keycard;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    len = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	len = keycard->pin_record->nbytes + 1;

	if (keycard->key2_status == TRUE)
		len++;


	if (keycard->key3_status == TRUE)
		len++;

	return (len);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      LofKeycard             */
/*-------------------------------------------------------------*/
#endif


/*-------------------------------------------------------------*/
/* E N D   O F   P A C K A G E       sctloc                    */
/*-------------------------------------------------------------*/
