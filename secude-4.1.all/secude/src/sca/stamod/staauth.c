/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 1.0		                             +-----*/
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-staauth                              VERSION 1.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	staauth.c                       		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides all functions for user authentication and device       */
/*      authentication of the smartcard application interface (SCA-IF).            */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*      Functions for User Authentication					   */
/*	sca_inst_pin()	       Install PIN on the smartcard		           */
/*							                           */
/*	sca_change_pin()       Change PIN 			                   */
/*							                           */
/*	sca_check_pin()        PIN authentication		 	           */
/*							                           */
/*	sca_unblock_pin()      Unblock a blocked PIN                               */
/*							                           */
/*      Functions for Device Authentication					   */
/*	sca_auth()    	       Device authentication                               */
/*							                           */
/*	sca_gen_dev_key()      Generate device key                                 */
/*      									   */
/*	sca_inst_dev_key()     Install device key on user smartcard                */
/*      									   */
/*	sca_del_dev_key()      Delete device key in SCT                            */
/*      									   */
/*	sca_read_keycard()     Read key(s) from keycard                            */
/*      									   */
/*	sca_write_keycard()    Write key(s) on keycard                             */
/*      									   */
/*      									   */
/*                                                                                 */
/*    IMPORT		    DESCRIPTION 		                           */
/*                                 -  aux_xdmp.c (libcrypt)                        */
/*                                                                                 */
/*	aux_fxdump()                  dump buffer in File	                   */
/*							                           */
/*							                           */
/*                                 -  sta_free.c (libsm)                           */
/*                                                                                 */
/*      sta_aux_bytestr_free()        set the bytes-buffer in Bytestring free      */
/*                                                                                 */
/*                                 -  sctint.c (libsm)                             */
/*      sct_interface()               Send SCT command / receive SCT response      */
/*							                           */
/*      sct_errno                     global error variable set by SCT-interface   */
/*							                           */
/*      sct_errmsg                    global pointer to error message set by       */
/*                                    SCT-interface                                */
/*                                                                                 */
/*				   -  sta_dev.c (libsm)                            */
/*                                                                                 */
/*      get_sct_keyid()               check key_id and get key_id in char          */
/*				      representation                               */
/*							                           */
/*      get_sct_algid()	              check alg_id and get SCT specific alg_id     */
/*                                                                                 */
/*      check_sct_sc()                check SCT and SC                             */
/*                                                                                 */
/*      check_key_attr_list()         check key attribute list                     */
/*                                                                                 */
/*      check_sec_mess()              check security mode(s) for command and response*/
/*                                                                                 */
/*      set_errmsg()                  set sca_errmsg                               */
/*                                                                                 */
/*      err_analyse()                 error analyse and handling                   */
/*                                                                                 */
/*      sca_errno                     global error variable set by STAMOD          */
/*                                                                                 */
/*      sca_errmsg                    global pointer to error message set by STAMOD*/
/*                                                                                 */
/*                                                                                 */
/*				   -  stacrypt.c (libsm)                           */
/*                                                                                 */
/*				   -  stasc.c (libsm)                              */
/*                                                                                 */
/*	get_bits()		      get bits			                   */
/*                                                                                 */
/*                                                                                 */
/*				   -  staprint.c   (libsm) for TEST-output         */
/*                                                                                 */
/*      print_keyid()							           */
/*      print_keydevpurpose()                                                      */
/*      print_keydevsel()                                                          */
/*      print_keyattrlist()                                                        */
/*      print_pinstruc()                                                           */
/*      print_secmess()                                                            */
/*                                                                                 */
/*                                                                                 */
/*                                                                                 */
/*                                                                                 */
/*                                                                                 */
/*    INTERNAL                                                                     */
/*                                                                                 */
/*      get_PIN_PUK_body()     compose PIN or PUK body for the PIN installation    */
/*                                                                                 */
/*                                                                                 */
/*---------------------------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files					       */
/*-------------------------------------------------------------*/
#include "stamod.h"
#include "stamsg.h"
#include "sctint.h"
#include "sccom.h"
#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#endif /* !MAC */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/
extern char     get_sct_keyid();
extern char     get_sct_algid();
extern int      get_alg_number();
extern int      check_sct_sc();
extern int      check_key_attr_list();
extern int      check_sec_mess();
extern int      set_errmsg();
extern void
                err_analyse();
extern int      sct_interface();
extern void     sta_aux_bytestr_free();
extern unsigned int get_bits();
extern void     aux_fxdump();
extern unsigned int sct_errno;	/* error number set by SCT-Interface */
extern char    *sct_errmsg;	/* pointer to error msg set by      */

 /* SCT-Interface                    */
extern unsigned int sca_errno;	/* error number set by STAMOD       */
extern char    *sca_errmsg;	/* pointer to error msg set by      */

 /* STAMOD                           */


#ifdef TEST
extern void     print_keyid();
extern void     print_keydevpurpose();
extern void     print_keydevsel();
extern void     print_keyattrlist();
extern void     print_pinstruc();
extern void     print_keydevlist();
extern void     print_secmess();

#endif

/*-------------------------------------------------------------*/
/*   globale variable definitions			       */
/*-------------------------------------------------------------*/






/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*   local Variable definitions			               */
/*-------------------------------------------------------------*/
static Request  request;	/* body of the SCT commands         */
static Bytestring response;	/* body of the response of the SCT  */
static int      command;	/* INS-Code of the SCT command      */
static Boolean  sc_expect;	/* = TRUE indicates: SC expected    */

 /* = FALSE indicates: SC not needed */
static KindOfKey kind_of_key;	/* {USER_KEY, PIN_KEY, PUK_KEY,     */

 /* DEVICE}                         */


/*-------------------------------------------------------------*/
/*   forward global declarations			       */
/*-------------------------------------------------------------*/
static int      get_PIN_PUK_body();



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_inst_pin	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Install Personal Identification Number (PIN) on the        */
/*  smartcard.                                                 */
/*  A smartcard must be inserted.		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id	               key_id of the PIN to be         */
/*                             installed	               */
/*                                                             */
/*   pin	               Structure which determines the  */
/*                             PIN to be installed             */
/*                                                             */
/*   key_attr_list             Structure which contains        */
/*                             additional information for      */
/*                             storing a PIN on the SC         */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EINVKID		       */
/*				 M_EPIN			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  check_key_attr_list        ERROR-Codes		       */
/*			         M_EKEYATTR		       */
/*							       */
/*  get_PIN_PUK_body           ERROR-Codes                     */
/*                               M_EMEMORY		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_inst_pin(sct_id, key_id, pin, key_attr_list)
	int             sct_id;
	KeyId          *key_id;
	PINStruc       *pin;
	KeyAttrList    *key_attr_list;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	PINRecord       pin_record;
	Bytestring      pin_body;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_inst_pin *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keyid(key_id);
	print_pinstruc(pin);
	print_keyattrlist(key_attr_list);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check key_id				       */
	/*-----------------------------------------------------*/
	if ((key_id->key_level != SC_MF) &&
	    (key_id->key_level != SC_DF) &&
	    (key_id->key_level != SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((key_id->key_number < 1) ||
	    (key_id->key_number > MAX_KEYID)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)	/* get char from key_id */
		return (-1);

	/*-----------------------------------------------------*/
	/* Check pin record				       */
	/*-----------------------------------------------------*/
	if (pin->pin_type == PIN) {	/* check PIN */
		kind_of_key = PIN_KEY;
		if ((pin->PINBody.pin_info.min_len < 0) ||
		    (pin->PINBody.pin_info.min_len > MAXL_PIN)) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if (pin->PINBody.pin_info.pin == NULL) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		} else if (strlen(pin->PINBody.pin_info.pin) > MAXL_PIN) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if (pin->PINBody.pin_info.clear_pin != NULL) {
			if (strlen(pin->PINBody.pin_info.clear_pin) > MAXL_PIN) {
				sca_errno = M_EPIN;
				set_errmsg();
				return (-1);
			}
		}
	} else if (pin->pin_type == PUK) {	/* check PUK */
		kind_of_key = PUK_KEY;
		if (pin->PINBody.puk_info.puk == NULL) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		} else if (strlen(pin->PINBody.puk_info.puk) > MAXL_PIN) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if ((pin->PINBody.puk_info.pin_key_id.key_level != SC_MF) &&
		    (pin->PINBody.puk_info.pin_key_id.key_level != SC_DF) &&
		    (pin->PINBody.puk_info.pin_key_id.key_level != SC_SF)) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if ((pin->PINBody.puk_info.pin_key_id.key_number < 1) ||
		(pin->PINBody.puk_info.pin_key_id.key_number > MAX_KEYID)) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
	} else {		/* no PIN, no PUK */
		sca_errno = M_EPIN;
		set_errmsg();
		return (-1);
	}

	/*-----------------------------------------------------*/
	/* Check key_attr_list			       */
	/*-----------------------------------------------------*/
	if (check_key_attr_list(kind_of_key, key_attr_list) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_INST_PIN;
	request.rq_p1.kid = sct_keyid;

	if (pin->pin_type == PIN)
		pin_record.key_algid = S_PIN;
	else
		pin_record.key_algid = S_PUK;
	pin_record.pin_attr = key_attr_list;

	rc = get_PIN_PUK_body(pin, &pin_body);
	if (rc == -1)
		return (-1);
	pin_record.pin_record = &pin_body;

#ifdef TEST
	fprintf(stdout, "pin_record->bytes: \n");
	aux_fxdump(stdout, pin_record.pin_record->bytes, pin_record.pin_record->nbytes, 0);
	fprintf(stdout, "\n");
#endif

	request.rq_datafield.pin = &pin_record;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		sta_aux_bytestr_free(&pin_body);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&pin_body);
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_inst_pin *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_inst_pin */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_inst_pin	       */
/*-------------------------------------------------------------*/





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_change_pin	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Change PIN value on the smartcard                          */
/*  A smartcard must be inserted.		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id	               key_id of the PIN to be         */
/*                             changed		               */
/*                                                             */
/*   sec_mess	               Specification of the security   */
/*			       mode(s) for the command and     */
/*			       response exchange between SCT   */
/*			       and smartcard.                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EINVKID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  check_sec_mess             ERROR-Codes		       */
/*			         M_ESECMESS		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_change_pin(sct_id, key_id, sec_mess)
	int             sct_id;
	KeyId          *key_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_change_pin *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keyid(key_id);
	print_secmess(sec_mess);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check key_id				       */
	/*-----------------------------------------------------*/
	if ((key_id->key_level != SC_MF) &&
	    (key_id->key_level != SC_DF) &&
	    (key_id->key_level != SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((key_id->key_number < 1) ||
	    (key_id->key_number > MAX_KEYID)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)	/* get char from key_id */
		return (-1);

	/*-----------------------------------------------------*/
	/* Check sec_mess parameter			       */
	/*-----------------------------------------------------*/
	if (check_sec_mess(sec_mess) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_CHANGE_PIN;
	request.rq_p1.kid = sct_keyid;
	request.rq_p2.sec_mode = sec_mess;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_change_pin *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_change_pin */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_change_pin	       */
/*-------------------------------------------------------------*/





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_check_pin	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  PIN authentication			                       */
/*  A smartcard must be inserted.		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id	               key_id of the PIN to be         */
/*                             changed		               */
/*                                                             */
/*   sec_mess	               Specification of the security   */
/*			       mode(s) for the command and     */
/*			       response exchange between SCT   */
/*			       and smartcard.                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EINVKID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  check_sec_mess             ERROR-Codes		       */
/*			         M_ESECMESS		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_check_pin(sct_id, key_id, sec_mess)
	int             sct_id;
	KeyId          *key_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_check_pin *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keyid(key_id);
	print_secmess(sec_mess);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check key_id				       */
	/*-----------------------------------------------------*/
	if ((key_id->key_level != SC_MF) &&
	    (key_id->key_level != SC_DF) &&
	    (key_id->key_level != SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((key_id->key_number < 1) ||
	    (key_id->key_number > MAX_KEYID)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)	/* get char from key_id */
		return (-1);

	/*-----------------------------------------------------*/
	/* Check sec_mess parameter			       */
	/*-----------------------------------------------------*/
	if (check_sec_mess(sec_mess) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
	request.rq_p1.kid = sct_keyid;
	request.rq_p2.acp = PIN_USER;
	request.rq_datafield.auth_secmode = sec_mess;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_check_pin *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_check_pin */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_check_pin	       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_unblock_pin	  VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Unblock a blocked PIN		                       */
/*  A smartcard must be inserted.		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id	               key_id of the PIN to be         */
/*                             changed		               */
/*                                                             */
/*   sec_mess	               Specification of the security   */
/*			       mode(s) for the command and     */
/*			       response exchange between SCT   */
/*			       and smartcard.                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EINVKID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  check_sec_mess             ERROR-Codes		       */
/*			         M_ESECMESS		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_unblock_pin(sct_id, key_id, sec_mess)
	int             sct_id;
	KeyId          *key_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_unblock_pin *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keyid(key_id);
	print_secmess(sec_mess);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check key_id				       */
	/*-----------------------------------------------------*/
	if ((key_id->key_level != SC_MF) &&
	    (key_id->key_level != SC_DF) &&
	    (key_id->key_level != SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((key_id->key_number < 1) ||
	    (key_id->key_number > MAX_KEYID)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)	/* get char from key_id */
		return (-1);

	/*-----------------------------------------------------*/
	/* Check sec_mess parameter			       */
	/*-----------------------------------------------------*/
	if (check_sec_mess(sec_mess) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
	request.rq_p1.kid = sct_keyid;
	request.rq_p2.acp = PUK_CHECK;
	request.rq_datafield.auth_secmode = sec_mess;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_unblock_pin *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_unblock_pin */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_unblock_pin	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_auth		  VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Device authentication		                       */
/*  A smartcard must be inserted.		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   auth_proc_id              Identifier of the authentication*/
/*			       procedure:                      */
/*                             des_auth (4)	               */
/*                                                             */
/*   auth_object_id            Identifier of the object to be  */
/*			       authenticated:                  */
/*			       smartcard (2),		       */
/*			       sct (3),			       */
/*			       sct_sc (5),		       */
/*			       INITIAL (6),		       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EPROCID		       */
/*				 M_EOBJECTID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				  ENOSHELL		       */
/*                                EOPERR                       */
/*			          EEMPTY                       */
/*                                ECLERR                       */
/*                                ESIDUNK                      */
/*                                ERDERR                       */
 /* */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_auth(sct_id, auth_proc_id, auth_object_id)
	int             sct_id;
	AuthProcId      auth_proc_id;
	AuthObjectId    auth_object_id;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	unsigned int    acp;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_auth *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	fprintf(stdout, "auth_proc_id           : %d\n", auth_proc_id);
	fprintf(stdout, "auth_object_id         : %d\n", auth_object_id);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check auth_proc_id and auth_object_id and 	       */
	/* set acp					       */
	/*-----------------------------------------------------*/
	if (auth_proc_id == des_auth) {
		if (auth_object_id == smartcard)
			acp = SC_DES;
		else if (auth_object_id == sct)
			acp = SCT_DES;
		else if (auth_object_id == sct_sc)
			acp = SC_SCT_DES;
		else if (auth_object_id == INITIAL)
			acp = SCT_INITIAL;
		else {
			sca_errno = M_EOBJECTID;
			set_errmsg();
			return (-1);
		}
	}
	/* end if (auth_proc_id == des_auth) */
	else {
		sca_errno = M_EPROCID;
		set_errmsg();
		return (-1);
	}			/* end else */


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
	request.rq_p1.kid = 0x00;
	request.rq_p2.acp = acp;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_auth *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_auth */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_auth	       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_gen_dev_key         VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Generate device key (DES )		                       */
/*							       */
/*						               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id                    Key-id    which determines the  */
/*                             generated key.                  */
/*                                                             */
/*   alg_id                    Algorithm Identifier            */
/*			       The following values are        */
/*			       possible:		       */
/*			       desCBC			       */
/*                                                             */
/*   key_dev_purpose           Structure which contains        */
/*                             the purpose, the status and     */
/*                             the type of the generated key   */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EINVKID		       */
/*				 EINVALGID		       */
/*				 M_EKEYDEV		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_algid              ERROR-Codes		       */
/*			         EINVALGID		       */
/*				 EKEYLENINV		       */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  get_alg_number             ERROR-Codes		       */
/*  (only in case of TEST)	 EINVALGID		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_gen_dev_key(sct_id, key_id, alg_id, key_dev_purpose)
	int             sct_id;
	KeyId          *key_id;
	AlgId          *alg_id;
	KeyDevPurpose  *key_dev_purpose;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	KeyAlgId        sct_algid;	/* SCT specific alg_id		     */
	DevKeyInfo      sct_devkeyinfo;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_gen_dev_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keyid(key_id);

	switch (aux_ObjId2AlgEnc(alg_id->objid)) {
	case DES:
		fprintf(stdout, "alg_id                  : DES-CBC\n");
		break;
	default:
		fprintf(stdout, "alg_id                  : not supported\n");
		break;
	}

	print_keydevpurpose(key_dev_purpose);
#endif


	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* check key_id and get keyid in char representation  */
	/*-----------------------------------------------------*/
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)
		return (-1);
	if (key_id->key_level == SCT) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check algid and get sct specific alg_id            */
	/*-----------------------------------------------------*/
	if ((sct_algid = get_sct_algid(alg_id)) == -1)
		return (-1);
	if (sct_algid != S_DES_CBC) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check key_dev_purpose                              */
	/*-----------------------------------------------------*/
	if (key_dev_purpose == NULL) {
		sca_errno = M_EKEYDEV;
		set_errmsg();
		return (-1);
	}
	if (((key_dev_purpose->key_purpose.authenticate != TRUE) &&
	     (key_dev_purpose->key_purpose.authenticate != FALSE)) ||
	    ((key_dev_purpose->key_purpose.sec_mess_auth != TRUE) &&
	     (key_dev_purpose->key_purpose.sec_mess_auth != FALSE)) ||
	    ((key_dev_purpose->key_purpose.sec_mess_con != TRUE) &&
	     (key_dev_purpose->key_purpose.sec_mess_con != FALSE)) ||
	    (key_dev_purpose->key_dev_status != DEV_ANY) ||
	    (key_dev_purpose->key_type != MASTER)) {
		sca_errno = M_EKEYDEV;
		set_errmsg();
		return (-1);
	}
	if ((key_dev_purpose->key_purpose.authenticate == FALSE) &&
	    (key_dev_purpose->key_purpose.sec_mess_auth == FALSE) &&
	    (key_dev_purpose->key_purpose.sec_mess_con == FALSE)) {
		sca_errno = M_EKEYDEV;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/



	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, FALSE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Generate key (S_GEN_DEV_KEY)		       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/* */
	/*-----------------------------------------------------*/
	command = S_GEN_DEV_KEY;
	request.rq_p1.kid = sct_keyid;
	request.rq_p2.algid = sct_algid;
	sct_devkeyinfo.purpose = key_dev_purpose->key_purpose;
	sct_devkeyinfo.status = key_dev_purpose->key_dev_status;
	sct_devkeyinfo.type = key_dev_purpose->key_type;
	request.rq_datafield.dev_key_info = &sct_devkeyinfo;



	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* (Release storage)				       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_gen_dev_key *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_gen_dev_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_gen_dev_key        */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_inst_dev_key         VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Install device key (DES )	on SC	                       */
/*							       */
/*						               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_dev_sel               Structure which determines the  */
/*                             device key.                     */
/*   key_attr_list             Structure which contains        */
/*                             additional information for      */
/*                             storing the device key on       */
/*			       the SC                          */
/*                                                             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EPAR	        	       */
/*				 EINVKID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  check_key_attr_list        ERROR-Codes		       */
/*			         M_EKEYATTR		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_inst_dev_key(sct_id, key_dev_sel, key_attr_list)
	int             sct_id;
	KeyDevSel      *key_dev_sel;
	KeyAttrList    *key_attr_list;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	DevInstKey      sct_devinstkey;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_inst_dev_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keydevsel(key_dev_sel);
	print_keyattrlist(key_attr_list);
#endif


	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* check key_dev_sel                                  */
	/*-----------------------------------------------------*/
	if (key_dev_sel == NULL) {
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check key_status and Key_id (only DEV_ANY allowed)     */
	/*-----------------------------------------------------*/
	switch (key_dev_sel->key_status) {
	case DEV_ANY:

		if ((sct_keyid = get_sct_keyid(&key_dev_sel->dev_ref.key_id)) == -1)
			return (-1);
		if (key_dev_sel->dev_ref.key_id.key_level == SCT) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		};

		sct_devinstkey.pval.kid = sct_keyid;
		break;

	default:
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	}

	/*-----------------------------------------------------*/
	/* key shall be installed on the SC,                  */
	/* then - check key attribute list                 */
	/*-----------------------------------------------------*/

	if (check_key_attr_list(DEVICE_KEY, key_attr_list) == -1)
		return (-1);



/************** input parameter check done *********************************/
	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, TRUE) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* Generate key (S_INST_DEV_KEY)		       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/* */
	/*-----------------------------------------------------*/
	command = S_INST_DEV_KEY;
	request.rq_p1.dev_inst_key = &sct_devinstkey;
	request.rq_p2.status = key_dev_sel->key_status;
	request.rq_datafield.keyattrlist = key_attr_list;



	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* (Release storage)				       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);


#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_inst_dev_key *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_inst_dev_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_inst_dev_key        */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_del_dev_key         VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Delete device key (DES )	in SCT	                       */
/*							       */
/*						               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_dev_sel               Structure which determines the  */
/*                             device key.                     */
/*                                                             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EKEYDEV		       */
/*				 EINVKID		       */
/*				 M_EPAR 		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_del_dev_key(sct_id, key_dev_sel)
	int             sct_id;
	KeyDevSel      *key_dev_sel;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	DevInstKey      sct_devinstkey;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_del_dev_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_keydevsel(key_dev_sel);
#endif


	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* check key_dev_sel                                  */
	/*-----------------------------------------------------*/
	if (key_dev_sel == NULL) {
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check key_status  and key_id / key_purpose         */
	/*-----------------------------------------------------*/
	switch (key_dev_sel->key_status) {
	case DEV_OWN:
		if (((key_dev_sel->dev_ref.key_purpose.authenticate != TRUE) &&
		(key_dev_sel->dev_ref.key_purpose.authenticate != FALSE)) ||
		((key_dev_sel->dev_ref.key_purpose.sec_mess_auth != TRUE) &&
		(key_dev_sel->dev_ref.key_purpose.sec_mess_auth != FALSE)) ||
		 ((key_dev_sel->dev_ref.key_purpose.sec_mess_con != TRUE) &&
		(key_dev_sel->dev_ref.key_purpose.sec_mess_con != FALSE))) {
			sca_errno = M_EKEYDEV;
			set_errmsg();
			return (-1);
		}
		if ((key_dev_sel->dev_ref.key_purpose.authenticate == FALSE) &&
		(key_dev_sel->dev_ref.key_purpose.sec_mess_auth == FALSE) &&
		 (key_dev_sel->dev_ref.key_purpose.sec_mess_con == FALSE)) {
			sca_errno = M_EPAR;
			set_errmsg();
			return (-1);
		}
		sct_devinstkey.pval.purpose.authenticate = key_dev_sel->dev_ref.key_purpose.authenticate;
		sct_devinstkey.pval.purpose.sec_mess_auth = key_dev_sel->dev_ref.key_purpose.sec_mess_auth;
		sct_devinstkey.pval.purpose.sec_mess_con = key_dev_sel->dev_ref.key_purpose.sec_mess_con;

		break;


	case DEV_ANY:

		if ((sct_keyid = get_sct_keyid(&key_dev_sel->dev_ref.key_id)) == -1)
			return (-1);
		if (key_dev_sel->dev_ref.key_id.key_level == SCT) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		};

		sct_devinstkey.pval.kid = sct_keyid;
		break;

	default:
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	}



/************** input parameter check done *********************************/

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, FALSE) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* Generate key (S_DEL_DEV_KEY)		       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/* */
	/*-----------------------------------------------------*/
	command = S_DEL_DEV_KEY;
	request.rq_p1.dev_inst_key = &sct_devinstkey;
	request.rq_p2.status = key_dev_sel->key_status;



	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* (Release storage)				       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_del_dev_key *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_del_dev_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_del_dev_key        */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_write_keycard        VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Write PIN and device keys (STATUS=DEV_ANY) from SCT in Keycard */
/*							       */
/*						               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*                                                             */
/*   pin	               Structure which determines the  */
/*                             PIN to be installed             */
/*                                                             */
/*   auth_key_id               Structure which determines the  */
/*                             device key for authentication.  */
/*                                                             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EPIN 		       */
/*				 EINVKID		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
/*  get_PIN_PUK_body           ERROR-Codes                     */
/*                               M_EMEMORY		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_write_keycard(sct_id, pin, auth_key_id)
	int             sct_id;
	PINStruc       *pin;
	KeyId          *auth_key_id;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid, auth_keyid, sec_auth_keyid, sec_con_keyid;
	PINRecord       pin_record;
	Bytestring      pin_body;
	KeyId           key_id;
	WriteKeycard    sct_writekey;
	KeyAttrList     key_attr_list;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_write_keycard *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_pinstruc(pin);
/*	print_keydevlist(key_dev_list);   */
	print_keyid(auth_key_id);
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/



	/*-----------------------------------------------------*/
	/* Check pin record				       */
	/*-----------------------------------------------------*/
	if (pin->pin_type == PIN) {	/* check PIN */
		if ((pin->PINBody.pin_info.min_len < 0) ||
		    (pin->PINBody.pin_info.min_len > MAXL_PIN)) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if (pin->PINBody.pin_info.pin == NULL) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		} else if (strlen(pin->PINBody.pin_info.pin) > MAXL_PIN) {
			sca_errno = M_EPIN;
			set_errmsg();
			return (-1);
		}
		if (pin->PINBody.pin_info.clear_pin != NULL) {
			if (strlen(pin->PINBody.pin_info.clear_pin) > MAXL_PIN) {
				sca_errno = M_EPIN;
				set_errmsg();
				return (-1);
			}
		}
	} else {		/* no PIN  */
		sca_errno = M_EPIN;
		set_errmsg();
		return (-1);
	}

#ifdef OLD
	/*-----------------------------------------------------*/
	/* Check key_dev_list  			       */
	/*-----------------------------------------------------*/
	if (!key_dev_list) {
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	};
	/* get char from auth_key */
	if (key_dev_list->auth_key) {
		/* KeyId defined */
		if ((auth_keyid = get_sct_keyid(key_dev_list->auth_key)) == -1)
			return (-1);
		if ((key_dev_list->auth_key->key_level < SC_MF) ||
		    (key_dev_list->auth_key->key_level > SC_SF)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
		if ((key_dev_list->auth_key->key_number < 1) ||
		    (key_dev_list->auth_key->key_number > MAX_KEYID)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
	} else
		auth_keyid = 0x00;



	/* get char from sec_auth_key */
	if (key_dev_list->sec_auth_key) {
		/* KeyId defined */
		if ((sec_auth_keyid = get_sct_keyid(key_dev_list->sec_auth_key)) == -1)
			return (-1);
		if ((key_dev_list->sec_auth_key->key_level < SC_MF) ||
		    (key_dev_list->sec_auth_key->key_level > SC_SF)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
		if ((key_dev_list->sec_auth_key->key_number < 1) ||
		    (key_dev_list->sec_auth_key->key_number > MAX_KEYID)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
	} else
		sec_auth_keyid = 0x00;


	/* get char from sec_con_key */
	if (key_dev_list->sec_con_key) {
		/* KeyId defined */
		if ((sec_con_keyid = get_sct_keyid(key_dev_list->sec_con_key)) == -1)
			return (-1);
		if ((key_dev_list->sec_con_key->key_level < SC_MF) ||
		    (key_dev_list->sec_con_key->key_level > SC_SF)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
		if ((key_dev_list->sec_con_key->key_number < 1) ||
		    (key_dev_list->sec_con_key->key_number > MAX_KEYID)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
	} else
		sec_con_keyid = 0x00;
#endif

	/*-----------------------------------------------------*/
	/* Check auth_key_id  			       */
	/*-----------------------------------------------------*/
	if (!auth_key_id) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	};

	/* get char from auth_key */
	if (auth_key_id) {
		/* KeyId defined */
		if ((auth_keyid = get_sct_keyid(auth_key_id)) == -1)
			return (-1);
		if ((auth_key_id->key_level < SC_MF) ||
		    (auth_key_id->key_level > SC_SF)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
		if ((auth_key_id->key_number < 1) ||
		    (auth_key_id->key_number > MAX_KEYID)) {
			sca_errno = EINVKID;
			set_errmsg();
			return (-1);
		}
	} else
		auth_keyid = 0x00;

	sec_auth_keyid = 0x00;
	sec_con_keyid = 0x00;


/*********************    check parameter done **************************/

	/*-----------------------------------------------------*/
	/* Send S_AUTH - Command                             */
	/*-----------------------------------------------------*/


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
/*
	request.rq_p1.kid = 0x04;
	request.rq_p2.acp = 0x45;
*/
	request.rq_p1.kid = 0x00;
	request.rq_p2.acp = 0x46;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef DEFINED
	/*-----------------------------------------------------*/
	/* Send S_INST_PIN - Command                         */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* set key_id for pin	 and get char-presentation     */
	/*-----------------------------------------------------*/
	key_id.key_level = SC_MF;
	key_id.key_number = 2;

	if ((sct_keyid = get_sct_keyid(&key_id)) == -1)	/* get char from key_id */
		return (-1);


	key_attr_list.key_inst_mode = INST;
	key_attr_list.key_attr.key_purpose.authenticate = TRUE;
	key_attr_list.key_attr.key_purpose.sec_mess_auth = FALSE;
	key_attr_list.key_attr.key_purpose.sec_mess_auth = FALSE;
	key_attr_list.key_attr.key_purpose.sec_mess_con = FALSE;
	key_attr_list.key_attr.key_purpose.cipherment = FALSE;
	key_attr_list.key_attr.key_presentation = KEY_LOCAL;
	key_attr_list.key_attr.key_op_mode = NO_REPLACE;
	key_attr_list.key_attr.MAC_length = 4;
	key_attr_list.key_fpc = 3;
	key_attr_list.key_status.PIN_check = TRUE;
	key_attr_list.key_status.key_state = KEY_NORMAL;

#ifdef TEST
	fprintf(stdout, "key_attr_list set by STAMOD\n");
	print_keyattrlist(&key_attr_list);
#endif


	command = S_INST_PIN;
	request.rq_p1.kid = sct_keyid;

	pin_record.key_algid = S_PIN;
	pin_record.pin_attr = key_attr_list;

	if ((rc = get_PIN_PUK_body(pin, &pin_body)) == -1)
		return (-1);
	pin_record.pin_record = &pin_body;

#ifdef TEST
	fprintf(stdout, "pin_record->bytes: \n");
	aux_fxdump(stdout, pin_record.pin_record->bytes, pin_record.pin_record->nbytes, 0);
	fprintf(stdout, "\n");
#endif

	request.rq_datafield.pin = &pin_record;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		sta_aux_bytestr_free(&pin_body);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&pin_body);
	sta_aux_bytestr_free(&response);
#endif

	/*-----------------------------------------------------*/
	/* Send S_WRITE_KEYCARD - Command                    */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_WRITE_KEYCARD;
	request.rq_p2.status = DEV_ANY;
	sct_writekey.auth_keyid = auth_keyid;
	sct_writekey.sec_auth_keyid = sec_auth_keyid;
	sct_writekey.sec_con_keyid = sec_con_keyid;
	request.rq_datafield.write_keycard = &sct_writekey;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);





#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_write_keycard *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_write_keycard */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_write_keycard      */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_read_keycard        VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Read device keyset  from Keycard in SCT                    */
/*							       */
/*						               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*                                                             */
/*                                                             */
/*   sec_mess	               Specification of the security   */
/*			       mode(s) for the command and     */
/*			       response exchange between SCT   */
/*			       and smartcard (PIN_AUTH )       */
/*                                                             */
/*							       */
/* IN/OUT						       */
/*   key_dev_sel               Structure which determines the  */
/*                             device key.                     */
/*			       key_status must be set by       */
/*			       application;		       */
/*			       In case of DEV_OWN => key_purpose   */
/*			       will be returned.	       */
/*			       In case of DEV_ANY => key_id  will  */
/*			       be returned.		       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EPAR 		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  check_sec_mess             ERROR-Codes		       */
/*			         M_ESECMESS		       */
/*							       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  err_analyse		       ERROR_Codes	               */
/*				 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               ECLERR                        */
/*                               ESIDUNK                       */
/*                               ERDERR                        */
/*							       */
/*  get_bits						       */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_read_keycard(sct_id, sec_mess, auth_key)
	int             sct_id;
	SecMess        *sec_mess;
	KeyDevSel      *auth_key;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	char            sct_keyid;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_read_keycard *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_secmess(sec_mess);
	if (!auth_key)
		fprintf(stdout, "auth_key                : NULL\n");
	else {
		fprintf(stdout, "auth_key                : \n");
		switch (auth_key->key_status) {
		case DEV_OWN:
			fprintf(stdout, "        key_status      : DEV_OWN\n");
			break;
		case DEV_ANY:
			fprintf(stdout, "        key_status      : DEV_ANY\n");
			break;
		default:
			fprintf(stdout, "        key_status      : value not defined\n");
			break;
		}
	}
#endif


	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* Check sec_mess parameter			       */
	/*-----------------------------------------------------*/
	if (check_sec_mess(sec_mess) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* Check key_status	         		       */
	/*-----------------------------------------------------*/
	if ((!auth_key) ||
	    ((auth_key->key_status != DEV_OWN) &&
	     (auth_key->key_status != DEV_ANY))) {
		sca_errno = M_EPAR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);


/*********************    check parameter done **************************/

	/*-----------------------------------------------------*/
	/* Send S_AUTH - Command   (device authentication)   */
	/*-----------------------------------------------------*/


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
/*
	request.rq_p1.kid = 0x04;
	request.rq_p2.acp = 0x45;
*/
	request.rq_p1.kid = 0x00;
	request.rq_p2.acp = 0x46;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef DEFINED
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_AUTH;
	key_id.key_level = SC_MF;
	key_id.key_number = 2;

	if ((sct_keyid = get_sct_keyid(&key_id)) == -1)	/* get char from key_id */
		return (-1);

	request.rq_p1.kid = sct_keyid;
	request.rq_p2.acp = PIN_USER;
	request.rq_datafield.auth_secmode = sec_mess;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);
#endif

	/*-----------------------------------------------------*/
	/* Send S_READ_KEYCARD - Command                     */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_READ_KEYCARD;
	request.rq_p2.status = auth_key->key_status;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* store response in auth_key  		       */
	/*-----------------------------------------------------*/
	if (response.bytes[1] == 0x01) {
		sca_errno = M_EREADKEY;
		set_errmsg();
		sta_aux_bytestr_free(&response);
		return (-1);
	}
	switch (auth_key->key_status) {
	case DEV_ANY:
		/* create key_id */
		auth_key->dev_ref.key_id.key_level =
			get_bits((unsigned) response.bytes[0], 2, 1);
		auth_key->dev_ref.key_id.key_number =
			get_bits((unsigned) response.bytes[0], 6, 7);
		break;
	case DEV_OWN:
		/* create key_purpose */
		auth_key->dev_ref.key_purpose.authenticate =
			get_bits((unsigned) response.bytes[0], 1, 0);
		break;
	}





	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);



#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	print_keydevsel(auth_key);
	fprintf(stdout, "\n***** Normal end of   sca_read_keycard *****\n\n");
#endif


	return (sca_errno);

}				/* end sca_read_keycard */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_read_keycard       */
/*-------------------------------------------------------------*/






















/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  get_PIN_PUK_body         VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Composes PIN or PUK body to one character string           */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   pin	               Structure which determines the  */
/*                             PIN to be installed             */
/*                                                             */
/* OUT							       */
/*   pin_body		       PIN body           	       */
/*			       (pin_body->bytes must be        */
/*			        released be calling program.)  */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0  	         	OK			       */
/*                              M_EMEMORY		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  get_sct_keyid               ERROR-Codes		       */
/*				  EINVKID		       */
/*							       */
/*-------------------------------------------------------------*/
static
int
get_PIN_PUK_body(pin, pin_body)
	PINStruc       *pin;
	Bytestring     *pin_body;

{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             body_ctr, pin_ctr;

#define PIN_INFO pin->PINBody.pin_info
#define PUK_INFO pin->PINBody.puk_info

#define MAX_PINBODY 17
#define MAX_PUKBODY  9

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* A PIN body on the smartcard consists of :           */
	/* - one Byte: 	Minimum length,                */
	/* - 8 bytes:	pin value, padded with tailing */
	/* blanks,			       */
	/* - 8 bytes:	clear pin value, padded with   */
	/* tailing blanks		       */
	/*-----------------------------------------------------*/
	if (pin->pin_type == PIN) {
		pin_body->nbytes = MAX_PINBODY;
		if ((pin_body->bytes = (char *) malloc(pin_body->nbytes)) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			return (-1);
		}
		pin_body->bytes[0] = PIN_INFO.min_len;	/* add min length */

		if (PIN_INFO.pin != NULL) {	/* add pin */
			body_ctr = 1;
			for (pin_ctr = 0; pin_ctr < strlen(PIN_INFO.pin);)
				pin_body->bytes[body_ctr++] = PIN_INFO.pin[pin_ctr++];
		}
		/* padding with blanks *//* add blanks */
		for (; body_ctr <= MAXL_PIN; body_ctr++)
			pin_body->bytes[body_ctr] = ' ';

		if (PIN_INFO.clear_pin != NULL) {	/* add clear_pin */
			for (pin_ctr = 0; pin_ctr < strlen(PIN_INFO.clear_pin);)
				pin_body->bytes[body_ctr++] = PIN_INFO.clear_pin[pin_ctr++];
		}
		/* padding with blanks *//* add blanks */
		for (; body_ctr <= MAX_PINBODY; body_ctr++)
			pin_body->bytes[body_ctr] = ' ';

	}			/* end if (pin_type == PIN) */
	/*-----------------------------------------------------*/
	/* A PUK body on the smartcard consists of :           */
	/* - one Byte: 	key_id,      	               */
	/* - 8 bytes:	puk value, padded with tailing */
	/* blanks,			       */
	/*-----------------------------------------------------*/
	if (pin->pin_type == PUK) {
		pin_body->nbytes = MAX_PUKBODY;
		if ((pin_body->bytes = (char *) malloc(pin_body->nbytes)) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			return (-1);
		}
		pin_body->bytes[0] = get_sct_keyid(&PUK_INFO.pin_key_id);	/* add key_id of pin */

		if (PUK_INFO.puk != NULL) {	/* add puk */
			body_ctr = 1;
			for (pin_ctr = 0; pin_ctr < strlen(PUK_INFO.puk);)
				pin_body->bytes[body_ctr++] = PUK_INFO.puk[pin_ctr++];
		}
		/* padding with blanks *//* add blanks */
		for (; body_ctr <= MAX_PUKBODY; body_ctr++)
			pin_body->bytes[body_ctr] = ' ';

	}			/* end if (pin_type == PUK) */
	return (0);

}				/* end  get_PIN_PUK_body */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	get_PIN_PUK_body       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-staauth	       */
/*-------------------------------------------------------------*/
