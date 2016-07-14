/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 1.0		                             +-----*/
/*							                           */
/*							                           */
/*							                           */
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-stacrypt                             VERSION 1.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	stacrypt.c                       		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides all cryptographic functions of the smartcard 	   */
/*	application interface (SCA-IF).      				           */
/*										   */
/*	Observe that:								   */
/*	  1. the functions sca_verify, sca_sign and sca_hash are compiled and      */
/*	  2. the external functions rsa_get_key and hash_sqmodn are used,          */
/*      only if ASSEMBLER is defined.						   */
/*							                           */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*	sca_gen_user_key()     Generate user key (DES or RSA)		           */
/*							                           */
/*	sca_get_rno()          Generate random octetstring	                   */
/*							                           */
/*	sca_del_user_key()     Delete user key stored in an SCT	 	           */
/*							                           */
/*	sca_sign() 	       Sign octetstring	                                   */
/*										   */
/*	sca_verify()	       Verify digital signature				   */
/*							                           */
/*	sca_encrypt()	       Encrypt octetstring				   */
/*							                           */
/*	sca_decrypt()	       Decrypt octetstring				   */
/*							                           */
/*	sca_hash()	       Hash octetstring					   */
/*							                           */
/*	sca_enc_des_key()      Encrypt a DES key with the RSA algorithm            */
/*							                           */
/*	sca_dec_des_key()      Decrypt an rsa-encrypted DES key			   */
/*							                           */

/*                                                                                 */
/*    IMPORT		    DESCRIPTION 		                           */
/*                                 -  aux_xdmp.c (libcrypt)                        */
/*                                                                                 */
/*	aux_fxdump()                  dump buffer in File	                   */
/*							                           */
/*                                 -  aux_util.c (libcrypt)                        */
/*                                                                                 */
/*	aux_cmp_ObjId()               compare two object_ids (part of alg_id)      */
/*                                                                                 */
/*	aux_ObjId2ParmType()          test the parameter type of the algorithm     */
/*                                                                                 */
/*                                 -  aux_free.c (libcrypt)                        */
/*                                                                                 */
/*	aux_free_OctetString()        releases storage of OctetString	           */
/*                                                                                 */
/*                                 -  rsa.c (libcrypt)                             */
/*                                                                                 */
/*      rsa_get_key()	              sets key in an internal function      	   */
/*			              (used for the hash function sqmodn)          */
/*                                                                                 */
/*      hash_sqmodn()	              Hash function square mod n    	           */
/*                                                                                 */
/*                                 -  md2_if.c (libcrypt)                          */
/*                                                                                 */
/*      md2_hash()	              Hash function MD2		      	           */
/*                                                                                 */
/*                                 -  md4_if.c (libcrypt)                          */
/*                                                                                 */
/*      md4_hash()	              Hash function MD4		      	           */
/*                                                                                 */
/*                                 -  md5_if.c (libcrypt)                          */
/*                                                                                 */
/*      md5_hash()	              Hash function MD5		      	           */
/*                                                                                 */
/*							                           */
/*                                 -  sta_free.c (libsm)                           */
/*                                                                                 */
/*      sta_aux_bytestr_free()        set the bytes-buffer in Bytestring free      */
/*                                                                                 */
/*                                                                                 */
/*                                 -  sctint.c (libsm)                             */
/*      sct_interface()               Send SCT command / receive SCT response      */
/*							                           */
/*      sct_errno                     global error variable set by SCT-interface   */
/*							                           */
/*      sct_errmsg                    global pointer to error message set by       */
/*                                    SCT-interface                                */
/*                                                                                 */
/*							                           */
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
/*				   -  stasc.c   (libsm)                            */
/*                                                                                 */
/*      create_trans()		      send SC command				   */
/*                                                                                 */
/*      cr_header()		      create SC-Command header			   */
/*									           */
/*      request			      global variable for create_trans		   */
/*										   */
/*      response		      global variable	for create_trans           */
/*										   */
/*      sc_param		      global variable for create_trans             */
/*										   */
 /* sc_apdu			      global variable for create_trans	           *//* */
/*				   -  staprint.c   (libsm) for TEST-output         */
/*                                                                                 */
/*      print_keyid()							           */
/*      print_secmess()                                                            */

 /*
  * print_keyattrlist()
  *//* I NTERNAL */
/*      compare()              compares two strings (independent of '\0')          */
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
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#else 
#include <stdlib.h>
#endif /* !MAC */



/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/
extern void     aux_fxdump();
extern int      aux_cmp_ObjId();
extern ParmType aux_ObjId2ParmType();
extern void     aux_free_OctetString();
extern void     sta_aux_bytestr_free();

#ifdef TEST
extern void     print_keyid();
extern void     print_secmess();
extern void     print_keyattrlist();

#endif


#ifdef ASSEMBLER
extern int      rsa_get_key();
extern int      hash_sqmodn();

#endif
extern int      md2_hash();
extern int      md4_hash();
extern int      md5_hash();
extern int      sct_interface();
extern char     get_sct_keyid();
extern char     get_sct_algid();
extern int      check_sct_sc();
extern int      check_key_attr_list();
extern int      check_sec_mess();
extern int      set_errmsg();
extern void     err_analyse();
extern int      create_trans();
extern int      cr_header();

extern unsigned int sct_errno;	/* error number set by SCT-Interface */
extern char    *sct_errmsg;	/* pointer to error msg set by      */

 /* SCT-Interface                    */
extern unsigned int sca_errno;	/* error number set by STAMOD       */
extern char    *sca_errmsg;	/* pointer to error msg set by      */

 /* STAMOD                           */


/* the following variables are declared in the sourec file stasc.c */

extern Request  request;	/* body of the SCT commands         */
extern Bytestring response;	/* body of the response of the SCT  */
extern int      command;	/* INS-Code of the SCT command      */
extern struct s_command sc_param;
extern Bytestring sc_apdu;



/*-------------------------------------------------------------*/
/*   local function declarations			       */
/*-------------------------------------------------------------*/
static int      compare();





/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/
typedef enum {
	F_null, F_encrypt, F_decrypt,
	F_hash, F_sign, F_verify
}               FTYPE;

/* definitions for the SC-Interface */
#define SCCMD                   sc_param.sc_header.inscode
#define SCHEAD                  sc_param.sc_header
#define SCCRYPT                 sc_param.sc_uval.sc_crypt

/*-------------------------------------------------------------*/
/*   macro definitions					       */
/*-------------------------------------------------------------*/
#define ALLOC_CHAR(v,s)  {if (0 == (v = malloc(s))) {sca_errno = M_EMEMORY; set_errmsg(); goto errcase;}}

#define ALLOC_OCTET(v,t)        {if (0 == (v = (t *)malloc(sizeof(t)))) {sca_errno =  M_EMEMORY; set_errmsg(); goto errcase;}}



/*-------------------------------------------------------------*/
/*   global Variable definitions			       */
/*-------------------------------------------------------------*/
static Boolean  sc_expect;	/* = TRUE indicates: SC expected    */

 /* = FALSE indicates: SC not needed */
static char     fermat_f4[3] = {'\001', '\000', '\001'};	/* public exponent                  */
static int      fermat_f4_len = 3;



static FTYPE    act_function = F_null;	/* used if encrypt, decrypt, sign   */

 /* or verify are called with more = */
 /* MORE                             */

static int      max_length;	/* maximal datalength for encrypt/decrypt */
static int      in_rest_len = 0;
static int      FIRST_CRYPT_CMD;
static char    *in_rest = NULL;
static char     cbc_initvek[8];





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_gen_user_key         VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Generate user key (DES or RSA)		               */
/*							       */
/*  DES-Key:	- if level of key is set to SC_MF, SC_DF, SC_SF*/
/*		     => Generate S_GEN_USER_KEY		       */
/*		        Generate S_INST_USER_KEY	       */
/*  		- if level of key is set to SCT                */
/*		     => Generate S_GEN_USER_KEY		       */
/*  RSA-Key:	- if level of key is set to SC_MF, SC_DF, SC_SF*/
/*		     => Generate S_GEN_USER_KEY		       */
/*		        Generate S_INST_USER_KEY	       */
/*  		- if level of key is set to SCT                */
/*		     => Return error			       */
/*						               */
/*  If key shall be installed on the smartcard, a smartcard    */
/*  must be inserted and parameter key_attr_list must be set.  */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_sel                   Structure which determines the  */
/*                             generated key.                  */
/*                                                             */
/*   key_attr_list             Structure which contains        */
/*                             additional information for      */
/*                             storing the generated key on    */
/*			       the SC or the NULL pointer      */
/*							       */
/* OUT							       */
/*   key_sel->key_bits         In case of RSA, the public key  */
/*			       is returned. Memory is provided */
/*			       by this function and must be    */
/*                             released by calling routine.    */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*   1                           M_KEYREPL                     */
/*  -1			       error			       */
/*				 M_ELEVEL		       */
/*				 EINVALGID		       */
/*				 M_EPOINTER		       */
/*				 M_EMEMORY		       */
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
sca_gen_user_key(sct_id, key_sel, key_attr_list)
	int             sct_id;
	KeySel         *key_sel;
	KeyAttrList    *key_attr_list;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i, algorithm;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	KeyAlgId        sct_algid;	/* SCT specific alg_id		     */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_gen_user_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	fprintf(stdout, "key_sel	        : \n");
	if (key_sel != NULL) {
		fprintf(stdout, "    key_algid           : %s\n", aux_ObjId2Name(key_sel->key_algid->objid));
		print_keyid(&key_sel->key_id);
	} 
	else fprintf(stdout, "key_sel	        : NULL\n");

	print_keyattrlist(key_attr_list);
#endif




	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* check algid and get sct specific alg_id            */
	/*-----------------------------------------------------*/
	if ((sct_algid = get_sct_algid(key_sel->key_algid)) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* check key_id and get keyid in char representation  */
	/*-----------------------------------------------------*/
	if ((sct_keyid = get_sct_keyid(&key_sel->key_id)) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* if key shall be installed on the SC,               */
	/* then - check key attribute list and             */
	/* - check whether SC is inserted	       */
	/*-----------------------------------------------------*/
	if ((key_sel->key_id.key_level == SC_MF) ||
	    (key_sel->key_id.key_level == SC_DF) ||
	    (key_sel->key_id.key_level == SC_SF)) {

		if (check_key_attr_list(USER_KEY, key_attr_list) == -1)
			return (-1);
		sc_expect = TRUE;
	}
	/*-----------------------------------------------------*/
	/* if key shall be stored in the SCT and alg_id = RSA, */
	/* then - return(error)                            */
	/* An RSA key must be installed on the SC.	       */
	/*-----------------------------------------------------*/
	else {
		if (sct_algid == S_RSA_F4) {
			sca_errno = M_ELEVEL;
			set_errmsg();
			return (-1);
		}
		sc_expect = FALSE;
	}

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* if sct_algid = S_RSA_F4,			       */
	/* then key_sel->key_bits must be valid for        */
	/* the returned public key.     	       */
	/*-----------------------------------------------------*/
	if ((sct_algid == S_RSA_F4) && (key_sel->key_bits == NULL)) {
		sca_errno = M_EPOINTER;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/

	/*-----------------------------------------------------*/
	/* Generate key (S_GEN_USER_KEY)		       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/* */
	/* At the SCA-IF the keysize is given in bits,       */
	/* at the SCT-IF the keysize is delivered in bytes,  */
	/* therefor the keysize in bits is divided by 8.     */
	/*-----------------------------------------------------*/
	command = S_GEN_USER_KEY;
	request.rq_p1.kid = sct_keyid;
	request.rq_p2.algid = sct_algid;
	if (sct_algid == S_RSA_F4)
		request.rq_datafield.keylen = RSA_PARM(key_sel->key_algid->parm) / 8;
	else
		request.rq_datafield.keylen = 0;

#ifdef TEST
	if (sct_algid == S_RSA_F4)
		fprintf(stdout, "keysize of RSA key: %d\n", RSA_PARM(key_sel->key_algid->parm));
#endif



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
	/* If an existing key in the SCT has been overwritten */
	/* then return (warning)			       */
	/*-----------------------------------------------------*/
	if (key_sel->key_id.key_level == SCT)
		if (rc == S_KEYREPL)
			sca_errno = M_KEYREPL;

	/*-----------------------------------------------------*/
	/* If sct_algid = S_RSA_F4  			       */
	/* then get modulus from SCT response and         */
	/* construct public key (modulus, Fermat-F4) */
	/* and return pk in key_sel->key_bits        */
	/*-----------------------------------------------------*/
	if (sct_algid == S_RSA_F4) {
		key_sel->key_bits->part1.noctets = response.nbytes;
		if ((key_sel->key_bits->part1.octets = (char *) malloc(response.nbytes)) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			sta_aux_bytestr_free(&response);
			return (-1);
		}
		for (i = 0; i < response.nbytes; i++)
			key_sel->key_bits->part1.octets[i] = response.bytes[i];

		/* get fermat-f4 as public exponent */
		key_sel->key_bits->part2.noctets = 3;
		if ((key_sel->key_bits->part2.octets = (char *) malloc(3)) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			sta_aux_bytestr_free(&response);
			return (-1);
		}
		key_sel->key_bits->part3.noctets =0;
		key_sel->key_bits->part4.noctets =0;

		memcpy(key_sel->key_bits->part2.octets, fermat_f4, 3);

#ifdef TEST
		fprintf(stdout, "modulus of public key:\n");
		aux_fxdump(stdout, key_sel->key_bits->part1.octets, key_sel->key_bits->part1.noctets, 0);
		fprintf(stdout, "\n");
		fprintf(stdout, "public exponent of public key:\n");
		aux_fxdump(stdout, key_sel->key_bits->part2.octets, key_sel->key_bits->part2.noctets, 0);
		fprintf(stdout, "\n");
#endif
	}
	/*-----------------------------------------------------*/
	/* (Release storage)				       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);




/************** key is now generated *********************************/


	/*-----------------------------------------------------*/
	/* if key shall not be installed on SC,              */
	/* then work is done			       */
	/*-----------------------------------------------------*/
	if (key_sel->key_id.key_level == SCT)
		return (sca_errno);

	/*-----------------------------------------------------*/
	/* otherwise (if key shall be installed on SC),      */
	/* then install key  on SC (S_INST_USER_KEY)      */
	/* and delete key in SCT (S_DEL_USER_KEY)         */
	/*-----------------------------------------------------*/


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_INST_USER_KEY;
	request.rq_p1.kid = sct_keyid;
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
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_DEL_USER_KEY;
	request.rq_p1.kid = sct_keyid;

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
	fprintf(stdout, "\n***** Normal end of   sca_gen_user_key *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_gen_user_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_gen_user_key       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_get_rno	          VERSION   1.0	    	       */
/*				     DATE   Juli 1992	       */
/*			      	       BY   L. Eckstein        */
/*							       */
/* DESCRIPTION						       */
/*  Get random number from SCT			               */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   rnd_len                   required length of the random   */
/*                             number                          */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   Octetstring	       Pointer to allocated structure  */
/*   NULL 		       error			       */
/*                               M_ETIME		       */
/*                               M_ETEXT		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
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
/*  sta_aux_bytestr_free				       */
/*							       */
/*  err_analyse		      ERROR_Codes	               */
/*				ENOSHELL		       */
/*                              EOPERR                         */
/*			        EEMPTY                         */
/*                              ECLERR                         */
/*                              ESIDUNK                        */
/*                              ERDERR                         */
/*							       */
/*							       */
/*  set_errmsg						       */
/*							       */
/*-------------------------------------------------------------*/
OctetString    *
sca_get_rno(sct_id, rnd_len)
	int             sct_id;
	unsigned int    rnd_len;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc, i;
	OctetString    *ostring;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = FALSE;	/* this function doesn't need a SC */

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_get_rndo *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	fprintf(stdout, "rnd_len	        : %d\n", rnd_len);
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc                                  */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return ((OctetString *) 0);


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_GET_RNO;
	request.rq_p1.lrno = rnd_len;

	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		return ((OctetString *) 0);
	}
	/*----------------------------------------------------------*/
	/* Normal End	  generate Octetstring and Release response */
	/*----------------------------------------------------------*/
	if ((ostring = (OctetString *) malloc(sizeof(OctetString))) == NULL) {
		sca_errno = M_EMEMORY;
		set_errmsg();
		sta_aux_bytestr_free(&response);
		return ((OctetString *) 0);
	}
	if ((ostring->octets = (char *) malloc(response.nbytes)) == NULL) {
		sca_errno = M_EMEMORY;
		set_errmsg();
		free(ostring);
		sta_aux_bytestr_free(&response);
		return ((OctetString *) 0);
	}
	ostring->noctets = response.nbytes;
	for (i = 0; i < ostring->noctets; i++)
		*(ostring->octets + i) = *(response.bytes + i);

	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "Octetstring             : \n");
	fprintf(stdout, "    noctets             : %d\n", ostring->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, ostring->octets, ostring->noctets, 0);
	fprintf(stdout, "\n***** Normal end of   sca_get_rno *****\n\n");
#endif


	return (ostring);





}				/* end sca_get_rno */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_get_rno	       */
/*-------------------------------------------------------------*/





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_del_user_key         VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Delete key within the specified SCT		               */
/*							       */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id                    Key-Id of the key to be deleted */
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
sca_del_user_key(sct_id, key_id)
	int             sct_id;
	KeyId          *key_id;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_del_user_key *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	if (key_id->key_level == SC_MF)
		fprintf(stdout, "key_id: MF-level Key_No: ");
	if (key_id->key_level == SC_DF)
		fprintf(stdout, "key_id: DF-level Key_No: ");
	if (key_id->key_level == SC_SF)
		fprintf(stdout, "key_id: SF-level Key_No: ");
	if (key_id->key_level == SCT)
		fprintf(stdout, "key_id: SCT-level Key_No: ");
	fprintf(stdout, "%d\n", key_id->key_number);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* check key_id and get keyid in char representation  */
	/*-----------------------------------------------------*/
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* A key on the smartcard cannot be deleted.          */
	/* If level = level on the smartcard                  */
	/* then return (error)			       */
	/*-----------------------------------------------------*/
	if ((key_id->key_level == SC_MF) ||
	    (key_id->key_level == SC_DF) ||
	    (key_id->key_level == SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, FALSE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_DEL_USER_KEY;
	request.rq_p1.kid = sct_keyid;

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
	fprintf(stdout, "\n***** Normal end of   sca_del_user_key *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_del_user_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_del_user_key       */
/*-------------------------------------------------------------*/



#ifdef ASSEMBLER
/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_sign                 VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Sign octetstring 				               */
/*							       */
/*  Smartcard must be inserted.				       */
/*							       */
/*  Observe that: 					       */
/*	If VERSION10 is defined				       */
/*	   then the result of the hash-function is padded with */
/*		leading zeroes (X'00') to the modulus length.  */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   in_octets		       Octetstring of the data to be   */
/*                             signed.                         */
/*                                                             */
/*   signature                 Algorithm to be used and        */
/*			       returned signature (memory is   */
/*                             provided by the called program) */
/*                                                             */
/*   more		       = MORE -> more data is expected */
/*   			       = END  -> Last data for this    */
/*				         sign process.         */
/*                                                             */
/*   key_id                    Key-Id of the sigature key      */
/*                             Level of this key must be a     */
/*                             level on the smartcard.         */
/*                                                             */
/*   hash_par                  Additional algorithm (hash_alg) */
/*                             specific parameters or the NULL */
/*                             pointer.                        */
/*							       */
/* OUT							       */
/*   signature->signature      returned signature              */
/*			       Memory is provided by this      */
/*			       function and must be released   */
/*			       by calling routine.             */
/*							       */
/*   signature->signAI         Only if this function is called */
/*			       with signature->signAI = NULL,  */
/*			       then this function creates a    */
/*			       structure AlgId and returns it. */
/*			       In this case the allocated      */
/*			       memory must be released by the  */
/*			       calling routine.                */
/*							       */
/*   signature->signAI->parm   If the given keysize is unequal */
/*			       to the keysize, which is        */
/*			       returned by the SCT, then this  */
/*			       function sets signature->       */
/*			       signAI->parm to the correct     */
/*			       value.                          */
/*			       In this case M_KEYLEN is        */
/*			       returned.                       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*   1				 M_KEYLEN		       */
/*  -1			       error			       */
/*				 M_EINDATA		       */
/*				 M_EPOINTER		       */
/*				 EINVALGID		       */
/*				 M_EMORE		       */
/*				 M_ELEVEL		       */
/*				 M_EHASHPAR		       */
/*				 M_EMEMORY		       */
/*				 M_EFUNCTION		       */
/*				 M_EHASH		       */
/*				 M_EPAR  		       */
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
/*							       */
/*  rsa_get_key		       ERROR-Codes		       */
/*				 -1 -> M_EHASHPAR              */
/*							       */
/*  hash_sqmodn 	       ERROR-Codes     	               */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md2_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md4_hash	       	       ERROR_Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md5_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
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
/*							       */
/*  err_analyse		      ERROR_Codes	               */
/*				ENOSHELL		       */
/*                              EOPERR                         */
/*			        EEMPTY                         */
/*                              ECLERR                         */
/*                              ESIDUNK                        */
/*                              ERDERR                         */
/*							       */
/*  set_errmsg						       */
/*							       */
/*  sta_aux_bytestr_free				       */
/*							       */
/*  aux_free_OctetString		    	               */
/*							       */
/*-------------------------------------------------------------*/
int
sca_sign(sct_id, in_octets, signature, more, key_id, hash_par)
	int             sct_id;
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	KeyId          *key_id;
	HashPar        *hash_par;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	char            sct_keyid;	/* char representation of the key_id */
	KeyAlgId        sct_algid;	/* SCT specific alg_id		     */
	Bytestring      sctint_hash;	/* hash string for SCT-Interface     */
	static AlgEnc   algenc;
	static AlgHash  alghash;
	static AlgSpecial     algspecial;
	static OctetString *hash_result;
	OctetString     *encodedDigest;

#ifdef VERSION10
	int             j;
	static OctetString *hash2_result;	/* is used for padding the
						 * hash-result */
	int             modulus_len;	/* modulus length in bytes             */
	char            *dd;

#endif

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_sign *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	if (in_octets != NULL) {
		fprintf(stdout, "in_octets: \n");
		aux_fxdump(stdout, in_octets->octets, in_octets->noctets, 0);
	}
	if (signature->signAI != NULL)
		if (signature->signAI->parm != NULL)
			fprintf(stdout, "signAI.keysize:    %d\n", RSA_PARM(signature->signAI->parm));
	if (more == MORE)
		fprintf(stdout, "more = MORE\n");
	if (more == END)
		fprintf(stdout, "more = END\n");
	if (key_id->key_level == SC_MF)
		fprintf(stdout, "key_id: MF-level Key_No: ");
	if (key_id->key_level == SC_DF)
		fprintf(stdout, "key_id: DF-level Key_No: ");
	if (key_id->key_level == SC_SF)
		fprintf(stdout, "key_id: SF-level Key_No: ");
	if (key_id->key_level == SCT)
		fprintf(stdout, "key_id: SCT-level Key_No: ");
	fprintf(stdout, "%d\n", key_id->key_number);
	if (hash_par != NULL) {
		fprintf(stdout, "hash_par (modulus): \n");
		aux_fxdump(stdout, hash_par->sqmodn_par.part1.octets, hash_par->sqmodn_par.part1.noctets, 0);
	}
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, TRUE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* check data to be signed    		               */
	/*-----------------------------------------------------*/
	if (in_octets == NULL) {
		sca_errno = M_EINDATA;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check signature algorithm , must be RSA            */
	/* if  signature->signAI = NULL pointer               */
	/* then take sqmodnWithRsa and set signature->signAI */
	/* to the corresponding values	       */
	/*-----------------------------------------------------*/
	if (signature == NULL) {
		sca_errno = M_EPOINTER;
		set_errmsg();
		return (-1);
	} 
	else {
		if(signature->signAI == NULL) signature->signAI = sqmodnWithRsa;
		if ((aux_ObjId2ParmType(signature->signAI->objid) == PARM_NULL) &&
		    (signature->signAI->parm)) {
			sca_errno = M_EPAR;
			set_errmsg();
			return (-1);
		}
	}

	if ((sct_algid = get_sct_algid(signature->signAI)) == -1)
		return (-1);
	if (sct_algid != S_RSA_F4) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check parameter more  		               */
	/*-----------------------------------------------------*/
	if ((more != END) && (more != MORE)) {
		sca_errno = M_EMORE;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check key_id and get keyid in char representation  */
	/* if level of key = SCT		               */
	/* then return (error)			       */
	/* RSA key must be a key on the smartcard.            */
	/*-----------------------------------------------------*/
	if ((sct_keyid = get_sct_keyid(key_id)) == -1)
		return (-1);
	if (key_id->key_level == SCT) {
		sca_errno = M_ELEVEL;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/
/************** now start hash function     *********************************/


	/*-----------------------------------------------------*/
	/* if first call of sign function		       */
	/* then 1) get hash algorithm,                         */
	/* 2) if algorithm = RSA-sqmodn                        */
	/* then set key (modulus) for hash-fct.                */
	/* 3) allocate storage for hash result and             */
	/* signature.bits                                      */
	/*-----------------------------------------------------*/

	if (act_function == F_null) {	/* first call of sca_sign */

		algenc = aux_ObjId2AlgEnc(signature->signAI->objid);
		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		algspecial = aux_ObjId2AlgSpecial(signature->signAI->objid);

		if (alghash == SQMODN) {
			if (hash_par == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			if (hash_par->sqmodn_par.part1.octets == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			/* set key in an internal function for hash-function */
			rc = rsa_get_key(&hash_par->sqmodn_par, 0);
			if (rc < 0) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
		}
		/* allocate storage for hash_result and signature.bits */
		ALLOC_OCTET(hash_result, OctetString);
		hash_result->noctets = 0;
		ALLOC_CHAR(hash_result->octets, (RSA_PARM(signature->signAI->parm) + 7) / 8);

		signature->signature.nbits = 0;
		ALLOC_CHAR(signature->signature.bits, (RSA_PARM(signature->signAI->parm) + 7) / 8);
		act_function = F_sign;

	}
	/* end if (act_function == F_null) */
	else
	 /* not first call of sca_sign */ if (act_function != F_sign) {
		sca_errno = M_EFUNCTION;	/* wrong function call */
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Call hash function depending on algorithm         */
	/*-----------------------------------------------------*/
	switch (alghash) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_result, more,
				 RSA_PARM(signature->signAI->parm));
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_result, more);
		break;
	case SHA:
		rc = sha_hash(in_octets, hash_result, more);
		break;
	default:
		sca_errno = EINVALGID;
		set_errmsg();
		goto errcase;
	}			/* end switch */
	if (rc < 0) {
		sca_errno = M_EHASH;
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Now hashing is done			       */
	/* If last call of sca_sign ( more = END)            */
	/* then call sct-interface                        */
	/*-----------------------------------------------------*/
	if (more == END) {	/* last call of sca_sign */

#ifdef TEST
		fprintf(stdout, "hash result: \n");
		aux_fxdump(stdout, hash_result->octets, hash_result->noctets, 0);
#endif

#ifdef VERSION10
		/* hash-value must have the same length as the modulus */
		modulus_len = RSA_PARM(signature->signAI->parm) / 8;

#ifdef TEST
		fprintf(stdout, "modulus len: %d \n", modulus_len);
#endif

		if (hash_result->noctets < modulus_len) {
			if(algspecial == PKCS_BT_01 || algspecial == PKCS_BT_TD) {

				/*  Here goes PKCS#1 ...   */

				encodedDigest = aux_create_PKCS_MIC_D(hash_result, signature->signAI);
				aux_free_OctetString(&hash_result);		
				hash_result = aux_create_PKCSBlock(algspecial, encodedDigest);
				if(encodedDigest) aux_free_OctetString(&encodedDigest);

       			}
#ifdef VERSION10
			ALLOC_OCTET(hash2_result, OctetString);
			hash2_result->noctets = 0;
			ALLOC_CHAR(hash2_result->octets, (RSA_PARM(signature->signAI->parm) + 7) / 8);
#endif

			i = modulus_len - hash_result->noctets;
			for (j = 0; j < i; j++)
				hash2_result->octets[j] = 0x00;
			for (i = 0; i < hash_result->noctets; i++, j++)
				hash2_result->octets[j] = hash_result->octets[i];
			hash2_result->noctets = modulus_len;
			aux_free_OctetString(&hash_result);		
			hash_result = hash2_result;

#ifdef TEST
			fprintf(stdout, "hash result: \n");
			aux_fxdump(stdout, hash_result->octets, 64, 0);
#endif
		}
#endif

		/*-----------------------------------------------------*/
		/* Prepare parameters for the SCT Interface          */
		/*-----------------------------------------------------*/
		command = S_RSA_SIGN;
		request.rq_p1.kid = sct_keyid;
		sctint_hash.nbytes = hash_result->noctets;
		sctint_hash.bytes = hash_result->octets;
		request.rq_datafield.hash = &sctint_hash;

		/*-----------------------------------------------------*/
		/* Call SCT Interface     			       */
		/*-----------------------------------------------------*/
		rc = sct_interface(sct_id, command, &request, &response);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			goto errcase;
		}
		/*-----------------------------------------------------*/
		/* 1) get returned signature and   		       */
		/* 2) if returned modulus length <> given modulus      */
		/* length (signature->signAI->parm), then the       */
		/* correct value and M_KEYLEN is returned.          */
		/*-----------------------------------------------------*/
		signature->signature.nbits = 8 * (response.nbytes - 1);
		for (i = 0; i < (response.nbytes - 1); i++) {
			signature->signature.bits[i] = response.bytes[i + 1];
		}

#ifdef TEST
		fprintf(stdout, "returned signature:\n");
		aux_fxdump(stdout, signature->signature.bits, signature->signature.nbits / 8, 0);
		fprintf(stdout, "\n");
		fprintf(stdout, "returned keylength:\n");
		aux_fxdump(stdout, &response.bytes[0], 1, 0);
		fprintf(stdout, "\n");
		fprintf(stdout, "given keysize: %d ", RSA_PARM(signature->signAI->parm));
#endif

		if (signature->signAI->parm) {
			if ((RSA_PARM(signature->signAI->parm) != (int) response.bytes[0]) * 8) {
				*signature->signAI->parm = (int) response.bytes[0] * 8;
				sca_errno = M_KEYLEN;
			}
		}
#ifdef TEST
		fprintf(stdout, "\nreturned keysize: %d ", RSA_PARM(signature->signAI->parm));
#endif

		/*-----------------------------------------------------*/
		/* Normal End	 (Release storage)		       */
		/*-----------------------------------------------------*/
		aux_free_OctetString(&hash_result);

		sta_aux_bytestr_free(&response);

		act_function = F_null;

	}			/* end if (more == END) */
#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_sign *********************************************\n\n");
#endif

	return (sca_errno);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	aux_free_OctetString(&hash_result);

	free(signature->signature.bits);
	act_function = F_null;
	return (-1);


}				/* end sca_sign */


/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_sign    	       */
/*-------------------------------------------------------------*/
#endif



#ifdef ASSEMBLER
/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_verify               VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */

/*
Achtung: Folgende Besonderheit ist NICHT implementiert:

	 Das SCT erwartet im S-RSA-VERIFY Kommando als Laenge des Exponenten:
		- entweder die X'00' => die Fermatzahl F4 wird vom SCT als Exponent
		  verwendet, oder
		- die Laenge des Exponenten muss gleich der Laenge des Modulus sein,
	 	  in diesem Fall muesste der Wert des Exponenten entsprechend mit
	  	  fuehrenden Nullen aufgefuellt werden.
	Da das T-1 Programm des SCT kein chaining kann, wuerde die verarbeitbare APDU-
	Laenge ueberschritten, wenn die Modulus-Laenge = 512 waere.
	

*/



/*							       */
/* DESCRIPTION						       */
/*  Verify a digital signature.			               */
/*  The signature algorithm is taken from signature->signAI.   */
/*							       */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/*  Observe that: 					       */
/*	If VERSION10 is defined				       */
/*	   then the result of the hash-function is padded with */
/*		leading zeroes (X'00') to the modulus length.  */
/*	   then the given signature is padded with             */
/*		leading zeroes (X'00') to the modulus length.  */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   in_octets		       Octetstring of the data to be   */
/*                             signed.                         */
/*                                                             */
/*   signature                 Signature to be verified and    */
/*			       corresponding algorithm         */
/*                                                             */
/*   more		       = MORE -> more data is expected */
/*   			       = END  -> Last data for this    */
/*				         verification process. */
/*                                                             */
/*   key_sel                   Structure which identifies the  */
/*                             verification key.               */
/*                             In the current version only the */
/*			       delivery of a public RSA key is */
/*			       supported (key_sel->key_bits).  */
/*                                                             */
/*   hash_par                  Additional algorithm (hash_alg) */
/*                             specific parameters or the NULL */
/*                             pointer.                        */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*   1				 M_SIGOK		       */
/*  -1			       error			       */
/*				 M_EINDATA		       */
/*				 M_EPOINTER		       */
/*				 EINVALGID		       */
/*				 M_EMORE		       */
/*				 M_EHASHPAR		       */
/*				 M_EMEMORY		       */
/*				 M_EFUNCTION		       */
/*				 M_EHASH		       */
/*				 M_EKEY 		       */
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
/*							       */
/*  compare                                                    */
/*							       */
/*  rsa_get_key		       ERROR-Codes		       */
/*				 -1 -> M_EHASHPAR              */
/*							       */
/*  hash_sqmodn 	       ERROR-Codes     	               */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md2_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md4_hash	       	       ERROR_Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md5_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
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
/*  aux_free_OctetString		    	                       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_verify(sct_id, in_octets, signature, more, key_sel, hash_par)
	int             sct_id;
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	KeySel         *key_sel;
	HashPar        *hash_par;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	int             rc;
	KeyAlgId        sct_algid;	/* SCT specific alg_id		     */
	Bytestring      sctint_hash;	/* hash string for SCT-Interface     */
	Bytestring      sctint_modulus;	/* modulus for SCT-Interface         */
	Bytestring      sctint_exponent;	/* exponent for SCT-Interface        */
	Bytestring      sctint_signature;	/* signature for
						 * SCT-Interface       */
	static AlgHash  alghash;
	static AlgEnc   algenc;
	static AlgSpecial     algspecial;
	static OctetString *hash_result;
	OctetString     *encodedDigest, *o1;
	char *proc = "sca_verify";


#ifdef VERSION10
	int             j;
	static OctetString *hash2_result;	/* is used for padding the
						 * hash-result */
	int             modulus_len;	/* modulus length in Bytes             */
	int             signature_len;	/* signature length in Bytes           */
	BitString       signature_help;	/* is used for padding the signature   */

#endif

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_verify *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	if (in_octets != NULL) {
		fprintf(stdout, "in_octets: \n");
		aux_fxdump(stdout, in_octets->octets, in_octets->noctets, 0);
	}
	if (signature != NULL)
		if (signature->signAI != NULL)
			if (signature->signAI->parm != NULL)
				fprintf(stdout, "signAI.keysize:    %d\n", RSA_PARM(signature->signAI->parm));
	if (signature != NULL) {
		fprintf(stdout, "signature->signature.bits: \n");
		aux_fxdump(stdout, signature->signature.bits, signature->signature.nbits / 8, 0);
		fprintf(stdout, "\n");
	}
	if (more == MORE)
		fprintf(stdout, "more = MORE\n");
	if (more == END)
		fprintf(stdout, "more = END\n");
	fprintf(stdout, "key_sel->key_bits->part1.octets: \n");
	aux_fxdump(stdout, key_sel->key_bits->part1.octets, key_sel->key_bits->part1.noctets, 0);
	fprintf(stdout, "key_sel->key_bits->part2.octets: \n");
	aux_fxdump(stdout, key_sel->key_bits->part2.octets, key_sel->key_bits->part2.noctets, 0);
	if (hash_par != NULL) {
		fprintf(stdout, "hash_par (modulus): \n");
		aux_fxdump(stdout, hash_par->sqmodn_par.part1.octets, hash_par->sqmodn_par.part1.noctets, 0);
	}
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, FALSE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* check input data for verification	               */
	/*-----------------------------------------------------*/
	if (in_octets == NULL) {
		sca_errno = M_EINDATA;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check signature and signature algorithm, algorithm */
	/* must be RSA.                                       */
	/*-----------------------------------------------------*/
	if (signature == NULL) {
		sca_errno = M_EPOINTER;
		set_errmsg();
		return (-1);
	} else {
		if ((signature->signature.bits == NULL) ||
		    (signature->signAI == NULL) ||
		    (signature->signAI->objid == NULL)) {
			sca_errno = M_EPOINTER;
			set_errmsg();
			return (-1);
		} else {

			if ((aux_ObjId2ParmType(signature->signAI->objid) == PARM_NULL) &&
			    (signature->signAI->parm)) {
				sca_errno = M_EPAR;
				set_errmsg();
				return (-1);
			}
		}



	}

	if ((sct_algid = get_sct_algid(signature->signAI)) == -1)
		return (-1);
	if (sct_algid != S_RSA_F4) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check parameter more  		               */
	/*-----------------------------------------------------*/
	if ((more != END) && (more != MORE)) {
		sca_errno = M_EMORE;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check key selection (only key from calling routine */
	/* allowed)                      */
	/* check key (key must be a public RSA key)           */
	/* key-id is not evaluated.			       */
	/*-----------------------------------------------------*/
	if (key_sel == NULL) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	} else {
		if (key_sel->key_bits == NULL) {
			sca_errno = M_EKEY;
			set_errmsg();
			return (-1);
		} else if ((key_sel->key_bits->part1.octets == NULL) ||
			   (key_sel->key_bits->part2.octets == NULL)) {
			sca_errno = M_EKEY;
			set_errmsg();
			return (-1);
		}
	}
	if (((sct_algid = get_sct_algid(key_sel->key_algid)) == -1) ||
	    (sct_algid != S_RSA_F4)) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/
/************** now start hash function     *********************************/


	/*-----------------------------------------------------*/
	/* if first call of verify function		       */
	/* then 1) get hash algorithm,                         */
	/* 2) if algorithm = RSA-sqmodn                        */
	/* then a) check hash-parameter                        */
	/* b) set key (modulus) for hash-                      */
	/* function                                            */
	/* 3) allocate storage for hash result                 */
	/*-----------------------------------------------------*/

	if (act_function == F_null) {	/* first call of sca_verify */

		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		algenc = aux_ObjId2AlgEnc(signature->signAI->objid);
		algspecial = aux_ObjId2AlgSpecial(signature->signAI->objid);

		if (alghash == SQMODN) {
			if (hash_par == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			if (hash_par->sqmodn_par.part1.octets == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			/* set key in an internal function for hash-function */
			rc = rsa_get_key(&hash_par->sqmodn_par, 0);
			if (rc < 0) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
		}
		/* allocate storage for hash_result */
		ALLOC_OCTET(hash_result, OctetString);
		hash_result->noctets = 0;
		ALLOC_CHAR(hash_result->octets, (RSA_PARM(signature->signAI->parm) + 7) / 8);

#ifdef VERSION10
		signature_help.nbits = 0;
		ALLOC_CHAR(signature_help.bits, (RSA_PARM(signature->signAI->parm) + 7) / 8);
#endif

		act_function = F_verify;

	}
	/* end if (act_function == F_null) */
	else
	 /* not first call of sca_verify */ if (act_function != F_verify) {
		sca_errno = M_EFUNCTION;	/* wrong function call */
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Call hash function depending on algorithm         */
	/*-----------------------------------------------------*/
	switch (alghash) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_result, more,
				 RSA_PARM(signature->signAI->parm));
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_result, more);
		break;
	case SHA:
		rc = sha_hash(in_octets, hash_result, more);
		break;
	default:
		sca_errno = EINVALGID;
		set_errmsg();
		goto errcase;
	}			/* end switch */
	if (rc < 0) {
		sca_errno = M_EHASH;
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Now hashing is done			       */
	/* If last call of sca_verify ( more = END)          */
	/* then call sct-interface                        */
	/*-----------------------------------------------------*/
	if (more == END) {	/* last call of sca_verify */

#ifdef TEST
		fprintf(stdout, "hash result: \n");
		aux_fxdump(stdout, hash_result->octets, hash_result->noctets, 0);
#endif

#ifdef VERSION10

		/*
		 * hash-value and signature must have the same length as the
		 * modulus
		 */
		modulus_len = RSA_PARM(signature->signAI->parm) / 8;

#ifdef TEST
		fprintf(stdout, "modulus len: %d \n", modulus_len);
#endif

		if (hash_result->noctets < modulus_len) {
			if(algspecial == PKCS_BT_01 || algspecial == PKCS_BT_TD) {

				/*  Here goes PKCS#1 ...   */

				encodedDigest = aux_create_PKCS_MIC_D(hash_result, signature->signAI);
				aux_free_OctetString(&hash_result);		
				hash_result = aux_create_PKCSBlock(1, encodedDigest);
				if(algspecial == PKCS_BT_TD) {
					o1 = (OctetString *)malloc(sizeof(OctetString));
					o1->noctets = 0;
					o1->octets = malloc(256);
					rc = rsa_get_key(key_sel->key_bits, 0);
					if (rc < 0) aux_add_error(EINVALID, "rsa_get_key failed", CNULL, 0, proc);
					rsa_encblock2OctetString(&(signature->signature), o1);
					for(i = 1; i < 20; i++) {
						if((unsigned char)o1->octets[i] == 255) {
							o1->octets[i] = '\0';
							sec_SignatureTimeDate = (UTCTime *)aux_cpy_String(&(o1->octets[1]));
							break;
						}
						hash_result->octets[i] = o1->octets[i];
					}
					hash_result->octets[0] = PKCS_BT_TD;
					aux_free_OctetString(&o1);
				}
				if(encodedDigest) aux_free_OctetString(&encodedDigest);
			}
#ifdef VERSION10
			ALLOC_OCTET(hash2_result, OctetString);
			hash2_result->noctets = 0;
			ALLOC_CHAR(hash2_result->octets, (RSA_PARM(signature->signAI->parm) + 7) / 8);
#endif

			i = modulus_len - hash_result->noctets;
			for (j = 0; j < i; j++)
				hash2_result->octets[j] = 0x00;
			for (i = 0; i < hash_result->noctets; i++, j++)
				hash2_result->octets[j] = hash_result->octets[i];
			hash2_result->noctets = modulus_len;
			aux_free_OctetString(&hash_result);		
			hash_result = hash2_result;

#ifdef TEST
			fprintf(stdout, "hash result: \n");
			aux_fxdump(stdout, hash_result->octets, 64, 0);
#endif
		}

		signature_len = signature->signature.nbits / 8;

#ifdef TEST
		fprintf(stdout, "signature len: %d \n", signature_len);
#endif

		if (signature_len < modulus_len) {
			i = modulus_len - signature_len;
			for (j = 0; j < i; j++)
				signature_help.bits[j] = 0x00;
			for (i = 0; i < signature_len; i++, j++)
				signature_help.bits[j] = signature->signature.bits[i];
			signature->signature.nbits = modulus_len * 8;
			signature->signature.bits = signature_help.bits;

#ifdef TEST
			fprintf(stdout, "signature: \n");
			aux_fxdump(stdout, signature->signature.bits, modulus_len, 0);
#endif
		}
#endif

		/*-----------------------------------------------------*/
		/* Prepare parameters for the SCT Interface          */
		/*-----------------------------------------------------*/
		command = S_RSA_VERIFY;
		request.rq_p1.kid = 0x00;
		sctint_modulus.nbytes = key_sel->key_bits->part1.noctets;
		sctint_modulus.bytes = key_sel->key_bits->part1.octets;
		if ((compare(key_sel->key_bits->part2.octets, fermat_f4, fermat_f4_len)) == 0) {
			sctint_exponent.nbytes = 0;	/* default exponent */
			sctint_exponent.bytes = NULL;
		} else {	/* exponent not = Fermatzahl F4 */
			sctint_exponent.nbytes = key_sel->key_bits->part2.noctets;
			sctint_exponent.bytes = key_sel->key_bits->part2.octets;
		}
		sctint_signature.nbytes = signature->signature.nbits / 8;
		sctint_signature.bytes = signature->signature.bits;
		sctint_hash.nbytes = hash_result->noctets;
		sctint_hash.bytes = hash_result->octets;
		if ((request.rq_datafield.verify = (Verify *) malloc(sizeof(Verify))) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			goto errcase;
		}
		if ((request.rq_datafield.verify->public = (Public *) malloc(sizeof(Public))) == NULL) {
			sca_errno = M_EMEMORY;
			set_errmsg();
			free(request.rq_datafield.verify);
			goto errcase;
		}
		request.rq_datafield.verify->public->modulus = &sctint_modulus;
		request.rq_datafield.verify->public->exponent = &sctint_exponent;
		request.rq_datafield.verify->signature = &sctint_signature;
		request.rq_datafield.verify->hash = &sctint_hash;


		/*-----------------------------------------------------*/
		/* Call SCT Interface     			       */
		/*-----------------------------------------------------*/
		rc = sct_interface(sct_id, command, &request, &response);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			free(request.rq_datafield.verify);
			free(request.rq_datafield.verify->public);
			goto errcase;
		}
		/*-----------------------------------------------------*/
		/* rc == S_SIKOK (M_SIGOK) means   		       */
		/* signature correct, keysize too short (256)    */
		/*-----------------------------------------------------*/
		if (rc == S_SIGOK)
			sca_errno = M_SIGOK;

		/*-----------------------------------------------------*/
		/* Normal End	 (Release storage)		       */
		/*-----------------------------------------------------*/
		free(request.rq_datafield.verify);
		free(request.rq_datafield.verify->public);
		aux_free_OctetString(&hash_result);

#ifdef VERSION10
		free(signature_help.bits);
#endif

		sta_aux_bytestr_free(&response);

		act_function = F_null;

	}			/* end if (more == END) */
#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_verify *********************************************\n\n");
#endif

	return (sca_errno);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	aux_free_OctetString(&hash_result);

#ifdef VERSION10
	free(signature_help.bits);
#endif

	act_function = F_null;
	return (-1);


}				/* end sca_verify */


/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_verify    	       */
/*-------------------------------------------------------------*/
#endif

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_encrypt               VERSION   1.0	       */
/*				     DATE   Juli 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Encrypt OctetString in SCT or SC.			       */
/*							       */
/*  Observe that: 					       */
/*	If VERSION10 is defined	and the exponent is not F4     */
/*	   then the exponent is padded with                    */
/*		leading zeroes (X'00') to the modulus length.  */
/*							       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   in_octets		       Octetstring of the data to be   */
/*                             encrypted.                      */
/*                                                             */
/*   out_octets                Encrypted data                  */
/*                                                             */
/*   more		       = MORE -> more data is expected */
/*   			       = END  -> Last data for this    */
/*				         encryption   process. */
/*                                                             */
/*   key_sel                   Structure which identifies the  */
/*                             encryption   key.               */
/*			       DES:			       */
/*			       The key is stored either in the */
/*			       SCT or in the SC.	       */
/*			       RSA:			       */
/*                             In the current version only the */
/*			       delivery of a public RSA key is */
/*			       supported (key_sel->key_bits).  */
/*   sec_mess                  Specification of the security   */
/*			       modes for the data exchange     */
/*			       between SCT and SC.	       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EINDATA		       */
/*				 M_EOUTDAT		       */
/*				 M_EMORE		       */
/*				 M_EKEY 		       */
/*				 EINVALGID		       */
/*				 M_EMEMORY		       */
/*				 M_EFUNCTION		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
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
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
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
/*							       */
/*  Achtung !!!!					       */
/*  In der Smartcard wird der CBC-Mode nur auf ein Kommando    */
/*  angewendet, d.h. Texte, die groesser als 32 Bytes sind     */
/*  werden in der SC nicht richtig behandelt, da bei jedem     */
/*  SC_CRYPT-Kommando der erste Block wieder mit dem Initial-  */
/*  vektor (0) verschluesselt wird und nicht wie beim CBC-Mode */
/*  mit dem letzten Chiffratblock.			       */
/*  STAMOD fuehrt deshalb folgende Funktionen durch:           */
/*  Im Falle von MORE=MORE wird der Text in 32er Bloecke       */
/*  aufgeteilt; Ist der Text kein Vielfaches von 32, dann wird */
/*  der Rest in STAMOD zwischengespeichert. Beim naechsten     */
/*  Aufruf wird der Rest mit dem neuen Text konkateniert und   */
/*  wieder in 32er Bloecke versendet.			       */
/*  Im Falle von MORE=END wird geprueft, ob die Anzahl der zu  */
/*  uebertragenden Bytes ein Vielfaches von 8 ist. Ist dies    */
/*  nicht der Fall, dann wird mit Padding Bytes aufgefuellt.   */
/*							       */
/*  Nach einem erfolgreichen SC_CRYPT-Kommando werden die      */
/*  letzten 8 Bytes des empfangenen Chiffrats auf die ersten   */
/*  8 Bytes des naechsten Klartext-Blockes geodert.            */
/*-------------------------------------------------------------*/
int
sca_encrypt(sct_id, in_octets, out_octets, more, key_sel, sec_mess)
	int             sct_id;
	OctetString    *in_octets;
	OctetString    *out_octets;
	More            more;
	KeySel         *key_sel;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					            */
	/*----------------------------------------------------------*/
	int             rc, i, first_len, next_len, apdusize, act_length, NOTENDE,
	                trans_length, enc_len, in_newlen, in_conc_len, offset,
	                j, len_public;
	static AlgEnc   algenc = NOENC;
	Bytestring      sctint_modulus;	/* modulus for SCT-Interface         */
	Bytestring      sctint_exponent;	/* exponent for SCT-Interface        */
	Enc             sctint_enc;
	Public          sctint_public;
	char            sct_keyid;	/* char representation of the key_id */
	Bytestring      bstring;
	SCTMore         cmd_more;
	char           *in_ptr, *out_ptr, *in_new, *in_conc, *exponent2_bytes;
	KeyLevel        key_level;

	/*----------------------------------------------------------*/
	/* Statements					            */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	in_new = NULL;
	in_conc = NULL;
	exponent2_bytes = NULL;
	if(algenc == NOENC) algenc = aux_ObjId2AlgEnc(key_sel->key_algid->objid);

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_encrypt *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	if ((in_octets != NULL) && (in_octets->octets != NULL)) {
		fprintf(stdout, "in_octets               : \n");
		fprintf(stdout, "    noctets             : %d\n", in_octets->noctets);
		fprintf(stdout, "    octets              : \n");
		aux_fxdump(stdout, in_octets->octets, in_octets->noctets, 0);
	} else
		fprintf(stdout, "in_octets/in_octets->octets : NULL\n");

	if ((out_octets == NULL) || (out_octets->octets == NULL))
		fprintf(stdout, "out_octets/out_octets->octets : NULL\n");


	if (more == MORE)
		fprintf(stdout, "more                    : MORE\n");
	else {
		if (more == END)
			fprintf(stdout, "more                    : END\n");
		else
			fprintf(stdout, "more                    : undefined\n");
	}

	fprintf(stdout, "key_sel	        : \n");
	if (key_sel != NULL) {
		fprintf(stdout, "    key_algid           : %s\n", aux_ObjId2Name(key_sel->key_algid->objid));
		if(aux_ObjId2AlgEnc(key_sel->key_algid->objid) == RSA) {
			if (key_sel->key_bits == NULL)
				fprintf(stdout, "    key_bits            : NULL\n");
			else {
				fprintf(stdout, "    key_bits            : \n");
				if (key_sel->key_bits->part1.octets == NULL)
					fprintf(stdout, "    part1               : NULL\n");
				else {
					fprintf(stdout, "    part1               : \n");
					fprintf(stdout, "        noctets         : %d\n",
					  key_sel->key_bits->part1.noctets);
					fprintf(stdout, "        octets          : \n");
					aux_fxdump(stdout, key_sel->key_bits->part1.octets,
					key_sel->key_bits->part1.noctets, 0);
				}
				if (key_sel->key_bits->part2.octets == NULL)
					fprintf(stdout, "    part2               : NULL\n");
				else {
					fprintf(stdout, "    part2               : \n");
					fprintf(stdout, "        noctets         : %d\n",
					  key_sel->key_bits->part2.noctets);
					fprintf(stdout, "        octets          : \n");
					aux_fxdump(stdout, key_sel->key_bits->part2.octets,
					key_sel->key_bits->part2.noctets, 0);
				}
			}
		}
		else print_keyid(&key_sel->key_id);
	} 
	else fprintf(stdout, "key_sel	        : NULL\n");

	print_secmess(sec_mess);
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* check input data for encryption	               */
	/*-----------------------------------------------------*/

	if ((in_octets == NULL) ||
	    (in_octets->noctets == 0) ||
	    (in_octets->octets == NULL)) {
		sca_errno = M_EINDATA;
		set_errmsg();
		return (-1);
	}

	/*-----------------------------------------------------*/
	/* check output data for encrypted data	               */
	/*-----------------------------------------------------*/

	if ((out_octets == NULL) ||
	    (out_octets->octets == NULL)) {
		sca_errno = M_EOUTDAT;
		set_errmsg();
		return (-1);
	}

	/*-----------------------------------------------------*/
	/* check parameter more  		               */
	/*-----------------------------------------------------*/

	if ((more != END) && (more != MORE)) {
		sca_errno = M_EMORE;
		set_errmsg();
		return (-1);
	}

	/*-----------------------------------------------------*/
	/* check key selection                                 */
	/*-----------------------------------------------------*/

	if (key_sel == NULL) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	} 

	/*-----------------------------------------------------*/
	/* check algorithm (must be RSA / DES-CBC / DES-EDE)   */
	/*-----------------------------------------------------*/

	sc_expect = FALSE;
	switch(algenc) {

	case RSA:


		/*-----------------------------------------------------*/
		/* if first call of encryption function	               */
		/*-----------------------------------------------------*/

		if (act_function == F_null) {	/* first call of sca_encrypt */


			/*-----------------------------------------------------*/
			/* check key selection in case of RSA                  */
			/* check key (key must be a public RSA key)            */
			/*-----------------------------------------------------*/
			if (key_sel->key_bits == NULL) {
				sca_errno = M_EKEY;
				set_errmsg();
				return (-1);
			} else {
				if ((key_sel->key_bits->part1.octets == NULL) ||
				(key_sel->key_bits->part2.octets == NULL)) {
					sca_errno = M_EKEY;
					set_errmsg();
					return (-1);
				}
			}
			sctint_modulus.nbytes = key_sel->key_bits->part1.noctets;
			sctint_modulus.bytes = key_sel->key_bits->part1.octets;
			if ((compare(key_sel->key_bits->part2.octets,
				     fermat_f4, fermat_f4_len)) == 0) {
				sctint_exponent.nbytes = 0;	/* default exponent */
				sctint_exponent.bytes = NULL;
			} else {/* exponent not = Fermatzahl F4 */
				sctint_exponent.nbytes = key_sel->key_bits->part2.noctets;
				sctint_exponent.bytes = key_sel->key_bits->part2.octets;

#ifdef VERSION10

				/*
				 * the exponent must have the same length as
				 * the modulus
				 */

				if (sctint_exponent.nbytes < sctint_modulus.nbytes) {
					ALLOC_CHAR(exponent2_bytes, sctint_modulus.nbytes);

					i = sctint_modulus.nbytes - sctint_exponent.nbytes;
					for (j = 0; j < i; j++)
						*(exponent2_bytes + j) = 0x00;
					for (i = 0; i < sctint_exponent.nbytes; i++, j++)
						*(exponent2_bytes + j) = *(sctint_exponent.bytes + i);
					sctint_exponent.nbytes = sctint_modulus.nbytes;
					sctint_exponent.bytes = exponent2_bytes;

				}
#endif
			}	/* exponent not = Fermatzahl F4 */
			if (sctint_exponent.nbytes == 0)
				len_public = sctint_modulus.nbytes + 3;
			else
				len_public = sctint_modulus.nbytes +
					sctint_exponent.nbytes + 2;

#ifdef DEFINED
			if (more == END) {
				if (in_octets->noctets > 245 - len_public)
					first_len = 120;
				else
					first_len = 245 - len_public;

			} else
				first_len = 120;
#else
			if (more == END) {
				if (in_octets->noctets > 128)
					first_len = 120;
				else
					first_len = 128;

			} else
				first_len = 120;
#endif


		} else {	/* next call of sca_encrypt */
			sctint_modulus.nbytes = 0;
			sctint_modulus.bytes = NULL;
			sctint_exponent.nbytes = 0;
			sctint_exponent.bytes = NULL;
			first_len = 120;

		}
		command = S_RSA_ENC;
		request.rq_p1.kid = 0x00;

		sctint_public.modulus = &sctint_modulus;
		sctint_public.exponent = &sctint_exponent;
		sctint_enc.public = &sctint_public;
		request.rq_datafield.enc = &sctint_enc;

		key_level = SCT;

		in_ptr = in_octets->octets;
		next_len = 120;
		act_length = in_octets->noctets;

		break;

	case DES:
	case DES3:
		/* if key_level = SCT => smartcard must be inserted */
		if (key_sel->key_id.key_level != SCT) {

			first_len = 32;
			next_len = 32;
			sc_expect = TRUE;


		} else {
			command = S_DES_ENC;
			/*-----------------------------------------------------*/
			/* check key_id and get keyid in char representation  */
			/*-----------------------------------------------------*/
			if ((sct_keyid = get_sct_keyid(&key_sel->key_id)) == -1)
				return (-1);
			request.rq_p1.kid = sct_keyid;
			first_len = 240;
			next_len = 240;

			in_ptr = in_octets->octets;
			act_length = in_octets->noctets;
		};
		key_level = key_sel->key_id.key_level;
		break;
	default:
		sca_errno = EINVALGID;
		set_errmsg();
		goto errcase;
	}			/* end switch */

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);


/************** input parameter check done *********************************/





	if (act_function == F_null) {	/* first call of sca_encrypt */
		in_rest_len = 0;
		in_rest = NULL;

		/* initialize cbc_initvek with zero */
		for (i = 0; i < 8; i++)
			cbc_initvek[i] = 0x00;


		if (key_level != SCT) {
			if (more == END) {
				if ((in_octets->noctets % 8) > 0) {
					/* allocate buffer, Padding with Zero */
					in_newlen = (in_octets->noctets -
					      (in_octets->noctets % 8)) + 8;
					ALLOC_CHAR(in_new, in_newlen);
					for (i = 0; i < in_newlen; i++)
						*(in_new + i) = 0x00;
					for (i = 0; i < in_octets->noctets; i++)
						*(in_new + i) = *(in_octets->octets + i);
					act_length = in_newlen;
					in_ptr = in_new;
				} else {
					in_ptr = in_octets->octets;
					act_length = in_octets->noctets;

				}
			} else {/* more == MORE */
				if ((in_octets->noctets % 32) > 0) {
					/* save rest for next transfer */
					in_rest_len = in_octets->noctets % 32;
					act_length = in_octets->noctets - in_rest_len;
					ALLOC_CHAR(in_rest, in_rest_len);

					offset = in_octets->noctets - in_rest_len;
					for (i = 0; i < in_rest_len; i++) {
						*(in_rest + i) = *(in_octets->octets + offset);
						offset++;
					}
					if (act_length == 0) {
						out_octets->noctets = 0;
						act_function = F_encrypt;
						return (0);
					}
					in_ptr = in_octets->octets;

				} else {
					in_ptr = in_octets->octets;
					act_length = in_octets->noctets;
				}
			}

		}
		act_function = F_encrypt;

	}
	/* end if (act_function == F_null) */
	else {			/* not first call of sca_encrypt */
		if (act_function != F_encrypt) {
			sca_errno = M_EFUNCTION;	/* wrong function call */
			set_errmsg();
			goto errcase;
		};

		if (key_level != SCT) {
			if (in_rest_len > 0) {
				in_conc_len = in_octets->noctets + in_rest_len;
			} else
				in_conc_len = in_octets->noctets;

			ALLOC_CHAR(in_conc, in_conc_len);

			for (i = 0; i < in_rest_len; i++)
				*(in_conc + i) = *(in_rest + i);

			free(in_rest);
			in_rest = NULL;

			offset = in_rest_len;
			for (i = 0; i < in_octets->noctets; i++) {
				*(in_conc + offset) = *(in_octets->octets + i);
				offset++;

			}
			in_rest_len = 0;


			if (more == END) {
				if ((in_conc_len % 8) > 0) {
					/* allocate buffer, Padding with Zero */
					in_newlen = (in_conc_len -
						     (in_conc_len % 8)) + 8;
					ALLOC_CHAR(in_new, in_newlen);
					for (i = 0; i < in_newlen; i++)
						*(in_new + i) = 0x00;
					for (i = 0; i < in_conc_len; i++)
						*(in_new + i) = *(in_conc + i);
					free(in_conc);
					in_conc_len = 0;
					in_conc = NULL;
					act_length = in_newlen;
					in_ptr = in_new;
				} else {
					in_ptr = in_conc;
					act_length = in_conc_len;
				}
			} else {/* more == MORE */
				if ((in_conc_len % 32) > 0) {
					/* save rest for next transfer */
					in_rest_len = in_conc_len % 32;
					act_length = in_conc_len - in_rest_len;

					ALLOC_CHAR(in_rest, in_rest_len);

					offset = in_conc_len - in_rest_len;
					for (i = 0; i < in_rest_len; i++) {
						*(in_rest + i) = *(in_conc + offset);
						offset++;
					}
					if (act_length == 0) {
						free(in_conc);
						return (0);
					}
					in_ptr = in_conc;
				} else {
					in_ptr = in_conc;
					act_length = in_conc_len;
				}
			}
		}
	}




	/*-----------------------------------------------------*/
	/* if last call of encryption function                */
	/*-----------------------------------------------------*/
	if (more == END) {	/* last call of sca_encrypt */
		algenc = NOENC;
		act_function = F_null;

	};






	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	max_length = first_len;

#ifdef TEST
	fprintf(stdout, "FIRST_LEN = %d\n", first_len);
#endif

	NOTENDE = TRUE;
	out_ptr = out_octets->octets + out_octets->noctets;
	enc_len = 0;
	do {
		if (act_length <= max_length) {
			trans_length = act_length;
			if (more == END)
				cmd_more = SCT_END;
			else
				cmd_more = SCT_MORE;

			NOTENDE = FALSE;
		} else {
			trans_length = max_length;
			cmd_more = SCT_MORE;
			max_length = next_len;
		}
		switch (key_level) {
		case SCT:

			request.rq_p2.more = cmd_more;
			bstring.nbytes = trans_length;
			bstring.bytes = in_ptr;

			if (command == S_RSA_ENC)
				request.rq_datafield.enc->plaintext = &bstring;
			else
				request.rq_datafield.plaintext = &bstring;
			/*-----------------------------------------------------*/
			/* Call SCT Interface     			   */
			/*-----------------------------------------------------*/
			rc = sct_interface(sct_id, command, &request, &response);
			if (rc < 0) {
				sca_errno = sct_errno;
				sca_errmsg = sct_errmsg;
				err_analyse(sct_id);
				goto errcase;
			};
			sctint_modulus.nbytes = 0;
			sctint_exponent.nbytes = 0;

			break;

		default:
			/*-------------------------------------*/
			/* create SC command CRYPT            */
			/*-------------------------------------*/
			/* create header                       */

			/* in_ptr[0..7] XOR cbc_initvek[0..7] for CBC-Mode */
			for (i = 0; i < 8; i++)
				*(in_ptr + i) = *(in_ptr + i) ^ cbc_initvek[i];


			if (cr_header(SC_CRYPT, sec_mess))
				goto errcase;


			/* set parameters			  */
			SCCRYPT.kid = &key_sel->key_id;
			SCCRYPT.modi = SC_ENC;

			SCCRYPT.lcrdata = trans_length;
			SCCRYPT.crdata = in_ptr;



			/* call create_trans			  */
			if (create_trans(sct_id, TRUE))
				goto errcase;

			/* save last 8 Bytes of ciphertext in cbc_initvek */
			j = 1;
			for (i = 7; i >= 0; i--) {
				cbc_initvek[i] = *(response.bytes + response.nbytes - j);
				j++;
			}

			break;

		}
		in_ptr += trans_length;
		act_length -= trans_length;
		for (i = 0; i < response.nbytes; i++) {
			*out_ptr = *(response.bytes + i);
			out_ptr++;
		}
		out_octets->noctets += response.nbytes;
		enc_len += response.nbytes;

		/*-----------------------------------------------------*/
		/* Normal End	 (Release storage)		 */
		/*-----------------------------------------------------*/
		sta_aux_bytestr_free(&response);

	} while (NOTENDE);

	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/

	if(in_new) free(in_new);
	if(in_conc) free(in_conc);
	if(exponent2_bytes) free(exponent2_bytes);








#ifdef TEST
	offset = out_octets->noctets - enc_len;
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "out_octets              : \n");
	fprintf(stdout, "    enc_len             : %d\n", enc_len);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, out_octets->octets + offset, enc_len, 0);

	fprintf(stdout, "\n***** Normal end of   sca_encrypt *****\n\n");
#endif


	return (enc_len);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	algenc = NOENC;
	act_function = F_null;
	sta_aux_bytestr_free(&response);
	if(in_new) free(in_new);
	if(in_conc) free(in_conc);
	if(in_rest) free(in_rest);
	in_rest = NULL;
	in_rest_len = NULL;
	if(exponent2_bytes) free(exponent2_bytes);
	return (-1);


}				/* end sca_encrypt */


/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_encrypt 	       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_decrypt               VERSION   1.0	       */
/*				     DATE   Juli 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Decrypt OctetString in SCT or SC.			       */
/*							       */
/*							       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   in_octets		       Octetstring of the encrypted    */
/*                             data                            */
/*                                                             */
/*   out_octets                Decrypted data                  */
/*                                                             */
/*   more		       = MORE -> more data is expected */
/*   			       = END  -> Last data for this    */
/*				         decryption   process. */
/*                                                             */
/*   key_sel                   Structure which identifies the  */
/*                             decryption   key.               */
/*			       DES:			       */
/*			       The key is stored either in the */
/*			       SCT or in the SC.	       */
/*			       RSA:			       */
/*                             The privat RSA key must be      */
/*			       stored in the SC.               */
/*   sec_mess                  Specification of the security   */
/*			       modes for the data exchange     */
/*			       between SCT and SC.	       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EINDATA		       */
/*				 EINVALGID		       */
/*				 M_EMORE		       */
/*				 M_EMEMORY		       */
/*				 M_EFUNCTION		       */
/*				 M_EOUTDAT		       */
/*				 M_EKEY 		       */
/* CALLED FUNCTIONS					       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
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
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
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
/*  Achtung !!!						       */
/*  Da in der Smartcard der CBC-Mode nur auf ein Kommando      */
/*  angewendet wird, d.h. Texte, die groesser als 32 Bytes sind*/
/*  werden in der SC nicht richtig behandelt, da bei jedem     */
/*  SC_CRYPT-Kommando der erste Block wieder mit dem Initial-  */
/*  vektor (0) entschluesselt wird und nicht wie beim CBC-Mode */
/*  mit dem letzten Chiffratblock des letzten SC_CRYPT-Kdos    */
/*  werden von STAMOD folgende Funktionen durchgefuehrt:       */
/*  Der gesamte Text wird in 8 Byte-Bloecke versendet.         */
/*  Die zu versendenden 8 Chiffrebytes werden als Initialvektor*/
/*  gesichert. D.h. die naechsten 8 Chiffrebytes werden zur SC */
/*  gesendet. Die von der Karte empfangenen Bytes werden mit   */
/*  dem Initialvektor geodert => Klartext.                     */
/*  							       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_decrypt(sct_id, in_octets, out_octets, more, key_sel, sec_mess)
	int             sct_id;
	OctetString    *in_octets;
	OctetString    *out_octets;
	More            more;
	KeySel         *key_sel;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc, i, act_length, NOTENDE, trans_length, dec_len, in_conc_len,
	                offset;
	static AlgEnc   algenc = NOENC;

	char            sct_keyid;	/* char representation of the key_id */
	Bytestring      bstring;
	SCTMore         cmd_more;
	char           *in_ptr, *out_ptr, *in_conc;
	KeyLevel        key_level;



	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	in_conc = NULL;
	if(algenc == NOENC) algenc = aux_ObjId2AlgEnc(key_sel->key_algid->objid);

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_decrypt *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	if ((in_octets != NULL) && (in_octets->octets != NULL)) {
		fprintf(stdout, "in_octets               : \n");
		fprintf(stdout, "    noctets             : %d\n", in_octets->noctets);
		fprintf(stdout, "    octets              : \n");
		aux_fxdump(stdout, in_octets->octets, in_octets->noctets, 0);
	} else
		fprintf(stdout, "in_octets/in_octets->octets : NULL\n");

	if ((out_octets == NULL) || (out_octets->octets == NULL))
		fprintf(stdout, "out_octets/out_octets->octets : NULL\n");
	if (more == MORE)
		fprintf(stdout, "more                    : MORE\n");
	else {
		if (more == END)
			fprintf(stdout, "more                    : END\n");
		else
			fprintf(stdout, "more                    : undefined\n");
	}

	fprintf(stdout, "key_sel	        : \n");
	if (key_sel != NULL) {
			fprintf(stdout, "    key_algid           : %s\n", aux_ObjId2Name(key_sel->key_algid->objid));
			print_keyid(&key_sel->key_id);
	} 
	else fprintf(stdout, "key_sel	        : NULL\n");

	print_secmess(sec_mess);
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	/*-----------------------------------------------------*/
	/* check key selection                                 */
	/*-----------------------------------------------------*/
	if (key_sel == NULL) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check input data for encryption	               */
	/*-----------------------------------------------------*/
	if ((in_octets == NULL) ||
	    (in_octets->noctets == 0) ||
	    (in_octets->octets == NULL)) {
		sca_errno = M_EINDATA;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check algorithm (must be RSA / DES-CBC / DES-EDE)   */
	/*-----------------------------------------------------*/

	sc_expect = FALSE;
	switch (algenc) {
	case RSA:

		sc_expect = TRUE;	/* smartcard must be inserted */
		command = S_RSA_DEC;
		/*-----------------------------------------------------*/
		/* check key_id and get keyid in char representation   */
		/*-----------------------------------------------------*/
		if ((sct_keyid = get_sct_keyid(&key_sel->key_id)) == -1)
			return (-1);
		request.rq_p1.kid = sct_keyid;
		key_level = SCT;
		max_length = 128;
		act_length = in_octets->noctets;
		in_ptr = in_octets->octets;

		break;

	case DES:
	case DES3:
		/* if key_level = SCT => smartcard must be inserted */
		if (key_sel->key_id.key_level != SCT) {
			max_length = 8;
			sc_expect = TRUE;
		} else {
			command = S_DES_DEC;
			/*-----------------------------------------------------*/
			/* check key_id and get keyid in char representation  */
			/*-----------------------------------------------------*/
			if ((sct_keyid = get_sct_keyid(&key_sel->key_id)) == -1)
				return (-1);
			request.rq_p1.kid = sct_keyid;
			max_length = 240;
			act_length = in_octets->noctets;
			in_ptr = in_octets->octets;

		};
		key_level = key_sel->key_id.key_level;
		break;

	default:
		sca_errno = EINVALGID;
		set_errmsg();
		goto errcase;
	}			/* end switch */
	/*-----------------------------------------------------*/
	/* call check_sct_sc                                  */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);


	/*-----------------------------------------------------*/
	/* check output data for encrypted data	       */
	/*-----------------------------------------------------*/
	if ((out_octets == NULL) ||
	    (out_octets->octets == NULL)) {
		sca_errno = M_EOUTDAT;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check parameter more  		               */
	/*-----------------------------------------------------*/
	if ((more != END) && (more != MORE)) {
		sca_errno = M_EMORE;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/

	if (act_function == F_null) {	/* first call of sca_decrypt */

		FIRST_CRYPT_CMD = TRUE;
		for (i = 0; i < 8; i++)
			cbc_initvek[i] = *(in_octets->octets + i);

		in_rest_len = 0;
		in_rest = NULL;


		if (key_sel->key_id.key_level != SCT) {
			if (more == END) {
				if ((in_octets->noctets % 8) > 0) {
					sca_errno = M_EINDATA;
					set_errmsg();
					return (-1);
				}
				in_ptr = in_octets->octets;
				act_length = in_octets->noctets;

			} else {/* more == MORE */
				if ((in_octets->noctets % 8) > 0) {
					/* save rest for next transfer */
					in_rest_len = in_octets->noctets % 8;
					act_length = in_octets->noctets - in_rest_len;
					ALLOC_CHAR(in_rest, in_rest_len);

					offset = in_octets->noctets - in_rest_len;
					for (i = 0; i < in_rest_len; i++) {
						*(in_rest + i) = *(in_octets->octets + offset);
						offset++;
					}
					if (act_length == 0) {
						out_octets->noctets = 0;
						act_function = F_decrypt;
						return (0);
					}
					in_ptr = in_octets->octets;

				} else {
					in_ptr = in_octets->octets;
					act_length = in_octets->noctets;
				}
			}
		}
		act_function = F_decrypt;

	}
	/* end if (act_function == F_null) */
	else {			/* not first call of sca_decrypt */
		if (act_function != F_decrypt) {
			sca_errno = M_EFUNCTION;	/* wrong function call */
			set_errmsg();
			goto errcase;
		};

		if (key_sel->key_id.key_level != SCT) {
			if (in_rest_len > 0) {
				in_conc_len = in_octets->noctets + in_rest_len;
			} else
				in_conc_len = in_octets->noctets;

			ALLOC_CHAR(in_conc, in_conc_len);

			for (i = 0; i < in_rest_len; i++)
				*(in_conc + i) = *(in_rest + i);

			if(in_rest) free(in_rest);
			in_rest = NULL;

			offset = in_rest_len;
			for (i = 0; i < in_octets->noctets; i++) {
				*(in_conc + offset) = *(in_octets->octets + i);
				offset++;

			}
			in_rest_len = 0;
			if (more == END) {
				if ((in_conc_len % 8) > 0) {
					sca_errno = M_EINDATA;
					set_errmsg();
					free(in_conc);
					return (-1);
				} else {
					in_ptr = in_conc;
					act_length = in_conc_len;
				}
			} else {/* more == MORE */
				if ((in_conc_len % 8) > 0) {
					/* save rest for next transfer */
					in_rest_len = in_conc_len % 8;
					act_length = in_conc_len - in_rest_len;

					ALLOC_CHAR(in_rest, in_rest_len);

					offset = in_conc_len - in_rest_len;
					for (i = 0; i < in_rest_len; i++) {
						*(in_rest + i) = *(in_conc + offset);
						offset++;
					}
					if (act_length == 0) {
						if(in_conc) free(in_conc);
						return (0);
					}
					in_ptr = in_conc;
				} else {
					in_ptr = in_conc;
					act_length = in_conc_len;
				}
			}
		}
	}



	/*-----------------------------------------------------*/
	/* if last call of encryption function                */
	/*-----------------------------------------------------*/
	if (more == END) {	/* last call of sca_decrypt */
		algenc = NOENC;
		act_function = F_null;
	}
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	NOTENDE = TRUE;
	out_ptr = out_octets->octets + out_octets->noctets;
	dec_len = 0;
	do {
		if (act_length <= max_length) {
			trans_length = act_length;
			if (more == END)
				cmd_more = SCT_END;
			else
				cmd_more = SCT_MORE;

			NOTENDE = FALSE;
		} else {
			trans_length = max_length;
			cmd_more = SCT_MORE;
		}
		switch (key_level) {
		case SCT:

			request.rq_p2.more = cmd_more;
			bstring.nbytes = trans_length;
			bstring.bytes = in_ptr;

			request.rq_datafield.chiffrat = &bstring;
			/*-----------------------------------------------------*/
			/* Call SCT Interface     			   */
			/*-----------------------------------------------------*/
			rc = sct_interface(sct_id, command, &request, &response);
			if (rc < 0) {
				sca_errno = sct_errno;
				sca_errmsg = sct_errmsg;
				err_analyse(sct_id);
				goto errcase;
			};

			break;
		default:
			/*-------------------------------------*/
			/* create SC command CRYPT            */
			/*-------------------------------------*/
			/* create header                       */
			if (cr_header(SC_CRYPT, sec_mess))
				goto errcase;


			/* set parameters			  */
			SCCRYPT.kid = &key_sel->key_id;
			SCCRYPT.modi = SC_DEC;

			SCCRYPT.lcrdata = trans_length;
			SCCRYPT.crdata = in_ptr;



			/* call create_trans			  */
			if (create_trans(sct_id, TRUE))
				goto errcase;

			if (FIRST_CRYPT_CMD == FALSE) {
				for (i = 0; i < 8; i++)
					*(response.bytes + i) = *(response.bytes + i) ^ cbc_initvek[i];


				/* save cbc_initvek */

				for (i = 0; i < 8; i++)
					cbc_initvek[i] = *(in_ptr + i);
			} else
				FIRST_CRYPT_CMD = FALSE;


			break;

		}
		in_ptr += trans_length;
		act_length -= trans_length;
		for (i = 0; i < response.nbytes; i++) {
			*out_ptr = *(response.bytes + i);
			out_ptr++;
		}
		out_octets->noctets += response.nbytes;
		dec_len += response.nbytes;

		/*-----------------------------------------------------*/
		/* Normal End	 (Release storage)		 */
		/*-----------------------------------------------------*/
		sta_aux_bytestr_free(&response);

	} while (NOTENDE);

	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	if(in_conc) free(in_conc);





#ifdef TEST
	offset = out_octets->noctets - dec_len;
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "out_octets              : \n");
	fprintf(stdout, "    dec_len             : %d\n", dec_len);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, out_octets->octets + offset, dec_len, 0);

	fprintf(stdout, "\n***** Normal end of   sca_decrypt *****\n\n");
#endif

	return (dec_len);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	algenc = NOENC;
	act_function = F_null;
	sta_aux_bytestr_free(&response);
	if(in_conc) free(in_conc);
	if(in_rest) free(in_rest);
	return (-1);


}				/* end sca_decrypt */


/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_decrypt 	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_hash                VERSION   1.0	    	       */
/*				     DATE   Juli 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Hash octetstring in the PC			               */
/*							       */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*			       In the current version the hash */
/*			       functions are implemented within*/
/*			       the PC, therefore this parameter*/
/*			       is not evaluated.	       */
/*                                                             */
/*   in_octets		       Data to be hashed               */
/*                             signed.                         */
/*                                                             */
/*   hash_result               Hash result in case of more=END */
/*			       Memory is provide by the called */
/*			       program.			       */
/*                                                             */
/*   more		       = MORE -> more data are expected*/
/*   			       = END  -> Last data for this    */
/*				         process.              */
/*                                                             */
/*   alg_id                    Algorithm Identifier            */
/*			       The following values are        */
/*			       possible:		       */
/*			       sqmodn			       */
/*			       md2			       */
/*			       md4			       */
/*			       md5			       */
/*                                                             */
/*   hash_par                  Additional algorithm (hash_alg) */
/*                             specific parameters or the NULL */
/*                             pointer.                        */
/*			       If the hash function 'sqmodn'   */
/*			       shall be used, the public RSA   */
/*			       key must be delivered in this   */
/*			       parameter.		       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EINDATA		       */
/*				 M_EMORE		       */
/*				 M_EHASHPAR		       */
/*				 M_EPOINTER		       */
/*				 EINVALGID		       */
/*				 M_EMEMORY		       */
/*				 M_EFUNCTION		       */
/*				 M_EOUTDAT		       */
/*				 M_EHASH		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*							       */
/*							       */
/*							       */
/*  rsa_get_key		       ERROR-Codes		       */
/*				 -1 -> M_EHASHPAR              */
/*							       */
/*  hash_sqmodn 	       ERROR-Codes     	               */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md2_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md4_hash	       	       ERROR_Codes      	       */
/*				 -1 -> M_EHASH                 */
/*                                                             */
/*  md5_hash	               ERROR-Codes      	       */
/*				 -1 -> M_EHASH                 */
/*							       */
/*							       */
/*  set_errmsg						       */
/*							       */
/*							       */
/*  aux_free_OctetString		    	               */
/*							       */
/*-------------------------------------------------------------*/
int
sca_hash(sct_id, in_octets, hash_result, more, alg_id, hash_par)
	int             sct_id;
	OctetString    *in_octets;
	OctetString    *hash_result;
	More            more;
	AlgId          *alg_id;
	HashPar        *hash_par;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc, i, memolen;
	static AlgHash  alghash = NOHASH;
	static OctetString *hash_cop_result;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	hash_result->noctets = 0;
	hash_result->octets = NULL;
	if(alghash == NOHASH) alghash = aux_ObjId2AlgHash(alg_id->objid);

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_hash *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	if ((in_octets != NULL) && (in_octets->octets != NULL)) {
		fprintf(stdout, "in_octets               : \n");
		fprintf(stdout, "    noctets             : %d\n", in_octets->noctets);
		fprintf(stdout, "    octets              : \n");
		aux_fxdump(stdout, in_octets->octets, in_octets->noctets, 0);
	} else
		fprintf(stdout, "in_octets/in_octets->octets : NULL\n");

	if (hash_result == NULL)
		fprintf(stdout, "hash_result             : NULL\n");
	else {
		if (hash_result->octets == NULL)
			fprintf(stdout, "hash_result->octets     : NULL\n");
		else
			fprintf(stdout, "hash_result->octets     : Pointer\n");
	}

	if (more == MORE)
		fprintf(stdout, "more                    : MORE\n");
	else {
		if (more == END)
			fprintf(stdout, "more                    : END\n");
		else
			fprintf(stdout, "more                    : undefined\n");
	}
	fprintf(stdout, "alg_id                  : %s\n", aux_ObjId2Name(alg_id->objid));
	switch (alghash) {
	case SQMODN:
		if (hash_par != NULL) {
			fprintf(stdout, "hash_par (modulus)      : \n");
			aux_fxdump(stdout, hash_par->sqmodn_par.part1.octets, hash_par->sqmodn_par.part1.noctets, 0);
		} else
			fprintf(stdout, "hash_par                : is not evaluated\n");
		break;
	case MD2:
	case MD4:
	case MD5:
	case SHA:
		fprintf(stdout, "hash_par                : is not evaluated\n");
		break;
	default:
		fprintf(stdout, "alg_id                  : undefined\n");
		fprintf(stdout, "hash_par                : is not evaluated\n");
		break;
	}
#endif


	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/


	/*-----------------------------------------------------*/
	/* check input data for hash    	               */
	/*-----------------------------------------------------*/
	if ((in_octets == NULL) ||
	    (in_octets->octets == NULL)) {
		sca_errno = M_EINDATA;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check parameter more  		               */
	/*-----------------------------------------------------*/
	if ((more != END) && (more != MORE)) {
		sca_errno = M_EMORE;
		set_errmsg();
		return (-1);
	}
/************** input parameter check done *********************************/
/************** now start hash function     *********************************/


	/*-----------------------------------------------------*/
	/* if first call of hash function		       */
	/* then 1) get hash algorithm,                    */
	/* 2) if algorithm = RSA-sqmodn              */
	/* then a) check hash-parameter        */
	/* b) set key (modulus) for hash- */
	/* function                    */
	/* 3) allocate storage for hash result       */
	/*-----------------------------------------------------*/

	if (act_function == F_null) {	/* first call of sca_hash */

		if (alghash == SQMODN) {
			if (hash_par == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			if (hash_par->sqmodn_par.part1.octets == NULL) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			/* set key in an internal function for hash-function */
			rc = rsa_get_key(&hash_par->sqmodn_par, 0);
			if (rc < 0) {
				sca_errno = M_EHASHPAR;
				set_errmsg();
				return (-1);
			}
			memolen = (RSA_PARM(alg_id->parm) + 7) / 8;
		} else	memolen = 64;

		/* allocate storage for hash_cop_result (local memory ) */

#ifdef TEST
		fprintf(stdout, "memolen: %d \n", memolen);
#endif

		ALLOC_OCTET(hash_cop_result, OctetString);
		hash_cop_result->noctets = 0;
		ALLOC_CHAR(hash_cop_result->octets, memolen);

		act_function = F_hash;

	}
	/* end if (act_function == F_null) */
	else
	 /* not first call of sca_hash */ if (act_function != F_hash) {
		sca_errno = M_EFUNCTION;	/* wrong function call */
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Call hash function depending on algorithm         */
	/*-----------------------------------------------------*/
	switch (alghash) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_cop_result, more,
				 RSA_PARM(alg_id->parm));
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_cop_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_cop_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_cop_result, more);
		break;
	default:
		sca_errno = EINVALGID;
		set_errmsg();
		goto errcase;
	}			/* end switch */
	if (rc < 0) {
		sca_errno = M_EHASH;
		set_errmsg();
		goto errcase;
	}
	/*-----------------------------------------------------*/
	/* Now hashing is done			       */
	/* If last call of sca_hash ( more = END)            */
	/* return hash_result                             */
	/*-----------------------------------------------------*/
	if (more == END) {	/* last call of sca_hash */
		/*-----------------------------------------------------*/
		/* check output parameter for hash    	         */
		/*-----------------------------------------------------*/
		if (hash_result == NULL) {
			sca_errno = M_EOUTDAT;
			set_errmsg();
			goto errcase;
		}
		/*-----------------------------------------------------*/
		/* allocate buffer for hash_result->octets and       */
		/* copy hash_cop_result				 */
		/*-----------------------------------------------------*/
		ALLOC_CHAR(hash_result->octets, hash_cop_result->noctets);
		hash_result->noctets = hash_cop_result->noctets;
		for (i = 0; i < hash_result->noctets; i++)
			*(hash_result->octets + i) = *(hash_cop_result->octets + i);


		/*-----------------------------------------------------*/
		/* Normal End	 (Release storage)		 */
		/*-----------------------------------------------------*/
		aux_free_OctetString(&hash_cop_result);

		alghash = NOHASH;
		act_function = F_null;

#ifdef TEST
		fprintf(stdout, "TRACE of the output parameters : \n");
		fprintf(stdout, "hash_result             : \n");
		fprintf(stdout, "    noctets             : %d\n", hash_result->noctets);
		fprintf(stdout, "    octets              : \n");
		aux_fxdump(stdout, hash_result->octets, hash_result->noctets, 0);
#endif


	}			/* end if (more == END) */
#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_hash *****\n\n");
#endif

	return (sca_errno);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	alghash = NOHASH;
	aux_free_OctetString(&hash_cop_result);
	act_function = F_null;
	return (-1);


}				/* end sca_hash */


/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_hash    	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_enc_des_key         VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Encrypt a DES key in the SCT with RSA		       */
/*							       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   encryption_key            Structure which identifies the  */
/*			       the encryption key.             */
/*                                                             */
/*   plain_key                 Key identifier of the key to be */
/*                             encrypted                       */
/*							       */
/*							       */
/* OUT							       */
/*   encrypted_key             Structure which contains  the   */
/*			       AlgId of the encryption key, the*/
/*			       AlgId of the encrypted key and  */
/*			       the encrypted key.	       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EKEY 		       */
/*				 EINVALGID		       */
/*				 M_EOUTDAT		       */
/*				 M_EMEMORY		       */
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
/*							       */
/*  get_sct_keyid              ERROR-Codes		       */
/*			         EINVKID		       */
/*							       */
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
/*  compare						       */
/*-------------------------------------------------------------*/
int
sca_enc_des_key(sct_id, encryption_key, plain_key, encrypted_key)
	int             sct_id;
	KeySel         *encryption_key;
	KeyId          *plain_key;
	EncryptedKey   *encrypted_key;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i, j;
	int             rc;
	static AlgEnc   algenc;
	static AlgType  algtype;
	Bytestring      sctint_modulus;	/* modulus for SCT-Interface         */
	Bytestring      sctint_exponent;	/* exponent for SCT-Interface        */
	Public          sctint_public;
	char            sct_keyid;	/* char representation of the key_id */
	char           *exponent2_bytes, *key_buffer;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	key_buffer = NULL;
	exponent2_bytes = NULL;
	algenc = aux_ObjId2AlgEnc(encryption_key->key_algid->objid);
	algtype = aux_ObjId2AlgType(encryption_key->key_algid->objid);

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_enc_des_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	fprintf(stdout, "encryption_key	        : \n");

	if (encryption_key != NULL) {
		switch (algenc) {
		case RSA:
			fprintf(stdout, "    key_algid           : RSA\n");
			if (encryption_key->key_bits == NULL)
				fprintf(stdout, "    key_bits            : NULL\n");
			else {
				fprintf(stdout, "    key_bits            : \n");
				if (encryption_key->key_bits->part1.octets == NULL)
					fprintf(stdout, "    part1               : NULL\n");
				else {
					fprintf(stdout, "    part1               : \n");
					fprintf(stdout, "        noctets         : %d\n",
						encryption_key->key_bits->part1.noctets);
					fprintf(stdout, "        octets          : \n");
					aux_fxdump(stdout, encryption_key->key_bits->part1.octets,
						   encryption_key->key_bits->part1.noctets, 0);
				}
				if (encryption_key->key_bits->part2.octets == NULL)
					fprintf(stdout, "    part2               : NULL\n");
				else {
					fprintf(stdout, "    part2               : \n");
					fprintf(stdout, "        noctets         : %d\n",
						encryption_key->key_bits->part2.noctets);
					fprintf(stdout, "        octets          : \n");
					aux_fxdump(stdout, encryption_key->key_bits->part2.octets,
						   encryption_key->key_bits->part2.noctets, 0);
				}
			}
			break;
		default:
			fprintf(stdout, "    key_algid           : undefined\n");
			break;

		}
		fprintf(stdout, "    key_id              : unused\n");
	}
	else fprintf(stdout, "encryption_key	: NULL\n");

	print_keyid(plain_key);
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*--------------------------------------------------------*/
	/* check plain_key and get keyid in char representation  */
	/*--------------------------------------------------------*/
	if ((sct_keyid = get_sct_keyid(plain_key)) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* check key selection                                */
	/*-----------------------------------------------------*/
	if ((encryption_key == NULL) ||
	    (encryption_key->key_bits == NULL) ||
	    (encryption_key->key_bits->part1.octets == NULL) ||
	    (encryption_key->key_bits->part2.octets == NULL)) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	}
	if (algtype != ASYM_ENC || algenc != RSA) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
	sctint_modulus.nbytes = encryption_key->key_bits->part1.noctets;
	sctint_modulus.bytes = encryption_key->key_bits->part1.octets;
	if ((compare(encryption_key->key_bits->part2.octets,
		     fermat_f4, fermat_f4_len)) == 0) {
		sctint_exponent.nbytes = 0;	/* default exponent */
		sctint_exponent.bytes = NULL;
	} else {		/* exponent not = Fermatzahl F4 */
		sctint_exponent.nbytes = encryption_key->key_bits->part2.noctets;
		sctint_exponent.bytes = encryption_key->key_bits->part2.octets;

#ifdef VERSION10
		/* the exponent must have the same length as the modulus */

		if (sctint_exponent.nbytes < sctint_modulus.nbytes) {
			ALLOC_CHAR(exponent2_bytes, sctint_modulus.nbytes);

			i = sctint_modulus.nbytes - sctint_exponent.nbytes;
			for (j = 0; j < i; j++)
				*(exponent2_bytes + j) = 0x00;
			for (i = 0; i < sctint_exponent.nbytes; i++, j++)
				*(exponent2_bytes + j) = *(sctint_exponent.bytes + i);
			sctint_exponent.nbytes = sctint_modulus.nbytes;
			sctint_exponent.bytes = exponent2_bytes;

		}
#endif
	}			/* exponent not = Fermatzahl F4 */





	/*-----------------------------------------------------*/
	/* check encrypted key                                */
	/*-----------------------------------------------------*/
	if (encrypted_key == NULL) {
		sca_errno = M_EOUTDAT;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, FALSE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_ENC_DES_KEY;
	request.rq_p1.kid = sct_keyid;
	sctint_public.modulus = &sctint_modulus;
	sctint_public.exponent = &sctint_exponent;
	request.rq_datafield.public = &sctint_public;



	/*-----------------------------------------------------*/
	/* Call SCT Interface     			       */
	/*-----------------------------------------------------*/
	rc = sct_interface(sct_id, command, &request, &response);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		err_analyse(sct_id);
		goto errcase;
	}
	/* allocate buffer for encrypted_key->subjectkey.bits */
	ALLOC_CHAR(key_buffer, response.nbytes);

	/* create output-parameter */
	for (i = 0; i < response.nbytes; i++)
		*(key_buffer + i) = *(response.bytes + i);
	encrypted_key->encryptionAI = rsa;
	encrypted_key->subjectAI = NULL;
	encrypted_key->subjectkey.nbits = response.nbytes * 8;
	encrypted_key->subjectkey.bits = key_buffer;



	/*-----------------------------------------------------*/
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "encrypted_key           : \n");
	switch (aux_ObjId2AlgEnc(encrypted_key->encryptionAI->objid)) {
	case RSA:
		fprintf(stdout, "    encryptionAI        : RSA\n");
		break;
	default:
		fprintf(stdout, "    encryptionAI        : undefined\n");
		break;

	}

	fprintf(stdout, "    subjectAI           : NULL\n");
	fprintf(stdout, "    subjectkey          : \n");
	fprintf(stdout, "      nbits             : %d\n", encrypted_key->subjectkey.nbits);
	fprintf(stdout, "      bits              : \n");
	aux_fxdump(stdout, encrypted_key->subjectkey.bits,
		   encrypted_key->subjectkey.nbits / 8, 0);

	fprintf(stdout, "\n***** Normal end of   sca_enc_des_key *****\n\n");
#endif

	return (sca_errno);

	/*-----------------------------------------------------*/
	/* In error case release all allocated storage        */
	/*------------------------------------------------------*/
errcase:
	if(exponent2_bytes) free(exponent2_bytes);
	sta_aux_bytestr_free(&response);
	return (-1);


}				/* end sca_enc_des_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_enc_des_key        */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_dec_des_key         VERSION   1.0	    	       */
/*				     DATE   August 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Decrypt an rsa-encrypted DES key and store it in the SCT   */
/*  or SC.						       */
/*  If key shall be installed on the smartcard, a smartcard    */
/*  must be inserted and parameter key_attr_list must be set.  */
/*							       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   encrypted_key             Structure which identifies      */
/*			       the encrypted key               */
/*                                                             */
/*   plain_key                 Key identifier under which the  */
/*                             decrytpted key is to be stored  */
/*							       */
/*   decryption_key            Key identifier of the decryption*/
/*                             key.                            */
/*			       In the current version only a   */
/*			       private RSA key stored on the SC*/
/*			       can be used.		       */
/*							       */
/*   key_attr_list             Structure which contains        */
/*                             additional information for      */
/*                             storing the generated key on    */
/*			       the SC or the NULL pointer      */
/*							       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EKEY 		       */
/*				 EINVALGID		       */
/*				 M_EINVKID		       */
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
sca_dec_des_key(sct_id, encrypted_key, plain_key, decryption_key, key_attr_list)
	int             sct_id;
	EncryptedKey   *encrypted_key;
	KeyId          *plain_key;
	KeyId          *decryption_key;
	KeyAttrList    *key_attr_list;
{
	/*----------------------------------------------------------*/
	/* Definitions					            */
	/*----------------------------------------------------------*/
	int             i, j;
	int             rc;
	static AlgEnc   algenc;
	static AlgType  algtype;
	DESKey          sctint_deskey;
	Bytestring      bstring;
	Public          sctint_public;
	char            rsa_keyid, des_keyid;
	KeyAlgId        sct_algid;	/* SCT specific alg_id	    */

	/*----------------------------------------------------------*/
	/* Statements					            */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	algenc = aux_ObjId2AlgEnc(encrypted_key->encryptionAI->objid);
	algtype = aux_ObjId2AlgType(encrypted_key->encryptionAI->objid);

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_dec_des_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	fprintf(stdout, "encrypted_key           : \n");
	if (encrypted_key->encryptionAI) {
		switch (algenc) {
		case RSA:
			fprintf(stdout, "    encryptionAI        : RSA\n");
			break;
		default:
			fprintf(stdout, "    encryptionAI        : undefined\n");
			break;

		}
	} else fprintf(stdout, "    encryptionAI        : NULL\n");

	if (encrypted_key->subjectAI) {
		switch (aux_ObjId2AlgEnc(encrypted_key->subjectAI->objid)) {
		case DES:
			fprintf(stdout, "    subjectAI           : DES-CBC\n");
			break;
		case DES3:
			fprintf(stdout, "    subjectAI           : DES-EDE\n");
			break;
		default:
			fprintf(stdout, "    subjectAI           : undefined\n");
			break;


		}
	} else
		fprintf(stdout, "    subjectAI           : NULL\n");


	if (encrypted_key->subjectkey.bits) {
		fprintf(stdout, "    subjectkey          : \n");
		fprintf(stdout, "      nbits             : %d\n",
			encrypted_key->subjectkey.nbits);
		fprintf(stdout, "      bits              : \n");
		aux_fxdump(stdout, encrypted_key->subjectkey.bits,
			   encrypted_key->subjectkey.nbits / 8, 0);
	} else
		fprintf(stdout, "    subjectkey          : NULL\n");


	fprintf(stdout, "plain_key               : \n");
	print_keyid(plain_key);
	fprintf(stdout, "decryption_key           : \n");
	print_keyid(decryption_key);
	print_keyattrlist(key_attr_list);
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* check encrypted key                                */
	/*-----------------------------------------------------*/
	if ((encrypted_key == NULL) ||
	    (encrypted_key->encryptionAI == NULL) ||
	    (encrypted_key->subjectAI == NULL) ||
	    (encrypted_key->subjectkey.nbits == 0) ||
	    (encrypted_key->subjectkey.bits == NULL)) {
		sca_errno = M_EKEY;
		set_errmsg();
		return (-1);
	}
	if (algtype != ASYM_ENC || algenc != RSA) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* check subjectAI and get sct specific alg_id        */
	/*-----------------------------------------------------*/
	if ((sct_algid = get_sct_algid(encrypted_key->subjectAI)) == -1)
		return (-1);


	/*--------------------------------------------------------*/
	/* check plain_key and get keyid in char representation  */
	/*--------------------------------------------------------*/
	if ((des_keyid = get_sct_keyid(plain_key)) == -1)
		return (-1);

	/*-------------------------------------------------------------*/
	/* check decryption_key and get keyid in char representation  */
	/*-------------------------------------------------------------*/
	if ((rsa_keyid = get_sct_keyid(decryption_key)) == -1)
		return (-1);
	if ((decryption_key->key_level < SC_MF) ||
	    (decryption_key->key_level > SC_SF)) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* if key shall be installed on the SC,               */
	/* then - check key attribute list and             */
	/* - check whether SC is inserted	       */
	/*-----------------------------------------------------*/
	if ((plain_key->key_level == SC_MF) ||
	    (plain_key->key_level == SC_DF) ||
	    (plain_key->key_level == SC_SF)) {

		if (check_key_attr_list(USER_KEY, key_attr_list) == -1)
			return (-1);
	};



/************** parameter check done *********************************/

	/*-----------------------------------------------------*/
	/* decrypt key          		               */
	/*-----------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, TRUE) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_DEC_DES_KEY;
	request.rq_p1.kid = rsa_keyid;
	request.rq_p2.kid = des_keyid;
	bstring.nbytes = encrypted_key->subjectkey.nbits / 8;
	bstring.bytes = encrypted_key->subjectkey.bits;
	sctint_deskey.algid = sct_algid;

	sctint_deskey.chiffrat = &bstring;
	request.rq_datafield.deskey = &sctint_deskey;



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

/************** key is now generated *********************************/


	/*-----------------------------------------------------*/
	/* if key shall not be installed on SC,              */
	/* then work is done			       */
	/*-----------------------------------------------------*/
	if (plain_key->key_level == SCT)
		return (sca_errno);

	/*-----------------------------------------------------*/
	/* otherwise (if key shall be installed on SC),      */
	/* then install key  on SC (S_INST_USER_KEY)      */
	/* and delete key in SCT (S_DEL_USER_KEY)         */
	/*-----------------------------------------------------*/


	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_INST_USER_KEY;
	request.rq_p1.kid = des_keyid;
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
	/* Normal End	 (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_DEL_USER_KEY;
	request.rq_p1.kid = des_keyid;

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
	fprintf(stdout, "\n***** Normal end of   sca_dec_des_key *****\n\n");
#endif


	return (0);


}				/* end sca_dec_des_key */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_dec_des_key        */
/*-------------------------------------------------------------*/


/************************** local functions: ***********************************/

/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  compare             VERSION   1.0                */
/*                              DATE   November 1991      */
/*                                BY   U.Viebeg,GMD       */
/*                                                        */
/* DESCRIPTION                                            */
/*  compares two strings (independent of '\0') and returns*/
/*  0 if strings are equal.                               */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   s                         first string               */
/*                                                        */
/*   t                         second string              */
/*                                                        */
/*   no                        number of chars to be      */
/*                             compared                   */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*    0                        strings are equal          */
/*                                                        */
/*   any                       strings are not equal      */
/*                                                        */
/*--------------------------------------------------------*/

static
int
compare(s, t, no)
	char           *s;
	char           *t;
	int             no;
{
	int             i;

	for (i = 0; i < no; i++) {
		if (s[i] != t[i])
			break;
	}
	if (i < no)
		return (s[i] - t[i]);
	else
		return (0);

}				/* end compare */



/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-stacrypt	       */
/*-------------------------------------------------------------*/
