/*
 *  SecuDE Release 4.0.1 (GMD)
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

/*----Tranformation functions between the SEC-IF and the SCA-IF-----*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990                                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   secsc              VERSION   3.0                       */
/*                                      DATE   6.7.92	            */
/*                                        BY   UV	            */
/* DESCRIPTION                                                      */
/*   This modul provides all functions needed for the               */
/*   transformation between the SEC-IF (project SECUDE) 	    */
/*   and the SCA-IF (project STARPAC).                              */
/*								    */
/*   Via the SEC-IF the communication with the SC (smartcard) and   */
/*   the access to the SC is possible.				    */
/*   The hash-functions are performed in the DTE, the crypto-	    */
/*   functions are performed within the STE (SCT and SC).	    */
/*								    */
/*   Assumption in all functions: 				    */
/*                - the "additional file information" which are     */
/*		    returned by the SC, when the application on the */
/*		    SC is selected, must contain information about  */
/*		    the required device authentication procedures.  */
/*		  - the PIN of the SW-PSE is stored in an WEF on    */
/*		    the SC.					    */
/*		- The following global variables are available and  */
/*		  correct:					    */
/*		  - sc_app_list[],				    */
/*		  - sca_fct_list[],				    */
/*		  - sct_stat_list[].				    */
/*                                                                  */
/*   Application:						    */
/*   "pse_sel->app_name" is mapped on DF-name for the SC.	    */
/*                                                                  */
/*   Object:							    */
/*   "pse_sel->object.name" is mapped on key_id or file_id for the  */
/*   SC using the global table "sc_app_list[].sc_obj_list[]".	    */
/*								    */
/*   Security mode:						    */
/*   If an SC-object is to be read/written, the security mode for   */
/*   the communication DTE/SCT and SCT/SC is set according to the   */
/*   parameters of this SC-object (sc_app_list[].sc_obj_list[]).    */
/*   In all other cases the security mode specified for the SCA-IF  */
/*   function, which shall be called, is set (sca_fct_list[]).	    */
/*                                                                  */
/*   Only WEFs whose data structure is TRANSPARENT are accessable   */
/*   via the SEC-IF.						    */
/*								    */
/*   PIN-authentication:					    */
/*   In the following cases the PIN authentication is performed:    */
/*		- The PIN for the SW-PSE shall be read from the SC. */
/*		- A key from the SC shall be used.	            */
/*		- A file on the SC shall be created or deleted.	    */
/*		- Data shall be written into a file on the SC.	    */
/*								    */
/*                                                                  */
/* EXPORT                                                           */
/*   secsc_close()   	  	Close application on the SC.	    */
/*   secsc_chpin()     		Change PIN for application on SC.   */
/*   secsc_create()     	Create file (WEF) on the SC.        */
/*   secsc_decrypt()     	Decrypt bitstring within SCT/SC.    */
/*   secsc_delete()     	Delete file (WEF) on the SC.        */
/*   secsc_del_key()     	Delete key stored in an SCT.	    */
/*   secsc_encrypt()     	Encrypt octetstring within SCT/SC.  */
/*   secsc_gen_key()  	        Generate DES or RSA key.            */
/*   secsc_get_EncryptedKey()   Encrypt key within SCT/SC.	    */
/*   secsc_open()  	        Open application on the SC.         */
/*   secsc_put_EncryptedKey()   Decrypt key within SCT/SC.	    */
/*   secsc_read()  	        Read data from file (WEF) on SC     */
/*				into octetstring.		    */
/*   secsc_sc_eject()  	        Eject SC(s).			    */
/*   secsc_sign()  	        Sign octetstring with key from SC.  */
/*   secsc_unblock_SCpin()      Unblock blocked PIN of the SC-app.  */
/*   secsc_verify()  	        Verify a digital signature.	    */
/*   secsc_write()  	        Write octetstring into file (WEF)   */
/*				on SC.				    */
/*								    */
/*  Auxiliary Functions                                             */
/*   aux_AppName2SCApp()	Get information about an SC app.    */
/*   aux_AppObjName2SCObj()	Get information about an SC object  */
/*			        belonging to an application on SC.  */
/*   get_connected_SCT()	Get first SCT of the registered SCTs*/
/*				which is connected to the DTE       */
/*			        (not used)			    */
/*   get_pse_pin_from_SC()	Read the PIN for the SW-PSE from    */
/*				the SC and sets it in 		    */
/*			        "sct_stat_list[]".		    */
/*   handle_sc_app()		If application not open, open it.   */
/*   SC_configuration()		Perform SC configuration (get data  */
/*				form file ".scinit".		    */
/*   SCT_configuration()	Perform SCT configuration (get data */
/*   				from a prior process).              */
/*								    */
/*                                                                  */
/* STATIC                                                           */
/*   analyse_sca_err()		Analyse of an error-number 	    */
/*				returned by an SCA-IF function.     */
/*   aux_FctName2FctPar()	Get security parameter for an SCA-  */
/*				Function.			    */
/*   bell_function()		"Ring the bell" to require user     */
/*                              input at the SCT.		    */
/*   check_sc_app()		Check whether application has 	    */
/*				been opened.                        */
/*   delete_old_SCT_config()    Delete old SCT configuration file.  */
/*   device_authentication() 	Perform device authentication 	    */
/*				according to the add. file info of  */
/*				the selected application on the SC. */
/*   display_on_SCT()		Display string on SCT-display.	    */
/*   eject_sc()			Handle the ejection of the SC.	    */
/*   enter_app_in_sctlist()	Enter information about app in      */
/*				sct_list for current SCT.           */
/*   gen_process_key()		Generate and set new process key.   */
/*   get_keyid_for_obj()	Get keyid for object.		    */
/*   get_DecSK_name()		Get name of decryption key on SC.   */
/*   get_SCT_config_fname()	Get name of SCT configuartion file. */
/*   get_process_key()		Get process key for encryption /    */
/*				decryption of SCT config.	    */
/*   get_sca_fileid()		Transform structure SCId into       */
/*				structure FileId (for a WEF on      */
/*				the SC).			    */
/*   get_sca_keyid()		Transform structure SCId into       */
/*				structure KeyId (for a key on       */
/*				the SC).			    */
/*   getbits	                Get n bits of byte x from 	    */
/*			        position p.			    */
/*   handle_gen_DecSK()		Special handling of objects	    */
/*				"DecSK_new", "DecSKold", resp..	    */
/*   handle_key_sc_app()	Handle SC-application for the       */
/*                              selected key.			    */
/*   int2ascii()		Transform an integer value into a   */
/*			        NULL terminated ASCII character     */
/*				string.				    */
/*   int_to_keyid()		Transform integer value into        */
/*				structure KeyId (for a key on       */
/*				the SC).	   		    */
/*   int_to_fileid()		Transform integer value into        */
/*				structure FileId (for a WEF on      */
/*				the SC).			    */
/*   is_SCT_connected()		Check whether selected SCT is 	    */
/*				available.                          */
/*   itos()   			Transform integer to char-string.   */
/*   keyref_to_keyid()	        Transform keyref into structure     */
/*                              keyid.				    */
/*   key_to_keyid()	        Get key_id from key.		    */
/*   open_sc_application() 	Require SC, open SC application,    */
/*				perform device authenticationn.     */
/*   read_SCT_config()		Read and decrypt SCT configuration  */
/*				data for the spcified SCT.	    */
/*   request_sc()		Request and initialize a smartcard. */
/*   set_fct_sec_mode()		Set security mode for communication */
/*				between DTE/SCT depending on the    */
/*                	        SCA-function to be called.          */
/*   set_sec_mode()		Set security mode for the 	    */
/*				communication between DTE/SCT.      */
/*   stoi()			Transform char-string to integer.   */
/*   user_authentication()      Perform user authentication         */
/*				(PIN or PUK).		            */
/*   write_SCT_config()		Encrypt and write SCT configuration */
/*				data for the specified SCT.         */
/*                                                                  */
/* IMPORT              		              		            */
/*  Functions of SCA-IF:  			                    */
/*   sca_auth()			Device authentication  		    */
/*   sca_change_pin()		Change PIN on the smartcard.	    */
/*   sca_check_pin()		PIN authentication  		    */
/*   sca_close_file()		Close file on the smartcard.        */
/*   sca_create_file()		Create file on the smartcard.       */
/*   sca_dec_des_key()		Decrypt an rsa encrypted DES key.   */
/*   sca_decrypt()		Decrypt octetstring.   	            */
/*   sca_delete_file()		Delete file on the smartcard.       */
/*   sca_del_user_key()		Delete user key in an SCT.	    */
/*   sca_display()		Display text on SCT-display.        */
/*   sca_eject_sc()		Eject smartcard. 	            */
/*   sca_enc_des_key()		Encrypt DES key with RSA. 	    */
/*   sca_encrypt()		Encrypt octetstring. 		    */
/*   sca_gen_user_key()		Generate and install user key.      */
/*   sca_get_SCT_config_fname	Get name of (SCA) SCT configuration */
/*				file.				    */
/*   sca_get_sc_info()		Get information about smartcard.    */
/*   sca_get_sct_info()		Get information about registered    */
/*				SCTs.				    */
/*   sca_init_sc()		Request and initialize a smartcard. */
/*   sca_read_data()		Read data from elementary file on   */
/*				the smartcard.      	            */
/*   sca_select_file()		Select file on the smartcard.       */
/*   sca_set_mode()		Set security mode.  		    */
/*   sca_sign()			Sign octetstring.  		    */
/*   sca_verify()		Verify a digital signature.	    */
/*   sca_unblock_pin()          Unblock blocked PIN of the SC-app.  */
/*   sca_write_data()		Write data in EF on the SC.	    */
/*                                                                  */
/*								    */
/*  SC_CONFIGURATION:						    */
/*   display_SC_configuration() Display the actual SC               */
/*				configuration ("sc_app_list[]").    */
/*   read_SC_configuration()    Read SC configuration file into     */
/*				global structure "sc_app_list[]".   */
/*								    */
/*  Auxiliary Functions of SCA-IF		                    */
/*   aux_free2_OctetString()	Release the octets-buffer in        */
/*			    	structure OctetString		    */
/*                                                                  */
/*  Auxiliary Functions of SECUDE		                    */
/*   aux_xdump()		dump buffer			    */
/*   aux_fxdump()		dump buffer in file		    */
/*   aux_add_error()		Add error to error stack.	    */
/*   aux_cmp_UTCTime()		Compare two time-values (UTCTime).  */
/*   aux_cpy_String()		Copy string.	 		    */
/*   aux_free_KeyBits()		Release members of struct 	    */
/*				KeyBits and KeyBits.		    */
/*   aux_ObjId2AlgEnc()		Map object identifier on 	    */
/*				algorithm encryption method.	    */
/*   aux_ObjId2AlgHash()	Map object identifier on     	    */
/*				algorithm hash method.		    */
/*   aux_ObjId2AlgType()	Map object identifier on 	    */
/*				algorithm type.			    */
/*   aux_ObjId2ParmType()	Map object identifier on 	    */
/*				type of parameter.		    */
/*   d_KeyBits()		Decode given BitString into 	    */
/*				structure KeyBits.		    */
/*   get_update_time_SCToc()	Get update time of object in SC-Toc.*/
/*   is_in_SCToc()	        Check whether object in SCToc.	    */
/*   strzfree()			Free string.			    */
/*   update_SCToc()		Update entry in SCToc.		    */
/*								    */
/*                                                                  */
/*  Global Variables                                                */
/*   sca_errno			Global error variable set by STAPAC */
/*   sca_errmsg			Global pointer to error message set */
/*                              by STAPAC 			    */
/*   sct_stat_list[]		Current status information          */
/*				about the SCTs (secure messaging    */
/*				parameter, app_name).   	    */
/*   sca_fct_list[]		List of the SCA-functions           */
/*				and the belonging secure messaging  */
/*				parameters.			    */
/*   sc_app_list[]		List of the applications available  */
/*				on the SC, including the list of    */
/*				all objects (app specific),         */
/*				-which shall be stored on the SC or */
/*				-which are stored on the SC.	    */
/*   sc_sel			Selection of SC and SCT	:	    */
/*                              sc_sel.sct_id - select SCT          */
/*------------------------------------------------------------------*/

#ifdef SCA

#include "af.h"			/* Names of PSE Objects 
				   ("DecSKnew_name", "DecSKold_name", 
				    "SK_new_name", "SK_old_name" */
#include "secsc.h"		/* definitions for this module	 */
#include "scarc.h"		/* return codes of the SCA-IF	 */


#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>


#define FILEMASK 0600		/* file creation mask (for SCT configuration files) */


/*
 *    Extern declarations
 */

extern int	display_SC_configuration();
extern int	read_SC_configuration();

extern int      sca_auth();
extern int      sca_change_pin();
extern int      sca_check_pin();
extern int      sca_close_file();
extern int      sca_create_file();
extern int      sca_dec_des_key();
extern int      sca_decrypt();
extern int      sca_delete_file();
extern int      sca_del_user_key();
extern int      sca_eject_sc();
extern int      sca_enc_des_key();
extern int      sca_encrypt();
extern int      sca_gen_user_key();
#ifdef PROCDAT
extern char	*sca_get_SCT_config_fname();
#endif	/* PROCDAT */
extern int      sca_get_sc_info();
extern int      sca_get_sct_info();
extern int      sca_init_sc();
extern int      sca_read_data();
extern int      sca_select_file();
extern int      sca_set_mode();
extern int      sca_sign();
extern int      sca_unblock_pin();
extern int      sca_verify();
extern int      sca_write_data();

extern void     aux_free2_OctetString();
extern void     aux_xdump();
extern void     aux_fxdump();
extern void     aux_add_error();
extern void     aux_free_KeyBits();
extern AlgEnc   aux_ObjId2AlgEnc();
extern AlgHash  aux_ObjId2AlgHash();
extern AlgType  aux_ObjId2AlgType();
extern KeyBits *d_KeyBits();
extern int	get_update_time_SCToc();
extern Boolean  is_in_SCToc();
extern void	strzfree();
extern int      update_SCToc();

extern unsigned int sca_errno;	/* error number set by STAPAC       */
extern char    *sca_errmsg;	/* pointer to error message set by  */
				/* STAPAC                           */



/*
 *    Local variables, but global within secsc.c
 */

static unsigned int secsc_errno;/* internal error-number	       */
static int      sca_rc;		/* return code of the SCA-functions */
static unsigned int i;

AlgId          *aux_cpy_AlgId();
char           *strcat(), *get_unixname();


typedef enum {
	F_null, F_encrypt, F_decrypt,
	F_hash, F_sign, F_verify
}


                FTYPE;
static FTYPE    sec_state = F_null;




/*
 *    Local definitions, but global within secsc.c
 */


/*
 *    Local declarations
 */


SCAppEntry     *aux_AppName2SCApp();
SCObjEntry     *aux_AppObjName2SCObj();
int             get_connected_SCT();
char	       *get_pse_pin_from_SC();		
int             handle_sc_app();
int		SCT_configuration();
int 		SC_configuration();


static int      analyse_sca_err();
static SCAFctPar *aux_FctName2FctPar();
static void     bell_function();
static int      check_sc_app();
static int      delete_old_SCT_config();
static int      device_authentication();
static void     display_on_SCT();
static int      eject_sc();
static int      enter_app_in_sctlist();
static int	gen_process_key();
static char     *get_DecSK_name();
static int      get_keyid_for_obj();
static char 	*get_SCT_config_fname();
static char 	*get_process_key();
static void     get_sca_fileid();
static void     get_sca_keyid();
static int      getbits();
static int      handle_gen_DecSK();
static int      handle_key_sc_app();
static int      int2ascii();
static void     int_to_fileid();
static void     int_to_keyid();
static int      itos();
static int	is_SCT_connected();
static int      key_to_keyid();
static int      keyref_to_keyid();
static int     	open_sc_application();
static int	read_SCT_config();
static int      request_sc();
static int      set_fct_sec_mode();
static int      set_sec_mode();
static int      stoi();
static int      user_authentication();
static int	write_SCT_config();



/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_create					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  a) Create an object on the SC:				*/
/*     1) Assumption: the belonging application has been opened */
/*	  by the calling routine.				*/
/*     2) The user authentication is performed.			*/
/*     3) Get parameters for the object to be created from the	*/
/*        global variable "sc_app_list[].sc_obj_list[]".	*/
/*        Case 1: Object on the SC is a key			*/
/*		  => return(ENOTSUPP)				*/
/*	  Case 2: Object on the SC is a file:			*/
/*		  Parameters for "Create WEF on SC":		*/
/*			   - "sc_obj_list[]" delivers:		*/
/*			      - number of bytes for the file	*/
/*			      - file identifier			*/
/*			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*		           - constant values for:		*/
/*			      - file_cat = EF			*/
/*			      - file_type = WEF			*/
/*			      - data_struc = TRANSPARENT	*/
/*			      - read acv = 0x80			*/
/*			      - write acv = 0x80		*/
/*			      - delete acv = 0x80		*/
/*			      - access to file : read / write	*/
/*			      - file is erasable		*/
/*			      - add_info = "    "		*/
/*     4) Init. the number of relevant data (first octets in    */
/*        the WEF with 0.					*/
/*								*/
/*  b) Create an application:					*/
/*     In this case the error ENOTSUPP is returned.		*/
/*     The creation of an application on the SC is not 		*/
/*     supported.						*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_close_file()		Close file on the SC. 		*/
/*				(close creation process)	*/
/*   sca_create_file()		Create file on the SC. 		*/
/*								*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_sca_fileid()		Transform structure SCId into   */
/*				structure FileId (for a WEF on  */
/*				the SC).			*/
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*   user_authentication()      Perform user authentication 	*/
/*				(PIN).				*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_create(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	FileCat         file_cat;
	FileType        file_type;
	DataStruc       data_struc;
	FileControlInfo file_control_info;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	FileSel         file_sel;
	FileCloseContext file_close_context;

	FileId          file_id;
	DataSel         data_sel;
	OctetString     in_data;
	char            WEF_len[WEF_LEN_BYTES];	/* The length of the data to be
						 * written is stored in the first
						 * bytes of the WEF on the SC.	
				 		 */



	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;
	int             rest;


	char           *proc = "secsc_create";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Create object on the SC
		 */

		/* get information about the object to be created */
		sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name);
		if (sc_obj_entry == (SCObjEntry * ) 0) {
			aux_add_error(ECONFIG, "get SC-Obj-info for object to be created", CNULL, 0, proc);
			return (-1);
		}
		if (sc_obj_entry->type == SC_KEY_TYPE) {
			/* object is a key */
			aux_add_error(ENOTSUPP, "Cannot create object 'key' on SC.", CNULL, 0, proc);
			return (-1);
		}


		/*
		 *  For creation an object the user authentication is required.
		 */	

		if (user_authentication(sct_id, pse_sel->app_name, PIN)) {
			aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
			return (-1);
		}


		/*
		 *  Object to be created is a file
		 */

		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_create_file", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			return (-1);
		}
		/* Create WEF on the SC */
		rest = sc_obj_entry->size % UNIT_SIZE;
		if (rest > 0)
			file_control_info.units = sc_obj_entry->size / UNIT_SIZE + 1;
		else
			file_control_info.units = sc_obj_entry->size / UNIT_SIZE;
		file_control_info.racv = 0x80;
		file_control_info.wacv = 0x80;
		file_control_info.dacv = 0x80;
		file_control_info.readwrite = READ_WRITE;
		file_control_info.execute = FALSE;
		file_control_info.mac = FALSE;
		file_control_info.not_erasable = FALSE;	/* => file is erasable */
		file_control_info.recordsize = 0;
		file_control_info.file_sel.file_name = CNULL;
		get_sca_fileid(&sc_obj_entry->sc_id, &file_control_info.file_sel.file_id);
		file_control_info.addinfo.noctets = 4;
		file_control_info.addinfo.octets = "    ";

		sca_rc = sca_create_file(sct_id,
					 file_cat = EF,
					 file_type = WEF,
					 data_struc = TRANSPARENT,
					 &file_control_info,
					 &sm_SC);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_create_file", sca_errmsg, char_n, proc);
			return (-1);
		}


/*
 *   Intermediate result: WEF on the SC has been created!
 *
 *            Next to do: Initialize the number of relevant octets in the WEF with 0.
 */

		data_sel.data_struc = TRANSPARENT;

		/* get length (= 0) of object as char-string */
		if (itos(0, &WEF_len[0], WEF_LEN_BYTES)) {
			aux_add_error(ESYSTEM, "get WEF length", CNULL, 0, proc);
			return (-1);
		}

		in_data.noctets = WEF_LEN_BYTES;
		in_data.octets = &WEF_len[0];
		data_sel.data_ref.string_sel = 0;
#ifdef SECSCTEST
		fprintf(stderr, "\n\nWritten length:\n");
		aux_fxdump(stderr, in_data.octets, in_data.noctets);
		fprintf(stderr, "\n");
#endif

		sca_rc = sca_write_data(sct_id,
					&file_control_info.file_sel.file_id,
					&data_sel,
					&in_data,
					&sc_obj_entry->sm_SC_write);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_write_file", sca_errmsg, char_n, proc);
		return (-1);
	}




/*
 *   Intermediate result: WEF on the SC has been created!
 *
 *            Next to do: Close creation process.
 */


		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_close_file", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			return (-1);
		}
		/* Close creation process */
		sca_rc = sca_close_file(sct_id,
					file_cat = EF,
					&file_control_info.file_sel,
					file_close_context = CLOSE_CREATE,
					&sm_SC);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_close_file", sca_errmsg, char_n, proc);
			return (-1);
		}
	}
	 /* end if */ 
	else {

		/*
		 * Creation of an application on the SC is not supported
		 */

		aux_add_error(ENOTSUPP, "Creation of app on SC not supported", CNULL, 0, proc);
		return (-1);
	}			/* end else */

	return (0);


}				/* end secsc_create() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_open					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  If the application is not open, it will be opened.		*/
/*								*/
/*  Open an application means:					*/
/*     1. get required SC,					*/
/*     2. open application on SC: 				*/
/*	     - select DF with name = pse_sel->app_name,		*/
/*           - perform authentication according to the		*/
/*	       "additional file information" from the SC	*/
/*	       (the "add_file_info" are returned by the SC, when*/
/*	       an application (DF) on the SC is selected),	*/
/*     4. set application to open for the current SCT:		*/
/*	     - enter app_name into the sct_stat_list for the 	*/
/*	       current SCT.					*/
/*								*/
/*								*/
/*  Open an object means:					*/
/*  1. Check whether object in SCToc.				*/
/*     If not => return(error)					*/
/*  2. As an object (file, key) on the SC cannot be opened 	*/
/*     with this function, this call is ignored. 		*/
/*     In this case "pse_sel->object.pin" is set to CNULL and 0	*/
/*     is returned.						*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   handle_sc_app()		If application not open, open it*/
/*   is_in_SCToc()	        Check whether object in SCToc.  */
/*			         		       		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_open(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;

	int             obj_in_SCToc;

	char           *proc = "secsc_open";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	/* If application (app_name) not open, open it */
	if (handle_sc_app(sct_id, pse_sel->app_name)) {
		aux_add_error(EAPP, "Application could not be opened", CNULL, 0, proc);
		return (-1);
	}

	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Check, whether object in SCToc
		 */

		if ((obj_in_SCToc = is_in_SCToc(pse_sel)) == -1) {
			aux_add_error(EOBJNAME, "Check 'is obj in SCToc' failed", pse_sel, PSESel_n, proc);
			return (-1);
		}
		if (obj_in_SCToc == FALSE) {
			aux_add_error(EOBJNAME, "SC-Object does not exist", pse_sel, PSESel_n, proc);
			return (-1);
		}

		/*
		 * Open an object on the SC => dummy function
		 */

		pse_sel->object.pin = CNULL;

		return (0);

	}			/* end if */
	return (0);


}				/* end secsc_open() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_close					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  a) Close an object on the SC:				*/
/*     If application not open 					*/
/*	  => return(error)					*/
/*     else:							*/
/*     1. Check whether object in SCToc.			*/
/*        If not => return(error)				*/
/*     2. As an object (file, key) on the SC cannot be closed 	*/
/*        with this function, this call is ignored. 		*/
/*        In this case "pse_sel->object.pin" is set to CNULL 	*/
/*        and 0	is returned.					*/
/*								*/
/*  b) Close an application on the SC:				*/
/*     Case a: If application not open (i.e. no application 	*/
/*	       open or other application open)			*/
/*             =>   return (error).				*/
/*     Case b: If application open 				*/
/*		  - close application on the SC.		*/
/*		  - set application to close for SCT		*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_close_file()		Close file on SC. 	        */
/*								*/
/*   check_sc_app()		Check whether application has   */
/*				been opened.                    */
/*   is_in_SCToc()	        Check whether object in SCToc.  */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/

RC
secsc_close(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	FileCat         file_cat;
	FileSel         file_sel;
	FileCloseContext file_close_context;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	char           *display_text;
	Boolean         alarm;


	/* Variables for internal use */
	int             obj_in_SCToc;

	char           *proc = "secsc_close";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Close an object!
		 */

		/* has the belonging application been opened ? */
		if (check_sc_app(sct_id, pse_sel->app_name)) {
			aux_add_error(EAPP, "Application has not been opened", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Check, whether object in SCToc
		 */

		if ((obj_in_SCToc = is_in_SCToc(pse_sel)) == -1) {
			aux_add_error(EOBJNAME, "Check 'is obj in SCToc' failed", pse_sel, PSESel_n, proc);
			return (-1);
		}
		if (obj_in_SCToc == FALSE) {
			aux_add_error(EOBJNAME, "SC-Object does not exist", pse_sel, PSESel_n, proc);
			return (-1);
		}

		/*
		 * Close an object => dummy function
		 */

		pse_sel->object.pin = CNULL;
		return (0);

	}
	else {

		/*
		 * Close an application!
		 */

		/*
		 * case a: If application not open 
		 *            return (error). 
		 * case b: If application open 
		 *	       - close application on the SC. 
		 *             - set application to close for SC
		 */

		/* has the belonging application been opened ? */
		if (check_sc_app(sct_id, pse_sel->app_name)) {
			/* application is not open */
			aux_add_error(EAPP, "Application to be closed is not open", CNULL, 0, proc);
			return (-1);
		} else {
			/* application is open */

			/* set security mode for SCA-function */
			if (set_fct_sec_mode(sct_id, "sca_close_file", &sm_SC)) {
				aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
				return (-1);
			}
			/* close application on the SC */
			file_sel.file_name = pse_sel->app_name;
			sca_rc = sca_close_file(sct_id,
						file_cat = DF,
						&file_sel,
					  	file_close_context = CLOSE_SELECT,
						&sm_SC	/* sec_mode for SCT/SC */
				);
			if (sca_rc < 0) {
				secsc_errno = analyse_sca_err(sct_id);
				aux_add_error(secsc_errno, "sca_close_file", sca_errmsg, char_n, proc);
				return (-1);
			}
			/* set application to CLOSE for the current SCT */
			if (enter_app_in_sctlist(sct_id, CNULL, CNULL)) {
				aux_add_error(ESCTID, "set app_name to NULL in sct_list", CNULL, 0, proc);
				return (-1);
			}
		}		
	}			

	return (0);

}				/* end secsc_close() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_delete					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  a) Delete an object on the SC:				*/
/*     1) Assumption: the belonging application has been opened */
/*	  by the calling routine.				*/
/*     2) The user authentication is performed.			*/
/*     3) Get parameters for the object to be deleted from the	*/
/*        global variable "sc_app_list[].sc_obj_list[]".	*/
/*        Case 1: Object on the SC is a key			*/
/*		  => return(ENOTSUPP)				*/
/*		     Deletion of a key on the SC is not         */
/*		     supported.					*/
/*	  Case 2: Object on the SC is a file:			*/
/*		  Delete WEF on SC:				*/
/*			   - "sc_obj_list[]" delivers:		*/
/*			      - file identifier			*/
/*			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*		           - constant values for:		*/
/*			      - file_cat = EF			*/
/*								*/
/*  b) Delete an application:					*/
/*     In this case the error ENOTSUPP is returned.		*/
/*     The deletion of an application on the SC is not 		*/
/*     supported.						*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_delete_file()		Delete (WEF) file on the SC. 	*/
/*							       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_sca_fileid()		Transform structure SCId into   */
/*				structure FileId (for a WEF on  */
/*				the SC).			*/
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*   user_authentication()      Perform user authentication     */
/*				(PIN).				*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_delete(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	FileCat         file_cat;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	FileSel         file_sel;


	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;


	char           *proc = "secsc_delete";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Delete object on the SC
		 */

		/* get information about the object to be deleted */
		sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name);
		if (sc_obj_entry == (SCObjEntry * ) 0) {
			aux_add_error(ECONFIG, "get SC-Obj-info for object to be deleted", CNULL, 0, proc);
			return (-1);
		}
		if (sc_obj_entry->type == SC_KEY_TYPE) {

			/*
			 * Deletion a key on the SC is not supported
			 */
			aux_add_error(ENOTSUPP, "Deletion of key on SC not supported", CNULL, 0, proc);
			return (-1);
		}


		/*
		 *  For deletion an object the user authentication is required.
		 */	

		if (user_authentication(sct_id, pse_sel->app_name, PIN)) {
			aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
			return (-1);
		}


		/*
		 * Object to be deleted is a file
		 */

		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_delete_file", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			return (-1);
		}
		/* Delete WEF on the SC */
		get_sca_fileid(&sc_obj_entry->sc_id, &file_sel.file_id);

		sca_rc = sca_delete_file(sct_id,
					 file_cat = EF,
					 &file_sel,
					 &sm_SC);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_delete_file", sca_errmsg, char_n, proc);
			return (-1);
		}
	}
	 /* end if */ 
	else {

		/*
		 * Deletion of an application on the SC is not supported
		 */

		aux_add_error(ENOTSUPP, "Deletion of app on SC not supported", CNULL, 0, proc);
		return (-1);
	}			/* end else */

	return (0);

}				/* end secsc_delete() */







/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_write					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Write octetstring into WEF on the SC:			*/
/*     If object_name missing   				*/
/*	  => return(error)					*/
/*     else:							*/
/*     1) Assumption: the belonging application has been opened */
/*	  by the calling routine.				*/
/*     2) The user authentication is performed.			*/
/*     3) Get parameters for the object to be written from the	*/
/*        global variable "sc_app_list[].sc_obj_list[]".	*/
/*        Case 1: Object on the SC is a key			*/
/*		  => return(error)				*/
/*	  Case 2: Object on the SC is a file:			*/
/*		  Parameters for "Write into WEF on SC":	*/
/*			   - "sc_obj_list" delivers:		*/
/*			      - file identifier			*/
/*			      - sec_mess			*/
/*		           - constant values for:		*/
/*			      - data_struc = TRANSPARENT	*/
/*								*/
/*  1. Store length:						*/
/*  The length of the data to be written is stored in the first */
/*  bytes of the WEF on the SC.	The no. of bytes which are used	*/
/*  for the length are specified in WEF_LEN_BYTES (constant).	*/
/*								*/
/*  2. Store data:						*/
/*  The octetstring to be written to the WEF is segmented into  */
/*  octetstrings, whose length is determined by the max. no. of */
/*  bytes (MAX_READWRITE_BYTES), which can be written/read to/	*/
/*  from the SC with one function call. 			*/
/*  Each segment is written with "sca_write_data" to the SC.	*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*   content		       Data to be written.		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_write_data()		Write data in EF on the SC.     */
/*							       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_sca_fileid()		Transform structure SCId into   */
/*				structure FileId (for a WEF on  */
/*				the SC).			*/
/*   itos()			Transform integer to char-string.*/
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   user_authentication ()     Perform user authentication	*/
/*				(PIN).				*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_write(pse_sel, content)
	PSESel         *pse_sel;
	OctetString    *content;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	FileId          file_id;
	DataSel         data_sel;
	OctetString     in_data;
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	char            WEF_len[WEF_LEN_BYTES];	/* The length of the data to be
						 * written is stored in the first
						 * bytes of the WEF on the SC.	
				 		 */
	unsigned int    no_write_calls;		/* No. of write calls with a length
					 	 * of MAX_READWRITE_BYTES
  						 */
	unsigned int    rest;
	unsigned int    i;
	char		err_msg[256];


	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;


	char           *proc = "secsc_write";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if ((!pse_sel->object.name) || (!strlen(pse_sel->object.name))) {
		aux_add_error(EOBJ, "Object name missing", CNULL, 0, proc);
		return (-1);
	}

	/* get information about the object to be written */
	sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name);
	if (sc_obj_entry == (SCObjEntry * ) 0) {
		aux_add_error(ECONFIG, "get SC-Obj-info for object to be written", CNULL, 0, proc);
		return (-1);
	}
	if (sc_obj_entry->type == SC_KEY_TYPE) {
		/* object is a key */
		aux_add_error(ENOTSUPP, "SC-Key cannot be written", CNULL, 0, proc);
		return (-1);
	}


	/*
	 *  The user authentication is required.
	 */	

	if (user_authentication(sct_id, pse_sel->app_name, PIN)) {
		aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
		return (-1);
	}			


	/*
	 * Object to be written is a file
	 */

	/* set security mode for writing an SC-object */
	sm_SCT.command = sc_obj_entry->sm_SCT;
	sm_SCT.response = SEC_NORMAL;
	if (set_sec_mode(sct_id, &sm_SCT)) {
		aux_add_error(ESECMESS, "set security mode for writing obj", CNULL, 0, proc);
		return (-1);
	}
	get_sca_fileid(&sc_obj_entry->sc_id, &file_id);
	data_sel.data_struc = TRANSPARENT;

	/* get length of object as char-string */
	if (itos(content->noctets, &WEF_len[0], WEF_LEN_BYTES)) {
		aux_add_error(ESYSTEM, "get WEF length", CNULL, 0, proc);
		return (-1);
	}
	/* first write length of object into WEF on SC */
	in_data.noctets = WEF_LEN_BYTES;
	in_data.octets = &WEF_len[0];
	data_sel.data_ref.string_sel = 0;
#ifdef SECSCTEST
	fprintf(stderr, "\n\nWritten length:\n");
	aux_fxdump(stderr, in_data.octets, in_data.noctets);
	fprintf(stderr, "\n");
#endif

	sca_rc = sca_write_data(sct_id,
				&file_id,
				&data_sel,
				&in_data,
				&sc_obj_entry->sm_SC_write);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		if (sca_errno == ELENINPUT) {
			sprintf(err_msg, "Write error: Not enough space in file (Required size of file is %d)", content->noctets + 2);
			aux_add_error(secsc_errno, "sca_write_file", err_msg, char_n, proc);
		}
		else	
			aux_add_error(secsc_errno, "sca_write_file", sca_errmsg, char_n, proc);
		return (-1);
	}

	/*
	 * Write octetstring into WEF on SC Data is segmented into portions
	 * each of a length of MAX_READWRITE_BYTES bytes. Each segment is
	 * written to the SC.
	 */

	/* get no. of write calls with a length of MAX_READWRITE_BYTES bytes */
	no_write_calls = content->noctets / MAX_READWRITE_BYTES;
	rest = content->noctets % MAX_READWRITE_BYTES;

	in_data.noctets = MAX_READWRITE_BYTES;
	in_data.octets = content->octets;
	data_sel.data_ref.string_sel = WEF_LEN_BYTES;

	for (i = 1; i <= no_write_calls; i++) {
#ifdef SECSCTEST
		fprintf(stderr, "\n\nWritten data:\n");
		aux_fxdump(stderr, in_data.octets, in_data.noctets);
		fprintf(stderr, "\n");
#endif
		sca_rc = sca_write_data(sct_id,
					&file_id,
					&data_sel,
					&in_data,
					&sc_obj_entry->sm_SC_write);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			if (sca_errno == ELENINPUT) {
				sprintf(err_msg, "Write error: Not enough space in file (Required size of file is %d)", content->noctets + 2);
				aux_add_error(secsc_errno, "sca_write_file", err_msg, char_n, proc);
			}
			else	
				aux_add_error(secsc_errno, "sca_write_file", sca_errmsg, char_n, proc);
		return (-1);
		}
		in_data.octets = &content->octets[(MAX_READWRITE_BYTES * i)];
		data_sel.data_ref.string_sel += in_data.noctets;

	}			/* end for */

	/*
	 * write rest, if no. of bytes to be written is not a multiple of
	 * MAX_READWRITE_BYTES
	 */
	if (rest > 0) {
		in_data.noctets = rest;
#ifdef SECSCTEST
		fprintf(stderr, "\n\nWritten data:\n");
		aux_fxdump(stderr, in_data.octets, in_data.noctets);
		fprintf(stderr, "\n");
#endif
		sca_rc = sca_write_data(sct_id,
					&file_id,
					&data_sel,
					&in_data,
					&sc_obj_entry->sm_SC_write);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			if (sca_errno == ELENINPUT) {
				sprintf(err_msg, "Write error: Not enough space in file (Required size of file is %d)", content->noctets + 2);
			aux_add_error(secsc_errno, "sca_write_file", err_msg, char_n, proc);
			}
			else	
				aux_add_error(secsc_errno, "sca_write_file", sca_errmsg, char_n, proc);
			return (-1);
		}
	}			/* end if */
	return (0);


}				/* end secsc_write() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_read					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read data from WEF on the SC into octetstring:		*/
/*     If object_name missing   				*/
/*	  => return(error)					*/
/*     else:							*/
/*     1) Assumption: the belonging application has been opened */
/*	  by the calling routine.				*/
/*     2) Get parameters for the object to be read from the	*/
/*        global variable "sc_app_list[].sc_obj_list[]".	*/
/*        Case 1: Object on the SC is a key			*/
/*		  => return(error)				*/
/*	  Case 2: Object on the SC is a file:			*/
/*		  Parameters for "Read from WEF on SC":		*/
/*			   - "sc_obj_list" delivers:		*/
/*			      - file identifier			*/
/*			      - sec_mess			*/
/*		           - constant values for:		*/
/*			      - data_struc = TRANSPARENT	*/
/*								*/
/*  1. Read length:						*/
/*  The assumption is that the length of the WEF (no. of 	*/
/*  relevant data) is stored in the first bytes of the WEF. The */
/*  no. of bytes which are used	for this length are specified   */
/*  in WEF_LEN_BYTES (constant).				*/
/*  If the length of the file is 0, "content->noctets" is set   */
/*  0 and 0 is returned.					*/
/*								*/
/*  2. Read data:						*/
/*  The no. of bytes which are read with one function call      */
/*  is determined by the max. no. of bytes (MAX_READWRITE_BYTES), */
/*  which can be written/read to/from the SC with one function  */
/*  call. 							*/
/*  According to MAX_READWRITE_BYTES the data are read in  	*/
/*  portions of this length, concatenated to one octetstring 	*/
/*  and returned in content->octets. 				*/
/*  Secsc_read provides content->noctets and allocates the      */
/*  necessary memory in content->octets.			*/
/* 								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*   content		       Data read from the SC.		*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_read_data()		Read data from EF on the SC.    */
/*							       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_sca_fileid()		Transform structure SCId into   */
/*				structure FileId (for a WEF on  */
/*				the SC).			*/
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   stoi()			Transform char-string to integer.*/
/*   user_authentication()      Perform user authentication     */
/*				(PIN).				*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_read(pse_sel, content)
	PSESel         *pse_sel;
	OctetString    *content;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	FileId          file_id;
	DataSel         data_sel;
	int             data_length;
	OctetString     out_data;
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	unsigned int    WEF_len;/* The length of the data to be read    */

	/* is stored in the first bytes of the  */
	/* WEF on the SC.	 		 */
	unsigned int    no_read_calls;	/* No. of read calls with a length of   */

	/* MAX_READWRITE_BYTES			 */
	unsigned int    rest;
	unsigned int    i, j;


	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;
	int		repeat_times;

	char           *proc = "secsc_read";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if ((!pse_sel->object.name) || (!strlen(pse_sel->object.name))) {
		aux_add_error(EOBJ, "Object name missing", CNULL, 0, proc);
		return (-1);
	}

	/* get information about the object to be read */
	sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name);
	if (sc_obj_entry == (SCObjEntry * ) 0) {
		aux_add_error(ECONFIG, "get SC-Obj-info for object to be read", CNULL, 0, proc);
		return (-1);
	}
	if (sc_obj_entry->type == SC_KEY_TYPE) {
		/* object is a key */
		aux_add_error(ENOTSUPP, "SC-Key cannot be read", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Object to be read is a file
	 */

	/* set security mode for reading an SC-object */
	sm_SCT.command = SEC_NORMAL;
	sm_SCT.response = sc_obj_entry->sm_SCT;
	if (set_sec_mode(sct_id, &sm_SCT)) {
		aux_add_error(ESECMESS, "set security mode for reading obj", CNULL, 0, proc);
		return (-1);
	}
	get_sca_fileid(&sc_obj_entry->sc_id, &file_id);
	data_sel.data_struc = TRANSPARENT;

	/* first read length of object from WEF on SC */
	data_sel.data_ref.string_sel = 0;
	data_length = WEF_LEN_BYTES;
	repeat_times = 0;
repeat_read:
	sca_rc = sca_read_data(sct_id,
			       &file_id,
			       &data_sel,
			       data_length,
			       &out_data,
			       &sc_obj_entry->sm_SC_write);
	if (sca_rc < 0) {

		if (sca_errno == EACF) {
			/* user authentication required. */
			if (user_authentication(sct_id, pse_sel->app_name, PIN)) {
				aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
				return (-1);
			}
			if (repeat_times == 0) {
				/* repeat read data from SC */
				repeat_times++;
				goto repeat_read;
			}
			else {
				aux_add_error(ESCAUTH, "Read not allowed in actual state of SC.", CNULL, 0, proc);
				return (-1);
			}		
		}
		else {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_read_data", sca_errmsg, char_n, proc);
			return (-1);
		}
	}

#ifdef SECSCTEST
	fprintf(stderr, "\n\nRead length:\n");
	aux_fxdump(stderr, out_data.octets, out_data.noctets);
	fprintf(stderr, "\n");
#endif

	/* get length of object as integer */
	if (stoi(out_data.octets, &WEF_len, WEF_LEN_BYTES)) {
		aux_add_error(EOBJ, "get WEF length", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Read octetstring from WEF on SC. Data is segmented into portions
	 * each of a length of MAX_READWRITE_BYTES bytes. Each segment is
	 * read from the SC.
	 */

	/* get no. of read calls with a length of MAX_READWRITE_BYTES bytes */
	no_read_calls = WEF_len / MAX_READWRITE_BYTES;
	rest = WEF_len % MAX_READWRITE_BYTES;

	if (!(content)) {
		aux_add_error(EINVALID, "invalid input value (content)", CNULL, 0, proc);
		return (-1);
	}
	/* allocate storage for the object to be read */
	content->noctets = WEF_len;
	if (!(content->octets = (char *) malloc(content->noctets))) {
		aux_add_error(EMALLOC, "content->octets", CNULL, 0, proc);
		return (-1);
	}
	
	/* if length of file is 0, file is empty */
	if (WEF_len == 0) {
		aux_add_error(EOBJ, "File to be read is empty", pse_sel->object.name, char_n, proc);
		return (0);
	}


	/*
	 * Read data from WEF in portions of MAX_READWRITE_BYTES bytes and
	 * concatenate these to one octetstring (content)
	 */

	data_sel.data_ref.string_sel = WEF_LEN_BYTES;
	data_length = MAX_READWRITE_BYTES;

	for (i = 0; i < no_read_calls; i++) {
		sca_rc = sca_read_data(sct_id,
				       &file_id,
				       &data_sel,
				       data_length,
				       &out_data,
				       &sc_obj_entry->sm_SC_read);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_read_data", sca_errmsg, char_n, proc);
			return (-1);
		}
#ifdef SECSCTEST
		fprintf(stderr, "\n\nRead data:\n");
		aux_fxdump(stderr, out_data.octets, out_data.noctets);
		fprintf(stderr, "\n");
#endif

		/* concatenate read data to one octetstring */
		for (j = 0; j < out_data.noctets; j++) {
			content->octets[(MAX_READWRITE_BYTES * i) + j] = out_data.octets[j];
		}
		free(out_data.octets);

		data_sel.data_ref.string_sel += out_data.noctets;

	}			/* end for */

	/*
	 * read rest, if no. of bytes to be read is not a multiple of
	 * MAX_READWRITE_BYTES
	 */

	if (rest > 0) {
		data_length = rest;
		sca_rc = sca_read_data(sct_id,
				       &file_id,
				       &data_sel,
				       data_length,
				       &out_data,
				       &sc_obj_entry->sm_SC_read);
		if (sca_rc < 0) {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(secsc_errno, "sca_read_data (rest)", sca_errmsg, char_n, proc);
			return (-1);
		}
#ifdef SECSCTEST
		fprintf(stderr, "\n\nRead data:\n");
		aux_fxdump(stderr, out_data.octets, out_data.noctets);
		fprintf(stderr, "\n");
#endif

		/* concatenate read data to one octetstring */
		for (j = 0; j < out_data.noctets; j++) {
			content->octets[(MAX_READWRITE_BYTES * i) + j] = out_data.octets[j];
		}
		free(out_data.octets);

	}			/* end if */
	return (0);


}				/* end secsc_read() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_chpin					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  a) Change PIN for object on SC:				*/
/*     In this case the error EOBJPIN is returned.		*/
/*     This function is not supported.				*/
/*								*/
/*  b) Change PIN for an application on the SC:			*/
/*     1) If the belonging application is not open, it will	*/
/*	  be opened.						*/
/*     2) Get parameters for the object SC_PIN from the		*/
/*        global variable "sc_app_list[].sc_obj_list[]".	*/
/*        - SC_PIN is an SC-object, which is determined by an 	*/
/*          entry in "sc_obj_list[]".				*/
/*     3) If user enters an incorrect PIN, the PIN-change       */
/*        is repeated two times.				*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_change_pin()		Change PIN on the smartcard.    */
/*   sca_display()		Display text on SCT-display.    */
/*							       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   bell_function()		"Ring the bell" to require user */
/*                              input at the SCT.		*/
/*   get_sca_keyid()		Transform structure SCId into   */
/*				structure KeyId (for a key on   */
/*				the SC).			*/
/*   handle_sc_app()		If application not open, open it*/
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_chpin(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	KeyId           key_id;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */
	int             time_out;
	char           *display_text;
	int             chgpin_rc;
	int             chgpin_errno;
	char           *chgpin_errmsg;
	int             chgpin_attempts = 0;	/* no. of attempts to change
						 * the PIN	 */


	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;



	char           *proc = "secsc_chpin";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Change PIN for an object (WEF, key) on the SC is not
		 * supported
		 */
		aux_add_error(EOBJPIN, "Change PIN for object not supported", CNULL, 0, proc);
		return (-1);

	}
	 /* end if */ 
	else {

		/*
		 * Change PIN for the application on the SC
		 */

		/* If belonging application not open, open it */
		if (handle_sc_app(sct_id, pse_sel->app_name)) {
			aux_add_error(EAPP, "Application could not be opened", CNULL, 0, proc);
			return (-1);
		}
		/* get information about the object SC_PIN */
		sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, SC_PIN_name);
		if (sc_obj_entry == (SCObjEntry * ) 0) {
			aux_add_error(ECONFIG, "get SC-Obj-info for object SC_PIN", CNULL, 0, proc);
			return (-1);
		}
		if (sc_obj_entry->type != SC_KEY_TYPE) {

			/*
			 * SC_PIN has to be a key on the SC
			 */
			aux_add_error(ECONFIG, "SC_PIN has to be a key on the SC", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * set security mode for writing an SC-object (object SC_PIN
		 * is written from the SCT to the SC
		 */
		sm_SCT.command = sc_obj_entry->sm_SCT;
		sm_SCT.response = SEC_NORMAL;
		if (set_sec_mode(sct_id, &sm_SCT)) {
			aux_add_error(ESECMESS, "set security mode for writing obj", CNULL, 0, proc);
			return (-1);
		}
		get_sca_keyid(&sc_obj_entry->sc_id, &key_id);


		/*
		 * change PIN  (if user enters invalid PIN / new PIN, repeat
		 * 2 times)
		 */
		do {
			bell_function();
			chgpin_rc = sca_change_pin(sct_id,
						   &key_id,
						&sc_obj_entry->sm_SC_write);
			chgpin_errno = sca_errno;
			chgpin_errmsg = sca_errmsg;
			chgpin_attempts++;

			if (chgpin_rc < 0) {
				switch (sca_errno) {

				case EKEYLOCK:
					aux_add_error(EPINLOCK, "sca_change_pin", sca_errmsg, char_n, proc);

					/* display message on SCT-Display */
					sca_rc = sca_display(sct_id,
					display_text = SCT_TEXT_PIN_LOCKED,
							     time_out = 0);
					if (sca_rc < 0) {
						secsc_errno = analyse_sca_err(sct_id);
						aux_add_error(secsc_errno, "sca_display", sca_errmsg, char_n, proc);
						return (-1);
					}
					return (-1);	/* PIN on SC is locked */
					break;

				case ENEWPIN:
					sca_rc = sca_display(sct_id,
					display_text = SCT_TEXT_NEW_PIN_INV,
							     time_out = 0);
					if (sca_rc < 0) {
						secsc_errno = analyse_sca_err(sct_id);
						aux_add_error(secsc_errno, "sca_display", sca_errmsg, char_n, proc);
						return (-1);
					}
					break;

				case EPININC:
				case EAUTH_WRITE:
					sca_rc = sca_display(sct_id,
					display_text = SCT_TEXT_PIN_INVALID,
							     time_out = 0);
					if (sca_rc < 0) {
						secsc_errno = analyse_sca_err(sct_id);
						aux_add_error(secsc_errno, "sca_display", sca_errmsg, char_n, proc);
						return (-1);
					}
					break;
				default:
					secsc_errno = analyse_sca_err(sct_id);
					aux_add_error(secsc_errno, "sca_change_pin (SC_PIN)", sca_errmsg, char_n, proc);
					return (-1);

				}	/* end switch */
			}
			 /* end if */ 
			else
				/* PIN change was successful */
				return (0);

		}		/* end do */
		while (chgpin_attempts < MAX_PIN_FAIL);

		/* after 3 unsuccessful attempts: PIN change fails */
		sca_errno = chgpin_errno;
		sca_errmsg = chgpin_errmsg;
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_change_pin (SC_PIN)", sca_errmsg, char_n, proc);
		return (-1);
	}			/* end else */


}				/* end secsc_chpin() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_gen_key					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Generate and install key on SCT/SC:			*/
/*								*/
/*   1) Handling of new and old decryption key:			*/
/*								*/			
/*      a) If "key->pse_sel->object.name" = "DecSKold", an      */
/*         error is returned.					*/
/*      b) If "key->pse_sel->object.name" = "DecSKnew" and 	*/ 
/*         the object "DecSKold" is an object on the SC, 	*/
/*         => the generated key is installed under the name of 	*/
/*            the oldest decryption key stored on the SC. 	*/
/*      c) If "key->pse_sel->object.name" = "DecSKnew" and 	*/ 
/*         the object "DecSKold" is not an object on the SC, 	*/
/*         => the generated key is installed under the name of 	*/
/*            "DecSKnew".					*/
/*								*/
/*      The objects "SKnew" and "SKold" are treated in the same	*/
/*	way.							*/
/*								*/
/*								*/
/*   2) Get key_id from key (keyref or pse_sel).		*/
/*  								*/
/*   3) Handle SC application for the key, if key = key on SC.  */
/*      (function handle_key_sc_app)				*/
/*								*/
/*--------------------------------------------------------------*/
/*								*/
/*   4) Algorithm:						*/
/*      If key->key->subjectAI != NULL				*/
/*	   => take this algorithm				*/
/*      else take algorithm specified in key->alg.		*/
/*								*/
/*   5) Key attribute list:					*/
/*      If key_id.key_level is set to SCT, the attribute list  	*/
/*      is set to NULL.						*/
/*      else the attribute list for the key installation on the */
/*      SC is set to constant values.				*/
/*								*/
/*      Parameters for "Generate and install key":		*/
/*			   - "sc_app_list[].sc_obj_list[]" or   */
/*                           key_ref delivers:			*/
/*			      - key identifier			*/
/*			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*		           - constant values for key_attr_list,	*/
/*			      if key shall be stored on the SC:	*/
/*			      - key_inst_mode = INST | REPL	*/
/*			      - purpose.authenticate  = FALSE	*/
/*			      - purpose.sec_mess_auth = FALSE	*/
/*			      - purpose.sec_mess_con  = FALSE	*/
/*			      - purpose.cipherment    = TRUE	*/
/*			      - key_presentation = KEY_LOCAL	*/
/*			      - access to file : read / write	*/
/*			      - key_op_mode = REPLACE		*/
/*			      - key_fpc  = 0			*/
/*			      - key_status.PIN_check = FALSE	*/
/*			      - key_status.key_state = NORMAL 	*/
/*								*/
/*   6) Update SC Toc.						*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   key	 	       selection of the key 		*/
/*   replace		       = FALSE => Install key		*/
/*   			       = TRUE  => Replace key		*/
/*							       	*/
/* OUT							       	*/
/*   key->key->subjectkey      In case of RSA the public key is */
/*			       returned.			*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_gen_user_key()		Generate and install user key.  */
/*								*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   get_keyid_for_obj()	Get keyid for object.	        */
/*   handle_gen_DecSK()		Special handling of new and 	*/
/*				old decryption key.		*/
/*   handle_key_sc_app()	Handle SC-application for the   */
/*                              selected key.			*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*   update_SCToc()		Update entry in SCToc.	        */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_gen_key(key, replace)
	Key            *key;
	Boolean         replace;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	KeySel          key_sel;
	KeyBits         key_bits;
	KeyAttrList     key_attr_list;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	char           *proc = "secsc_gen_key";
	char	       *new_DecSK_name;
	Boolean		internal_replace;
	char	       *save_obj_name;
	Boolean	       special_DecSK_selection;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;
	internal_replace = replace;


	/*
	 *  Handling of new and old decryption key:
	 */

	if (handle_gen_DecSK(key, replace, &new_DecSK_name, &internal_replace)) {
		aux_add_error(EKEYSEL, "Cannot generate DecSK for SC", CNULL, 0, proc);
		return (-1);
	}
	if (new_DecSK_name) {

		/*
		 *  Object name of DecSK has been mapped on a new name.
		 */

		if (get_keyid_for_obj(key->pse_sel->app_name, new_DecSK_name, &key_sel.key_id)) {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			strzfree(&new_DecSK_name);
			return (-1);
		}
	}
	else {
		if (key_to_keyid(key, &key_sel.key_id, special_DecSK_selection = FALSE)) {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			return (-1);
		}
	}

	/*
	 * Handle SC application for key:
	 */

	if (handle_key_sc_app(sct_id, key, key_sel.key_id)) {
		aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
		return (-1);
	}


/*
 *   Intermediate result: 1) Key-id of the key to be generated and installed
 *                           is stored in "key_sel.key_id" !
 * 			  2) If key shall be installed on the SC,
 *			        the belonging application on the SC is open.
 *
 *
 *            Next to do: 1. Get algorithm,
 *            		  2. If key shall be installed on the SC,
 *			        set the attribute list for the key
 *		          3. Call SCA-IF function "sca_gen_user_key"
 */


	/* Get algorithm  of the key to be generated */
	if ((key->key) && (key->key->subjectAI))
		key_sel.key_algid = key->key->subjectAI;
	else if (key->alg)
		key_sel.key_algid = key->alg;
	else {
		aux_add_error(EALGID, "Algorithm for generation of key missing", CNULL, 0, proc);
		return (-1);
	}

	key_sel.key_bits = &key_bits;	/* for a returned public RSA key */


	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_gen_user_key", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}
	if ((key_sel.key_id.key_level == SC_MF) ||
	    (key_sel.key_id.key_level == SC_DF) ||
	    (key_sel.key_id.key_level == SC_SF)) {

		/* set key attribute list */
		if (internal_replace == FALSE)
			key_attr_list.key_inst_mode = INST;
		else
			key_attr_list.key_inst_mode = REPL;

		key_attr_list.key_attr.key_purpose.authenticate = FALSE;
		key_attr_list.key_attr.key_purpose.sec_mess_auth = FALSE;
		key_attr_list.key_attr.key_purpose.sec_mess_con = FALSE;
		key_attr_list.key_attr.key_purpose.cipherment = TRUE;
		key_attr_list.key_attr.key_presentation = KEY_LOCAL;
		key_attr_list.key_attr.key_op_mode = REPLACE;
		key_attr_list.key_attr.MAC_length = 4;

		key_attr_list.key_fpc = 0;
		key_attr_list.key_status.PIN_check = FALSE;
		key_attr_list.key_status.key_state = KEY_NORMAL;

		sca_rc = sca_gen_user_key(sct_id, &key_sel, &key_attr_list);
	} else {
		sca_rc = sca_gen_user_key(sct_id, &key_sel, (KeyAttrList *)0);
	}

	if (sca_rc < 0) {
		if ((sca_errno == EFILE) && (key_attr_list.key_inst_mode == INST)) {
			aux_add_error(EKEYSEL, "Key to be installed exists already!", CNULL, 0, proc);
		}
		else 
		if ((sca_errno == EFILE) && (key_attr_list.key_inst_mode == REPL)) {
			aux_add_error(EKEYSEL, "Key to be replaced doesn't exist!", CNULL, 0, proc);
		}
		else {
			secsc_errno = analyse_sca_err(sct_id);
			aux_add_error(EKEYSEL, "sca_gen_user_key", sca_errmsg, char_n, proc);
		}
		return (-1);
	}
/*
 *   Intermediate result: The key/keypair has been generated!
 *
 *            Next to do: If algid = RSA
 *                           Transform public key (structure KeyBits) into
 *                                     public key (structure KeyInfo) and
 *			     return public key in "key->key->subjectkey".
 *
 */

	switch (aux_ObjId2AlgEnc(key_sel.key_algid->objid)) {
	case RSA:

		if (!key->key) {
			aux_add_error(EINVALID, "No memory for public RSA key!", CNULL, 0, proc);
			return (-1);
		}
		if (e2_KeyBits(key_sel.key_bits, &key->key->subjectkey)) {
			aux_add_error(EINVALID, "e2_KeyBits", CNULL, 0, proc);
			return (-1);
		}
#ifdef SECSCTEST
		fprintf(stderr, "&key->key->subjectkey: \n");
		aux_fxdump(stderr, key->key->subjectkey.bits, key->key->subjectkey.nbits / 8);
		fprintf(stderr, " \n");
#endif
		/* release storage for public key (structure KeyBits) */
		aux_free2_KeyBits(key_sel.key_bits);
		break;
	}			/* end switch */



	/*
	 *  Update SC Toc
	 */

	if ( (key->pse_sel != (PSESel *) 0) && (key->pse_sel->object.name != CNULL) ) {

		if (new_DecSK_name) {

			/* 
			 *  Update the entry in SCToc for the name
			 *   of the old decryption key. 
			 */

			save_obj_name = key->pse_sel->object.name;
			key->pse_sel->object.name = new_DecSK_name;
#ifdef SECSCTEST
			fprintf(stderr,"Update new_DecSK_name: %s\n", new_DecSK_name);
#endif

			update_SCToc(key->pse_sel, 93, 0);

			key->pse_sel->object.name = save_obj_name;
  			strzfree(&new_DecSK_name);
		}
		else {

#ifdef SECSCTEST
			fprintf(stderr,"Update: %s\n", key->pse_sel->object.name);
#endif
			update_SCToc(key->pse_sel, 93, 0);
		}
	}

#ifdef SECSCTEST
			sec_print_toc(stderr, key->pse_sel);
#endif


	return (0);


}				/* end secsc_gen_key() */







/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_sign					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Sign octetstring with key from the SC.			*/
/*								*/
/*   1) Get key_id from key (keyref or pse_sel).		*/
/*   2) Check key_id:						*/
/*      Level of key_id must be a level on the SC, 		*/
/*      else return(error).					*/
/*   3) Handle SC application for the key, if key = key on SC.  */
/*      (function handle_key_sc_app)				*/
/*								*/
/*--------------------------------------------------------------*/
/*								*/
/*   4) Algorithm:						*/
/*      If signature->signAI->objid == NULL			*/
/*         take default_sign_alg: md5WithRsa and 		*/
/*         return it in signature->signAI->objid		*/
/*         (memory is allocated)				*/
/*								*/
/*       Check signAI:						*/
/*        if alg != signature algorithm				*/
/*            => return(error)					*/
/*								*/
/*								*/
/*	Check signature algorithm:				*/
/*	If a parameter is specified for an algorithm which has 	*/
/*	no parameter,  an error is returned.			*/
/*								*/
/*   5) Get parameter for hash-function				*/
/*   6) Call "sca_sign" to sign octetstring with key from SC.	*/
/*      Parameters for "Sign octetstring":			*/
/*			   - "sc_app_list[].sc_obj_list[]" or 	*/
/*			     key_ref delivers:			*/
/*			      - key identifier			*/
/*			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   in_octets		       Data to be signed.		*/
/*   signature							*/
/*   more							*/
/*   key		       Structure which identifies the   */
/*			       signature key.		 	*/
/*   hash_input		       Add. hash-alg specific parameters*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*   signature->signature      Returned signature. Memory is 	*/
/*			       provided by "sca_sign".		*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_sign()			Sign octetstring. 		*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgHash()	Map object identifier on 	*/
/*				algorithm hash method.		*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   aux_ObjId2ParmType()	Map object identifier on 	*/
/*				type of parameter.		*/
/*   d_KeyBits()		Decode given BitString into 	*/
/*				structure KeyBits.		*/
/*   handle_key_sc_app()	Handle SC-application for the   */
/*                              selected key.			*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_sign(in_octets, signature, more, key, hash_input)
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	Key            *key;
	HashInput      *hash_input;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	static KeyId    key_id;
	HashPar        *hash_par;
	HashPar         hash_par1;
	static KeyBits *sqmodn_par;
	static SecMess  sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgType         algtype;
	static AlgHash  alghash;
	ParmType        parmtype;
	int             rc;
	Boolean	        special_DecSK_selection;

	char           *proc = "secsc_sign";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (sec_state == F_null) {
		/* first call of this signature process */

		if (key_to_keyid(key, &key_id, special_DecSK_selection = TRUE)) {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			return (-1);
		}
		if ((key_id.key_level != SC_MF) &&
		    (key_id.key_level != SC_DF) &&
		    (key_id.key_level != SC_SF)) {
			aux_add_error(EKEYSEL, "Signature key must be key on the SC!", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Handle SC application for key:
		 */

		if (handle_key_sc_app(sct_id, key, key_id)) {
			aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
			return (-1);
		}
/*
 *   Intermediate result: 1) Key-id of the signature key is stored in key_id !
 * 			  2) Signature key is a key on the SC.
 * 			  3) The application on the SC is open.
 *
 *
 *            Next to do: 1. Get signature algorithm,
 *            		  2. Get parameter for hash-function,
 *		          3. Call SCA-IF function "sca_sign"
 */

		/*
		 * Get signature algorithm
		 */

		if ((signature->signAI == NULLALGID) || (signature->signAI->objid == NULLOBJID)) {
			/* default signature AI = md5WithRsa */
			signature->signAI = aux_cpy_AlgId(md5WithRsa);
		}
		algtype = aux_ObjId2AlgType(signature->signAI->objid);
		if (algtype != SIG) {
			aux_add_error(EINVALID, "wrong signAI in signature", signature->signAI, AlgId_n, proc);
			return (-1);
		}

		/*
		 * Check signature algorithm:
		 */

		if (((parmtype = aux_ObjId2ParmType(signature->signAI->objid)) == PARM_NULL) &&
		    (signature->signAI->parm)) {
			aux_add_error(EINVALID, "wrong parameter in signature algorithm", signature->signAI, AlgId_n, proc);
			return (-1);
		}

		/*
		 * Get parameter for hash-function:
		 */

		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		if (alghash == SQMODN) {
			/* decode given BitString into structure KeyBits */
			sqmodn_par = d_KeyBits(&hash_input->sqmodn_input);
			if (!sqmodn_par) {
				aux_add_error(EINVALID, "Decode hash_input failed", CNULL, 0, proc);
				return (-1);
			}
		}
		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_sign", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			goto errcase;
		}
		sec_state = F_sign;
	}
	 /* end if (sec_state == F_null) */ 
	else if (sec_state != F_sign) {
		aux_add_error(ESIGN, "wrong sec_state", CNULL, 0, proc);
		goto errcase;
	}

	/*
	 * The following is performed in any case
	 */


	/*
	 * Get parameter for hash-function:
	 */

	switch (alghash) {
	case SQMODN:
		if (!sqmodn_par) {
			aux_add_error(EINVALID, "Decode hash_input failed", CNULL, 0, proc);
			return (-1);
		}
		hash_par1.sqmodn_par.part1.noctets = sqmodn_par->part1.noctets;
		hash_par1.sqmodn_par.part1.octets = sqmodn_par->part1.octets;
		hash_par1.sqmodn_par.part2.noctets = sqmodn_par->part2.noctets;
		hash_par1.sqmodn_par.part2.octets = sqmodn_par->part2.octets;
		hash_par1.sqmodn_par.part3.noctets = 0;
		hash_par1.sqmodn_par.part4.noctets = 0;
		hash_par = &hash_par1;
		break;
	case MD2:
	case MD4:
	case MD5:
	case SHA:
		hash_par = (HashPar * ) 0;
		break;
	default:
		aux_add_error(EALGID, "invalid hash alg_id", CNULL, 0, proc);
		return (-1);
	}			/* end switch */


	sca_rc = sca_sign(sct_id,
			  in_octets,
			  signature,
			  more,
			  &key_id,
			  hash_par);


	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_sign", sca_errmsg, char_n, proc);
		goto errcase;
	}

	/*
	 * if more == END, release storage
	 */

	if (more == END) {
		if ((alghash == SQMODN) && (sqmodn_par))
			aux_free_KeyBits(&sqmodn_par);

		sec_state = F_null;

#ifdef SECSCTEST
		fprintf(stderr, "signature->signature.bits: \n");
		aux_fxdump(stderr, signature->signature.bits, signature->signature.nbits / 8);
		fprintf(stderr, " \n");
#endif

	}			/* end if (more == END) */
	return (0);


errcase:
	if ((alghash == SQMODN) && (sqmodn_par))
		aux_free_KeyBits(&sqmodn_par);

	sec_state = F_null;

	return (-1);



}				/* end secsc_sign() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_verify					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Verify a given digital signature within the SCT.		*/
/*								*/
/*   1) Check key:						*/
/*      Key must be delivered in key->key.			*/
/*      No application check will be done,  the verification is */
/*      done within the SCT.					*/
/*								*/
/*   2) Algorithm:						*/
/*      If signature->signAI->objid == NULL			*/
/*         take default_sign_alg: md5WithRsa and 		*/
/*         return it in signature->signAI->objid		*/
/*         (memory is allocated)				*/
/*								*/
/*       Check signAI:						*/
/*        if alg != signature algorithm				*/
/*            => return(error)					*/
/*								*/
/*       Check verification key:				*/
/*        if key->key->subjectAI->objid != NULL			*/
/*	        => encryption method of verification key must 	*/
/*                 be = encryption algorithm of signAI		*/
/*        if key->key->subjectAI->objid == NULL			*/
/*	        => return error				 	*/
/*								*/
/*	Check algorithm:					*/
/*	If a parameter is specified for an algorithm which has 	*/
/*	no parameter,  an error is returned.			*/
/*								*/
/*   3) Get parameter for hash-function				*/
/*   4) Transform structure KeyInfo to structure KeyBits	*/
/*   5) Call "sca_verify" to verify given signature within the	*/
/*      SCT:							*/
/*      Parameters for "Verify signature":			*/
/* 			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   in_octets		       Data to be verified.		*/
/*   signature		      					*/
/*   more							*/
/*   key		       Structure which identifies the   */
/*			       verification key.	 	*/
/*   hash_input		       Add. hash-alg specific parameters*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       Signature ok.			*/
/*   -1			       Invalid signature.		*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_verify()		Sign octetstring. 		*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   aux_ObjId2AlgHash()	Map object identifier on 	*/
/*				algorithm hash method.		*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   aux_ObjId2ParmType()	Map object identifier on 	*/
/*				type of parameter.		*/
/*   d_KeyBits()		Decode given BitString into 	*/
/*				structure KeyBits.		*/
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_verify(in_octets, signature, more, key, hash_input)
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	Key            *key;
	HashInput      *hash_input;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	HashPar        *hash_par;
	static KeySel   key_sel;
	static AlgId   *key_alg;
	HashPar         hash_par1;
	static KeyBits *sqmodn_par;
	static SecMess  sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgType         algtype;
	AlgEnc          algenc;
	static AlgHash  alghash;
	ParmType        parmtype;
	int             rc;

	char           *proc = "secsc_verify";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (sec_state == F_null) {
		/* first call of this verification process */

		if ((!key) || (!key->key)) {
			aux_add_error(EKEYSEL, "No verification key!", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Get signature algorithm
		 */

		if ((signature->signAI == NULLALGID) || (signature->signAI->objid == NULLOBJID)) {
			/* default signature AI = md5WithRsa */
			signature->signAI = aux_cpy_AlgId(md5WithRsa);
		}
		algtype = aux_ObjId2AlgType(signature->signAI->objid);
		algenc = aux_ObjId2AlgEnc(signature->signAI->objid);
		if (algtype != SIG) {
			aux_add_error(EINVALID, "wrong signAI in signature", signature->signAI, AlgId_n, proc);
			return (-1);
		}

		/*
		 * Check verification key
		 */

		if ((key->key->subjectAI != NULLALGID) && (key->key->subjectAI->objid != NULLOBJID)) {
			if (algenc != aux_ObjId2AlgEnc(key->key->subjectAI->objid)) {
				aux_add_error(EINVALID, "wrong encryption method in parameter key->key->subjectAI", key->key->subjectAI, AlgId_n, proc);
				return -1;
			}
		} else {
			aux_add_error(EINVALID, "wrong alg in parameter key->key->subjectAI", key->key->subjectAI, AlgId_n, proc);
			return -1;
		}


		/*
		 * Check algorithm:
		 */

		if (((parmtype = aux_ObjId2ParmType(signature->signAI->objid)) == PARM_NULL) &&
		    (signature->signAI->parm)) {
			aux_add_error(EINVALID, "wrong parameter in signature algorithm", signature->signAI, AlgId_n, proc);
			return (-1);
		}

		/*
		 * Get parameter for hash-function:
		 */

		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		if (alghash == SQMODN) {
			/* decode given BitString into structure KeyBits */
			sqmodn_par = d_KeyBits(&hash_input->sqmodn_input);
			if (!sqmodn_par) {
				aux_add_error(EINVALID, "Decode hash_input failed", CNULL, 0, proc);
				return (-1);
			}
		}

		/*
		 * Transform structure KeyInfo to structure KeyBits
		 */

		if ((key_sel.key_bits = d_KeyBits(&key->key->subjectkey)) == (KeyBits * ) 0) {
			aux_add_error(EINVALID, "d_KeyBits failed for encryptionkey", CNULL, 0, proc);
			return (-1);
		}
		key_alg = aux_cpy_AlgId(key->key->subjectAI);


		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_verify", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			goto errcase;
		}
		sec_state = F_verify;
	}
	 /* end if (sec_state == F_null) */ 
	else if (sec_state != F_verify) {
		aux_add_error(EVERIFY, "wrong sec_state", CNULL, 0, proc);
		goto errcase;
	}

	/*
	 * The following is performed in any case
	 */

	/*
	 * Get parameter for hash-function:
	 */

	switch (alghash) {
	case SQMODN:
		if (!sqmodn_par) {
			aux_add_error(EINVALID, "Decode hash_input failed", CNULL, 0, proc);
			return (-1);
		}
		hash_par1.sqmodn_par.part1.noctets = sqmodn_par->part1.noctets;
		hash_par1.sqmodn_par.part1.octets = sqmodn_par->part1.octets;
		hash_par1.sqmodn_par.part2.noctets = sqmodn_par->part2.noctets;
		hash_par1.sqmodn_par.part2.octets = sqmodn_par->part2.octets;
		hash_par = &hash_par1;
		hash_par1.sqmodn_par.part3.noctets = 0;
		hash_par1.sqmodn_par.part4.noctets = 0;
		break;
	case MD2:
	case MD4:
	case MD5:
	case SHA:
		hash_par = (HashPar * ) 0;
		break;
	default:
		aux_add_error(EALGID, "invalid hash alg_id", CNULL, 0, proc);
		return (-1);
	}			/* end switch */


	key_sel.key_algid = key_alg;


	sca_rc = sca_verify(sct_id,
			    in_octets,
			    signature,
			    more,
			    &key_sel,
			    hash_par);


	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_verify", sca_errmsg, char_n, proc);
		goto errcase;
	}

	/*
	 * if more == END, release storage
	 */

	if (more == END) {
		if ((alghash == SQMODN) && (sqmodn_par))
			aux_free_KeyBits(&sqmodn_par);
		if (key_sel.key_bits)
			aux_free_KeyBits(&key_sel.key_bits);
		if (key_alg)
			aux_free_AlgId(&key_alg);

		sec_state = F_null;

	}			/* end if (more == END) */
	return (0);


errcase:
	if ((alghash == SQMODN) && (sqmodn_par))
		aux_free_KeyBits(&sqmodn_par);
	if (key_sel.key_bits)
		aux_free_KeyBits(&key_sel.key_bits);
	if (key_alg)
		aux_free_AlgId(&key_alg);

	sec_state = F_null;

	return (-1);


}				/* end secsc_verify() */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_encrypt					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Encrypt octetstring within the SCT or the SC.		*/
/*								*/
/*   1) Algorithm:						*/
/*      If key->key != NULL					*/
/*         => algorithm is supposed to be in key->key->subjectAI*/
/*      else 							*/
/*         if key->alg != NULL					*/
/*	      => take this algorithm				*/
/*         else return(error)					*/
/*								*/
/*   2) Depending on encryption algorithm:			*/
/*   2.a) RSA:							*/
/*        1) Check key:						*/
/*           Key must be delivered in key->key.			*/
/*           No application check will be done,  the encryption	*/
/*           is done within the SCT.				*/
/*	  2) Transform structure KeyInfo to structure KeyBits	*/
/*								*/
/*								*/
/*   2.b) DES/DES3:						*/
/*        1) Check key:						*/
/*           An error is returned, if the DES-key is delivered  */
/*           in key->key.					*/
/*        2) Get key_id from key (keyref or pse_sel).		*/
/*        3) Handle SC application for the key, if key = key on */
/*           SC (function handle_key_sc_app). 			*/
/*								*/
/*								*/
/*   3) If "out_bits->nbits" is not a multiple of 8,		*/
/*         => return(error)					*/
/*      else 							*/
/*         set "out_octets->octets" = "out_bits->bits" 		*/
/*         set "out_octets->noctets" = "out_bits->nbits" / 8	*/
/*								*/
/*								*/
/*   4) Call "sca_encrypt" to encrypt octetstring within in 	*/
/*      SCT/SC.							*/
/*								*/
/*      Parameters for "Encryption":				*/
/* 			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*								*/
/*								*/
/*   5) Set "out_bits->nbits" = "out_octets->noctets" * 8	*/
/*      return(return of sca_encrypt * 8)			*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   in_octets		       Data to be encrypted.		*/
/*   out_bits		       Encrypted data.			*/
/*   more							*/
/*   key		       Structure which identifies the   */
/*			       encryption key.	 		*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   nn			       no of encrypted bits.		*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_encrypt()		Encrypt octetstring. 		*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   d_KeyBits()		Decode given BitString into 	*/
/*				structure KeyBits.		*/
/*   handle_key_sc_app()	Handle SC-application for the   */
/*                              selected key.			*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_encrypt(in_octets, out_bits, more, key)
	OctetString    *in_octets;
	BitString      *out_bits;
	More            more;
	Key            *key;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	static OctetString *out_octets;
	static AlgId   *key_alg;
	static KeySel   key_sel;
	static SecMess  sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgEnc          algenc;
	AlgType         algtype;
	int             no_enc;
	Boolean	        special_DecSK_selection;

	char           *proc = "secsc_encrypt";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (sec_state == F_null) {
		/* first call of this encryption process */

		if (!key) {
			aux_add_error(EKEYSEL, "No encryption key!", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Get algorithm of the encryption key
		 */

		if (key->key) {
			if ((key->key->subjectAI != NULLALGID) && (key->key->subjectAI->objid != NULLOBJID)) {
				key_alg = aux_cpy_AlgId(key->key->subjectAI);
			} else {
				aux_add_error(EINVALID, "Algorithm missing in key->key", CNULL, 0, proc);
				return (-1);
			}
		} else {
			if (key->alg) {
				key_alg = aux_cpy_AlgId(key->alg);
			} else {
				aux_add_error(EINVALID, "Algorithm missing", CNULL, 0, proc);
				return (-1);
			}
		}

		if (!key_alg) {
			aux_add_error(EINVALID, "Algorithm missing", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Algorithm = encryption algorithm?
		 */

		if (((algtype = aux_ObjId2AlgType(key_alg->objid)) != SYM_ENC) &&
		    ((algtype = aux_ObjId2AlgType(key_alg->objid)) != ASYM_ENC)) {
			aux_add_error(EALGID, "Invalid encryption algorithm", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Get key depending on the algorithm
		 */

		algenc = aux_ObjId2AlgEnc(key_alg->objid);

		switch (algenc) {
		case RSA:
			if (!key->key) {
				aux_add_error(EKEYSEL, "No RSA encryption key!", CNULL, 0, proc);
				return (-1);
			}

			/*
			 * Transform structure KeyInfo to structure KeyBits
			 */
#ifdef SECSCTEST
			fprintf(stderr, "SECSC_ENCRYPT: &key->key->subjectkey: \n");
			aux_fxdump(stderr, key->key->subjectkey.bits, key->key->subjectkey.nbits / 8);
			fprintf(stderr, " \n");
#endif

			if ((key_sel.key_bits = d_KeyBits(&key->key->subjectkey)) == (KeyBits * ) 0) {
				aux_add_error(EINVALID, "d_KeyBits failed for encryptionkey", CNULL, 0, proc);
				return (-1);
			}
			break;
		case DES:
		case DES3:
			if (key->key) {
				aux_add_error(EKEYSEL, "Delivery of DES key to SCT/SC not allowed!", CNULL, 0, proc);
				return (-1);
			}
			if (key_to_keyid(key, &key_sel.key_id, special_DecSK_selection = FALSE)) {
				aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
				return (-1);
			}

			/*
			 * Handle SC application for key:
			 */

			if (handle_key_sc_app(sct_id, key, key_sel.key_id)) {
				aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
				return (-1);
			}
			break;
		default:
			aux_add_error(EALGID, "unknown alg_id", CNULL, 0, proc);
			return (-1);
		}		/* end switch */


		if ((out_octets = (OctetString *) malloc(sizeof(OctetString))) == NULLOCTETSTRING) {
			aux_add_error(EMALLOC, "out_octets", CNULL, 0, proc);
			goto errcase;
		}
		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_encrypt", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			goto errcase;
		}
		sec_state = F_encrypt;
	}
	 /* end if (sec_state == F_null) */ 
	else if (sec_state != F_encrypt) {
		aux_add_error(EENCRYPT, "wrong sec_state", CNULL, 0, proc);
		goto errcase;
	}

	/*
	 * The following is performed in any case
	 */

	/*
	 * The SCA-software works with octets, the SEC-software expects the
	 * encrypted output as a bitstring
	 */


	if ((out_bits->nbits > 0) && ((out_bits->nbits % 8) != 0)) {
		aux_add_error(ENOTSUPP, "out_bits->nbits not a multiple of 8!", CNULL, 0, proc);
		goto errcase;
	}
	out_octets->octets = out_bits->bits;
	if (out_bits->nbits > 0)
		out_octets->noctets = out_bits->nbits / 8;
	else
		out_octets->noctets = out_bits->nbits;

#ifdef SECSCTEST
	fprintf(stderr, "in_octets: \n");
	aux_fxdump(stderr, in_octets->octets, in_octets->noctets);
	fprintf(stderr, " \n");
#endif

	key_sel.key_algid = key_alg;

	no_enc = sca_encrypt(sct_id,
			     in_octets,
			     out_octets,
			     more,
			     &key_sel,
			     &sm_SC);


	if (no_enc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_encrypt", sca_errmsg, char_n, proc);
		goto errcase;
	}

	/*
	 * The SCA-software works with octets, the SEC-software expects the
	 * encrypted output as a bitstring
	 */

	out_bits->nbits += no_enc * 8;


	/*
	 * if more == END, release storage of key_bits
	 */

	if (more == END) {
		free(out_octets);
		if (key_sel.key_bits)
			aux_free_KeyBits(&key_sel.key_bits);
		if (key_alg)
			aux_free_AlgId(&key_alg);
		sec_state = F_null;
	}
#ifdef SECSCTEST
	fprintf(stderr, "SECSC_ENCRYPT: no of encrypted data: %d\n", no_enc);
	fprintf(stderr, "out_octets: \n");
	aux_fxdump(stderr, out_octets->octets, no_enc);
	fprintf(stderr, " \n");
	fprintf(stderr, "out_bits->nbits: %d\n", out_bits->nbits);
	fprintf(stderr, "out_octets->noctets: %d\n", out_octets->noctets);
#endif



	/*
	 * normal end :
	 */

	return (no_enc * 8);



	/*
	 * error case => release storage:
	 */

errcase:
	if (out_octets)
		free(out_octets);
	if (key_sel.key_bits)
		aux_free_KeyBits(&key_sel.key_bits);
	if (key_alg)
		aux_free_AlgId(&key_alg);

	sec_state = F_null;
	return (-1);


}				/* end secsc_encrypt() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_decrypt					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Decrypt bitstring within the SCT or the SC.		*/
/*								*/
/*   1) Algorithm:						*/
/*      if key->alg == NULL					*/
/*         return(error)					*/
/*	else take this algorithm				*/
/*								*/
/*   2) Key selection:						*/
/*      1) An error is returned, if the key is delivered 	*/
/*         in "key->key".					*/
/*      2) Get key_id from key (keyref or pse_sel).		*/
/*	   Special selection of an decryption key is done in	*/
/*	   function "key_to_keyid()".				*/
/*      3) Handle SC application for the key, if key = key on   */
/*         SC (function handle_key_sc_app). 			*/
/*								*/
/*   3) If "in_bits->nbits" is not a multiple of 8,		*/
/*         => return(error)					*/
/*      else 							*/
/*         set "in_octets->octets" = "in_bits->bits" 		*/
/*         set "in_octets->noctets" = "in_bits->nbits" / 8	*/
/*								*/
/*								*/
/*   4) Call "sca_decrypt" to decrypt octetstring within in 	*/
/*      SCT/SC.							*/
/*								*/
/*      Parameters for "Decryption":				*/
/* 			   - "sca_fct_list[]" delivers:		*/
/*			      - sec_mess			*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   in_bits		       Data to be Decrypted.		*/
/*   out_octets		       Decrypted data.			*/
/*   more							*/
/*   key		       Structure which identifies the   */
/*			       decryption key.		 	*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   nn			       no of decrypted octets.		*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_decrypt()		Decrypt octetstring. 		*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   handle_key_sc_app()	Handle SC-application for the   */
/*                              selected key.			*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_decrypt(in_bits, out_octets, more, key)
	BitString      *in_bits;
	OctetString    *out_octets;
	More            more;
	Key            *key;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	static OctetString *in_octets;
	static AlgId   *key_alg;
	static KeyBits *key_bits;
	static KeySel   key_sel;
	static SecMess  sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgType         algtype;
	int             no_dec;
	Boolean	        special_DecSK_selection;

	char           *proc = "secsc_decrypt";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (sec_state == F_null) {
		/* first call of this decryption process */

		if (!key) {
			aux_add_error(EKEYSEL, "No decryption key!", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Get algorithm of the decryption key
		 */

		if (!key->alg) {
			aux_add_error(EINVALID, "Algorithm missing", CNULL, 0, proc);
			return (-1);
		} else {
			key_alg = aux_cpy_AlgId(key->alg);
			if (!key_alg) {
				aux_add_error(EINVALID, "Algorithm missing", CNULL, 0, proc);
				return (-1);
			}
		}



		/*
		 * Algorithm = decryption algorithm?
		 */

		if (((algtype = aux_ObjId2AlgType(key_alg->objid)) != SYM_ENC) &&
		    ((algtype = aux_ObjId2AlgType(key_alg->objid)) != ASYM_ENC)) {
			aux_add_error(EALGID, "Invalid encryption algorithm", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Key selection:
		 */

		if (key->key) {
			aux_add_error(EKEYSEL, "Delivery of decryption key to SCT/SC not allowed!", CNULL, 0, proc);
			return (-1);
		}
		key_bits = (KeyBits * ) 0;

		if (key_to_keyid(key, &key_sel.key_id, special_DecSK_selection = TRUE)) {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			return (-1);
		}

		/*
		 * Handle SC application for key:
		 */

		if (handle_key_sc_app(sct_id, key, key_sel.key_id)) {
			aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
			return (-1);
		}
		if ((in_octets = (OctetString *) malloc(sizeof(OctetString))) == NULLOCTETSTRING) {
			aux_add_error(EMALLOC, "out_octets", CNULL, 0, proc);
			goto errcase;
		}
		/* set security mode for SCA-function */
		if (set_fct_sec_mode(sct_id, "sca_decrypt", &sm_SC)) {
			aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
			goto errcase;
		}
		sec_state = F_decrypt;
	}
	 /* end if (sec_state == F_null) */ 
	else if (sec_state != F_decrypt) {
		aux_add_error(EENCRYPT, "wrong sec_state", CNULL, 0, proc);
		goto errcase;
	}

	/*
	 * The following is performed in any case
	 */

	/*
	 * The SCA-software works with octets, the SEC-software delivers the
	 * input data in an bitstring
	 */

	if ((in_bits->nbits > 0) && ((in_bits->nbits % 8) != 0)) {
		aux_add_error(ENOTSUPP, "in_bits->nbits not a multiple of 8!", CNULL, 0, proc);
		goto errcase;
	}
	in_octets->octets = in_bits->bits;
	if (in_bits->nbits > 0)
		in_octets->noctets = in_bits->nbits / 8;
	else
		in_octets->noctets = in_bits->nbits;

#ifdef SECSCTEST
	fprintf(stderr, "in_octets: \n");
	aux_fxdump(stderr, in_octets->octets, in_octets->noctets);
	fprintf(stderr, " \n");
#endif


	key_sel.key_algid = key_alg;
	key_sel.key_bits = key_bits;	/* is set to NULL */

	no_dec = sca_decrypt(sct_id,
			     in_octets,
			     out_octets,
			     more,
			     &key_sel,
			     &sm_SC);


	if (no_dec < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_decrypt", sca_errmsg, char_n, proc);
		goto errcase;
	}

	/*
	 * if more == END, release storage
	 */

	if (more == END) {
		if (in_octets)
			free(in_octets);
		if (key_alg)
			aux_free_AlgId(&key_alg);
		sec_state = F_null;
	}
#ifdef SECSCTEST
	fprintf(stderr, "SECSC_DECRYPT: no of decrypted data: %d\n", no_dec);
	fprintf(stderr, "out_octets: \n");
	aux_fxdump(stderr, out_octets->octets, no_dec);
	fprintf(stderr, " \n");
	fprintf(stderr, "out_octets->noctets: %d\n", out_octets->noctets);
#endif



	/*
	 * normal end :
	 */

	return (no_dec);



	/*
	 * error case => release storage:
	 */

errcase:
	if (in_octets)
		free(in_octets);
	if (key_alg)
		aux_free_AlgId(&key_alg);

	sec_state = F_null;
	return (-1);


}				/* end secsc_decrypt() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_get_EncryptedKey				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Encrypt an DES key with RSA within SCT/SC.			*/
/*   - The key to be encrypted (plain_key) must be a key stored */
/*     within the SCT (selected with key_ref or object.name).	*/
/*   - The encryption key (encryption_key) must be delivered in */
/*     "encryption_key->key" and encryption alg must be RSA.	*/
/*								*/
/*   1) Check "plain_key":					*/
/*      -  An error is returned, if the key is delivered  	*/
/*         in key->key.						*/
/*      -  Get key_id from key (keyref or pse_sel).		*/
/*								*/
/*   2) "encryption_key":					*/
/*      1) Check encryption key and encryption alg:		*/
/*         If "encryption_key->key" == NULL or  		*/
/*            "encryption_key->key->subjectAI" != rsa		*/
/*	      => return(error)					*/
/*      2) Transform structure KeyInfo to structure KeyBits	*/
/*								*/
/*   3)	No application check will be done, the encryption is	*/
/*      performed within the SCT.				*/
/*								*/
/*   4) Call "sca_enc_des_key" to encrypt the DES key within  	*/
/*      the SCT.						*/
/*								*/
/*   5) As the SCA-function doesn't create a new structure for  */
/*      "encrypted->encryptionAI", a new structure AlgId is 	*/
/*      created by secsc_get_EncryptedKey.			*/
/*      The calling routine can release this structure with 	*/
/*      "aux_free_AlgId".					*/
/*?????????????????????????????????????????????????????????????????????????????????*/
/*      Don't know what to do with "encrypted->subjectAI = NULL???????????????????????*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   encrypted_key	       Encrypted key.			*/
/*   plain_key		       Key to be encrypted.		*/
/*   encryption_key	       Encryption key.			*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*    0			       ok				*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_enc_des_key()		Encrypt DES key with RSA.	*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   d_KeyBits()		Decode given BitString into 	*/
/*				structure KeyBits.		*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_get_EncryptedKey(encrypted_key, plain_key, encryption_key)
	EncryptedKey   *encrypted_key;
	Key            *plain_key;
	Key            *encryption_key;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	KeyId           plain_keyid;
	KeySel          encryption_keysel;
	AlgId          *enc_alg;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgEnc          algenc;
	AlgType         algtype;
	Boolean	        special_DecSK_selection;

	char           *proc = "secsc_get_EncryptedKey";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (!plain_key || !encryption_key || !encrypted_key) {
		aux_add_error(EINVALID, "key missing", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Check "plain_key"
	 */

	if (plain_key->key) {
		aux_add_error(EKEYSEL, "Delivery of plain key to SCT/SC not allowed!", CNULL, 0, proc);
		return (-1);
	}
	if (key_to_keyid(plain_key, &plain_keyid, special_DecSK_selection = FALSE)) {
		aux_add_error(EKEYSEL, "Cannot select plain key!", CNULL, 0, proc);
		return (-1);
	}
	if (plain_keyid.key_level != SCT) {
		aux_add_error(EKEYSEL, "Plain key not a key within the SCT!", CNULL, 0, proc);
		return (-1);
	}
/*
 *   Intermediate result: Plain key is ok!
 *
 *            Next to do: - Check encryption key and encryption alg
 *       		  - Transform structure KeyInfo to structure KeyBits
 */

	if ((!encryption_key->key) ||
	    (!encryption_key->key->subjectAI) ||
	    (!encryption_key->key->subjectAI->objid)) {
		aux_add_error(EKEYSEL, "No encryption key/algorithm!", CNULL, 0, proc);
		return (-1);
	} else {
		algenc = aux_ObjId2AlgEnc(encryption_key->key->subjectAI->objid);
		algtype = aux_ObjId2AlgType(encryption_key->key->subjectAI->objid);
		if ((algenc != RSA) || (algtype != ASYM_ENC)) {
			aux_add_error(EINVALID, "Invalid encryption algorithm!", encryption_key->key->subjectAI, AlgId_n, proc);
			return (-1);
		}
	}

	/*
	 * Transform structure KeyInfo to structure KeyBits
	 */

	if ((encryption_keysel.key_bits = d_KeyBits(&encryption_key->key->subjectkey)) == (KeyBits * ) 0) {
		aux_add_error(EINVALID, "d_KeyBits failed for encryptionkey", CNULL, 0, proc);
		return (-1);
	}
	encryption_keysel.key_algid = encryption_key->key->subjectAI;



/*
 *   Intermediate result: Plain key and encryption key are ok!
 *
 *            Next to do: Call "sca_enc_des_key"
 */

	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_enc_des_key", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		goto errcase;
	}
	sca_rc = sca_enc_des_key(sct_id,
				 &encryption_keysel,
				 &plain_keyid,
				 encrypted_key);


	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_enc_des_key", sca_errmsg, char_n, proc);
		goto errcase;
	}

	/*
	 * Copy returned "encrypted_key->encryptionAI" to a new structure
	 * AlgId
	 */

	enc_alg = encrypted_key->encryptionAI;
	encrypted_key->encryptionAI = aux_cpy_AlgId(enc_alg);


/*?????????????????????????????????????????????????????????????????????????????????*/
/*      Don't know what to with "encrypted->subjectAI = NULL???????????????????????*/
/*      Create new structure and copy "desCBC"
????????????????? */

	if (!encrypted_key->subjectAI) {
		encrypted_key->subjectAI = aux_cpy_AlgId(desCBC);
	}

	/*
	 * normal end, release storage:
	 */

	if (encryption_keysel.key_bits)
		aux_free_KeyBits(&encryption_keysel.key_bits);

	return (0);




	/*
	 * error case => release storage:
	 */

errcase:
	if (encryption_keysel.key_bits)
		aux_free_KeyBits(&encryption_keysel.key_bits);

	return (-1);


}				/* end secsc_get_EncryptedKey() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_put_EncryptedKey				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Decrypt an rsa encrypted DES key and store within SCT/SC.	*/
/*   - The decryption key ("decryption_key") must be a private 	*/
/*     RSA key stored on the SC (selected with key_ref or 	*/
/*     object.name).						*/
/*   - The resulting key (decrypted DES key) is stored under    */
/*     the key_id specified by "plain_key". "plain_key" must    */
/*     address a key in the SCT or on the SC (selected with 	*/
/*     key_ref or object.name).					*/
/*   - The encrypted key ("encrypted_key") must be delivered in	*/
/*     "encrypted_key->subjectkey",				*/
/*     "encrypted_key->subjectAI" must be DES or DES3,		*/
/*     "encrypted_key->encryptionAI" must be RSA.		*/
/*								*/
/*   1) Check "plain_key":					*/
/*      1) Get key_id from key (keyref or pse_sel).		*/
/*      2) Handle SC application for the key, if key = key on   */
/*         SC (function handle_key_sc_app). 			*/
/*								*/
/*   2) Check "decryption_key":					*/
/*      1) An error is returned, if the key is delivered 	*/
/*         in "decryption_key->key".				*/
/*      2) Get key_id from key (keyref or pse_sel).		*/
/*	   Special selection of an decryption key is done in	*/
/*	   function "key_to_keyid()".				*/
/*      3) Handle SC application for the key, if key = key on   */
/*         SC (function handle_key_sc_app). 			*/
/*								*/
/*   3) Check "encrypted_key":					*/
/*      If "encrypted_key->subjectkey" == NULL or		*/
/*         "encrypted_key->subjectAI" != DES or DES3 or 	*/
/*         "encrypted_key->encryptionAI" != RSA		 	*/
/*         return(error)					*/
/*								*/
/*   4) Key attribute list for plain_key:			*/
/*      If key_id.key_level is set to SCT, the attribute list  	*/
/*      is set to NULL.						*/
/*      else the attribute list for the key installation on the */
/*      SC is set to constant values.				*/
/*								*/
/*      Parameters for "Generate and install key":		*/
/*		           - constant values for key_attr_list,	*/
/*			      if key shall be stored on the SC:	*/
/*			      - key_inst_mode = INST | REPL	*/
/*			      - purpose.authenticate  = FALSE	*/
/*			      - purpose.sec_mess_auth = FALSE	*/
/*			      - purpose.sec_mess_con  = FALSE	*/
/*			      - purpose.cipherment    = TRUE	*/
/*			      - key_presentation = KEY_LOCAL	*/
/*			      - access to file : read / write	*/
/*			      - key_op_mode = REPLACE		*/
/*			      - key_fpc  = 0			*/
/*			      - key_status.PIN_check = FALSE	*/
/*			      - key_status.key_state = NORMAL 	*/
/*								*/
/*   4) Call "sca_dec_des_key" to decrypt the rsa encrypted DES */
/*      key within the SCT.					*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   encrypted_key	       Encrypted key.			*/
/*   plain_key		       Key to be encrypted.		*/
/*   decryption_key	       Decryption key.			*/
/*   replace		       if FALSE do not overwrite key    */
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*    0			       ok				*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_dec_des_key()		Encrypt DES key with RSA.	*/
/*								*/
/*   aux_free_KeyBits()		Release members of struct 	*/
/*				KeyBits and KeyBits.		*/
/*   aux_ObjId2AlgEnc()		Map object identifier on 	*/
/*				algorithm encryption method.	*/
/*   aux_ObjId2AlgType()	Map object identifier on 	*/
/*				algorithm type.			*/
/*   handle_key_sc_app()	Handle SC-application for the   */
/*                              selected key.			*/
/*   key_to_keyid()	        Get key_id from key.            */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_put_EncryptedKey(encrypted_key, plain_key, decryption_key, replace)
	EncryptedKey   *encrypted_key;
	Key            *plain_key;
	Key            *decryption_key;
	Boolean         replace;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	KeyId           plain_keyid;
	KeyId           decryption_keyid;
	AlgId          *enc_alg;
	KeyAttrList     key_attr_list;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */
	AlgEnc          algenc;
	AlgType         algtype;
	Boolean	        special_DecSK_selection;

	char           *proc = "secsc_put_EncryptedKey";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (!plain_key || !decryption_key || !encrypted_key) {
		aux_add_error(EINVALID, "key missing", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Check "plain_key"
	 */

	if (plain_key->key) {
		aux_add_error(EKEYSEL, "Delivery of plain key to SCT/SC not allowed!", CNULL, 0, proc);
		return (-1);
	}
	if (key_to_keyid(plain_key, &plain_keyid, special_DecSK_selection = FALSE)) {
		aux_add_error(EKEYSEL, "Cannot select plain key!", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Handle SC application for key:
	 */

	if (handle_key_sc_app(sct_id, plain_key, plain_keyid)) {
		aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
		return (-1);
	}
/*
 *   Intermediate result: Plain key is ok!
 *
 *            Next to do: - Check decryption key
 */

	if (decryption_key->key) {
		aux_add_error(EKEYSEL, "Delivery of decryption key to SCT/SC not allowed!", CNULL, 0, proc);
		return (-1);
	}
	if (key_to_keyid(decryption_key, &decryption_keyid, special_DecSK_selection = TRUE)) {
		aux_add_error(EKEYSEL, "Cannot select decryption key!", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Handle SC application for key:
	 */

	if (handle_key_sc_app(sct_id, decryption_key, decryption_keyid)) {
		aux_add_error(EKEYSEL, "Cannot handle SC-application for SC-key!", CNULL, 0, proc);
		return (-1);
	}
/*
 *   Intermediate result: Plain key and decryption key are ok!
 *
 *            Next to do: Check encrypted key
 */

	if ((encrypted_key == (EncryptedKey * ) 0) ||
	    (encrypted_key->encryptionAI == NULLALGID) ||
	    (encrypted_key->encryptionAI->objid == NULLOBJID) ||
	    (encrypted_key->subjectAI == NULLALGID) ||
	    (encrypted_key->subjectAI->objid == NULLOBJID) ||
	    (encrypted_key->subjectkey.nbits == 0) ||
	    (encrypted_key->subjectkey.bits == CNULL)) {
		aux_add_error(EKEYSEL, "Invalid encrypted_key!", CNULL, 0, proc);
		return (-1);
	}
	algenc = aux_ObjId2AlgEnc(encrypted_key->encryptionAI->objid);
	algtype = aux_ObjId2AlgType(encrypted_key->encryptionAI->objid);
	if ((algenc != RSA) || (algtype != ASYM_ENC)) {
		aux_add_error(EINVALID, "Invalid encryption algorithm!", CNULL, 0, proc);
		return (-1);
	}
	algenc = aux_ObjId2AlgEnc(encrypted_key->subjectAI->objid);
	algtype = aux_ObjId2AlgType(encrypted_key->subjectAI->objid);
	if (((algenc != DES) && (algenc != DES3)) || (algtype != SYM_ENC)) {
		aux_add_error(EINVALID, "Invalid encryption algorithm!", CNULL, 0, proc);
		return (-1);
	}
/*
 *   Intermediate result: Plain key,decryption and encrypted key are ok!
 *
 *            Next to do: - If the plain_key shall be installed on the SC
 *		             set the key_attr_list
 *			  - call sca_dec_des_key
 */


	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_dec_des_key", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}
	if ((plain_keyid.key_level == SC_MF) ||
	    (plain_keyid.key_level == SC_DF) ||
	    (plain_keyid.key_level == SC_SF)) {

		/* set key attribute list */
		if (replace == FALSE)
			key_attr_list.key_inst_mode = INST;
		else
			key_attr_list.key_inst_mode = REPL;

		key_attr_list.key_attr.key_purpose.authenticate = FALSE;
		key_attr_list.key_attr.key_purpose.sec_mess_auth = FALSE;
		key_attr_list.key_attr.key_purpose.sec_mess_con = FALSE;
		key_attr_list.key_attr.key_purpose.cipherment = TRUE;
		key_attr_list.key_attr.key_presentation = KEY_LOCAL;
		key_attr_list.key_attr.key_op_mode = REPLACE;
		key_attr_list.key_attr.MAC_length = 4;

		key_attr_list.key_fpc = 0;
		key_attr_list.key_status.PIN_check = FALSE;
		key_attr_list.key_status.key_state = KEY_NORMAL;

		sca_rc = sca_dec_des_key(sct_id,
					 encrypted_key,
					 &plain_keyid,
					 &decryption_keyid,
					 &key_attr_list);

	} else {
		sca_rc = sca_dec_des_key(sct_id,
					 encrypted_key,
					 &plain_keyid,
					 &decryption_keyid,
					 (KeyAttrList *)0);
	}


	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_dec_des_key", sca_errmsg, char_n, proc);
		return (-1);
	}
	return (0);



}				/* end secsc_put_EncryptedKey() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_del_key					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Delete a key stored in the SCT.				*/
/*								*/
/*   The key to be deleted must be a key stored in the SCT.     */
/*								*/
/*   1) Check "keyref":						*/
/*      -  Get key_id from keyref.				*/
/*      -  an error is returned if the level of the key is not  */
/*         the SCT.						*/
/*								*/
/*   2) Call "sca_del_user_key" to delete user key in the SCT. 	*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   keyref     	       Reference to an existing key.	*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*    0			       ok				*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_del_user_key()		Delete user key in an SCT.	*/
/*								*/
/*   keyref_to_keyid()	        Transform keyref into structure */
/*                              keyid.				*/
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_del_key(keyref)
	KeyRef          keyref;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	KeyId           keyid;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */


	/* Variables for internal use */

	char           *proc = "secsc_del_key";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	if (keyref_to_keyid(keyref, &keyid)) {
		aux_add_error(EKEYSEL, "Cannot select plain key!", CNULL, 0, proc);
		return (-1);
	}
	if (keyid.key_level != SCT) {
		aux_add_error(EKEYSEL, "Only a key within the SCT can be deleted!", CNULL, 0, proc);
		return (-1);
	}
	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_del_user_key", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}
	sca_rc = sca_del_user_key(sct_id,
				  &keyid);


	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_del_user_key", sca_errmsg, char_n, proc);
		return (-1);
	}
	return (0);


}				/* end secsc_del_key() */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_unblock_SCpin				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Unblock blocked PIN on the SC with the PUK.			*/
/*								*/
/*  1. Call "open_sc_application" to open the application on 	*/
/*     the SC and to perform the device authentication.		*/
/*  2. Perform user authentication with "pin_type" = PUK to    	*/
/*     unblock the PIN on the SC.				*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   open_sc_application() 	Require SC, open SC application,*/
/*				perform device authentication.  */
/*   user_authentication()      Perform user authentication	*/
/*				(PUK).				*/
/*			         		       		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC
secsc_unblock_SCpin(pse_sel)
	PSESel         *pse_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;

	int             obj_in_SCToc;


	char           *proc = "secsc_unblock_SCpin";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;



	if (open_sc_application(sct_id, pse_sel->app_name)) {
		aux_add_error(ESCPUK, "Cannot unblock PIN on SC, open app. fails", CNULL, 0, proc);
		return (-1);
	}


	if (user_authentication(sct_id, pse_sel->app_name, PUK)) {
		aux_add_error(ESCAUTH, "PUK authentication not successful.", CNULL, 0, proc);
		return (-1);
	}

	return (0);


}				/* end secsc_unblock_SCpin() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  secsc_sc_eject					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Case 1: Input parameter "sct_sel" == ALL_SCTS: 		*/
/*             =>  eject all SCs, which have been requested	*/
/*                 (in this session) and set application to 	*/
/*	           close for the SCTs.			 	*/
/*								*/
/*   Case 2: Input parameter "sct_sel" == CURRENT_SCT:		*/
/*		=> Eject without check whether SC is inserted.	*/
/*		=> Send to the current SCT an EJECT command by  */
/*                 by calling the function sca_eject.		*/
/*	 	   The sct_id of the current SCT is the value   */
/*		   of the global variable "sc_sel.sct_id".	*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_sel	 	       					*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_sc_info()		Get information about smartcard */
/*   sca_get_sct_info()		Get information about  		*/
/*				registered SCTs.		*/
/*								*/
/*   eject_sc()		        Handle ejection of the SC.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/

RC
secsc_sc_eject(sct_sel)
	SCTSel          sct_sel;
{

	/* Variables for the SCA-IF */
	unsigned int    sct_id;
	OctetString     sc_info;	/* historical characters 		 */
	char           *display_text;
	Boolean         alarm;


	/* Variables for internal use */
	int             no_of_SCTs;	/* number os registered SCTs		 */
	int             count_SCTs;

	char           *proc = "secsc_sc_eject";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	secsc_errno = NOERR;
	sca_rc = 0;
	sct_id = sc_sel.sct_id;


	switch (sct_sel) {

	case ALL_SCTS:

		/*
		 * Send EJECT command to all registered SCTs.
		 */

		/* get number of registered SCTs */
		no_of_SCTs = sca_get_sct_info();

		for (count_SCTs = 1; count_SCTs <= no_of_SCTs; count_SCTs++) {

			/* check: SC in SCT? */
			sca_rc = sca_get_sc_info(count_SCTs, &sc_info);

			if (sca_rc >= 0) {
				aux_free2_OctetString(&sc_info);
				/* SC is inserted => eject it */
				if (eject_sc(count_SCTs, display_text = CNULL, alarm = FALSE)) {
					if (aux_last_error() == EOPENDEV) 
						aux_add_error(EOPENDEV, "Cannot eject smartcard (device for SCT is not available)", CNULL, 0, proc);
					else
						aux_add_error(EEJECT, "Cannot eject smartcard", CNULL, 0, proc);
					return (-1);
				}
			}

		}

		break;

	case CURRENT_SCT:

		/*
		 * Send EJECT command to current SCT.
		 */

		sct_id = sc_sel.sct_id;
		if (eject_sc(sct_id, display_text = CNULL, alarm = FALSE)) {
			if (aux_last_error() == EOPENDEV) 
				aux_add_error(EOPENDEV, "Cannot eject smartcard (device for SCT is not available)", CNULL, 0, proc);
			else
				aux_add_error(EEJECT, "Cannot eject smartcard", CNULL, 0, proc);
			return (-1);
		}
		break;

	default:
		aux_add_error(EEJECT, "Invalid input for sc_eject", CNULL, 0, proc);
		return (-1);

	}			/* end switch */


	return (0);

}				/* end secsc_sc_eject() */







/*--------------------------------------------------------------*/
/*						                */
/* PROC  analyse_sca_err				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Analyse of an error-number returned by an SCA-IF function.  */
/*								*/
/*  - "sca_errno" is the global error variable set by an SCA-IF	*/
/*    function.							*/
/*  - "sca_errmsg" is the global pointer to error message set   */
/*    by an SCA-IF function.					*/
/*     								*/
/*  1. If "sca_errno" indicates that the SC is ejected/removed, */
/*     this "analyse_sca_err" sets the application to NULL for  */
/*     the specified SCT (sct_id).				*/
/*								*/
/*  2. Eject SC, if reset of the SC failed.			*/
/*								*/
/*  3. Return error number ESC to indicate that a STAPAC -   	*/
/*     function has produced this error.			*/
/*								*/



/*??????????????????????????????????????????????????????????????
 *  Levona fragt bei GAO bzgl. der error codes nach !!!
 *  Transforms the error code "sca_errno" into error code for SECSC and returns the latter
 *  In case of an severe error -> set app to close
 *				  close application ?
 *				  eject SC
 *  Soll ein error status zurueckgegeben werden ?????????????????
 *  z.B. ERR-WITH_CARD:  => The application on the SC has to be closed
 *			    The SC has to be ejected.
 *			    Application has to start the communication with the SC again.
 *
 *       ERR_NO_CARD:	 => SC is already ejected
 *			    Application has to start the communication with the SC again.
 *
 *	ERR_SEVERE:	 => The application on the SC has to be closed
 *			    The SC has to be ejected.
 *			    The whole program has to be finished (exit)
 *
 */
/*??????????????????????????????????????????????????????????????*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id 		       SCT identifier			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   ESC		       Error number to be used by the   */
/*                             calling routine.			*/
/*   EOPENDEV		       This number will be returned if  */
/*			       SCA-IF has returned EOPEN	*/
/*								*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   enter_app_in_sctlist()	Enter information about app in  */
/*				sct_list for current SCT.       */
/*   eject_sc()			Handle the ejection of the SC.  */
/*   sca_display()		Display text on SCT-display.    */
/*			         		       		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static
int 
analyse_sca_err(sct_id)
{

	int             ret_sca_errno;
	char           *ret_sca_errmsg;

	char           *proc = "analyse_sca_err";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	ret_sca_errno = sca_errno;
	ret_sca_errmsg = sca_errmsg;


	/*
	 * If SC has been ejected/removed or user break or no answer from
	 * user, the application is closed for the specified SCT
	 */

	if ((sca_errno == ENOCARD) || (sca_errno == ERESET) ||
	    (sca_errno == ESCTIMEOUT) ||
	    (sca_errno == ESCREMOVED) || (sca_errno == EUSERBREAK) ||
	    (sca_errno == EUSTIMEOUT)) {

		/* set application to CLOSE for the current SCT */
		if (enter_app_in_sctlist(sct_id, CNULL)) {
			aux_add_error(ESCTID, "set app_name to NULL in sct_list", CNULL, 0, proc);
		}
	}



	/*
	 *  If user presses the "Abbruch"-button, the SCT ejects the SC.
	 *     In this case the SCT configuration files will be deleted.
	 */

	if (sca_errno == EUSERBREAK) {
	        delete_old_SCT_config(sct_id);
	}



	/*
	 * Eject SC, if reset of the SC failed.
	 */

	if (sca_errno == ERESET) {
		eject_sc(sct_id, CNULL, FALSE);
		sca_display(sct_id, SCT_TEXT_RESET_SC_ERR, 0);
	}
	sca_errno = ret_sca_errno;
	sca_errmsg = ret_sca_errmsg;

	/* 
	 *  Handle open error on device
	 */

	if (sca_errno == EOPEN)
		return (EOPENDEV);

	return (ESC);


}				/* analyse_sca_err */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  open_sc_application				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Require SC, open SC application, perform device 		*/
/*  authentication. 						*/
/*								*/
/*     1. If no SC inserted, request new SC.			*/
/*     2. Open application, 					*/
/*	     - open it (select DF with name = app_name),	*/
/*           - perform device authentication,			*/
/*	       No user authentication is performed.		*/	
/*  	     - set application to OPEN for current SCT (enter 	*/
/*	       app_name into the "sct_stat_list[]".		*/
/*								*/
/*     								*/
/*     Observe that: 					        */
/*     If another application was open (that means, the  	*/
/*     specified app is not open), the new one will be opened.  */
/*     The old one will implicitly be closed.                   */
/*								*/
/*     If the function "check_sc_app()" fails and the errno	*/
/*     set by the SCA-IF is EOPEN (device is busy or unknown    */
/*     this function returns -1.				*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id	 	       SCT identifier			*/
/*   app_name	 	       application name			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_sc_info()		Get information about smartcard.*/
/*   sca_select_file()		Select file on the smartcard.   */
/*								*/
/*   check_sc_app()		Check whether application has   */
/*				been opened.                    */
/*   device_authentication()    Perform device authentication 	*/
/*				according to the add. file info */
/*				of the selected SC-application.	*/
/*   enter_app_in_sctlist()	Enter information about app in  */
/*				sct_list for current SCT.       */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   aux_free2_OctetString()	Release the octets-buffer in    */
/*			    	structure OctetString		*/
/*   request_sc()		Request and initialize a 	*/
/*				smartcard.			*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static 
int open_sc_application(sct_id, app_name)
	int             sct_id;
	char           *app_name;
{

	/* Variables for the SC-IF */
	OctetString     sc_info;	/* historical characters*/
	char           *display_text;
	Boolean         alarm;
	int             time_out;	/* time_out in seconds	*/
	FileCat         file_cat;
	char           *file_name;
	char            sel_control_par;
	FileInfoReq     file_info_req;
	FileInfo        file_info;	/* return parameter of
					 * sca_select_file, */
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */

	/* Variables for internal use */
	Boolean         SC_in_SCT;
	SCObjEntry     *sc_obj_entry;


	char           *proc = "open_sc_application";

	secsc_errno = NOERR;
	sca_rc = 0;
	SC_in_SCT = FALSE;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	fprintf(stderr, "                   Application-Name: %s\n", app_name);
#endif


	/*
	 *  Check: SC in SCT? 
	 */

	sca_rc = sca_get_sc_info(sct_id, &sc_info);
	if (sca_rc >= 0) {
		SC_in_SCT = TRUE;	/* SC is inserted */
		aux_free2_OctetString(&sc_info);
	} else if (sca_errno == ENOCARD)
		SC_in_SCT = FALSE;	/* no SC is inserted */
	else {
		secsc_errno = analyse_sca_err(sct_id);	/* error */
		aux_add_error(secsc_errno, "sca_get_sc_info", sca_errmsg, char_n, proc);
		return (-1);
	}


		
	/*
	 *  If no SC inserted, request new SC.
	 */

	if (SC_in_SCT == FALSE) {
		if (request_sc(sct_id, display_text = CNULL, time_out = SC_timer)) {
			aux_add_error(ESCREQUEST, "Request SC failed", CNULL, 0, proc);
			return (-1);
		}
	}



	/* 
	 *  Next to do:		     - open application, 
	 *                           - perform device authentication,
	 *			     - set application to OPEN for current SCT.
	 */



	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_select_file", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}
	/* select application on the SC */
	sca_rc = sca_select_file(sct_id,
				 file_cat = DF,
				 file_name = app_name,
				 sel_control_par = ' ',
				 file_info_req = SHORT_INFO,
				 &file_info,
				 &sm_SC	/* sec_mode for SCT/SC */
				);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_select_file", sca_errmsg, char_n, proc);
		return (-1);
	}


	/* perform the authentication according to the returned file_info */
	if (device_authentication(sct_id, app_name, &file_info.addinfo)) {
		aux_add_error(ESCAUTH, "Error during device authentication (addinfo)", CNULL, 0, proc);
		return (-1);
	}
	/* release file_info.addinfo.octets  */
	aux_free2_OctetString(&file_info.addinfo);


	/*
	 *   Intermediate result: The application on the SC is open
	 *
	 *            Next to do: set application to OPEN for the current SCT
	 */


	/* set application to OPEN for the current SCT, SW-PSE-PIN is set to CNULL */
	if (enter_app_in_sctlist(sct_id, app_name)) {
		aux_add_error(ESCTID, "set app_name into sct_list", CNULL, 0, proc);
		return (-1);
	}

	return (0);

}				/* end open_sc_application() */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_pse_pin_from_SC				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*  								*/
/*  Return the PIN for the SW-PSE.				*/							/*								*/
/*  It is assumed that the application on the SC has been 	*/
/*  opened.							*/
/*								*/
/*  If the PIN is already stored in the global list		*/
/*  "sct_stat_list[sc_sel.sct_id]", this value is returned.	*/
/*  Otherwise this function reads the PIN for the SW-PSE from	*/
/*  the smartcard, returns this PIN and sets it in 		*/
/*  "sct_stat_list[]"  for the current SCT.			*/
/*								*/
/*  The SW-PSE-PIN is an SC-object, which is determined by an 	*/
/*  entry in "sc_app_list[].sc_obj_list[]".			*/
/*								*/
/*  To read the SW-PSE-PIN from the SC a user authentication is */
/*  neccessary.							*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   app_name	 	       application name			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   Ptr to the PIN    	       o.k			       	*/
/*   CNULL		       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_read_data()		Read data from elementary file on   */
/*				the smartcard.      	        */
/*								*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   aux_cpy_String()		Copy string.			*/
/*   aux_free2_OctetString()	Release the octets-buffer in    */
/*			    	structure OctetString		*/
/*   enter_app_in_sctlist()	Enter information about app in  */
/*				sct_list for current SCT.       */
/*   get_sca_fileid()		Transform structure SCId into   */
/*				structure FileId (for a WEF on  */
/*				the SC).			*/
/*   get_sca_keyid()		Transform structure SCId into   */
/*				structure KeyId (for a key on   */
/*				the SC).			*/
/*   user_authentication()      Perform user authentication	*/
/*				(PIN).				*/
/*				application on the SC.	        */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   write_SCT_config()		Encrypt and write SCT configuration   */
/*				data for the specified SCT.	*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/


char		*
get_pse_pin_from_SC(app_name)
	char           *app_name;
{

	/* Variables for the SC-IF */
	int		sct_id;
	FileCat         file_cat;
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */
	FileId          file_id;
	DataSel         data_sel;
	int             data_length;
	OctetString     out_data;

	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;
	char            sw_pse_pin[PSE_PIN_L];


	char           *proc = "get_pse_pin_from_SC";

	secsc_errno = NOERR;
	sca_rc = 0;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	fprintf(stderr, "                   Application-Name: %s\n", app_name);
#endif

	sct_id = sc_sel.sct_id;


	/*
	 *  If the SW-PSE-PIN has already been read from the SC
	 *     return this value.
	 */

	if (strlen(sct_stat_list[sct_id].sw_pse_pin))	
		return (aux_cpy_String(sct_stat_list[sct_id].sw_pse_pin));



/*
 *   Intermediate result: The SW-PSE_PIN has not been read from the SC
 *
 *            Next to do: - Perform the user authentication, if not yet done.
 *			  - Read SW-PSE-PIN from SC.
 *			  - Set SW-PSE-PIN in the sct_stat_list for the curent SCT.
 */



	/*
	 *  Perform user authentication if not yet done.
	 */	

	if (user_authentication(sct_id, app_name, PIN)) {
		aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
		return (CNULL);
	}


	/*
	 *  Read SW-PSE_PIN from SC
	 */	

	/* get information about the object PSE_PIN */
	sc_obj_entry = aux_AppObjName2SCObj(app_name, PSE_PIN_name);
	if (sc_obj_entry == (SCObjEntry *) 0) {
		aux_add_error(ECONFIG, "get SC-Obj-info for PSE_PIN", CNULL, 0, proc);
		return (CNULL);
	}
	if (sc_obj_entry->type == SC_KEY_TYPE) {
		aux_add_error(ECONFIG, "PSE_PIN has to be a file on the SC", CNULL, 0, proc);
		return (CNULL);
	}
	/* set security mode for reading an SC-object */
	sm_SCT.command = SEC_NORMAL;
	sm_SCT.response = sc_obj_entry->sm_SCT;
	if (set_sec_mode(sct_id, &sm_SCT)) {
		aux_add_error(ESECMESS, "set security mode for reading obj", CNULL, 0, proc);
		return (CNULL);
	}
	/* read PIN from SC */
	get_sca_fileid(&sc_obj_entry->sc_id, &file_id);
	data_sel.data_struc = TRANSPARENT;
	data_sel.data_ref.string_sel = 0;
	data_length = PSE_PIN_L;
	sca_rc = sca_read_data(sct_id,
			       &file_id,
			       &data_sel,
			       data_length,
			       &out_data,
			       &sc_obj_entry->sm_SC_read);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_read_data (PSE_PIN)", sca_errmsg, char_n, proc);
		return (CNULL);
	}
	/* check PIN length */
	if (out_data.noctets != PSE_PIN_L) {
		aux_add_error(EPIN, "invalid PSE-PIN from SC", CNULL, 0, proc);
		return (CNULL);
	}
	for (i = 0; i < out_data.noctets; i++)
		sw_pse_pin[i] = out_data.octets[i];
	sw_pse_pin[i] = '\0';


	/* set the SW-PSE-PIN for the current SCT */
	if (sw_pse_pin)
		strcpy(sct_stat_list[sct_id].sw_pse_pin, sw_pse_pin);


	/*
	 *  Save the changed SCT configuration data
	 */

	if ((write_SCT_config(sct_id)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration!", CNULL, 0, proc);
		return (CNULL);
	}


#ifdef SECSCTEST
	fprintf(stderr, "PIN for SW-PSE: \n");
	aux_fxdump(stderr, sct_stat_list[sct_id].sw_pse_pin, strlen(sct_stat_list[sct_id].sw_pse_pin), 0);
	fprintf(stderr, "\n");
#endif

	return (aux_cpy_String(sct_stat_list[sct_id].sw_pse_pin));




}				/* end get_pse_pin_from_SC() */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  request_sc					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Request SC with function "sca_init_sc()".			*/
/*  If reset of the SC was not successful (sca_errno = ERESET),	*/
/*  the request for the SC is repeated two times.		*/
/*								*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id	       	       SCT identifier			*/
/*   display_text	       Text to be displayed on the SCT-	*/
/*			       display				*/
/*   time_out		       Time_out in seconds.		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0         	               ok			  	*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*								*/
/*   sca_init_sc()		Request and initialize a smartcard. */
/*   bell_function()		"Ring the bell" to require user */
/*                              input at the SCT.		*/
/*   display_on_SCT()		Display text on SCT-display.    */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/

static
int 
request_sc(sct_id, display_text, time_out)
	int             sct_id;
	char           *display_text;
	int             time_out;

{
	SecMess         sm_SC;	/* sec. mode for communication SCT/SC	 */

	int             req_attempts = 0;	/* no. of attempts to request
						 * SC	 */

	char           *proc = "request_sc";

	secsc_errno = NOERR;
	sca_rc = 0;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_init_sc", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}
	/* request SC  (if reset of the SC failed, repeat 2 times) */
	do {
		/* request new SC */
		bell_function();
		sca_rc = sca_init_sc(sct_id, display_text, time_out);

		req_attempts++;

		if (sca_rc < 0) {
			switch (sca_errno) {

			case ERESET:
				break;

			default:
				secsc_errno = analyse_sca_err(sct_id);
				aux_add_error(secsc_errno, "sca_init_sc", sca_errmsg, char_n, proc);
				return (-1);

			}	/* end switch */
		}
		 /* end if */ 
		else {
			/* request SC was successful => set SCT-display to blanks */
			display_on_SCT(sct_id, "");
			return (0);
		}

	}			/* end do */
	while (req_attempts < MAX_SCRESET_FAIL);

	/* after 3 unsuccessful attempts: request SC fails */
	secsc_errno = analyse_sca_err(sct_id);
	aux_add_error(secsc_errno, "sca_init_sc", sca_errmsg, char_n, proc);
	return (-1);

}				/* request_sc */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  display_on_SCT					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Display delivered string on specified SCT.			*/
/*								*/
/*  As the SCT does not use any timer for this function, no 	*/
/*  time-out is specified.					*/
/*								*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id	       	       SCT identifier			*/
/*   display_text	       Text to be displayed on the SCT-	*/
/*			       display				*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_display()		Display text on SCT-display.    */
/*								*/
/*                                                              */
/*--------------------------------------------------------------*/

static
void 
display_on_SCT(sct_id, display_text, alarm)
	int             sct_id;
	char           *display_text;
{



	char           *proc = "display_on_SCT";



#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif
	sca_display(sct_id, display_text, 0);


}				/* display_on_SCT */







/*--------------------------------------------------------------*/
/*						                */
/* PROC  eject_sc					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Eject SC and set application to CLOSE for the current SCT.  */
/*  The SCT configuration data file for the specified SCT is 	*/
/*  deleted.							*/
/*								*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id	       	       SCT identifier			*/
/*   display_text	       Text to be displayed on the SCT-	*/
/*			       display				*/
/*   alarm		       Switch for the acoustic alarm	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0         	               ok			  	*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_eject_sc()		Eject smartcard. 	        */
/*								*/
/*   bell_function()		"Ring the bell" .		*/
/*   delete_old_SCT_config()    Delete old SCT configuration    */
/*				file.				*/
/*   enter_app_in_sctlist()	Enter information about app in  */
/*				sct_list for current SCT.       */
/*   set_fct_sec_mode()		Set security mode for comm.     */
/*				between DTE/SCT depending on the*/
/*                	        SCA-function to be called.      */
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/

static
int 
eject_sc(sct_id, display_text, alarm)
	int             sct_id;
	char           *display_text;
	Boolean         alarm;
{

	/* Variables for the SCA-IF */
	SecMess         sm_SC;		/* sec. mode for communication SCT/SC	 */
	OctetString     sc_info;	/* historical characters 		 */


	char           *proc = "eject_sc";

	secsc_errno = NOERR;
	sca_rc = 0;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	/* set security mode for SCA-function */
	if (set_fct_sec_mode(sct_id, "sca_eject_sc", &sm_SC)) {
		aux_add_error(ESECMESS, "set_fct_sec_mode", CNULL, 0, proc);
		return (-1);
	}

	/* eject inserted SC */
	sca_rc = sca_eject_sc(sct_id, display_text, alarm);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_eject_sc", sca_errmsg, char_n, proc);
		if (secsc_errno != EOPENDEV) {
	      		enter_app_in_sctlist(sct_id, CNULL);
	        	delete_old_SCT_config(sct_id);
		}
		return (-1);
	}

	/* If eject SC was successful => ring the bell */
	bell_function();

	/* set application to CLOSE for the current SCT */
	if (enter_app_in_sctlist(sct_id, CNULL)) {
		aux_add_error(ESCTID, "set app_name to NULL in sct_list", CNULL, 0, proc);
		return (-1);
	}
			
	if (delete_old_SCT_config(sct_id)) {
		aux_add_error(ESCPROCDATA, "Cannot delete old SCT configuration file !", CNULL, 0, proc);
		return (-1);
	}

	return (0);
}				/* eject_sc */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  aux_FctName2FctPar				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Returns parameters belonging to the specified SCA-function. */
/*								*/
/*  - Global variable "sca_fct_list" contains a list of the 	*/
/*    SCA-functions and the belonging parameters.		*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   SCA_fct_name	       Name of the SCA-function		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   NULL         	       No entry for "SCA_fct_name" in  	*/
/*			       "sca_fct_list".			*/
/*   SCAFctPar *	       Pointer to the parameters of the */
/*			       specified SCA-function.	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
SCAFctPar      *
aux_FctName2FctPar(SCA_fct_name)
	char           *SCA_fct_name;
{
	register SCAFctPar *f = &sca_fct_list[0];
	char           *proc = "aux_FctName2FctPar";


	if (!SCA_fct_name)
		return ((SCAFctPar *) 0);

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	fprintf(stderr, "                   Funktions-Name: %s\n", SCA_fct_name);
#endif

	while (f->fct_name) {
		if (strcmp(SCA_fct_name, f->fct_name) == 0)
			return (f);
		f++;
	}
	return ((SCAFctPar *) 0);


}				/* end aux_FctName2FctPar */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  aux_AppObjName2SCObj				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Returns parameters belonging to the specified SC_object     */
/*  which belongs to the specified SC-application.		*/
/*								*/
/*  - Global variable "sc_app_list" contains a list of the 	*/
/*    applications available on the SC.				*/
/*    Part of "sc_app_list" is "sc_obj_list" which contains  	*/
/*    depending on the application a list of the objects (incl. */
/*    parameters), which shall be stored on the SC or which are */
/*    stored on the SC.						*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   app_name		       Name of the application 		*/
/*   obj_name		       Name of the object 		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   NULL         	       No entry for "app_name" in  	*/
/*			       "sc_app_list" or 		*/
/*              	       no entry for "obj_name" in  	*/
/*			       "sc_obj_list".			*/
/*   SCObjEntry *	       Pointer to the parameters of the */
/*			       specified SC-Object.	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
SCObjEntry * aux_AppObjName2SCObj(app_name, obj_name)
	char           *app_name;
	char           *obj_name;
{
	register SCAppEntry *a = &sc_app_list[0];
	SCObjEntry     *o;

	char           *proc = "aux_AppObjName2SCObj";


	if ((!app_name) || (!obj_name))
		return ((SCObjEntry *) 0);

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: aux_AppObjName2SCObj \n");
	fprintf(stderr, "                   Application-Name: %s\n", app_name);
	fprintf(stderr, "                   Object-Name: %s\n", obj_name);
#endif

	while (a->app_name) {
		if (strcmp(app_name, a->app_name) == 0) {
			/* get obj */
			o = &a->sc_obj_list[0];

			while (o->name) {
				if (strcmp(obj_name, o->name) == 0)
					return (o);
				o++;
			}
		}		/* end if */
		a++;
	}			/* end while */

	return ((SCObjEntry *) 0);

}				/* end aux_AppObjName2SCObj */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  aux_AppName2SCApp				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Returns parameters belonging to the specified 		*/
/*  SC_application, if the specified application is available   */
/*  on the SC.							*/
/*								*/
/*  - Global variable "sc_app_list" contains a list of the 	*/
/*    applications available on the SC.				*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   app_name		       Name of the application 		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   NULL         	       No entry for "app_name" in  	*/
/*			       "sc_app_list".			*/
/*   SCAppEntry *	       Pointer to the parameters of the */
/*			       specified SC-Application	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
SCAppEntry * aux_AppName2SCApp(app_name)
	char           *app_name;
{
	register SCAppEntry *a = &sc_app_list[0];
	char           *proc = "aux_AppName2SCApp";

	if (!app_name)
		return ((SCAppEntry *) 0);

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: aux_AppName2SCApp \n");
	fprintf(stderr, "                   Application-Name: %s\n", app_name);
#endif

	while (a->app_name) {
		if (strcmp(app_name, a->app_name) == 0)
			return (a);
		a++;
	}
	return ((SCAppEntry *) 0);

}				/* end aux_AppName2SCApp */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  enter_app_in_sctlist				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Enter the given application name into "sct_stat_list" for	*/
/*  the specified SCT. 						*/
/*  The values of "user_auth_done", "sw_pse_pin" and "sm_SCT" 	*/
/*  are set to initial values.					*/
/*								*/
/*  To delete an application from this list, the input parameter*/
/*  "app_name" must be set to CNULL.				*/
/*								*/
/*								*/
/*  - Global variable "sct_stat_list[sct_id]" contains 		*/
/*    current information for the SCT specified by sct_id.	*/
/*     								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   app_name		       Name of the application to be    */
/*			       set in "sct_stat_list". 		*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       ok				*/
/*   -1		               Error			      	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   write_SCT_config()		Encrypt and write SCT configuration data  */
/*				for the specified SCT.		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int 
enter_app_in_sctlist(sct_id, app_name)
	int             sct_id;
	char           *app_name;
{

	char           *proc = "enter_app_in_sctlist";


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	/* check the given sct_id */
	if ((sct_id >= MAX_SCTNO) || (sct_id <= 0)) {
		aux_add_error(ESCTID, "Invalid sct_id", CNULL, 0, proc);
		return (-1);
	}
	/* check the given app_name */
	if (app_name) {
		if (strlen(app_name) > MAXL_APPNAME) {
			aux_add_error(EAPPNAME, "app_name too long", CNULL, 0, proc);
			return (-1);
		}
	}


	/*
	 *  Set parameters to their initial values
	 */

	sct_stat_list[sct_id].user_auth_done = FALSE;
	strcpy(sct_stat_list[sct_id].sw_pse_pin, "");
	sct_stat_list[sct_id].sm_SCT.command  = SEC_NORMAL;
	sct_stat_list[sct_id].sm_SCT.response = SEC_NORMAL;


	if (app_name)
		strcpy(sct_stat_list[sct_id].app_name, app_name);
	else
		strcpy(sct_stat_list[sct_id].app_name, "");


	/*
	 *  Save the changed SCT configuration data
	 */

	if ((write_SCT_config(sct_id)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration data!", CNULL, 0, proc);
		return (-1);
	}



#ifdef SECSCTEST
	fprintf(stderr, "                   app_name: %s\n", &sct_stat_list[sct_id].app_name[0]);
#endif



	return (0);

}				/* end enter_app_in_sctlist */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  check_sc_app					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*  This function returns whether an application on the SC is 	*/
/*  open.							*/
/*								*/
/*  1. Check whether SC in SCT!					*/
/*     if no SC is inserted => return(-1)			*/
/*  2. Check whether application on the SC has been opened via  */
/*     the specified SCT. 					*/
/*     If "app_name" is set to NULL, this function checks,      */
/*        whether any application has been opened.		*/
/*     If "app_name" is not set to NULL, this function checks 	*/
/*        whether this application has been opened.		*/
/*								*/
/*  An application is open, if its name has been set in the 	*/
/*  "sct_stat_list" for this SCT. 				*/
/*								*/
/*  - Global variable "sct_stat_list[sct_id]" contains 		*/
/*    current application name.					*/
/*     								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   app_name		       Name of the application or NULL 	*/
/*			       for any application.		*/
/*								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       Application has been opened	*/
/*   -1		               Application has not been opened	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_sc_info()		Get information about smartcard.*/
/*--------------------------------------------------------------*/

static
int 
check_sc_app(sct_id, app_name)
	int             sct_id;
	char           *app_name;
{

	/* Variables for the SCA-IF */
	OctetString     sc_info;		/* historical characters 		 */

	char           *proc = "check_sc_app";

	sca_rc = 0;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	if (app_name)
		fprintf(stderr, "                   Application name: %s\n", app_name);
	else
		fprintf(stderr, "                   no app_name specified:\n");
#endif

	/* check: SC in SCT? */
	sca_rc = sca_get_sc_info(sct_id, &sc_info);
	if (sca_rc < 0) {
		/* SC is not inserted => no app open */
		return (-1);
	}
	aux_free2_OctetString(&sc_info);



	/* check the current sct_id */
	if ((sct_id >= MAX_SCTNO) || (sct_id <= 0)) {
		aux_add_error(ESCTID, "Invalid sct_id", CNULL, 0, proc);
		return (-1);
	}
	/* If no application name is set, no application is open */
	if ((!sct_stat_list[sct_id].app_name) ||
	    (!(strlen(sct_stat_list[sct_id].app_name)))) {
		return (-1);
	}


/*
 *   Intermediate result: An application is open for the current SCT:
 *			  - an application name is set
 *
 *            Next to do: If app_name  = NULL => any application is open => return(0).
 *			  If app_name != NULL => compare this name with
 *						 the name in the sct_stat_list.
 */


	if (!app_name) {
		return (0);
	}
	else {
		if (strcmp(app_name, sct_stat_list[sct_id].app_name) == 0)
			return (0);
		else
			return (-1);
	}

}				/* end check_sc_app */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  handle_sc_app					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  1. Handle application:					*/
/*     Check whether application (app_name) on the SC 		*/
/*     has been opened via the specified SCT. 			*/
/*     If application has not been opened, this function calls  */
/*     function "open_sc_application" to open the application  	*/
/*     on the SC.						*/
/*     								*/
/*     Observe that: 					        */
/*     If another application was open (that means, the  	*/
/*     specified app is not open), the new one will be opened.  */
/*     The old one will implicitly be closed.                   */
/*								*/
/*     If the function "check_sc_app()" fails and the errno	*/
/*     set by the SCA-IF is EOPEN (device is busy or unknown)   */
/*     this function returns -1.				*/
/*     								*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   pse_sel		       Structure which identifies the 	*/
/*			       PSE object.			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       Application has been opened	*/
/*   -1		               Application could not been 	*/
/*			       opened.				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   check_sc_app()		Check whether application has   */
/*				been opened.                    */
/*   open_sc_application() 	Require SC, open SC application,*/
/*				perform device authenticationn. */
/*--------------------------------------------------------------*/


int 
handle_sc_app(sct_id, app_name)
	int             sct_id;
	char           *app_name;
{

	SCObjEntry     *sc_obj_entry;

	char           *proc = "handle_sc_app";
	secsc_errno = NOERR;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	if (app_name)
		fprintf(stderr, "                   Application name: %s\n", app_name);
	else
		fprintf(stderr, "                   no app_name specified:\n");
#endif


	/* has the application been opened? */
	if (check_sc_app(sct_id, app_name)) {

		secsc_errno = analyse_sca_err(sct_id);
		if (secsc_errno == EOPENDEV) {
			aux_add_error(secsc_errno, "Cannot open application", sca_errmsg, char_n, proc);
			return (-1);
		}

		/* application not open => open it */

		if (open_sc_application(sct_id, app_name)) {
			aux_add_error(EAPP, "Cannot open application", CNULL, 0, proc);
			return (-1);
		}
	}

	return (0);

}				/* end handle_sc_app */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  handle_key_sc_app				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Handle SC application for specified key, if key is a key   */
/*   on the SC.							*/
/*      If key shall be installed on the  SC,			*/
/*         => Case 1: Selection of key with object name:	*/
/*                    Assumption: the belonging application has */
/*		      been opened by the calling routine.	*/
/*         => Case 2: Selection of key with key reference:	*/
/*		      Check whether any application is 		*/
/*		      open. If not, return(error).		*/
/*         => Case 3: return(error).				*/
/*								*/
/*  If a key on the SC shall be accessed, the user 		*/
/*  authentication is performed.				*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   key		       Structure which identifies the   */
/*			       key.				*/
/*   key_id		       key identifier used at the SCA-IF*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			        ok				*/
/*   -1		                error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   check_sc_app()		Check whether application has   */
/*				been opened.                    */
/*   user_authentication()      Perform user authentication	*/
/*				(PIN).				*/
/*			         		       		*/
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int 
handle_key_sc_app(sct_id, key, key_id)
	int             sct_id;
	Key            *key;
	KeyId           key_id;
{


	char           *proc = "handle_key_sc_app";


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	if ((key->keyref == 0) && (key->pse_sel != (PSESel * ) 0)) {

		/*
		 * Select key with object name,
		 *  the belonging application has been opened in the calling routine
		 */

	} else {
		if (key->keyref != 0) {

			/*
			 * Select key with keyref
			 */

			if ((key_id.key_level == SC_MF) ||
			    (key_id.key_level == SC_DF) ||
			    (key_id.key_level == SC_SF)) {
				if (check_sc_app(sct_id, CNULL)) {
					aux_add_error(EAPP, "No application open!", CNULL, 0, proc);
					return (-1);
				}
			}
		} else {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			return (-1);
		}		/* end else */

	}			/* end else */



	/*
	 *  If a key on the SC shall be accessed, the user authentication is required.
	 */	

	if ((key_id.key_level == SC_MF) ||
	    (key_id.key_level == SC_DF) ||
	    (key_id.key_level == SC_SF)) {

		if ((key->pse_sel != (PSESel * ) 0) &&
		    (key->pse_sel->app_name)) {
			if (user_authentication(sct_id, key->pse_sel->app_name, PIN)) {
				aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
				return (-1);
			}
		}
		else {
			/*
			 * key selected with keyref
			 */

			if (user_authentication(sct_id, sct_stat_list[sct_id].app_name, PIN)) {
				aux_add_error(ESCAUTH, "PIN authentication not successful.", CNULL, 0, proc);
				return (-1);
			}

		}

	}
		

	return (0);

}				/* end handle_key_sc_app */



/*--------------------------------------------------------------*/
/*						                */
/* PROC  SC_configuration				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read the SC configuration file, if not yet done.	        */
/*  This function returns whether an SC configuration file      */
/*  could be successfully read (TRUE | FALSE).			*/ 
/*								*/
/*								*/
/*  First this function tries to read an SC configuration file  */
/*  stored under the home directory of the user.		*/
/*  If no configuration file exists under this directory, this  */
/*  function tries to read one under a system directory.	*/
/*								*/
/*  If no configuration file could be found, FALSE is returned. */
/*  In this case the global list "sc_app_list[]" is left 	*/
/*  unchanged.							*/
/*								*/
/*								*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE		       SC is available and 		*/
/*			       configuration was successful.	*/
/*   FALSE		       No SC configuration file found   */
/*			       => SC not available.		*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   display_SC_configuration() Display the actual SC           */
/*				configuration ("sc_app_list[]").*/
/*   read_SC_configuration()   read SC-configuration file	*/
/*                                                              */
/*--------------------------------------------------------------*/

int 
SC_configuration()
{
	static Boolean  config_done = FALSE;
	static	int	SC_available = FALSE;

	int             rc;

	char           *proc = "SC_configuration";


	if (config_done == FALSE) {

		rc = read_SC_configuration(USER_CONF);
		if (rc < 0) {
			aux_add_error(ECONFIG, "Error in read SC configuration file (user)", CNULL, 0, proc);
			return (-1);
		}
		if ((rc == 0) && (sc_app_list[0].app_name == CNULL)) {

			/*
			 * There is no SC configuration file under the user directory 
	                 *   => take SC configuration file under the system dirctory
			 */

			rc = read_SC_configuration(SYSTEM_CONF);
			if (rc < 0) {
				aux_add_error(ECONFIG, "Error in read SC configuration file (system)", CNULL, 0, proc);
				return (-1);
			}
		       if ((rc == 0) && (sc_app_list[0].app_name != CNULL)) 
			 	SC_available = TRUE;

		}
		else
		       SC_available = TRUE;
			

#ifdef SECSCTEST
		if (sc_app_list[0].app_name == CNULL) 
			fprintf(stderr, "\nNo SC configuration file found => no smartcard available\n\n");
		else 
			display_SC_configuration();
#endif

		config_done = TRUE;

	}  /* end if (config_done == FALSE) */

	return (SC_available);


}  			/* end SC_configuration */






/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  get_connected_SCT				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Get the first SCT (sct_id) of the SCTs registered in file   */
/*  "ustamod.gen", which is actually connected to the DTE.	*/
/*  								*/
/*  An SCT is connected, if the function "sca_display" for this */
/*  SCT is successful.						*/
/*							        */
/*  If  - "ustamod.gen doesn't exist,				*/
/*      - no SCTs are registered,				*/
/*      - no SCT is connected to the DTE,			*/
/*  => return(-1)						*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   sct_id (>0)	       Id. of the connected SCT.	*/
/*   -1		               No SCT connected.		*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_display()		Display text on SCT-display.    */
/*   sca_get_sct_info()		Get information about  		*/
/*				registered SCTs.		*/
/*--------------------------------------------------------------*/


int 
get_connected_SCT()
{


	int             no_of_SCTs;
	int             count_SCTs;

	char           *proc = "get_connected_SCT";

	secsc_errno = NOERR;
	sca_rc = 0;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	/* get number of registered SCTs */

	no_of_SCTs = sca_get_sct_info();

	if (no_of_SCTs < 1)
		return (-1);


	/* check registered SCTs */

	for (count_SCTs = 1; count_SCTs <= no_of_SCTs; count_SCTs++) {

		sca_rc = sca_display(count_SCTs, SCT_TEXT_SCT_CHECK, 3);

		if (sca_rc >= 0) {

			/* SCT is connected */
			return (count_SCTs);
		}
	}

	return (-1);

}				/* end get_connected_SCT */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  is_SCT_connected				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check whether the specified SCT is connected.		*/
/*  								*/
/*								*/
/*  TRUE will be returned, if					*/
/*       the function "sca_display" for this SCT was successful.*/
/*								*/
/*  FALSE will be returned, if					*/
/*	- the file specified by the global variable STAMOD      */
/*        doesn't exist,					*/
/*      - no SCTs are registered,				*/
/*	- the specified sct_id is greater than the no. of 	*/
/*        registered SCTs.					*/
/*     								*/
/*  -1 will be returned, if 					*/
/*      "sca_display()" was not successful and the error number */
/*      of the SCA-IF (sca_errno) is set to EOPEN. This means   */
/*      that the device for the SCT could not be opened (e.g.   */
/*      device unknown or device busy).				*/
/*     								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE	               The specified SCT is available.	*/
/*   FALSE		       No access possible to the 	*/
/*			       specified SCT.			*/
/*   -1		               Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_display()		Display text on SCT-display.    */
/*   sca_get_sct_info()		Get information about  		*/
/*				registered SCTs.		*/
/*--------------------------------------------------------------*/

static
int is_SCT_connected(sct_id)
unsigned int sct_id;
{


	static int             no_of_SCTs;
	static Boolean         first_call = TRUE;

	char           *proc = "is_SCT_connected";

	secsc_errno = NOERR;
	sca_rc = 0;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	if (first_call == TRUE) {

		/* get number of registered SCTs */
		no_of_SCTs = sca_get_sct_info();

		first_call = FALSE;
	}

	if (no_of_SCTs < 1) {
#ifdef SECSCTEST
		fprintf(stderr, "No SCT registered\n");
#endif
		return (FALSE);
	}

	if (no_of_SCTs < sct_id) {
#ifdef SECSCTEST
		fprintf(stderr, "Specified SCT (SCT_id: %d) is not registered\n", sct_id);
#endif
		return (FALSE);
	}


	/* check specified SCT (try to display text on SCT-display) */

	sca_rc = sca_display(sct_id, SCT_TEXT_SCT_CHECK, 3);

	if (sca_rc >= 0) {

		/* SCT is connected */
		return (TRUE);
	}
	else {
		/* SCT is not available */
		if (sca_errno == EOPEN) {
			aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
			return (-1);
		}
	}

	return (FALSE);

}				/* end is_SCT_connected */




/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  SCT_configuration				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Perform the configuration for the specified SCT.		*/
/*								*/
/*								*/
/*  1) Check value of sct_id.					*/
/*								*/
/*  2) If the configuration for the specified SCT has not been 	*/
/*     done:							*/
/*  	       => 1. Get process key			        */
/*                2. If a process key could be generated:	*/
/*	             =>  The data for the specified SCT are 	*/
/*	                 read, decrypted and set into 		*/
/*	      	         "sct_stat_list[sct_id]".		*/
/*			 If no configuration file for the    	*/
/*	      		 specified SCT exists, the values in 	*/
/*	      		 "sct_stat_list[sct_id]" are left 	*/
/*			 unchanged.				*/
/*								*/
/*     		  3. Check whether SCT is available.		*/
/*								*/
/*  3) Return whether SCT is available (TRUE | FALSE)		*/ 
/*  								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the configuration shall be done. */
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE		       SCT is available and 		*/
/*			       configuration was successful.	*/
/*   FALSE		       SCT is not available. 		*/
/*   -1		               error during SCT configuration	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_process_key()		Get process key for encryption/ */
/*				decryption of SCT config.	*/
/*   is_SCT_connected()		Check whether selected SCT is   */
/*				available.                      */
/*   read_SCT_config()		Read and decrypt SCT configuration    */
/*				data for the specified SCT.	*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

int 
SCT_configuration(sct_id)
	int             sct_id;
{


	char		*process_key;
	int		SCT_available;

	char            *proc = "SCT_configuration";

	secsc_errno = NOERR;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	if (sct_stat_list[sct_id].config_done == FALSE)
		fprintf(stderr, "                config_done = FALSE\n");
	else	fprintf(stderr, "                config_done = TRUE\n");
	if (sct_stat_list[sct_id].available == FALSE)
		fprintf(stderr, "                available = FALSE\n");
	else	fprintf(stderr, "                available = TRUE\n");

#endif


	/* check the specified sct_id */
	if ((sct_id >= MAX_SCTNO) || (sct_id <= 0)) {
		aux_add_error(ESCTID, "Invalid sct_id", CNULL, 0, proc);
		return (-1);
	}

	if (sct_stat_list[sct_id].config_done == FALSE)  {
	
		/*
		 *  Configuration for the specified SCT has not been done.
	 	 *
	         *  => 1. Get key for the decryption of the SCT
		 *        configuration data.
		 *     2. Read and decrypt SCT configuration data
	         */

		process_key = get_process_key();
		if (process_key != CNULL) {

			/* There is a key => read and decrypt SCT config data */
			if (read_SCT_config (sct_id, process_key)) {
				aux_add_error(ESCPROCDATA, "Cannot read SCT configuration! ", CNULL, char_n, proc);
				free(process_key);
				return (-1);
			}
			free(process_key);    
		}
		else {
			aux_add_error(ESCPROCKEY, "Cannot generate process key !", CNULL, 0, proc);
			return (-1);
		}


		/*
		 *  Check whether SCT is available, is done for each process
		 */

		if ((SCT_available = is_SCT_connected(sct_id)) == -1) {
			if (aux_last_error() == EOPENDEV) 
				aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
			else
				aux_add_error(ESCTID, "Error during check whether SCT is connected!", CNULL, 0, proc);
			sct_stat_list[sct_id].available = FALSE;
			sct_stat_list[sct_id].config_done = FALSE;
			return (-1);
		}
		sct_stat_list[sct_id].available = SCT_available;

		sct_stat_list[sct_id].config_done = TRUE;

	} /* end SCT configuration not yet done */


#ifdef SECSCTEST
		if (sct_stat_list[sct_id].available == TRUE)
			fprintf(stderr, "SCT with sct_id = %d is available\n", sct_id);
		else    fprintf(stderr, "SCT with sct_id = %d is not available\n", sct_id);
#endif

	return(sct_stat_list[sct_id].available);

}				/* end SCT_configuration */



/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  get_process_key				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Compose process key and return pointer to the process key. 	*/
/*							        */
/*  The allocated storage has to be released by the calling 	*/
/*  routine.							*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*							        */
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   CNULL		       error				*/
/*   != CNULL		       pointer to process key	 	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
char *get_process_key()
{

	static char		*process_key = CNULL;

	char           *proc = "get_process_key";


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	if (!process_key) {

		if (!(process_key = (char *) malloc(MAX_LEN_PROC_KEY))) {
			aux_add_error(EMALLOC, "process key", CNULL, 0, proc);
			return (CNULL);
		}

		strcpy(process_key, get_unixname());
		sprintf(process_key + strlen(process_key), "%d", 3 * getuid() - 100);
		strcat(process_key, ".&%)#(#$");

	}

	return (aux_cpy_String(process_key));

}				/* end get_process_key */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  read_SCT_config				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Case 1:  SCT configuration file exists:			*/
/*   This file is read and decrypted, the values are checked:   */
/*      If the values are correct, the resulting data are 	*/
/*         stored in the global list: "sct_stat_list[sct_id]".	*/
/*	If the values are not correct, the SCT configuration 	*/
/*         file is deleted and the values in 			*/
/*         "sct_stat_list[sct_id]" are left unchanged.		*/
/*								*/
/*   Case 2:  SCT configuration file does not exist:		*/				
/*   The values in "sct_stat_list[sct_id]" are left unchanged.	*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the configuration shall be done. */
/*   process_key	       Decryption key for the process   */
/*			       data file.			*/
/*							        */
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       ok			 	*/
/*   -1			       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_AppName2SCApp()	Get information about an SC app.*/
/*   delete_old_SCT_config()    Delete old SCT configuration    */
/*				file.				*/
/*   get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int read_SCT_config(sct_id, process_key)
int	sct_id;
char	*process_key;
{

	char           *config_file_name = "";
	int            fd_SCT_config;
	SCTStatus      sct_entry;

	char           *proc = "read_SCT_config";

	secsc_errno = NOERR;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

/********************************************************************************/
/*
 *      Get name of SCT configuration file:
 */

	config_file_name = get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT Configuration file!", CNULL, 0, proc);
		return (-1);
	}


/********************************************************************************/
/*
 *	Open SCT configuration file
 */

	if ((fd_SCT_config = open(config_file_name, O_RDONLY)) < 0) {
#ifdef SECSCTEST
		fprintf(stderr, "SCT Configuration file %s missing, default values are used.\n", config_file_name);
#endif
		free(config_file_name);
		return (0);
	}

/********************************************************************************/
/*
 *	Read and decrypt SCT configuration file 
 */

	if (secsc_errno = read_dec(fd_SCT_config, &sct_entry, sizeof(SCTStatus), process_key) <= 0) {
#ifdef SECSCTEST
		fprintf(stderr, "SCT configuration file %s invalid, is deleted!\n", config_file_name);
#endif
	        close_dec(fd_SCT_config);
	        delete_old_SCT_config(sct_id);
		free(config_file_name);
		return (0);
	}
	close_dec(fd_SCT_config);


/********************************************************************************/
/*
 *	Check read values:
 *		If values are correct, the read information are stored into sct status list.
 *              Otherwise the read file is deleted.
 */

	if ((sct_entry.user_auth_done != TRUE) &&
	    (sct_entry.user_auth_done != FALSE))
		secsc_errno = ESCPROCDATA;
	else if ((sct_entry.sm_SCT.command != SEC_NORMAL) &&
	         (sct_entry.sm_SCT.command != AUTHENTIC) &&
	         (sct_entry.sm_SCT.command != CONCEALED) &&
	         (sct_entry.sm_SCT.command != COMBINED)) 
			secsc_errno = ESCPROCDATA;
	     else if ((sct_entry.sm_SCT.response != SEC_NORMAL) &&
	              (sct_entry.sm_SCT.response != AUTHENTIC) &&
	              (sct_entry.sm_SCT.response != CONCEALED) &&
	              (sct_entry.sm_SCT.response != COMBINED)) 
			secsc_errno = ESCPROCDATA;
	          else  if ((sct_entry.config_done != TRUE) &&
	                    (sct_entry.config_done != FALSE))
				secsc_errno = ESCPROCDATA;
	   		else if ((sct_entry.available != TRUE) &&
	              	         (sct_entry.available != FALSE)) 
					secsc_errno = ESCPROCDATA;
			else {
				sct_entry.app_name[MAXL_APPNAME] = '\0';
				sct_entry.sw_pse_pin[PSE_PIN_L] = '\0';
			}


	if (secsc_errno == NOERR) {

		sct_stat_list[sct_id].user_auth_done  = sct_entry.user_auth_done;
		sct_stat_list[sct_id].available       = sct_entry.available;
		sct_stat_list[sct_id].sm_SCT.command  = sct_entry.sm_SCT.command;
		sct_stat_list[sct_id].sm_SCT.response = sct_entry.sm_SCT.response;
		strcpy (sct_stat_list[sct_id].app_name,sct_entry.app_name);
		strcpy (sct_stat_list[sct_id].sw_pse_pin, sct_entry.sw_pse_pin);
		sct_stat_list[sct_id].config_done     = sct_entry.config_done;
		sct_stat_list[sct_id].available       = sct_entry.available;

#ifdef SECSCTEST
		fprintf(stderr, "Read SCT configuration file for SCT: %d\n", sct_id);

		if (fd_SCT_config >= 0) {
			if (sct_stat_list[sct_id].sm_SCT.command == SEC_NORMAL) 
				fprintf(stderr, "command == SEC_NORMAL\n");
			if (sct_stat_list[sct_id].sm_SCT.command == AUTHENTIC) 
				fprintf(stderr, "command == AUTHENTIC\n");
			if (sct_stat_list[sct_id].sm_SCT.command == CONCEALED) 
				fprintf(stderr, "command == CONCEALED\n");
			if (sct_stat_list[sct_id].sm_SCT.command == COMBINED) 
				fprintf(stderr, "command == COMBINED\n");
			if (sct_stat_list[sct_id].sm_SCT.response == SEC_NORMAL) 
				fprintf(stderr, "response == SEC_NORMAL\n");
			if (sct_stat_list[sct_id].sm_SCT.response == AUTHENTIC) 
				fprintf(stderr, "response == AUTHENTIC\n");
			if (sct_stat_list[sct_id].sm_SCT.response == CONCEALED) 
				fprintf(stderr, "response == CONCEALED\n");
			if (sct_stat_list[sct_id].sm_SCT.response == COMBINED) 
				fprintf(stderr, "response == COMBINED\n");
			fprintf(stderr, "app_name:   %s\n", sct_stat_list[sct_id].app_name);
			fprintf(stderr, "sw_pse_pin: %s\n", sct_stat_list[sct_id].sw_pse_pin);
			if (sct_stat_list[sct_id].user_auth_done == TRUE) 
				fprintf(stderr, "auth_done == TRUE\n");
			else	fprintf(stderr, "auth_done == FALSE\n");
			if (sct_stat_list[sct_id].config_done == TRUE) 
				fprintf(stderr, "config_done == TRUE\n");
			else	fprintf(stderr, "config_done == FALSE\n");
			if (sct_stat_list[sct_id].available == TRUE) 
				fprintf(stderr, "available == TRUE\n");
			else	fprintf(stderr, "available == FALSE\n");
		}
#endif

	}	
	else {
		aux_add_error(ESCPROCDATA, "SCT configuration file invalid, is deleted!", config_file_name, char_n, proc);
	        delete_old_SCT_config(sct_id);
		free(config_file_name);
		return (0);
	}

	free(config_file_name);
	return(0);

}				/* end read_SCT_config */


/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  write_SCT_config				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Encrypt and write the SCT configuration data for the 	*/
/*  specified SCT into a file.					*/
/*								*/
/*  Get key from the environment variable "SC_PROCESS_KEY"	*/
/*								*/
/*  Case 1: A process key is set:				*/
/*	    => The data for the specified SCT 			*/
/*	       ("sct_stat_list[sct_id]") are encrypted with     */
/*	       the process key and written into a file.		*/
/*  Case 2: No process key is set:				*/
/*	    =>  return(ok).					*/
/*  								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the SCT configuration data shall */
/*			       be written.			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       ok				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*   get_process_key()		Get process key for encryption/ */
/*				decryption of SCT config.	*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static
int	write_SCT_config(sct_id)
	int             sct_id;
{


	char	       *process_key;
	char           *config_file_name = "";
	int            fd_SCT_config;
	SCTStatus      sct_entry;

	char           *proc = "write_SCT_config";

	secsc_errno = NOERR;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif




/********************************************************************************/
/*
 *      Get encryption key for the SCT configuration data
 */

	process_key = get_process_key();

	if (process_key == CNULL) {
		/* No key available => error */
		aux_add_error(ESCPROCKEY, "No process key available!", CNULL, 0, proc);
		return (0);
	}

#ifdef SECSCTEST
	fprintf(stderr, "process key from get_process_key: %s\n", process_key);
#endif


/********************************************************************************/
/*
 *      Get name of SCT configuration file:
 */

	config_file_name = get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT configuration file!", CNULL, 0, proc);
		free(process_key);    
		return (0);
	}



/********************************************************************************/
/*
 *	Open SCT configuration file
 */

	if ((fd_SCT_config = open(config_file_name, O_WRONLY | O_CREAT, FILEMASK)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot open SCT configuration file!", config_file_name, char_n, proc);
		free(process_key);    
		free(config_file_name);
		return (0);
	}

	chmod(config_file_name, FILEMASK);
	free(config_file_name);
			


/********************************************************************************/
/*
 *	Encrypt and write SCT configuration data
 */

	sct_entry.user_auth_done  = sct_stat_list[sct_id].user_auth_done;
	sct_entry.sm_SCT.command  = sct_stat_list[sct_id].sm_SCT.command;
	sct_entry.sm_SCT.response = sct_stat_list[sct_id].sm_SCT.response;
	strcpy (sct_entry.app_name,sct_stat_list[sct_id].app_name);
	strcpy (sct_entry.sw_pse_pin, sct_stat_list[sct_id].sw_pse_pin);
	sct_entry.config_done     = sct_stat_list[sct_id].config_done;
	sct_entry.available     = sct_stat_list[sct_id].available;



	if ((write_enc(fd_SCT_config, &sct_entry, sizeof(SCTStatus), process_key)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration file! ", CNULL, char_n, proc);
		close_enc(fd_SCT_config);
		free(process_key);
		return (0);
	}

	close_enc(fd_SCT_config);
	free(process_key);    


	return(0);

}				/* end write_SCT_config */




/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  delete_old_SCT_config				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Delete old SCT specific configuration files. Both the file 	*/
/*  which is produced by the SECSC-IF and the SCA-IF are 	*/
/*  deleted.							*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the configuration file shall be   */
/*			       deleted.				*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       ok (file deleted or file does 	*/
/*			           not exist)			*/ 
/*   -1		               error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*   sca_get_SCT_config_fname()	Get name of (SCA) SCT 	        */
/*				configuration file.		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static
int	delete_old_SCT_config(sct_id)
int	sct_id;
{


	char           *config_file_name = "";
	char           *sca_config_file_name = "";
	char           *proc = "delete_old_SCT_config";

	secsc_errno = NOERR;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif




/********************************************************************************/
/*
 *      Get name of SCT configuration files:
 */

	config_file_name = get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT configuration file!", CNULL, 0, proc);
		return (-1);
	}

#ifdef PROCDAT

	sca_config_file_name = sca_get_SCT_config_fname (sct_id);

	if (sca_config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCA SCT configuration file!", CNULL, 0, proc);
		return (-1);
	}

#endif	/* PROCDAT */

/********************************************************************************/
/*
 *	Delete old SCT configuration files
 */


	if (unlink(config_file_name)) {
		if (errno != ENOENT) {
			aux_add_error(ESCPROCDATA, "Cannot delete SCT configuration file!", config_file_name, char_n, proc);
			free(config_file_name);
			return (-1);
		}
	}

	free(config_file_name);
			
#ifdef PROCDAT

	if (unlink(sca_config_file_name)) {
		if (errno != ENOENT) {
			aux_add_error(ESCPROCDATA, "Cannot delete SCA SCT configuration file!", config_file_name, char_n, proc);
			free(sca_config_file_name);
			return (-1);
		}
	}

	free(sca_config_file_name);
#endif	/* PROCDAT */
			
	return(0);

}				/* end delete_old_SCT_config */



/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  gen_process_key				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Generate random string and set this string into the 	*/
/*  environment variable "SC_PROCESS_KEY". 		 	*/
/*							        */
/*							        */
/* IN			     DESCRIPTION		       	*/
/*							        */
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0		       	       ok				*/
/*   -1		               error			 	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sec_random_str()	       Generate random character string.*/
/*   strzfree()		       Free string.   		    	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int gen_process_key()
{

	char		*setenv_cdo;
	char		*process_key;
	int		nchar;

	char           *proc = "gen_process_key";


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	if (!(process_key = sec_random_str(PROCESS_KEY_LEN, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))) {
		aux_add_error(ESCPROCKEY, "Cannot generate process key!", CNULL, 0, proc);
		return (-1);
	}

	nchar = strlen(process_key) + strlen(SC_PROCESS_KEY) + 16;

	if (!(setenv_cdo = (char *) malloc(nchar))) {
		aux_add_error(EMALLOC, "setenv command", CNULL, 0, proc);
		return (-1);
	}
	
	strcpy(setenv_cdo, SC_PROCESS_KEY);
	strcat(setenv_cdo, "=");
	strcat(setenv_cdo, process_key);

#ifdef SECSCTEST
	fprintf(stderr, "setenv command: %s\n", setenv_cdo);
#endif

	if (putenv(setenv_cdo)) {
		aux_add_error(ESYSTEM, "putenv command", setenv_cdo, char_n, proc);
		return (-1);
	} 


	free (process_key);

/*	free(setenv_cdo);	This command would unset the environment variable */

	return(0);	


}				/* end gen_process_key */



/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  get_SCT_config_fname				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Compose and return name of configuration file for the 	*/
/*  specified SCT: 						*/
/*								*/
/*  Structure:							*/
/*  Home directory || SCT_CONFIG_name || sct_id			*/
/*							        */
/*							        */
/*  The calling routine has to release the allocated memory.	*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT.		*/
/*							        */
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   <> CNULL		       ptr to name of file		*/
/*   CNULL		       error			 	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_SCT_config_fname()	Get name of SCT configuration   */
/*				file.			        */
/*   int2ascii()		Transform an integer value into */
/*			        a NULL terminated ASCII         */
/*				character string.	        */
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
char	*get_SCT_config_fname(sct_id)
int	sct_id;


{
	char           *homedir = "";
	static char    *config_file_name = "";
	char           *sca_config_file_name = "";
	static int     old_sctid = 0;
	char	       sct_id_ascii[MAXSCTID_LEN];

	char           *proc = "get_SCT_config_fname";

	secsc_errno = NOERR;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	if ((old_sctid != sct_id) || 
	    (!(config_file_name)) || (strlen(config_file_name) == 0)) {

		if ((config_file_name) && (strlen(config_file_name) != 0)) 
			free(config_file_name);

	    /*
	     *  Compose configuration file name 
	     */

		homedir = getenv("HOME");
		if (!homedir) {
			aux_add_error(ESYSTEM, "Getenv failed for variable HOME.", CNULL, 0, proc);
			return (CNULL);
		}
		config_file_name = (char *) malloc(strlen(homedir) + strlen(SCT_CONFIG_name) + 16);
		if (!config_file_name) {
			aux_add_error(EMALLOC, "SCT configuration file", CNULL, 0, proc);
			return (CNULL);
		}
		strcpy(config_file_name, homedir);
		if (strlen(homedir))
			if (config_file_name[strlen(config_file_name) - 1] != '/')
				strcat(config_file_name, "/");
		strcat(config_file_name, SCT_CONFIG_name);


		if (int2ascii(&sct_id_ascii[0], sct_id)) {
			aux_add_error(ESYSTEM, "Cannot get ASCII representation of sct_id", CNULL, 0, proc);
			free(config_file_name);
			return (CNULL);
		}
		strcat(config_file_name, sct_id_ascii);

	
#ifdef PROCDAT

		/* 
		 * To make sure that the home-directories of 
		 *   the two SCT configuration files are equal
		 */

		sca_config_file_name = sca_get_SCT_config_fname (sct_id);
		free (sca_config_file_name);

#endif	/* PROCDAT */


		old_sctid = sct_id;
	}


#ifdef SECSCTEST
	fprintf(stderr, "Name of SCT configuration file: %s\n", config_file_name);
#endif

	return(aux_cpy_String(config_file_name));

}			/* get_SCT_config_fname */


/*--------------------------------------------------------------*/
/*						                */
/* PROC  set_sec_mode					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Sets the security mode for the communication between DTE   	*/
/*  and the specified SCT to the required value.		*/
/*								*/
/*  - Global variable "sct_stat_list[sc_sel.sct_id]" contains */
/*    current security mode for the SCT specified by     	*/
/*    sc_sel.sct_id						*/
/*     								*/
/*  If the current security mode is unequal to the required 	*/
/*  value:	-  set security mode to the required value by   */
/*		   calling "sca_set_mode" and			*/
/*		-  change value in "sct_stat_list"		*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   new_sm_SCT		       Required security 		*/
/*			       mode for the communication 	*/
/*			       between DTE and SCT. Separat     */
/*			       values for command and response.	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_set_mode()		Set security mode.  		*/
/*   write_SCT_config()		Encrypt and write SCT configuration data  */
/*				for the specified SCT.		*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int 
set_sec_mode(sct_id, new_sm_SCT)
	int             sct_id;
	SecMess        *new_sm_SCT;
{

	char           *proc = "set_sec_mode";

	secsc_errno = NOERR;
	sca_rc = 0;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	/* check the current sct_id */
	if ((sct_id >= MAX_SCTNO) || (sct_id <= 0)) {
		aux_add_error(ESCTID, "Invalid sct_id", CNULL, 0, proc);
		return (-1);
	}
	/* if actual value = new value => do nothing */
	if ((sct_stat_list[sct_id].sm_SCT.command == new_sm_SCT->command) &&
	  (sct_stat_list[sct_id].sm_SCT.response == new_sm_SCT->response))
		return (0);

	/* set security mode to new value */
	sca_rc = sca_set_mode(sct_id, new_sm_SCT);
	if (sca_rc < 0) {
		secsc_errno = analyse_sca_err(sct_id);
		aux_add_error(secsc_errno, "sca_set_mode", sca_errmsg, char_n, proc);
		return (-1);
	}
	/* change entry in sct_stat_list */
	sct_stat_list[sct_id].sm_SCT.command = new_sm_SCT->command;
	sct_stat_list[sct_id].sm_SCT.response = new_sm_SCT->response;


	/*
	 *  Save the changed SCT configuration data
	 */

	if ((write_SCT_config(sct_id)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration!", CNULL, 0, proc);
		return (-1);
	}


	return (0);

}				/* end set_sec_mode */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  set_fct_sec_mode				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Depending on the specified SCA-function:			*/
/*	- the security mode for the communication between DTE 	*/
/*	  and the specified SCT is set and			*/
/*	- the security mode for the communication between SCT	*/
/*	  and SC is returned.					*/
/*  The name of the SCA-function is delivered in an input 	*/
/*  parameter.   						*/
/*								*/
/*  - Global variable "sca_fct_list" contains a list of the 	*/
/*    SCA-functions and the belonging secure messaging values.  */
/*     								*/
/*  If the delivered function name is not stored within       	*/
/*  "sca_fct_list", the security mode will not be changed and 	*/
/*  the sec-mode for SCT/SC is set to SEC_NORMAL		*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   SCA_fct_name	       Name of the SCA-function		*/
/*   sm_SC		       Pointer to the sec-mode for the	*/
/*			       communication SCT/SC		*/
/*							       	*/
/* OUT							       	*/
/*   sm_SC		       Sec-mode for the			*/
/*			       communication SCT/SC		*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_FctName2FctPar		Get security mode for the SCA-  */
/*				function			*/
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*                                                              */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int 
set_fct_sec_mode(sct_id, SCA_fct_name, sm_SC)
	int             sct_id;
	char           *SCA_fct_name;
	SecMess        *sm_SC;
{
	SCAFctPar      *sca_fct_par;

	char           *proc = "set_fct_sec_mode";


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	if (!SCA_fct_name) {
		sm_SC->command = SEC_NORMAL;
		sm_SC->response = SEC_NORMAL;
		return (0);
	}
	sca_fct_par = aux_FctName2FctPar(SCA_fct_name);
	if (!sca_fct_par) {
		sm_SC->command = SEC_NORMAL;
		sm_SC->response = SEC_NORMAL;
		return (0);
	}
	if (set_sec_mode(sct_id, &sca_fct_par->sm_SCT)) {
		aux_add_error(ESECMESS, "set security mode", CNULL, 0, proc);
		return (-1);
	}
	sm_SC->command = sca_fct_par->sm_SC.command;
	sm_SC->response = sca_fct_par->sm_SC.response;
	return (0);

}				/* set_fct_sec_mode */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  device_authentication				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Perform device authentication.				*/
/*								*/
/*  Device authentication:					*/
/*  According to the additional file information of the selected*/
/*  application on the SC the device authentication is 		*/
/*  performed.	      						*/
/*  ( the device authentication is not implemented ????????????????????????????*/								/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   app_name		       Application name.		*/
/*   add_info		       additional file information	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*   aux_add_error()		Add error to error stack	*/
/*                                                              */
/*--------------------------------------------------------------*/



static
int 
device_authentication(sct_id, app_name, add_info)
	unsigned int    sct_id;
	char           *app_name;
	AddInfo        *add_info;
{


	char           *proc = "device_authentication";

	secsc_errno = NOERR;
	sca_rc = 0;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);

	fprintf(stderr, "                   Additional file information:\n");
	aux_xdump(add_info->octets, add_info->noctets, 0);
	fprintf(stderr, "\n");
#endif


	/* the length of the additional file information must be 4 (min) */
	if (add_info->noctets < 4) {
		aux_add_error(ESCAUTH, "invalid add file info from the SC", CNULL, 0, proc);
		return (-1);
	}

/* the device authentication is not implemented ????????????????????????????????????????????????????*/



	return (0);

}				/* device_authentication */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  user_authentication				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  According to parameter pin_type (PIN, PUK) the user 	*/
/*  authentication is performed.				*/
/*								*/
/*  If pin_type == PIN =>  PIN authentication:			*/
/*	    If not yet done the user authentication is 		*/ 
/*	    performed:						*/
/*	    The PIN is handled like an object (name = SC_PIN).	*/
/*	    The key_id of the PIN is taken from the    		*/
/*          sc_app_list[].sc_obj_list[].			*/
/*          If user enters an incorrect PIN, the PIN-check is   */
/*	    repeated two times.					*/
/*								*/
/*  If pin_type == PUK =>  Unblock PIN with PUK:		*/
/*	    The PUK is handled like an object (name = SC_PUK).	*/
/*	    The key_id of the PUK is taken from the    		*/
/*          sc_app_list[].sc_obj_list[].			*/
/*          If user enters an incorrect PUK, the unblock_PIN is */
/*	    repeated two times.					*/
/*								*/
/*  If the user authentication was successful, parameter	*/
/*  "user_auth_done" in "sct_stat_list[sct_id]" is set to TRUE	*/
/*								*/
/*								*/
/*  - Global variable "sct_stat_list[sct_id]" contains 		*/
/*    current information for the SCT specified by sct_id.	*/
/*							        */
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       SCT identifier			*/
/*   app_name		       Application name.		*/
/*   pin_type		       {PIN, PUK}			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_auth()			Device authentication  		*/
/*   sca_check_pin()		PIN authentication  		*/
/*   sca_display()		Display text on SCT-display.    */
/*   sca_unblock_pin()		Unblock PIN with PUK.		*/
/*                                                              */
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   bell_function()		"Ring the bell" to require user */
/*                              input at the SCT.		*/
/*   set_sec_mode()		Set security mode for the 	*/
/*				communication between DTE/SCT.  */
/*   write_SCT_config()		Encrypt and write SCT configuration data  */
/*				for the specified SCT.		*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack	*/
/*                                                              */
/*--------------------------------------------------------------*/



static
int 
user_authentication(sct_id, app_name, pin_type)
	unsigned int    sct_id;
	char           *app_name;
	PINType         pin_type;
{
	KeyId           key_id;
	SecMess         sm_SCT;	/* sec. mode for communication DTE/SCT	 */
	SCObjEntry     *sc_obj_entry;
	int             time_out;
	char           *display_text;
	int             auth_rc = 0;
	int             auth_errno;
	char           *auth_errmsg;

	char           *err_text_lock;
	char           *err_text_inv;
	char           *add_error_text;
	int             errno_lock;

	int             auth_attempts = 0;	/* no. of attempts to check
						 * the PIN	 */

	char           *proc = "user_authentication";

	secsc_errno = NOERR;
	sca_rc = 0;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	if (pin_type == PIN) 
		fprintf(stderr, "                   with PIN.\n");
	if (pin_type == PUK) 
		fprintf(stderr, "                   with PUK.\n");

#endif

/*
 *      Perform the PIN | PUK authentication.
 *			  (If necessary: three times)
 */


	switch (pin_type) {

	case (PIN):
		if (sct_stat_list[sct_id].user_auth_done == TRUE) {
			/* 
			 *  The user authentication has already been performed.
			 */
			return (0);
		}
	
		/* PIN Authentication */

		/* get information about the object SC_PIN */
		sc_obj_entry = aux_AppObjName2SCObj(app_name, SC_PIN_name);
		if (sc_obj_entry == (SCObjEntry * ) 0) {
			aux_add_error(ECONFIG, "get SC-Obj-info for SC_PIN", CNULL, 0, proc);
			return (-1);
		}
		err_text_lock = SCT_TEXT_PIN_LOCKED;
		err_text_inv = SCT_TEXT_PIN_INVALID;
		errno_lock = EPINLOCK;
		add_error_text = "sca_check_pin (SC_PIN)";
		break;

	case (PUK):
		/* Unblock PIN with PUK */

		/* get information about the object SC_PUK */
		sc_obj_entry = aux_AppObjName2SCObj(app_name, SC_PUK_name);
		if (sc_obj_entry == (SCObjEntry * ) 0) {
			aux_add_error(ECONFIG, "get SC-Obj-info for SC_PUK", CNULL, 0, proc);
			return (-1);
		}
		err_text_lock = SCT_TEXT_PUK_LOCKED;
		err_text_inv = SCT_TEXT_PIN_PUK_INVALID;
		errno_lock = EPUKLOCK;
		add_error_text = "sca_unblock_pin (SC_PUK)";
		break;

	default:
		aux_add_error(EINVALID, "invalid parameter pin_type", CNULL, 0, proc);
		return (-1);

	}			/* end case */

	/* set security mode for writing an SC-object */
	sm_SCT.command = sc_obj_entry->sm_SCT;
	sm_SCT.response = SEC_NORMAL;
	if (set_sec_mode(sct_id, &sm_SCT)) {
		aux_add_error(ESECMESS, "set security mode for writing obj", CNULL, 0, proc);
		return (-1);
	}
	get_sca_keyid(&sc_obj_entry->sc_id, &key_id);

	/* check PIN/PUK  (if user enters invalid PIN/PUK, repeat 2 times) */
	do {
		bell_function();
		if (pin_type == PIN)
			auth_rc = sca_check_pin(sct_id,
						&key_id,
						&sc_obj_entry->sm_SC_write);
		else
			auth_rc = sca_unblock_pin(sct_id,
						  &key_id,
						  &sc_obj_entry->sm_SC_write);

		auth_errno = sca_errno;
		auth_errmsg = sca_errmsg;
		auth_attempts++;

		if (auth_rc < 0) {
			switch (sca_errno) {

			case EKEYLOCK:
			case ELAST:
				aux_add_error(errno_lock, add_error_text, sca_errmsg, char_n, proc);

				/* display message on SCT-Display */
				sca_rc = sca_display(sct_id,
					       display_text = err_text_lock,
						     time_out = 0);
				if (sca_rc < 0) {
					secsc_errno = analyse_sca_err(sct_id);
					aux_add_error(secsc_errno, "sca_display", sca_errmsg, char_n, proc);
					return (-1);
				}
				return (-1);	/* PIN | PUK on SC is locked */
				break;

			case EPININC:
			case ENEWPIN:
			case EAUTH_WRITE:
			case EAUTH:
				sca_rc = sca_display(sct_id,
						display_text = err_text_inv,
						     time_out = 0);
				if (sca_rc < 0) {
					secsc_errno = analyse_sca_err(sct_id);
					aux_add_error(secsc_errno, "sca_display", sca_errmsg, char_n, proc);
					return (-1);
				}
				break;
			default:
				secsc_errno = analyse_sca_err(sct_id);
				aux_add_error(errno_lock, add_error_text, sca_errmsg, char_n, proc);
				return (-1);

			}	/* end switch */
		}
		 /* end if */ 
		else {
			/* PIN authentication | unblocking PIN was successful */

			sct_stat_list[sct_id].user_auth_done = TRUE;

			/*
			 *  Save the changed SCT configuration data
			 */

			if ((write_SCT_config(sct_id)) < 0) {
				aux_add_error(ESCPROCDATA, "Cannot write SCT configuration!", CNULL, 0, proc);
				return (-1);
			}

			return (0);
		}

	}			/* end do */
	while (auth_attempts < MAX_PIN_FAIL);

	/* after 3 unsuccessful attempts: authentication fails */
	sca_errno = auth_errno;
	sca_errmsg = auth_errmsg;
	secsc_errno = analyse_sca_err(sct_id);
	aux_add_error(errno_lock, add_error_text, sca_errmsg, char_n, proc);
	return (-1);

}				/* user_authentication */










/*--------------------------------------------------------------*/
/*						                */
/* PROC  handle_gen_DecSK				       	*/
/*   								*/
/* DESCRIPTION						       	*/
/*								*/
/*  This routine checks under which name the decryption key to 	*/
/*  be generated shall be installed on the SC.			*/
/*  If this routine sets the output parameter "new_DecSKname"	*/
/*  to CNULL, the key shall be installed under the name given   */
/*  in "key".							*/
/*  Otherwise the calling routine has to store the key under    */
/*  the name returned in "new_DecSKname".			*/
/*							       	*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   key	 	       Structure to identify the key.	*/
/*   replace		       = FALSE => Install new key	*/
/*   			       = TRUE  => Replace existing key	*/
/*   new_DecSKname	       **char				*/
/*   new_replace_value	       Pointer on type Boolean.		*/	
/*								*/
/*							       	*/
/*							       	*/
/* OUT							       	*/
/*   *new_DecSKname	       = CNULL  => no change of object 	*/
/*			                   name			*/
/*			       != CNULL => object name, under   */
/*					   which the new decryption key */
/*					   shall be installed on the SC.*/ 
/*  *new_replace_value	       replace value for the installation of    */
/*			       the decryption key under the name in     */
/*			       new_DecSKname.		        	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       o.k.				*/
/*   -1			       Error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_update_time_SCToc()	Get update time of object in 	*/
/*				SC-Toc.				*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   aux_cmp_UTCTime()		Compare two time-values  	*/
/*				(UTCTime).			*/
/*   aux_cpy_String()		Copy string.			*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*							       	*/
/*--------------------------------------------------------------*/
static
int
handle_gen_DecSK (key, replace, new_DecSK_name, new_replace_value) 
Key		*key;
Boolean		 replace;
char		**new_DecSK_name;
Boolean		*new_replace_value;

{

	UTCTime	       *DecSKnew_update = (UTCTime *)0;
	UTCTime	       *DecSKold_update = (UTCTime *)0;
	char	       *save_obj_name;
	char 	       *old_key_name;

	char           *proc = "handle_gen_DecSK";

#ifdef SECSCTEST
	fprintf(stderr, "%s\n", proc);
#endif


	*new_DecSK_name = CNULL;


	if ((key->keyref != 0) || (key->pse_sel == (PSESel * ) 0) ||
	    (!key->pse_sel->object.name) || (!strlen(key->pse_sel->object.name)))

		return(0);


	/*
	 * Select key with object name
	 */

	if (!(strcmp(key->pse_sel->object.name, DecSKold_name)) ||
	    !(strcmp(key->pse_sel->object.name, SKold_name))) {
		aux_add_error(EKEYSEL, "Not allowed to generate old decryption key!", CNULL, 0, proc);
		return (-1);
	}

	if (!(strcmp(key->pse_sel->object.name, DecSKnew_name)) ||
	    !(strcmp(key->pse_sel->object.name, SKnew_name))) {

		/*
		 *  Get update time of DecSKnew (SKnew) on the SC
		 */

		if (get_update_time_SCToc(key->pse_sel, &DecSKnew_update)) {
			aux_add_error(EKEYSEL, "Error in SCToc", CNULL, 0, proc);
			return (-1);
		}
		if (DecSKnew_update == (UTCTime *)0) {

			/* 
			 *  DecSKnew (SKnew) not yet installed on the SC 
			 *     => if replace = TRUE, return(error)  
			 *                           (There is no key, which can be replaced)
			 *     => if replace = FALSE, key can be installed under the name of
			 *                            DecSKnew | SKnew.
			 */

			if (replace == TRUE) {
				aux_add_error(EKEYSEL, "Key to be replaced doesn't exist!", CNULL, 0, proc);
				return (-1);
			}
		}	
		else {

			/* 
			 *  DecSKnew (SKnew) is already installed on the SC 
			 *     => if replace = FALSE, return(error)
			 *     => if replace = TRUE and DecSKold (SKold) is an object on the SC, check DecSKold
			 */
	
			if (replace == FALSE) {
				aux_add_error(EKEYSEL, "Key exists already!", key->pse_sel, PSESel_n, proc);
				return (-1);
			}

			/*
			 *  DecSKold (SKold) an object on the SC ?
			 */

			if (!(strcmp(key->pse_sel->object.name, DecSKnew_name)))
				old_key_name = DecSKold_name;
			else    old_key_name = SKold_name;
 
			if ((aux_AppObjName2SCObj(key->pse_sel->app_name, old_key_name)) != (SCObjEntry * ) 0) {

				/*
	 			 *  Get update time of DecSKold (SKold) on the SC
				 */

				save_obj_name = key->pse_sel->object.name;
				key->pse_sel->object.name = old_key_name;
				if (get_update_time_SCToc(key->pse_sel, &DecSKold_update)) {
					aux_add_error(EKEYSEL, "Error in SCToc", CNULL, 0, proc);
					return (-1);
				}
				key->pse_sel->object.name = save_obj_name;

				if (DecSKold_update == (UTCTime *)0) {

					/* 
					 *  DecSKold (SKold) not yet installed on the SC 
					 *     => - Key shall be installed under the name of DecSKold (SKold).
					 *        - For the SC this is a new key, therefore the parameter
					 *          new_replace_value is set to FALSE.
					 */

					*new_DecSK_name = aux_cpy_String(old_key_name);
					*new_replace_value = FALSE;
				}
				else {

					/* 
					 *  Both DecSKnew (SKnew) and DecSKold  (SKold) are
					 *   already installed on the SC 
					 *     => Get the name of the oldest decryption key.
					 */

						
					if ((aux_cmp_UTCTime(DecSKnew_update, DecSKold_update)) == 1) {

						/* 
						 *  DecSKold (SKold) is older than 
					         *    DecSKnew (SKnew)
						 *     => Key shall be installed under the 
						 *        name of DecSKold (SKold).
						 */ 

						*new_DecSK_name = aux_cpy_String(old_key_name);
					}
				}
			}
		}
	}		/* object_name = DecSKnew_name (SKnew_name) */


	return(0);


}				/* handle_gen_DecSK */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_DecSK_name					       	*/
/*   								*/
/* DESCRIPTION						       	*/
/*								*/
/*  Returns the object name under which the decryption key	*/
/*  is stored on the SC.			 		*/
/*								*/
/*  The value of the input parameter "pse_sel->object.name"  	*/
/*  is "DecSK_new_name", "DecSKold_name", "SK_new_name",	*/
/*  "SK_old_name", resp..					*/
/*							       	*/
/*  "DecSKnew" ("SKnew"):					*/
/*  If the given object name is set to "DecSKnew" ("SKnew"), 	*/
/*  this routine returns the name of the decryption key on the  */
/*  SC, which has been changed last.				*/
/*  								*/
/*  "DecSKold" ("SKold"):					*/
/*  If the given object name is set to "DecSKold" ("SKold"),    */
/*  this routine returns the name of the oldest decryption key  */
/*  on the SC.							*/
/*  								*/
/*  This routine gets the entries of "DecSKnew" (SKnew") and 	*/
/*  "DecSKold" ("SKold") from SCToc and checks/compares the 	*/
/*  update-time of the keys to decide which key is the new one  */
/*  and which is the old one.					*/
/*							       	*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	       						*/
/*							       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   CNULL		       Error				*/
/*   ptr. to object name       Name under which the decryption  */
/*			       key is stored on the SC.		*/
/*							       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_update_time_SCToc()	Get update time of object in 	*/
/*				SC-Toc.				*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   aux_cmp_UTCTime()		Compare two time-values  	*/
/*				(UTCTime).			*/
/*   aux_cpy_String()		Copy string.			*/
/*                                                              */
/*   analyse_sca_err()		Analyse of an error-number 	*/
/*				returned by an SCA-IF function. */
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*							       	*/
/*--------------------------------------------------------------*/
static
char
*get_DecSK_name (pse_sel) 
PSESel		*pse_sel;

{

	UTCTime	       *DecSKnew_update = (UTCTime *)0;
	UTCTime	       *DecSKold_update = (UTCTime *)0;
	char	       *save_obj_name;
	char 	       *old_key_name;
	char 	       *new_key_name;


	char           *proc = "get_DecSK_name";

#ifdef SECSCTEST
	fprintf(stderr, "%s\n", proc);
#endif


	if (!(strcmp(pse_sel->object.name, DecSKnew_name))) {
		new_key_name = DecSKnew_name;
		old_key_name = DecSKold_name;
	}
	else {
		new_key_name = SKnew_name;
		old_key_name = SKold_name;
	}
 


	/*
	 *  Get update time of DecSKnew (SKnew) on the SC
	 */

	save_obj_name = pse_sel->object.name;
	pse_sel->object.name = new_key_name;
	if (get_update_time_SCToc(pse_sel, &DecSKnew_update)) {
		aux_add_error(EKEYSEL, "Error in SCToc", CNULL, 0, proc);
		return (CNULL);
	}
	pse_sel->object.name = save_obj_name;

	if (DecSKnew_update == (UTCTime *)0) {

		/* 
		 *  DecSKnew not yet installed on the SC 
		 */

		aux_add_error(EKEYSEL, "Decryption key not stored on the SC!", pse_sel->object.name, char_n, proc);
		return (CNULL);

	}


	/*
	 *  Intermediate result:  DecSKnew is installed on the SC 
	 *
	 *           Next to do:  If DecSKold is an object on the SC
	 *			  => Get update time of DecSKold on the SC
	 */

	if ((aux_AppObjName2SCObj(pse_sel->app_name, old_key_name)) != (SCObjEntry * ) 0) {

		save_obj_name = pse_sel->object.name;
		pse_sel->object.name = old_key_name;
		if (get_update_time_SCToc(pse_sel, &DecSKold_update)) {
			aux_add_error(EKEYSEL, "Error in SCToc", CNULL, 0, proc);
			return (CNULL);
		}
		pse_sel->object.name = save_obj_name;
	}



	if (!(strcmp(pse_sel->object.name, new_key_name))) {

		/*
		 *  Search for the decryption key which has been changed last.
		 */

		if (DecSKold_update == (UTCTime *)0) {

			/* 
			 *  DecSKold is not installed on the SC 
			 *    => DecSKnew has been changed last 
			 */

			return (aux_cpy_String(new_key_name));
		}
		
		/*
		 *  Intermediate result:  Both DecSKnew and DecSKold are installed on the SC 
		 *
		 *           Next to do:  Return the name of the key which has been changed last
		 */

						
		if ((aux_cmp_UTCTime(DecSKnew_update, DecSKold_update)) == 1) {

			/* 
			 *  DecSKnew is the key which has been changed last
			 */ 

			return (aux_cpy_String(new_key_name));
		}
		else  {

			/* 
			 *  DecSKold is the key which has been changed last
			 */ 

			return(aux_cpy_String(old_key_name));
		}

	}

	else {
		if (!(strcmp(pse_sel->object.name, old_key_name))) {

			/*
			 *  Search for the oldest decryption key stored on the SC.
			 */

			if (DecSKold_update == (UTCTime *)0) {

				/* 
				 *  DecSKold is not installed on the SC 
				 *    => DecSKnew has been changed last 
				 */

				aux_add_error(EKEYSEL, "No old decryption key on the SC!", CNULL, 0, proc);
				return (CNULL);
			}
		
		
			/*
			 *  Intermediate result:  Both DecSKnew and DecSKold are installed on the SC. 
			 *
			 *           Next to do:  Return the name of the key which is older.
			 */

						
			if ((aux_cmp_UTCTime(DecSKnew_update, DecSKold_update)) == 1) {

				/* 
				 *  DecSKold is older 
				 */ 

				return(aux_cpy_String(old_key_name));
			}
			else  {

				/* 
				 *  DecSKnew is older
				 */ 

				return(aux_cpy_String(new_key_name));
			}
		}
		else {
			aux_add_error(EKEYSEL, "Wrong name of decryption key", pse_sel->object.name, char_n, proc);
			return (CNULL);
		}
	}



}				/* get_DecSK_name */







/*--------------------------------------------------------------*/
/*						                */
/* PROC  int_to_fileid					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an integer value into the structure FileId, which */
/*  is used at the SCA-IF.				        */
/*								*/
/*  Bit-Structure of a FileId (one byte): 			*/
/*         B'nnnnttll' (n=no., t=file-type, l=file-level)	*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   fileid_int	 	       Integer value of the file_id	*/
/*   file_id		       Pointer to the structure FileId 	*/
/*							       	*/
/* OUT							       	*/
/*   file_id		       File Identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   getbits()	                Get n bits of byte x from 	*/
/*			        position p.			*/
/*                                                              */
/*--------------------------------------------------------------*/



static
void 
int_to_fileid(fileid_int, file_id)
	int             fileid_int;
	FileId         *file_id;
{
	char            fileid_char;
	char		*proc = "int_to_fileid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	fileid_char = (char) fileid_int;

	file_id->file_level = getbits(fileid_char, 1, 2);
	file_id->file_type = getbits(fileid_char, 3, 2);
	file_id->name = getbits(fileid_char, 7, 4);


}




/*--------------------------------------------------------------*/
/*						                */
/* PROC  int_to_keyid					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an integer value into the structure KeyId, which  */
/*  is used at the SCA-IF.				        */
/*								*/
/*  Bit-Structure of a KeyId (one byte): 			*/
/*         B'nnnnnnll' (n=no., l=file-level)			*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   keyid_int	 	       Integer value of the key_id	*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*							       	*/
/* OUT							       	*/
/*   key_id		       Key Identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   getbits()	                Get n bits of byte x from       */
/*			        position p.		        */
/*                                                              */
/*--------------------------------------------------------------*/


static
void 
int_to_keyid(keyid_int, key_id)
	int             keyid_int;
	KeyId          *key_id;
{
	char            keyid_char;
	char		*proc = "int_to_keyid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	keyid_char = (char) keyid_int;

	key_id->key_level = getbits(keyid_char, 1, 2);
	key_id->key_number = getbits(keyid_char, 7, 6);


}				/* int_to_keyid */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_sca_fileid					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform the structure SCId into structure FilId, which    */
/*  is used at the SCA-IF.				        */
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sc_id	 	       Pointer to structure SCId	*/
/*   file_id		       Pointer to the structure FileId 	*/
/*							       	*/
/* OUT							       	*/
/*   file_id		       File Identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/



static
void 
get_sca_fileid(sc_id, file_id)
	SCId           *sc_id;
	FileId         *file_id;
{
	char		*proc = "get_sca_fileid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	file_id->file_level = sc_id->level;
	file_id->file_type = sc_id->type;
	file_id->name = sc_id->no;


}




/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_sca_keyid					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform the structure SCId into structure KeyId, which    */
/*  is used at the SCA-IF.				        */
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sc_id	 	       Pointer to structure SCId	*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*							       	*/
/* OUT							       	*/
/*   key_id		       Key Identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   getbits()	                Get n bits of byte x from       */
/*			        position p.		        */
/*                                                              */
/*--------------------------------------------------------------*/


static
void 
get_sca_keyid(sc_id, key_id)
	SCId           *sc_id;
	KeyId          *key_id;
{
	char		*proc = "get_sca_keyid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	key_id->key_level = sc_id->level;
	key_id->key_number = sc_id->no;

}				/* get_sca_keyid */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_keyid_for_obj				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Provide the keyid for an object:				*/
/*								*/
/*  1. Get parameters for the object from the global variable 	*/
/*     "sc_app_list[].sc_obj_list[]". 				*/
/*     If object is a file					*/
/*	  => return (error).					*/
/*  2. Get key_id for the object.				*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   app_name		       Name of the application		*/
/*   obj_name	 	       Name of the object		*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*							       	*/
/* OUT							       	*/
/*   key_id		       Key Identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_sca_keyid()		Transform structure SCId into   */
/*				structure KeyId (for a key on   */
/*				the SC).			*/
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/


static
int 
get_keyid_for_obj(app_name, obj_name, key_id)
	char	       *app_name;
	char           *obj_name;
	KeyId          *key_id;
{
	char		*proc = "get_keyid_for_obj";


	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	/* get information about the object */
	sc_obj_entry = aux_AppObjName2SCObj(app_name, obj_name);
	if (sc_obj_entry == (SCObjEntry * ) 0) {
		aux_add_error(ECONFIG, "get SC-Obj-info for object(key)", obj_name, char_n, proc);
		return (-1);
	}
	if (sc_obj_entry->type == SC_FILE_TYPE) {
		/* object is a file */
		aux_add_error(ECONFIG, "Type of object is not key!", obj_name, char_n, proc);
		return (-1);
	}
	get_sca_keyid(&sc_obj_entry->sc_id, key_id);

	return(0);

}				/* get_keyid_for_obj */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  keyref_to_keyid				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform the key reference into the structure KeyId, which */
/*  is used at the SCA-IF.				        */
/*								*/
/*  The key reference (integer) of the SEC-IF can be used to 	*/
/*  address:							*/
/*      - a key stored on the SC (on MF-, DF-, SF-level) or	*/
/*      - a key stored in the SCT or				*/
/*      - a key stored in the key pool (SW-PSE).		*/
/*								*/
/*  The two most significant bytes of the key reference 	*/
/*  indicate the address of the key as follows:	   	        */
/*  #define	SC_MF_KEY   0xFF00				*/
/*  #define	SC_DF_KEY   0xFF40		                */
/*  #define	SC_SF_KEY   0xFF80				*/
/*  #define	SCT_KEY     0xFFC0				*/
/*  #define	KeyPool_KEY 0x0000				*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   keyref	 	       Key reference			*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*							       	*/
/* OUT							       	*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/


static
int 
keyref_to_keyid(keyref, key_id)
	int             keyref;
	KeyId          *key_id;
{
	int             key_level;
	char           *proc = "keyref_to_keyid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	if ((keyref & SC_KEY) == SC_KEY) {
		key_id->key_level = SC_DF;
		key_id->key_number = keyref & ~SC_KEY;
	}
	else {
		if ((keyref & SCT_KEY) == SCT_KEY) {
			key_id->key_level = SCT;
			key_id->key_number = keyref & ~SCT_KEY;
		}
		else {
			aux_add_error(EKEYSEL, "Invalid level of key!", CNULL, 0, proc);
			return (-1);
		}
	}
	return (0);


}				/* keyref_to_keyid */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  key_to_keyid					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Return key_id according to the key selection in key:	*/
/*								*/
/*   Case 1: Selection with an object name:			*/
/*    If key->keyref == 0 && key->pse_sel != NULL		*/
/*	   a) If "special_DecSK_selection" is set to TRUE, 	*/
/*	      "DecSKnew" and "DecSKold" are selected according  */
/*	      to the update time of the keys on the SC, e.g.	*/
/*	      "DecSKnew" is the key which has been changed last.*/
/*	      "SKnew" and "SKold" are treated in the same way.	*/
/*         b) Get parameters for the object 		 	*/
/*            from the global variable "sc_app_list[].sc_obj_list[]". */
/*	      If object is a file				*/
/*		 => return (error).				*/
/*	   c) Get key_id for the object.			*/
/*								*/
/*   Case 2: Selection with the key reference:			*/
/*    If key->keyref != 0					*/
/*         a) Get key_id from keyref.				*/
/*								*/
/*   Case 3: return(error)					*/
/*								*/
/*  Structure KeyId is used at the SCA-IF to identify a key.	*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   key	 	       Structure which identifies a key	*/
/*   key_id		       Pointer to the structure KeyId 	*/
/*   special_DecSK_selection   = TRUE 				*/
/*				 => If object.name = DecSKnew (SKnew),  */
/*				    the key which has been 	*/
/*				    installed last is selected.	*/
/*				 => If object.name = DecSKold (SKold),  */
/*				    the key which has been 	*/
/*				    installed prior is selected.*/
/*			       = FALSE				*/
/*				 => no special handling of the  */
/*				    Decryption secret keys	*/
/*				 
/*							       	*/
/* OUT							       	*/
/*   key_id		       Key identifier		 	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_DecSK_name()		Get name of decryption key on SC*/
/*   get_keyid_for_obj()	Get keyid for object.	        */
/*   get_sca_keyid()		Transform structure SCId into   */
/*				structure KeyId (for a key on   */
/*				the SC).			*/
/*   keyref_to_keyid()	        Transform keyref into structure */
/*                              keyid.				*/
/*                                                              */
/*   aux_add_error()		Add error to error stack.	*/
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/
/*--------------------------------------------------------------*/


static
int 
key_to_keyid(key, key_id, special_DecSK_selection)
	Key            *key;
	KeyId          *key_id;
	Boolean		special_DecSK_selection;
{

	/* Variables for internal use */
	SCObjEntry     *sc_obj_entry;
	char	       *obj_name = CNULL;

	char           *proc = "key_to_keyid";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


	if (!key || !key_id) {
		aux_add_error(EINVALID, "key missing in key_to_keyid", CNULL, 0, proc);
		return (-1);
	}
	if ((key->keyref == 0) && (key->pse_sel != (PSESel * ) 0)) {

		/*
		 * Select key with object name
		 */

		if ((special_DecSK_selection == TRUE) &&
		    ((!(strcmp(key->pse_sel->object.name, DecSKnew_name))) || 
		     (!(strcmp(key->pse_sel->object.name, SKnew_name))) || 
		     (!(strcmp(key->pse_sel->object.name, DecSKold_name))) || 
		     (!(strcmp(key->pse_sel->object.name, SKold_name))))) {

			/*
			 *  Get the name of the decryption key on the SC
			 */

			if ( (obj_name = get_DecSK_name(key->pse_sel)) == CNULL ) {
				aux_add_error(EKEYSEL, "Cannot get name of decryption key on the SC!", CNULL, 0, proc);
				return (-1);
			}
		}
		else {
			if ( (obj_name = aux_cpy_String (key->pse_sel->object.name)) == CNULL) {
				aux_add_error(EMALLOC, "obj_name", CNULL, 0, proc);
				return (-1);
			}
		}



		if (get_keyid_for_obj(key->pse_sel->app_name, obj_name, key_id)) {
			aux_add_error(EKEYSEL, "Cannot get keyid for object!", CNULL, 0, proc);
			return (-1);
		}

		free(obj_name);
		
	} else {
		if (key->keyref != 0) {

			/*
			 * Select key with keyref
			 */

			if (keyref_to_keyid(key->keyref, key_id)) {
				aux_add_error(EKEYSEL, "Cannot get keyid for keyref!", CNULL, 0, proc);
				return (-1);
			};

		} else {
			aux_add_error(EKEYSEL, "Cannot select key!", CNULL, 0, proc);
			return (-1);
		}		/* end else */

	}			/* end else */

	return (0);

}				/* key_to_keyid */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  itos						       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an integer value into a character string. The    */
/*  max. length of the char-string is specified by an input 	*/
/*  parameter.							*/
/*  The resulting character string is not NULL terminated.	*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   int_value	 	       Integer value to be transformed. */
/*   char_string 	       Pointer to char_string.		*/
/*   max_len		       Max. length of the char_string to*/
/*			       be returned.			*/
/*							       	*/
/* OUT							       	*/
/*   char_string 	       Character string.		*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*--------------------------------------------------------------*/


static
int 
itos(int_value, char_string, max_len)
	unsigned int    int_value;
	char           *char_string;
	unsigned int    max_len;
{

	unsigned int    i;

	char           *proc = "itos";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif
	i = sizeof(int);
	if ((max_len <= 0) || (max_len > i)) {
		aux_add_error(secsc_errno, "max. length wrong", CNULL, 0, proc);
		return (-1);
	}
	for (i = 0; i < max_len; i++) {

		char_string[max_len - i - 1] = (unsigned) int_value >> i * 8;

	}			/* end for */

#ifdef SECSCTEST
	fprintf(stderr, "char_string\n");
	aux_fxdump(stderr, char_string, max_len);
	fprintf(stderr, "\n");
#endif

	return (0);

}				/* end itos */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  stoi						       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an character string into an integer value. The    */
/*  max. length of the char-string is specified by an input 	*/
/*  parameter.							*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   char_string 	       Pointer to char_string to be	*/
/*			       transformed.			*/
/*   int_value	 	       POinter to integer value.	*/
/*   max_len		       Max. length of the char_string.  */
/*							       	*/
/* OUT							       	*/
/*   int_value	 	       Integer value.			*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*--------------------------------------------------------------*/


static
int 
stoi(char_string, int_value, max_len)
	char           *char_string;
	unsigned int   *int_value;
	unsigned int    max_len;
{

	unsigned int    i;

	char           *proc = "stoi";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	fprintf(stderr, "char_string to be transformed\n");
	aux_fxdump(stderr, char_string, max_len);
	fprintf(stderr, "\n");
#endif
	i = sizeof(int);
	if ((max_len <= 0) || (max_len > i)) {
		aux_add_error(secsc_errno, "max. length wrong", CNULL, 0, proc);
		return (-1);
	}
	if (!(int_value)) {
		aux_add_error(EINVALID, "invalid input value", CNULL, 0, proc);
		return (-1);
	}
	*int_value = 0;
	for (i = 0; i < max_len; i++) {
		*int_value += (((unsigned int) char_string[i] & 0xFF) << (max_len - i - 1) * 8);
	}			/* end for */
#ifdef SECSCTEST
	fprintf(stderr, "int_value: %d, i: %d\n", *int_value, i);
#endif

	return (0);

}				/* end stoi */



/*--------------------------------------------------------------*/
/*						                */
/* PROC  int2ascii					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an integer value into a NULL terminated ASCII 	*/
/*  character string. 						*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   s		 	       Pointer to char_string.		*/
/*   n		 	       Integer value to be transformed. */
/*							       	*/
/* OUT							       	*/
/*   char_string 	       Character string.		*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*--------------------------------------------------------------*/

static
int int2ascii(s,n)			     /* from integer to NULL terminated ascii string */
char s[];
int n;
{
    int c,i,j, sign;
	char           *proc = "int2ascii";

#ifdef SECSCTEST
/*	fprintf(stderr, "SECSC-Function: %s\n", proc);*/
#endif

	if (!(s)) {
		aux_add_error(EINVALID, "invalid input value", CNULL, 0, proc);
		return (-1);
	}

	if((sign = n) < 0)
	      n = -n;
	i = 0;
    	do {			 /* generation from right to left */
	 	s[i++] = n % 10 + '0';
    	} while ((n /= 10) > 0);
    	s[i] = '\0';

    	/* reverse(s);*/
    	for (i=0, j=strlen(s)-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
    	} /* end for */

#ifdef SECSCTEST
/*	fprintf(stderr, "char_string: %s\n", s);*/
#endif

	return(0);

} /* end int2ascii */



/*--------------------------------------------------------------*/
/*						                */
/* PROC  getbits					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Returns n bits of byte x from position p. The returned bits */
/*  are shifted to right. Position 0 is the right end of x.	*/
/*								*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   x	 	       	       One byte	(8 bits)		*/
/*   p			       Position				*/
/*   n			       Number of bits			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   				Return value			*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/




static
int 
getbits(x, p, n)		/* get n bits from position p */
	unsigned        x, p, n;

{

	return ((x >> (p + 1 - n)) & ~(~0 << n));

}				/* end getbits */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  bell_function					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  "Ring the bell" to require user input at the SCT.		*/
/*  If the Workstation is not equipped with an audible bell, the*/
/*  system flashes the window.					*/
/*  ('\07' is written to /dev/tty)				*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/




static
void 
bell_function()
{
	int             fd, rc;

	if ((fd = open("/dev/tty", O_RDWR)) != -1) {
		rc = write(fd, USER_BELL, 1);
	}
	close(fd);

}				/* end bell_function */


#endif
