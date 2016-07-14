/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 1.0		                             +-----*/
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-stasc                                VERSION 1.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	stasc.c                          		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides all functions for file handling and data access        */
/*      on the smartcard  of the smartcard application interface                   */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*	sca_trans()	      Transfer of a smartcard command   	           */
/*							                           */
/*	sca_create_file()     Create file on the smartcard                         */
/*							                           */
/*	sca_register()        Registering of applications       	           */
/*							                           */
/*	sca_select_file()     Select file on the smartcard	                   */
/*										   */
/*      sca_close_file()      Close file on the smartcard                          */
/*										   */
/*      sca_lock_file()       Lock working elementary file on the smartcard        */
/*										   */
/*      sca_unlock_file()     Unlock WEF on the smartcard                          */
/*										   */
/*      sca_delete_file()     Delete file on the smartcard                         */
/*										   */
/*      request;              body of the SCT commands                             */
/*      response;             body of the response of the SCT                      */
/*      command;              INS-Code of the SCT command                          */
/*      sc_param;             structure of parameters for the                      */
/*                            SC-commands                                          */
/*      sc_apdu;              generated apdu of the SC-command                     */
/*      create_trans();							           */
/* 	cr_header();								   */
/*	get_bits();								   */
/*                                                                                 */
/*							                           */
/*                                                                                 */
/*    IMPORT		    DESCRIPTION 		                           */
/*                                 -  aux_xdmp.c (libcrypt)                        */
/*                                                                                 */
/*	aux_fxdump()                  dump buffer in File	                   */
/*							                           */
/*                                 -  sta_free.c (libsm)                           */
/*                                                                                 */
/*      sta_aux_bytestr_free()        set the bytes-buffer in Bytestring free      */
/*                                                                                 */
/*				   -  sctint.c (libsm)                             */
/*							                           */
/*      sct_interface()               Send SCT command / receive SCT response      */
/*							                           */
/*      sct_errno                     global error variable set by SCT-interface   */
/*							                           */
/*      sct_errmsg                    global pointer to error message set by       */
/*                                    SCT-interface                                */
/*                                                                                 */
/*				   -  sccom.c (libsm)				   */
/*                                                                                 */
/*      sc_create()                   create SC-request APDU                       */
/*                                                                                 */
/*      sc_check()                    check SC-response APDU                       */
/*									 	   */
/*      sc_errno                      global error variable set by SC-interface    */
/*										   */
/*      sc_errmsg                     global pointer to error message set by       */
/*                                    SC-interface                                 */
/*                                                                                 */
/*				   -  sta_dev.c (libsm)                            */
/*                                                                                 */
/*      check_sct_sc()                check SCT and SC                             */
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
/*				   -  staprint.c   (libsm) for TEST-output         */
/*                                                                                 */
/*      print_filecat()							           */
/*      print_filetype()                                                           */
/*      print_datastruc()                                                          */
/*      print_filecontinfo()                                                       */
/*      print_secmess()                                                            */
/*      print_filesel()                                                            */
/*      print_fileid()                                                             */
/*      print_inforeq()                                                            */
/*      print_closecontext()                                                       */
/*      print_datasel()                                                            */
/*      print_datastruc()                                                          */
/*      print_keyid()                                                              */
/*      print_recordlist()                                                         */
/*      print_transmode()                                                          */
/*                                                                                 */
/*                                                                                 */
/*    INTERNAL                                                                     */
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
#else
#include <stdlib.h>
#endif /* !MAC */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/

extern int      sct_interface();
extern void     sta_aux_bytestr_free();
extern void     aux_fxdump();
extern int      sc_create();
extern int      sc_check();
extern int      check_sct_sc();
extern int      check_sec_mess();
extern int      set_errmsg();
extern void     err_analyse();

extern unsigned int sca_errno;	/* error number set by STAMOD-      */

 /* stadevice			       */
extern char    *sca_errmsg;	/* pointer to error message set by  */

 /* STAMOD-stadevice                 */
extern unsigned int sct_errno;	/* error number set by SCT-Interface */
extern char    *sct_errmsg;	/* pointer to error msg set by      */

 /* SCT-Interface                    */
extern unsigned int sc_errno;	/* error number set by SC-Interface */
extern char    *sc_errmsg;	/* pointer to error msg set by      */

 /* SC-Interface */

#ifdef TEST
extern void     print_filecat();
extern void     print_filetype();
extern void     print_datastruc();
extern void     print_filecontinfo();
extern void     print_secmess();
extern void     print_filesel();
extern void     print_fileid();
extern void     print_inforeq();
extern void     print_closecontext();
extern void     print_datasel();
extern void     print_keyid();
extern void     print_recordlist();
extern void     print_transmode();

#endif

/*-------------------------------------------------------------*/
/*   globale variable and function definitions	               */
/*-------------------------------------------------------------*/
Request         request;	/* body of the SCT commands         */
Bytestring      response;	/* body of the response of the SCT  */
int             command;	/* INS-Code of the SCT command      */

struct s_command sc_param;	/* structure of parameters for the  */

 /* SC-commands                      */
Bytestring      sc_apdu;	/* generated apdu of the SC-command */


int             create_trans();
int             cr_header();
unsigned int    get_bits();



/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/

/* definitions for the SC-Interface */
#define SCCMD                   sc_param.sc_header.inscode
#define SCHEAD                  sc_param.sc_header
#define SCSELECT                sc_param.sc_uval.sc_select
#define SCREG                   sc_param.sc_uval.sc_register
#define SCCREATE                sc_param.sc_uval.sc_create
#define SCCLOSE                 sc_param.sc_uval.sc_close
#define SCDELFILE               sc_param.sc_uval.sc_delfile
#define SCLOCKF                 sc_param.sc_uval.sc_lockfile



/*-------------------------------------------------------------*/
/*   local Variable definitions			               */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*   local procedure definitions	                       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_trans                VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Transfer of a smartcard command.         	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   sc_command                Smartcard command               */
/*							       */
/*   trans_mode		       Transfer mode                   */
/*			       (TRANSP,SECURE)   	       */
/*							       */
/* OUT							       */
/*   sc_response               Response of the smartcard       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*			         M_EPOINTER                    */
/*                               M_EMEMORY                     */
/*				 M_ESECMODE		       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               T1 - ERROR                    */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
 /* *//* */
/*-------------------------------------------------------------*/
int
sca_trans(sct_id, sc_command, trans_mode, sc_response)
	int             sct_id;
	OctetString    *sc_command;
	TransMode       trans_mode;
	OctetString    *sc_response;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	Bytestring      bstring;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_trans *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	fprintf(stdout, "sc_command              : \n");
	fprintf(stdout, "    noctets             : %d\n", sc_command->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, sc_command->octets, sc_command->noctets, 0);
	print_transmode(trans_mode);
#endif

	/*-------------------------------------*/
	/* check parameter                    */
	/*-------------------------------------*/
	if (sc_response == NULL) {
		sca_errno = M_EPOINTER;
		set_errmsg();
		return (-1);
	}
	if ((trans_mode != TRANSP) &&
	    (trans_mode != SECURE)) {
		sca_errno = M_ESECMODE;
		set_errmsg();
		return (-1);
	}
	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SCT command S_TRANS         */
	/*-------------------------------------*/
	command = S_TRANS;
	request.rq_p1.secmode = trans_mode;
	bstring.nbytes = sc_command->noctets;
	bstring.bytes = sc_command->octets;
	request.rq_datafield.sccommand = &bstring;

	/* call create_trans			  */
	if (create_trans(sct_id, FALSE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => transfer response message      */
	/* from SC into sc_response       */
	/*----------------------------------------------*/
	sc_response->noctets = response.nbytes;
	if ((sc_response->octets = (char *) malloc(sc_response->noctets)) == NULL) {
		sca_errno = M_EMEMORY;
		set_errmsg();
		sta_aux_bytestr_free(&response);
		return (-1);
	}
	for (i = 0; i < sc_response->noctets; i++)
		sc_response->octets[i] = response.bytes[i];
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "sc_response             : \n");
	fprintf(stdout, "    noctets             : %d\n", sc_response->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, sc_response->octets, sc_response->noctets, 0);
	fprintf(stdout, "\n***** Normal end of   sca_trans *****\n\n");
#endif

	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_trans	       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_create_file          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Create file on the smartcard.        	               */
/*  Sca_create_file creates a new file (MF,DF,SF or EF) on     */
/*  the smartcard. 					       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_cat                  File category(MF,DF,SF,EF)      */
/*							       */
/*   file_type		       Elementary file type            */
/*			       (PEF,ACF,ISF,WEF)	       */
/*   data_struc                Data structure of the EF        */
/* 			       (LIN_FIX,LIN_VAR,CYCLIC,        */
/*			        TRANSPAREN)		       */
/*   file_control_info         File control information        */
/*						  	       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
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
/*							       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_create_file(sct_id, file_cat, file_type, data_struc, file_control_info,
		sec_mess)
	int             sct_id;
	FileCat         file_cat;
	FileType        file_type;
	DataStruc       data_struc;
	FileControlInfo *file_control_info;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/



	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_create_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_filecat(file_cat);
	print_filetype(file_type, NULL);
	fprintf(stdout, "                          set to 0x00 in case of MF,DF or SF\n");

	print_datastruc(data_struc);
	fprintf(stdout, "                          set to 0x00 in case of MF,DF or SF\n");

	print_filecontinfo(file_cat, file_control_info);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* check / set parameter              */
	/*-------------------------------------*/
	if (file_cat < EF) {
		file_type = 0x00;
		data_struc = 0x00;
		file_control_info->readwrite = 0x00;
	}
	if (((file_cat == EF) &&
	     ((data_struc != LIN_FIX) && (data_struc != CYCLIC))) ||
	    (file_cat <= SF))
		file_control_info->recordsize = 0;




	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);

	/*-------------------------------------*/
	/* create SC command CREATE           */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_CREATE, sec_mess))
		return (-1);

	/* set parameters			  */
	SCCREATE.filecat = file_cat;
	SCCREATE.filetype = file_type;
	SCCREATE.datastruc = data_struc;
	SCCREATE.filecontrolinfo = file_control_info;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_create_file *****\n\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_create_file	       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_register             VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Registering of applications.         	               */
/*  With sca_register a DF which shall be created must be      */
/*  registered on the smartcard.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   DF_name                   Name of the DF                  */
/*							       */
/*   memory_units	       Number of units required for    */
/*			       this DF           	       */
/*   auth_key_id               Unused in the current version   */
/*			                 		       */
/*   sec_status                Security status to protect the  */
/*			       creation			       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_register(sct_id, DF_name, memory_units, auth_key_id, sec_status,
	     sec_mess)
	int             sct_id;
	char           *DF_name;
	int             memory_units;
	KeyId          *auth_key_id;
	char            sec_status;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_register *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	fprintf(stdout, "DF_name                 : %s\n", DF_name);
	fprintf(stdout, "memory_units            : %d\n", memory_units);
	fprintf(stdout, "auth_key_id             : unused in this version\n");
	fprintf(stdout, "sec_status              : %x\n", sec_status);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);

	/*-------------------------------------*/
	/* set parameter, which are unused in */
	/* this version                       */
	/*-------------------------------------*/
	auth_key_id->key_level = 0;
	auth_key_id->key_number = 0;

	/*-------------------------------------*/
	/* create SC command REGISTER         */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_REGISTER, sec_mess))
		return (-1);


	/* set parameters			  */
	SCREG.units = memory_units;
	SCREG.kid = auth_key_id;
	SCREG.acv = sec_status & 0xFF;
	SCREG.fn = DF_name;

	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_register *****\n\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_register	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_select_file          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Select file on the smartcard.         	               */
/*  Sca_select_file will be used to select the file (MF,DF or  */
/*  SF) on the smartcard and to set the smartcard in the       */
/*  context of this file.				       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_cat                  File category (MF,DF,SF         */
/*							       */
/*   file_name                 File name                       */
/*			                         	       */
/*   sel_control_par           Unused in the current version   */
/*			                 		       */
/*   file_info_req             File information requested      */
/*			       (NONE or SHORT)		       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*   file_info                 Returned file information       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 M_EOUTDAT		       */
/*                               M_EMEMORY                     */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_select_file(sct_id, file_cat, file_name, sel_control_par, file_info_req,
		file_info, sec_mess)
	int             sct_id;
	FileCat         file_cat;
	char           *file_name;
	char            sel_control_par;
	FileInfoReq     file_info_req;
	FileInfo       *file_info;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_select_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_filecat(file_cat);
	fprintf(stdout, "file_name               : %s\n", file_name);
	fprintf(stdout, "sel_control_par         : unused in this version\n");
	print_inforeq(file_info_req);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);

	/*-------------------------------------*/
	/* set parameter, which are unused in */
	/* this version                       */
	/*-------------------------------------*/
	sel_control_par = 0x00;

	/*-------------------------------------*/
	/* create SC command SELECT           */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_SELECT, sec_mess))
		return (-1);


	/* set parameters			  */
	SCSELECT.id = file_cat;
	SCSELECT.fi = file_info_req;
	SCSELECT.scp = sel_control_par & 0xFF;
	SCSELECT.fn = file_name;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);



	/* if file_info_req == SHORT_INFO => get file information */
	if (file_info_req == SHORT_INFO) {
		if (response.nbytes != 5) {	/* addinfo = 4 + 1 byte FSTAT */
			sca_errno = M_EOUTDAT;
			set_errmsg();
			sta_aux_bytestr_free(&response);
			return (-1);
		} else {
			/* create file_info->file_status */
			file_info->file_status.install_status = get_bits((unsigned) response.bytes[4], 2, 1);
			file_info->file_status.file_memory = get_bits((unsigned) response.bytes[4], 1, 6);
			file_info->file_status.file_access = get_bits((unsigned) response.bytes[4], 1, 7);

			/* create file_info->addinfo      */
			file_info->addinfo.noctets = response.nbytes - 1;
			if ((file_info->addinfo.octets = (char *) malloc(file_info->addinfo.noctets)) == NULL) {
				sca_errno = M_EMEMORY;
				set_errmsg();
				sta_aux_bytestr_free(&response);
				return (-1);
			} else {
				for (i = 0; i < file_info->addinfo.noctets; i++)
					file_info->addinfo.octets[i] = response.bytes[i];


			}
		}
	}
	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	if (file_info_req != NONE_INFO) {
		fprintf(stdout, "file_status             : %d\n", sct_id);
		switch (file_info->file_status.install_status) {
		case REGISTERED:
			fprintf(stdout, "    install_status      : REGISTERED\n");
			break;
		case DELETED:
			fprintf(stdout, "    install_status      : DELETED\n");
			break;
		case DEL_PENDING:
			fprintf(stdout, "    install_status      : DEL_PENDING\n");
			break;
		case INSTALLED:
			fprintf(stdout, "    install_status      : INSTALLED\n");
			break;
		default:
			fprintf(stdout, "    install_status      : undefined\n");
			break;
		}
		switch (file_info->file_status.file_memory) {
		case MEM_CONSISTENT:
			fprintf(stdout, "    file_memory         : MEM_CONSISTENT\n");
			break;
		case MEM_INCONSISTENT:
			fprintf(stdout, "    file_memory         : MEM_INCONSISTENT\n");
			break;
		default:
			fprintf(stdout, "    file_memory         : undefined\n");
			break;
		}
		switch (file_info->file_status.file_access) {
		case FILE_UNLOCKED:
			fprintf(stdout, "    file_access         : FILE_UNLOCKED\n");
			break;
		case FILE_LOCKED:
			fprintf(stdout, "    file_access         : FILE_LOCKED\n");
			break;
		default:
			fprintf(stdout, "    file_access         : undefined\n");
			break;
		}

		fprintf(stdout, "addinfo                 : ");
		for (i = 0; i < file_info->addinfo.noctets; i++)
			fprintf(stdout, "%c", file_info->addinfo.octets[i]);
		fprintf(stdout, "\n");
	} else
		fprintf(stdout, "file_info_req           : no output data \n");
	fprintf(stdout, "\n***** Normal end of   sca_select_file *****\n\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_select_file	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_close_file           VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Close file on the smartcard.         	               */
/*  Sca_close_file closes the specified file and also all files*/
/*  belonging to the related file.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_cat                  File category (MF,DF,SF         */
/*							       */
/*   file_sel                  File name / File identifier     */
/*			                         	       */
/*   file_close_context        Close context                   */
/*			       (CLOSE_CREATE or CLOSE_SELECT)  */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_close_file(sct_id, file_cat, file_sel, file_close_context,
	       sec_mess)
	int             sct_id;
	FileCat         file_cat;
	FileSel        *file_sel;
	FileCloseContext file_close_context;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_close_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_filecat(file_cat);
	print_filesel(file_cat, file_sel);
	print_closecontext(file_close_context);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command CLOSE            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_CLOSE, sec_mess))
		return (-1);


	/* set parameters			  */
	SCCLOSE.filecat = file_cat;
	SCCLOSE.context = file_close_context;
	SCCLOSE.file_sel = file_sel;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_close_file *****\n\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_close_file	       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_lock_file            VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Lock working elementary file on the smartcard.             */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_lock_file(sct_id, file_id, sec_mess)
	int             sct_id;
	FileId         *file_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_lock_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_LOCKF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCLOCKF.fid = file_id;
	SCLOCKF.co = CO_LOCK;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_lock_file *****\n\n");
#endif

	return (0);






}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_lock_file	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_unlock_file          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Unlock working elementary file on the smartcard.           */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   file_name                 File name                       */
/*			                         	       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_unlock_file(sct_id, file_id, sec_mess)
	int             sct_id;
	FileId         *file_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_unlock_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_LOCKF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCLOCKF.fid = file_id;
	SCLOCKF.co = CO_UNLOCK;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_unlock_file *****\n\n");
#endif

	return (0);






}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_unlock_file	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_delete_file          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Delete file on the smartcard.         	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_cat                  File category (MF,DF,SF )       */
/*							       */
/*   file_sel                  File name / File identifier     */
/*			                         	       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
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
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
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
/*							       */
/*-------------------------------------------------------------*/
int
sca_delete_file(sct_id, file_cat, file_sel, sec_mess)
	int             sct_id;
	FileCat         file_cat;
	FileSel        *file_sel;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_delete_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_filecat(file_cat);
	print_filesel(file_cat, file_sel);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_DELF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCDELFILE.filecat = file_cat;
	SCDELFILE.file_sel = file_sel;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_delete_file *****\n\n");
#endif

	return (0);





}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_delete_file	       */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  create_trans             VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Create SC command and send it via S_TRANS 	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   flag                      if flag = TRUE =>               */
/*    				       - create sc_command     */
/*                                     - check sc_response     */
/*                             if flag = FALSE =>              */
/*                                   only in case of sca_trans */
/*				     don't check sc_response   */
/* OUT							       */
/*   common variable response				       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_interface	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               EPARMISSED                    */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  sc_create                  ERROR_Codes		       */
/*                               EPARINC                       */
/*			         EMEMAVAIL                     */
/*                               ETOOLONG		       */
/*    							       */
/*  sc_check		       ERROR-Codes		       */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*  err_analyse		      ERROR_Codes	               */
/*				ENOSHELL		       */
/*                              EOPERR                         */
/*			        EEMPTY                         */
/*                              ECLERR                         */
/*                              ESIDUNK                        */
/*                              ERDERR                         */
/*							       */
/*-------------------------------------------------------------*/
int
create_trans(sct_id, flag)
	int             sct_id;
	Boolean         flag;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	Boolean         sec_mode;
	int             ssc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sec_mode = FALSE;

	if (flag == TRUE) {

		/*
		 * call sc_create ; in case of no error sc_apdu.bytes must be
		 * set free
		 */
		if (sc_create(&sc_param, sec_mode, ssc, &sc_apdu) == -1) {
			/* error  => release sc_apdu and return */
			sca_errno = sc_errno;
			sca_errmsg = sc_errmsg;
			return (-1);
		}
		/*--------------------------------------------*/
		/* prepare parameters for the S_TRANS-command */
		/*--------------------------------------------*/
		command = S_TRANS;
		request.rq_p1.secmode = SECURE;

		request.rq_datafield.sccommand = &sc_apdu;
	}
	/*-------------------------------------*/
	/* send SC command via S_TRANS         */
	/*-------------------------------------*/

	/* call sct_interface		  */
	if (sct_interface(sct_id, command, &request, &response) == -1) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		if (flag == TRUE)
			sta_aux_bytestr_free(&sc_apdu);
		/* error => call err_analyse  */
		err_analyse(sct_id);
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* normal end => release storage of sc_apdu.bytes      */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&sc_apdu);


	if (flag == TRUE) {
		/*-------------------------------------*/
		/* check SC response                   */
		/*-------------------------------------*/
		if (sc_check(&response) == -1) {
			sca_errno = sc_errno;
			sca_errmsg = sc_errmsg;
			if ((sca_errno == EDATAINC_CLPEN) && (SCCMD == SC_READF) &&
			    (response.nbytes != 0)) {
				/* data inconsistency, but data received */
				return (-1);
			}
			/* error => release buffer and return */
			sta_aux_bytestr_free(&response);
			return (-1);
		}
	}
	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	create_trans	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  cr_header                VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Create Header of SC command         	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   ins		       Instruction code		       */
/*                                                             */
/*   sec_mess                  security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sec_mess	       ERROR-Codes	               */
/*                               M_ESECMESS		       */
/*-------------------------------------------------------------*/
int
cr_header(ins, sec_mess)
	int             ins;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	/*-------------------------------------*/
	/* check sec_mess                      */
	/*-------------------------------------*/
	if (check_sec_mess(sec_mess))
		return (-1);


	/* set instruction code		  */
	SCCMD = ins;

	/* set security modes		  */
	SCHEAD.security_mess.command = sec_mess->command;
	SCHEAD.security_mess.response = sec_mess->response;

	/* set command set			  */
	SCHEAD.cmd_class = SC_NON_INTER;	/* non interindustry command
						 * set */


	return (0);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	cr_header              */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  get_bits                 VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Get n bits from position p.         	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   x  		       1 byte   		       */
/*                                                             */
/*   n                         number of bits                  */
/*							       */
/*   p                         position                        */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
 /* n-bit field of x that begins at position p                *//*-------------------------------------------------------------*/
unsigned int
get_bits(x, n, p)
	unsigned int    x;
	unsigned int    n;
	unsigned int    p;

{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	return ((x >> (p + 1 - n)) & ~(~0 << n));
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	get_bits               */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-stasc 	       */
/*-------------------------------------------------------------*/
