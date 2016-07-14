/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 1.0		                             +-----*/
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-stadevice                            VERSION 1.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	stadevice.c                       		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides all functions for device handling, the                 */
/*      SCT display  and secure messaging between DTE and SCT                      */
/*      of the smartcard application interface                                     */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*      Functions for Device Handling						   */
/*	sca_init_sc()	      Request and initialize a smartcard	           */
/*							                           */
/*	sca_get_sc_info()     Get information about smartcard                      */
/*							                           */
/*	sca_get_sct_info()    Get information about registered SCTs 	           */
/*							                           */
/*	sca_eject_sc()	      Eject smartcard	                                   */
/*							                           */
/*      Function for SCT-Display						   */
/*	sca_display()	      Print text on SCT display                            */
/*      									   */
/*      Function for Secure Messaging						   */
/*	sca_set_mode()	      Set security mode                                    */
/*                                                                                 */
/*									           */
/*      get_sct_keyid         check key_id and get key_id in char representation   */
/*							                           */
/*      get_sct_algid	      check alg_id and get SCT specific alg_id             */
/*                                                                                 */
/*      check_sct_sc()        check SCT and SC                                     */
/*                                                                                 */
/*      check_key_attr_list() check key attribute list                             */
/*                                                                                 */
/*      check_sec_mess()      check security mode(s) for command and response      */
/*                                                                                 */
/*      set_errmsg()          sets sca_errmsg                                      */
/*                                                                                 */
/*      err_analyse()         error analyse and handling                           */
/*                                                                                 */
/*      sca_errno             global error variable                                */
/*                                                                                 */
/*      sca_errmsg            global pointer to error message                      */
/*							                           */
/*    IMPORT		    DESCRIPTION 		                           */
/*                                 -  aux_xdmp.c (libcrypt)                        */
/*                                                                                 */
/*	aux_fxdump()                  dump buffer in File	                   */
/*							                           */
/*                                 -  sta_free.c (libsm)                           */
/*                                                                                 */
/*      sta_aux_bytestr_free()        set the bytes-buffer in Bytestring free      */
/*                                                                                 */
/*                                 -  aux_util.c (libcrypt)                        */
/*                                                                                 */
/*	aux_cmp_ObjId()               compare two object_ids (part of alg_id)      */
/*                                                                                 */
/*							                           */
/*				   -  sctint.c (libsm)                             */
/*							                           */
/*      sct_reset()                   Reset Smartcard Terminal                     */
/*							                           */
/*      sct_interface()               Send SCT command / receive SCT response      */
/*							                           */
/*      sct_perror()                  Print error message                          */
/*							                           */
/*      sct_get_errmsg()              Set sct_errmsg according to error number     */
/*							                           */
/*      sct_info()                    information about sct/sc                     */
/*							                           */
/*      sct_list()                    list of installed sct's                      */
/*                                                                                 */
/*      sct_errno                     global error variable set by SCT-interface   */
/*							                           */
/*      sct_errmsg                    global pointer to error message set by       */
/*                                    SCT-interface                                */
/*                                                                                 */
/*                                                                                 */
/*    INTERNAL                                                                     */
/*                                                                                 */
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
#else
#include <stdlib.h>
#endif /* !MAC */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/

extern int      sct_reset();
extern int      sct_interface();
extern int      sct_perror();
extern void     sct_get_errmsg();
extern int      sct_info();
extern int      sct_list();
extern int      aux_cmp_ObjId();
extern void     sta_aux_bytestr_free();
extern void     aux_fxdump();
extern unsigned int sct_errno;	/* error number set by SCT-Interface */
extern char    *sct_errmsg;	/* pointer to error msg set by      */

 /* SCT-Interface                    */



/*-------------------------------------------------------------*/
/*   forward global declarations			       */
/*-------------------------------------------------------------*/
char            get_sct_keyid();
char            get_sct_algid();
void            err_analyse();


/*-------------------------------------------------------------*/
/*   globale variable definitions			       */
/*-------------------------------------------------------------*/
unsigned int    sca_errno;	/* error number set by STAMOD       */
char           *sca_errmsg;	/* pointer to error message set by  */

 /* STAMOD                           */






/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/
#define BITNULL		(BitString *)0




/*-------------------------------------------------------------*/
/*   local Variable definitions			               */
/*-------------------------------------------------------------*/
static Request  request;	/* body of the SCT commands         */
static Bytestring response;	/* body of the response of the SCT  */
static int      command;	/* INS-Code of the SCT command      */
static SCTInfo  sctinfo;	/* structure of sct_info-parameter  */
static Boolean  sc_expect;	/* = TRUE indicates: SC expected    */

 /* = FALSE indicates: SC not needed */
static Boolean  first_call = TRUE;	/* In case of first_call = TRUE     */

 /* sct_reset will be called         */





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_init_sc	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Request and initialize a smartcard.		               */
/*  Sca_init_sc has to be the first function to be called      */
/*  before the communication with the smartcard is             */
/*  possible.                                                  */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   display_text              text which shall be             */
/*                             displayed on the SCT-           */
/*                             display or the NULL-Pointer     */
/*   time_out                  Time-out in seconds             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 EEXECDEN		       */
/*                               M_ETIME		       */
/*                               M_ETEXT		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_info                   ERROR-Codes		       */
/*			         ESIDUNK		       */
/*							       */
/*  sct_reset		       ERROR-Codes		       */
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
/*							       */
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
int
sca_init_sc(sct_id, display_text, time_out)
	int             sct_id;
	char           *display_text;
	int             time_out;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	Bytestring      bstring;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_init_sc *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	fprintf(stdout, "display_text: %s\n", display_text);
	fprintf(stdout, "time_out(sec): %d\n", time_out);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	if (display_text != NULL) {
		if (strlen(display_text) > MAXL_SCT_DISPLAY) {
			sca_errno = M_ETEXT;
			set_errmsg();
			return (-1);
		}
	}
	if ((time_out < 0) || (time_out > MAX_TIME)) {
		sca_errno = M_ETIME;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* If first call == TRUE			       */
	/* then reset SCT				       */
	/*-----------------------------------------------------*/
	if (first_call == TRUE) {
		rc = sct_reset(sct_id);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			return (-1);
		}
		first_call = FALSE;
	}
	/*-----------------------------------------------------*/
	/* If SCT not initialized			       */
	/* then reset SCT				       */
	/* else if SC already inserted		       */
	/* then return(EEXECDEN).                 */
	/*-----------------------------------------------------*/
	rc = sct_info(sct_id, &sctinfo);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		return (-1);
	}
	if (sctinfo.port_open == FALSE) {	/* if port not open       */
		rc = sct_reset(sct_id);	/* then reset port        */
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			return (-1);
		}
	}
	/* end if */
	else {
		if (sctinfo.sc_request == TRUE) {	/* if sc already
							 * inserted */
			sca_errno = EEXECDEN;	/* then execution denied  */
			set_errmsg();
			return (-1);
		}
	}			/* end else */

	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_REQUEST_SC;
	request.rq_p2.time = time_out;
	if (display_text == NULL)
		request.rq_datafield.outtext = BYTENULL;
	else {
		bstring.nbytes = strlen(display_text);
		bstring.bytes = display_text;
		request.rq_datafield.outtext = &bstring;
	}

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
	fprintf(stdout, "\n***** Normal end of   sca_init_sc *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_init_sc */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_init_sc	       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_get_sc_info         VERSION   1.0	    	       */
/*				     DATE   Juni 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Get information about smartcard      		       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*							       */
/* OUT							       */
/*   sc_info                   historical characters           */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k                             */
/*  -1			       error			       */
/*				 ENOCARD		       */
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
/*-------------------------------------------------------------*/
int
sca_get_sc_info(sct_id, sc_info)
	int             sct_id;
	OctetString    *sc_info;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc, i;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_get_sc_info *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
#endif


	/*-------------------------------------*/
	/* call sct_info                      */
	/*-------------------------------------*/

#ifdef PROCDAT

	/* 
	 *  "sct_info()"   calls "get_idelem()", 
	 *  "get_idelem()" calls "sca_read_SCT_config()", which calls "COMinit()"
	 *  If "COMinit()" fails, the calling function should get the error code.
         *  
	 */
	rc = sct_info(sct_id, &sctinfo);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		return (-1);
	}
#else
	sct_info(sct_id, &sctinfo);
#endif


	/*-------------------------------------*/
	/* get historical characters out of   */
	/* sctinfo-structure		  */
	/*-------------------------------------*/
	if ((sctinfo.history_sc == NULL) ||
	    ((sc_info->noctets = strlen(sctinfo.history_sc)) == 0)) {
		sca_errno = ENOCARD;
		set_errmsg();
		return (-1);
	}
	if ((sc_info->octets = (char *) malloc(sc_info->noctets)) == NULL) {
		sca_errno = M_EMEMORY;
		set_errmsg();
		return (-1);
	}
	for (i = 0; i < sc_info->noctets; i++)
		*(sc_info->octets + i) = *(sctinfo.history_sc + i);





#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "sc_info                 : \n");
	fprintf(stdout, "    noctets             : %d\n", sc_info->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, sc_info->octets, sc_info->noctets, 0);
	fprintf(stdout, "\n***** Normal end of   sca_get_sc_info *****\n\n");
#endif


	return (0);

}				/* end sca_get_sc_info */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_get_sc_info        */
/*-------------------------------------------------------------*/



/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_get_sct_info         VERSION   1.0	    	       */
/*				     DATE   Juni 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Get information about registered SCT's.		       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   n	         	       number of registered SCT's      */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_list                   ERROR-Codes		       */
/*				 ENOSHELL		       */
/*                               EOPERR 		       */
/*                               EEMPTY 		       */
/*				 EMEMAVAIL		       */
/*				 ECLERR			       */
/*			         ESIDUNK		       */
/*							       */
/*							       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_get_sct_info()
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_get_sct_info *********************************************\n\n");
#endif

	rc = sct_list();
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		return (-1);
	}
#ifdef TEST
	fprintf(stdout, "output-parameters:\n");
	fprintf(stdout, "No. of SCT's : %d\n", rc);
	fprintf(stdout, "\n***** Normal end of   sca_get_sct_info *********************************************\n\n");
#endif

	return (rc);

}				/* end sca_get_sct_info */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_get_sct_info       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_eject_sc	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Eject smartcard.				               */
/*  A smartcard must be inserted 			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   display_text              text which shall be             */
/*                             displayed on the SCT-           */
/*                             display or the NULL-Pointer     */
/*   alarm                     = TRUE - acoustic alarm signal  */
/*                             = FALSE - no alarm signal       */
/* OUT							       */
/*							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_EALARM		       */
/*                               M_ETEXT		       */
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
int
sca_eject_sc(sct_id, display_text, alarm)
	int             sct_id;
	char           *display_text;
	Boolean         alarm;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	Bytestring      bstring;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = TRUE;	/* this function needs the SC */

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_eject_sc *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	fprintf(stdout, "display_text: %s\n", display_text);
	if (alarm == TRUE)
		fprintf(stdout, "alarm switched on\n");
	else
		fprintf(stdout, "alarm switched off\n");
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
	if (display_text != NULL) {
		if (strlen(display_text) > MAXL_SCT_DISPLAY) {
			sca_errno = M_ETEXT;
			set_errmsg();
			return (-1);
		}
	}
	if ((alarm != TRUE) && (alarm != FALSE)) {
		sca_errno = M_EALARM;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_EJECT_SC;
	request.rq_p2.signal = alarm;
	if (display_text == NULL)
		request.rq_datafield.outtext = BYTENULL;
	else {
		bstring.nbytes = strlen(display_text);
		bstring.bytes = display_text;
		request.rq_datafield.outtext = &bstring;
	}

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
	fprintf(stdout, "\n***** Normal end of   sca_eject_sc *********************************************\n\n");
#endif

	sct_close(sct_id);
	return (sca_errno);

}				/* end sca_eject_sc */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_eject_sc	       */
/*-------------------------------------------------------------*/





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_display	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Print text on SCT-display			               */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   display_text              text which shall be             */
/*                             displayed on the SCT-           */
/*                             display or the NULL-Pointer     */
/*   time_out                  Time-out in seconds             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_ETIME		       */
/*                               M_ETEXT		       */
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
int
sca_display(sct_id, display_text, time_out)
	int             sct_id;
	char           *display_text;
	int             time_out;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;
	Bytestring      bstring;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = FALSE;	/* this function doesn't need a SC */

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_display *********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	fprintf(stdout, "sct_id:     %d\n", sct_id);
	fprintf(stdout, "display_text: %s\n", display_text);
	fprintf(stdout, "time_out(sec): %d\n", time_out);
	fprintf(stdout, "\n\n");
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc                                  */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameters			       */
	/*-----------------------------------------------------*/
	if (display_text != NULL) {
		if (strlen(display_text) > MAXL_SCT_DISPLAY) {
			sca_errno = M_ETEXT;
			set_errmsg();
			return (-1);
		}
	}
	if ((time_out < 0) || (time_out > MAX_TIME)) {
		sca_errno = M_ETIME;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Prepare parameters for the SCT Interface          */
	/*-----------------------------------------------------*/
	command = S_DISPLAY;
	request.rq_p2.time = time_out;
	if (display_text == NULL)
		request.rq_datafield.outtext = BYTENULL;
	else {
		bstring.nbytes = strlen(display_text);
		bstring.bytes = display_text;
		request.rq_datafield.outtext = &bstring;
	}

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
	/* Normal End	  (Release storage)		       */
	/*-----------------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_display *********************************************\n\n");
#endif

	return (sca_errno);

}				/* end sca_display */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_display	       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_set_mode	          VERSION   1.0	    	       */
/*				     DATE   Juni 1992	       */
/*			      	       BY   L.Eckstein         */
/*							       */
/* DESCRIPTION						       */
/*  Set security mode    			               */
/*  A smartcard is not expected.			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_ETIME		       */
/*                               M_ETEXT		       */
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
int
sca_set_mode(sct_id, sec_mess)
	int             sct_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;
	sca_errno = M_NOERR;
	sca_errmsg = NULL;
	sc_expect = FALSE;	/* this function doesn't need a SC */

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_set_mode *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id		        : %d\n", sct_id);
	print_secmess(sec_mess);
#endif

	/*-----------------------------------------------------*/
	/* call check_sct_sc                                  */
	/*-----------------------------------------------------*/
	if (check_sct_sc(sct_id, sc_expect) == -1)
		return (-1);

	/*-----------------------------------------------------*/
	/* Check input parameter sec_mess		       */
	/*-----------------------------------------------------*/
	if ((sec_mess->command != SEC_NORMAL) &&
	    (sec_mess->command != CONCEALED)) {
		sca_errno = M_ESECMESS;
		set_errmsg();
		return (-1);
	}
	if ((sec_mess->response != SEC_NORMAL) &&
	    (sec_mess->response != CONCEALED)) {
		sca_errno = M_ESECMESS;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* if sec_mess = CONCEALED check sessionkey	       */
	/*-----------------------------------------------------*/
	if ((sec_mess->command == CONCEALED) ||
	    (sec_mess->response == CONCEALED)) {

		/*----------------------------------------------*/
		/* test, if sessionkey available		 */
		/*----------------------------------------------*/
		rc = sct_info(sct_id, &sctinfo);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			return (-1);
		}
		rc = sct_secure(sct_id);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			return (-1);
		}
	}
	/*-----------------------------------------------------*/
	/* Store security mode in port-memory                */
	/*-----------------------------------------------------*/
	rc = sct_setmode(sct_id, sec_mess);
	if (rc < 0) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		return (-1);
	}
#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_set_mode *****\n\n");
#endif

	return (0);


}				/* end sca_set_mode */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_set_mode	       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  check_sct_sc             VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Check, if SCT initialized and SC inserted 	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*   sc_expect		       = TRUE => SC is expected        */
/*   			       = FALSE => SC is not expected   */
/*                                                             */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               ENOCARD		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_info                   ERROR-Codes		       */
/*			         ESIDUNK		       */
/*							       */
/*  sct_reset		       ERROR-Codes		       */
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
/*-------------------------------------------------------------*/
int
check_sct_sc(sct_id, sc_expect)
	int             sct_id;
	Boolean         sc_expect;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	/*-------------------------------------*/
	/* if first_call = TRUE               */
	/* then reset SCT                  */
	/*-------------------------------------*/
	if (first_call == TRUE) {
		rc = sct_reset(sct_id);
		if (rc < 0) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			return (-1);
		}
		first_call = FALSE;
	}
	/*-------------------------------------*/
	/* call sct_info                      */
	/*-------------------------------------*/
	if (sct_info(sct_id, &sctinfo) == -1) {
		sca_errno = sct_errno;
		sca_errmsg = sct_errmsg;
		return (-1);
	}
	/*-------------------------------------*/
	/* test, if port open                 */
	/*-------------------------------------*/
	if (sctinfo.port_open == FALSE) {
		/* port not open => call sct_reset */
		if (sct_reset(sct_id) == -1) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
			err_analyse(sct_id);
			return (-1);
		}
		if (sc_expect == TRUE) {
			sca_errno = ENOCARD;
			set_errmsg();
			return (-1);
		}
	}
	/*-------------------------------------*/
	/* function only allowed, if smartcard */
	/* already requested.                 */
	/* Therefore test, if smartcard is    */
	/* inserted				  */
	/*-------------------------------------*/
	if ((sc_expect == TRUE) && (sctinfo.sc_request == FALSE)) {
		/* error => smartcard not requested */
		sca_errno = ENOCARD;
		set_errmsg();
		return (-1);
	}
	/*-------------------------------------*/
	/* normal end                          */
	/*-------------------------------------*/
	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	check_sct_sc	       */
/*-------------------------------------------------------------*/





/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  get_sct_keyid       VERSION   1.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                     U.Viebeg,GMD       */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check key_id of SCA-IF and                            */
/*  transform key_id of SCA-IF to one character, which is */
/*  used at the SCT-IF.				          */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   kid                       kid structure              */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      SCT specific key-id        */
/*                                                        */
/*   -1                        error                      */
/*                               EINVKID                  */
/*--------------------------------------------------------*/
char
get_sct_keyid(kid)
	KeyId          *kid;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char            kidvalue;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((kid->key_number <= 0) || (kid->key_number > 63) ||
	    ((kid->key_level != SC_MF) &&
	     (kid->key_level != SC_DF) &&
	     (kid->key_level != SC_SF) &&
	     (kid->key_level != SCT))) {
		sca_errno = EINVKID;
		set_errmsg();
		return (-1);
	}
	kidvalue = (((char) kid->key_number & 0xFF) << 2) |
		((char) kid->key_level & 0xff);

#ifdef TEST
	fprintf(stdout, "key_id_char: ");
	aux_fxdump(stdout, &kidvalue, 1, 0);
	fprintf(stdout, "\n");
#endif

	return (kidvalue);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      get_sct_keyid          */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  get_sct_algid       VERSION   1.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                     U.Viebeg,GMD       */
/*							                           */
/*	Achtung: AlgId = DES-3 is still missing		                           */
/*							                           */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check alg_id of SCA-IF and                            */
/*  transform  alg_id of SCA-IF to SCT specific alg_id,   */
/*  which is used at the SCT-IF.		          */
/*  In case of RSA keysize is checked: allowed values are */
/*  256, 512 bits.               	                  */
/*                                                        */
/*  alg_id	is transformed to 	sct_algid:        */
/*  ------                              ----------        */
/*  rsa			->		S_RSA_F4          */
/*  sqmodnWithRsa	->		S_RSA_F4          */
/*  md2WithRsa		->		S_RSA_F4          */
/*  md4WithRsa		->		S_RSA_F4          */
/*  md5WithRsa		->		S_RSA_F4          */
/*  desCBC		->		S_DES_CBC         */
/*  missing		->		S_DES_3_CBC       */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   algid                     algid structure            */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      Value of Byte              */
/*                                                        */
/*   -1                        error                      */
/*                               EINVALGID                */
/*                               EKEYLENINV               */
/*                                                        */
/*                                                        */
/*  CALLED FUNCTIONS                                      */
/*    aux_cmp_ObjId              ERROR-Codes                */
/*    		                 -1 => EINVALGID          */
/*--------------------------------------------------------*/
char
get_sct_algid(algid)
	AlgId          *algid;
{
	/*----------------------------------------------------------*/
	/* Definitions                                              */
	/*----------------------------------------------------------*/
	KeyAlgId        sct_algid;
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements                                               */
	/*----------------------------------------------------------*/
	sct_algid = -1;


	/*-----------------------------------------------------*/
	/* aux_cmp_ObjId returns 0 if objids are equal         */
	/* aux_cmp_ObjId returns 1 if objids are not equal     */
	/*-----------------------------------------------------*/
	if ((!algid) || (!algid->objid)) {
		sca_errno = EINVALGID;
		set_errmsg();
		return (-1);
	}
/* 17.11.92 WS
	if (((rc = aux_cmp_ObjId(algid->objid, rsa->objid)) == 0) ||
	  ((rc = aux_cmp_ObjId(algid->objid, sqmodnWithRsa->objid)) == 0) ||
	    ((rc = aux_cmp_ObjId(algid->objid, md2WithRsa->objid)) == 0) ||
	    ((rc = aux_cmp_ObjId(algid->objid, md4WithRsa->objid)) == 0) ||
	    ((rc = aux_cmp_ObjId(algid->objid, md5WithRsa->objid)) == 0)) {
*/
	if(aux_ObjId2AlgEnc(algid->objid) == RSA) {
		/* if RSA, then check keysize */
		if (algid->parm) {
			if ((RSA_PARM(algid->parm) != 256) &&
			    (RSA_PARM(algid->parm) != 512)) {
				sca_errno = EKEYLENINV;
				set_errmsg();
				return (-1);
			}
		}
		sct_algid = S_RSA_F4;
	} else if ((rc = aux_cmp_ObjId(algid->objid, desCBC->objid)) == 0) {
		sct_algid = S_DES_CBC;
	} else {
		if ((rc = aux_cmp_ObjId(algid->objid, desCBC3->objid)) == 0) {
			sct_algid = S_DES_3_CBC;
		} else {
			sca_errno = EINVALGID;
			set_errmsg();
			return (-1);
		}
	};


#ifdef TEST
	fprintf(stdout, "SCT algid: %d\n ", sct_algid);
#endif

	return (sct_algid);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      get_sct_algid          */
/*-------------------------------------------------------------*/






/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/*   check_key_attr_list      VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Ursula Viebeg      */
/*							       */
/* DESCRIPTION						       */
/*  Check key attribute list for user keys, device keys, PIN   */
/*  and PUK. 						       */
/*  In case of a user key,PIN or PUK the value of key_purpose  */
/*  is set by  this function.				       */
/*  The MAC_length is automatically set to 4.                  */
/*  If the key is not an authentication key, key_fpc will be   */
/*  set to 0 by this function.				       */
/*  In case of PIN or PUK, key_status.PIN_check is checked,    */
/*  otherwise key_status.PIN_check is set to FALSE.            */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   kind_of_key	       {USER_KEY, PIN_KEY, PUK_KEY     */
/*                              DEVICE_KEY}                    */
/*                                                             */
/*   key_attr_list	       pointer to the list of the key  */
/*                             attributes                      */
/*							       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_EKEYATTR		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  set_errmsg						       */
/*-------------------------------------------------------------*/
int
check_key_attr_list(kind_of_key, key_attr_list)
	KindOfKey       kind_of_key;
	KeyAttrList    *key_attr_list;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
#define PURPOSE   key_attr_list->key_attr.key_purpose
#define PRESENT   key_attr_list->key_attr.key_presentation
#define OPMODE    key_attr_list->key_attr.key_op_mode
#define MACLEN    key_attr_list->key_attr.MAC_length

	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* Check key attr list     			       */
	/*-----------------------------------------------------*/
	if (key_attr_list == KEYATTRNULL) {
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Check key install mode    			       */
	/*-----------------------------------------------------*/
	if ((key_attr_list->key_inst_mode != INST) &&
	    (key_attr_list->key_inst_mode != REPL)) {
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Check key purpose depending on kind of key	:      */
	/* */
	/* USER_KEY: key_purpose is set by this function:    */
	/* key_purpose.authenticate to FALSE      */
	/* key_purpose.sec_mess_auth to FALSE     */
	/* key_purpose.sec_mess_con to FALSE      */
	/* key_purpose.cipherment to TRUE         */
	/* */
	/* PIN_KEY:  key_purpose is set by this function:    */
	/* key_purpose.authenticate to TRUE       */
	/* key_purpose.sec_mess_auth to FALSE     */
	/* key_purpose.sec_mess_con to FALSE      */
	/* key_purpose.cipherment to FALSE        */
	/* */
	/* */
	/* PUK_KEY:  see PIN_KEY			       */
	/* */
	/* DEVICE_KEY: 				       */
	/* At least one of the following three     */
	/* must be set to TRUE:                    */
	/* 1) key_purpose.authenticate,           */
	/* 2) key_purpose.sec_mess_auth,          */
	/* 3) key_purpose.sec_mess_con,           */
	/* key_purpose.cipherment must be FALSE    */
	/*-----------------------------------------------------*/
	switch (kind_of_key) {
	case USER_KEY:
		PURPOSE.authenticate = FALSE;
		PURPOSE.sec_mess_auth = FALSE;
		PURPOSE.sec_mess_con = FALSE;
		PURPOSE.cipherment = TRUE;
		break;
	case PIN_KEY:
	case PUK_KEY:
		PURPOSE.authenticate = TRUE;
		PURPOSE.sec_mess_auth = FALSE;
		PURPOSE.sec_mess_con = FALSE;
		PURPOSE.cipherment = FALSE;
		break;
	case DEVICE_KEY:
		if (((PURPOSE.authenticate != TRUE) &&
		     (PURPOSE.sec_mess_auth != TRUE) &&
		     (PURPOSE.sec_mess_con != TRUE)) ||
		    (PURPOSE.cipherment != FALSE)) {
			sca_errno = M_EKEYATTR;
			set_errmsg();
			return (-1);
		}
		break;
	default:
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}			/* end case */

	/*-----------------------------------------------------*/
	/* Check key presentation    			       */
	/*-----------------------------------------------------*/
	if ((PRESENT != KEY_GLOBAL) && (PRESENT != KEY_LOCAL)) {
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Check key operation mode 			       */
	/*-----------------------------------------------------*/
	if ((OPMODE != REPLACE) && (OPMODE != NO_REPLACE)) {
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Set MAC length	 			       */
	/*-----------------------------------------------------*/
	MACLEN = 4;

	/*-----------------------------------------------------*/
	/* Check key fault presentation counter	       */
	/* If key is not an authentication key, key_fpc      */
	/* is set to 0 by this function.                     */
	/*-----------------------------------------------------*/
	if (PURPOSE.authenticate == FALSE)
		key_attr_list->key_fpc = 0;
	else {
		if ((key_attr_list->key_fpc < 0) ||
		    (key_attr_list->key_fpc > MAX_KPFC)) {
			sca_errno = M_EKEYATTR;
			set_errmsg();
			return (-1);
		}
	}			/* end else */

	/*-----------------------------------------------------*/
	/* Check key status				       */
	/* If kind_of_key is not PIN or PUK,                 */
	/* key_status.PIN_check is set to FALSE.             */
	/*-----------------------------------------------------*/
	if ((kind_of_key == PIN_KEY) || (kind_of_key == PUK_KEY)) {
		if ((key_attr_list->key_status.PIN_check != FALSE) &&
		    (key_attr_list->key_status.PIN_check != TRUE)) {
			sca_errno = M_EKEYATTR;
			set_errmsg();
			return (-1);
		}
	} else
		key_attr_list->key_status.PIN_check = FALSE;
	if ((key_attr_list->key_status.key_state != KEY_NORMAL) &&
	    (key_attr_list->key_status.key_state != KEY_LOCKED)) {
		sca_errno = M_EKEYATTR;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End		   			       */
	/*-----------------------------------------------------*/
	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	check_key_attr_list    */
/*-------------------------------------------------------------*/






/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  check_sec_mess           VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Ursula Viebeg      */
/*							       */
/* DESCRIPTION						       */
/*  Check security modes for command and response   	       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sec_mess		       security mode(s)		       */
/*							       */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_ESECMESS		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  set_errmsg						       */
/*-------------------------------------------------------------*/
int
check_sec_mess(sec_mess)
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	if ((sec_mess->command != SEC_NORMAL) &&
	    (sec_mess->command != AUTHENTIC) &&
	    (sec_mess->command != CONCEALED) &&
	    (sec_mess->command != COMBINED)) {
		sca_errno = M_ESECMESS;
		set_errmsg();
		return (-1);
	}
	if ((sec_mess->response != SEC_NORMAL) &&
	    (sec_mess->response != AUTHENTIC) &&
	    (sec_mess->response != CONCEALED) &&
	    (sec_mess->response != COMBINED)) {
		sca_errno = M_ESECMESS;
		set_errmsg();
		return (-1);
	}
	/*-----------------------------------------------------*/
	/* Normal End		   			       */
	/*-----------------------------------------------------*/
	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	check_sec_mess	       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  set_errmsg	          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  sets global sca_errmsg according to the global error       */
/*  variable sca_errno                                         */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_get_errmsg                        		       */
/*							       */
/*-------------------------------------------------------------*/

int
set_errmsg()
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	unsigned int    err_no;
	int             rc;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	/*-----------------------------------------------------*/
	/* if value of sca_errno is invalid                  */
	/* then initialize sca_errno and sca_errmsg       */
	/*-----------------------------------------------------*/
	if (sca_errno <= 0) {
		sca_errno = 0;
		sca_errmsg = NULL;
		return (M_NOERR);
	}
	/*-----------------------------------------------------*/
	/* if sca_errno < MIN_STAMOD_ERRNO                   */
	/* then take error list of the SCT Interface      */
	/* else take error list of STAMOD		       */
	/*-----------------------------------------------------*/
	if (sca_errno < MIN_STAMOD_ERRNO) {
		err_no = sca_errno;	/* error from SCT-Interface */
		sct_get_errmsg(err_no);
		sca_errmsg = sct_errmsg;
	} else {		/* error from STAMOD */
		err_no = sca_errno - MIN_STAMOD_ERRNO;
		if (err_no >= 0)
			sca_errmsg = stamod_error[err_no].msg;
		else
			sca_errmsg = NULL;

	}			/* end else */

	return (0);

}				/* end set_errmsg */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	set_errmsg	       */
/*-------------------------------------------------------------*/





/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  err_analyse             VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Error analyse and error handling		               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_close                ERROR-Codes		       */
/*				ENOSHELL		       */
/*                              EOPERR                         */
/*			        EEMPTY                         */
/*                              ECLERR                         */
/*                              ESIDUNK                        */
/*                              ERDERR                         */
/*							       */
/*							       */
/*-------------------------------------------------------------*/

void
err_analyse(sct_id)
	int             sct_id;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	if (((sca_errno >= EREAD) && (sca_errno <= ESYNTAX)) ||
	    (sca_errno == ERESET) ||
	    (sca_errno == ESCTRES) ||
	    ((sca_errno >= ESCREMOVED) && (sca_errno <= EUSTIMEOUT))) {
		if (sct_close(sct_id) == -1) {
			sca_errno = sct_errno;
			sca_errmsg = sct_errmsg;
		}
	}
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	err_analyse	       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-stadevice	       */
/*-------------------------------------------------------------*/
