/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCTINT			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME					               */
/*	sctint.c		         		       */
/*							       */
/*    DESCRIPTION					       */
/*	SCT - Interface - Module			       */
/*							       */
/*    EXPORT		    DESCRIPTION 		       */
/*	sct_reset()	      Reset SmartCard terminal	       */
/*							       */
/*	sct_interface()       Send Command / receive response  */
/*							       */
/*	sct_perror()	      Print error message	       */
/*							       */
/*	sct_info()	      information about sct/sc	       */
/*							       */
/*	sct_list()	      list of installed sct's          */
/*							       */
/*      sct_close()           close port of SCT                */
/*							       */
/*      sct_secure()          set sessionkey                   */
/*							       */
/*      sct_setmode()         set security mode DTE-SCT        */
/*							       */
/*      sct_get_errmsg()      get SCT error message            */
/*              					       */
/*	sct_errno	      error number		       */
/*							       */
/*	sct_errmsg	      address of error message	       */
/*							       */
/*	sct_tester	      send sct-apdu / receive sct_apdu */
/*			      (only for sct tester )	       */
/*	sctint.h					       */
/*							       */
/*	sctrc.h 					       */
/*							       */
/*							       */
/*							       */
/*    IMPORT		    DESCRIPTION 		       */
/*							       */
/*	sta_aux_bytestr_free  release byte-buffer	       */
/*							       */
/*	sta_aux_elemlen       eleminate length field in resp.  */
/*							       */
/*	SCTcreate	      create S-Command		       */
/*							       */
/*	SCTerr		      error-handling		       */
/*							       */
/*	SCTcheck	      check 1 or 3 bytes	       */
/*							       */
/*	SCTstatus	      send S_STATUS      	       */
/*							       */
/*	SCTresponse           analyse the response	       */
/*							       */
/*	get_orgelem	      read org. element out of install */
/*			      file			       */
/*							       */
/*	get_idelem	      read element out of sct-list     */
/*							       */
/*	cr_sctlist	      create sct-list		       */
/*							       */
/*     pr_element                print sct-element if TRACE    */
/*                                                             */
/*	COMinit 	      Port-Initialisation	       */
/*							       */
/*	COMreset	      Port-Reset		       */
/*							       */
/*	COMtrans	      Transfer of S-APDU               */
/*							       */
/*	COMclose	      Close port		       */
/*							       */

/*  Aenderungen Viebeg Beginn				       */

/*   sca_write_SCT_config()	Encrypt and write configuration*/
/*				data for the specified SCT.    */
/*  Aenderungen Viebeg Ende				       */
/*							       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files					       */
/*-------------------------------------------------------------*/
#include <stdio.h>

#ifdef PROCDAT
#include "secsc.h"
#else
#include "sca.h"
#endif 	/* PROCDAT */

#include "sctint.h"
#include "sctrc.h"
#include "sctmsg.h"
#include "sctmem.h"
#include "sctport.h"
#include "error.h"		/* transmission module */

#ifdef MAC
#include "baud.h"
#endif


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/
extern unsigned int tp1_err;	/* error-variable from transmission module */
extern int      COMinit();
extern int      COMreset();
extern int      COMtrans();
extern int      COMclose();

extern struct s_portparam *p_lhead;	/* Begin of sct_list from sctmem.c */
extern struct s_portparam *get_idelem();
extern int      cr_sctlist();
extern int      get_orgelem();
extern void     pr_element();

extern void     sta_aux_bytestr_free();
extern void     sta_aux_elemlen();

extern char    *SCTcreate();
extern int      SCTerr();
extern int      SCTcheck();
extern int      SCTstatus();
extern int      SCTresponse();

#ifdef PROCDAT

extern int	sca_write_SCT_config();

#endif	/* PROCDAT */


/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/

#ifdef BSD
/* #define B19200 14 */
#include <sys/ttydev.h>
#endif

#ifdef SYSTEMV
/* #define B19200 14 */
#include <sys/ttydev.h>
#endif

#ifdef __HP__
#ifdef SYSV
#include <termio.h>
#else
#include <sgtty.h>
#endif
#endif

#define BITNULL		(BitString *)0



/*-------------------------------------------------------------*/
/*   globale variable definitions			       */
/*-------------------------------------------------------------*/
unsigned int    sct_errno;	/* error variable		 */
char           *sct_errmsg;	/* error message		 */

/*-------------------------------------------------------------*/
/*   lokale Variable definitions			       */
/*-------------------------------------------------------------*/

#ifdef STREAM
static BOOL     first = FALSE;	/* FLAG, if Trace-File open	 */
FILE           *sct_trfp;	/* Filepointer of trace file    */

#endif
static BOOL     resfirst = FALSE;	/* FLAG, if sct_reset already called */

static char     fermat_f4[3] = {'\001', '\000', '\001'};	/* public exponent                  */
static int      fermat_f4_len = 3;





/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_reset	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*  Reset Smartcard Terminal				  */
/*  If this function is called the first time, then	  */
/*  the installation file will be opened and the	  */
/*  sct-list for further use will be created.		  */
/*							  */

/*  Aenderungen Viebeg Beginn				  */
/*							  */
/*  Save SCT configuration data in a file		  */

/*  Aenderungen Viebeg Ende				  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   sct_id		       SCT identifier		  */
/* OUT							  */
/*							  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*   0	         	       o.k			  */
/*  -1			       error			  */
/*							  */
/*				ENOSHELL		  */
/*                              EOPERR                    */
/*			        EEMPTY                    */
/*                              EMEMAVAIL                 */
/*                              ECLERR                    */
/*                              ESIDUNK                   */
/*                              ERDERR                    */
/*                              EINVARG			  */
/*                              ETOOLONG		  */
/*                              sw1/sw2 from SCT response */
/*                              T1 - ERROR                */
/*                                                        */
/* CALLED FUNCTIONS					  */
/*  cr_sctlist						  */
/*  get_idelem						  */
/*  get_orgelem						  */
/*  COMinit						  */
/*  COMclose						  */
/*  COMreset						  */
/*  sct_interface					  */
/*  sta_aux_bytestr_free				  */


/*  Aenderungen Viebeg Beginn				       */

/*   sca_write_SCT_config()	Encrypt and write configuration */
/*				data for the specified SCT.     */
/*  Aenderungen Viebeg Ende				       */

/*  							  */
/*--------------------------------------------------------*/
int
sct_reset(sct_id)
	int             sct_id;	/* SCT identifier 	 */
{


	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;
	struct s_portparam *p_elem;
	unsigned int    sw1 = 0;
	Bytestring      response;
	Request         request;
	int             baud;
	int             databits;
	int             stopbits;
	char           *p;
	int             div = 19200;
	int             index;
	int             resetbaud;

#ifdef PROCDAT
	char           *proc = "sct_reset";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

#endif 	/* PROCDAT */


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	/*------------------------------------*/
	/* Initialisation			 */
	/*------------------------------------*/

	sct_errno = 0;

#ifdef STREAM
	if (!first) {
		sct_trfp = fopen("SCTINT.TRC", "wt");
		first = TRUE;
	};
#endif


	/*------------------------------------*/
	/* Create sct_list			 */
	/*------------------------------------*/
	if (!resfirst) {	/* create sct-list */
		if (cr_sctlist() == -1)
			return (S_ERR);
		resfirst = TRUE;
	};




	/*------------------------------------------*/
	/* test, if sct_id refers to a sct element  */
	/*------------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (S_ERR);	/* ERROR: sct not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_reset\n");
	pr_element(sct_trfp, p_elem);
#endif


#ifdef PROCDAT

	/*
	 *  If a previous process has already resetted the SCT and
	 *     the SC has already been inserted
         *     => don't reset port again
	 */

	if ((p_elem->sc_request == TRUE) && 
	    (p_elem->schistory != NULL) && (strlen(p_elem->schistory) != 0) &&
	    (p_elem->port_id > 0)) {
		return (S_NOERR);		/* reset already done by a previous process*/
	}


#endif 	/*PROCDAT */





	/*------------------------------------*/
	/* set sad, dad in sct_element	 */
	/*------------------------------------*/

	p_elem->sad = SAD;
	p_elem->dad = DAD;


	/*------------------------------------*/
	/* call COMinit - procedure		 */
	/*------------------------------------*/
	if (p_elem->port_id > 0)
		COMclose(p_elem->port_id);

#ifdef TRACE
	fprintf(sct_trfp, "CALL get_orgelem in sct_reset before COMinit\n");
#endif

	if (get_orgelem(sct_id, p_elem) == -1)
		return (S_ERR);

	if ((COMinit(p_elem)) == -1)
		return (SCTerr(sw1, tp1_err));

#ifdef SECSCTEST
		fprintf(stderr, "(sct_reset) Port: %d for SCT: %d opened\n", p_elem->port_id, sct_id);
#endif




	/*------------------------------------*/
	/* send RESET - Command		 */
	/*------------------------------------*/
	if (sct_interface(sct_id, S_RESET, &request, &response) == -1)
		return (S_ERR);


	/*------------------------------------*/
	/* set reset-values in p_elem	 */
	/*------------------------------------*/
	baud = p_elem->baud;
	databits = p_elem->databits;
	stopbits = p_elem->stopbits;
	p = response.bytes;
	p_elem->dataformat = *p++;
	p_elem->protocoltype = *p++;
	p_elem->bwt = *p++;
	p_elem->cwt = *p++;
	p_elem->chaining = (Chain) * p++;

	p_elem->baud = 0;
	p_elem->baud = ((((int) *p++) & 0xff) << 8);
	p_elem->baud += (((int) *p++) & 0xFF);

#ifdef DOS
	p_elem->baud = (div / p_elem->baud) * 6;
#endif

	/*------------------------------------*/
	/* release response-buffer		 */
	/*------------------------------------*/
	sta_aux_bytestr_free(&response);


#ifdef BSD
	/*------------------------------------*/
	/* test baudrate			 */
	/*------------------------------------*/
	if (p_elem->baud < 2400) {
		COMclose(p_elem->port_id);

#ifdef TRACE
		fprintf(sct_trfp, "CALL get_orgelem in sct_reset after p_elem->baud < 2400 \n");
#endif

		if (get_orgelem(sct_id, p_elem) == -1)
			return (S_ERR);
		sct_errno = EBAUD;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	}
	index = 0;
	resetbaud = p_elem->baud;
	while ((div / resetbaud) != 1) {
		resetbaud = resetbaud * 2;
		index++;
	}
	p_elem->baud = B19200 - index;
#endif

#ifdef SYSTEMV
	/*------------------------------------*/
	/* test baudrate			 */
	/*------------------------------------*/
	if (p_elem->baud < 2400) {
		COMclose(p_elem->port_id);

#ifdef TRACE
		fprintf(sct_trfp, "CALL get_orgelem in sct_reset after p_elem->baud < 2400 \n");
#endif

		if (get_orgelem(sct_id, p_elem) == -1)
			return (-1);
		sct_errno = EBAUD;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	}
	index = 0;
	resetbaud = p_elem->baud;
	while ((div / resetbaud) != 1) {
		resetbaud = resetbaud * 2;
		index++;
	}
	p_elem->baud = B19200 - index;
#endif

#ifdef MAC
   /* Baudrate zu klein? */
   if (p_elem->baud < 2400)
      {
      COMclose(p_elem->port_id);
      if (get_orgelem(sct_id,p_elem) == -1)
         return(-1);
      sct_errno = EBAUD;
      sct_errmsg = sct_error[sct_errno].msg;
      return(S_ERR);
      }
   
   /* Baudrate wieder in's System umrechnen */
      p_elem->baud = MacBaud(p_elem->baud);
      
#endif /* MAC */

	if (*p++ == 0x07)
		p_elem->databits = DATA_7;
	else
		p_elem->databits = DATA_8;
	if (*p++ == 0x01)
		p_elem->stopbits = STOP_1;
	else
		p_elem->stopbits = STOP_2;

	p_elem->edc = (EdcType) * p++;
	p_elem->tpdusize = SCTcheck(&p);
	/* apdusize = tpdusize - length of TPDU-Header - Length of EDC */
	p_elem->apdusize = p_elem->tpdusize - 3 - ((p_elem->edc == E_LRC) ? 1 : 2);


	/*------------------------------------*/
	/* if baud / databits / stopbits	 */
	/* changed, then call COMreset	 */
	/*------------------------------------*/
	if ((baud != p_elem->baud) || (databits != p_elem->databits) ||
	    (stopbits != p_elem->stopbits)) {

		if (COMreset(p_elem) == -1) {
			COMclose(p_elem->port_id);

#ifdef TRACE
			fprintf(sct_trfp, "CALL get_orgelem in sct_reset after COMreset with ERROR \n");
#endif

			if (get_orgelem(sct_id, p_elem) == -1)
				return (S_ERR);
			return (SCTerr(sw1, tp1_err));
		}
	}
	/*------------------------------------*/
	/* set secure messaging       	 */
	/*------------------------------------*/

	if ((p_elem->setmode == 1) &&
	    ((p_elem->secure_messaging.command != SEC_NORMAL) ||
	     (p_elem->secure_messaging.response != SEC_NORMAL))) {
		if (sct_secure(sct_id) == -1)
			return (S_ERR);
	}
#ifdef MEMTRACE
	pr_element(sct_trfp, p_elem);
	fprintf(sct_trfp, "END of sct_reset\n");
#endif

#ifdef PROCDAT
	if ((sca_write_SCT_config(sct_id, p_elem)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration data!", CNULL, 0, proc);
		return (S_ERR);
	}

#endif	/*PROCDAT */




	return (S_NOERR);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_reset	       */
/*-------------------------------------------------------------*/





/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_interface	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*  Creat the s_apdu.					  */
/*  The sct_interface checks the mandatory parameter	  */
/*  in the body and the validity of the Instruction-Code. */
/*  It constructs the CLASS-Byte and executes the secure  */
/*  messaging functions.				  */
/*  The memory for the s_apdu is provided by this program.*/
/*  Send the s_apdu to the SCT. 			  */
/*  Receive the response from the SCT.			  */
/*  The memory for the response-apdu is provided by this  */
/*  program (response.bytes);				  */
/*  Execute the secure messaging functions.		  */
/*  Check the SW1 / SW2 - Byte. 			  */
/*  In case of O.K., sct_interface returns a pointer to   */
/*  the response-buffer response.bytes. 		  */
/*  The response-buffer contains only the datafield	  */
/*  without SW1 / SW2.					  */
/*  If SW1/SW2 indicates an error, sct_interface returns  */
/*  the value -1 and in sct_errno the error number.	  */
/*							  */
/*							  */

/*  Aenderungen Viebeg Beginn				  */
/*							  */
/*  Save SCT configuration data in a file.		  */

/*  Aenderungen Viebeg Ende				  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   int sct_id 	       SCT-Identifier		  */
/*							  */
/*   command		       instruction code 	  */
/*							  */
/*   pointer		       request structure	  */
/*							  */
/*   pointer		       response structure	  */
/*							  */
/* OUT							  */
/*   pointer		       response.bytes		  */
/*			       will be allocated by this  */
/*			       procedure and must be set  */
/*			       free by the calling proc.  */
/*			       but only in case of no err.*/
/*							  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*   0			       o.k.			  */
/*   1			       SCT waiting	          */
/*   2			       Key in SCT replaced	  */
/*   3			       Signature correct, but	  */
/*			       key to short		  */
/*   4			       PIN-CHECK off from SC	  */
/*   5			       PIN-CHECK on  from SC	  */
/*  -1			       error			  */
/*                             EINVARG			  */
/*                             ETOOLONG		          */
/*                             EMEMAVAIL		  */
/*                             ESIDUNK                    */
/*                             EPARMISSED                 */
/*                             EINVPAR                    */
/*                             EINVINS                    */
/*                             sw1/sw2 from SCT response  */
/*                             T1 - ERROR                 */
/*							  */
/* CALLED FUNCTIONS					  */
/*  get_idelem						  */
/*  SCTcreate						  */
/*  SCTresponse						  */
/*  SCTstatus						  */
/*  sta_aux_bytestr_free				  */
/*  COMtrans						  */


/*  Aenderungen Viebeg Beginn				       */

/*   sca_write_SCT_config()	Encrypt and write configuration */
/*				data for the specified SCT.     */
/*  Aenderungen Viebeg Ende				       */
/*							  */
/*--------------------------------------------------------*/
int
sct_interface(sct_id, command, request, response)
	int             sct_id;	/* sct_identifier   */
	unsigned int    command;/* instruction code */
	Request        *request;/* IN  - Puffer     */
	Bytestring     *response;	/* Pointer of OUT - Puffer     */
{

	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	char           *s_apdu;
	unsigned int    lapdu;
	unsigned int    sw1;
	unsigned int    sw2;
	int             i;
	struct s_portparam *p_elem;
	BOOL            flag = FALSE;	/* FLAG, if S_STATUS must be send */

#ifdef PROCDAT
	char           *proc = "sct_interface";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

#endif 	/* PROCDAT */


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	/*------------------------------------*/
	/* Initialisation			 */
	/*------------------------------------*/

	sct_errno = 0;
	response->bytes = NULL;


#ifdef STREAM
	if (!first) {
		sct_trfp = fopen("SCTINT.TRC", "wt");
		first = TRUE;
	};
#endif

	/*------------------------------------*/
	/* test sct_id  in sct_list		 */
	/*------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (-1);	/* ERROR: sct_id not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_interface\n");
	pr_element(sct_trfp, p_elem);
#endif



	/*------------------------------------*/
	/* test request argument		 */
	/*------------------------------------*/
	if (request == REQNULL) {
		sct_errno = EINVARG;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);

	};

	/*------------------------------------*/
	/* Create s_apdu			 */
	/*------------------------------------*/
	if ((s_apdu = SCTcreate(p_elem, command, request, &lapdu, &flag)) == NULL)
		return (S_ERR);

	if (lapdu > p_elem->apdusize) {	/* test apdusize */
		sct_errno = ETOOLONG;
		sct_errmsg = sct_error[sct_errno].msg;
		free(s_apdu);
		return (S_ERR);
	};




	/*------------------------------------*/
	/* allocate response-buffer		 */
	/*------------------------------------*/

#ifdef MALLOC
	response->bytes = malloc(p_elem->apdusize);
#endif

	if (response->bytes == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		free(s_apdu);
		return (S_ERR);
	};


	response->nbytes = 0;
	for (i = 0; i < p_elem->apdusize; i++)
		*(response->bytes + i) = 0x00;


	/*------------------------------------*/
	/* call transmission-procedure	 */
	/*------------------------------------*/
	if (COMtrans(p_elem, s_apdu, lapdu, response->bytes, &response->nbytes) == -1) {
		free(s_apdu);
		sta_aux_bytestr_free(response);
		return (SCTerr(0, tp1_err));
	}
	/*------------------------------------*/
	/* release s_apdu			 */
	/*------------------------------------*/
	free(s_apdu);



	/*------------------------------------*/
	/* analyse response                   */
	/*------------------------------------*/
	if (SCTresponse(p_elem, command, response, &sw1, &sw2) == -1)
		return (S_ERR);


	/*------------------------------------*/
	/* if flag = TRUE, then send S_STATUS */
	/*------------------------------------*/
	if (flag) {
		sta_aux_bytestr_free(response);
		i = SCTstatus(command, p_elem, response);
		/* close port in case of a local error of SCTdec */
		if ((command == S_REQUEST_SC) &&
		    ((sct_errno == EDESDEC) ||
		     (sct_errno == ESCT_SSC)))
			sct_close(sct_id);
#ifdef PROCDAT
		if ((sca_write_SCT_config(sct_id, p_elem)) < 0) {
			aux_add_error(ESCPROCDATA, "Cannot write SCT configuration data!", CNULL, 0, proc);
			return (S_ERR);
		}

#endif	/*PROCDAT */


		return (i);
	};

	/*--------------------------------------------------------------*/
	/* if command = S_EJECT_SC, then set p_elem->sc_request = FALSE */
	/*--------------------------------------------------------------*/
	if (command == S_EJECT_SC)
		p_elem->sc_request = FALSE;

#ifdef MEMTRACE
	pr_element(sct_trfp, p_elem);
	fprintf(sct_trfp, "END of sct_interface\n");
#endif


#ifdef PROCDAT
	if ((sca_write_SCT_config(sct_id, p_elem)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write SCT configuration data!", CNULL, 0, proc);
		return (S_ERR);
	}

#endif	/*PROCDAT */


	/*------------------------------------*/
	/* no error => set sw2, if > 0        */
	/*------------------------------------*/
	if (sw2 == S_NOERR)
		return (sw2);

	if (sw1 == OKSC)
		sw2 += 3;

	return (sw2);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_interface	       */
/*-------------------------------------------------------------*/






/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_perror	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Print error message				  */
/*   In case of sct_errno > 0, sct_perror first prints	  */
/*   msg, then a colon	and a blank, and then the error   */
/*   message to stderr. If msg is NULL or "", only the    */
/*   error message is printed.				  */
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   msg		       additional message	  */
/*							  */
/* OUT							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*   0			       o.k.			  */
/*							  */
/*							  */
/*							  */
/*							  */
/*--------------------------------------------------------*/
int
sct_perror(msg)
	char           *msg;	/* additional message	 */
{
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

	if (msg && strlen(msg))
		fprintf(stderr, "%s: ", msg);
	fprintf(stderr, "%s\n", sct_error[sct_errno].msg);
	return (S_NOERR);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_perror	       */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_info	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Information about SCT / SC 			  */
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   sct_id		      SCT-Identifier		  */
/*							  */
/*  sctinfo		      Pointer to structure	  */
/*							  */
/*							  */
/* OUT							  */
/*  sctinfo->history_sc       Pointer to Bytestring	  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*  0			      o.k			  */
/*							  */
/*  -1			      no element found in LIST	  */
/*                             ESIDUNK                    */
/*							  */
/*							  */
/* CALLED FUNCTIONS					  */
/*  get_idelem						  */
/*--------------------------------------------------------*/
int
sct_info(sct_id, sctinfo)
	int             sct_id;	/* SCT - Identifier */
	SCTInfo        *sctinfo;/* SCTInfo structure */
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	struct s_portparam *p_elem;

#ifdef PROCDAT
	char           *proc = "sct_info";

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

#endif 	/* PROCDAT */

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sct_errno = 0;
	sctinfo->apdusize = 0;
	sctinfo->history_sc = NULL;
	sctinfo->port_open = FALSE;
	sctinfo->sc_request = FALSE;
	sctinfo->sessionkey = FALSE;

#ifdef PROCDAT

	/*------------------------------------*/
	/* Create sct_list			 */
	/*------------------------------------*/
	if (!resfirst) {	/* create sct-list */

		/*
	   	   Problem war: 
			"sct_info()" wird von fast jeder STARMOD Funktion als erstes 
			aufgerufen, "sct_reset()" oder "sct_interface()" wurden 
			noch nicht aufgerufen. Somit wurden bei einem neuen Prozess
	 	        alte Prozess Daten noch nicht gelesen und auch noch keine
			SCT Liste erzeugt.
			Nach dem Kreieren der SCT Liste wird "get_idelem()" 
			aufgerufen und damit die alten Prozess Daten gelesen.
		*/

		if (cr_sctlist() == -1)
			return (S_ERR);
		resfirst = TRUE;
	};
#else

	if (!resfirst) {	/* sct-list not created  */
		return (S_NOERR);
	};
#endif

	/*------------------------------------*/
	/* test sct_id  in sct_list		 */
	/*------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (S_ERR);	/* ERROR: sct_id not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_info\n");
	pr_element(sct_trfp, p_elem);
#endif

	sctinfo->apdusize = p_elem->apdusize;
	sctinfo->history_sc = p_elem->schistory;
	if (p_elem->port_id > 0)
		sctinfo->port_open = TRUE;
	if (p_elem->sc_request > 0)
		sctinfo->sc_request = TRUE;
	if (p_elem->session_key.subjectkey.bits != NULL)
		sctinfo->sessionkey = TRUE;

	return (S_NOERR);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_info	       */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_secure	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Generate sessionkey and set it and the ssc in        */
/*   port-memory for secure messaging  between DTE and SCT*/
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   sct_id		      SCT-Identifier		  */
/*							  */
/*							  */
/*							  */
/* OUT							  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*  0			      o.k			  */
/*							  */
/*  -1			      no element found in LIST	  */
/*                             ESIDUNK                    */
/*			       EGENSESS			  */
/*			       EMEMAVAIL		  */
/*			       EKEY			  */
/* 			       ERSAENC			  */
/*                             EINVARG			  */
/*                             ETOOLONG		          */
/*                             EPARMISSED                 */
/*                             EINVPAR                    */
/*                             EINVINS                    */
/*                             sw1/sw2 from SCT response  */
/*                             T1 - ERROR                 */
/*							  */
/*							  */
/* CALLED FUNCTIONS					  */
/*  get_idelem						  */
/*  sec_random_bstr					  */
/*  sct_interface					  */
/*  rsa_get_key						  */
/*  rsa_encrypt						  */
/*  aux_free_BitString					  */
/*  sta_aux_bytestr_free				  */
/*  aux_free2_OctetString				  */
/*  aux_free2_BitString					  */
/*  aux_fxdump					  */
/*--------------------------------------------------------*/
int
sct_secure(sct_id)
	int             sct_id;	/* SCT - Identifier */
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	struct s_portparam *p_elem;
	int             rc, i, ssc, key_pos;
	BitString      *sessionkey;	/* Structure will be allocated by
					 * sec_random_bstr */

	/* must be set free by aux_free_BitString	     */
	KeyBits         key_bits;
	OctetString     in;
	BitString       out;
	Bytestring      enc_sess_key;
	More            more;
	int             keysize, memolen;

	AlgId          *subjectAI;
	SessionKey      sess_key_par;
	Request         request;
	Bytestring      response;
	Boolean         old_key;
	char           *des_key;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sct_errno = 0;

	if (!resfirst) {	/* sct-list not created  */
		return (S_NOERR);
	};

	/*------------------------------------*/
	/* test sct_id  in sct_list		 */
	/*------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (S_ERR);	/* ERROR: sct_id not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_secure\n");
	pr_element(sct_trfp, p_elem);
#endif



	/*--------------------------------------*/
	/* generate DES-Sessionkey	    	   */
	/*--------------------------------------*/
	sessionkey = BITNULL;
	if (p_elem->session_key.subjectkey.bits == NULL) {
		if ((sessionkey = sec_random_bstr(64)) == BITNULL) {
			sct_errno = EGENSESS;
			sct_errmsg = sct_error[sct_errno].msg;
			return (-1);
		}
		old_key = FALSE;

#ifdef STREAM
		fprintf(sct_trfp, "new sessionkey          : \n");
		fprintf(sct_trfp, "    nbits               : %d\n", sessionkey->nbits);
		fprintf(sct_trfp, "    bits                : \n");
		aux_fxdump(sct_trfp, sessionkey->bits, sessionkey->nbits / 8, 0);
#endif
	} else {
		old_key = TRUE;
		sessionkey = &p_elem->session_key.subjectkey;

#ifdef STREAM
		fprintf(sct_trfp, "old sessionkey          : \n");
		fprintf(sct_trfp, "    nbits               : %d\n", sessionkey->nbits);
		fprintf(sct_trfp, "    bits                : \n");
		aux_fxdump(sct_trfp, sessionkey->bits, sessionkey->nbits / 8, 0);
#endif
	}






	/*--------------------------------------*/
	/* Prepare parameters for the           */
	/* SCT Interface Cmd S_GET_TRANSPORT_KEY */
	/*--------------------------------------*/
	request.rq_p2.algid = S_RSA_F4;

	/*--------------------------------------*/
	/* Call SCT Interface 			 */
	/*--------------------------------------*/
	rc = sct_interface(sct_id, S_GET_TRANSPORT_KEY, &request, &response);
	if (rc < 0) {
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
#ifdef STREAM
	fprintf(sct_trfp, "modulus from the SCT    : \n");
	fprintf(sct_trfp, "    nbytes              : %d\n", response.nbytes);
	fprintf(sct_trfp, "    bytes               : \n");
	aux_fxdump(sct_trfp, response.bytes, response.nbytes, 0);
#endif

	/*--------------------------------------*/
	/* get modulus from SCT response and    */
	/* construct public key (modulus,       */
	/* Fermat-F4)                           */
	/*--------------------------------------*/
	key_bits.part1.noctets = response.nbytes;
	if ((key_bits.part1.octets = (char *) malloc(response.nbytes)) == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		sta_aux_bytestr_free(&response);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
	for (i = 0; i < response.nbytes; i++)
		key_bits.part1.octets[i] = response.bytes[i];

	/* get fermat-f4 as public exponent */
	key_bits.part2.noctets = fermat_f4_len;
	key_bits.part2.octets = fermat_f4;
	key_bits.part3.noctets = 0;
	key_bits.part4.noctets = 0;

#ifdef STREAM
	fprintf(sct_trfp, "Key_bits                : \n");
	fprintf(sct_trfp, "    part1.noctets       : %d\n", key_bits.part1.noctets);
	fprintf(sct_trfp, "    part1.octets        : \n");
	aux_fxdump(sct_trfp, key_bits.part1.octets, key_bits.part1.noctets, 0);
	fprintf(sct_trfp, "    part2.noctets       : %d\n", key_bits.part2.noctets);
	fprintf(sct_trfp, "    part2.octets        : \n");
	aux_fxdump(sct_trfp, key_bits.part2.octets, key_bits.part2.noctets, 0);
#endif


	/*--------------------------------------*/
	/* Release storage   		        */
	/*--------------------------------------*/
	sta_aux_bytestr_free(&response);

	/*--------------------------------------*/
	/* set key in an internal function for  */
	/* hash-function                        */
	/*--------------------------------------*/
	rc = rsa_get_key(&key_bits, 0);
	if (rc < 0) {
		sct_errno = EKEY;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&key_bits.part1);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
	/*--------------------------------------*/
	/* encrypt sessionkey with RSA-Publickey */
	/*--------------------------------------*/

#ifdef MALLOC
	/* allocate buffer for DES-Key             */
	/* The Key must be set in the last 8 Bytes */
	/* The first 56 Bytes are set to 0x00      */
	des_key = malloc(((sessionkey->nbits / 8) * 8) - 1);
#endif

	if (des_key == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&key_bits.part1);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
	for (i = 0; i < ((sessionkey->nbits / 8) * 8) - 1; i++)
		*(des_key + i) = 0x00;
	key_pos = 55;

	for (i = 0; i < 8; i++)
		*(des_key + key_pos + i) = *(sessionkey->bits + i);
	in.noctets = ((sessionkey->nbits / 8) * 8) - 1;
	in.octets = des_key;

#ifdef STREAM
	fprintf(sct_trfp, "in                      : \n");
	fprintf(sct_trfp, "    noctets             : %d\n", in.noctets);
	fprintf(sct_trfp, "    octets              : \n");
	aux_fxdump(sct_trfp, in.octets, in.noctets, 0);
#endif

	subjectAI = rsa;
	keysize = RSA_PARM(subjectAI->parm);
	memolen = in.noctets + ((keysize + 7) / 8);

#ifdef STREAM
	fprintf(sct_trfp, "keysize                 : %d\n", keysize);
	fprintf(sct_trfp, "memolen                 : %d\n", memolen);
#endif

	out.nbits = 0;

#ifdef MALLOC
	out.bits = malloc(memolen);	/* will be set free in this proc. */
#endif

	if (out.bits == NULL) {
		sct_errno = EMEMAVAIL;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&key_bits.part1);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		free(des_key);
		return (-1);
	}
	rc = rsa_encrypt(&in, &out, more, keysize);
	free(des_key);
	if (rc < 0) {
		sct_errno = ERSAENC;
		sct_errmsg = sct_error[sct_errno].msg;
		aux_free2_OctetString(&key_bits.part1);
		aux_free2_BitString(&out);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
#ifdef STREAM
	fprintf(sct_trfp, "encrypted sessionkey    : \n");
	fprintf(sct_trfp, "    nbits/8             : %d\n", out.nbits / 8);
	fprintf(sct_trfp, "    bits                : \n");
	aux_fxdump(sct_trfp, out.bits, out.nbits / 8, 0);
#endif

	/*--------------------------------------*/
	/* Release storage   		        */
	/*--------------------------------------*/
	aux_free2_OctetString(&key_bits.part1);



	/*--------------------------------------*/
	/* Prepare parameters for the           */
	/* SCT Interface Cmd S_GEN_SESSION_KEY  */
	/*--------------------------------------*/
	request.rq_p1.kid = 0x00;
	request.rq_p2.algid = S_DES_CBC;
	sess_key_par.sec_mode = CONCEALED;
	sess_key_par.com_line = DTE_SCT;
	enc_sess_key.nbytes = out.nbits / 8;
	enc_sess_key.bytes = out.bits;
	sess_key_par.session_key = &enc_sess_key;
	request.rq_datafield.session_key = &sess_key_par;

	/*--------------------------------------*/
	/* Call SCT Interface 			 */
	/*--------------------------------------*/
	rc = sct_interface(sct_id, S_GEN_SESSION_KEY, &request, &response);
	if (rc < 0) {
		aux_free2_BitString(&out);
		if (old_key == FALSE)
			aux_free_BitString(&sessionkey);
		return (-1);
	}
	ssc = (*response.bytes) & 0xFF;

#ifdef STREAM
	fprintf(sct_trfp, "ssc                     : %x\n", ssc);
#endif

	/*--------------------------------------*/
	/* Release storage   		        */
	/*--------------------------------------*/
	sta_aux_bytestr_free(&response);
	aux_free2_BitString(&out);


	/*----------------------------------------------*/
	/* Store sessionkey and ssc in port-memory 	 */
	/*----------------------------------------------*/
	if (old_key == FALSE) {

#ifdef MALLOC
		/* allocate buffer for sessionkey;    */
		p_elem->session_key.subjectkey.bits = malloc(sessionkey->nbits / 8);
#endif

		if (p_elem->session_key.subjectkey.bits == NULL) {
			sct_errno = EMEMAVAIL;
			sct_errmsg = sct_error[sct_errno].msg;
			aux_free_BitString(&sessionkey);
			return (-1);
		}
		for (i = 0; i < sessionkey->nbits / 8; i++)
			*(p_elem->session_key.subjectkey.bits + i) = *(sessionkey->bits + i);
		p_elem->session_key.subjectAI = desCBC;
		p_elem->session_key.subjectkey.nbits = sessionkey->nbits;

		aux_free_BitString(&sessionkey);

	}
	p_elem->ssc = ssc + 1;

#ifdef MEMTRACE
	pr_element(sct_trfp, p_elem);
	fprintf(sct_trfp, "End of sct_secure\n");
#endif

	return (S_NOERR);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_secure	       */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_setmode	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Set security mode for DTE-SCT in port memory 	  */
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   sct_id		      SCT-Identifier		  */
/*							  */
/*   sec_mess                 security mode               */
/*							  */
/* OUT							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*  0			      o.k			  */
/*							  */
/*  -1			      no element found in LIST	  */
/*                             ESIDUNK                    */
/*							  */
/*							  */
/* CALLED FUNCTIONS					  */
/*  get_idelem						  */
/*--------------------------------------------------------*/
int
sct_setmode(sct_id, sec_mess)
	int             sct_id;	/* SCT - Identifier */
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	struct s_portparam *p_elem;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sct_errno = 0;

	if (!resfirst) {	/* sct-list not created  */
		return (S_NOERR);
	};

	/*------------------------------------*/
	/* test sct_id  in sct_list		 */
	/*------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (S_ERR);	/* ERROR: sct_id not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_setmode\n");
	pr_element(sct_trfp, p_elem);
#endif

	p_elem->secure_messaging.command = sec_mess->command;
	p_elem->secure_messaging.response = sec_mess->response;
	p_elem->setmode = 1;

#ifdef MEMTRACE
	pr_element(sct_trfp, p_elem);
	fprintf(sct_trfp, "END of sct_setmode\n");
#endif

	return (S_NOERR);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_setmode	       */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_list	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Information about installed sct's                    */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*							  */
/*							  */
/* OUT							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*  entryno		      Number of entries 	  */
/*  -1			      error			  */
/*				ENOSHELL		  */
/*                              EOPERR                    */
/*			        EEMPTY                    */
/*                              EMEMAVAIL                 */
/*                              ECLERR                    */
/*							  */
/* CALLED FUNCTIONS					  */
/*  cr_sctlist						  */
/*--------------------------------------------------------*/
int
sct_list()
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	struct s_portparam *dp_tail;
	int             lindex = 0;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sct_errno = 0;
	/*------------------------------------*/
	/* Create sct_list			 */
	/*------------------------------------*/
	if (!resfirst) {	/* create sct-list */
		if (cr_sctlist() == -1)
			return (S_ERR);
		resfirst = TRUE;
	};
	dp_tail = p_lhead;

	while (dp_tail != PORTNULL) {
		dp_tail = dp_tail->p_next;
		lindex++;
	}


	return (lindex);

}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_list	       */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_close	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Close port of SCT          			  */
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   sct_id		      SCT-Identifier		  */
/*							  */
/*							  */
/* OUT							  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*  0			      o.k			  */
/*							  */
/*  -1			      error             	  */
/*				ENOSHELL		  */
/*                              EOPERR                    */
/*			        EEMPTY                    */
/*                              ECLERR                    */
/*                              ESIDUNK                   */
/*                              ERDERR                    */
/*							  */
/*							  */
/* CALLED FUNCTIONS					  */
/*  get_idelem						  */
/*  get_orgelem						  */
/*  COMclose
/*--------------------------------------------------------*/
int
sct_close(sct_id)
	int             sct_id;	/* SCT - Identifier */
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	struct s_portparam *p_elem;



	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	/*------------------------------------------*/
	/* test, if sct_id refers to a sct element  */
	/*------------------------------------------*/
	if ((p_elem = get_idelem(sct_id)) == PORTNULL)
		return (S_ERR);	/* ERROR: sct not in sct-list */

#ifdef MEMTRACE
	fprintf(sct_trfp, "Element after get_idelem in sct_close\n");
	pr_element(sct_trfp, p_elem);
#endif

	/*------------------------------------*/
	/* call COMclose - procedure		 */
	/*------------------------------------*/
	if (p_elem->port_id > 0)
		COMclose(p_elem->port_id);





	/*------------------------------------*/
	/* get original element out of	 */
	/* installation file			 */
	/*------------------------------------*/

#ifdef TRACE
	fprintf(sct_trfp, "CALL get_orgelem in sct_close \n");
#endif

	if (get_orgelem(sct_id, p_elem) == -1)
		return (S_ERR);

#ifdef MEMTRACE
	pr_element(sct_trfp, p_elem);
	fprintf(sct_trfp, "END of sct_close\n");
#endif


	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_close	       */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*						    | GMD */
/*						    +-----*/
/* PROC  sct_get_errmsg	     VERSION   2.0		  */
/*				DATE   November 1991	  */
/*				  BY   L.Eckstein,GMD	  */
/*							  */
/* DESCRIPTION						  */
/*   Get pointer of error message     			  */
/*							  */
/*							  */
/*							  */
/*							  */
/*							  */
/* IN			     DESCRIPTION		  */
/*   error_no		      Error number		  */
/*							  */
/*							  */
/* OUT							  */
/*							  */
/*							  */
/* RETURN		     DESCRIPTION		  */
/*--------------------------------------------------------*/
void
sct_get_errmsg(error_no)
	unsigned int    error_no;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	sct_errno = error_no;
	sct_errmsg = sct_error[error_no].msg;
}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sct_get_errmsg	       */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     sctint		       */
/*-------------------------------------------------------------*/
