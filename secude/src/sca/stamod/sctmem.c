/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   SCTMEM                  VERSION 2.0            */
/*                                         DATE November 1991  */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME                                                 */
/*      sctmem.c                                               */
/*                                                             */
/*    DESCRIPTION                                              */
/*      SCT - Memory - Module                                  */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*      cr_sctlist()          create SCT-list out of install-  */
/*                            File                             */
/*      get_idelem()          get SCT-Element                  */
/*                            search-string = SCT-identifier   */
/*      get_orgelem()         get original SCT-Element out     */
/*                            of install-file                  */
/*     pr_element                print sct-element if TRACE    */
/*                                                             */
/* Aenderungen Viebeg Beginn */
/*   sca_get_SCT_config_fname()	Get name of SCT configuration  */
/*				file.			       */
/*   sca_write_SCT_config()	Encrypt and write SCT          */
/*				configuration data.	       */
/* Aenderungen Viebeg End */
/*                                                             */
/*                                                             */
/*    INTERNAL              DESCRIPTION                        */
/*     del_sctlist               delete sct-list               */
/*     init_elem                 initialize sct element        */
/*     pr_sctlist                print sct-list if TRACE       */
/*                                                             */
/*    IMPORT                DESCRIPTION                        */
/*     sct_errno                 error variable from sctint.c  */
/*                                                             */


/* Aenderungen Viebeg Beginn */

/*							       	*/
/* STATIC                                                       */
/*   sca_delete_old_SCT_config() Delete old SCT configuration   */
/*				 file.				*/
/*   sca_get_process_key()	Get process key for encryption /*/
/*				decryption of SCT config.	*/
/*   sca_int2ascii()		Transform integer to asciistring*/
/*   sca_read_SCT_config()	Read and decrypt configuration  */
/*				data for the specified SCT.	*/
/*   SCT_config_changed()	Check whether SCT config data   */
/*				have been changed.		*/
/*   aux_add_error()		Add error to error stack.	*/
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/

/* Aenderungen Viebeg End */


/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/



#include <stdio.h>
#include <string.h>

#ifdef PROCDAT
#define FILEMASK 0600		/* file creation mask (for SCT configuration files) */

#include <sys/types.h>
#include <sys/stat.h>
#include "secsc.h"
#include <fcntl.h>
#include <errno.h>
#else
#include "sca.h"
#endif 	/* PROCDAT */

#include "sctport.h"
#include "install.h"
#include "sctmem.h"
#include "sctrc.h"
#include "sctloc.h"

#ifdef MAC
#include "Mac.h"
#include "baud.h"
#endif /* MAC */

char *get_unixname();


/*-------------------------------------------------------------*/
/*   extern declarations                                       */
/*-------------------------------------------------------------*/

#ifdef PROCDAT
extern unsigned int tp1_err;	/* error-variable from transmission module */
extern int      COMinit();

#endif
extern unsigned int sct_errno;	/* error variable               */
extern char    *sct_errmsg;
extern SCTerror sct_error[TABLEN];

#ifdef TRACE
extern FILE    *sct_trfp;	/* Filepointer of trace file    */

#endif


/*-------------------------------------------------------------*/
/*   forward declarations                                      */
/*-------------------------------------------------------------*/
static void     del_sctlist();
static void     init_elem();
static void     pr_sctlist();
void            pr_element();

/*-------------------------------------------------------------*/
/*   type definitions                                          */
/*-------------------------------------------------------------*/

#ifdef BSD
/*#define B19200  14*/
#include <sys/ttydev.h>
#endif

#ifdef SYSTEMV
/*#define B19200  14*/
#include <sys/ttydev.h>
#endif

#ifdef __HP__
#ifdef SYSV
#include <termio.h>
#else
#include <sgtty.h>
#endif
#endif


/*-------------------------------------------------------------*/
/*   globale variable definitions                              */
/*-------------------------------------------------------------*/
struct s_portparam *p_lhead;

/*-------------------------------------------------------------*/
/*   lokale Variable definitions                               */
/*-------------------------------------------------------------*/
static struct s_portparam *p_llast;
static struct s_portparam *p_elem;



#ifdef PROCDAT


static int	sca_delete_old_SCT_config();    
static char 	*sca_get_process_key();
static int	sca_read_SCT_config();
static int 	sca_int2ascii();
char		*sca_get_SCT_config_fname();
static Boolean  SCT_config_changed();

#endif	/* PROCDAT */


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  cr_sctlist          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create SCT-List                                       */
/*  In the environment must exists the shell-variable     */
/*  "STAMOD".                                             */
/*  This shell-variable contains the name of the          */
/*  installation - File                                   */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k.                       */
/*  -1                         error                      */
/*				ENOSHELL		  */
/*                              EOPERR                    */
/*			        EEMPTY                    */
/*                              EMEMAVAIL                 */
/*                              ECLERR                    */
/*--------------------------------------------------------*/
int
cr_sctlist()
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *fileptr;
	FILE           *fd;
	struct s_record genrecord;
	int             lindex = 0;
	int             i;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	/*------------------------------------*/
	/* Open file for read                 */
	/*------------------------------------*/
	/* read shell - variable               */
#ifdef MAC
    if ((fileptr = MacGetEnv("STAMOD")) == NULL) {
#else
    if ((fileptr = getenv("STAMOD")) == NULL) {
#endif /* !MAC */
		sct_errno = ENOSHELL;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

	/* open File for read */

	if ((fd = fopen(fileptr, "r")) == NULL) {
		sct_errno = EOPERR;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

	/*------------------------------------*/
	/* create SCT-List                    */
	/*------------------------------------*/
	if (fread(&genrecord, sizeof(struct s_record), 1, fd) == 0) {
		sct_errno = EEMPTY;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

	do {
		if (lindex == 0) {	/* create first element */

#ifdef MALLOC
			p_lhead = (struct s_portparam *) malloc(sizeof(struct s_portparam));
#endif

			p_llast = p_lhead;
		} else {	/* next element         */

#ifdef MALLOC
			p_llast->p_next = (struct s_portparam *) malloc(sizeof(struct s_portparam));
#endif

			p_llast = p_llast->p_next;
		};


		if (p_llast != PORTNULL) {
			memcpy(p_llast->port_name, genrecord.port_name, LPORTNAME);
			p_llast->port_name[LPORTNAME] = '\0';
			for (i = 0; i < LPORTNAME; i++) {
				if (p_llast->port_name[i] == 0x20) {
					p_llast->port_name[i] = '\0';
					break;
				};
			};


			/*------------------------------------------------------*/
			/* Initialize element					 */
			/*------------------------------------------------------*/
			init_elem(p_llast, &genrecord, TRUE);
			p_llast->p_next = PORTNULL;


			/*------------------------------------------------------*/
			/* create next element					 */
			/*------------------------------------------------------*/
			lindex++;
		} else {
			sct_errno = EMEMAVAIL;
			sct_errmsg = sct_error[sct_errno].msg;
			/* delete sct-list */
			fclose(fd);
			del_sctlist();
			return (S_ERR);
		};

	} while (fread(&genrecord, sizeof(struct s_record), 1, fd) != 0);

	/*------------------------------------*/
	/* close Installation File            */
	/*------------------------------------*/
	if (fclose(fd) != 0) {
		sct_errno = ECLERR;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

#ifdef TRACE
	/* print list */
	fprintf(sct_trfp, "FUNCTION cr_sctlist: \n");
	pr_sctlist(sct_trfp);
#endif

	return (0);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      cr_sctlist             */
/*-------------------------------------------------------------*/






/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  get_idelem          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Get sct-element with search-string = sct_id           */


/* Aenderungen Viebeg Beginn */

/*  If the configuration for the SCT (sct_id=1|2) has not been 	*/
/*  done:							*/
/*								*/
/*  => 1. Get key for the decryption of the SCT config data     */
/*     2a. There is a key:					*/
/*         Read SCA SCT configuration data:			*/
/*         The data for the specified SCT are read, decrypted	*/
/*	   and set into "p_elem".				*/
/*	   If no configuration file for the specified SCT    	*/
/*	   exists, the value of p_elem is left unchanged.	*/
/*	   If the port to the specified SCT has already been    */
/*         opened by a previous process, the port is opened 	*/
/*         again.						*/
/*     2b. There is no key:					*/
/*	   The value of p_elem is left unchanged.		*/
/*								*/
/* Aenderungen Viebeg End */


/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  fd                        filedescriptor              */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*  Pointer                   Pointer of sct-element      */
/*  POINTNULL                 error                       */
/*                             ESIDUNK                    */

/* Aenderungen Viebeg Beginn */

/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_process_key()	Get process key for encryption /*/
/*				decryption of SCT config.	*/
/*   sca_read_SCT_config()	Read and decrypt configuration  */
/*				file for the specified SCT.	*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/

/* Aenderungen Viebeg End */


/*--------------------------------------------------------*/
struct s_portparam *
get_idelem(sct_id)
	int             sct_id;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	int             i;

#ifdef PROCDAT
	char		*process_key;
	static Boolean	SCT1_config_done = FALSE;
	static Boolean	SCT2_config_done = FALSE;
	char           *proc = "get_idelem";
#endif 	/* PROCDAT */

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p_elem = PORTNULL;

	if (sct_id == 0) {
		sct_errno = ESIDUNK;
		sct_errmsg = sct_error[sct_errno].msg;
		return (p_elem);
	};

	p_elem = p_lhead;
	if (p_elem == PORTNULL) {
		sct_errno = ESIDUNK;
		sct_errmsg = sct_error[sct_errno].msg;
		return (p_elem);
	};

	for (i = 0; i < sct_id - 1; i++) {
		p_elem = p_elem->p_next;


		if (p_elem == PORTNULL) {
			sct_errno = ESIDUNK;
			sct_errmsg = sct_error[sct_errno].msg;
			return (p_elem);
		};
	};

#ifdef PROCDAT

/* 
    Konnte der port nicht geoeffnet werden ( Fehler in "sca_read_SCT_config()") , 
    bleibt die Variable "SCT1_config_done" auf FALSE.
    Somit wird beim naechsten Aufruf von "get_idelem()" die Funktion "sca_read_SCT_config()"
    nochmals aufgerufen.
*/


	if (sct_id == 1) {
		if (SCT1_config_done == FALSE) {

			/* 
			 *  Configuration for the SCT (sct_id = 1) has not been done 
			 *
			 *  => 1. Get process key for decryption of the SCT
			 *	  configuration data.
			 *     2. If there is a process key the data for the specified SCT
			 *	  are read and decrypted.
			 *        Otherwise nothing will be done.
			 */

			process_key = sca_get_process_key();
			if (process_key != CNULL) {

				/* There is a key => read and decrypt SCT configuration data */
				if (sca_read_SCT_config (sct_id, process_key)) {

					if (sct_errno != EOPEN)
						aux_add_error(ESCPROCDATA, "Cannot read SCT configuration data! ", CNULL, char_n, proc);
					free(process_key);
					return (PORTNULL);
				}
				free(process_key);    
			}
			SCT1_config_done = TRUE;
		}
	}
/*
 *  Very quick and very dirty
 */
	if (sct_id == 2) {
		if (SCT2_config_done == FALSE) {

			/* 
			 *  Configuration for the SCT (sct_id = 1) has not been done 
			 *
			 *  => 1. Get process key for decryption of the SCT
			 *	  configuration data.
			 *     2. If there is a process key the data for the specified SCT
			 *	  are read and decrypted.
			 *        Otherwise nothing will be done.
			 */

			process_key = sca_get_process_key();
			if (process_key != CNULL) {

				/* There is a key => read and decrypt SCT configuration data */
				if (sca_read_SCT_config (sct_id, process_key)) {

					if (sct_errno != EOPEN)
						aux_add_error(ESCPROCDATA, "Cannot read SCT configuration data! ", CNULL, char_n, proc);
					free(process_key);
					return (PORTNULL);
				}
				free(process_key);    
			}
			SCT2_config_done = TRUE;
		}
	}

#endif 	/* PROCDAT */


#ifdef TRACE
	fprintf(sct_trfp, "FUNCTION get_idelem: \n");
	pr_element(sct_trfp, p_elem);
#endif


	return (p_elem);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      get_idelem             */
/*-------------------------------------------------------------*/




#ifdef PROCDAT


/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  sca_get_process_key				       	*/
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
/*   CNULL		       Env variable is not set.		*/
/*   pointer		       ok			 	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
char *sca_get_process_key()
{

	static char		*process_key = CNULL;

	char           *proc = "sca_get_process_key";


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

}				/* end sca_get_process_key */




/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  sca_read_SCT_config				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*   Case 1:  SCT configuration file exists:			*/
/*   This file is read and decrypted, the values are checked:   */
/*      If the values are correct, the resulting data are 	*/
/*         stored in  "p_elem". If the read values indicate     */
/*	   that the port has been opened by a previous process, */
/*         this function opens the port again (COMinit).	*/
/*      							*/
/*	If the values are not correct, the SCT configuration 	*/
/*         file is deleted and the values of 'p_elem" are left  */
/*         unchanged.						*/
/*								*/
/*   Case 2:  SCT configuration file does not exist:		*/				
/*   The values in "p_elem" are left unchanged.			*/
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
/*   COMinit()			Open port.			*/
/*   aux_AppName2SCApp()	Get information about an SC app.*/
/*   sca_delete_old_SCT_config() Delete old SCT configuration 	*/
/*				 file. 				*/
/*   sca_get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*   aux_cpy_String()		Copy string.			*/
/*			         		       		*/
/*--------------------------------------------------------------*/

static
int sca_read_SCT_config(sct_id, process_key)
int	sct_id;
char	*process_key;
{

	unsigned int    sw1 = 0;


	unsigned int secsc_errno;
	char           *config_file_name = "";
	int            fd_proc_data;
	struct s_help_portparam      sct_elem;

	char           *proc = "sca_read_SCT_config";

	secsc_errno = NOERR;

#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

/********************************************************************************/
/*
 *      Get name of SCT configuration file:
 */

	config_file_name = sca_get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT configuration file!", CNULL, 0, proc);
		return (-1);
	}


/********************************************************************************/
/*
 *	Open SCT configuration file
 */

	if ((fd_proc_data = open(config_file_name, O_RDONLY)) < 0) {
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

	sct_elem.schistory[0] = '\0';

	if (secsc_errno = read_dec(fd_proc_data, &sct_elem, sizeof(struct s_help_portparam), process_key) <= 0) {
#ifdef SECSCTEST
		fprintf(stderr,"SCA SCT configuration file %s invalid, is deleted!\n", config_file_name);
#endif
	        close_dec(fd_proc_data);
	        sca_delete_old_SCT_config(sct_id);
		free(config_file_name);
		return (0);
	}
	close_dec(fd_proc_data);


/********************************************************************************/
/*
 *	Check read values:
 *		If values are correct, the read information are stored into sct status list.
 *              Otherwise the read file is deleted.
 */


	if ((sct_elem.parity != P_NONE) &&
	    (sct_elem.parity != P_ODD) && 
	    (sct_elem.parity != P_EVEN))
		secsc_errno = ESCPROCDATA;
	else if ((sct_elem.chaining != C_OFF) &&
	         (sct_elem.chaining != C_ON) ) 
			secsc_errno = ESCPROCDATA;
	     else if ((sct_elem.edc != E_LRC) &&
	              (sct_elem.edc != E_CRC) ) 
				secsc_errno = ESCPROCDATA;
	          else if ((sct_elem.secure_messaging.command != SEC_NORMAL) &&
	       	           (sct_elem.secure_messaging.command != AUTHENTIC) &&
	        	   (sct_elem.secure_messaging.command != CONCEALED) &&
	        	   (sct_elem.secure_messaging.command != COMBINED)) 
				secsc_errno = ESCPROCDATA;
	   	       else if ((sct_elem.secure_messaging.response != SEC_NORMAL) &&
	                        (sct_elem.secure_messaging.response != AUTHENTIC) &&
	                        (sct_elem.secure_messaging.response != CONCEALED) &&
	                        (sct_elem.secure_messaging.response != COMBINED)) 
					secsc_errno = ESCPROCDATA;


	if (secsc_errno == NOERR) 	{

		p_elem->bwt 				= sct_elem.bwt;
		strcpy (p_elem->port_name,  sct_elem.port_name);
		p_elem->cwt 				= sct_elem.cwt;
		p_elem->baud 				= sct_elem.baud;
		p_elem->databits 			= sct_elem.databits;
		p_elem->stopbits 			= sct_elem.stopbits;
		p_elem->parity 				= sct_elem.parity;
		p_elem->dataformat 			= sct_elem.dataformat;
		p_elem->tpdusize 			= sct_elem.tpdusize;
		p_elem->apdusize 			= sct_elem.apdusize;
		p_elem->edc 				= sct_elem.edc;
		p_elem->protocoltype 			= sct_elem.protocoltype;
		p_elem->chaining 			= sct_elem.chaining;
		p_elem->ns 				= sct_elem.ns;
		p_elem->rsv 				= sct_elem.rsv;
		p_elem->sad 				= sct_elem.sad;
		p_elem->dad 				= sct_elem.dad;

		if (!(p_elem->schistory = malloc(64)) ) {
			aux_add_error(EMALLOC, "p_elem->schistory", CNULL, 0, proc);
			return (-1);
		}
		strcpy (p_elem->schistory,  sct_elem.schistory);

		p_elem->port_id 			= sct_elem.port_id;
		p_elem->first 				= sct_elem.first;
		p_elem->setmode 			= sct_elem.setmode;

		p_elem->session_key.subjectAI 		= NULL;		/* init values */
		p_elem->session_key.subjectkey.bits 	= NULL;		/* init values */
		p_elem->session_key.subjectkey.nbits 	= 0;		/* init values */
		p_elem->ssc 				= 0;		/* init values */

		p_elem->secure_messaging.command	= sct_elem.secure_messaging.command;
		p_elem->secure_messaging.response	= sct_elem.secure_messaging.response;
		p_elem->sc_request 			= sct_elem.sc_request;




#ifdef SECSCTEST
		fprintf(stderr, "Read SCA configuration data for SCT: %d\n", sct_id);

		if (fd_proc_data >= 0) {
			if (sct_elem.sc_request == TRUE) 
				fprintf(stderr, "sct_elem.sc_request == TRUE\n");
			else    fprintf(stderr, "sct_elem.sc_request == FALSE\n");
			fprintf(stderr, "port_id: %d\n", sct_elem.port_id);
			
			fprintf(stderr, "sct_elem.ns: %d\n", sct_elem.ns);
			fprintf(stderr, "sct_elem.rsv: %d\n", sct_elem.rsv);
			if (sct_elem.parity == P_NONE) 
				fprintf(stderr, "sct_elem.parity == P_NONE\n");
			if (sct_elem.parity == P_ODD) 
				fprintf(stderr, "sct_elem.parity == P_ODD\n");
			if (sct_elem.parity == P_EVEN) 
				fprintf(stderr, "sct_elem.parity == P_EVEN\n");
			if (sct_elem.chaining == C_OFF) 
				fprintf(stderr, "sct_elem.chaining != C_OFF\n");
			if (sct_elem.chaining == C_ON) 
				fprintf(stderr, "sct_elem.chaining != C_ON\n");
			if (sct_elem.edc == E_LRC) 
				fprintf(stderr, "sct_elem.edc == E_LRC\n");
			if (sct_elem.edc == E_CRC) 
				fprintf(stderr, "sct_elem.edc == E_CRC\n");
			if (sct_elem.secure_messaging.command == SEC_NORMAL) 
				fprintf(stderr, "command == SEC_NORMAL\n");
			if (sct_elem.secure_messaging.command == AUTHENTIC) 
				fprintf(stderr, "command == AUTHENTIC\n");
			if (sct_elem.secure_messaging.command == CONCEALED) 
				fprintf(stderr, "command == CONCEALED\n");
			if (sct_elem.secure_messaging.command == COMBINED) 
				fprintf(stderr, "command == COMBINED\n");
			if (sct_elem.secure_messaging.response == SEC_NORMAL) 
				fprintf(stderr, "response == SEC_NORMAL\n");
			if (sct_elem.secure_messaging.response == AUTHENTIC) 
				fprintf(stderr, "response == AUTHENTIC\n");
			if (sct_elem.secure_messaging.response == CONCEALED) 
				fprintf(stderr, "response == CONCEALED\n");
			if (sct_elem.secure_messaging.response == COMBINED) 
				fprintf(stderr, "response == COMBINED\n");
		}
#endif


		/*
		 *  Open port again
		 */

		if (p_elem->port_id > 0) {
			if ((COMinit(p_elem)) == -1) {
				aux_add_error(EOPENDEV, "Cannot open device", p_elem->port_name, char_n, proc);
				return (SCTerr(sw1, tp1_err));
			}

#ifdef SECSCTEST
			fprintf(stderr, "(PROCDAT) Port: %d for SCT: %d opened\n", p_elem->port_id, sct_id);
#endif
			return (S_NOERR);		/* reset already done */
		}


	}
	else {
		aux_add_error(ESCPROCDATA, "SCA SCT configuration file invalid, is deleted!", config_file_name, char_n, proc);
	        sca_delete_old_SCT_config(sct_id);
		free(config_file_name);
		return (0);
	}

	free(config_file_name);
	return(0);

}				/* end sca_read_SCT_config */



/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  sca_write_SCT_config				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Encrypt and write the configuration data for the specified 	*/
/*  SCT into a file.						*/
/*								*/
/*  1. Check whether the SCT configuration data have been 	*/
/*     changed.							*/
/*     If the main parts of the data haven't changed, nothing 	*/
/*     will be done.						*/
/*								*/
/*  2. If the data have been changed:				*/
/*     Get key for the encryption of the SCT config data.	*/
/*								*/
/*     Case 1: There is a key:					*/
/*	       => The data for the specified SCT ("p_elem") are */
/*                encrypted with this key and written into a 	*/
/*                configuration file.				*/
/*     Case 2: No key:						*/
/*	       =>  nothing will be done.			*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the SCT configuration data shall	*/
/*			       be written.			*/
/*   p_elem		       Pointer to SCT specific structure*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0			       ok				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   sca_get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*   sca_get_process_key()	Get process key for encryption /*/
/*				decryption of SCT config.	*/
/*   SCT_config_changed()	Check whether SCT config data   */
/*				have been changed.		*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
int	sca_write_SCT_config(sct_id, p_elem)
	int             sct_id;
	struct s_portparam      *p_elem;
	
{

	unsigned int secsc_errno;

	char	       *process_key;
	char           *config_file_name = "";
	int            fd_proc_data;
	static int     old_sctid = 0;
	struct s_help_portparam     	    sct_elem;
	static struct s_help_portparam      last_sct_elem;

	char           *proc = "sca_write_SCT_config";

	secsc_errno = NOERR;



/********************************************************************************/
/*
 *      If the SCT configuration data haven't been changed, the data will 
 *	 not be written to the SCT configuration file
 */
	
	if (old_sctid == sct_id) 
		if (SCT_config_changed(&last_sct_elem, p_elem) == FALSE)
			return(0);

	old_sctid = sct_id;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif


/********************************************************************************/
/*
 *      Get encryption key for the SCT configuration data
 */

	process_key = sca_get_process_key();

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

	config_file_name = sca_get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT configuration file!", CNULL, 0, proc);
		free(process_key);    
		return (0);
	}



/********************************************************************************/
/*
 *	Open SCT configuration file
 */

	if ((fd_proc_data = open(config_file_name, O_WRONLY | O_CREAT, FILEMASK)) < 0) {
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


		sct_elem.bwt 				=  p_elem->bwt;
		strcpy (sct_elem.port_name,  p_elem->port_name);
		sct_elem.cwt 				=  p_elem->cwt;
		sct_elem.baud 				= p_elem->baud;
		sct_elem.databits 			= p_elem->databits;
		sct_elem.stopbits 			= p_elem->stopbits;
		sct_elem.parity 			= p_elem->parity;
		sct_elem.dataformat 			= p_elem->dataformat;
		sct_elem.tpdusize 			= p_elem->tpdusize;
		sct_elem.apdusize 			= p_elem->apdusize;
		sct_elem.edc 				= p_elem->edc;
		sct_elem.protocoltype 			= p_elem->protocoltype;
		sct_elem.chaining 			= p_elem->chaining;
		sct_elem.ns 				= p_elem->ns;
		sct_elem.rsv 				= p_elem->rsv;
		sct_elem.sad 				= p_elem->sad;
		sct_elem.dad 				= p_elem->dad;
		if (p_elem->schistory)
			strcpy (sct_elem.schistory, p_elem->schistory);
		else
			sct_elem.schistory[0] = '\0';
		sct_elem.port_id 			= p_elem->port_id;
		sct_elem.first 				= p_elem->first;
		sct_elem.ssc 				= p_elem->ssc;
		sct_elem.sc_request 			= p_elem->sc_request;
		sct_elem.setmode 			= p_elem->setmode;
		sct_elem.session_key.subjectAI 		= p_elem->session_key.subjectAI;
		sct_elem.session_key.subjectkey.bits 	= p_elem->session_key.subjectkey.bits;
		sct_elem.session_key.subjectkey.nbits 	= p_elem->session_key.subjectkey.nbits;
		sct_elem.secure_messaging.response 	= p_elem->secure_messaging.response;
		sct_elem.secure_messaging.command 	= p_elem->secure_messaging.command;


	/* 
	 *  The values of sct_elem will be encrypted by function "write_enc()"
         */

	if ((write_enc(fd_proc_data, &sct_elem, sizeof(struct s_help_portparam), process_key)) < 0) {
		aux_add_error(ESCPROCDATA, "Cannot write configuration data for SCT! ", CNULL, char_n, proc);
		close_enc(fd_proc_data);
		free(process_key);
		return (0);
	}

	close_enc(fd_proc_data);
	free(process_key);    


/********************************************************************************/
/*
 *	Save values of p_elem 
 */

	last_sct_elem.bwt 				=  p_elem->bwt;
	strcpy (last_sct_elem.port_name,  p_elem->port_name);
	last_sct_elem.cwt 				=  p_elem->cwt;
	last_sct_elem.baud 				= p_elem->baud;
	last_sct_elem.databits 				= p_elem->databits;
	last_sct_elem.stopbits 				= p_elem->stopbits;
	last_sct_elem.parity 				= p_elem->parity;
	last_sct_elem.dataformat 			= p_elem->dataformat;
	last_sct_elem.tpdusize 				= p_elem->tpdusize;
	last_sct_elem.apdusize 				= p_elem->apdusize;
	last_sct_elem.edc 				= p_elem->edc;
	last_sct_elem.protocoltype 			= p_elem->protocoltype;
	last_sct_elem.chaining 				= p_elem->chaining;
	last_sct_elem.ns 				= p_elem->ns;
	last_sct_elem.rsv 				= p_elem->rsv;
	last_sct_elem.sad 				= p_elem->sad;
	last_sct_elem.dad 				= p_elem->dad;
	if (p_elem->schistory)
		strcpy (last_sct_elem.schistory, p_elem->schistory);
	else
		last_sct_elem.schistory[0] = '\0';
	last_sct_elem.port_id 				= p_elem->port_id;
	last_sct_elem.first 				= p_elem->first;
	last_sct_elem.ssc 				= p_elem->ssc;
	last_sct_elem.sc_request 			= p_elem->sc_request;
	last_sct_elem.setmode 				= p_elem->setmode;
	last_sct_elem.session_key.subjectAI 		= p_elem->session_key.subjectAI;
	last_sct_elem.session_key.subjectkey.bits 	= p_elem->session_key.subjectkey.bits;
	last_sct_elem.session_key.subjectkey.nbits 	= p_elem->session_key.subjectkey.nbits;
	last_sct_elem.secure_messaging.response 	= p_elem->secure_messaging.response;
	last_sct_elem.secure_messaging.command 		= p_elem->secure_messaging.command;




	return(0);

}				/* end sca_write_SCT_config */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  sca_delete_old_SCT_config			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Delete old SCT specific SCT configuration file.		*/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   sct_id		       Identifier of the SCT for which	*/
/*			       the SCT configuration file shall */
/*			       be deleted.			*/
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
/*   sca_get_SCT_config_fname()	Get name of SCT configuration 	*/
/*				file.				*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static
int	sca_delete_old_SCT_config(sct_id)
int	sct_id;
{

	unsigned int 	secsc_errno;
	char           *config_file_name = "";

	char           *proc = "sca_delete_old_SCT_config";

	secsc_errno = NOERR;


#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif




/********************************************************************************/
/*
 *      Get name of SCT configuration file:
 */

	config_file_name = sca_get_SCT_config_fname (sct_id);

	if (config_file_name == CNULL) {
		aux_add_error(ESCPROCDATA, "Cannot get name of SCT configuration file!", CNULL, 0, proc);
		return (-1);
	}



/********************************************************************************/
/*
 *	Delete old proc data files
 */


	if (unlink(config_file_name)) {
		if (errno != ENOENT) {
			aux_add_error(ESCPROCDATA, "Cannot delete SCT configuration file!", config_file_name, char_n, proc);
			free(config_file_name);
			return (-1);
		}
	}

	free(config_file_name);
			
	return(0);

}				/* end sca_delete_old_SCT_config */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  sca_get_SCT_config_fname			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Compose and return name of the SCT configuration file for  	*/
/*  the specified SCT:						*/
/*								*/
/*  Structure:							*/
/*  Home directory || SCA_SCT_CONFIG_name || sct_id		*/
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
/*			         		       		*/
/*--------------------------------------------------------------*/

char	*sca_get_SCT_config_fname(sct_id)
int	sct_id;


{
	unsigned int 	secsc_errno;
	char           *homedir = "";
	static char    *config_file_name = "";
	static int     old_sctid = 0;
	char	       sct_id_ascii[MAXSCTID_LEN];

	char           *proc = "sca_get_SCT_config_fname";

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
		config_file_name = (char *) malloc(strlen(homedir) + strlen(SCA_SCT_CONFIG_name) + 16);
		if (!config_file_name) {
			aux_add_error(EMALLOC, "SCT configuration filename", CNULL, 0, proc);
			return (CNULL);
		}
		strcpy(config_file_name, homedir);
		if (strlen(homedir))
			if (config_file_name[strlen(config_file_name) - 1] != '/')
				strcat(config_file_name, "/");
		strcat(config_file_name, SCA_SCT_CONFIG_name);


		if (sca_int2ascii(&sct_id_ascii[0], sct_id)) {
			aux_add_error(ESYSTEM, "Cannot get ASCII representation of sct_id", CNULL, 0, proc);
			return (CNULL);
		}
		strcat(config_file_name, sct_id_ascii);

		old_sctid = sct_id;
	}

#ifdef SECSCTEST
	fprintf(stderr, "Name of SC configuration file: %s\n", config_file_name);
#endif

	return(aux_cpy_String(config_file_name));

}			/* sca_get_SCT_config_fname */





/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  SCT_config_changed				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check whether SCT configuration data have been changed.	*/
/*								*/
/*  Compare the values of "old_elem" with the values of 	*/
/*  "new_elem".						 	*/
/*****************?????????????????????????????????????????????????????????*************/

/*  Achtung:

	Die alten bzw. neuen Werte von 
	"ns" und "rsv" werden nicht verglichen, da sonst nach jedem Kommando
	zum SCT hin das SCT configuration file geschrieben wuerde.
	
Es gibt keine Probleme damit, wenn ein neuer Prozess gestartet wird, da

	beim Einlesen der SCT configuration data,  auch "COMinit()" aufgerufen
	wird. "COMinit()" setzt "p_elem->first" auf 0.
	Dies bewirkt beim naechsten Aufruf von "COMtrans()", dass
	"Resynch()" aufgerufen wird, wo "ns" (alias "ssv") und "rsv" 
	initialisiert werden.
*/

/*  Achtung der session key wird noch nicht verglichen */




/*****************?????????????????????????????????????????????????????????*************/
/*								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   old_elem		       Pointer to the old values.	*/
/*   new_elem		       Pointer to the new values.       */
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE			SCT configuration data have been*/
/*				changed.			*/
/*   FALSE			SCT configuration data have not */
/*				been changed.			*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*			         		       		*/
/*--------------------------------------------------------------*/
static
Boolean	SCT_config_changed(old_elem, new_elem)
	struct s_help_portparam      *old_elem;
	struct s_portparam     	     *new_elem;
	
{

	unsigned int secsc_errno;
	Boolean	     changed = FALSE;


	char           *proc = "SCT_config_changed";

	secsc_errno = NOERR;


#ifdef SECSCTEST
/*	fprintf(stderr, "SECSC-Function: %s\n", proc); */
#endif


		if (strcmp (old_elem->port_name,  new_elem->port_name)) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->bwt != new_elem->bwt) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->cwt != new_elem->cwt) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->baud != new_elem->baud) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->databits != new_elem->databits) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->stopbits != new_elem->stopbits) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->parity != new_elem->parity) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->dataformat != new_elem->dataformat) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->tpdusize != new_elem->tpdusize) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->apdusize != new_elem->apdusize) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->edc != new_elem->edc) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->protocoltype != new_elem->protocoltype) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->chaining != new_elem->chaining) {
			changed = TRUE; 
			goto ret_value;
		}
/*		if (old_elem->ns != new_elem->ns) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->rsv != new_elem->rsv) {
			changed = TRUE; 
			goto ret_value;
		}
*/
		if (old_elem->sad != new_elem->sad) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->dad != new_elem->dad) {
			changed = TRUE; 
			goto ret_value;
		}

		if (new_elem->schistory) {
			if (strcmp (old_elem->schistory,  new_elem->schistory)) {
				changed = TRUE; 
				goto ret_value;
			}
		}
		else {
			if (old_elem->schistory[0] != '\0') {
				changed = TRUE; 
				goto ret_value;
			}
		}

		if (old_elem->port_id != new_elem->port_id) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->first != new_elem->first) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->ssc != new_elem->ssc) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->setmode != new_elem->setmode) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->sc_request != new_elem->sc_request) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->secure_messaging.command != new_elem->secure_messaging.command) {
			changed = TRUE; 
			goto ret_value;
		}
		if (old_elem->secure_messaging.response != new_elem->secure_messaging.response) {
			changed = TRUE; 
			goto ret_value;
		}



/*********?????????????????????????????????????*********/
/* Folgendes sollte auch verglichen werden??????????????**

		old_elem->session_key.subjectAI 		= new_elem->session_key.subjectAI;
		old_elem->session_key.subjectkey.bits 	= new_elem->session_key.subjectkey.bits;
		old_elem->session_key.subjectkey.nbits 	= new_elem->session_key.subjectkey.nbits;

************???????????????????????????????????******/

ret_value:

#ifdef SECSCTEST
	if (changed == TRUE)
		fprintf(stderr, "SECSC-Function: %s\n", proc);
#endif

	return(changed);

}				/* end SCT_config_changed */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  sca_int2ascii					       	*/
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
int sca_int2ascii(s,n)			     /* from integer to NULL terminated ascii string */
char s[];
int n;
{
    int c,i,j, sign;
	char           *proc = "sca_int2ascii";

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

} /* end sca_int2ascii */







#endif 	/* PROCDAT */





/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  get_orgelem()       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Read original SCT-Element out of Install-File.        */
/*  In the environment must exists the shell-variable     */
/*  "STAMOD".                                             */
/*  This shell-variable contains the name of the          */
/*  installation - File                                   */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  Pointer                   Pointer of old listelement  */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k.                       */
/*  -1                         error                      */
/*			        ESIDUNK                   */
/*                              ENOSHELL                  */
/*                              EOPERR                    */
/*                              EEMPTY                    */
/*                              ERDERR                    */
/*                              ECLERR                    */
/*--------------------------------------------------------*/
int
get_orgelem(sct_id, oldelem)
	int             sct_id;
	struct s_portparam *oldelem;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *fileptr;
	FILE           *fd;
	struct s_record genrecord;
	int             rc;
	long            offset;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	if (sct_id == 0) {
		sct_errno = ESIDUNK;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};
	/*------------------------------------*/
	/* Open file for read                 */
	/*------------------------------------*/
	/* read shell - variable               */
#ifdef MAC
    if ((fileptr = MacGetEnv("STAMOD")) == NULL) {
#else
    if ((fileptr = getenv("STAMOD")) == NULL) {
#endif /* !MAC */
		sct_errno = ENOSHELL;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

	/* open File for read */

	if ((fd = fopen(fileptr, "r")) == NULL) {
		sct_errno = EOPERR;
		sct_errmsg = sct_error[sct_errno].msg;
		return (S_ERR);
	};

	/*------------------------------------*/
	/* read install-file, until element   */
	/* found                              */
	/*------------------------------------*/

	offset = (long) (sizeof(struct s_record) * (sct_id - 1));
	if (fseek(fd, offset, 0) != 0) {
		sct_errno = EEMPTY;
		sct_errmsg = sct_error[sct_errno].msg;
		fclose(fd);
		return (S_ERR);
	};


	if (fread(&genrecord, sizeof(struct s_record), 1, fd) == 0) {
		sct_errno = ERDERR;
		sct_errmsg = sct_error[sct_errno].msg;
		fclose(fd);
		return (S_ERR);
	};



	/*------------------------------------------------------*/
	/* Test, if schistory buffer allocated	            */
	/*------------------------------------------------------*/
	if (oldelem->schistory != NULL)
		free(oldelem->schistory);


	/*------------------------------------------------------*/
	/* Initialize element				    */
	/*------------------------------------------------------*/
	init_elem(oldelem, &genrecord, FALSE);

	/*------------------------------------*/
	/* close Installation File            */
	/*------------------------------------*/
	if (fclose(fd) != 0) {
		sct_errno = ECLERR;
		sct_errmsg = sct_error[sct_errno].msg;
		return (-1);
	};

#ifdef TRACE
	/* print element */
	fprintf(sct_trfp, "FUNCTION get_orgelem: \n");
	pr_element(sct_trfp, oldelem);
#endif

	return (0);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      get_orgelem            */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  del_sctlist         VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Delete sct-List                                       */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
del_sctlist()
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	struct s_portparam *dp_tail;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	dp_tail = p_lhead;

	while (dp_tail != PORTNULL) {
		p_lhead = p_lhead->p_next;
		free(dp_tail);
		dp_tail = p_lhead;
	}

	p_lhead = PORTNULL;

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      del_sctlist            */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  init_elem           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Initialize sct element                                */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  Pointer                   Pointer of listelement      */
/*                                                        */
/*  Pointer                   Pointer of genrecord        */
/*                                                        */
/*  first                     call  of init_elem          */
/*			      TRUE : call of cr_sctlist   */
/*			      FALSE: call of get_orgelem  */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
init_elem(sct_elem, genrecord, first)
	struct s_portparam *sct_elem;
	struct s_record *genrecord;
	Boolean         first;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	int             div = 19200;
	int             baud;
	int             index;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	sct_elem->bwt = genrecord->bwt;
	sct_elem->cwt = genrecord->cwt;

#ifdef DOS
	sct_elem->baud = (div / genrecord->baud) * 6;
#endif

#ifdef BSD
	index = 0;
	baud = genrecord->baud;
	while ((div / baud) != 1) {
		baud = baud * 2;
		index++;
	}
	sct_elem->baud = B19200 - index;
#endif

#ifdef SYSTEMV
	index = 0;
	baud = genrecord->baud;
	while ((div / baud) != 1) {
		baud = baud * 2;
		index++;
	}
	sct_elem->baud = B19200 - index;
#endif
#ifdef MAC
        sct_elem->baud = MacBaud(genrecord->baud);
#endif

	if (genrecord->databits == 7)
		sct_elem->databits = DATA_7;
	else
		sct_elem->databits = DATA_8;
	if (genrecord->stopbits == 1)
		sct_elem->stopbits = STOP_1;
	else
		sct_elem->stopbits = STOP_2;
	if (sct_elem->databits == DATA_8)
		sct_elem->parity = PARNONE;
	else
		sct_elem->parity = genrecord->parity;
	sct_elem->dataformat = genrecord->dataformat;
	sct_elem->tpdusize = genrecord->tpdu_size;
	sct_elem->apdusize = genrecord->apdu_size;
	sct_elem->edc = genrecord->edc;
	sct_elem->chaining = C_ON;
	sct_elem->schistory = NULL;
	sct_elem->port_id = 0;
	sct_elem->ssc = 0;
	sct_elem->sc_request = 0;
	if (first == TRUE) {
		sct_elem->setmode = 0;
		sct_elem->session_key.subjectAI = NULL;
		sct_elem->session_key.subjectkey.bits = NULL;
		sct_elem->session_key.subjectkey.nbits = 0;
		sct_elem->secure_messaging.response = SEC_NORMAL;
		sct_elem->secure_messaging.command = SEC_NORMAL;
	}
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      init_elem              */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC   pr_sctlist         VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print  sct-List                                       */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
pr_sctlist(dump_file)
	FILE           *dump_file;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	struct s_portparam *dp_tail;
	int             lindex = 1;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	dp_tail = p_lhead;

	while (dp_tail != PORTNULL) {

		fprintf(dump_file, "\n%d. Listenelement \n", lindex);
		pr_element(dump_file, dp_tail);

		dp_tail = dp_tail->p_next;
		lindex++;
	}



}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       pr_sctlist            */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC   pr_element         VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print  one listelement                                */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*  Pointer                    Pointer of listelement      */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
void
pr_element(dump_file, elem)
	FILE           *dump_file;
	struct s_portparam *elem;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	if (elem != PORTNULL) {
		fprintf(dump_file, "\nListenelement \n");
		fprintf(dump_file, "  PORT_NAME    = %s\n", elem->port_name);
		fprintf(dump_file, "  BWT          = %d\n", elem->bwt);
		fprintf(dump_file, "  CWT          = %d\n", elem->cwt);
		fprintf(dump_file, "  BAUD         = %d\n", elem->baud);
		fprintf(dump_file, "  DATABITS     = %d\n", elem->databits);
		fprintf(dump_file, "  STOPBITS     = %d\n", elem->stopbits);
		fprintf(dump_file, "  PARITY       = %d\n", elem->parity);
		fprintf(dump_file, "  DATAFORMAT   = %d\n", elem->dataformat);
		fprintf(dump_file, "  TPDUSIZE     = %d\n", elem->tpdusize);
		fprintf(dump_file, "  APDUSIZE     = %d\n", elem->apdusize);
		fprintf(dump_file, "  EDC          = %d\n", elem->edc);
		fprintf(dump_file, "  PROTTYPE     = %d\n", elem->protocoltype);
		fprintf(dump_file, "  CHAINING     = %d\n", elem->chaining);
		fprintf(dump_file, "  NS           = %d\n", elem->ns);
		fprintf(dump_file, "  RSV          = %d\n", elem->rsv);
		fprintf(dump_file, "  SAD          = %d\n", elem->sad);
		fprintf(dump_file, "  DAD          = %d\n", elem->dad);
		fprintf(dump_file, "  SCHISTORY    = ");
		if (elem->schistory == NULL)
			fprintf(dump_file, "NULL\n");
		else
			fprintf(dump_file, "%s\n", elem->schistory);
		fprintf(dump_file, "  PORT_ID       = %d\n", elem->port_id);
		fprintf(dump_file, "  FIRST         = %d\n", elem->first);
		fprintf(dump_file, "  SETMODE       = %d\n", elem->setmode);

		if (elem->session_key.subjectkey.bits != NULL) {
			fprintf(dump_file, "  SESSIONKEY           = \n");
			fprintf(dump_file, "     subjectAI         = %x\n", elem->session_key.subjectAI);
			fprintf(dump_file, "     subjectkey.nbits  = %d\n", elem->session_key.subjectkey.nbits);
			fprintf(dump_file, "     subjectkey.bits   = \n");
			aux_fxdump(dump_file, elem->session_key.subjectkey.bits,
				 elem->session_key.subjectkey.nbits / 8, 0);
		} else {
			fprintf(dump_file, "  SESSIONKEY           = \n");
			fprintf(dump_file, "     subjectAI         = NULL\n");
			fprintf(dump_file, "     subjectkey.bits   = NULL\n");
		}

		fprintf(dump_file, "  SSC             = %x\n", elem->ssc);
		fprintf(dump_file, "  SECMESS_COMMAND = %d\n", elem->secure_messaging.command);
		fprintf(dump_file, "  SECMESS_RESPONSE= %d\n", elem->secure_messaging.response);
		fprintf(dump_file, "  SC_REQUEST      = %d\n\n", elem->sc_request);
	}
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       pr_element            */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E       s c t m e m           */
/*-------------------------------------------------------------*/
