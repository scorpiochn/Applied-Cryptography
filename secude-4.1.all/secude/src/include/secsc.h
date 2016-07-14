/******************************************************************
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

/*-----------------------------------------------------------------------*/
/* INCLUDE FILE  sc_mod.h                                                */
/* Definition of structures and types for the 				 */
/* SEC-IF - SCA-IF interface module (secsc).				 */
/*-----------------------------------------------------------------------*/

#ifndef _SECSC_
#define _SECSC_

/*
 *
 *   secure.h defines:
 *          AlgId               (typedef struct AlgId)
 *          BitString           (typedef struct Bitstring)
 *          Boolean             (typedef char)
 *          EncryptedKey        (typedef struct EncryptedKey)
 *          ENCRYPTED           (typedef struct BitString)
 *          EncryptedKey        (typedef struct EncryptedKey) 
 *          KeyBits             (typedef struct KeyBits)
 *          More                (typedef enum { END, MORE })
 *          ObjId               (typedef struct ObjId)
 *          OctetString         (typedef struct Octetstring)
 *          Signature           (typedef struct Signature)
 *
 *   sca.h defines:
 *           Structures and types of the SCA-IF
 */

#include "sca.h"

/*-----------------------------------------------------------------------*/
/*     G l o b a l s     						 */
/*-----------------------------------------------------------------------*/

extern Boolean SC_verify, SC_encrypt, SC_ignore, SC_ignore_SWPSE;

extern int     SC_timer;	/* During this time interval (in seconds) the 	*/
				/* SCT accepts the insertion of an SC.		*/
				/* The timer starts after the user has been 	*/
				/* requested to insert the SC.			*/
				/* If the variable is set to 0, no timer is     */
				/* specified.					*/

/*
 *  External initialization of SC_timer:
 *  
  int		SC_timer =	SC_WAITTIME;
 */



/*-----------------------------------------------------------------------*/
/*     E r r o r  -  c o d e s						 */
/*-----------------------------------------------------------------------*/
#define ERR_flag	-1
#define EOF_flag	-2
#define EOF_with_ERR	-3
  
#define NOERR		 0
#define ENOSC		50
#define ESCAUTH         51	/* authentication failed		*/
#define ESECMESS        52	/* secure messaging failed		*/
#define ECONFIG         53	/* Error in SC-Obj-list or  		*/
				/* error in configuration file 		*/
#define ENOTSUPP        54	/* Function not supported by the SC-Env	*/
#define ESCTID          55	/* Invalid value of sc_sel.sct_id	*/
#define EPINLOCK	56	/* PIN on SC locked			*/
#define EEJECT		57	/* Eject failed				*/
#define EKEYSEL		58	/* Selection of key failed		*/
#define EPSEPIN		59	/* CannGenot get PIN for SW-PIN from SC	*/
#define ESCOPEN		60	/* Open app/object on SC		*/
#define EOBJPIN		61	/* If SC, PIN for object not supported	*/
#define ESCCLOSE	62	/* Close app/object on SC		*/
#define ESCDELETE	63      /* Delete object on SC			*/
#define ESCREAD		64      /* Cannot read from SC object		*/
#define ESCWRITE	65      /* Cannot write from SC object		*/
#define ESCAPP		66      /* Application  not an SC application	*/
#define ESCREQUEST	67      /* Request SC failed			*/
#define EDISPLAY	68      /* Cannot display text on SCT-display   */
#define ESCPUK		69      /* Cannot unblock PIN on SC		*/
#define EPUKLOCK	70	/* PUK on SC locked			*/
#define ESCPROCDATA	71	/* Error during SCT configuration       */
				/* (process data)			*/
#define ESCPROCKEY	72	/* Error with the key for encryption/	*/
				/* decryption of the process data	*/
/*-----------------------------------------------------------------------*/
/*     D e f i n i t i o n s      					 */
/*-----------------------------------------------------------------------*/
#define USER_BELL	 "\007" /* Control character  to "ring the bell" */
 


/*-----------------------------------------------------------------------*/
/*     T e x t  - ,  C h a r a c t e r  -  D e f i n i t i o n s  	 */
/*-----------------------------------------------------------------------*/
#define SC_CONFIG_name   ".scinit"
#define	SCT_CONFIG_name	 ".sctinit."		/* Name of the SCT configuration file   */
						/* (one file per SCT)			*/
#define SCA_SCT_CONFIG_name ".sca_sct_init."	/* Name of the SCA-SCT configuration 	*/
						/* file (one file per SCT)		*/
#define SC_PROCESS_KEY	 "SC_PROCESS_KEY"	/* Name of an environment variable	*/

#define APP_KEY_WORD     "APPLICATION"
#define OBJ_KEY_WORD     "OBJECT"
#define IGN_KEY_WORD	 "IGNORE"
#define SC_ENC_KEY_WORD	 "SC_ENCRYPT"
#define SC_VER_KEY_WORD	 "SC_VERIFY"
#define TRUE_WORD	 "TRUE"
#define FALSE_WORD	 "FALSE"
#define SC_KEY_WORD	 "SC_KEY"
#define SC_FILE_WORD	 "SC_FILE"
#define DF_WORD		 "DF"
#define MF_WORD		 "MF"
#define SF_WORD		 "SF"
#define WEF_WORD	 "WEF"
#define NORM_WORD	 "NORM"
#define AUTH_WORD	 "AUTH"
#define CONC_WORD	 "CONC"
#define COMB_WORD	 "COMB"

#define COMMENT		 '#'
#define BLANK_CHAR	 ' '
#define TAB		 '\t'
#define COMMA		 ','
#define EQUAL		 '='
#define CR_CHAR		 '\r'			/* carriage return */


 

/*-----------------------------------------------------------------------*/
/*     M a x  - M i n  -  Definitions					 */
/*-----------------------------------------------------------------------*/
#define PSE_PIN_L	 8	/* length of the PSE-PIN stored on the SC 	*/
#define MAXL_APPNAME	 8	/* max length of the name of an application on  */
				/* the SC					*/
#define UNIT_SIZE	32	/* Size of a file on the SC is specified in     */
				/* units					*/
#define MAX_PIN_FAIL	 3	/* Max number of faulty PIN authentications	*/
#define MAX_SCRESET_FAIL 3	/* Max number of failed SC resets		*/
#define WEF_LEN_BYTES	 2	/* No. of bytes used to store the length of     */
                                /* a WEF on the SC.				*/
#define MAX_READWRITE_BYTES 31	/* Max no. of bytes which can be read/write     */
                                /* to/from the SC with one call.		*/
#define SC_WAITTIME	20	/* After the request an SC is accepted within 	*/
				/* this time (in seconds).			*/
#define MAX_RECORD     512	/* max length of record in configuration file	*/
#define NO_OF_SM	 5	/* max number of secure messaging parameters    */
				/* for one object in configuration file		*/
#define	MAXSCTID_LEN	 2	/* No. of ASCII characters used for the sct_id.	*/
#define PROCESS_KEY_LEN	 8	/* length of the process key			*/
#define MAX_LEN_PROC_KEY 64	/* Max length of the process key.		*/

/*-----------------------------------------------------------------------*/
/*     Max. number of list entries					 */
/*-----------------------------------------------------------------------*/
#define MAX_SCAPP 	20	/* max # of applications stored on the smartcard*/
				/* List: sc_app_list[]				*/
#define MAX_SCOBJ 	20	/* max # of objects stored on the smartcard	*/
				/* List: sc_obj_list[]				*/
#define MAX_SCTNO 	20	/* max # of SCTs				*/
				/* List: sct_stat_list[]			*/



/*-----------------------------------------------------------------------*/
/*     Texts for the SCT-display					 */
/*-----------------------------------------------------------------------*/
/*				  12345678901234561234567890123456	 */
#define SCT_TEXT_PIN_LOCKED	 "PIN on SC locked                "
#define SCT_TEXT_PUK_LOCKED	 "PUK on SC locked		  "
#define SCT_TEXT_PIN_INVALID	 "  PIN invalid    		  "
#define SCT_TEXT_PIN_PUK_INVALID "   PIN or PUK      invalid      "
#define SCT_TEXT_NEW_PIN_INV	 " New PIN invalid                "
#define SCT_TEXT_RESET_SC_ERR	 "  Reset of SC       failed!     "
#define SCT_TEXT_SCT_CHECK	 "   SCT check                    "


/*-----------------------------------------------------------------------*/
/*     Type definitions							 */
/*-----------------------------------------------------------------------*/
typedef	enum   {ALL_SCTS, CURRENT_SCT}	SCTSel;
typedef struct SCT_Status		SCTStatus;
typedef struct SC_Sel           	SCSel;
typedef	struct SCAppEntry		SCAppEntry;
typedef	struct SCObjEntry		SCObjEntry;
typedef	enum   {SC_KEY_TYPE, SC_FILE_TYPE}	SCObjType;
typedef	struct SCId			SCId;
typedef	struct SCAFctPar		SCAFctPar;
typedef enum  {SYSTEM_CONF, USER_CONF}  WhichSCConfig;



typedef struct File_Par {
	FileId	file_id;
	int	no_of_bytes;	 /* no of bytes to be reserved for the WEF on the SC */
} FilePar;


/*-----------------------------------------------------------------------*/
/*     Selection of the SCT and the SC					 */
/*-----------------------------------------------------------------------*/

struct SC_Sel {
       int      sct_id;         		/* selected sct number   	*/

};
extern SCSel sc_sel;

/*
 *  External initialization of sc_sel:
 *  
 #	1    -> select first SCT in the installation file (list of the connected SCTs)
  SCSel		sc_sel =	{ 1 };
 */





/*
 *  Definitions of security mode(s) used for the communication between DTE-SCT and SCT-SC
 */

#define NORM	SEC_NORMAL			/* Normal mode			*/
#define AUTH	AUTHENTIC			/* Authentic mode		*/
#define CONC	CONCEALED			/* Concealed mode		*/
#define COMB	COMBINED			/* Authentic and concealed mode	*/





/*-----------------------------------------------------------------------*/
/*     SCT-List								 */
/*     Contains current status information for max. 20 SCTs		 */
/*-----------------------------------------------------------------------*/
   
struct SCT_Status {
	Boolean	  config_done;			/* = TRUE,  configuration done, e.g.    */
						/*          process data read.		*/ 
						/* = FALSE, configuration not yet done. */
	Boolean   available;			/* = TRUE , SCT is available		*/
						/* = FALSE, SCT is not available	*/
	char	  app_name[MAXL_APPNAME+1];	/* name of the application on the SC,   */
						/* which has been opened, else = CNULL  */
	char	  sw_pse_pin[PSE_PIN_L+1];	/* PIN for the application on the 	*/
						/* SW-PSE, else = CNULL  		*/
        SecMess	  sm_SCT;			/* Security mode for the command and	*/
						/* response exchange between DTE and SCT*/
	Boolean	  user_auth_done;		/* = TRUE,  if user authentication has  */
						/*          been performed.		*/ 
						/* = FALSE, if user authentication has  */
						/*          not been performed.		*/ 
};
	


extern SCTStatus		sct_stat_list[MAX_SCTNO+1];	

/*
 *  External initialization of sct_stat_list[]:
 *  
 *
 *      config	available,	sm_SCT,      app_name,	sw_pse_pin,     user_auth_done
 *	done			cmd,  resp.,
{

	FALSE,	FALSE,	 	NORM, NORM,    "",	 "",		FALSE,  # 0. SCT (not available) #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 1. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "",	 "",		FALSE,	# 2. SCT #
	FALSE,	FALSE,	 	NORM, NORM,    "",	 "",		FALSE,	# 3. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "",	 "",		FALSE,	# 4. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 5. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 6. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 7. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 8. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 9. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "",	 "",		FALSE,	# 10. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "",	 "",		FALSE,	# 11. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 12. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 13. SCT #
	FALSE,	FALSE,	 	NORM, NORM,    "",	 "",		FALSE,	# 14. SCT #
	FALSE,	FALSE,	 	NORM, NORM,    "",	 "",		FALSE,	# 15. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 16. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 17. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 18. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE,	# 19. SCT #
	FALSE,	FALSE, 		NORM, NORM,    "", 	 "",		FALSE	# 20. SCT #
	
};
 *
 */






/*-----------------------------------------------------------------------*/
/*     P S E  -  O b j e c t s, if a smartcard environment is available  */
/*-----------------------------------------------------------------------*/

/*
 *  Names of PSE-Objects additional to the PSE-Objects defined in af.h
 */

#define SC_PIN_name     "SC_PIN"  		 /* PIN for the smartcard	*/
#define SC_PUK_name     "SC_PUK"  		 /* PUK for the smartcard	*/
#define PSE_PIN_name    "PSE_PIN"  		 /* PIN for the SW-PSE		*/
#define SCToc_name      "SCToc"  		 /* Toc in the SC		*/

struct SCId {
	int	level;				 /* level for key/file		*/ 
	int	type;				 /* used as file-type		*/
	int	no;				 /* key-no | file_name		*/
};

/*
 *  If a smartcard (SC) environment is available,
 *     the following list is used to address objects stored on the smartcard.
 *  This list is integrated within the list of the applications stored on the SC
 */
   
struct SCObjEntry {
        char		*name;			/* SC object name			*/
	SCObjType	type;			/* Type of the object (key, file)	*/
	SCId		sc_id;			/* Identifier for a key/file on the SC	*/
	int		size;		        /* size of a file on the SC             */
	SecMessMode	sm_SCT;			/* Security mode (one value) for the 	*/
						/* command and response exchange 	*/
						/* between DTE and SCT.			*/
	SecMess		sm_SC_read;		/* Security mode for the command and	*/
						/* response exchange between SCT/SC, if */
						/* the PSE-Object is read from the SC.	*/
						/* Separat values for cmd. and response.*/
	SecMess		sm_SC_write;		/* Security modes for the command and	*/
						/* response exchange between SCT/SC, if */
						/* the PSE-Object is written to the SC.	*/
						/* Separat values for cmd. and response.*/
};


/*
 *  If a smartcard (SC) environment is available,
 *     the following list contains the names of the applications and the 
 *     belonging objects stored on the SC.
 */
   
struct SCAppEntry {
        char		*app_name;		   /* SC application name	  	  */
        Boolean		ignore_flag;		   /* TRUE:  If the Software-PSE part cannot be opened
                                             		     with the pin from SC_PIN_name, sec_open
                                             		     ignores this error.
                                      		      FALSE: sec_open returns -1 in this case          */
	SCObjEntry	sc_obj_list[MAX_SCOBJ+1];  /* List of the objects belonging to    */
						   /* the application			  */

};




extern SCAppEntry	sc_app_list[MAX_SCAPP+1];	

/*
 *  External initialization of sc_obj_list[]:
 *  
  SCAppEntry		sc_app_list[0] = {0};
 *
 */







/*
 *  If a smartcard (SC) environment is available, 
 *     the SEC-IF function calls are transformed into SCA-IF function calls.
 *  The SCA-IF functions are transformed into a command and response protocol,
 *  which is used between the DTE/SCT and SCT/SC.
 *
 *  The following list contains the SCA-Functions and their security mode(s) for 
 *  the communication between DTE/SCT and SCT/SC, resp.:
 *	 
 */
   
struct SCAFctPar {
        char		*fct_name;		/* SCA-Function name			*/
	SecMess		sm_SCT;			/* Security mode for the  command and	*/
						/* response exchange between DTE and SCT*/
	SecMess		sm_SC;			/* Security mode for the command and	*/
						/* response exchange between SCT and SC.*/
						/* Separat values for cmd. and resp..	*/
};


extern SCAFctPar	sca_fct_list[];	


/*
 *  External initialization of sca_fct_list[]:
 *  
  SCAFctPar	sca_fct_list[] =

# fct_name,		  sm_SCT,	   sm_SC
#			cmd,   resp.	cmd,	resp. 
  {
  "sca_init_sc",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_get_sc_info",	NO_SM, NORM,   NO_SM,	NO_SM,
  "sca_eject_sc",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_gen_user_key",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_del_user_key",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_sign",		NORM,  NORM,   NO_SM,	NO_SM,
  "sca_verify",		NORM,  NORM,   NO_SM,	NO_SM,
  "sca_encrypt",	CONC,  NORM,   CONC,	NORM,
  "sca_decrypt",	NORM,  CONC,   NORM,	CONC,
  "sca_enc_des_key",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_dec_des_key",	NORM,  NORM,   NO_SM,	NO_SM,
  "sca_auth",		NORM,  NORM,   NO_SM,	NO_SM,
  "sca_create_file",	NORM,  NORM,   NORM,	NORM,
  "sca_select_file",	NORM,  NORM,   NORM,	NORM,
  "sca_close_file",	NORM,  NORM,   NORM,	NORM,
  "sca_delete_file",	NORM,  NORM,   NORM,	NORM,
  "sca_set_mode",	NORM,  NORM,   NO_SM,	NO_SM,
  0
  };
 */



/* Function prototypes  */

PSEToc *read_SCToc(), *create_SCToc(), *chk_SCToc();
RC write_SCToc(), update_SCToc(), delete_SCToc();
Boolean is_in_SCToc(); 

#endif
