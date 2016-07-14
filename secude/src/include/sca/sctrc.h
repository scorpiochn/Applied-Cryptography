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
/*    FILENAME			                 	       */
/*      sctrc.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all returncodes from the t1-modul,  */
/*	SCT-interface-modules and the smartcard	               */
/*-------------------------------------------------------------*/

/* Returncodes from the sctinterface - Procedure                       */
#define S_NOERR                 0       /* no error                    */
#define S_WAIT                  1       /* SCT waiting                  */
#define S_KEYREPL               2       /* Key in SCT replaced          */
#define S_SIGOK                 3       /* Signatur correct, but Key too*/
                                        /* short                        */
#define S_PINOFF                4       /* PIN-CHECK off    90 01       */
#define S_PINON                 5       /* PIN-CHECK on                 */

#define S_ERR                   -1      /* error (errornumber in sct_errno */




/* Errors from the transmission - module                               */
#define EREAD                   1       /* Read error                   */
#define EWRITE                  2       /* Write error                  */
#define EEDCERR                 3       /* EDC - Error                  */
#define EMEMO                   4       /* Memory error                 */
#define EOPEN                   5       /* Open error                   */
#define ECLOSE                  6       /* Close error                  */
#define EBWTERR                 7       /* BWT - Timeout                */
#define ECWTERR                 8       /* CWT - Timeout error          */
#define EINVLEN                 9       /* Invalid length               */
#define ETPDULEN                10      /* TPDU-Length error            */
#define EINVALIDPORT            11      /* Not available port */
#define ESYSCALL                12      /* Error from system call    */
#define EPROTRESYNCH            13      /* Protocol has been resynchronized.
                                           and
                                     communication can be started again with
                                     new protocol parameter state.        */
#define ESCTRESET               14/* Smart card terminal should be reset
                                     communication can be started again with
                                     new protocol parameter state.        */

#define ESYNTAX                 15      /* Block format error        */


/* Errors      from the SmartCard - Terminal                           */
/*---------------------------------------------------------------------*/
/* SW1(41)=Parameter not correct or inconsistent                       */
/*---------------------------------------------------------------------*/
#define EINVCLASS               20      /* wrong CLASS                  41 00*/
#define EINVINS                 21      /* wrong INS                    41 01*/
#define EINVKID                 22      /* invalid  KID                 41 02*/
#define EINVALGID               23      /* invalid  algorithm identifier41 03*/
#define EOPMODE                 24      /* Operation Mode not allowed   41 04*/
#define EPARMISSED              25      /* parameter in body missing    41 05*/
#define EINVPAR                 26      /* parameter in body invalid    41 06*/
#define EDATALEN                27      /* incorrect datalength         41 07*/
#define EUSERIN                 28      /* user input incorrect         41 08*/
#define EP1P2INC                29      /* P1 - P2 incorrect            41 09*/
#define EDATL2INC	        30      /* data length leve 2 incorrect 41 0A*/
#define ECOMCOUNT               31      /* communication counter incorrect 41 0B*/


/*---------------------------------------------------------------------*/
/* SW1(42)=key access error                                            */
/*---------------------------------------------------------------------*/
#define EKEYUNKNOWN             32      /* Key unknown                  42 00*/
#define EKEYALGINCON            33      /* KEY and ALGID inconsistent   42 01*/
#define EKEYNOTREPL             34      /* Key not replaceable          42 02*/
#define EKEYINFO                35      /* incorrect Key-Information at */
                                        /* keycard                      42 03*/

/*---------------------------------------------------------------------*/
/* SW1(43)=Parameter- or Dataerror                                     */
/*---------------------------------------------------------------------*/
#define EDUMMY                  36      /* RFU                          43 00*/
#define ESCCOM                  37      /* SC-Command not allowed       43 01*/
#define EDECLEN                 38      /* incorrect length of ciphertext43 02*/
#define EINVSIG                 39      /* invalid  signature           43 03*/
#define EKEYLENINV              40      /* Keylength invalid            43 04*/
#define ESCTNOMEM               41      /* no memory available          43 05*/
#define EAUTH                   42      /* Authentication failed        43 06*/
#define ESCTRES                 43      /* reset of SCT not successful  43 07*/
#define EEXECDEN                44      /* execution denied             43 08*/
#define ESERVNOTAVAIL           45      /* service not available        43 09*/
#define ESECMESSKEY             46      /* secure messaging key undefined43 0A*/
#define EAUTHKEY                47      /* authentication key undefined 43 0B*/



/*---------------------------------------------------------------------*/
/* SW1(44)=Communication-error with smartcard                          */
/*---------------------------------------------------------------------*/
#define ENOCARD                 48      /* no smartcard                 44 00*/
#define ERESET                  49      /* reset of SC not successful   44 01*/
#define ESCREMOVED              50      /* SC removed                   44 02*/
#define ESCTIMEOUT              51      /* Timeout     - no response from44 03*/
                                        /* SC                           */
#define EUSERBREAK              52      /* break from user              44 04*/
#define EUSTIMEOUT              53      /* Timeout     - no response from44 05*/
                                        /* user                          */

/*---------------------------------------------------------------------*/
/* SW1(45)=internal address-error                                      */
/*---------------------------------------------------------------------*/
#define ESCTADDR                54      /* internal address-error       45 00*/



/* Errors      from the Smartcard                                      */
/*---------------------------------------------------------------------*/
/* CLASS = Application independent error                               */
/*---------------------------------------------------------------------*/
/* SW1 = 6x  and 90 03          */
#define EDATAINC_CLPEN		59	/* DATA_INCONSISTENCY	   90 03  */
					/* CLOSE_PENDING_LEVEL            */
					/* NO_DATA_FOUND		  */ 
#define ECLASS                  60      /* INVALID_CLASS           6E 00  */
#define ESCIN                   61      /* INVALID_INS             6D 00  */
#define EFCBUPDATE              62      /* FCB_UPDATE_ERROR        6F 00  */
#define EVCC                    63      /* EEPROM_VCC_ERROR        6F 01  */
#define ECOMP                   64      /* EEPROM_COMP_ERROR       6F 02  */
#define EPARINC                 65      /* INVALID_PARAMETER       6B 00  */
#define ESID_NOLOCK             66      /* SID_INCORRECT           6B 01  */
                                        /* NO_LOCK_IAP                    */
#define EPOSLEN                 67      /* WRONG_POS_LEN_SPECIFIED 67 01  */
                                        /* INVALID_FID_LEN                */
                                        /* INVALID_NAME_LENGTH            */
                                        /* SIZE_NOT_OK                    */
                                        /* SIZE_TOO_BIG                   */
#define ELENINPUT               68      /* SPECIFIED_SIZE_NOT_OK   67 02  */
                                        /* INVALID_DATA_LENGTH            */
#define ELENOUTPUT              69      /* TOO_MANY_DATA           67 03  */
#define EINVBODYLEN             70      /* INVALID_BODY_LENGTH     67 04  */
#define EPARBODY_SPACE          71      /* INVALID_BODY_PARAMETER  67 05  */
                                        /* INVALID_SPACE_PARAMETER        */

/*---------------------------------------------------------------------*/
/* CLASS = Application protocol error                                  */
/*---------------------------------------------------------------------*/
/* SW1 = 50                             */
#define ECLPENDLEVEL            72      /* CLOSE_PEND_LEVEL        50 00  */
#define ECMD                    73      /* COM_NOT_ALLOWED         50 01  */
#define EACF                    74      /* INVALID_COM_ACF         50 02  */
#define EINVFROM                75      /* INVALID_FROM            50 03  */
#define EEFACVDENY              76      /* EF_ACV_DENY             50 04  */


/*---------------------------------------------------------------------*/
/* CLASS =                                                             */
/* internal integrity management error                                 */
/*---------------------------------------------------------------------*/
/*SW1 = 91                              */
#define ESCADDR                 77      /* ADDRESS_ERROR           91 01  */
#define EINVACF                 78      /* NO_VALID_ACF            91 03  */
                                        /* ACF_NO_EF                      */
#define EECC                    79      /* UNDETECTED_ECC_ERROR    00 00  */
#define ESYS_OFFSET             80      /* SYSTEM_INVALID_OFFSET   00 51  */  


/*---------------------------------------------------------------------*/
/* CLASS = memory management error                                     */
/*---------------------------------------------------------------------*/
/* SW1 = 92                             */
#define ESYS                    81      /* SYSTEM_WRONG_FILE_PTR   92 01  */
                                        /* SYSTEM_MD_DIR_INCONS           */
                                        /* WRONG_FREE_MD                  */
                                        /* SYSTEM_NR_MD                   */
                                        /* INITIAL_CTR_WRONG              */ 
#define EFILEALREADY            82      /* EF_DF_MF_SF_ALREADYEXIST92 02  */
#define ESPACE                  83      /* NOT_ENOUGH_SPACE        92 03  */
#define ERIDALREADY             84      /* RID_ALREADY_EXIST       92 05  */


/*---------------------------------------------------------------------*/
/* CLASS = referencing management error                                */
/*---------------------------------------------------------------------*/
/* SW1 = 94                             */
#define ENOTREG                 85      /* DF_NOT_REGISTERED       94 01  */
                                        /* EF_REGISTERED                  */
#define ENOTFOUND               86      /* FILE_NOT_FOUND          94 02  */
#define EINVRID                 87      /* RID_NOT_FOUND           94 03  */
                                        /* INVALID_RID                    */
#define EACFNOTFOUND            88      /* ACF_NOT_FOUND           94 04  */
#define EFILE                   89      /* NO_READ_IA              94 05  */
                                        /* INVALID_CAT_TYP                */
                                        /* INVALID_OP_MODE                */
                                        /* INVALID_NAME                   */
#define ESYS_MF                 90      /* SYSTEM_OPEN_NO_OPEN     94 06  */
                                        /* MF_NOT_ACTIVE                  */
#define ENODAT                  91      /* NO_DAT_CLOSE_PEND       94 07  */

/*---------------------------------------------------------------------*/
/* CLASS = security management error                                   */
/*---------------------------------------------------------------------*/
/* SW1 = 98                             */
#define EINVKEYSEL              92      /* INVALID_KEY_SEL         98 01  */
#define EKEYLOCK                93      /* KEY_LOCKED              98 02  */
#define EPININC                 94      /* INVALID_PIN_LEN         98 03  */
                                        /* PUK_TO_NO_PIN                  */
#define ENEWPIN                 95      /* NEW_PIN_INCORRECT       98 04  */
                                        /* CPIN_NOT_ALLOWED               */
#define EACCESS                 96      /* FILE_LOCKED             98 05  */
                                        /* FILE_ONLY_REGISTERED           */
                                        /* NO_ACTUAL_DF                   */
                                        /* FILE_NOT_DF                    */
                                        /* PIN_OFF_PUK                    */
                                        /* NO_DELETE                      */
#define EAUTH_WRITE             97      /* AUT_FAILED              98 06  */
                                        /* NO_WRITE_IAP                   */
                                        /* NO_RND_EXIST                   */
#define EALGO                   98      /* WRONG_ALGO              98 07  */
#define EKIDEDC                 99      /* KID_INVALID_EDC         98 08  */
#define EKFPC                  100      /* KFPC_ERR                98 09  */
#define ENOSECKEY              101      /* NO_SEC_MESS_KEY         98 0A  */
#define ESSC                   102      /* WRONG_SSC               98 0B  */
#define EMAC                   103      /* WRONG_MAC               98 0C  */
#define ELAST                  104      /* LAST_BLOCK              98 0D  */  


/* Errors      from the sct-Interface and sccom module (local errors)            */
#define EINVARG                 105     /* invalid argument             */
#define EMEMAVAIL               106     /* memory not available         */
#define EINVDEVICE              107     /* invalid devicenumber         */
#define ETOOLONG                108     /* apdu too long or             */
					/* length of parameter invalid  */
#define ENOSHELL                109     /* no shell-variable in env.    */
#define EOPERR                  110     /* can't open install-file      */
#define EEMPTY                  111     /* install-file empty           */
#define ECLERR                  112     /* install-file not successfully
			                   closed */
#define ERDERR                  113     /* Read error on install-file   */
#define ESIDUNK                 114     /* SCT_ID unknown               */
#define ELENERR                 115     /* Length error                 */
#define EBAUD                   116     /* Baudvalue not allowed        */
#define EDESENC                 117     /* Data can`t be encrypted      */
#define EDESDEC                 118     /* Data can`t be decrypted      */
#define EGENSESS                119     /* Can't generate sessionkey    */
#define ERSAENC                 120     /* Error after RSA encryption   */
#define EKEY                    121     /* Can't set RSA key            */
#define ESCT_SSC                122      /* WRONG_SSC  from SCT         */


/* SW1 = no error                                                       */
#define OKSCT                   0x40
#define OKSC                    0x90
#define DATAINC			0x03


