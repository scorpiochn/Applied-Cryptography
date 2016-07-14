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
/*      sctint.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all local define's and structures   */
/*	for the sctint-programm	         		       */
/*-------------------------------------------------------------*/

#define DEVICEMAX               3       /* number of devices = 3*/
/* Instructioncodes of the SCT-Commands                         */
/* local SCT - commands     */
#define S_REQUEST_SC            0x01    /* Request Smartcard    */
#define S_EJECT_SC              0x03    /* Eject Smartcard      */
#define S_STATUS                0x02    /* Status               */
#define S_DISPLAY               0x04    /* display text on SCT  */
#define S_RESET                 0x05    /* RESET SCT            */

/* SC - TRANSFER - Commands */
#define S_TRANS                 0x11    /* transport of SC-Commands */

/* Cryptology - commands    */
#define S_GEN_USER_KEY          0x21    /* generate user-key    */
#define S_INST_USER_KEY         0x22    /* install user-key     */
#define S_DEL_USER_KEY          0x23    /* delete  user-key     */
#define S_GET_RNO               0x24    /* get random number    */
#define S_RSA_SIGN              0x25    /* create signature     */
#define S_RSA_VERIFY            0x26    /* verify signature     */
#define S_DES_ENC               0x27    /* DES-encryption       */
#define S_RSA_ENC               0x28    /* RSA-encryption       */
#define S_DES_DEC               0x29    /* DES-decryption       */
#define S_RSA_DEC               0x2A    /* RSA-decryption       */
#define S_ENC_DES_KEY           0x2B    /* encrypt DES-KEY      */
#define S_DEC_DES_KEY           0x2C    /* decrypt DES-KEY      */

/* Device key   - commands  */
#define S_GEN_DEV_KEY		0x31	/* generate device keys */
#define S_INST_DEV_KEY		0x32	/* install device keys  */
#define S_DEL_DEV_KEY		0x33	/* delete device keys   */

/* Authenticate - commands  */
#define S_INST_PIN              0x41    /* install PIN-Record   */
#define S_CHANGE_PIN            0x42    /* change PIN           */
#define S_AUTH                  0x43    /* authentication       */

/* Secure messaging  - commands  */
#define S_GET_TRANSPORT_KEY     0x51    /* get transport key    */
#define S_GEN_SESSION_KEY       0x52    /* install session key  */


/* Keycard      - commands  */
#define S_WRITE_KEYCARD         0x61    /* write keycard        */
#define S_READ_KEYCARD          0x62    /* read  keycard        */



/* values of the parameter ACP   aut       */
#define PIN_OFF                 0x20
#define PIN_USER                0x21
#define SC_DES                  0x42
#define SCT_DES                 0x43
#define SC_SCT_DES              0x45
#define PUK_CHECK               0x31 
#define SCT_INITIAL             0x46


typedef int BOOL;

typedef enum {SCT_END,SCT_MORE} SCTMore;
typedef enum {COM_DUMMY0,DTE_SCT} ComLine;


typedef enum {S_PIN,S_PUK,S_DES_CBC,S_DES_3_CBC,S_RSA_F4,NOT_DEFINED} KeyAlgId;


/* Structure - definitions              */
typedef struct s_sctinfo  {
        unsigned int  apdusize;
        char          *history_sc;
        BOOL           port_open;
        BOOL           sc_request;
        BOOL           sessionkey;
               } SCTInfo;


typedef struct s_bytestring  {
        unsigned int  nbytes;
        char         *bytes;
               } Bytestring;

typedef struct s_public{
         Bytestring   *modulus;
         Bytestring   *exponent;
         } Public;



typedef struct s_enc     {
         Public     *public;
         Bytestring *plaintext;
         } Enc;

typedef struct s_verify {
         Public       *public;
         Bytestring   *signature;
         Bytestring   *hash;
         } Verify;

typedef struct s_deskey {
         int        algid;
         Bytestring *chiffrat;
        } DESKey;

typedef struct s_dev_key_info {		
	 KeyPurpose    purpose;
         KeyDevStatus  status;
         KeyDevType       type;
        } DevKeyInfo;


typedef struct s_dev_inst_key {		
        union {
                char          kid;
                KeyPurpose    purpose;
              }pval;
        }DevInstKey;

typedef struct s_pin_record {		
        KeyAlgId     key_algid;
        KeyAttrList *pin_attr;
        Bytestring  *pin_record;
        } PINRecord;

typedef struct s_session_key {
         SecMessMode sec_mode;
         ComLine     com_line;
         Bytestring  *session_key;
        }SessionKey;

typedef struct s_writekeycard {		
         char	     auth_keyid;
	 char        sec_auth_keyid;
	 char        sec_con_keyid;
        }WriteKeycard;

#ifdef OLDIMPL
typedef struct s_writekeycard {		
         Bytestring  *pin_record;
	 Boolean     key2_status;
	 DevInstKey  *key2;
	 Boolean     key3_status;
	 DevInstKey  *key3;
        }WriteKeycard;
#endif
                



typedef struct s_request  {
         union p1 {
               char            kid;     /* S_GEN_USER_KEY, S_INST_USER_KEY,*/
				        /* S_DEL_USER_KEY, 	        */
				        /* S_GEN_DEV_KEY,               */
                                        /* S_GEN_SESSION_KEY            */
                                        /* S_RSA_SIGN, S_INST_PIN,      */
                                        /* S_CHANGE_PIN,                */
                                        /* S_RSA_ENC, S_RSA_DEC,        */
                                        /* S_DES_ENC, S_DES_DEC,        */
                                        /* S_DEC_DES_KEY, S_ENC_DES_KEY,*/
                                        /* S_RSA_VERIFY, S_AUTH         */
               TransMode       secmode; /* S_TRANS                      */
               unsigned int    lrno;    /* S_GET_RNO                    */
               DevInstKey      *dev_inst_key;  /* S_INST_DEV_KEY        */
                                               /* S_DEL_DEV_KEY         */
                                               /* S_WRITE_KEYCARD       */
                  }rq_p1;
         union p2 {
               unsigned int    time;    /* S_REQUEST_SC,S_DISPLAY       */
	       Boolean         signal;  /* S_EJECT_SC			*/
               KeyAlgId        algid;   /* S_GEN_USER_KEY               */
                                        /* S_GEN_DEV_KEY                */
                                        /* S_GET_TRANSPORT_KEY          */
                                        /* S_GEN_SESSION_KEY            */
               SCTMore         more;    /* S_RSA_ENC, S_RSA_DEC,        */
                                        /* S_DES_ENC, S_DES_DEC         */
               char            kid;     /* S_DEC_DES_KEY                */
               unsigned int    acp;     /* S_AUTH                       */
               KeyDevStatus    status;  /* S_INST_DEV_KEY               */
                                        /* S_DEL_DEV_KEY                */
                                        /* S_WRITE_KEYCARD              */
                                        /* S_READ_KEYCARD               */
               SecMess         *sec_mode; /* S_CHANGE_PIN    ???????            */ 
                  }rq_p2;

         union datafield {
               Bytestring      *outtext;        /* S_REQUEST_SC, S_DISPLAY,
						   S_EJECT_SC */
               unsigned int     keylen;         /* S_GEN_USER_KEY          */
               DevKeyInfo      *dev_key_info;   /* S_GEN_DEV_KEY           */
               KeyAttrList     *keyattrlist;	/* S_INST_USER_KEY	   */
                                                /* S_INST_DEV_KEY          */
               Bytestring      *hash;           /* S_RSA_SIGN              */
               PINRecord       *pin;            /* S_INST_PIN              */
               Enc             *enc;            /* S_RSA_ENC               */
               Bytestring      *chiffrat;       /* S_RSA_DEC, S_DES_DEC    */
               Bytestring      *plaintext;      /* S_DES_ENC               */
               DESKey          *deskey;         /* S_DEC_DES_KEY           */
               Public          *public;         /* S_ENC_DES_KEY           */
               Bytestring      *sccommand;      /* S_TRANS                 */
               Verify          *verify;         /* S_RSA_VERIFY            */
               SecMess         *auth_secmode;   /* S_AUTH                  */
               SessionKey      *session_key;    /* S_GEN_SESSION_KEY       */
               WriteKeycard    *write_keycard;  /* S_WRITE_KEYCARD  ?????? */
             } rq_datafield;
         } Request;




/* NULL-Pointer - Definitions           */
#define PUBNULL         (Public  *)0
#define ENCNULL         (Enc  *)0
#define BYTENULL        (Bytestring   *)0
#define VERNULL         (Verify  *)0
#define DESKNULL        (DESKey  *)0
#define REQNULL         (Request *)0
#define DEVNULL		(DevKeyInfo *)0
#define PINNULL		(PINRecord *)0
#define SESSNULL	(SessionKey *)0
#define WRITENULL	(WriteKeycard *)0
#define KEYATTRNULL	(KeyAttrList *)0



