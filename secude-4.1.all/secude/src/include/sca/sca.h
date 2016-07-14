/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAPAC  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	STAMOD			VERSION 2.0	       */
/*					   DATE Januar 1992    */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      sca.h    		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all structures and types for the    */
/*	STAPAC Application Interface         		       */
/*-------------------------------------------------------------*/
/*
 *   secure.h defines:
 *
 *         AlgId,
 *         BitString,  
 *         Boolean, 
 *         EncryptedKey,
 *         ENCRYPTED,
 *         KeyBits,
 *         More,
 *         ObjId,
 *         OctetString, 
 *         Signature,
 */

#include "secure.h"



/*------------------------------------------------------------------*/
/*  MAX values for parameters of the application interface          */
/*------------------------------------------------------------------*/


#define MAX_FILENAME    8       /* max. length fo file name         */
#define MAX_ADDINFO     4       /* max. length of add info of file control info */
#define RECNULL           (RecordList *)0


/*------------------------------------------------------------------*/
/*  Definitions                                                     */
/*------------------------------------------------------------------*/

/* authentication object identifiers */
#define smartcard    2
#define sct          3
#define sct_sc       5
#define INITIAL      6

/* authentication procedure identifiers */
#define des_auth     4

#ifndef TRUE
#define TRUE		1
#endif
#ifndef FALSE
#define FALSE		0
#endif



/*------------------------------------------------------------------*/
/*  General type definitions                                        */
/*------------------------------------------------------------------*/

typedef int AuthObjectId;		/* object to be authenticated     */
typedef int AuthProcId;			/* authentication procedure       */


/*------------------------------------------------------------------*/
/*  Definitions for secure messaging                                */
/*------------------------------------------------------------------*/
typedef enum {SEC_NORMAL,AUTHENTIC,CONCEALED,COMBINED}  SecMessMode;
typedef enum {TRANSP, SECURE}   TransMode;        /* transfer mode for the     */ 
						  /* function sca_trans        */
                                                  /* of smartcard commands     */


typedef struct Sec_Mess {
		SecMessMode command;
                SecMessMode response;
               } SecMess;


/*------------------------------------------------------------------*/
/*  Type Definitions for Smartcard Files                            */
/*------------------------------------------------------------------*/

typedef  enum {MF, DF, SF, EF} FileCat;           /* file category               */

typedef  enum {NONE_INFO, SHORT_INFO} FileInfoReq;
                                                  /* file information requested  */

typedef  enum {MF_LEVEL, DF_LEVEL, SF_LEVEL} FileLevel;
                                                  /* level of an elementary file */

typedef  enum {PEF, WEF, ACF, ISF} FileType;      /* type of an elementary file  */

typedef  enum { LIN_FIX=1, LIN_VAR, CYCLIC, TRANSPARENT} DataStruc;
                                                  /*  structure of an elementary */
						  /*  file                       */ 

typedef  enum {CLOSE_CREATE, CLOSE_SELECT} FileCloseContext;
                                                  /* finish a creation process   */
                                                  /* or close a selected file    */




typedef enum {READ_WRITE,WORM,READ_ONLY,WRITE_ONLY} ReadWrite;
						  /* read/write access mode      */
                                                  /* (part of FileControlInfo)   */ 

typedef enum {FILE_UNLOCKED, FILE_LOCKED} FileAccess;
						  /* Status of file access       */

typedef enum {MEM_CONSISTENT, MEM_INCONSISTENT} FileMemory;
						  /* Status of file memory       */
typedef enum {REGISTERED,DELETED,DEL_PENDING,INSTALLED} InstallStatus;
						  /* Status of file installation */

typedef  OctetString AddInfo;                     /* additional information      */




typedef struct Record_Sel {			  /* for LIN_FIX,LIN_VAR         */
        unsigned int  record_id;                  /* Record identifier           */
        unsigned int  record_pos;                 /* Position                    */
}                      RecordSel;

typedef struct Element_Sel {			  /* for CYCLIC                  */
        unsigned int  element_ref;                /* Element reference           */
        unsigned int  element_no;                 /* Numbers of elements         */
}                      ElementSel;

typedef unsigned int  StringSel;		  /* for TRANSPARENT             */



typedef struct Data_Sel {
        DataStruc   data_struc;                   
        union { 				  /* data access to an:          */
	        RecordSel   record_sel;	          /* record oriented file        */
                ElementSel  element_sel;          /* cyclic file                 */
                StringSel   string_sel;           /* transparent file            */ 
              }data_ref; 
}                      DataSel;


typedef struct File_Id {                          /* File_id for an elementary   */
                                                  /* file (EF)                   */   
        FileLevel     file_level;                 /* level of the EF             */
        FileType      file_type;                  /* type of the EF              */
        unsigned int  name;                       /* possible values: 0-15       */
}                          FileId;

typedef union File_Sel {
        char     *file_name;                      /* to select an MF, DF or SF   */
        FileId   file_id;                         /* to select an EF             */
}                          FileSel;

typedef struct File_Status {                      /* file status                 */
        InstallStatus  install_status;
        FileMemory     file_memory;
        FileAccess     file_access;                    
}                          FileStatus;

typedef struct File_Info {                        /* file information            */ 
        FileStatus  file_status;                  /* file status                 */
        AddInfo     addinfo;                      /* additional information      */
}
                          FileInfo;

typedef struct File_Cont_info {                   /* file control information    */
        unsigned int units;                       /* number of units             */
                char racv;                        /* read acv                    */
                char wacv;                        /* write acv                   */
                char dacv;                        /* delete acv                  */
        ReadWrite    readwrite;                   /* READ / WRITE - Mode         */
        Boolean      execute;                     /* execute - mode - RFU        */
        Boolean      mac;                         /* mac - mode - RFU            */
        Boolean      enc;                         /* encrypted mode - RFU        */
        Boolean      not_erasable;                /* erase - flag                */
        unsigned int recordsize;                  /* record size                 */
        FileSel      file_sel;                    /* filename / file_id          */
        AddInfo  addinfo;                         /* additional information      */
}                      FileControlInfo;

 
typedef struct Record_List {
        OctetString         record;
        struct Record_List  *next;
}RecordList;



/*------------------------------------------------------------------*/
/*  structure for key handling                                      */
/*------------------------------------------------------------------*/
typedef enum {MASTER, COMMON}   KeyDevType;       /* type of a device key        */

typedef enum {INST,REPL} KeyInstMode;             /* the key is to be installed  */
                                                  /* or replaced                 */ 

typedef enum {REPLACE,NO_REPLACE} KeyOpMode;      /* key is replaceable /        */
                                                  /* key is nor replaceable      */

typedef enum {KEY_GLOBAL,KEY_LOCAL} KeyPresent;   /* global use or local use     */
                                                  /* of the key                  */

typedef enum { KEY_NORMAL, KEY_LOCKED } KeyState; /* internal status of the key  */
                                                  /* or PIN                      */

typedef enum {DEV_OWN, DEV_ANY } KeyDevStatus;    /* status of a device key      */
                                                  /* OWN=dev_key for local use   */
                                                  /* ANY=dev_key for distribution*/    

typedef enum {SC_MF,SC_DF,SC_SF,SCT } KeyLevel;   /* specifies where the key is  */
                                                  /* stored                      */  

typedef enum {PIN,PUK} PINType;                   /* type of a PIN               */ 


 

typedef struct Key_purpose {                      /* purpose of a key            */
        Boolean authenticate;                     /* authentication key ?        */
        Boolean sec_mess_auth;          /* secure messaging key (authentic) ?    */ 
        Boolean sec_mess_con;           /* secure messaging key (concealed) ?    */
        Boolean cipherment;                       /* user key ?                  */
}            KeyPurpose;

typedef struct Key_Status {                       /* SC internal status of the   */
                                                  /* key/PIN                     */  
        Boolean   PIN_check;                      /* FALSE=inactive              */
                                                  /* TRUE =active                */
        KeyState  key_state;                      /* State of the key            */
}            KeyStatus;

typedef struct Key_attr {                         /* key attributes              */
        KeyPurpose    key_purpose;                /* purpose of the key          */ 
        KeyPresent    key_presentation;           /* key presentation            */ 
        KeyOpMode     key_op_mode;                /* replaceable/not replaceable */
        unsigned int  MAC_length;                 /* length of MAC               */
} KeyAttr;

 struct KEYAttrList {                             /* key attribute list for the SC*/
        KeyInstMode   key_inst_mode;              /* installation or replacement  */
        KeyAttr       key_attr;                   /* several key attributes       */
        unsigned int  key_fpc;                    /* key fault presentation counter*/
        KeyStatus   key_status;                   /* SC internal status of the key*/
};
  
typedef struct KEYAttrList KeyAttrList;

struct KEYId   {                                  /* key identifier              */
        KeyLevel     key_level;                   /* key level                   */
        unsigned int key_number;                  /* number in the range 1 to 63 */ 
};

typedef struct KEYId KeyId;

typedef struct Key_Dev_List    {		  /* defines the list of dev keys*/
	KeyId        *auth_key;  		  /* authentication key 	*/
	KeyId        *sec_auth_key;		  /* authenticate key for 	*/
						  /* secure messaging		*/
	KeyId        *sec_con_key;		  /* concealed  key for 	*/
						  /* secure messaging		*/

} KeyDevList;


typedef struct Key_Dev_Purpose {		  /* defines a device key	*/
	KeyPurpose   key_purpose;		  /* purpose of the device key	*/
	KeyDevStatus key_dev_status;		  /* local use or distribution 	*/
	KeyDevType   key_type;			  /* MASTER / COMMON key 	*/
} KeyDevPurpose;
       


typedef struct Key_Sel {                          /* this structure identifies   */
                                                  /* a key                       */
        AlgId	    *key_algid;			  /* Alg-Id of the key	         */
	KeyBits     *key_bits;			  /* In case of rsa key this     */
                                                  /* structure contains the      */
                                                  /* public key                  */
						  /* (part1 = modulus m;	 */
						  /*  part2 = exponent e)	 */
        KeyId        key_id;                      /* key identifier              */
}                          KeySel;


typedef struct Key_Dev_Sel {			  /* this structure identifies a */
					 	  /* a device Key			*/
	KeyDevStatus    key_status;		  /* OWN/ ANY				*/
	union {
		     KeyId	key_id;		  /* If ANY, select by key_id		*/
		     KeyPurpose key_purpose;	  /* If OWN, select by purpose		*/
	      } dev_ref;
}			    KeyDevSel;

 



typedef struct PIN_Info {
        unsigned int min_len;			  /* minimum length of a new PIN */
                                                  /* value                       */
	char        *pin;			  /* value of the PIN	         */
 	char        *clear_pin;			  /* value of the Clear PIN      */
}			   PINInfo;


typedef struct PUK_Info {
	char	    *puk;			  /* value of the PUK	         */
	KeyId	     pin_key_id;		  /* key_id of the corresponding */
						  /* PIN		         */
}		           PUKInfo;
	

typedef struct PIN_Struc {
	PINType	    pin_type;			  /* PIN or PUK	                 */
	union {
		PINInfo		pin_info;	  /* Body for a PIN	         */
		PUKInfo		puk_info;	  /* Body for a PUK	         */
	      }  PINBody;
}			   PINStruc;
				 
     

/*------------------------------------------------------------------*/
/*  structure for the hash function                                 */
/*------------------------------------------------------------------*/
typedef union Hashpar {
	KeyBits	        sqmodn_par;		  /* modulus of public rsa key   */

}			   HashPar;	








