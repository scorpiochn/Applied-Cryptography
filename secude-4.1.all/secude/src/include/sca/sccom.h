/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCCOM			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      sccom.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all  define's and structures        */
/*	for the SC-Interface	         		       */
/*-------------------------------------------------------------*/

/*--------------------------------*/
/* define sc-command-instruction  */
/* code                           */
/*--------------------------------*/
#define SC_EXRND        0xF8		/* EXCHANGE RAND */
#define SC_GET_CD       0xF6		/* GET CARD DATA */
#define SC_SETKEY	0x88
#define SC_SELECT       0xA6
#define SC_REGISTER     0xA4
#define SC_READF        0xB2		/* READ FILE     */
#define SC_LOCKF        0x8E		/* LOCK FILE     */
#define SC_DELREC       0x8A		/* DELETE RECORD */
#define SC_DELF         0xC8		/* DELETE FILE   */
#define SC_CLOSE        0xA8
#define SC_CHG_PIN      0x24		/* CHANGE PIN    */
#define SC_AUTH         0x42		/* AUTHENTICATE  */
#define SC_CREATE       0xD4
#define SC_WR_KEY       0xF7		/* WRITE_KEY     */
#define SC_WRITEF       0xB8		/* WRITE FILE    */
#define SC_LOCKKEY      0x86
#define SC_CRYPT        0x82



/*--------------------------------*/
/* define sc-command-parameter    */
/* length                         */
/*--------------------------------*/
#define SCILEN          3       /* max. length of              */
                                /* status control indicator = 3         */
#define RNDLEN          8       /* max. length of Random number = 8     */
#define AUTHRELLEN      8       /* max. length of auth-releated-info = 8 */
#define PINLEN          8       /* max. length of PIN = 8                */
#define DATLEN          254     /* max. length of data                   */
#define KEYLEN          254     /* max. length of key-data               */
#define SCPLEN          1       /* length of Security Control Parameter  */
#define KIDLEN          1       /* length of Key Identifier              */
#define REGACVLEN       1       /* length of Security Status Description */
                                /* of the REGISTER-Command               */
#define UNITLEN         2       /* max. length of UNITS                  */
#define OPLEN           1       /* max. length of Operation mode         */
#define SIZELEN         1       /* max. length of Record or Element Size */
#define FIDLEN          1       /* max. length of File Identifier   */
#define KEYHEAD         5       /* max. length of Key Header        */
#define MAXR_W_LEN      31      /* max. length of READ / WRITE - Data */

/*--------------------------------*/
/* define sc-command-parameter    */
/* values                         */
/* other values are in sta.h      */
/*--------------------------------*/
#define SC_NOTUSED      0x00
#define LOCK_CAT        0x03      /* EF */

typedef enum {ICC_TO_IFD,IFD_TO_ICC,BOTH} Direction;
typedef enum {SC_ENC,SC_DEC,SC_MAC} Modi;
typedef enum {CO_LOCK, CO_UNLOCK=0xFF} Context;
typedef enum {SC_NON_INTER=0xB0} CmdClass;
typedef enum {ACP_PIN=0x21, ACP_PUK=0x31, ACP_SC=0x42,
	      ACP_SCT=0x43,ACP_DTE=0x44,ACP_SC_SCT=0x45} AuthControlPar;




/*--------------------------------*/
/* define sc-command-header       */
/*--------------------------------*/
struct s_header {
        SecMess      security_mess;
        CmdClass     cmd_class;
        unsigned int inscode;
        };


/*--------------------------------*/
/* define sc-command-parameter    */
/*--------------------------------*/
struct s_exrnd  {
        Direction    di;			/* direction		*/
        unsigned int lrnd;			/* length of random	*/
        char        *rnd;                       /* random number        */
        };

struct s_get_cd {
        unsigned int cd_len;	
        };

struct s_setkey {
        KeyId  *auth_kid;			/* 0x00 => not used */
        KeyId  *conc_kid;                        /* values <= 255    */ 
        };
struct s_select {
        FileCat      id;			/* category id		*/
        FileInfoReq  fi;			/* requested file information */
        unsigned int scp;			/* select control parameter   */
                                                /* value <= 255               */
        char *fn;				/* filename		      */
        };

struct s_register {
        unsigned int  units;			/* space_high, space_low      */
        KeyId         *kid;			/* key_id => RFU              */
        unsigned int  acv;			/* access control value <= 255*/
        char *fn;				/* filename		      */
        };

struct s_readf {
        DataSel      *data_sel;
        FileId       *fid;
        unsigned int lrddata;
        };

struct s_lockf {
        Context      co;		
        FileId       *fid;		
        };

struct s_delrec {
        FileId       *fid;
        unsigned int rid;                       /* value <= 255              */
        };

struct s_delfile {
        FileCat      filecat;
        FileSel      *file_sel; 
        };

struct s_close {
        FileCat      filecat;
        FileCloseContext context;
        FileSel      *file_sel;
        };

struct s_chg_pin {
        KeyId        *kid;
        unsigned int len_oldpin;
        char        *old_pin;
        unsigned int len_newpin;
        char        *new_pin;
        };

struct s_auth {
        KeyId          *kid;
        AuthControlPar acp;  		/* authentication control parameter */
        unsigned int len_authd;			/* authentication data	*/
        char        *authd;
        };


struct s_create {			
        FileCat      filecat;
        FileType     filetype;
        DataStruc    datastruc;
        FileControlInfo *filecontrolinfo;
        };

struct s_write_key {
        KeyId          *kid;
        KeyAttrList   *keyattrlist;
        KeyAlgId       key_algid;
        unsigned   int key_len;
        char          *key_body;
        };


struct s_writef {
        DataSel      *data_sel; 
        FileId       *fid;
        unsigned int lwrdata;
        char *wrdata;
        };



struct s_lockk {
        Context      operation;
        KeyId        *kid;
        };

struct s_crypt {
        KeyId        *kid;
        Modi         modi;
        unsigned int lcrdata;
        char *crdata;
        };



/*--------------------------------*/
/* define sccom-structure         */
/*--------------------------------*/
struct s_command {
        struct s_header sc_header;
        union
               {
		struct s_exrnd     sc_exrnd;
		struct s_get_cd    sc_get_cd;
		struct s_setkey    sc_setkey;
                struct s_select    sc_select;
                struct s_register  sc_register;
                struct s_readf     sc_readf;
                struct s_lockf     sc_lockfile;
                struct s_delrec    sc_delrec;
                struct s_delfile   sc_delfile;
                struct s_close     sc_close;
		struct s_chg_pin   sc_chg_pin;
		struct s_auth      sc_auth;
                struct s_create    sc_create;
		struct s_write_key sc_write_key;
                struct s_writef    sc_writef;
                struct s_lockk     sc_lockkey;
                struct s_crypt     sc_crypt;
               } sc_uval;
        };







