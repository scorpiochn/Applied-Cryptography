/*
 *  SecuDE Release 4.1 (GMD)
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

/*-----------------------sectool.h----------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/* 	Grimm/Nausester/Schneider/Viebeg/Vollmer/                   */
/* 	Surkau/Reichelt/Kolletzki                     et alii       */
/*------------------------------------------------------------------*/
/* INCLUDE FILE  sectool.h                                          */
/* Definition of the structuretypes for SecuDE Tool                 */
/*	Kolletzki						    */
/*------------------------------------------------------------------*/





#ifndef _AF_
#include "af.h"
#endif
#ifdef MFCHECK
#include "MF_check.h"
#endif
#include <fcntl.h>
#include <stdio.h>





/*
 *	sectool globals
 */

#define OPEN_TO_READ	0
#define OPEN_TO_WRITE	1


typedef enum {
       ADDEK, ADDPK, ALGS, ALIAS2DNAME, AUTHNONE, AUTHSIMPLE,
#ifdef X500
#ifdef STRONG
       AUTHSTRONG,
#endif
#endif
       CACERTIFICATE, CAPEMCRL, CAPRINTLOG, CASERIALNUMBERS, CAUSERS, CERTIFY,
       CERT2KEYINFO, CERT2PKROOT, CHPIN, CHALLPIN, CHECK, CLOSE, CREATE, DELEK, DELETE,
       DELKEY, DELPK, DNAME2ALIAS,
#ifdef SCA
       EJECT,
#endif
       ENDE, ENTER, ERROR, EXIT, GENKEY, HELP, KEYTOC,
#ifdef MFCHECK
       MFLIST,
#endif 
       OPEN, PROTOTYPE, QM, QUIT, READ, REMOVE,
       RENAME, RESETERROR, RETRIEVE, REVOKE, SETPARM, SHOW,
       SPLIT, STRING2KEY, TOC,
#ifdef SCA
       TOGGLE,
#endif
       VERIFY, WRITE, XDUMP
} commands;



#ifdef X500
extern DName 			* directory_user_dname;    	/* defined in af_init.c */
extern int     			count;				/* defined in af_init.c */
extern char 			** vecptr;   			/* defined in af_init.c */
extern int     			auth_level;			/* defined in af_dir.c  */
#endif

extern int			SCapp_available;		/* defined in secude.c */		

extern	int     		cmd;
extern	Boolean 		replace;
extern	char    		inp[256];
extern	char    		* cmdname, * helpname, * filename, * pin, * newpin, * algname, * objtype, * attrname;
extern	CertificateType 	certtype;
extern	KeyRef  		keyref;
extern	Key     		*key, *publickey, *secretkey;
extern	Boolean 		interactive;
extern	char 			*pname, *ppin;
extern	int 			pkeyref;
extern	char			*newstring;
extern  char			*optarg;
extern  int			optind, opterr;
extern	int            		fd1, fd2, fdin;
extern	int             	i, anz, n, k, algtype, found;
extern	time_t          	atime, etime;
extern	char	        	opt, x500;
extern	Boolean         	update, create, replace_afdb_cert;
extern	char            	*enc_file, *plain_file, *tbs_file, *sign_file, *hash_file;
extern	char            	*buf1, *buf2, *ii, *xx;
extern	char            	*par, *dd, *ptr, *cc, *afname, *newname, *objname, *number;
extern	char	        	*pgm_name;
extern	char 	        	*revlistpempath;
extern	char            	*pse_name, *pse_path, *ca_dir, *home;
extern	RC              	rcode_dir, rcode_afdb, rcode;
extern	OctetString     	octetstring, *ostr, *objectvalue, *tmp_ostr;
extern	ObjId    		objecttype, object_oid, *oid;
extern	AlgId           	*algid;
extern	BitString       	bitstring, *bstr;
extern	HashInput       	hashinput;
extern	KeyInfo         	tmpkey, *keyinfo, *signpk, *encpk;
extern	FCPath          	*fcpath;
extern	PKList          	*pklist;
extern	PKRoot          	*pkroot;
extern	Certificate     	*certificate;
extern	Certificates    	*certs;
extern	ToBeSigned 		*tbs;
extern	SET_OF_Certificate 	*certset, *soc, *tmp_soc;
extern	CertificatePair 	*cpair;
extern	SET_OF_CertificatePair 	*cpairset;
extern	SEQUENCE_OF_RevCertPem 	*revcertpemseq;
extern	SET_OF_int      	*tmp_intset;
extern	Name            	*name, *alias, * issuer, * subject;
extern	DName			* dname, * issuer_dn, * subject_dn, * own_dname, * signsubject, * encsubject;
extern	EncryptedKey    	encryptedkey;
extern	rsa_parm_type   	*rsaparm;
extern	KeyType         	ktype;
extern	AlgEnc          	algenc;
extern	PSESel  		std_pse;
extern	PSESel          	*pse_sel;
extern	PSEToc          	*psetoc, *sctoc;
extern	struct PSE_Objects 	*pseobj;
extern	int 			serial;
extern	SET_OF_IssuedCertificate *isscertset;
extern	SET_OF_Name		*nameset;
extern	SerialNumbers   	* serialnums;	
extern	UTCTime 		*lastUpdate, *nextUpdate;	
extern	FILE            	*logfile;
extern	AlgList         	*a;
extern	Boolean         	onekeypaironly;

#ifdef AFDBFILE
extern	char		 	afdb[256];
#endif
#ifdef X500
extern	int 		 	dsap_index;
extern	char			*callflag;
#endif

#define TEMP_FILE		"/.stxv.txt.tmp"
#define ALIAS_FILE		"/.af-alias"



/* SecTool */

extern Boolean 			verbose;
extern Boolean 			sectool_verbose;
extern Boolean			alias_tool;
extern Boolean			directory_tool;
extern Boolean			alias_save_needed;

extern int			sectool_argc;
extern char			**sectool_argp;

extern int			pin_failure_count;
extern char			*unix_home;
extern char			tempfile[];
extern char			rmtemp[];
extern char			user_aliasfile[];
extern char			system_aliasfile[];
extern char			notice_text[];

extern unsigned 		mindex, allsize;		/* defined in malloc_free.c */
extern struct {					
	char 			*maddr;
	unsigned 		 msize;
	char			*mproc;
} mlist[];




struct pklistclientdata  {			/* PANEL_LIST_CLIENT_DATA for pk/ek-list */
	DName	*subject;
	DName	*issuer;
	int	serial;
};
typedef struct pklistclientdata PKList_client_data;



/*
 *	Global X defs & decs
 */

#define SECTXV_LARGE_BASE_HEIGHT	620				/* for one-key-pair-only, no EKList */
#define SECTXV_SMALL_BASE_HEIGHT	460				/* for two-key-pairs, with EKList */

#define SECTXV_PIN_LENGTH		80				/* textfield item max length in sectxv.G is 80, too */
#define SECTXV_PIN_FAILURES		3				/* you have three trials to enter ... */

#define SECTXV_BASE_SETTING_SC		1				/* bit masks for base setting values */
#define SECTXV_BASE_SETTING_SWPSE	2
#define SECTXV_BASE_SETTING_ONEKP	4

#define SECTXV_PSELISTSTR_LENGTH	100				/* list string properties */
#define SECTXV_PKLISTSTR_LENGTH		100

#define SECTXV_PKSERIAL_LENGTH		10 
#define SECTXV_ALIASLISTSTR_LENGTH	100

/* #define SECTXV_ALIASALIAS_LENGTH	25
#define SECTXV_ALIASDNAME_LENGTH	50
#define SECTXV_ALIASTEXT_LENGTH		50 */

#define SECTXV_SHOW_ALG			1				/* prop_show_menu items */
#define SECTXV_SHOW_BSTR		2
#define SECTXV_SHOW_DER			3
#define SECTXV_SHOW_ISSUER		4
#define SECTXV_SHOW_KEYBITS		5
#define SECTXV_SHOW_KEYINFO		6
#define SECTXV_SHOW_SIGNAT		7
#define SECTXV_SHOW_TBS			8
#define SECTXV_SHOW_VAL			9

#define SECTXV_ALIAS_NONE		0				/* alias_file_setting values (bit masks) */				
#define SECTXV_ALIAS_USER		1
#define SECTXV_ALIAS_SYSTEM		2
#define SECTXV_ALIAS_BOTH		3				
#define SECTXV_ALIAS_LOCALNAME		0				/* alias_type_setting values (index) */
#define SECTXV_ALIAS_RFCMAIL		1				
#define SECTXV_ALIAS_NEXTBEST		2				
#define SECTXV_ALIAS_X400MAIL		3	

#define SECTXV_NO_SELECTION		NULL				/* no list item selected */			





/* Window basics */
extern Xv_Server			Srv;
extern Display				*Dspl;
extern int				ScreenNo;
extern short				FullX, FullY;

extern Rect				*Rct;				/* used by macros */

/* X default values */
extern int				sectool_drag_threshold;
extern double				sectool_click_timeout;







/*
 *	my own X Macros
 */

#define SECTXV_RMTEMP()			system(rmtemp)
#define SECTXV_ALARM()			xv_set(sectxv_base_window->base_window, WIN_ALARM, NULL)
#define SECTXV_OPEN(object)		xv_set(object, XV_SHOW, TRUE, FRAME_CLOSED, FALSE, NULL)	
#define SECTXV_ACTIVE(object)		xv_set(object, PANEL_INACTIVE, FALSE, NULL)
#define SECTXV_INACTIVE(object)		xv_set(object, PANEL_INACTIVE, TRUE, NULL)	
#define SECTXV_SHOW(object)		xv_set(object, XV_SHOW, TRUE, NULL)
#define SECTXV_HIDE(object)		xv_set(object, FRAME_CMD_PUSHPIN_IN, FALSE, XV_SHOW, FALSE, FRAME_CMD_PUSHPIN_IN, TRUE, NULL)
#define SECTXV_BUSY(object,s)		xv_set(object, FRAME_BUSY, TRUE, FRAME_LEFT_FOOTER, s, NULL)
#define SECTXV_IDLE(object,s)		xv_set(object, FRAME_BUSY, FALSE, FRAME_LEFT_FOOTER, s, NULL)
#define SECTXV_BASE_BUSY(s)		SECTXV_BUSY(sectxv_base_window->base_window, s)
#define SECTXV_BASE_IDLE(s)		SECTXV_IDLE(sectxv_base_window->base_window, s)
#define SECTXV_SAVENEEDED(object)	xv_set(object, FRAME_RIGHT_FOOTER, "Save needed", NULL)
#define SECTXV_CLRFOOTER(object)	xv_set(object, FRAME_RIGHT_FOOTER, "", NULL)
#define SECTXV_CENTER(object)		{	xv_set(object, XV_X, xv_get(xv_get(object, XV_OWNER), XV_X)				\
							+ (xv_get(xv_get(object, XV_OWNER), XV_WIDTH) - xv_get(object, XV_WIDTH))/2,	\
							XV_Y, xv_get(xv_get(object, XV_OWNER), XV_Y)					\
							+ (xv_get(xv_get(object, XV_OWNER), XV_HEIGHT) - xv_get(object, XV_HEIGHT))/2,	\
							NULL);										\
						Rct = (Rect *)xv_get(object, XV_RECT);							\
						xv_set(object, WIN_MOUSE_XY,						\
							Rct->r_left + xv_get(object, XV_WIDTH)/2,			\
							Rct->r_top + xv_get(object, XV_HEIGHT)/2,			\
							NULL);    									}




/*
 *	function declarations
 */

off_t 			fsize();
time_t 			time();
char 			*sec_read_pin(), *getalgname();
char 			*gets(), *nxtpar(), *strmtch(), *getenv();
CertificatePair 	*specify_CertificatePair(), *compose_CertificatePair();
OctetString 		*aux_file2OctetString();
DName 			*getdname();
Name 			*getname();
Key 			*object();
Key			*build_key_object();
int 			getserial();
UTCTime 		*get_nextUpdate();



Xv_Font			load_font();
char 			*search_add_alias();
Notify_value 		base_destroy_func();
Notify_value 		dir_destroy_func();
Notify_value 		alias_destroy_func();



/*
 * *** *** *** *** ***
 * 	And now ...
 * *** *** *** *** ***
 */


#ifndef	sectxv_HEADER
#define	sectxv_HEADER

/*
 * sectxv_ui.h - User interface object and function declarations.
 */

extern Attr_attribute	INSTANCE;

extern Xv_opaque	sectxv_ca_menu_create();
extern Xv_opaque	sectxv_pse_menu_create();
extern Xv_opaque	sectxv_ca_user_menu_create();
extern Xv_opaque	sectxv_pse_pse_menu_create();
extern Xv_opaque	sectxv_pse_objects_menu_create();
extern Xv_opaque	sectxv_prop_menu_create();
extern Xv_opaque	sectxv_prop_dua_menu_create();
extern Xv_opaque	sectxv_prop_algs_menu_create();
extern Xv_opaque	sectxv_prop_debug_menu_create();
extern Xv_opaque	sectxv_ek_menu_create();
extern Xv_opaque	sectxv_pk_menu_create();
extern Xv_opaque	sectxv_ca_list_menu_create();
extern Xv_opaque	sectxv_key_list_menu_create();
extern Xv_opaque	sectxv_utilities_menu_create();
extern Xv_opaque	sectxv_prop_show_menu_create();
extern Xv_opaque	sectxv_dir_user_menu_create();
extern Xv_opaque	sectxv_pse_expert_menu_create();
extern Xv_opaque	sectxv_alias_find_menu_create();
extern Xv_opaque	sectxv_alias_names_menu_create();

typedef struct {
	Xv_opaque	base_window;
	Xv_opaque	base_controls;
	Xv_opaque	ca_button;
	Xv_opaque	pse_button;
	Xv_opaque	dir_button;
	Xv_opaque	alias_button;
	Xv_opaque	prop_button;
	Xv_opaque	utilities_button;
	Xv_opaque	base_clipboard_textfield;
	Xv_opaque	base_setting;
	Xv_opaque	base_ca_textfield;
	Xv_opaque	base_owner_textfield;
	Xv_opaque	base_pse_textfield;
	Xv_opaque	base_dname_textfield;
	Xv_opaque	base_dir_textfield;
	Xv_opaque	base_mail_textfield;
	Xv_opaque	base_created_textfield;
	Xv_opaque	base_changed_textfield;
	Xv_opaque	base_message;
	Xv_opaque	base_message1;
	Xv_opaque	base_message2;
	Xv_opaque	base_message3;
	Xv_opaque	pse_list;
	Xv_opaque	base_message5;
	Xv_opaque	base_message6;
	Xv_opaque	base_message7;
	Xv_opaque	pk_list;
	Xv_opaque	pk_button;
	Xv_opaque	base_message8;
	Xv_opaque	base_message9;
	Xv_opaque	base_message10;
	Xv_opaque	ek_list;
	Xv_opaque	ek_button;

	Xv_drop_site		drop_site;
	Xv_drag_drop		dnd;
	Selection_requestor	sel;

} sectxv_base_window_objects;

extern sectxv_base_window_objects	*sectxv_base_window_objects_initialize();

extern Xv_opaque	sectxv_base_window_base_window_create();
extern Xv_opaque	sectxv_base_window_base_controls_create();
extern Xv_opaque	sectxv_base_window_ca_button_create();
extern Xv_opaque	sectxv_base_window_pse_button_create();
extern Xv_opaque	sectxv_base_window_dir_button_create();
extern Xv_opaque	sectxv_base_window_alias_button_create();
extern Xv_opaque	sectxv_base_window_prop_button_create();
extern Xv_opaque	sectxv_base_window_utilities_button_create();
extern Xv_opaque	sectxv_base_window_base_clipboard_textfield_create();
extern Xv_opaque	sectxv_base_window_base_setting_create();
extern Xv_opaque	sectxv_base_window_base_ca_textfield_create();
extern Xv_opaque	sectxv_base_window_base_owner_textfield_create();
extern Xv_opaque	sectxv_base_window_base_pse_textfield_create();
extern Xv_opaque	sectxv_base_window_base_dname_textfield_create();
extern Xv_opaque	sectxv_base_window_base_dir_textfield_create();
extern Xv_opaque	sectxv_base_window_base_mail_textfield_create();
extern Xv_opaque	sectxv_base_window_base_created_textfield_create();
extern Xv_opaque	sectxv_base_window_base_changed_textfield_create();
extern Xv_opaque	sectxv_base_window_base_message_create();
extern Xv_opaque	sectxv_base_window_base_message1_create();
extern Xv_opaque	sectxv_base_window_base_message2_create();
extern Xv_opaque	sectxv_base_window_base_message3_create();
extern Xv_opaque	sectxv_base_window_pse_list_create();
extern Xv_opaque	sectxv_base_window_base_message5_create();
extern Xv_opaque	sectxv_base_window_base_message6_create();
extern Xv_opaque	sectxv_base_window_base_message7_create();
extern Xv_opaque	sectxv_base_window_pk_list_create();
extern Xv_opaque	sectxv_base_window_pk_button_create();
extern Xv_opaque	sectxv_base_window_base_message8_create();
extern Xv_opaque	sectxv_base_window_base_message9_create();
extern Xv_opaque	sectxv_base_window_base_message10_create();
extern Xv_opaque	sectxv_base_window_ek_list_create();
extern Xv_opaque	sectxv_base_window_ek_button_create();

typedef struct {
	Xv_opaque	key_popup;
	Xv_opaque	key_controls;
	Xv_opaque	key_show_button;
	Xv_opaque	key_xdump_button;
	Xv_opaque	key_delkey_button;
	Xv_opaque	key_genkey_button;
	Xv_opaque	key_string2key_button;
	Xv_opaque	key_cert2keyinfo_button;
	Xv_opaque	key_clipboard_textfield;
	Xv_opaque	key_list;
} sectxv_key_popup_objects;

extern sectxv_key_popup_objects	*sectxv_key_popup_objects_initialize();

extern Xv_opaque	sectxv_key_popup_key_popup_create();
extern Xv_opaque	sectxv_key_popup_key_controls_create();
extern Xv_opaque	sectxv_key_popup_key_show_button_create();
extern Xv_opaque	sectxv_key_popup_key_xdump_button_create();
extern Xv_opaque	sectxv_key_popup_key_delkey_button_create();
extern Xv_opaque	sectxv_key_popup_key_genkey_button_create();
extern Xv_opaque	sectxv_key_popup_key_string2key_button_create();
extern Xv_opaque	sectxv_key_popup_key_cert2keyinfo_button_create();
extern Xv_opaque	sectxv_key_popup_key_clipboard_textfield_create();
extern Xv_opaque	sectxv_key_popup_key_list_create();

typedef struct {
	Xv_opaque	ca_popup;
	Xv_opaque	ca_controls;
	Xv_opaque	ca_show_button;
	Xv_opaque	ca_revoke_button;
	Xv_opaque	ca_user_button;
	Xv_opaque	ca_clipboard_textfield;
	Xv_opaque	ca_list;
} sectxv_ca_popup_objects;

extern sectxv_ca_popup_objects	*sectxv_ca_popup_objects_initialize();

extern Xv_opaque	sectxv_ca_popup_ca_popup_create();
extern Xv_opaque	sectxv_ca_popup_ca_controls_create();
extern Xv_opaque	sectxv_ca_popup_ca_show_button_create();
extern Xv_opaque	sectxv_ca_popup_ca_revoke_button_create();
extern Xv_opaque	sectxv_ca_popup_ca_user_button_create();
extern Xv_opaque	sectxv_ca_popup_ca_clipboard_textfield_create();
extern Xv_opaque	sectxv_ca_popup_ca_list_create();

typedef struct {
	Xv_opaque	chpin_popup;
	Xv_opaque	chpin_controls;
	Xv_opaque	chpin_old_textfield;
	Xv_opaque	chpin_new_textfield;
	Xv_opaque	chpin_re_textfield;
	Xv_opaque	chpin_apply_button;
	Xv_opaque	chpin_cancel_button;
} sectxv_chpin_popup_objects;

extern sectxv_chpin_popup_objects	*sectxv_chpin_popup_objects_initialize();

extern Xv_opaque	sectxv_chpin_popup_chpin_popup_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_controls_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_old_textfield_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_new_textfield_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_re_textfield_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_apply_button_create();
extern Xv_opaque	sectxv_chpin_popup_chpin_cancel_button_create();

typedef struct {
	Xv_opaque	pin_popup;
	Xv_opaque	pin_controls;
	Xv_opaque	pin_textfield;
	Xv_opaque	pin_button;
} sectxv_pin_popup_objects;

extern sectxv_pin_popup_objects	*sectxv_pin_popup_objects_initialize();

extern Xv_opaque	sectxv_pin_popup_pin_popup_create();
extern Xv_opaque	sectxv_pin_popup_pin_controls_create();
extern Xv_opaque	sectxv_pin_popup_pin_textfield_create();
extern Xv_opaque	sectxv_pin_popup_pin_button_create();

typedef struct {
	Xv_opaque	create_popup;
	Xv_opaque	create_controls;
	Xv_opaque	create_textfield;
	Xv_opaque	create_apply_button;
	Xv_opaque	create_cancel_button;
} sectxv_create_popup_objects;

extern sectxv_create_popup_objects	*sectxv_create_popup_objects_initialize();

extern Xv_opaque	sectxv_create_popup_create_popup_create();
extern Xv_opaque	sectxv_create_popup_create_controls_create();
extern Xv_opaque	sectxv_create_popup_create_textfield_create();
extern Xv_opaque	sectxv_create_popup_create_apply_button_create();
extern Xv_opaque	sectxv_create_popup_create_cancel_button_create();

typedef struct {
	Xv_opaque	dir_window;
	Xv_opaque	dir_controls;
	Xv_opaque	dir_enter_button;
	Xv_opaque	dir_retrieve_button;
	Xv_opaque	dir_delete_button;
	Xv_opaque	dir_user_button;
	Xv_opaque	dir_clipboard_textfield;
	Xv_opaque	dir_textfield;
	Xv_opaque	dir_list;
} sectxv_dir_window_objects;

extern sectxv_dir_window_objects	*sectxv_dir_window_objects_initialize();

extern Xv_opaque	sectxv_dir_window_dir_window_create();
extern Xv_opaque	sectxv_dir_window_dir_controls_create();
extern Xv_opaque	sectxv_dir_window_dir_enter_button_create();
extern Xv_opaque	sectxv_dir_window_dir_retrieve_button_create();
extern Xv_opaque	sectxv_dir_window_dir_delete_button_create();
extern Xv_opaque	sectxv_dir_window_dir_user_button_create();
extern Xv_opaque	sectxv_dir_window_dir_clipboard_textfield_create();
extern Xv_opaque	sectxv_dir_window_dir_textfield_create();
extern Xv_opaque	sectxv_dir_window_dir_list_create();

typedef struct {
	Xv_opaque	alias_window;
	Xv_opaque	alias_controls;
	Xv_opaque	alias_type_setting;
	Xv_opaque	alias_file_setting;
	Xv_opaque	alias_find_button;
	Xv_opaque	alias_clipboard_textfield;
	Xv_opaque	alias_list;
	Xv_opaque	alias_dname_textfield;
	Xv_opaque	alias_localname_textfield;
	Xv_opaque	alias_rfcmail_textfield;
	Xv_opaque	alias_x400mail_textfield;
	Xv_opaque	alias_names_button;
	Xv_opaque	alias_names_textfield;
	Xv_opaque	alias_apply_button;
	Xv_opaque	alias_reset_button;
	Xv_opaque	alias_new_button;
	Xv_opaque	alias_add_button;
	Xv_opaque	alias_change_button;
	Xv_opaque	alias_delete_button;
} sectxv_alias_window_objects;

extern sectxv_alias_window_objects	*sectxv_alias_window_objects_initialize();

extern Xv_opaque	sectxv_alias_window_alias_window_create();
extern Xv_opaque	sectxv_alias_window_alias_controls_create();
extern Xv_opaque	sectxv_alias_window_alias_type_setting_create();
extern Xv_opaque	sectxv_alias_window_alias_file_setting_create();
extern Xv_opaque	sectxv_alias_window_alias_find_button_create();
extern Xv_opaque	sectxv_alias_window_alias_clipboard_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_list_create();
extern Xv_opaque	sectxv_alias_window_alias_dname_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_localname_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_rfcmail_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_x400mail_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_names_button_create();
extern Xv_opaque	sectxv_alias_window_alias_names_textfield_create();
extern Xv_opaque	sectxv_alias_window_alias_apply_button_create();
extern Xv_opaque	sectxv_alias_window_alias_reset_button_create();
extern Xv_opaque	sectxv_alias_window_alias_new_button_create();
extern Xv_opaque	sectxv_alias_window_alias_add_button_create();
extern Xv_opaque	sectxv_alias_window_alias_change_button_create();
extern Xv_opaque	sectxv_alias_window_alias_delete_button_create();

typedef struct {
	Xv_opaque	addalias_popup;
	Xv_opaque	addalias_controls;
	Xv_opaque	addalias_name_textfield;
	Xv_opaque	addalias_alias_textfield;
	Xv_opaque	addalias_apply_button;
	Xv_opaque	addalias_cancel_button;
} sectxv_addalias_popup_objects;

extern sectxv_addalias_popup_objects	*sectxv_addalias_popup_objects_initialize();

extern Xv_opaque	sectxv_addalias_popup_addalias_popup_create();
extern Xv_opaque	sectxv_addalias_popup_addalias_controls_create();
extern Xv_opaque	sectxv_addalias_popup_addalias_name_textfield_create();
extern Xv_opaque	sectxv_addalias_popup_addalias_alias_textfield_create();
extern Xv_opaque	sectxv_addalias_popup_addalias_apply_button_create();
extern Xv_opaque	sectxv_addalias_popup_addalias_cancel_button_create();

typedef struct {
	Xv_opaque	text_window;
	Xv_opaque	textpane;
} sectxv_text_window_objects;

extern sectxv_text_window_objects	*sectxv_text_window_objects_initialize();

extern Xv_opaque	sectxv_text_window_text_window_create();
extern Xv_opaque	sectxv_text_window_textpane_create();



extern	sectxv_base_window_objects	*sectxv_base_window;
extern	sectxv_key_popup_objects	*sectxv_key_popup;
extern	sectxv_ca_popup_objects		*sectxv_ca_popup;
extern	sectxv_chpin_popup_objects	*sectxv_chpin_popup;
extern	sectxv_pin_popup_objects	*sectxv_pin_popup;
extern	sectxv_create_popup_objects	*sectxv_create_popup;
extern	sectxv_dir_window_objects	*sectxv_dir_window;
extern	sectxv_alias_window_objects	*sectxv_alias_window;
extern	sectxv_addalias_popup_objects	*sectxv_addalias_popup;
extern	sectxv_text_window_objects	*sectxv_text_window;


extern Xv_opaque			sectxv_alias_list_user_glyph;
extern Xv_opaque			sectxv_alias_list_system_glyph;
extern Xv_opaque			sectxv_alias_list_both_glyph;
extern Xv_opaque			sectxv_pse_list_sc_glyph;
extern Xv_opaque			sectxv_pse_list_swpse_glyph;
	

extern	Menu				sectxv_show_options_menu;
#endif
