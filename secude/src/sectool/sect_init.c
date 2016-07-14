
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

/*-----------------------sect_init.c--------------------------------*/
/*                                                                  */
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (I2)                  */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDE" 1991/92/93                */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer 	                    */
/* Luehe/Surkau/Reichelt/Kolletzki		                    */
/*------------------------------------------------------------------*/
/* PACKAGE   util            VERSION   3.0                          */
/*                              DATE   20.01.1992                   */
/*                                BY   ws                           */
/*                                                                  */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PROGRAM   sectool         VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/* PROGRAM   sect_init       VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/*------------------------------------------------------------------*/



#include "sect_inc.h"




/*
 *	sectool globals
 */



int     		cmd;
Boolean 		replace;
char    		inp[256];
char    		* cmdname, * helpname, * filename, * pin, * newpin, * algname, * objtype, * attrname;
CertificateType 	certtype;
KeyRef  		keyref;
Key     		*key, *publickey, *secretkey;
Boolean 		interactive = TRUE;
char 			*pname, *ppin;
int 			pkeyref;
char			*newstring;
extern char		*optarg;
extern int		optind, opterr;
int            		fd1, fd2, fdin;
int             	i, anz, n, k, algtype, found;
time_t          	atime, etime;
char	        	opt, x500 = TRUE;
Boolean         	update, create, replace_afdb_cert;
char            	*enc_file, *plain_file, *tbs_file, *sign_file, *hash_file;
char            	*buf1, *buf2, *ii, *xx;
char            	*par, *dd, *ptr, *cc, *afname, *newname, *objname, *number;
char	        	*pgm_name;
char 	        	*revlistpempath;
char            	*pse_name = CNULL, *pse_path = CNULL, *ca_dir = CNULL, *home;
RC              	rcode_dir, rcode_afdb, rcode;
OctetString     	octetstring, *ostr, *objectvalue, *tmp_ostr;
ObjId    		objecttype, object_oid, *oid;
AlgId           	*algid;
BitString       	bitstring, *bstr;
HashInput       	hashinput;
KeyInfo         	tmpkey, *keyinfo, *signpk, *encpk;
FCPath          	*fcpath;
PKList          	*pklist;
PKRoot          	*pkroot;
Certificate     	*certificate;
Certificates    	*certs;
ToBeSigned 		*tbs;
SET_OF_Certificate 	*certset, *soc, *tmp_soc;
CertificatePair 	*cpair;
SET_OF_CertificatePair *cpairset;
SET_OF_int      	*tmp_intset;
Name            	*name, *alias, * issuer, * subject;
DName			* dname, * issuer_dn, * subject_dn, * own_dname, * signsubject, * encsubject;
EncryptedKey    	encryptedkey;
rsa_parm_type   	*rsaparm;
KeyType         	ktype;
AlgEnc          	algenc;
PSESel  		std_pse;
PSESel          	*pse_sel;
PSEToc          	*psetoc, *sctoc;
struct PSE_Objects 	*pseobj;
int 			serial;
SET_OF_IssuedCertificate *isscertset;
SET_OF_Name		*nameset;
SerialNumbers   	* serialnums;	
UTCTime 		*lastUpdate, *nextUpdate;	
AlgList         	*a;
Boolean         	onekeypaironly = FALSE;

#ifdef AFDBFILE
char		 	afdb[256];
#endif
#ifdef X500
int 		 	dsap_index;
char			*callflag;
#endif



/* SecTool */

Boolean 		verbose = FALSE;
Boolean 		sectool_verbose = FALSE;
Boolean			alias_tool = FALSE;
Boolean			directory_tool = FALSE;
Boolean			alias_save_needed = FALSE;

int			sectool_argc;
char			**sectool_argp;

int			pin_failure_count;
char			*unix_home;
char			tempfile[256];
char			rmtemp[256];
char			user_aliasfile[256];
char			system_aliasfile[256];
char			notice_text[256];


/* XView */

Attr_attribute	INSTANCE;

sectxv_base_window_objects	*sectxv_base_window;
sectxv_key_popup_objects	*sectxv_key_popup;
sectxv_ca_popup_objects		*sectxv_ca_popup;
sectxv_chpin_popup_objects	*sectxv_chpin_popup;
sectxv_pin_popup_objects	*sectxv_pin_popup;
sectxv_create_popup_objects	*sectxv_create_popup;
sectxv_dir_window_objects	*sectxv_dir_window;
sectxv_alias_window_objects	*sectxv_alias_window;
sectxv_addalias_popup_objects	*sectxv_addalias_popup;
sectxv_text_window_objects	*sectxv_text_window;

Xv_opaque			sectxv_alias_list_user_glyph;
Xv_opaque			sectxv_alias_list_system_glyph;
Xv_opaque			sectxv_alias_list_both_glyph;
Xv_opaque			sectxv_pse_list_sc_glyph;
Xv_opaque			sectxv_pse_list_swpse_glyph;
	
Menu				sectxv_show_options_menu;

 
/* Window basics */
Xv_Server			Srv;
Display				*Dspl;
int				ScreenNo;
short				FullX, FullY;

Rect				*Rct;				/* used by macros */

/* X default values */
int				sectool_drag_threshold;
double				sectool_click_timeout;
