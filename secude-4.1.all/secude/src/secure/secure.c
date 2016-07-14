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

/*-------------secure-cryptographic-fuctions and i/o functions------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990                                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   secure             VERSION   3.0                       */
/*                                      DATE   27.11.1990           */
/*                                        BY   Tr./Na./Gr./WS       */
/* DESCRIPTION                                                      */
/*   This modul presents the cryptographic functions and            */
/*   the basic i/o functions of the ``sec-interface''.              */
/*   More basic algorithmic functions of RSA, DSA and DES           */
/*   are called (imported) here.                                    */
/*                                                                  */
/* EXPORT                                                           */
/*   sec_chpin          sec_close       sec_create                  */
/*   sec_decrypt        sec_del_key     sec_delete                  */
/*   sec_encrypt        sec_gen_key     sec_get_EncryptedKey        */
/*   sec_get_key        sec_hash        sec_get_keysize             */
/*   sec_open           sec_print_toc   sec_put_EncryptedKey        */
/*   sec_put_key        sec_read        sec_read_toc                */
/*   sec_rename         sec_sign        sec_string_to_key           */
/*   sec_verify         sec_write       sec_write_toc               */
/*   sec_checkSK        sec_sctest      sec_psetest                 */
/*   sec_read_PSE       sec_unblock_SCpin 			    */
/*   sec_write_PSE   	sec_pin_check	                            */
/*   get_unixname						    */
/*                                                                  */
/* STATIC                                                           */
/*   chk_parm                                                       */
/*   fsize                                                          */
/*   get_keyinfo_from_key                                           */
/*   get2_keyinfo_from_key                                          */
/*   get_keyinfo_from_keyref                                        */
/*   get2_keyinfo_from_keyref                                       */
/*   object_reencrypt                                               */
/*   pin_check                                                      */
/*   put_keyinfo_according_to_key                                   */
/*   pse_name                                                       */
/*   read_toc                                                       */
/*   write_toc                                                      */
/*                                                                  */
/*   open_app_on_SC()					            */
/*   handle_in_SCTSC()						    */
/*                                                                  */
/* IMPORT                                                           */
/*   rsa_encrypt        aux_cpy_KeyInfo                             */
/*   rsa_decrypt        aux_cpy2_KeyInfo                            */
/*   hash_sqmodn        aux_cpy2_AlgId                              */
/*   rsa_sign           aux_cmp_AlgId                               */
/*   rsa_verify         aux_cmp_ObjId                               */
/*   rsa_get_key        aux_free_OctetString                        */
/*   des_ebc_encrypt    aux_free_KeyInfo                            */
/*   des_cbc_encrypt    d2_KeyInfo                                  */
/*   rsa_gen_key        e_KeyInfo                                   */
/*   e_DName            d_DName                                     */
/*   sec_read_pin                                                   */
/*   aux_current_UTCTime                                            */
/*   aux_readable_UTCTime                                           */
/*								    */
/*   SECSC-IF:							    */
/*     secsc_close()     	Close application on the SC.        */
/*     secsc_chpin()     	Change PIN for application on SC.   */
/*     secsc_create()     	Create file (WEF) on the SC.        */
/*     secsc_delete()     	Delete file (WEF) on the SC.        */
/*     secsc_del_key()     	Delete key stored in an SCT.        */
/*     secsc_decrypt()     	Decrypt octetstring within SCT/SC.  */
/*     secsc_encrypt()     	Encrypt octetstring within SCT/SC.  */
/*     secsc_gen_key()     	Generate key and install key on SCT */
/*				or SC.				    */
/*     secsc_get_EncryptedKey() Encrypt key within SCT/SC.	    */
/*     secsc_open()  	        Open application on the SC.         */
/*     secsc_put_EncryptedKey() Decrypt key within SCT/SC.	    */
/*     secsc_read()  	        Read data from file (WEF) on SC     */
/*				into octetstring.		    */
/*     secsc_sc_eject()         Eject SC(s).			    */
/*     secsc_sign()  	        Sign octetstring with key from SC.  */
/*     secsc_verify()  	        Verify signature (with SCT).        */
/*     secsc_unblock_SCpin()    Unblock blocked PIN of the SC-app.  */
/*     secsc_write()  	        Write octetstring into file (WEF)   */
/*				on SC.				    */
/*     aux_AppName2SCApp()	Get information about an SC app.    */
/*     aux_AppObjName2SCObj()	Get information about an SC object  */
/*			        belonging to an application on SC.  */
/*     check_SCapp_configuration()				    */
/*				Check consistency of configuration  */
/*				data for an SC-application.	    */
/*     get_pse_pin_from_SC()	Read the PIN for the SW-PSE from    */
/*				the SC and sets it in 		    */
/*			        "sct_status_list[]".		    */
/*     handle_sc_app()	        If application not open, open it.   */
/*     SC_configuration()	Perform SC configuration (get data  */
/*				form file ".scinit".		    */
/*     SCT_configuration()	Perform SCT configuration (get data */
/*   				from a prior process).              */
/*								    */
/*------------------------------------------------------------------*/


#define DIRMASK 0700		/* directory creation mask */
#define OBJMASK 0600		/* object creation mask */

#include "secure.h"

#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <stdlib.h>
#include <string.h>
#include "MacTypes.h"
#include "Mac.h"
#endif /* MAC */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
extern int      errno;

/*
 *    Local variables, but global within secure.c
 */

static          pse_pw;
static char    *pse_name(),  *pin_check(), *key_pool_pw();
static KeyInfo  got_key;
static PSEToc  *psetoc, *read_toc();
static int      update_toc();
static int      get2_keyinfo_from_keyref();
static RC       put_keyinfo_according_to_key();

static struct PSE_Objects **locate_toc();
static PSESel  *set_key_pool();
static off_t    fsize();
static int      chk_parm(), write_toc(), object_reencrypt();
KeyInfo        *get_keyinfo_from_keyref();
KeyInfo        *get_keyinfo_from_key();
char	       *get_unixname();
static OctetString *get_encodedkeyinfo_from_keyref();
static char     text[128];
static void     strzero();
static RC       open_object(), read_object();
extern AlgId    desCBC_pad_aid;	/* from sec_init.c */
static AlgId   *sec_io_algid = &desCBC_pad_aid;	/* Default Algid for the
						 * encryption of the PSE */
static ObjId    dummy_oid;

static PSESel   sec_key_pool = {
	".key_pool", CNULL, { CNULL, CNULL }, 0
};

#ifdef SCA
static PSEToc  *sc_toc;
extern SCAppEntry *aux_AppName2SCApp();
extern SCObjEntry *aux_AppObjName2SCObj();
extern int      secsc_close();
extern int      secsc_chpin();
extern int      secsc_create();
extern int      secsc_delete();
extern int      secsc_del_key();
extern int      secsc_decrypt();
extern int      secsc_encrypt();
extern int      secsc_get_EncryptedKey();
extern int      secsc_gen_key();
extern int      secsc_put_EncryptedKey();
extern int      secsc_open();
extern int      secsc_read();
extern int      secsc_sc_eject();
extern int      secsc_sign();
extern int      secsc_verify();
extern int      secsc_unblock_SCpin();
extern int      secsc_write();
extern char    *get_pse_pin_from_SC();
extern int	handle_sc_app();
extern int      SC_configuration();
extern int	SCT_configuration();
extern int      check_SCapp_configuration();


int             handle_in_SCTSC();
static int      open_app_on_SC();

int             SCapp_available;
int             call_secsc = FALSE;

#endif
extern ObjId   *RSA_SK_OID, *DSA_SK_OID, *DES_OID, *DES3_OID, *Uid_OID;

char           *getenv();


typedef enum {
	F_null, F_encrypt, F_decrypt,
	F_hash, F_sign, F_verify
} FTYPE;

static FTYPE    sec_state = F_null;

/***************************************************************************************
 *                                     sec_chpin                                       *
 ***************************************************************************************/

RC
sec_chpin(pse_sel, newpin)
	PSESel         *pse_sel;
	char           *newpin;
{
	struct PSE_Objects *nxt;
	char           *object, pwcontent[32];
	int             fd, ret, n, old_pin = TRUE;
	int             free_name;

	char           *proc = "sec_chpin";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/*
		 * secsc_chpin(): Change PIN for an object:  => an error will
		 * be returned
		 * 
		 * Change PIN for application: => Only the PIN for the
		 * application on the SC is changed. The PIN for the SW-PSE
		 * is not changed. => Parameter "newpin" is not evaluated.
		 */

#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_chpin\n");
#endif
		if (secsc_chpin(pse_sel)) {
			aux_add_error(EPIN, "Can't change PIN", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* PIN on the SC has been changed */

	}			/* if (SC available && app = SC-app) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if the SC is not available or the
	 * application is not an SC-application.
	 */
#endif				/* SCA */


	if (!newpin) newpin = "";

	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Change object PIN
		 */

		if (object_reencrypt(pse_sel, newpin, FALSE) < 0) {
			aux_add_error(EENCRYPT, "reencrypt object (1)", CNULL, 0, proc);
			return (-1);
		}
	} else {

		/*
		 * Change PSE PIN
		 */

		/* Read toc */

		if (!(psetoc = chk_toc(pse_sel, FALSE))) {
			aux_add_error(LASTERROR, "check pse_toc", pse_sel, PSESel_n, proc);
			return (-1);
		}
		if (pse_sel->pin && strlen(pse_sel->pin)) old_pin = TRUE;
		else old_pin = FALSE;

		nxt = psetoc->obj;
		while (nxt) {
			if (!(object = pse_name(pse_sel->app_name, nxt->name, &free_name))) {
				aux_add_error(EOBJ, " get object-name(1)", nxt->name, char_n, proc);
				return (-1);
			}

			/*
			 * reencrypt all .sf objects which have no .pw, if
			 * old_pin == TRUE, or all objects without .sf
			 * suffix, if old_pin == FALSE
			 */

			strcat(object, ".sf");

			if ((fd = open(object, O_RDONLY)) > 0) {
				close(fd);
				object[strlen(object) - 3] = '\0';
				strcat(object, ".pw");
				if ((fd = open(object, O_RDONLY)) < 0) {
					pse_sel->object.name = nxt->name;
					ret = object_reencrypt(pse_sel, newpin, TRUE);
					if (ret < 0) {
						if (free_name)
							free(object);
						aux_add_error(EENCRYPT, "reencrypt object(2)", CNULL, 0, proc);
						return (-1);
					}
				} else {

					/*
					 * here we have an object with .pw,
					 * i.e. it has a pin which is
					 * different from the old PSE pin. If
					 * its pin is equal to the new pin,
					 * remove .pw
					 */

					if ((n = read_dec(fd, pwcontent, sizeof(pwcontent), newpin)) > 0) {
						pwcontent[n] = '\0';
						if (!strcmp(pwcontent, newpin)) {
							/* yes, remove .pw */
							close_dec(fd);
							unlink(object);
						}
					}
					close_dec(fd);
				}
				close(fd);
			} else if (old_pin == FALSE) {
				object[strlen(object) - 3] = '\0';
				if ((fd = open(object, O_RDONLY)) > 0) {
					close(fd);
					pse_sel->object.name = nxt->name;
					ret = object_reencrypt(pse_sel, newpin, TRUE);
					if (ret < 0) {
						if (free_name) free(object);
						aux_add_error(EENCRYPT, "reencrypt object(3)", CNULL, 0, proc);
						return (-1);
					}
				}
			}
			if (free_name) free(object);
			nxt = nxt->next;
		}

		/* Create pse.pw with encrypted newpin */

		if (pse_sel->pin && strlen(pse_sel->pin)) {
			if (!(object = pse_name(pse_sel->app_name, "pse.pw", &free_name))) {
				aux_add_error(EOBJ, " get object-name(2)", "pse.pw", char_n, proc);
				return (-1);
			}
			unlink(object);
			if (free_name)	free(object);
		}
		if (strlen(newpin)) {
			if (!(object = pse_name(pse_sel->app_name, "pse.pw", &free_name))) {
				aux_add_error(EOBJ, " get object-name(3)", "pse.pw", char_n, proc);
				return (-1);
			}
#ifndef MAC
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */
				aux_add_error(ESYSTEM, "can't create object", object, char_n, proc);
				if (free_name) free(object);
				return (-1);
			}
			chmod(object, OBJMASK);
			strcpy(text, newpin);	/* save pin because write_enc
						 * encrypts inline */
			if (write_enc(fd, text, strlen(newpin), newpin) < 0) {
				aux_add_error(ESYSTEM, "can't write object", object, char_n, proc);
				if (free_name) free(object);
				close_enc(fd);
				return (-1);
			}
			if (free_name) free(object);
			close_enc(fd);
		}
		/* delete old Toc/Toc.sf */

		if (!(object = pse_name(pse_sel->app_name, "Toc", &free_name))) {
			aux_add_error(EOBJ, " get object-name(4)", "Toc", char_n, proc);
			return (-1);
		}
		unlink(object);
		strcat(object, ".sf");
		unlink(object);
		if (free_name) free(object);

		/* Create Toc.sf with (encrypted) toc */

		if(pse_sel->pin) strzfree(&(pse_sel->pin));
		pse_sel->pin = aux_cpy_String(newpin);
		if (write_toc(pse_sel, psetoc, O_WRONLY | O_CREAT | O_EXCL) < 0) {
			strzfree(&(pse_sel->pin));
			aux_add_error(ESYSTEM, "can't write toc", CNULL, 0, proc);
			return (-1);
		}
	}
	return (0);
}


/***************************************************************************************
 *                                     sec_close                                       *
 ***************************************************************************************/

RC
sec_close(pse_sel)
	PSESel         *pse_sel;
{
	char           *proc = "sec_close";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_close \n");
#endif


		if ((!pse_sel->object.name) || (!strlen(pse_sel->object.name)) ||
		  ((pse_sel->object.name && strlen(pse_sel->object.name)) &&
		   (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)))) {

			if (secsc_close(pse_sel)) {
				aux_add_error(ESCCLOSE, "Can't close app/object on SC", CNULL, 0, proc);
				return (-1);
			}
			if (pse_sel->object.name && strlen(pse_sel->object.name)) {
				return (0);	/* object on SC has been
						 * closed */
			}
		}
	}			/* end if (SC available && app = SC-app) */
	/**************************************************************************************/

	/*
	 * If an application shall be closed, the following is performed in
	 * any case. If an object shall be closed, the following is only
	 * performed, if - the SC is not available or - the application is
	 * not an SC-application or - the object to be closed is not an
	 * SC-object.
	 */
#endif				/* SCA */


	if (!pse_sel->object.name) {
		aux_free_PSEToc(&psetoc);
#ifdef SCA
		aux_free_PSEToc(&sc_toc);
#endif
		strzfree(&(pse_sel->pin));
	}
	else strzfree(&(pse_sel->object.pin));

	return (0);
}


/***************************************************************************************
 *                                     sec_create                                      *
 ***************************************************************************************/

RC
sec_create(pse_sel)
	PSESel         *pse_sel;
{
	char           *dirname, *object, buf[32], *zwpin;
	int             fd, free_object, ret, toc_flag;
	struct PSE_Objects *nxt, *pre, *new;
	int             free_owner, maxref = -1, ref;
	int             free_name, free_obj;
	PSEToc         *sctoc = (PSEToc *) 0;


	char           *proc = "sec_create";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/* If SC application not open => open it */
		if (open_app_on_SC(pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		if(pse_sel->object.name && strlen(pse_sel->object.name)) {

			/*
			 * If object = SC object    => create object on SC
			 */

			if (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)) {
				/* create object on SC */
#ifdef SECSCTEST
				fprintf(stderr, "Call of secsc_create (obj)\n");
#endif
				if (secsc_create(pse_sel)) {
					aux_add_error(err_stack->e_number, "Can't create object on SC", pse_sel->object.name, char_n, proc);
					return (-1);
				}
				update_SCToc(pse_sel, 0, 0);	/* update or create SC
								 * toc */

				return (0);	/* object on SC has been
						 * created */
			} 


			/* 
			 *
			 *  An object on the SW-PSE shall be created!
			 *
			 *  => Get the PIN for the SW-PSE from the SC.
			 */
		
			strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
			if(!pse_sel->pin) {
				aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
				return (-1);
			}
			if(pse_sel->object.name && strlen(pse_sel->object.name)) {
				strrep(&(pse_sel->object.pin), pse_sel->pin);
			}

		}
		else {

			/*
			 *  Create application on SC
			 */

			/*
			 *  If application on SC is virgin (no toc on SC)
			 *     => check consistency of configuration data of SC application
			 *     => install toc on SC
			 *  If application on SC is not virgin (toc exists on SC)
			 *     => return (-1)
			 */
		
			sctoc = read_SCToc(pse_sel);
			if (!sctoc) {

				/*
				 *  No toc => application on SC is virgin
				 */

				/*
				 *  Check consistency of the configuration data for the SC-application
				 */

				if (check_SCapp_configuration(pse_sel->app_name, sec_onekeypair)) {
					if (aux_last_error() == EOBJ) 
						aux_add_error(ECREATEOBJ, "Configuration data for SC application are inconsistent", pse_sel, PSESel_n, proc);
					else 
						aux_add_error(ECREATEOBJ, "Error during SC configuration check", pse_sel, PSESel_n, proc);
					return (-1);
				}

				/*
				 *  Install Toc on SC
				 */

				sctoc = create_SCToc(pse_sel);
				if (!sc_toc) {
					aux_add_error(ECREATEOBJ, "Can't create SC toc", pse_sel, PSESel_n, proc);
					return (-1);
				}
				else {
					/*
					 *  If onekeypair, set status byte in Toc 
					 */

					sctoc->status = 0;
					if (sec_onekeypair == TRUE)

						sctoc->status |= ONEKEYPAIRONLY;
					if (write_SCToc(pse_sel, sctoc) < 0) {
						aux_add_error(EWRITEPSE, "write_SCToc failed", CNULL, 0, proc);
						return (-1);
					}
				}
				aux_free_error();
			}				
			else {

				/*
				 *  Toc on SC exists => application on SC is not virgin
				 */

				aux_add_error(ECREATEAPP, "Application on SC exists already", pse_sel->app_name, char_n, proc);
				return(-1);
			}

			return(0);
		}

	}			/* if (SC available && app = SC-app) */


	
/**************************************************************************************/

	/*
	 * The following is only performed, 
	 * if an application | object on the SW-PSE shall be created.
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */


	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Check whether a keypool object with the highest existing
		 * number + 1 shall be created
		 */

		if (pse_sel == &sec_key_pool && strcmp(pse_sel->object.name, "-1") == 0)
			maxref = 0;

		/*
		 * Create an object on an existing PSE
		 */

		/* Read toc */

		if (!(psetoc = chk_toc(pse_sel, FALSE))) {
#ifdef SCA

			if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
				aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
				return (-1);
			}
			if (SCapp_available == TRUE) {
				aux_free_error();
				/* 
				 *
				 *  An object on the SW-PSE shall be created!
				 *
				 *  => Get the PIN for the SW-PSE from the SC.
				 */
		
				strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
				if(!pse_sel->pin) {
					aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
					return (-1);
				}
				if(pse_sel->object.name && strlen(pse_sel->object.name)) {
					strrep(&(pse_sel->object.pin), pse_sel->pin);
				}

				if(create_PSE(pse_sel) < 0) return(-1);
				toc_flag = O_WRONLY | O_CREAT | O_EXCL;
			}
			else {
#endif
				aux_add_error(LASTERROR, "chk_toc failed", pse_sel, PSESel_n, proc);
				return (-1);
#ifdef SCA
			}
#endif
		}
		else toc_flag = O_WRONLY;

		/* allocate memory for new element */

		new = (struct PSE_Objects *) calloc(1, sizeof(struct PSE_Objects));
		if (!new) {
			aux_add_error(EMALLOC, "new", CNULL, 0, proc);
			return (-1);
		}
		/* Check whether pse_sel->object.name already exists */

		if (!(nxt = psetoc->obj)) psetoc->obj = new;
		else {
			while (nxt) {
				if (maxref >= 0) {	/* create new keypoool
							 * object as maxref + 1 */
					strcpy(buf, nxt->name);
					buf[strlen(buf) - 3] = '\0';	/* cut suffix .sf */
					sscanf(buf, "%X", &ref);
					if (ref > maxref) maxref = ref;
				} else {
					if (strcmp(nxt->name, pse_sel->object.name) == 0) {
						/* yes */
						free(new);
						aux_add_error(ECREATEOBJ, "object exists", pse_sel->object.name, char_n, proc);
						return (-1);
					}
				}
				pre = nxt;
				nxt = nxt->next;
			}
			pre->next = new;
		}

		if (maxref >= 0) {
			maxref++;
			if (!(pse_sel = set_key_pool(maxref))) {
				aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
				return (-1);
			}
		}
		/* append new object */

		nxt = new;
		if (!(nxt->name = aux_cpy_String(pse_sel->object.name))) {
			aux_add_error(EMALLOC, "next->name", CNULL, 0, proc);
			return (-1);
		}
		nxt->create = aux_current_UTCTime();
		nxt->update = aux_current_UTCTime();
		nxt->noOctets = 0;
		nxt->status = 0;
		nxt->next = (struct PSE_Objects *) 0;


		/* Ask for object PIN, if not present */

		if(pse_sel->pin && !pse_sel->object.pin) pse_sel->object.pin = aux_cpy_String(pse_sel->pin);


		if (!pse_sel->object.pin) {
			pse_sel->object.pin = sec_read_pin("PIN for", pse_sel->object.name, TRUE);
			if (!pse_sel->object.pin) {
				aux_add_error(ECREATEOBJ, "read PIN failed", pse_sel, PSESel_n, proc);
				return (-1);
			}
		}


		/*
		 * Create object.pw with encrypted PIN if PIN exists and is
		 * different from PSE pin
		 */

		if (!(object = pse_name(pse_sel->app_name, pse_sel->object.name, &free_name))) {
			aux_add_error(EOBJ, " get object-name(1)", pse_sel->object.name, char_n, proc);
			return (-1);
		}
		free_object = free_name;
		if (strlen(pse_sel->object.pin)) {
			if (!pin_check(pse_sel, "pse", pse_sel->object.pin, FALSE, TRUE)) {
				strcat(object, ".pw");
#ifndef MAC
				if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
				if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */
					aux_add_error(ESYSTEM, "can't create object", object, char_n, proc);
					if (free_object) free(object);
					return (-1);
				}
				chmod(object, OBJMASK);
				strcpy(text, pse_sel->object.pin);	/* save pin because
									 * write_enc encrypts
									 * inline */
				if (write_enc(fd, text, strlen(pse_sel->object.pin), pse_sel->object.pin) < 0) {
					aux_add_error(ESYSTEM, "can't write object", object, char_n, proc);
					if (free_object) free(object);
					close_enc(fd);
					return (-1);
				}
				close_enc(fd);
				object[strlen(object) - 3] = '\0';
			}
			strcat(object, ".sf");
		}
		/* Create object */

#ifndef MAC
		if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
		if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */
			aux_add_error(ESYSTEM, "can't create object", object, char_n, proc);
			if (free_object) free(object);
			return (-1);
		}
		close(fd);
		chmod(object, OBJMASK);
		if (free_object) free(object);
	} 
	else {
		if(create_PSE(pse_sel) < 0) return(-1);
		toc_flag = O_WRONLY | O_CREAT | O_EXCL;
	}


	/* Write toc */

	if (pse_sel == &sec_key_pool && pse_sel->object.name) {
		/* sec_write follows, write toc there */
		if (maxref > 0)	return (maxref);
		else return (0);
	} 
	else {
		if (!pse_sel->object.name || !strlen(pse_sel->object.name)) {

			/*
			 *  If pse has been created, set status byte in Toc 
			 */

			psetoc->status = 0;
			if (sec_onekeypair == TRUE)
				psetoc->status |= ONEKEYPAIRONLY;
		}

		ret = write_toc(pse_sel, psetoc, toc_flag);
		if (ret) aux_add_error(EAPP, "write toc", (char *) pse_sel, PSESel_n, proc);
		return (ret);
	}
}


/***************************************************************************************
 *                                     create_PSE                                      *
 ***************************************************************************************/

RC
create_PSE(pse_sel)
	PSESel         *pse_sel;
{
	char           *dirname, *object, buf[32], *zwpin, *dd;
	int             fd, free_object, ret, toc_flag;
	struct PSE_Objects *nxt, *pre, *new;
	int             free_owner, maxref = -1, ref;
	int             free_name, free_obj;

	char           *proc = "create_PSE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

		/*
		 * Create a PSE
		 */

		/* check conflict with key_pool */

		if (!strcmp(pse_sel->app_name, ".key_pool")) {
			if (!(pse_sel->pin) || strcmp(pse_sel->pin, key_pool_pw())) {
				aux_add_error(EINVALID, "name .key_pool not allowed", CNULL, 0, proc);
				return (-1);
			}
		}
		/* Build directory name of the PSE */

		if (!(dirname = pse_name(pse_sel->app_name, CNULL, &free_name))) {
			aux_add_error(EAPP, " get directory-name", CNULL, 0, proc);
			return (-1);
		}
		/* Make directory of the PSE */

		if (mkdir(dirname, DIRMASK) < 0) {
			if (errno == EEXIST) {
				dd = (char *) malloc(32 + strlen(dirname));
				strcpy(dd, "PSE ");
				strcat(dd, dirname);
				strcat(dd, " exists already");
				aux_add_error(ECREATEAPP, dd, dirname, char_n, proc);
			}
			else {
				aux_add_error(ESYSTEM, "mkdir failed", dirname, char_n, proc);
			}
			if (free_name) free(dirname);
			return (-1);
		}
		chmod(dirname, DIRMASK);

		/* Ask for PIN, if not present */

		if (!pse_sel->pin) {
			pse_sel->pin = sec_read_pin("PIN for", pse_sel->app_name, TRUE);
			if (!pse_sel->pin) {
				aux_add_error(EPIN, "read PIN failed", pse_sel, PSESel_n, proc);
				rmdir(dirname);
				if (free_name) free(dirname);
				return (-1);
			}
		}
		/* Create pse.pw with encrypted PIN if PIN exists */

		free_obj = FALSE;
		if (strlen(pse_sel->pin)) {
			if (!(object = pse_name(pse_sel->app_name, "pse.pw", &free_obj))) {
				aux_add_error(EOBJ, " get object-name(2)", "pse.pw", char_n, proc);
				return (-1);
			}
#ifndef MAC
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */
				aux_add_error(ESYSTEM, "can't create object", object, char_n, proc);
				if (free_obj) free(object);
				rmdir(dirname);
				if (free_name) free(dirname);
				return (-1);
			}
			chmod(object, OBJMASK);
			strcpy(text, pse_sel->pin);	/* save pin because
							 * write_enc encrypts
							 * inline */
			if (write_enc(fd, text, strlen(pse_sel->pin), pse_sel->pin) < 0) {
				aux_add_error(ESYSTEM, "can't write object", object, char_n, proc);
				close_enc(fd);
				unlink(object);
				rmdir(dirname);
				if (free_obj) free(object);
				if (free_name) free(dirname);
				return (-1);
			}
			close_enc(fd);
		}
		/* Build initial toc */

		if (!(psetoc = chk_toc(pse_sel, TRUE))) {
			aux_add_error(EMALLOC, "psetoc", CNULL, 0, proc);
			unlink(object);
			rmdir(dirname);
			if (free_obj) free(object);
			if (free_name) free(dirname);
			return (-1);
		}
		if (!(psetoc->owner = (char *) malloc(128))) {
			aux_add_error(EMALLOC, "psetoc->owner", CNULL, 0, proc);
			unlink(object);
			rmdir(dirname);
			if (free_obj) free(object);
			if (free_name) free(dirname);
			return (-1);
		}
		strcpy(psetoc->owner, get_unixname());
		psetoc->create = aux_current_UTCTime();
		psetoc->update = aux_current_UTCTime();
		psetoc->obj = (struct PSE_Objects *) 0;


		if (free_obj) free(object);
		if (free_name) free(dirname);

		return(0);
}

/***************************************************************************************
 *                                 sec_decrypt                                         *
 ***************************************************************************************/

RC
sec_decrypt(in_bits, out_octets, more, key)
	BitString      *in_bits;
	OctetString    *out_octets;
	More            more;
	Key            *key;
{
	int             n, i, rc, PSlength;
	char           *dd, *bb;
	static AlgEnc   algenc;
	static AlgSpecial     algspecial;

#ifdef SCA
	int             no_dec;

#endif

	char           *proc = "sec_decrypt";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	public_modulus_length = 0;

#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether decryption shall be done within the SCT/SC.
	 * If the key is selected with object name, the PIN for the
	 * SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}
	if (call_secsc == TRUE) {

		/* decrypt within SCT/SC */
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_decrypt\n");
#endif
		if ((no_dec = secsc_decrypt(in_bits, out_octets, more, key)) == -1) {
			aux_add_error(EDECRYPT, "Decryption error within SCT/SC", CNULL, 0, proc);
			return (-1);
		}
		algenc = aux_ObjId2AlgEnc(key->alg->objid);
		algspecial = aux_ObjId2AlgSpecial(key->alg->objid);

		/*
		 * If decryption algorithm = RSA and block format = PKSC_BT_02,
		 * it is assumed that the encrypted block has been extended 
		 * before encryption.
		 */

		if ((algenc == RSA) && (algspecial == PKCS_BT_02)) {

			/*  Here goes PKCS#1 ...   */

			if(more != END) {
				aux_add_error(EINVALID, "MORE not possible with rsaEncryption", CNULL, 0, proc);
				return(-1);
			}
			/* 
			 * Restore D from out_octets which should be 
			 * 0x02 || PS || 0x00 || D, PS should be all non-zero.  
			 */

			PSlength = strlen(out_octets->octets + 1);
			if(out_octets->octets[0] != 2 || PSlength > out_octets->noctets - 3) {
				aux_add_error(EDECRYPT, "decrypted block wrong (PKCS#1 BT 02)", CNULL, 0, proc);
				return(-1);
			}
			bb = out_octets->octets;
			dd = bb + PSlength + 2;
			out_octets->noctets -= (PSlength + 2);
			no_dec = out_octets->noctets;
			for(i = 0; i < out_octets->noctets; i++) *bb++ = *dd++;
		}

		return (no_dec);	/* Decryption was successful! */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if - the SC is not available or -
	 * the decryption key doesn't address a key within SCT/SC
	 * 
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if (sec_state == F_null) {
		if (get2_keyinfo_from_key(&got_key, key) < 0) {
			aux_add_error(EINVALID, "get keyinfo", CNULL, 0, proc);
			return -1;
		}
		algenc = aux_ObjId2AlgEnc(got_key.subjectAI->objid);
		algspecial = aux_ObjId2AlgSpecial(got_key.subjectAI->objid);
		if (algenc == RSA) {
			rc = rsa_get_key(&got_key.subjectkey, 1);
			if (rc != 0) {
				aux_add_error(EINVALID, "rsa_get_key failed", CNULL, 0, proc);
				return -1;
			}
		}
		if(key->alg) {
			if(aux_ObjId2AlgEnc(key->alg->objid) != algenc) {
				aux_add_error(EINVALID, "Invalid algorithm in key->alg", key->alg, AlgId_n, proc);
				return -1;
			}
			algspecial = aux_ObjId2AlgSpecial(key->alg->objid);
		}
		if(sec_time) {
			if(algenc == RSA) rsa_sec = rsa_usec = 0;
			else des_sec = des_usec = 0;
		}
		sec_state = F_decrypt;
	} else if (sec_state != F_decrypt) {
		aux_add_error(EDECRYPT, "wrong sec_state", CNULL, 0, proc);
		return -1;
	}
	if(sec_verbose) {
		fprintf(stderr, "Input to sec_decrypt:\n");
		aux_fprint_BitString(stderr, in_bits);
	}
	switch (algenc) {
	case RSA:

		if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

#ifdef SECSCTEST
		fprintf(stderr, "input for rsa_decrypt\n");
                aux_xdump(in_bits->bits, in_bits->nbits / 8, 0);
	        fprintf(stderr, "\n");
#endif

		n = rsa_decrypt(in_bits, out_octets, more, RSA_PARM(got_key.subjectAI->parm));

#ifdef SECSCTEST
		fprintf(stderr, "rsa_output + PKCS blocking \n");
                aux_xdump(out_octets->octets, out_octets->noctets, 0);
	        fprintf(stderr, "\n");
#endif
		if(algspecial == PKCS_BT_02 && n > 0) {

			/*  Here goes PKCS#1 ...   */

			if(more != END) {
				aux_add_error(EINVALID, "MORE not possible with rsaEncryption", CNULL, 0, proc);
				n = -1;
			}
			else {

				/* Restore D from out_octets which should be 0x02 || PS || 0x00 || D
				   PS should be all non-zero.  */

				if(sec_verbose) {
					fprintf(stderr, "Output from sec_decrypt (PKCS #2 block):\n");
					aux_fprint_OctetString(stderr, out_octets);
				}
				PSlength = strlen(out_octets->octets + 1);
				if(out_octets->octets[0] != 2 || PSlength > out_octets->noctets - 3) {
					aux_add_error(EDECRYPT, "decrypted block wrong (PKCS#1 BT 02)", CNULL, 0, proc);
					n = -1;
				}
				else {
					bb = out_octets->octets;
					dd = bb + PSlength + 2;
					out_octets->noctets -= (PSlength + 2);
					n = out_octets->noctets;
					for(i = 0; i < out_octets->noctets; i++) *bb++ = *dd++;
				}
			}
		}
		if(sec_time) {
			gettimeofday(&sec_tp2, &sec_tzp2);
			rsa_usec = (rsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	rsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
			rsa_sec = rsa_usec/1000000;
			rsa_usec = rsa_usec % 1000000;
		}
		break;
	case DES:
	case DES3:
		if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

		n = des_decrypt(in_bits, out_octets, more, &got_key);

		if(sec_time) {
			gettimeofday(&sec_tp2, &sec_tzp2);
			des_usec = (des_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	des_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
			des_sec = des_usec/1000000;
			des_usec = des_usec % 1000000;
		}
		break;
	default:
		aux_add_error(EALGID, "invailid or unknown alg_id", CNULL, 0, proc);
		return -1;
	}
	if (more == END) {
		algenc = NOENC;
		aux_free2_KeyInfo(&got_key);
		sec_state = F_null;
	}
	if (n < 0) {
		aux_add_error(EDECRYPT, "decrypt error", CNULL, 0, proc);
		return (-1);
	}
	return (n);
}


/***************************************************************************************
 *                                 sec_del_key                                         *
 ***************************************************************************************/

RC
sec_del_key(keyref)
	KeyRef          keyref;
{
	int             rc;
	PSESel         *pse_sel;
	register char  *dd;

#ifdef SCA
	Key		key;

#endif


	char           *proc = "sec_del_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

#ifdef SCA
	if ((keyref == -1) || (keyref == 0)) {
#else
	if (keyref <= 0) {
#endif				/* SCA */
		aux_add_error(EINVALID, "invalid keyref", CNULL, 0, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether key stored within the SCT/SC shall be deleted.
	 */

	key.keyref  = keyref;
	key.pse_sel = (PSESel *) 0;
        key.key     = (KeyInfo *)0;

	if ((call_secsc = handle_in_SCTSC(&key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}
	if (call_secsc == TRUE) {
			
		/* Delete key in SC/SCT */
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_del_key\n");
#endif
		if (secsc_del_key(keyref)) {
			aux_add_error(EKEYSEL, "Can't delete key in SC/SCT", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* key has been deleted */
	}		
	/**************************************************************************************/

	/*
	 * The following is only performed, if - the SC is not available or -
	 * the key to be deleted is stored in the key_pool
	 * 
	 * 
	 */
#endif				/* SCA */



	if (!(pse_sel = set_key_pool(keyref))) {
		aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
		return (-1);
	}
	rc = sec_delete(pse_sel);
	if(pse_sel->pin) strzfree(&(pse_sel->pin));
	if (rc)	aux_add_error(EINVALID, "delete object", pse_sel, PSESel_n, proc);
	return (rc);
}


/***************************************************************************************
 *                                     sec_delete                                      *
 ***************************************************************************************/

#ifndef MAC
#include <dirent.h>
#endif /* !MAC */

RC
sec_delete(pse_sel)
	PSESel         *pse_sel;
{
	struct PSE_Objects *nxt, *pre, *new;
	int             fd, free_name, ret;
	char            *object, *cmd, *o;
#ifndef MAC
	struct dirent   *dp, *readdir();
	DIR             * dir, *opendir();
#endif /* !MAC */


	char           *proc = "sec_delete";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/* If SC application not open => open it */
		if (open_app_on_SC(pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		if (pse_sel->object.name && strlen(pse_sel->object.name)) {

			/*
			 * If object = SC object    => delete object on SC
			 */

			if (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)) {
				/* delete object on SC */
#ifdef SECSCTEST
				fprintf(stderr, "Call of secsc_delete (obj)\n");
#endif
				if (secsc_delete(pse_sel)) {
					aux_add_error(ESCDELETE, "Can't delete object on SC", pse_sel->object.name, char_n, proc);
					return (-1);
				}
				delete_SCToc(pse_sel);	/* delete object from SC
							 * toc */

				return (0);	/* object on SC has been
						 * deleted */
			}
		}

	}			/* if (SC available && app = SC-app) */

	/**************************************************************************************/

	/*
	 * The following is only performed, 
	 * if an application | object on the SW-PSE shall be deleted.
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if ((fd = open_object(pse_sel, O_WRONLY | O_TRUNC)) == -1) {
		aux_add_error(LASTERROR, "open object", pse_sel, PSESel_n, proc);
		return (-1);
	}
	close(fd);

	if (!pse_sel->object.name || !strlen(pse_sel->object.name)) {
#ifndef MAC 
		/* delete application */

		if (!(object = pse_name(pse_sel->app_name, "", &free_name))) {
			aux_add_error(EOBJ, " get object-name(1)", "", char_n, proc);
			return (-1);
		}
		if (!(dir = opendir(object))) {
			if (free_name) free(object);
			aux_add_error(ESYSTEM, "can't access", object, char_n, proc);
			return (-1);
		}
		o = &object[strlen(object)];
		if (*o != '/') {
			*o++ = '/';
			*o = '\0';
		}
		while ((dp = readdir(dir))) {
			strcpy(o, dp->d_name);
			unlink(object);
		}
		closedir(dir);
		*o-- = '\0';
		if (*o == '/')
			*o = '\0';
		if ((ret = rmdir(object)) < 0) {
			aux_add_error(ESYSTEM, "can't remove", object, char_n, proc);
		}
		if (free_name) free(object);
		return (ret);
#endif /* !MAC */
	}

	/* delete object */

	/*
	 * Check whether pse_sel->object.name exists in toc (we have the toc
	 * from sec_open)
	 */

	nxt = psetoc->obj;
	pre = (struct PSE_Objects *) 0;
	while (nxt) {
		if (strcmp(nxt->name, pse_sel->object.name) == 0) {

			/* yes */

			/* chain out */

			if (pre) pre->next = nxt->next;
			else {
				psetoc->obj = nxt->next;
				if(!psetoc->obj) {

					/* last object removed from SW-PSE
                                         * delete entire SW-PSE if application is SC app */
#ifdef SCA
					SCapp_available = sec_sctest(pse_sel->app_name);
					if (SCapp_available == TRUE) {
						if(pse_sel->object.name) free(pse_sel->object.name);
						pse_sel->object.name = CNULL;
						strzfree(&(pse_sel->object.pin));
						ret = sec_delete(pse_sel);
						strzfree(&(pse_sel->pin));
						aux_free_PSEToc(&psetoc);
						if(ret == 0) return(0);
					}
#endif
				}
			}

			/* Write toc */

			ret = write_toc(pse_sel, psetoc, O_WRONLY | O_TRUNC);
			if (ret < 0) {
				aux_add_error(EINVALID, "write toc", pse_sel, PSESel_n, proc);
				return (-1);
			}
			/* unlink all corresponding files) */

			if (!(object = pse_name(pse_sel->app_name, pse_sel->object.name, &free_name))) {
				aux_add_error(EOBJ, " get object-name(2)", pse_sel->object.name, char_n, proc);
				return (-1);
			}
			unlink(object);
			strcat(object, ".sf");
			unlink(object);
			object[strlen(object) - 3] = '\0';
			strcat(object, ".pw");
			unlink(object);
			return (0);
		}
		pre = nxt;
		nxt = nxt->next;
	}
	aux_add_error(EOBJNAME, "object is not in toc", pse_sel->object.name, char_n, proc);
	return (-1);
}


/***************************************************************************************
 *                               sec_rename                                            *
 ***************************************************************************************/

RC
sec_rename(pse_sel, objname)
	PSESel         *pse_sel;
	char           *objname;
{
#ifdef MAC
	FILE           *f;
#endif /* MAC */
	char           *object, *newobj;
	int             free_obj, free_new;
	struct PSE_Objects **toc_obj;
	int             rc;
	char           *proc = "sec_rename";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
	if (!pse_sel->object.name || !*(pse_sel->object.name)) {
		aux_add_error(EINVALID, "object missing", pse_sel, PSESel_n, proc);
		return -1;
	}
	/* locate object in toc */
	if (!(psetoc = chk_toc(pse_sel, FALSE))) {
		aux_add_error(LASTERROR, "check pse_toc", pse_sel, PSESel_n, proc);
		return (-1);
	}
	toc_obj = locate_toc(pse_sel->object.name);
	if (!toc_obj || !*toc_obj) {
		aux_add_error(EOBJNAME, "object not in toc ", pse_sel, PSESel_n, proc);
		return -1;
	}
	rc = -1;
	free_obj = FALSE;
	free_new = FALSE;
	if (strcmp(pse_sel->object.name, objname)) {	/* objects differ */
		object = pse_name(pse_sel->app_name, pse_sel->object.name, &free_obj);
		newobj = pse_name(pse_sel->app_name, objname, &free_new);
		if (!object || !newobj)
			goto rename_err;

/* object wird in newobject umbenannt. Falls es nicht klappt und Fehler = ENOENT ist,
   wird object.sf in newobject.sf umbenannt. Wenn das geklappt hat, wird noch
   object.pw in newobject.pw umbenannt. AS */
   
#ifndef MAC
		if (link(object, newobj) < 0) {
			if (errno != ENOENT) {
				aux_add_error( errno, "link fails", newobj, char_n, proc);
				goto rename_err;
			}
			/* object possibly secure file */
			strcat(object, ".sf");
			strcat(newobj, ".sf");
			if (link(object, newobj) < 0) {
				aux_add_error( errno, "link fails", newobj, char_n, proc);
				goto rename_err;
			}
			unlink(object);
			strcpy( object + strlen(object) - 2, "pw");
			strcpy( newobj + strlen(newobj) - 2, "pw");
			link(object, newobj);	/* ignore any failure */
			unlink(object);
		} else {
			unlink(object);
		}
#else
        if (rename(object, newobj) != 0)
           {
           if ( ( (f = fopen(object, "r")), errno) != ENOENT )
              {  
              aux_add_error( errno, "rename fails", newobj, char_n, proc);
              if (f) fclose(f);
              goto rename_err;
              }
           if (f) fclose(f);
           
           /* object possibly secure file */
           strcat(object,".sf");
           strcat(newobj,".sf");
           if (rename(object, newobj) != 0)
              {
              aux_add_error( errno, "rename fails", newobj, char_n, proc);
              goto rename_err;
              }
              
           strcpy(object + strlen(object) - 2, "pw");
           strcpy(newobj + strlen(newobj) - 2, "pw");
           rename(object, newobj);     /* ignore any failure */
           }
#endif /* MAC */

		if (update_toc(pse_sel, *toc_obj, objname)) {
			aux_add_error(EINVALID, "update toc", pse_sel, PSESel_n, proc);
			goto rename_err;
		}
	} /* else :  objects are same, do not complain ignore
	   * instead */


	rc = 0;

	/*------ error handling ------*/
rename_err:
	if (free_obj)
		free(object);
	if (free_new)
		free(newobj);
	return rc;
}


/***************************************************************************************
 *                               update_toc                                            *
 ***************************************************************************************/

static int
update_toc(pse_sel, objp, objname)
	PSESel         *pse_sel;
	struct PSE_Objects *objp;
	char           *objname;
{
	RC              rc;
	char           *proc = "update_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (psetoc && objp && objp->name && objname) {
		free(objp->name);
		objp->name = (char *) malloc(strlen(objname) + 1);
		if (!objp->name) {
			aux_add_error(EMALLOC, "objp->name", CNULL, 0, proc);
			return -1;
		}
		strcpy(objp->name, objname);
		rc = write_toc(pse_sel, psetoc, O_WRONLY | O_TRUNC);
		if (rc)
			aux_add_error(EINVALID, "write toc", CNULL, 0, proc);
		return (rc);
	} else {
		aux_add_error(EINVALID, "param error", CNULL, 0, proc);
		return -1;
	}
}

/***************************************************************************************
 *                               sec_sc_eject
 ***************************************************************************************/
RC
sec_sc_eject(sct_sel)
#ifdef SCA
	SCTSel          sct_sel;
{
	int             rc = 0;

	char           *proc = "sec_sc_eject";

        if ((rc = secsc_sc_eject(sct_sel)) == -1)  {
		if (aux_last_error() == EOPENDEV) 
			aux_add_error(EOPENDEV, "Eject failed. Device for SCT not available (No such device or device busy).", CNULL, 0, proc);
	}

	return (rc);
}

#else
	int             sct_sel;
{
	return (0);

}

#endif

/***************************************************************************************
 *                               sec_encrypt                                           *
 ***************************************************************************************/

RC
sec_encrypt(in_octets, out_bits, more, key)
	OctetString    *in_octets;
	BitString      *out_bits;
	More            more;
	Key            *key;
{

	int             n, rc;
	static AlgEnc   algenc;
	static AlgSpecial     algspecial;
	OctetString     *rsa_input;

#ifdef SCA
	int             no_enc;

#endif

	char           *proc = "sec_encrypt";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif


#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether encryption shall be done within the
	 * SCT/SC - If the key is selected with object name,
	 * the PIN for the SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(key, SC_encrypt)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}

	if (call_secsc == TRUE) {

		/* encrypt within SCT/SC */
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_encrypt\n");
#endif

		/*
		 * Get algorithm of the encryption key
		 */

		if (key->key) {
			if ((key->key->subjectAI != NULLALGID) && (key->key->subjectAI->objid != NULLOBJID)) {
				algenc = aux_ObjId2AlgEnc(key->key->subjectAI->objid);
       				algspecial = aux_ObjId2AlgSpecial(key->key->subjectAI->objid);
			} else {
				aux_add_error(EINVALID, "Algorithm missing in key->key", CNULL, 0, proc);
				return (-1);
			}
		} else {
			if (key->alg) {
				algenc = aux_ObjId2AlgEnc(key->alg->objid);
       				algspecial = aux_ObjId2AlgSpecial(key->alg->objid);
			} else {
				aux_add_error(EINVALID, "Algorithm missing", CNULL, 0, proc);
				return (-1);
			}
		}

		/*
		 * If encryption algorithm = RSA and block format = PKSC_BT_02,
		 * the input data are padded with leading octets before encryption.
		 */

		if ((algenc == RSA) && (algspecial == PKCS_BT_02)) {

			/*  Here goes PKCS#1 ...   */

			if(more != END) {
				aux_add_error(EINVALID, "MORE not possible with rsaEncryption", CNULL, 0, proc);
				return(-1);
			}
			else {
				if ((rsa_input = aux_create_PKCSBlock(2, in_octets)) == NULLOCTETSTRING) {
					aux_add_error(EENCRYPT, "Cannot create PKCS#1 BT 02 block", CNULL, 0, proc);
					return (-1);
				}
#ifdef SECSCTEST
				fprintf(stderr, "rsa_input + PKCS blocking \n");
                                aux_xdump(rsa_input->octets, rsa_input->noctets, 0);
				fprintf(stderr, "\n");
#endif
				if ((no_enc = secsc_encrypt(rsa_input, out_bits, more, key)) == -1) {
					aux_add_error(EENCRYPT, "Error during encryption within SCT/SC", CNULL, 0, proc);
					return (-1);
				}
				aux_free_OctetString(&rsa_input);
			}
			}
		else {
			if ((no_enc = secsc_encrypt(in_octets, out_bits, more, key)) == -1) {
				aux_add_error(EENCRYPT, "Error during encryption within SCT/SC", CNULL, 0, proc);
				return (-1);
			}
		}
		return (no_enc);	/* encryption done within SC/SCT */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is performed in case of
	 * 
	 * RSA, if: - global variable "SC_encrypt" is FALSE or - the SC is not
	 * available or - the key is not delivered by the calling routine
	 * 
	 * 
	 * DES/DES3, if - the SC is not available or - encryption key doesn't
	 * address a key within SCT/SC
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if (sec_state == F_null) {
		if (get2_keyinfo_from_key(&got_key, key) < 0) {
			aux_add_error(EINVALID, "get keyinfo", CNULL, 0, proc);
			return -1;
		}
		public_modulus_length = sec_get_keysize(&got_key);
		algenc = aux_ObjId2AlgEnc(got_key.subjectAI->objid);
		algspecial = aux_ObjId2AlgSpecial(got_key.subjectAI->objid);
		if (algenc == RSA) {
			rc = rsa_get_key(&got_key.subjectkey, 1);
			if (rc != 0) {
				aux_add_error(EINVALID, "rsa_get_key failed", CNULL, 0, proc);
				return -1;
			}
		}
		if(key->alg) {
			if(aux_ObjId2AlgEnc(key->alg->objid) != algenc) {
				aux_add_error(EINVALID, "Invalid algorithm in key->alg", key->alg, AlgId_n, proc);
				return -1;
			}
			algspecial = aux_ObjId2AlgSpecial(key->alg->objid);
		}
		if(sec_time) {
			if(algenc == RSA) rsa_sec = rsa_usec = 0;
			else des_sec = des_usec = 0;
		}
		sec_state = F_encrypt;
	} else if (sec_state != F_encrypt) {
		aux_add_error(EENCRYPT, "wrong sec_state", CNULL, 0, proc);
		return -1;
	}

	if(sec_verbose) {
		fprintf(stderr, "Input to sec_encrypt:\n");
		aux_fprint_OctetString(stderr, in_octets);
	}

	switch (algenc) {

	case RSA:

		if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

		if(algspecial == PKCS_BT_02) {

			/*  Here goes PKCS#1 ...   */

			if(more != END) {
				aux_add_error(EINVALID, "MORE not possible with rsaEncryption", CNULL, 0, proc);
				n = -1;
			}
			else {
				if ((rsa_input = aux_create_PKCSBlock(2, in_octets)) == NULLOCTETSTRING) {
					aux_add_error(EENCRYPT, "Cannot create PKCS#1 BT 02 block", CNULL, 0, proc);
					return (-1);
				}
#ifdef SECSCTEST
				fprintf(stderr, "rsa_input + PKCS blocking \n");
                                aux_xdump(rsa_input->octets, rsa_input->noctets, 0);
				fprintf(stderr, "\n");
#endif
				if(sec_verbose) {
					fprintf(stderr, "RSA input block (PKCS #2):\n");
					aux_fprint_OctetString(stderr, rsa_input);
				}
				n = rsa_encrypt(rsa_input, out_bits, END, public_modulus_length);
#ifdef SECSCTEST
				fprintf(stderr, "encrypted block \n");
                                aux_xdump(out_bits->bits, out_bits->nbits / 8, 0);
				fprintf(stderr, "\n");
#endif
				aux_free_OctetString(&rsa_input);
			}
		}
		else n = rsa_encrypt(in_octets, out_bits, more, public_modulus_length);
		if(sec_time) {
			gettimeofday(&sec_tp2, &sec_tzp2);
			rsa_usec = (rsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	rsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
			rsa_sec = rsa_usec/1000000;
			rsa_usec = rsa_usec % 1000000;
		}
		break;
	case DES:
	case DES3:
		if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);
		n = des_encrypt(in_octets, out_bits, more, &got_key);
		if(sec_time) {
			gettimeofday(&sec_tp2, &sec_tzp2);
			des_usec = (des_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	des_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
			des_sec = des_usec/1000000;
			des_usec = des_usec % 1000000;
		}
		break;
	default:
		aux_add_error(EALGID, "invalid or unknown alg_id", CNULL, 0, proc);
		return -1;
	}

	if (more == END) {
		algenc = NOENC;
		aux_free2_KeyInfo(&got_key);
		sec_state = F_null;
	}
	if (n < 0) {
		aux_add_error(EINVALID, "decrypt error", CNULL, 0, proc);
		return (-1);
	}
	return (n);
}


/***************************************************************************************
 *                               sec_gen_key                                           *
 ***************************************************************************************/

RC
sec_gen_key(key, replace)
	Key            *key;
	Boolean         replace;
{
	int             rc, i;
	BitString      *public_keybits, *secret_keybits;
	KeyInfo  	subjectprivatekeyinfo;
	ObjId          *keytype;
	AlgId          *SKalgid;
	ObjId          *af_get_objoid();
	int             keysize;


	char           *proc = "sec_gen_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	public_modulus_length = 0;


#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether key generation shall be done within the
	 * SCT/SC - If the key is selected with object name, the PIN
	 * for the SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}

	if (call_secsc == TRUE) {

		/* generate key for SCT/SC */
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_gen_key\n");
#endif
		if (secsc_gen_key(key, replace)) {
			aux_add_error(EKEYSEL, "Can't generate key within SC/SCT", CNULL, 0, proc);
			return (-1);
		}

		/*
		 *  Update of SCToc is done in secsc_gen_key()	
		 */		

		return (0);	/* key has been generated for SC/SCT */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if - the SC is not available or -
	 * the key to be generated shall not be stored within SCT/SC
	 * 
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if ((key->keyref > 0) || (key->pse_sel != (PSESel * ) 0)) {
		if (key->pse_sel != (PSESel * ) 0) {
			if (sec_create(key->pse_sel) < 0) {
				if (replace == FALSE) {
					aux_add_error(EINVALID, "object exists and replace flag is not set", key->pse_sel, PSESel_n, proc);
					return -1;
				}
			}
		}
		else if(key->keyref > 0) {
			if(get2_keyinfo_from_keyref(&subjectprivatekeyinfo, key->keyref) == 0) {
				aux_free2_KeyInfo(&subjectprivatekeyinfo);
				if(replace == FALSE) {
					aux_add_error(EINVALID, "object exists and replace flag is not set", key->pse_sel, PSESel_n, proc);
					return -1;
				}
			}
		}

	}

	if(key->pse_sel) {
		keytype = af_get_objoid(key->pse_sel->object.name);
		if(!aux_cmp_ObjId(keytype, Uid_OID)) aux_free_ObjId(&keytype);
	}
	else keytype = (ObjId *)0;

	switch (aux_ObjId2AlgEnc(key->key->subjectAI->objid)) {
	case RSA:
		keysize = RSA_PARM(key->key->subjectAI->parm);
		if ((key->keyref == 0) && (key->pse_sel == (PSESel * ) 0)) {
			aux_add_error(EINVALID, "invalid key", CNULL, 0, proc);	/* secret key would be
										 * lost */
			return -1;
		}
		rc = rsa_gen_key(keysize, &secret_keybits, &public_keybits);

		if (rc) {
			aux_add_error(EINVALID, "rsa_gen_key failed", CNULL, 0, proc);
			return -1;
		}
		/* public key */

		key->key->subjectkey.nbits = public_keybits->nbits;
		key->key->subjectkey.bits = public_keybits->bits;
		if(!keytype) keytype = RSA_SK_OID;
		SKalgid = rsa;
		break;

	case DSA:
		keysize = sec_dsa_keysize;
		if ((key->keyref == 0) && (key->pse_sel == (PSESel * ) 0)) {
			aux_add_error(EINVALID, "invalid key", CNULL, 0, proc);	/* secret key would be
										 * lost */
			return -1;
		}
		rc = dsa_gen_key(keysize, &secret_keybits, &public_keybits);

		if (rc) {
			aux_add_error(EINVALID, "dsa_gen_key failed", CNULL, 0, proc);
			return -1;
		}
		/* public key */

		key->key->subjectkey.nbits = public_keybits->nbits;
		key->key->subjectkey.bits = public_keybits->bits;
		if(!keytype) keytype = DSA_SK_OID;
		if(sec_dsa_predefined) SKalgid = dsaSK;
		else SKalgid = dsa;
		break;

	case DES:
		while (1) {
			secret_keybits = sec_random_bstr(64);

			/* check for bad DES keys */
			for (i = 0; i < no_of_bad_des_keys; i++) {
				if (bcmp(secret_keybits->bits, bad_des_keys[i], 8) == 0)
					break;
			}
			if (i == no_of_bad_des_keys)
				break;
		}
		if(!keytype) keytype = DES_OID;
		SKalgid = key->key->subjectAI;
		break;
	case DES3:
		while (1) {
			secret_keybits = sec_random_bstr(128);

			/* check for bad DES keys */
			for (i = 0; i < no_of_bad_des_keys; i++) {
				if (bcmp(secret_keybits->bits, bad_des_keys[i], 8) == 0)
					break;
				if (bcmp(secret_keybits->bits + 8, bad_des_keys[i], 8) == 0)
					break;
			}
			if (i == no_of_bad_des_keys)
				break;
		}
		if(!keytype) keytype = DES3_OID;
		SKalgid = key->key->subjectAI;
		break;
	default:
		aux_add_error(EALGID, "unknown alg_id", key->key->subjectAI, AlgId_n, proc);
		return -1;
	}

	/* secret RSA or DSA key or DES key */

	subjectprivatekeyinfo.subjectAI = aux_cpy_AlgId(SKalgid);
	subjectprivatekeyinfo.subjectkey.nbits = secret_keybits->nbits;
	subjectprivatekeyinfo.subjectkey.bits = secret_keybits->bits;

	/* store key */

		
	if (put_keyinfo_according_to_key(&subjectprivatekeyinfo, key, keytype) < 0) {
		aux_free2_KeyInfo(&subjectprivatekeyinfo);
		aux_add_error(EINVALID, "can't store generated key", CNULL, 0, proc);
		return -1;
	}
	for(i = 0; i < secret_keybits->nbits / 8; i++) secret_keybits->bits[i] = 0;
	aux_free2_KeyInfo(&subjectprivatekeyinfo);
	return 0;
}


/***************************************************************************************
 *                               sec_get_EncryptedKey                                 *
 ***************************************************************************************/

RC
sec_get_EncryptedKey(encrypted_key, plain_key, encryption_key)
	EncryptedKey   *encrypted_key;
	Key            *plain_key;
	Key            *encryption_key;
{
	OctetString     in_octets;
	KeyInfo        *plain_keyinfo, *encryption_keyinfo;

#ifdef SCA
	int             SC_available;
#endif
	AlgEnc          plainkey_algenc;
	int             i, j, len_plain_key, pos_plain_key, len_extended_key;
	OctetString    *extended_key = (OctetString * ) 0;


	char           *proc = "sec_get_EncryptedKey";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!plain_key || !encryption_key || !encrypted_key) {
		aux_add_error(EINVALID, "key missing", CNULL, 0, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether key to be encrypted (plain_key) is stored in
	 * the SCT/SC - If the key is selected with object name, the
	 * PIN for the SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(plain_key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}
	if (call_secsc == TRUE) {

		/* key to be encrypted is stored within SCT/SC */

		/*
		 * in this case the encryption key must be delivered
		 * in encryption_key->key
		 */

		if (!encryption_key->key) {
			aux_add_error(ENOTSUPP, "plainkey = SCT/SC-key && encryption key not delivered in key!", CNULL, 0, proc);
			return (-1);
		}
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_get_EncryptedKey\n");
#endif
		if (secsc_get_EncryptedKey(encrypted_key, plain_key, encryption_key)) {
			aux_add_error(EENCRYPT, "Can't encrypt key within SCT/SC", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* Encryption of key was successful! */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if the SC is not available or 
	 * plain_key doesn't address a key within SCT/SC
	 * 
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if (!(plain_keyinfo = get_keyinfo_from_key(plain_key))) {
		aux_add_error(EINVALID, "get_keyinfo_from_key failed for plain_key", CNULL, 0, proc);
		return (-1);
	}
	if (!(encryption_keyinfo = get_keyinfo_from_key(encryption_key))) {
		aux_add_error(EINVALID, "get_keyinfo_from_key failed for encryption_key", CNULL, 0, proc);
		aux_free_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	if (!(encrypted_key->encryptionAI = aux_cpy_AlgId(encryption_keyinfo->subjectAI))) {
		aux_add_error(EINVALID, "aux_cpy_AlgId failed for encryptionAI", CNULL, 0, proc);
		aux_free_KeyInfo(&encryption_keyinfo);
		aux_free_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	if (!(encrypted_key->subjectAI = aux_cpy_AlgId(plain_keyinfo->subjectAI))) {
		aux_add_error(EINVALID, "aux_cpy_AlgId failed for subjectAI",
			      plain_keyinfo->subjectAI, AlgId_n, proc);
		aux_free_KeyInfo(&encryption_keyinfo);
		aux_free_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	if (!(encrypted_key->subjectkey.bits = (char *) malloc((plain_keyinfo->subjectkey.nbits / 8) + 128))) {
		aux_add_error(EMALLOC, "encrypted_key->subjectkey.bits", CNULL, 0, proc);
		aux_free_KeyInfo(&encryption_keyinfo);
		aux_free_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	encrypted_key->subjectkey.nbits = 0;

#ifdef SECSCTEST
		fprintf(stderr, "plain_key:\n");
		aux_fxdump(stderr, plain_keyinfo->subjectkey.bits, plain_keyinfo->subjectkey.nbits / 8, 0);
		fprintf(stderr, "\n");
#endif

	plainkey_algenc = aux_ObjId2AlgEnc(plain_keyinfo->subjectAI->objid);

	if (((plainkey_algenc != DES) && (plainkey_algenc != DES3)) || 
	     (aux_ObjId2AlgEnc(encryption_keyinfo->subjectAI->objid) != RSA) || 
	     (aux_ObjId2AlgSpecial(encryption_keyinfo->subjectAI->objid) == PKCS_BT_02) || 
	     (aux_ObjId2AlgSpecial(encryption_key->alg->objid) == PKCS_BT_02) || 
	     ((RSA_PARM(encryption_keyinfo->subjectAI->parm) % 8) != 0)) {

		/*
		 * No padding before encryption.
		 */

		in_octets.noctets = (plain_keyinfo->subjectkey.nbits / 8);
		if (plain_keyinfo->subjectkey.nbits % 8)
			in_octets.noctets++;
		in_octets.octets = plain_keyinfo->subjectkey.bits;
	}
	else {

		/* 
		 * Extend DES key to be encrypted before encryption.
		 */ 

		len_extended_key = (RSA_PARM(encryption_keyinfo->subjectAI->parm) / 8) - 1;
		if ((extended_key = sec_random_ostr(len_extended_key)) == NULLOCTETSTRING) {
			aux_add_error(EMALLOC, "random ostr for extended_key->octets", CNULL, 0, proc);
			return (-1);
		}

		len_plain_key = plain_keyinfo->subjectkey.nbits / 8;
		pos_plain_key = len_extended_key - len_plain_key;

		j = pos_plain_key;
		for (i = 0; i < len_plain_key && j < len_extended_key;)
			extended_key->octets[j++] = plain_keyinfo->subjectkey.bits[i++];

#ifdef SECSCTEST
		fprintf(stderr, "extended_key->octets (random string with key):\n");
		aux_fxdump(stderr, extended_key->octets, extended_key->noctets, 0);
		fprintf(stderr, "\n");
#endif
		in_octets.noctets = extended_key->noctets;
		in_octets.octets = extended_key->octets;

	}


	/* 
	 * Encrypt plain key.
	 */ 

	if (sec_encrypt(&in_octets, &(encrypted_key->subjectkey), END, encryption_key) < 0) {

		aux_add_error(EINVALID, "sec_encrypt", CNULL, 0, proc);

		if (extended_key)
			aux_free_OctetString(&extended_key);
		aux_free_KeyInfo(&encryption_keyinfo);
		aux_free_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	
	if (extended_key)
		aux_free_OctetString(&extended_key);
	aux_free_KeyInfo(&encryption_keyinfo);
	aux_free_KeyInfo(&plain_keyinfo);

	return (0);
}


/***************************************************************************************
 *                                 sec_get_key                                         *
 ***************************************************************************************/

int 
sec_get_key(keyinfo, keyref, key)
	KeyInfo        *keyinfo;
	KeyRef          keyref;
	Key            *key;
{
	char           *proc = "sec_get_key";

	if (keyref)
		return (get2_keyinfo_from_keyref(keyinfo, keyref));
	else if (key)
		return (get2_keyinfo_from_key(keyinfo, key));
	else {
		aux_add_error(EINVALID, "don't know which key", CNULL, 0, proc);
		return (-1);
	}
}


/***************************************************************************************
 *                               sec_get_keysize                                       *
 ***************************************************************************************/

int 
sec_get_keysize(keyinfo)
	KeyInfo        *keyinfo;
{

	KeyBits *keybits;
	int ret;

	keybits = d_KeyBits(&keyinfo->subjectkey);
	if(!keybits) return(0);
	ret = keybits->part1.noctets * 8;
	aux_free_KeyBits(&keybits);
	return(ret);
}
	
/***************************************************************************************
 *                                     sec_hash                                        *
 ***************************************************************************************/

RC
sec_hash(in_octets, hash_result, more, alg_id, hash_input)
	OctetString    *in_octets;
	OctetString    *hash_result;
	More            more;
	AlgId          *alg_id;
	HashInput      *hash_input;
{
	static int      keysize;
	static AlgHash  algorithm;
	int             rc;
	OctetString    *key_parm_octetstring;

	char           *proc = "sec_hash";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (sec_state == F_null) {

		/* first call of sec_hash */

		if(sec_time) {
			hash_sec  = hash_usec = 0;
		}
		algorithm = aux_ObjId2AlgHash(alg_id->objid);

		switch (algorithm) {
		case SQMODN:
			keysize = RSA_PARM(alg_id->parm);
			rc = rsa_get_key(&hash_input->sqmodn_input, 1);
			if (rc != 0) {
				aux_add_error(EINVALID, "rsa_get_key failed for sqmodn", CNULL, 0, proc);
				return -1;
			}
			if (!(hash_result->octets = malloc((*(alg_id->parm) + 7) / 8))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		case MD2:
		case MD4:
		case MD5:
		case SHA:
			if (!(hash_result->octets = malloc(64))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		default:
			aux_add_error(EINVALID, "Invalid algorithm", alg_id, AlgId_n, proc);
			return (-1);

		}
		hash_result->noctets = 0;
		sec_state = F_hash;
	}

	if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

	switch (algorithm) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_result, more, keysize);
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_result, more);
		break;
	case SHA:
		rc = sha_hash(in_octets, hash_result, more);
		break;
	default:
		aux_add_error(EALGID, "invalid alg_id", CNULL, 0, proc);
		sec_state = F_null;
		return -1;
	}

	if(sec_time) {
		gettimeofday(&sec_tp2, &sec_tzp2);
		hash_usec = (hash_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	hash_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
		hash_sec = hash_usec/1000000;
		hash_usec = hash_usec % 1000000;
	}

	if (more == END) {
		sec_state = F_null;
		algorithm = NOHASH;
	}
	if (rc)
		aux_add_error(EINVALID, "hash error", CNULL, 0, proc);
	return (rc);
}

/***************************************************************************************
 *                                     sec_keysize                                     *
 ***************************************************************************************/

/*
 *  sec_keysize returns the size of the modulus of the key in keyinfo
 *  which is supposed to be a public RSA key.
 */

int sec_keysize(keyinfo)
KeyInfo *keyinfo;
{
	KeyBits *keybits;
	int keysize;

	keybits = d_KeyBits(keyinfo->subjectkey);
	keysize = keybits->part1.noctets * 8;
	aux_free_KeyBits(&keybits);
	return(keysize);
}


/***************************************************************************************
 *                                     sec_open                                        *
 ***************************************************************************************/

RC
sec_open(pse_sel)
	PSESel         *pse_sel;
{
	int             fd;
	char           *proc = "sec_open";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif


#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/* If SC application not open => open it */
		if (open_app_on_SC(pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		if (pse_sel->object.name && strlen(pse_sel->object.name)) {

			/*
			 * If object = SC object    => open object on SC
			 */

			if (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)) {
				/* open object on SC */
#ifdef SECSCTEST
				fprintf(stderr, "Call of secsc_open (obj)\n");
#endif
				if (secsc_open(pse_sel)) {
					aux_add_error(EOBJ, "Can't open object on SC", pse_sel->object.name, char_n, proc);
					return (-1);
				}
				return (0);	/* object on SC has been
						 * opened */
			} 
		} 
		else {

			/*
                         * SC application has already been opened.
                         * 
                         * The application on the SW-PSE will be opened,
                         * if an object on the SW-PSE shall be opened.
                         * 
			 */
			return (0);

		}		

	}			/* if (SC available && app = SC-app) */
	/**************************************************************************************/

	/*
	 * The following is only performed, 
	 * if an object on the SW-PSE shall be opened.
	 * 
         * --------------------------------------------------------------
         * If the SC is available and an application on the SC could be 
         * opened, the PIN read from the SC is used as PIN for the SW-PSE 
         * application/object.
	 */
#endif				/* SCA */


	fd = open_object(pse_sel, O_RDONLY);
	if (fd == -1) {
		aux_add_error(LASTERROR, "open object", pse_sel, PSESel_n, proc);
		return (-1);
	} 
	else if (fd >= 0) close(fd);
	return (0);
}



/***************************************************************************************
 *                                     sec_print_toc                                   *
 ***************************************************************************************/

RC
sec_print_toc(ff, pse_sel)
	FILE           *ff;
	PSESel         *pse_sel;
{
	PSEToc         *sctoc;
	char           *proc = "sec_print_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!pse_sel)
		if (!(pse_sel = set_key_pool(0))) {
			aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
			return (-1);
		}
	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}

#ifdef SCA
	if((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if(SCapp_available == TRUE) {
		sctoc = chk_SCToc(pse_sel);
/*
		strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
		if(!pse_sel->pin) {
			aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
			return (-1);
		}
*/
		if(pse_sel->object.name && strlen(pse_sel->object.name)) {
			strrep(&(pse_sel->object.pin), pse_sel->pin);
		}
	}
#endif

	/* Read toc */

	if (!(psetoc = chk_toc(pse_sel, FALSE))) {
#ifdef SCA
		if(SCapp_available == TRUE && SC_ignore_SWPSE == FALSE) {
			aux_add_error(EOBJ, "Can't read SW PSEToc", pse_sel, PSESel_n, proc);
			return (-1);
		}
		if(SCapp_available == FALSE) {
			aux_add_error(EOBJ, "Can't read PSEToc", pse_sel, PSESel_n, proc);
			return (-1);
		}
#else
		aux_add_error(LASTERROR, "Can't read PSEToc", pse_sel, PSESel_n, proc);
		return (-1);
#endif
	}
	fprintf(ff, "Table of Contents of PSE %s:\n", pse_sel->app_name);
#ifdef SCA
	if(SCapp_available == TRUE) {
		if (psetoc) aux_fprint_PSEToc(ff, sctoc, psetoc);
		else aux_fprint_PSEToc(ff, sctoc, sctoc);
	}
	else aux_fprint_PSEToc(ff, psetoc, (PSEToc * ) 0);
#else
	aux_fprint_PSEToc(ff, psetoc, (PSEToc * ) 0);
#endif

	return (0);
}


/***************************************************************************************
 *                                     sec_read_toc                                   *
 ***************************************************************************************/

PSEToc *
sec_read_toc(pse_sel)
	PSESel         *pse_sel;
{
	char           *proc = "sec_read_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!pse_sel)
		if (!(pse_sel = set_key_pool(0))) {
			aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
			return ((PSEToc *)0);
		}
	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return ((PSEToc *)0);
	}

#ifdef SCA
	if((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return ((PSEToc *)0);
	}
	if(SCapp_available == TRUE) {
		sc_toc = chk_SCToc(pse_sel);
		if (!sc_toc) {
			aux_add_error(LASTERROR, "Can't read SCToc", pse_sel, PSESel_n, proc);
			return ((PSEToc *)0);
		}

		if(pse_sel->object.name && strlen(pse_sel->object.name)) {
			strrep(&(pse_sel->object.pin), pse_sel->pin);
		}
	}
#endif

	/* Read toc */

	if (!(psetoc = chk_toc(pse_sel, FALSE))) {
#ifdef SCA
		if(SCapp_available == TRUE && SC_ignore_SWPSE == FALSE) {
			aux_add_error(EOBJ, "Can't read SW PSEToc", pse_sel, PSESel_n, proc);
			return ((PSEToc *)0);
		}
		if(SCapp_available == FALSE) {
			aux_add_error(EOBJ, "Can't read PSEToc", pse_sel, PSESel_n, proc);
			return ((PSEToc *)0);
		}
#else
		aux_add_error(LASTERROR, "Can't read PSEToc", pse_sel, PSESel_n, proc);
		return ((PSEToc *)0);
#endif
	}

/* sc_toc and psetoc should be merged here! */
#ifdef SCA
	if(sc_toc) return(sc_toc);
	else return(psetoc);
#else
	return(psetoc);
#endif

}

/***************************************************************************************
 *                                     sec_read_tocs                                   *
 ***************************************************************************************/

RC
sec_read_tocs(pse_sel, SCtoc, PSEtoc)
	PSESel         *pse_sel;
	PSEToc         **SCtoc, **PSEtoc;
{
	char           *proc = "sec_read_tocs";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif
	*SCtoc = (PSEToc *)0;

	if (!pse_sel)
		if (!(pse_sel = set_key_pool(0))) {
			aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
			return (-1);
		}
	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}

#ifdef SCA
	if((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if(SCapp_available == TRUE) {
		sc_toc = chk_SCToc(pse_sel);
		if(pse_sel->object.name && strlen(pse_sel->object.name)) {
			strrep(&(pse_sel->object.pin), pse_sel->pin);
		}
	}
#endif

	/* Read toc */

	if (!(psetoc = chk_toc(pse_sel, FALSE))) {
#ifdef SCA
		if(SCapp_available == TRUE && SC_ignore_SWPSE == FALSE) {
			aux_add_error(EOBJ, "Can't read SW PSEToc", pse_sel, PSESel_n, proc);
			return (-1);
		}
		if(SCapp_available == FALSE) {
			aux_add_error(EOBJ, "Can't read PSEToc", pse_sel, PSESel_n, proc);
			return (-1);
		}
#else
		aux_add_error(LASTERROR, "Can't read PSEToc", pse_sel, PSESel_n, proc);
		return (-1);
#endif
	}

/* sc_toc and psetoc should be merged here! */
#ifdef SCA
	if(sc_toc) *SCtoc = sc_toc;
#endif
	*PSEtoc = psetoc;
	return(0);

}
/***************************************************************************************
 *                            sec_put_EncryptedKey                                    *
 ***************************************************************************************/

RC
sec_put_EncryptedKey(encrypted_key, plain_key, decryption_key, replace)
	EncryptedKey   *encrypted_key;
	Key            *plain_key;
	Key            *decryption_key;
	Boolean         replace;
{
	BitString       in_bits;
	static KeyInfo  plain_keyinfo;
	KeyBits        *kb;
	char           *zw;
	int             keysize;
	rsa_parm_type  *rsaparm;
	AlgEnc          plainkey_algenc;
	AlgEnc          deckey_algenc;
	AlgSpecial      deckey_algspecial;

	int		i, j, pos_plain_key, len_plain_key, len_extended_key;
	KeyInfo        *decryption_keyinfo;

	char           *proc = "sec_put_EncryptedKey";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!plain_key || !decryption_key || !encrypted_key) {
		aux_add_error(EINVALID, "key missing", CNULL, 0, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * For the decryption of the encrypted key within SCT/SC both
	 * the plain_key and the encryption key must address keys
	 * within SCT/SC
	 */

	/*
	 * 1. Check whether plain_key (where to store decrypted key)
	 * addresses a key within SCT/SC - If the key is selected
	 * with object name, the PIN for the SW-PSE is read from the
	 * SC.
	 */

	if ((call_secsc = handle_in_SCTSC(plain_key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}
	if (call_secsc == TRUE) {

		/* plain_key within SCT/SC */

		/*
		 * in this case the decryption key must be a key
		 * within SCT/SC, too
		 */

		if ((call_secsc = handle_in_SCTSC(decryption_key, FALSE)) == -1) {
			aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
			return (-1);
		}
		if (call_secsc == FALSE) {
			aux_add_error(ENOTSUPP, "plainkey = SCT/SC-key && decryption key not!", CNULL, 0, proc);
			return (-1);
		}
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_put_EncryptedKey\n");
#endif
		if (secsc_put_EncryptedKey(encrypted_key, plain_key, decryption_key, replace)) {
			aux_add_error(EENCRYPT, "Can't decrypt key within SCT/SC", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* Decryption of key was successful! */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if the SC is not available or 
	 * plain_key does not address a key within SCT/SC.
	 * 
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */




	if (!(plain_keyinfo.subjectAI = aux_cpy_AlgId(encrypted_key->subjectAI))) {
		aux_add_error(EINVALID, "copy AlgId", encrypted_key->subjectAI, AlgId_n, proc);
		return (-1);
	}
	if (!(plain_keyinfo.subjectkey.bits = (char *) malloc((encrypted_key->subjectkey.nbits / 8) + 32))) {
		aux_add_error(EMALLOC, "plain_keyinfo.subjectkey.bits ", CNULL, 0, proc);
		aux_free2_KeyInfo(&plain_keyinfo);
		return (-1);
	}
	plain_keyinfo.subjectkey.nbits = 0;

	in_bits.nbits = encrypted_key->subjectkey.nbits;
	in_bits.bits = encrypted_key->subjectkey.bits;

	if (sec_decrypt(&in_bits, &(plain_keyinfo.subjectkey), END, decryption_key) < 0) {

		aux_add_error(EINVALID, "sec_decrypt", CNULL, 0, proc);
		return (-1);
	}
	plain_keyinfo.subjectkey.nbits *= 8;

	plainkey_algenc = aux_ObjId2AlgEnc(plain_keyinfo.subjectAI->objid);
	if (plainkey_algenc == RSA) {
		zw = plain_keyinfo.subjectkey.bits;
		if (e2_KeyBits((kb = d_KeyBits(&(plain_keyinfo.subjectkey))), &(plain_keyinfo.subjectkey)) < 0) {
			free(zw);
			aux_free_KeyBits(&kb);
			aux_add_error(EINVALID, "d/e_KeyBits failed for subjectkey", CNULL, 0, proc);
			return (-1);
		}
		free(zw);
		aux_free_KeyBits(&kb);
	} 
	else if (plainkey_algenc == DES)
		len_plain_key = 8;
	else if (plainkey_algenc == DES3)
		len_plain_key = 16;


	/*
	 * If algorithm of plain_key = DES or DES3 and 
	 *    algorithm of decryption_key = RSA and 
	 *    special block format of decryption key != PKCS_BT_02,
	 * 
	 * it is assumed that the DES key has been extended before encryption
	 *    (In this case the last 8 (16) octets contain the DES (DES3) key)
	 */

	/*
	 * Get algorithm of the decryption key
	 */

#ifdef SCA

	if ((call_secsc = handle_in_SCTSC(decryption_key, FALSE)) == TRUE) {
		/*
		 * Decryption key is a key stored on the SC
		 */
		deckey_algenc = aux_ObjId2AlgEnc(decryption_key->alg->objid);
		deckey_algspecial = aux_ObjId2AlgSpecial(decryption_key->alg->objid);
	}
	else {
#endif
		/*
		 * Decryption key is a key stored in the SW-PSE
		 */
		if (!(decryption_keyinfo = get_keyinfo_from_key(decryption_key))) {
			aux_add_error(EINVALID, "get_keyinfo_from_key failed for decryption_key", CNULL, 0, proc);
			aux_free2_KeyInfo(&plain_keyinfo);
			return (-1);
		}
		deckey_algenc  = aux_ObjId2AlgEnc(decryption_keyinfo->subjectAI->objid);
		deckey_algspecial = aux_ObjId2AlgSpecial(decryption_keyinfo->subjectAI->objid);

		aux_free_KeyInfo(&decryption_keyinfo);
#ifdef SCA
	}
#endif


	if (((plainkey_algenc == DES) || (plainkey_algenc == DES3)) &&
	     (deckey_algenc == RSA) && (deckey_algspecial != PKCS_BT_02)) {

#ifdef SECSCTEST
		fprintf(stderr, "extended key:\n");
		fprintf(stderr, "plain_keyinfo.subjectkey.nbits: %d\n", plain_keyinfo.subjectkey.nbits);
		aux_fxdump(stderr, plain_keyinfo.subjectkey.bits, plain_keyinfo.subjectkey.nbits / 8, 0);
		fprintf(stderr, "\n");
#endif

		len_extended_key = plain_keyinfo.subjectkey.nbits / 8;
		pos_plain_key = len_extended_key - len_plain_key;
	
		j = pos_plain_key;

		for (i=0; i<len_plain_key && j < len_extended_key;)
			plain_keyinfo.subjectkey.bits[i++] = plain_keyinfo.subjectkey.bits[j++];

	}

	plain_keyinfo.subjectkey.nbits = len_plain_key * 8;

#ifdef SECSCTEST
		fprintf(stderr, "plain_key:\n");
		fprintf(stderr, "plain_keyinfo.subjectkey.nbits: %d\n", plain_keyinfo.subjectkey.nbits);
		aux_fxdump(stderr, plain_keyinfo.subjectkey.bits, plain_keyinfo.subjectkey.nbits / 8, 0);
		fprintf(stderr, "\n");
#endif



	/* store key */
	if (put_keyinfo_according_to_key(&plain_keyinfo, plain_key, (ObjId *)0) < 0) {
		aux_add_error(EINVALID, "can't store decrypted key", CNULL, 0, proc);
		return -1;
	}
	
	return (0);

}


/***************************************************************************************
 *                                 sec_put_key                                         *
 ***************************************************************************************/

KeyRef 
sec_put_key(keyinfo, keyref)
	KeyInfo        *keyinfo;
	KeyRef          keyref;
{
	PSESel         *pse_sel;
	PSEToc         *toc;
	struct PSE_Objects *nxt;
	char           *object, key[32], buf[32];
	int             fd, maxref, ref, rcode, free_name;
	OctetString    *encoded_key;


	char           *proc = "sec_put_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!(pse_sel = set_key_pool(0))) {
		aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
		return (-1);
	}
	if (!(object = pse_name(pse_sel->app_name, "", &free_name))) {
		aux_add_error(EOBJ, " get object-name(1)", "", char_n, proc);
		if (pse_sel->pin) strzero(pse_sel->pin);
		return (-1);
	}
	if ((fd = open(object, O_RDONLY)) < 0) {	/* check whether
							 * key_pool exists */
		if (errno == ENOENT)
			if (sec_create(pse_sel) < 0) {	/* create one */
				aux_add_error(EINVALID, "can't create keypool", pse_sel, PSESel_n, proc);
				if (pse_sel->pin) strzero(pse_sel->pin);
				if (free_name) free(object);
				return (-1);
			}
	}
	close(fd);

	if (!(pse_sel = set_key_pool(keyref))) {
		aux_add_error(EINVALID, "set_key_pool failed for object", CNULL, 0, proc);
		return (-1);
	}
	if ((ref = sec_create(pse_sel)) < 0) {	/* create object in key_pool */
		aux_add_error(EINVALID, "can't create object in keypool", pse_sel, PSESel_n, proc);
		if (pse_sel->pin) strzero(pse_sel->pin);
		return (-1);
	}
	if (keyref < 0)	keyref = ref;
	encoded_key = e_KeyInfo(keyinfo);	/* encode keyinfo */
	if(encoded_key) {
		rcode = sec_write(pse_sel, encoded_key);	/* write it to object */
		if(encoded_key->octets) free(encoded_key->octets);
	}
	else {
		aux_add_error(EINVALID, "can't encode keyinfo", keyinfo, KeyInfo_n, proc);
		return (-1);
	}
	if (pse_sel->pin) strzero(pse_sel->pin);
	if (rcode < 0) {
		aux_add_error(EINVALID, "write keyinfo to object", pse_sel, PSESel_n, proc);
		return (-1);
	} 
	else return (keyref);
}


/***************************************************************************************
 *                                     sec_read                                        *
 ***************************************************************************************/

RC
sec_read(pse_sel, content)
	PSESel         *pse_sel;
	OctetString    *content;
{
	int             fd, size, len;
	RC              rc;
	char           *proc = "sec_read";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
		return (-1);
	}
	if (!pse_sel->object.name || !strlen(pse_sel->object.name)) {
		aux_add_error(EINVALID, "object name missing", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
		return (-1);
	}
	if (!content) {
		aux_add_error(EINVALID, "content is NULL", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/* If SC application not open => open it */
		if (open_app_on_SC(pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		if (pse_sel->object.name && strlen(pse_sel->object.name)) {

			/*
			 * If object = SC object    => read from WEF on SC
			 */

			if (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)) {
				/* read from object on SC */
#ifdef SECSCTEST
				fprintf(stderr, "Call of secsc_read (obj)\n");
#endif
				if (secsc_read(pse_sel, content)) {
					aux_add_error(ESCREAD, "Can't read from SC object", pse_sel->object.name, char_n, proc);
					return (-1);
				}
				return (0);	/* read from SC-object
						 * successful */
			} 
		}

		/* 
		 *
		 *  An application | object on the SW-PSE shall be read!
		 *
		 *  => Get the PIN for the SW-PSE from the SC.
		 */
		
		strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
		if(!pse_sel->pin) {
			aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
			return (-1);
		}
		if(pse_sel->object.name && strlen(pse_sel->object.name)) {
			strrep(&(pse_sel->object.pin), pse_sel->pin);
		}

	}			/* if (SC available && app = SC-app) */
	/**************************************************************************************/

	/*
	 * The following is only performed, 
	 * if the object to be read is an object on the SW-PSE.
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */




	if ((fd = open_object(pse_sel, O_RDONLY)) < 0) {
		aux_add_error(LASTERROR, "open object", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
		return (-1);
	}
	rc = read_object(pse_sel, fd, content);
	if (rc)	aux_add_error(EOBJ, "read object", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
	return (rc);
}


/***************************************************************************************
 *                                     sec_read_PSE                                    *
 ***************************************************************************************/

RC 
sec_read_PSE(pse_sel, type, value)
	PSESel         *pse_sel;
	ObjId          *type;
	OctetString    *value;
{
	OctetString     content;
	OctetString    *result;

	char           *proc = "sec_read_PSE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!value || !type) {
		aux_add_error(EINVALID, "value or type = 0", CNULL, 0, proc);
		return (-1);
	}
	if (sec_read(pse_sel, &content) < 0) {
		aux_add_error(EOBJ, "read object", aux_cpy_PSESel(pse_sel), PSESel_n, proc);
		return (-1);
	}
	if ((result = d_PSEObject(type, &content)) == (OctetString *) 0) {
		aux_add_error(EINVALID, "decoding of PSEObject", CNULL, 0, proc);
		free(content.octets);
		return (-1);
	}
	free(content.octets);

	value->noctets = result->noctets;
	value->octets = result->octets;

	return (0);
}



/********************************************************************************
 *                              sec_write_toc
 *******************************************************************************/

/*
 *      sec_write_toc(pse_sel, toc) writes the toc specified by "toc" onto the PSE 
 *      specified by "pse_sel".
 *      It returns -1 in case of errors, 0 otherwise.
 */

int
sec_write_toc(pse_sel, toc)
PSESel         * pse_sel;
PSEToc	       * toc;
{
	int              ret;

	char           * proc = "sec_write_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (! pse_sel || ! toc) {
		aux_add_error(EINVALID, "No pse_sel or toc parameter provided", CNULL, 0, proc);
		return (- 1);
	}

	ret = write_toc(pse_sel, toc, O_WRONLY | O_TRUNC);

	return (ret);
}



/*******************************************************************************
 *                                    sec_sctest                               *
 *									       *
 *  Check whether SCT/SC is available:					       *
 *									       *
 *  1) Perform SC configuration (read SC configuration file (".scinit")).      *
 *  									       *
 *  2) If app_name != NULL, check whether this application is an SC-application*
 *									       *
 *  The following is performed, - if app_name == CNULL or 		       *
 *			        - if app_name != CNULL and app = SC-app.       *
 *									       *
 *  3) Perform SCT configuration 					       *
 *     - e.g. get data from a prior process		     		       *
 *     - Check whether selected SCT (sc_sel.sct_id) is available. This is done *
 *       internally by calling the STARMOD function "sca_display". 	       *
 *       If the actual process hasn't yet opened the device for the selected   *
 *       SCT, this is done automatically by the STARMOD modul. If open fails   *
 *       (device unknown or device busy), "sec_sctest()" returns -1.	       *
 *									       *
 *									       *
 *  Return values:							       *
 *  TRUE  ->  SCT/SC is available and application is an SC-application         *
 *  FALSE ->  SCT/SC is not available or application is not an SC-application  *
 *  -1    ->  error during SCT/SC configuration				       *
 *                 (e.g. error in SC configuration file,       		       *
 *		         device unknown or device busy)		 	       *
 *									       *
 *******************************************************************************/

RC
sec_sctest(app_name)
	char           *app_name;
{
#ifdef SCA

	int		SCT_available;
	int		SC_available;
	SCAppEntry     *sc_app_entry;

	char           *proc = "sec_sctest";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif


	if (SC_ignore == TRUE)
		return (FALSE);


	/*
	 * Perform SC configuration
	 */

	if ((SC_available = SC_configuration()) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SC_available == FALSE)

		/*
		 * SC is not available (no SC configuration file found)
		 */
		return (FALSE);



	/*
	 *  Intermediate result :  SC configuration was successful
	 *  Next to do:		   Check whether app is an SC-application
	 */

	if ((app_name) && (!(sc_app_entry = aux_AppName2SCApp(app_name)))) {

		/*
		 * application to be tested is not an SC-application.
		 */
		return (FALSE);
	}



	/*
	 * Perform SCT configuration (get data from a prior process)
	 *   and check whether selected SCT is available (open device for SCT, if not yet done).
	 */

	if ((SCT_available = SCT_configuration (sc_sel.sct_id)) == -1) {
		if (aux_last_error() == EOPENDEV) 
			aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
		else
			aux_add_error(ECONFIG, "Error during SCT configuration.", CNULL, 0, proc);
		return (-1);
	}

	if (SCT_available == FALSE)

		/*
		 * SCT is not available
		 */
		return (FALSE);



	if (app_name) SC_ignore_SWPSE = sc_app_entry->ignore_flag;
	return (TRUE);


#else
	return (FALSE);
#endif				/* SCA */

}				/* sec_sctest */





/*******************************************************************************
 *                                    sec_psetest                              *
 *									       *
 *									       *
 *									       *
 * 1) Perform SC configuration (read SC configuration file (".scinit")).       *
 *  									       *
 *									       *
 * 2) Check type of pse:						       *
 *									       *
 *    a) Check type of application (pse_sel->object == CNULL):		       *
 *									       *
 *	 Check whether application (pse_sel->app_name) is an SC-application.   *
 *       Possible return values: NOT_ON_SC, APP_ON_SC			       *
 *									       *
 *									       *
 *    b) Check type of object  (pse_sel->object != CNULL):		       *
 *									       *
 *       Check whether application and object are objects on the SC. If object *
 *	 is an object on the SC, it is returned whether this object is a key   *
 *	 or a file on the SC.						       *
 *       Possible return values: NOT_ON_SC, FILE_ON_SC, KEY_ON_SC	       *
 *									       *
 *									       *
 *******************************************************************************/

PSEType 
sec_psetest(pse_sel)
	PSESel           *pse_sel;
{
#ifdef SCA

	int		SC_available;
	SCAppEntry     *sc_app_entry;
	SCObjEntry     *sc_obj_entry;

	char           *proc = "sec_psetest";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif


	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
	

	/*
	 * Perform SC configuration
	 */

	if ((SC_available = SC_configuration()) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SC_available == FALSE)

		/*
		 * SC is not available (no SC configuration file found)
		 */
		return (NOT_ON_SC);



	/*
	 *  Intermediate result :  SC configuration was successful => SC is available
         *  Next to do:		   Check whether Application and/or object 
         *			   are supposed to be on the SC.
	 */
	

	if (pse_sel->object.name && strlen(pse_sel->object.name)) {

		/*
		 * Check type of object
		 */

		sc_obj_entry = aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name);

		if (sc_obj_entry == (SCObjEntry * ) 0) 	        
			return (NOT_ON_SC);

		else if (sc_obj_entry->type == SC_KEY_TYPE) 		
			return (KEY_ON_SC);
		     else    					
			return (FILE_ON_SC);

	}
	else {

		/*
		 * Check type of application
		 */

	        sc_app_entry = aux_AppName2SCApp(pse_sel->app_name);

		if (sc_app_entry == (SCAppEntry * ) 0) 	
			return (NOT_ON_SC);
		else  	return (APP_ON_SC);

	}


#else
	return (NOT_ON_SC);
#endif				/* SCA */

}				/* sec_psetest */





/*******************************************************************************
 *                                    sec_set_sct                              *
 *******************************************************************************/
void
sec_set_sct(sct_id)
	int             sct_id;
{
#ifdef SCA
	sc_sel.sct_id = sct_id;
#endif
}


/*******************************************************************************
 *                                    sec_sign                                 *
 *******************************************************************************/

RC
sec_sign(in_octets, signature, more, key, hash_input)
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	Key            *key;
	HashInput      *hash_input;
{
	static AlgEnc   algenc;
	static AlgHash  alghash;
	static AlgSpecial  algspecial;
	static OctetString *hash_result;
	OctetString     *rsa_input, *encodedDigest;
	AlgType         algtype;
	AlgEnc          keyalgenc;
	int             rc;

	char           *proc = "sec_sign";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	public_modulus_length = 0;

#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether signing shall be done within the SCT/SC - If
	 * the key is selected with object name, the PIN for the
	 * SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(key, FALSE)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}
	if (call_secsc == TRUE) {

		/* sign with key from the SC */
#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_sign\n");
#endif
		if (secsc_sign(in_octets, signature, more, key, hash_input)) {
			aux_add_error(ESIGN, "Can't sign with key from SC", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* Generation of signature was
					 * successful! */

	}		/* if (call_secsc == TRUE) */
	/**************************************************************************************/

	/*
	 * The following is only performed, if - the SC is not available or -
	 * signature key doesn't address a key within SCT/SC
	 * 
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if (sec_state == F_null) {
		if(sec_time) {
			hash_sec  = hash_usec = rsa_sec = rsa_usec = dsa_sec = dsa_usec = 0;
		}
		if (get2_keyinfo_from_key(&got_key, key) < 0)
			return -1;

		keyalgenc = aux_ObjId2AlgEnc(got_key.subjectAI->objid);
		if(key->alg) {
			if (!signature->signAI) { /* for compatibility with older SecuDE versions, accept
						     the sign algorithm also from parameter signature */
				signature->signAI = aux_cpy_AlgId(key->alg);
			}
		}
			
		if ((signature->signAI == NULLALGID) || (signature->signAI->objid == NULLOBJID)) {
			/* default signature AI = md5WithRsaEncryption or dsaWithSHA 
			   depending of keyalgenc  */
			if(keyalgenc == RSA) signature->signAI = aux_cpy_AlgId(md5WithRsaEncryption);
			if(keyalgenc == DSA) signature->signAI = aux_cpy_AlgId(dsaWithSHA);
		}
		algenc = aux_ObjId2AlgEnc(signature->signAI->objid);
		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		algspecial = aux_ObjId2AlgSpecial(signature->signAI->objid);
		algtype = aux_ObjId2AlgType(signature->signAI->objid);
		if (algtype != SIG) {
			aux_add_error(EINVALID, "wrong signAI in signature", signature->signAI, AlgId_n, proc);
			return -1;
		}

		/* check required encryption method against that of the secret key */

		if (algenc != keyalgenc) {
			aux_add_error(EINVALID, "wrong encryption method in parameter key", got_key.subjectAI, AlgId_n, proc);
			return -1;
		}
		if(algenc == RSA) public_modulus_length = RSA_PARM(got_key.subjectAI->parm);
		if(algenc == DSA) {
			if(got_key.subjectAI->parm) public_modulus_length = *(dsaSK_parm_type *)(got_key.subjectAI->parm);
			else public_modulus_length = 320;
		} 
		if (!(hash_result = (OctetString *) malloc(sizeof(OctetString)))) {
			aux_add_error(EMALLOC, "hash_result", CNULL, 0, proc);
			return (-1);
		}
		hash_result->noctets = 0;
		switch (alghash) {
		case SQMODN:
			rc = rsa_get_key(&hash_input->sqmodn_input, 1);
			if (rc != 0) {
				aux_add_error(EINVALID, "rsa_get_key failed for sqmodn", CNULL, 0, proc);
				return -1;
			}
			if (!(hash_result->octets = malloc((public_modulus_length + 7) / 8))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		case MD2:
		case MD4:
		case MD5:
		case SHA:
			if (!(hash_result->octets = malloc(64))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		}

		signature->signature.nbits = 0;
		if (!(signature->signature.bits = malloc(public_modulus_length / 8 + 16))) {
			aux_add_error(EMALLOC, "signature->signature.bits", CNULL, 0, proc);
			return (-1);
		}
		sec_state = F_sign;
	}

	if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

	switch (alghash) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_result, more, public_modulus_length);
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_result, more);
		break;
	case SHA:
		rc = sha_hash(in_octets, hash_result, more);
		break;
	default:
		aux_add_error(EALGID, "invalid alg_id", CNULL, 0, proc);
		algenc = NOENC;
		alghash = NOHASH;
		aux_free_OctetString(&hash_result);
		aux_free2_KeyInfo(&got_key);
		sec_state = F_null;
		return -1;
	}

	if(sec_time) {
		gettimeofday(&sec_tp2, &sec_tzp2);
		hash_usec = (hash_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	hash_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
		hash_sec = hash_usec/1000000;
		hash_usec = hash_usec % 1000000;
	}

	if (more == END) {
		if (rc == 0) {
			switch (algenc) {
			case RSA:

				if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

				if(algspecial == PKCS_BT_01 || algspecial == PKCS_BT_TD) {

					/*  Here goes PKCS#1 ...   */

					encodedDigest = aux_create_PKCS_MIC_D(hash_result, signature->signAI);
					rsa_input = aux_create_PKCSBlock(algspecial, encodedDigest);
					aux_free_OctetString(&hash_result);		
					if(encodedDigest) aux_free_OctetString(&encodedDigest);
          			}
				else rsa_input = hash_result;

				rc = rsa_get_key(&got_key.subjectkey, 1);
				if (rc < 0) aux_add_error(EINVALID, "rsa_get_key failed failed", CNULL, 0, proc);
				else if(!rsa_input) aux_add_error(EINVALID, "aux_create_PKCSBlock failed", CNULL, 0, proc);  
				else {
					rc = rsa_sign(rsa_input, &(signature->signature));
					if (rc < 0) aux_add_error(ESIGN, "sign failed", CNULL, 0, proc);
				}
				if(sec_time) {
					gettimeofday(&sec_tp2, &sec_tzp2);
					rsa_usec = (rsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + rsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
					rsa_sec = rsa_usec/1000000;
					rsa_usec = rsa_usec % 1000000;
				}

				break;
			case DSA:

				if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

				rc = dsa_get_key(&got_key.subjectkey, public_modulus_length);
				if (rc < 0) aux_add_error(EINVALID, "dsa_get_key failed failed", CNULL, 0, proc);
				else {
					rc = dsa_sign(hash_result, &(signature->signature));
					if (rc < 0) aux_add_error(ESIGN, "sign failed", CNULL, 0, proc);
				}
				if(sec_time) {
					gettimeofday(&sec_tp2, &sec_tzp2);
					dsa_usec = (dsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + dsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
					dsa_sec = dsa_usec/1000000;
					dsa_usec = dsa_usec % 1000000;
				}

				break;
			default: 
			        aux_add_error(EINVALID, "AlgEnc of algorithm wrong", CNULL, 0, proc);
				rc = -1;
				break;	
			}
		}
		else aux_add_error(EHASH, "hash failed", CNULL, 0, proc);
		if(algenc == RSA) aux_free_OctetString(&rsa_input);
		aux_free2_KeyInfo(&got_key);
		algenc = NOENC;
		alghash = NOHASH;
		sec_state = F_null;
	}
	return (rc);
}

/*******************************************************************************
 *                             sec_string_to_key                               *
 *******************************************************************************/

RC
sec_string_to_key(pin, des_key)
	char           *pin;
	Key            *des_key;
{
	KeyInfo        *key_sec; 
	PSEToc         *toc;
	RC              rcode;
	char           *string_to_key();

	char           *proc = "sec_string_to_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	/*
	 * Build KeyInfo
	 */

	if (!(key_sec = (KeyInfo *) calloc(1, sizeof(KeyInfo)))) {
		aux_add_error(EMALLOC, "key_sec", CNULL, 0, proc);
		return (-1);
	}
	key_sec->subjectAI = aux_cpy_AlgId(sec_io_algid);

	/* Generate key from string */

	if (!(key_sec->subjectkey.bits = string_to_key(pin))) {
		aux_add_error(EMALLOC, "key_sec->subjectkey.bits", CNULL, 0, proc);
		aux_free_KeyInfo(&key_sec);
		return (-1);
	}
	key_sec->subjectkey.nbits = 64;

	/*
	 * Return the key in the form requested by des_key
	 */
	rcode = put_keyinfo_according_to_key(key_sec, des_key, (ObjId *)0);
	aux_free_KeyInfo(&key_sec);
	if (rcode) aux_add_error(EINVALID, "put_keyinfo_according_to_key failed", CNULL, 0, proc);
	return (rcode);
}


/***************************************************************************************
 *                                     sec_verify                                      *
 ***************************************************************************************/

RC
sec_verify(in_octets, signature, more, key, hash_input)
	OctetString    *in_octets;
	Signature      *signature;
	More            more;
	Key            *key;
	HashInput      *hash_input;
{

	static OctetString *hash_result;
	static AlgEnc   algenc;
	static AlgHash  alghash;
	static AlgSpecial     algspecial;
	static int      keysize;
	OctetString     *rsa_input, *encodedDigest;
	BitString       *b1;
	OctetString     *o1;
	AlgType         algtype;
	int             rc, i;

	char           *proc = "sec_verify";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

#ifdef SCA
/************************  S C  -  P A R T  *******************************************/


	/*
	 * Check whether verification shall be done within the
	 * SCT/SC - If the key is selected with object name,
	 * the PIN for the SW-PSE is read from the SC.
	 */

	if ((call_secsc = handle_in_SCTSC(key, SC_verify)) == -1) {
		aux_add_error(EPSEPIN, "Error in handle_in_SCTSC", CNULL, 0, proc);
		return (-1);
	}

	if (call_secsc == TRUE) {

		/* verify within SCT/SC */

#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_verify(key)\n");
#endif
		if (secsc_verify(in_octets, signature, more, key, hash_input) < 0) {
			aux_add_error(EVERIFICATION, "Verification within SCT/SC failed", CNULL, 0, proc);
			return (-1);
		}
		return (0);	/* Verification positive! */

	}			/* end if (SC available && key->key) */
	/**************************************************************************************/

	/*
	 * The following is called, if : - global variable "SC_verify" is
	 * FALSE or - the SC is not available or - the key is not delivered
	 * by the calling routine
	 */
#endif				/* SCA */



	if (sec_state == F_null) {
		if(sec_time) {
			hash_sec  = hash_usec = rsa_sec = rsa_usec = dsa_sec = dsa_usec = 0;
		}
		if (get2_keyinfo_from_key(&got_key, key) < 0) {
			aux_add_error(EINVALID, "get2_keyinfo_from_key failed", CNULL, 0, proc);
			return -1;
		}
		i = sec_get_keysize(&got_key);
		public_modulus_length = i;
		sec_SignatureTimeDate = (UTCTime *)0;
		if ((signature->signAI == NULLALGID) || (signature->signAI->objid == NULLOBJID)) {
			/* default signature AI = md5WithRsa */
			signature->signAI = aux_cpy_AlgId(md5WithRsa);
		}
		algenc = aux_ObjId2AlgEnc(signature->signAI->objid);
		alghash = aux_ObjId2AlgHash(signature->signAI->objid);
		algtype = aux_ObjId2AlgType(signature->signAI->objid);
		algspecial = aux_ObjId2AlgSpecial(signature->signAI->objid);
		if (algtype != SIG) {
			aux_add_error(EINVALID, "wrong signAI in signature", signature->signAI, AlgId_n, proc);
			return -1;
		}
		/* check encryption method of signature key */
		if (algenc != aux_ObjId2AlgEnc(got_key.subjectAI->objid)) {
			aux_add_error(EINVALID, "wrong encryption method in parameter key", got_key.subjectAI, AlgId_n, proc);
			return -1;
		}
		if (!(hash_result = (OctetString *) malloc(sizeof(OctetString)))) {
			aux_add_error(EMALLOC, "hash_result", CNULL, 0, proc);
			return (-1);
		}
		hash_result->noctets = 0;
		switch (alghash) {
		case SQMODN:
			keysize = public_modulus_length;
			rc = rsa_get_key(&hash_input->sqmodn_input, 1);
			if (rc != 0) {
				aux_add_error(EINVALID, "rsa_get_key failed for sqmodn", CNULL, 0, proc);
				return -1;
			}
			if (!(hash_result->octets = malloc(512))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		case MD2:
		case MD4:
		case MD5:
		case SHA:
			if (!(hash_result->octets = malloc(64))) {
				aux_add_error(EMALLOC, "hash_result->octets", CNULL, 0, proc);
				return (-1);
			}
			break;
		}
		sec_state = F_verify;
	}

	if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);
	switch (alghash) {
	case SQMODN:
		rc = hash_sqmodn(in_octets, hash_result, more, keysize);
		break;
	case MD2:
		rc = md2_hash(in_octets, hash_result, more);
		break;
	case MD4:
		rc = md4_hash(in_octets, hash_result, more);
		break;
	case MD5:
		rc = md5_hash(in_octets, hash_result, more);
		break;
	case SHA:
		rc = sha_hash(in_octets, hash_result, more);
		break;
	default:
		aux_add_error(EALGID, "invalid alg_id", CNULL, 0, proc);
		algenc = NOENC;
		alghash = NOHASH;
		aux_free_OctetString(&hash_result);
		aux_free2_KeyInfo(&got_key);
		sec_state = F_null;
		return -1;
	}

	if(sec_time) {
		gettimeofday(&sec_tp2, &sec_tzp2);
		hash_usec = (hash_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + 	hash_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
		hash_sec = hash_usec/1000000;
		hash_usec = hash_usec % 1000000;
	}

	if(sec_verbose) {
		fprintf(stderr, "Input to sec_verify:\n");
		aux_fprint_OctetString(stderr, in_octets);
		fprintf(stderr, "Hash value of input to sec_verify:\n");
		aux_fprint_OctetString(stderr, hash_result);
	}

	if (more == END) {

		if (rc == 0) {
			switch (algenc) {
			case RSA:
				if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);
				if(algspecial == PKCS_BT_01 || algspecial == PKCS_BT_TD) {

					/*  Here goes PKCS#1 ...   */

					encodedDigest = aux_create_PKCS_MIC_D(hash_result, signature->signAI);
					rsa_input = aux_create_PKCSBlock(1, encodedDigest);
					if(algspecial == PKCS_BT_TD) {
						o1 = (OctetString *)malloc(sizeof(OctetString));
						o1->noctets = 0;
						o1->octets = malloc(256);
						rc = rsa_get_key(&got_key.subjectkey, 1);
						if (rc < 0) aux_add_error(EINVALID, "rsa_get_key failed", CNULL, 0, proc);
						rsa_encblock2OctetString(&(signature->signature), o1);
						for(i = 1; i < 20; i++) {
							if((unsigned char)o1->octets[i] == 255) {
								o1->octets[i] = '\0';
								sec_SignatureTimeDate = (UTCTime *)aux_cpy_String(&(o1->octets[1]));
								break;
							}
							rsa_input->octets[i] = o1->octets[i];
						}
						rsa_input->octets[0] = PKCS_BT_TD;
						aux_free_OctetString(&o1);
					}
					aux_free_OctetString(&hash_result);		
					if(encodedDigest) aux_free_OctetString(&encodedDigest);
          			}
				else rsa_input = hash_result;

				if(sec_verbose) {
					fprintf(stderr, "RSA block generated from hash-value:\n");
					aux_fprint_OctetString(stderr, rsa_input);
					fprintf(stderr, "Signature value (input to sec_verify):\n");
					aux_fprint_BitString(stderr, &(signature->signature));
					fprintf(stderr, "Public Key for RSA encryption of the signature:\n");
					print_keyinfo_flag |= (PK | KEYBITS);
					aux_fprint_KeyInfo(stderr, &got_key);
					fprintf(stderr, "RSA-encrypted signature (must be equal to the RSA block above):\n");
				}

				rc = rsa_get_key(&got_key.subjectkey, 1);
				if (rc < 0) aux_add_error(EINVALID, "rsa_get_key failed", CNULL, 0, proc);
				else if(!rsa_input) aux_add_error(EINVALID, "aux_create_PKCSBlock failed", CNULL, 0, proc);  
				else {
					rc = rsa_verify(rsa_input, &(signature->signature));
					if (rc < 0) aux_add_error(EVERIFICATION, "verification failed", CNULL, 0, proc);
				}
				if(sec_time) {
					gettimeofday(&sec_tp2, &sec_tzp2);
					rsa_usec = (rsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + rsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
					rsa_sec = rsa_usec/1000000;
					rsa_usec = rsa_usec % 1000000;
				}

				break;
			case DSA:
				if(sec_time) gettimeofday(&sec_tp1, &sec_tzp1);

				if(sec_verbose) {
					fprintf(stderr, "DSA input block:\n");
					aux_fprint_OctetString(stderr, hash_result);
					fprintf(stderr, "Signature value:\n");
					aux_fprint_BitString(stderr, &(signature->signature));
				}

				rc = dsa_get_key(&got_key.subjectkey, public_modulus_length);
				if (rc < 0) aux_add_error(EINVALID, "dsa_get_key failed", CNULL, 0, proc);
				else {
					rc = dsa_verify(hash_result, &(signature->signature));
					if (rc < 0) aux_add_error(EVERIFICATION, "verification failed", CNULL, 0, proc);
				}
				if(sec_time) {
					gettimeofday(&sec_tp2, &sec_tzp2);
					dsa_usec = (dsa_sec + (sec_tp2.tv_sec - sec_tp1.tv_sec)) * 1000000 + dsa_usec + (sec_tp2.tv_usec - sec_tp1.tv_usec);
					dsa_sec = dsa_usec/1000000;
					dsa_usec = dsa_usec % 1000000;
				}

				break;
			default: 
			        aux_add_error(EINVALID, "AlgEnc of algorithm wrong", CNULL, 0, proc);
				rc = -1;
				break;	
			}
		}
		else aux_add_error(EHASH, "hash failed", CNULL, 0, proc);

		if(algenc == RSA) aux_free_OctetString(&rsa_input);
		aux_free2_KeyInfo(&got_key);
		algenc = NOENC;
		alghash = NOHASH;
		sec_state = F_null;
	}
	return (rc);
}


/****************************************************************************************
 *                                     sec_checkSK                                      *
 *	sec_checkSK does an encryption and decryption on a random data block		*
 *	and returns 0 for success, if the process was the identity; -1 otherwise	*
 ***************************************************************************************/

RC
sec_checkSK(sk, pkinfo)
	Key            *sk;
	KeyInfo        *pkinfo;
{
	OctetString    *rand_octs;
	BitString       enc_bits;
	OctetString     dec_octs;
	Key             pk;
	int             rc;

	char           *proc = "sec_checkSK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!sk || !pkinfo)
		goto checkerr;
	if (aux_ObjId2AlgEnc(pkinfo->subjectAI->objid) != RSA) {
		aux_add_error(EALGID, "invalid alg_id", pkinfo->subjectAI, AlgId_n, proc);
		return -1;
	}
	/* get some random data of minimum keysize */
	rand_octs = sec_random_ostr(sizeof(int));
	if (!rand_octs) {
		aux_add_error(EINVALID, "can`t generate random string", CNULL, 0, proc);
		return -1;
	}
	pk.key = pkinfo;
	pk.keyref = 0;
	pk.pse_sel = (PSESel * ) 0;
	pk.alg = (AlgId *)0;
	enc_bits.nbits = 0;
	enc_bits.bits = (char *) malloc(512);
	if (!enc_bits.bits) {
		aux_add_error(EMALLOC, "enc_bits.bits", CNULL, 0, proc);
		return -1;
	}
	if (sec_encrypt(rand_octs, &enc_bits, END, &pk) < 0) {
		free(enc_bits.bits);
		aux_add_error(EINVALID, "can`t encrypt", CNULL, 0, proc);
		return -1;
	}
	dec_octs.noctets = 0;
	dec_octs.octets = (char *) malloc(512);
	if (!dec_octs.octets) {
		free(enc_bits.bits);
		aux_add_error(EMALLOC, "dec_octs.octets", CNULL, 0, proc);
		return -1;
	}
	if (sec_decrypt(&enc_bits, &dec_octs, END, sk) < 0) {
		aux_add_error(EINVALID, "can`t decrypt", CNULL, 0, proc);
		free(dec_octs.octets);
		free(enc_bits.bits);
		return -1;
	}
	rc = bcmp(rand_octs->octets, dec_octs.octets, rand_octs->noctets);
	free(dec_octs.octets);
	free(enc_bits.bits);
	return (rc);

checkerr:
	aux_add_error(EINVALID, "SK or PKInfo is zero", CNULL, 0, proc);
	return -1;
}



#ifdef SCA
/***************************************************************************************
 *                                sec_unblock_SCpin                                    *
 ***************************************************************************************/

RC
sec_unblock_SCpin(pse_sel)
	PSESel         *pse_sel;
{
	char           *proc = "sec_unblock_SCpin";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

#ifdef SECSCTEST
		fprintf(stderr, "Call of secsc_unblock_SCpin \n");
#endif
		if (secsc_unblock_SCpin(pse_sel)) {
			aux_add_error(ESCPUK, "Can't unblock PIN on SC", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		return (0);	/* unblocking PIN on SC was successful */

	}
	 /* if (SC available && app = SC-app) */ 
	else {
		aux_add_error(ESCPUK, "Can't select application on SC", CNULL, 0, proc);
		return (-1);
	}

}				/* sec_unblock_SCpin */

#endif				/* SCA */



/***************************************************************************************
 *                                     sec_write                                       *
 ***************************************************************************************/

RC
sec_write(pse_sel, content)
	PSESel         *pse_sel;
	OctetString    *content;
{
	int             fd, len, free_name, ret;
	char           *object;
	struct PSE_Objects *nxt;

	char           *proc = "sec_write";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
	if (!pse_sel->object.name || !strlen(pse_sel->object.name)) {
		aux_add_error(EINVALID, "Obj name missing", CNULL, 0, proc);
		return (-1);
	}
	if (!content) {
		aux_add_error(EINVALID, "content is NULL", CNULL, 0, proc);
		return (-1);
	}
#ifdef SCA
/************************  S C  -  P A R T  *******************************************/

	/*
	 * Check whether SC available and application = SC-application.
	 */

	if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
		return (-1);
	}
	if (SCapp_available == TRUE) {

		/*
		 * SC available and application = SC application.
		 */

		/* If SC application not open => open it */
		if (open_app_on_SC(pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
			return (-1);
		}

		if (pse_sel->object.name && strlen(pse_sel->object.name)) {

			/*
			 * If object = SC object    => write into WEF on SC
			 */


			if (aux_AppObjName2SCObj(pse_sel->app_name, pse_sel->object.name)) {
				/* write into object on SC */
#ifdef SECSCTEST
				fprintf(stderr, "Call of secsc_write (obj)\n");
#endif
				if (secsc_write(pse_sel, content)) {
					aux_add_error(ESCWRITE, "Can't write to SC object", pse_sel->object.name, char_n, proc);
					return (-1);
				}
				update_SCToc(pse_sel, content->noctets, 0);	/* update modification
										 * time in SC toc */

				return (0);	/* write into SC-object
						 * successful */
			} 
		}

		/* 
		 *
		 *  An object on the SW-PSE shall be written!
		 *
		 *  => Get the PIN for the SW-PSE from the SC.
		 */
		
		strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
		if(!pse_sel->pin) {
			aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
			return (-1);
		}
		if(pse_sel->object.name && strlen(pse_sel->object.name)) {
			strrep(&(pse_sel->object.pin), pse_sel->pin);
		}

	}			/* if (SC available && app = SC-app) */
	/**************************************************************************************/

	/*
	 * The following is only performed, 
	 * if the object to be written is an object on the SW-PSE.
	 * 
	 * --------------------------------------------------------------
	 * If the SC is available and an application on the SC could be 
	 * opened, the PIN read from the SC is used as PIN for the SW-PSE 
	 * application/object.
	 */
#endif				/* SCA */



	if ((fd = open_object(pse_sel, O_WRONLY | O_TRUNC)) < 0) {
		aux_add_error(LASTERROR, "open object", pse_sel, PSESel_n, proc);
		return (-1);
	}
	/* update time stamp in toc which we have from open_object() */

	nxt = psetoc->obj;
	while (nxt) {
		if (strcmp(nxt->name, pse_sel->object.name) == 0) {

			/* yes */

			if (nxt->update)
				free(nxt->update);
			nxt->update = aux_current_UTCTime();
			nxt->noOctets = content->noctets;
			nxt->status = 0;

			/* Write toc */

			ret = write_toc(pse_sel, psetoc, O_WRONLY | O_TRUNC);
			if (ret < 0) {
				aux_add_error(ESYSTEM, "write toc", pse_sel, PSESel_n, proc);
				return (-1);
			}
			break;
		}
		nxt = nxt->next;
	}

	/* write object */


	if (!(object = (char *) malloc(content->noctets))) {
		aux_add_error(EMALLOC, "object", CNULL, 0, proc);
		close_enc(fd);
		return (-1);
	}
	bcopy(content->octets, object, content->noctets);
	if (write_enc(fd, object, content->noctets, pse_sel->object.pin) < 0) {
		sprintf(text, "can't write %s", pse_sel->object.name);
		aux_add_error(ESYSTEM, "can't write object", pse_sel->object.name, char_n, proc);
		close_enc(fd);
		free(object);
		return (-1);
	}
	close_enc(fd);
	free(object);
	return (0);
}


/***************************************************************************************
 *                                     sec_write_PSE                                   *
 ***************************************************************************************/

RC 
sec_write_PSE(pse_sel, type, value)
	PSESel         *pse_sel;
	ObjId          *type;
	OctetString    *value;
{
	OctetString    *content;
	ObjId          *af_get_objoid();

	char           *proc = "sec_write_PSE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!type)
		type = af_get_objoid(pse_sel->object.name);
	if ((content = e_PSEObject(type, value)) == (OctetString *) 0) {
		aux_add_error(EINVALID, "encoding of PSEObject", CNULL, 0, proc);
		return (-1);
	}
	if (sec_write(pse_sel, content) < 0) {
		return (-1);
	}
	return (0);
}



/***************************************************************************************
 *                                     sec_pin_check                                   *
 ***************************************************************************************/

Boolean
sec_pin_check(pse_sel, obj, pin)
	PSESel         *pse_sel;
	char           *obj, *pin;
{
	char           *proc = "sec_pin_check";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif


	if (!pse_sel || !pin) return(FALSE);

	if (!pin_check(pse_sel, obj, pin, TRUE, FALSE)) return(FALSE);

	return(TRUE);
}










/* ************************ local functions: ********************************* */

/***************************** chk_parm *****************************************/

static
int 
chk_parm(pse_sel)
	PSESel         *pse_sel;
{
	char           *proc = "chk_parm";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!pse_sel) {
		aux_add_error(EINVALID, "pse_sel is NULL", CNULL, 0, proc);
		return (-1);
	}
	if (!pse_sel->app_name || !strlen(pse_sel->app_name)) {
		aux_add_error(EINVALID, "application name missing", pse_sel, PSESel_n, proc);
		return (-1);
	}
	return (0);
}


/******************************** fsize *****************************************
 *
 *      fsize(fd) returns the size of the file fd points to.
 *
 *******************************************************************************/

static
off_t 
fsize(fd)
	int             fd;
{
	struct stat     stat;
	char           *proc = "fsize";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (fstat(fd, &stat) == 0)
		return (stat.st_size);

	aux_add_error(ESYSTEM, "fstat failed", CNULL, 0, proc);
	return (-1);
}


/********************* get_encodedkeyinfo_from_keyref ***************************
 *
 *  given: keyref
 *  Return Value: OctetString with encoded keyinfo
 *
 *******************************************************************************/

static
OctetString    *
get_encodedkeyinfo_from_keyref(keyref)
	KeyRef          keyref;
{
	static OctetString encoded_key;
	PSESel         *pse_sel;
	char           *proc = "sec_get_encodedkeyinfo_from_keyref";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (keyref <= 0) {
		aux_add_error(EINVALID, "invalid keyref ", CNULL, 0, proc);
		return ((OctetString *) 0);
	}
	if (!(pse_sel = set_key_pool(keyref))) {
		aux_add_error(EINVALID, "set_key_pool failed", CNULL, 0, proc);
		return ((OctetString *) 0);
	}
	if (sec_read(pse_sel, &encoded_key) < 0) {	/* read object */
		aux_add_error(EOBJ, "can't read object", pse_sel, PSESel_n, proc);
		if (pse_sel->pin) strzero(pse_sel->pin);
		return ((OctetString *) 0);
	}
	if (pse_sel->pin) strzero(pse_sel->pin);
	return (&encoded_key);
}


/****************************** get_keyinfo_from_key ****************************
 *
 *      get_keyinfo_from_key(key) returns a KeyInfo from Key
 *
 *******************************************************************************/

KeyInfo        *
get_keyinfo_from_key(key)
	Key            *key;
{
	OctetString     encoded_key;
	KeyInfo        *keyinfo;
	char           *proc = "get_keyinfo_from_key";

	if (!key) {
		aux_add_error(EINVALID, "key missing in get_keyinfo_from_key", CNULL, 0, proc);
		return ((KeyInfo *) 0);
	}
	keyinfo = (KeyInfo *) 0;

	if (key->keyref == 0 && !key->pse_sel)
		keyinfo = aux_cpy_KeyInfo(key->key);
	else {
		if (key->keyref == 0 && key->pse_sel) {
			if (sec_read_PSE(key->pse_sel, &dummy_oid, &encoded_key) >= 0) {
				keyinfo = d_KeyInfo(&encoded_key);
				free(encoded_key.octets);
			}
		} else {
			if (key->keyref > 0)
				keyinfo = get_keyinfo_from_keyref(key->keyref);
		}
	}

	return (keyinfo);
}


/***************************** get2_keyinfo_from_key ****************************
 *
 *    given:  key (and struct of keyinfo)
 *    return: keyinfo
 *    RC:     0 or -1
 *
 *******************************************************************************/

get2_keyinfo_from_key(keyinfo, key)
/*
 *    given:  key (and struct of keyinfo)
 *    return: keyinfo
 *    RC:     0 or -1
*/
	KeyInfo        *keyinfo;
	Key            *key;
{
	OctetString     pse_content;
	char           *proc = "get2_keyinfo_from_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!key || !keyinfo) {
		aux_add_error(EINVALID, "key missing in get2_keyinfo_from_key", CNULL, 0, proc);
		return (-1);
	}
	if (key->keyref == 0) {
		if (key->pse_sel == (PSESel *) 0) {
			if (key->key == (KeyInfo *) 0) {
				aux_add_error(EINVALID, "invalid keyinfo ", CNULL, 0, proc);
				return (-1);
			}
			/* key is in key->key: */
			if (aux_cpy2_KeyInfo(keyinfo, key->key) < 0) {
				aux_add_error(EINVALID, "...cpy2 failed", key->key, KeyInfo_n, proc);
				return (-1);
			}
		} else {	/* key is in PSE-Object: */

			/*
			 * sec_read does sec_open in case of PSE if (
			 * sec_open (key->pse_sel) < 0 ) {
			 * aux_add_error(EINVALID,"can't open
			 * object",key->pse_sel,PSESel_n,proc); return (-1) ;
			 * }
			 */
			if (sec_read_PSE(key->pse_sel, &dummy_oid, &pse_content) < 0) {
				aux_add_error(EINVALID, "can't read object", key->pse_sel, PSESel_n, proc);
				return (-1);
			}

			/*
			 * if ( sec_close (key->pse_sel) < 0 ) { free
			 * (pse_content.octets) ;
			 * aux_add_error(EINVALID,"can't close
			 * object",key->pse_sel,PSESel_n,proc); return (-1) ;
			 * }
			 */
			if (d2_KeyInfo(&pse_content, keyinfo) < 0) {
				aux_add_error(EDECODE, "d2_KeyInfo failed", CNULL, 0, proc);	/* in fact: object is
												 * broken */
				free(pse_content.octets);
				return (-1);
			}
			free(pse_content.octets);
		}
	} else {		/* key is referenced: */
		if (get2_keyinfo_from_keyref(keyinfo, key->keyref) < 0) {
			aux_add_error(EINVALID, "can't get KeyInfo", CNULL, 0, proc);
			return (-1);
		}
	}
	return (0);
}


/***************************** get_keyinfo_from_keyref *************************
 *
 *    given:  keyref
 *    Return Value: keyinfo or NULL
 *
 *******************************************************************************/

KeyInfo        *
get_keyinfo_from_keyref(keyref)
	KeyRef          keyref;
{
	OctetString    *encoded_key;
	KeyInfo        *keyinfo;
	char           *proc = "get_keyinfo_from_keyref";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!(encoded_key = get_encodedkeyinfo_from_keyref(keyref)))
		return ((KeyInfo *) 0);

	if (!(keyinfo = d_KeyInfo(encoded_key))) {
		aux_add_error(EDECODE, "d_KeyInfo failed", CNULL, 0, proc);
	}
	free(encoded_key->octets);

	return (keyinfo);
}


/***************************** get2_keyinfo_from_keyref *************************
 *
 *    given:  keyref
 *    return: keyinfo
 *    RC:     0 or -1
 *
 *******************************************************************************/

static
int 
get2_keyinfo_from_keyref(keyinfo, keyref)
	KeyInfo        *keyinfo;
	KeyRef          keyref;
{
	OctetString    *encoded_key;
	char           *proc = "get2_keyinfo_from_keyref";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!(encoded_key = get_encodedkeyinfo_from_keyref(keyref)))
		return (-1);

	if (d2_KeyInfo(encoded_key, keyinfo) < 0) {	/* decode into keyinfo */
		aux_add_error(EDECODE, "d_KeyInfo failed", CNULL, 0, proc);
		free(encoded_key->octets);
		return (-1);
	}
	free(encoded_key->octets);
	return (0);
}


/***************************** get_unixname *************************************
 *
 *      get_unixname returns a pointer to a static char * containing
 *      the UNIX username generated from environment variable USER
 *
 *******************************************************************************/
#if defined(MS_DOS)
 char           *get_unixname()
{
	return ("\0");
}
#elif defined(MAC)
 char	          *get_unixname()
{
   static char unixname[128];

   unixname[8] = '\0';
   return(strncpy(unixname, getlogin(), 8));
    
   /* ist getlogin() kuerzer als 8 Zeichen, haengt '\0' schon dran,
      andernfalls von Hand anhaengen. */
}
    
#else  /* UN*X */

char           *
get_unixname()
{

	return ((char *)getlogin());
}

#endif

/***************************** is_key_pool *************************************
 *
 *      is_key_pool returns TRUE if the given address is the address of the
 *      static variable sec_key_pool
 *
 *******************************************************************************/

Boolean is_key_pool(psesel)
PSESel *psesel;
{
	if(psesel == &sec_key_pool) return(TRUE);
	else return(FALSE);
}


/***************************** object_reencrypt *********************************
 *
 *      object_reencrypt reencrypts object with newpin
 *
 *******************************************************************************/

static
int 
object_reencrypt(pse_sel, newpin, psepin)
	PSESel         *pse_sel;
	char           *newpin;
	Boolean         psepin;
{
	OctetString     ostr;
	int             fd, free_name;
	char           *object, *o_pin, *zwpin;
	unsigned int    size;

	char           *proc = "object_reencrypt";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if ((fd = open_object(pse_sel, O_RDWR)) < 0) {
		aux_add_error(LASTERROR, "open object", pse_sel, PSESel_n, proc);
		return (-1);
	}
	o_pin = pse_sel->object.pin;
	if (!o_pin) o_pin = "";

	if (strlen(o_pin)) {
		if (!strcmp(o_pin, newpin)) {
			close(fd);
			return (0);
		}
	}

	if (read_object(pse_sel, fd, &ostr) < 0) {
		aux_add_error(ESYSTEM, "read object", pse_sel, PSESel_n, proc);
		close(fd);
		return (-1);
	}
	if (!(object = pse_name(pse_sel->app_name, pse_sel->object.name, &free_name))) {
		aux_add_error(EOBJ, " get object-name(2)", pse_sel->object.name, char_n, proc);
		return (-1);
	}
	unlink(object);
	strcat(object, ".pw");
	unlink(object);
	object[strlen(object) - 3] = '\0';
	strcat(object, ".sf");
	unlink(object);
	object[strlen(object) - 3] = '\0';

	if (!psepin && strlen(newpin)) {
		if (!pin_check(pse_sel, "pse", newpin, FALSE, TRUE)) {
			strcat(object, ".pw");
#ifndef MAC
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
			if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */

				aux_add_error(ESYSTEM, "create object", object, char_n, proc);
				if (free_name) free(object);
				return (-1);
			}
			chmod(object, OBJMASK);
			strcpy(text, newpin);	/* save pin because write_enc
						 * encrypts inline */
			if (write_enc(fd, text, strlen(newpin), newpin) < 0) {
				aux_add_error(ESYSTEM, "create object", object, char_n, proc);
				if (free_name) free(object);
				close_enc(fd);
				return (-1);
			}
			close_enc(fd);
			object[strlen(object) - 3] = '\0';
		}
	}
	if (strlen(newpin)) strcat(object, ".sf");

	/* Create object */

#ifndef MAC
	if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL, OBJMASK)) < 0) {
#else
	if ((fd = open(object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
#endif /* MAC */
		aux_add_error(ESYSTEM, "create object", object, char_n, proc);
		if (free_name) free(object);
		return (-1);
	}
	chmod(object, OBJMASK);
	if (free_name) free(object);

	/* write reencrypted content */

	if (!(object = (char *) malloc(ostr.noctets))) {
		aux_add_error(EMALLOC, "object ", CNULL, 0, proc);
		close_enc(fd);
		return (-1);
	}
	bcopy(ostr.octets, object, ostr.noctets);
	if (write_enc(fd, object, ostr.noctets, newpin) < 0) {
		aux_add_error(ESYSTEM, "write object", object, char_n, proc);
		close_enc(fd);
		free(ostr.octets);
		free(object);
		return (-1);
	}
	free(object);
	close_enc(fd);
	free(ostr.octets);
	return (0);
}


/*********************************** open_object ****************************************
 *
 *      open_object returns an open filedescriptor or zero. In addition, it leaves
 *      the toc in psetoc, if it was called with flag != O_RDONLY and RC is not -1.
 *
 ***************************************************************************************/


static          RC
open_object(pse_sel, flag)
	PSESel         *pse_sel;
	int             flag;
{
	char           *object;
	int             fd_sf, fd_pw, free_name;
	struct PSE_Objects *nxt;

	char           *proc = "open_object";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (chk_parm(pse_sel)) {
		aux_add_error(EOBJ, "check pse_sel", pse_sel, PSESel_n, proc);
		return (-1);
	}
	/* Read toc */

	if (!(psetoc = chk_toc(pse_sel, FALSE))) {
		aux_add_error(LASTERROR, "check pse_toc", pse_sel, PSESel_n, proc);
		return (-1);
	}
	fd_sf = -2;
	if (pse_sel->object.name) {

		/*
		 * Open an object of a PSE
		 */

		/* Check whether pse_sel->object.name exists */

		nxt = psetoc->obj;
		while (nxt) {
			if (strcmp(nxt->name, pse_sel->object.name) == 0) {
				/* yes */

				goto found;
			}
			nxt = nxt->next;
		}
		aux_add_error(EOBJNAME, "object is not in toc", pse_sel->object.name, char_n, proc);
		return (-1);
found:

		if (!(object = pse_name(pse_sel->app_name, pse_sel->object.name, &free_name))) {
			aux_add_error(EOBJ, " get object-name", pse_sel->object.name, char_n, proc);
			return (-1);
		}
		strcat(object, ".sf");
		pse_pw = TRUE;
		if ((fd_sf = open(object, flag)) < 0) {
			object[strlen(object) - 3] = '\0';
			pse_pw = FALSE;
			if ((fd_sf = open(object, flag)) < 0) {
				aux_add_error(EDAMAGE, "object is in toc, but can't open", pse_sel->object.name, char_n, proc);
				if (free_name) free(object);
				return (-1);
			}
		}
		if (pse_pw) {

			/*
			 * Check object PIN
			 */

#ifdef SCA
			if ((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
				aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
				return (-1);
			}
			if (SCapp_available == TRUE) {

				/* open object of SC application on SW-PSE */

				/*
				 * Get the PIN for the SW-PSE from the SC.
				 */

				strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
				if(!pse_sel->pin) {
					aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
					return (-1);
				}
				if(pse_sel->object.name && strlen(pse_sel->object.name)) {
					strrep(&(pse_sel->object.pin), pse_sel->pin);
				}
			}
#endif


			object[strlen(object) - 3] = '\0';
			strcat(object, ".pw");
			if ((fd_pw = open(object, O_RDONLY)) < 0) {

				/* object needs PSE PIN */
				if(pse_sel->object.pin) pse_sel->object.pin = pin_check(pse_sel, pse_sel->object.name, pse_sel->object.pin, TRUE, TRUE);
				else pse_sel->object.pin = aux_cpy_String(pin_check(pse_sel, pse_sel->object.name, pse_sel->pin, TRUE, TRUE));

			}
			else {
				/* object needs object PIN */

				pse_sel->object.pin = pin_check(pse_sel, pse_sel->object.name, pse_sel->object.pin, TRUE, TRUE);
				close(fd_pw);
			}
			if (!pse_sel->object.pin) {
				aux_add_error(EPIN, "pin_check failed", pse_sel, PSESel_n, proc);
				if (free_name) free(object);
				close(fd_sf);
				return (-1);
			}
		}
/*		else pse_sel->object.pin = CNULL; */

		if (free_name)	free(object);

		/*
		 * free toc if open for reading, else toc will be free'd by
		 * the calling program
		 */

	}
	return (fd_sf);
}


/******************************* pin_check **************************************
 *
 *      pin_check(app, obj, pin, err_ind) checks whether pin is the PIN of the 
 *      given (app, obj), using the following strategy:
 *      
 *      It asks for the PIN if it is not present and returns pin
 *      to the PIN entered by the user. If obj == "pse", the PIN of the
 *      PSE is checked. If err_ind == FALSE, no aux_add_error( ) is called
 *      after PIN check failed.
 *
 *******************************************************************************/

static
char           *
pin_check(pse_sel, obj, pin, err_ind, interactive)
	PSESel         *pse_sel;
	char           *obj, *pin;
	int             err_ind;
	Boolean interactive;
{
	char           *object, decrypted_pin[64];
	int             fd, len, fbz, free_name, free_pin, free_object;
	char 	       *objpin;
	char           *proc = "pin_check";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

/*  
   fbz: maximum number of retries if the PIN is entered from /dev/tty (only if parameter pin is NULL)
*/
	if (pin && strlen(pin)) fbz = 0;
	else fbz = 2;

	if (!(object = pse_name(pse_sel->app_name, obj, &free_object))) {
		aux_add_error(EOBJ, " get object-name(1)", obj, char_n, proc);
		return (CNULL);
	}
	strcat(object, ".pw");
	if ((fd = open(object, O_RDONLY)) < 0) {

		if (free_object) free(object);
		if (errno == ENOENT && strcmp(obj, "pse")) {

			/* obj uses PSE pin instead of own PIN */

			if (!(object = pse_name(pse_sel->app_name, "pse.pw", &free_object))) {
				aux_add_error(EOBJ, " get object-name(1)", "pse.pw", char_n, proc);
				return (CNULL);
			}
			if ((fd = open(object, O_RDONLY)) >= 0) goto opened;
			if (free_object) free(object);
		}
		if (errno == ENOENT) return (CNULL);
		if (err_ind) aux_add_error(ESYSTEM, "can't open object", object, char_n, proc);
		return (CNULL);
	}
opened:
	free_pin = FALSE;

try_again:

	if ((!pin || !strlen(pin)) && interactive == FALSE) {
		aux_add_error(EPIN, "no pin", CNULL, 0, proc);
		if (free_object) free(object);
		return(CNULL);
	}

	if (!pin || !strlen(pin)) {

		if (strcmp(obj, "pse") == 0) pin = sec_read_pin("PIN for", pse_sel->app_name, FALSE);
		else pin = sec_read_pin("PIN for", obj, FALSE);
		if (!pin) {
			if (free_object) free(object);
			aux_add_error(EPIN, "read pin", CNULL, 0, proc);
			return (CNULL);
		}
		free_pin = TRUE;
	}
	if ((len = read_dec(fd, decrypted_pin, sizeof(decrypted_pin), pin)) < 0) {
		close_dec(fd);
		goto failed;
	}
	close_dec(fd);
	decrypted_pin[len] = '\0';
	if (strcmp(decrypted_pin, pin) == 0) {

		/*
		 * PIN o.k.
		 */

		strzero(decrypted_pin);
		if (free_object) free(object);
		return(pin);
	}
failed:

	if (free_pin) free(pin);
	if (fbz--) {
		fd = open(object, O_RDONLY);
		pin = CNULL;
		goto try_again;
	}
	if (err_ind) aux_add_error(EPIN, "PIN check failed", CNULL, 0, proc);
	if (free_object) free(object);
	return (CNULL);
}


/********************** put_keyinfo_according_to_key ****************************
 *
 *      put_keyinfo_according_to_key(keyinfo, key) puts keyinfo either to
 *      key->key, or stores it on the PSE or as keyref according to key->keyref
 *      and key->pse_sel;
 *
 *******************************************************************************/

static
                RC
put_keyinfo_according_to_key(keyinfo, key, objid)
	KeyInfo        *keyinfo;
	Key            *key;
	ObjId          *objid;
{
	int             rcode;
	OctetString    *encoded_key;
	char           *proc = "put_keyinfo_according_to_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (!key || !keyinfo) {
		aux_add_error(EINVALID, "key missing", CNULL, 0, proc);
		return (-1);
	}
	if (key->keyref == 0 && !key->pse_sel) {

		/*
		 * Return key in key
		 */

		key->key = aux_cpy_KeyInfo(keyinfo);
		return (0);
	}
	if (key->keyref == 0 && key->pse_sel) {

		/*
		 * Write key to PSE-object
		 */

		if ((encoded_key = e_KeyInfo(keyinfo))) {
			rcode = sec_write_PSE(key->pse_sel, objid, encoded_key);
			if (rcode)
				aux_add_error(EINVALID, "write key to object", key->pse_sel, PSESel_n, proc);
			free(encoded_key->octets);
			return (rcode);
		} else {
			aux_add_error(EENCODE, "e_KeyInfo failed", CNULL, 0, proc);
			return (-1);
		}
	}
	if (key->keyref > 0 || key->keyref == -1) {

		/*
		 * Install key as key reference
		 */

		rcode = sec_put_key(keyinfo, key->keyref);
		if(rcode < 0)
			aux_add_error(EINVALID, "can't put key", CNULL, 0, proc);
		if(rcode > 0)
			key->keyref = rcode;
		return (rcode);
	}
	return(0);
}


/***************************** sec_read_pin ****************************************
 *
 *      sec_read_pin(text, object, reenter) reads PIN for object from /dev/tty without
 *      echo and returns a pointer which can be freed afterwards with free().
 *      It prompts text, object and ": " to stderr. If reenter == TRUE, it asks
 *      to reenter the PIN.
 *
 *******************************************************************************/

char           *
sec_read_pin(text, object, reenter)
	char           *text, *object;
	int             reenter;
{
	char           *dd, *buf, prompt[64];
	char           *getpass();
	char           *proc = "sec_read_pin";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	buf = (char *) malloc(16);
	if (!buf) {
		aux_add_error(EMALLOC, "buf", CNULL, 0, proc);
		return (CNULL);
	}
enter:
	strcpy(prompt, "  Enter ");
	if (text && strlen(text))
		strcat(prompt, text);
	if (object && strlen(object)) {
		strcat(prompt, " ");
		strcat(prompt, object);
	}
	if (strlen(prompt))
		strcat(prompt, ": ");

	if (!(dd = getpass(&prompt[2]))) {
		aux_add_error(ESYSTEM, "get password", CNULL, 0, proc);
		return (CNULL);
	}
	strcpy(buf, dd);
	if (reenter) {
		strcpy(prompt, "Re");
		prompt[2] = 'e';
		if (!(dd = getpass(prompt))) {
			aux_add_error(ESYSTEM, "get password", CNULL, 0, proc);
			return (CNULL);
		}
		if (strcmp(buf, dd))
			goto enter;
	}
	return (buf);
}


/****************************** read_object ************************************
 *
 *      read_object(pse_sel, fd, content) reads the the previously with open_object
 *      opened object from filedescriptor fd into OctetString content.
 *      It mallocs content->octets and closes fd.
 *
 *******************************************************************************/

static
                RC
read_object(pse_sel, fd, content)
	PSESel         *pse_sel;
	int             fd;
	OctetString    *content;
{
	int    		size;
	int             len;

	char           *proc = "read_object";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if ((size = fsize(fd)) < 0) {
		aux_add_error(ESYSTEM, "fsize failed ", CNULL, 0, proc);
		close(fd);
		return (-1);
	}
	content->octets = (char *) malloc(size);
	if (!content->octets) {
		aux_add_error(EMALLOC, "content->octets ", CNULL, 0, proc);
		close(fd);
		return (-1);
	}
	if ((len = read_dec(fd, content->octets, (unsigned int)  size, pse_sel->object.pin)) < 0) {
		sprintf(text, "can't read %s", pse_sel->object.name);
		aux_add_error(ESYSTEM, "can't read object", pse_sel->object.name, char_n, proc);
		close_dec(fd);
		free(content->octets);
		return (-1);
	}
	close_dec(fd);
	content->noctets = len;
	return (0);
}


/****************************** read_toc ****************************************
 *
 *      read_toc(pse_sel) reads the toc of the PSE specified by pse_sel
 *      and returns a pointer to PSEToc. It does all necessary PIN checking
 *      and questionning. After successful read_toc, pse_sel->pin contains
 *      the checked PIN of the PSE.
 *
 *******************************************************************************/

static
PSEToc         *
read_toc(pse_sel)
	PSESel         *pse_sel;
{
	int             fdtoc, len, free_name;
	int    		tocsize;
	OctetString     encoded_toc;
	char           *toc_name, *tmppin;

	char           *proc = "read_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (psetoc) return (psetoc);

	if (!(toc_name = pse_name(pse_sel->app_name, "Toc.sf", &free_name))) {
		aux_add_error(EOBJ, " get object-name", "Toc.sf", char_n, proc);
		return ( (PSEToc * ) 0);
	}
	pse_pw = TRUE;
	if ((fdtoc = open(toc_name, O_RDONLY)) < 0) {
		toc_name[strlen(toc_name) - 3] = '\0';
		pse_pw = FALSE;
		if ((fdtoc = open(toc_name, O_RDONLY)) < 0) {
			toc_name[strlen(toc_name) - 3] = '\0';
			if ((fdtoc = open(toc_name, O_RDONLY)) < 0) {
				/* can't open PSE directory */
				if (errno == ENOENT) {
					aux_add_error(EAPPNAME, "directory doesn't exist", toc_name, char_n, proc);
				} 
				else {
					aux_add_error(EDAMAGE, "can't open directory", toc_name, char_n, proc);
				}
			} 
			else {
				/* can open PSE directory, but no toc */
				aux_add_error(EOBJ, "can't open ", toc_name, char_n, proc);
				close(fdtoc);
			}
			if (free_name) free(toc_name);
			return ((PSEToc *) 0);
		}
	}
	if (pse_pw) {

		/*
		 * Check PIN of PSE
		 */

#ifdef SCA
		if((SCapp_available = sec_sctest(pse_sel->app_name)) == -1) {
			aux_add_error(ECONFIG, "Error during SC configuration", CNULL, 0, proc);
			return ((PSEToc *) 0);
		}
		if(SCapp_available == TRUE) {
			strrep(&(pse_sel->pin), get_pse_pin_from_SC(pse_sel->app_name));
			if(!pse_sel->pin) {
				aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
				return ((PSEToc *) 0);
			}
			if(pse_sel->object.name && strlen(pse_sel->object.name)) {
				strrep(&(pse_sel->object.pin), pse_sel->pin);
			}
		}
#endif
		if(!(pse_sel->pin = pin_check(pse_sel, "pse", pse_sel->pin, TRUE, TRUE))) {
			aux_add_error(EPIN, "pin check failed", CNULL, 0, proc);
			close(fdtoc);
			if (free_name) free(toc_name);
			return ((PSEToc *) 0);
		} 
		tmppin = pse_sel->pin;
	}
	else tmppin = CNULL;

	if ((tocsize = fsize(fdtoc)) < 0) {
		aux_add_error(ESYSTEM, "fsize failed ", CNULL, 0, proc);
		return ((PSEToc *) 0);
	}

	/*
	 * Read and decrypt encoded toc
	 */

	encoded_toc.octets = (char *) malloc(tocsize);
	if (!encoded_toc.octets) {
		aux_add_error(EMALLOC, "encoded_toc.octets ", CNULL, 0, proc);
		close(fdtoc);
		if (free_name) free(toc_name);
		return ((PSEToc *) 0);
	}
	if ((len = read_dec(fdtoc, encoded_toc.octets, (unsigned int) tocsize, tmppin)) < 0) {
		sprintf(text, "can't read %s", toc_name);
		aux_add_error(ESYSTEM, "can't read toc", toc_name, char_n, proc);
		if (free_name) free(toc_name);
		close_dec(fdtoc);
		return ((PSEToc *) 0);
	}
	close_dec(fdtoc);
	encoded_toc.noctets = len;
	if (!(psetoc = d_PSEToc(&encoded_toc))) {
		aux_add_error(EDECODE, "decoding error for toc", toc_name, char_n, proc);
	}
	if (free_name) free(toc_name);
	free(encoded_toc.octets);
	return (psetoc);
}



/********************************** set_key_pool ***************************************
 *
 *      set_key_pool sets pse_sel to appropriate values to handle an object
 *      from the key_pool, and returns its address
 *
 ***************************************************************************************/

static
PSESel         *
set_key_pool(keyref)
	KeyRef          keyref;
{
	PSESel         *pse_sel;
	static char     key[4];
	KeyInfo        *keyinfo;


	char           *proc = "set_key_pool";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	pse_sel = &sec_key_pool;

	pse_sel->pin = key_pool_pw();
	if (keyref > 0) {
		sprintf(key, "%X", keyref);	/* convert number to text */
		pse_sel->object.name = key;
		pse_sel->object.pin = pse_sel->pin;
	} else if (keyref < 0)
		pse_sel->object.name = "-1";
	else
		pse_sel->object.name = CNULL;
	return (pse_sel);
}


static
char           *
key_pool_pw()
{
	static char     pin[64];

	strcpy(pin, get_unixname());
	sprintf(pin + strlen(pin), "%d", 3 * getuid() - 100);
	strcat(pin, ".&%)#(#$");
	return (pin);
}


/********************************** strzero ********************************************
 *
 *      strzero(string) overwrites string with zeroes (until the first zero)
 *
 ***************************************************************************************/

static
void 
strzero(string)
	register char  *string;
{
	while(*string) *string++ = '\0';
	return;
}


/***************************** pse_name ***************************************
 *
 *      pse_name(app, object) concatenates object to app, if app begins with /
 *      or $HOME/app otherwise, and returns a pointer to the concatenated name.
 *      In addition, it sets free_name to TRUE if this pointer can be freed
 *      by free() afterwards.
 *
 *******************************************************************************/

static
char           *
pse_name(app, object, free_name)
	char           *app, *object;
	int            *free_name;
{
	char           *homedir, *dirname;
	char           *proc = "pse_name";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	*free_name = FALSE;
	if (object == CNULL)
		object = "";

	if (*app != '/') {
#ifndef MAC
		homedir = getenv("HOME");
#else
		homedir = MacGetEnv("HOME");
#endif /* MAC */
		if (!homedir) {
			aux_add_error(ESYSTEM, "getenv failed in pse_name", CNULL, 0, proc);
			return (CNULL);
		}
	} else
		homedir = "";

	dirname = (char *) malloc(strlen(homedir) + strlen(app) + strlen(object) + 64);
	if (!dirname) {
		aux_add_error(EMALLOC, "dirname", CNULL, 0, proc);
		return (CNULL);
	}
	*free_name = TRUE;

	strcpy(dirname, homedir);
	if (strlen(homedir))
#ifndef MAC 
		if (dirname[strlen(dirname)-1] != '/') 
			strcat(dirname, "/");
#else
		if (dirname[strlen(dirname)-1] != ':') 
			strcat(dirname, ":");
#endif /* MAC */
	strcat(dirname, app);
	if (strlen(object))
#ifndef MAC 
		if (dirname[strlen(dirname)-1] != '/') 
			strcat(dirname, "/");
#else
		if (dirname[strlen(dirname)-1] != ':') 
			strcat(dirname, ":");
#endif /* MAC */
	strcat(dirname, object);
	return (dirname);
}



/******************************* write_toc ***************************************
 *
 *      write_toc(pse_sel, toc, flags) writes the toc of the PSE specified by
 *      pse_sel and toc. It opens the toc file according to flags. It returns -1
 *      in case of errors, 0 otherwise.
 *
 *******************************************************************************/

static
int 
write_toc(pse_sel, toc, flags)
	PSESel         *pse_sel;
	PSEToc         *toc;
	int             flags;
{
	OctetString    *encoded_toc;
	int             fd, free_name;
	char           *object;

	char           *proc = "write_toc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	/* Open or Create Toc.sf with (encrypted) toc */

	if (pse_sel->pin && strlen(pse_sel->pin)) {
		if (!(object = pse_name(pse_sel->app_name, "Toc.sf", &free_name))) {
			aux_add_error(EOBJ, " get object-name(1)", "Toc.sf", char_n, proc);
			return (-1);
		}
	} else {
		if (!(object = pse_name(pse_sel->app_name, "Toc", &free_name))) {
			aux_add_error(EOBJ, " get object-name(2)", "Toc", char_n, proc);
			return (-1);
		}
	}
#ifndef MAC
	if ((fd = open(object, flags, OBJMASK)) < 0) {
#else
	if ((fd = open(object, flags)) < 0) {
#endif /* MAC */
		aux_add_error(ESYSTEM, "can't open object", object, char_n, proc);
		if (free_name)
			free(object);
		return (-1);
	}
	chmod(object, OBJMASK);

	/* update time stamp */

	if (toc->update)
		free(toc->update);
	toc->update = aux_current_UTCTime();

	/* encode it */

	encoded_toc = e_PSEToc(toc);

	/* write it to PSE */

	if (write_enc(fd, encoded_toc->octets, encoded_toc->noctets, pse_sel->pin) < 0) {
		sprintf(text, "can't write %s", object);
		aux_add_error(ESYSTEM, "can't write object", object, char_n, proc);
		free(encoded_toc->octets);
		if (free_name)
			free(object);
		close_enc(fd);
		return (-1);
	}
	if (free_name)
		free(object);
	free(encoded_toc->octets);
	close_enc(fd);
	return (0);
}



PSEToc         *
chk_toc(pse_sel, create)
	PSESel         *pse_sel;
	Boolean		create;
{
	static char     last_pse_app_name[128];
	char           *proc = "chk_toc";

	if (strcmp(last_pse_app_name, pse_sel->app_name) || create == TRUE) {
		strcpy(last_pse_app_name, pse_sel->app_name);
		if (psetoc) aux_free_PSEToc(&psetoc);
		if (create == TRUE) {
			if (!(psetoc = (PSEToc *) calloc(1, sizeof(PSEToc)))) {
				aux_add_error(EMALLOC, "psetoc", CNULL, 0, proc);
				return ( (PSEToc * ) 0);
			}
		} 
		else psetoc = read_toc(pse_sel);
		return (psetoc);
	} else {
		if (!psetoc) psetoc = read_toc(pse_sel);
		return (psetoc);
	}
}


/******************************* locate_toc ***************************************
 *
 *      locate_toc(object_name) locates the object entry in psetoc. It returns the
 *	end of the object list if the object does not exist in psetoc and returns
 *	the address of the next pointer if found.
 *
 *******************************************************************************/

static
struct PSE_Objects **
locate_toc(objname)
	char           *objname;
{
	struct PSE_Objects **obj, *nxt;
	char           *proc = "locate_toc";

	if (!psetoc || !objname)
		return ( (struct PSE_Objects * * ) 0);
	obj = &psetoc->obj;
	for (nxt = *obj; nxt; obj = &nxt->next, nxt = *obj) {
		if (strcmp(nxt->name, objname))
			continue;
		else
			break;
	}

	return obj;
}

/******************************* strzfree ***************************************
 *
 *      strzfree (char **str) sets **str until the next '\0' to zero, frees *str
 *      and finally sets *str to zero. *str must be a null terminated string
 *      and must be obtained from a prior malloc(), calloc() etc.
 *      Intended use: Free memory which was used to store a PIN
 *
 *******************************************************************************/

void strzfree(str)
char **str;
{
	char *dd;

	dd = *str;
	if(!dd) return;

	while(*dd) *dd++ = '\0';
	free(*str);
	*str = 0;
	return;
}

/******************************* strrep ***************************************
 *
 *      strrep (char **str1, char *str2) frees *str1, if non-zero, and
 *      creates a newly malloc'ed copy of str2 in *str1. It returns zero
 *      on success and -1 if the malloc failed. *str1 and str2 are supposed
 *      to be null terminated strings.
 *
 *******************************************************************************/

int strrep(str1, str2)
char **str1;
char *str2;
{
	if(*str1) free(*str1);
	*str1 = aux_cpy_String(str2);
	if(*str1) return(0);
	else return(-1);
}

		

#ifdef SCA




/*--------------------------------------------------------------*/
/*						                */
/* PROC  open_app_on_SC					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  The calling routine has checked that the application is an	*/
/*  SC application.						*/
/*								*/
/*  If the application on the SC has not been opened via the    */
/*  actual SCT (sc_sel.sct_id), the specified application will  */
/*  be opened.							*/
/*								*/
/*  Observe that: 					        */
/*  If another application was open, this one will implicitly   */
/*  be closed and the new one will be opened.	                */
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   pse_sel	 	       Structure which identifies the   */
/*                             PSE object.			*/
/*								*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0		    	       o.k			       	*/
/*   -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   handle_sc_app()	       If application not open, open it.*/
/*                                                              */
/*--------------------------------------------------------------*/

static
int	open_app_on_SC(pse_sel)
	PSESel          *pse_sel;
{
	int             sct_id;

	char           *proc = "open_app_on_SC";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	sct_id = sc_sel.sct_id;

	/* If belonging application not open, open it */
	if (handle_sc_app(sct_id, pse_sel->app_name)) {
		aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
		return (-1);
	}

	return (0);

}				/* end open_app_on_SC */



/*--------------------------------------------------------------*/
/*						                */
/* PROC  handle_in_SCTSC				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Depending on the parameter "key", it is checked whether a 	*/
/*  SECSC-function is to be called to perform the crypto-	*/
/*  function (e.g. sign) within the SCT/SC.		        */
/*  If a crypto function in the SCT/SC shall be performed, it   */
/*  is automatically checked whether the SCT/SC is available.	*/
/*								*/
/*								*/
/*  Object-name:						*/
/*  If the key is selected with "key->pse_sel" and the application */
/*  is an application on the SC, the SC-application is opened.	*/
/*								*/
/*  If the key is selected with an object name and this object  */
/*  addresses a key on the SW-PSE, the PIN for the SW-PSE is 	*/
/*  read from the SC and stored in "key->pse_sel->pin".		*/
/*								*/
/*  Keyref:							*/
/*  If the key is selected with "key->keyref", it is checked    */
/*  whether the key is stored in SCT/SC or in the SW-PSE.	*/
/*								*/
/*  Delivered key:						*/
/*  If the key is delivered in "key->key", SC_crypt == TRUE,    */
/*  it is checked whether SCT/SC available. 			*/
/*  If SCT/SC is not available, an error code will be returned, */
/*  otherwise TRUE will be returned.				*/
/*								*/
/*								*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE         	       SECSC-function is to be called  	*/
/*   FALSE         	       Perform SW-PSE-software       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   aux_AppName2SCApp()	Get information about an SC app.*/
/*   aux_AppObjName2SCObj()	Get information about an SC     */
/*        			object belonging to an 		*/
/*                              application on SC. 		*/
/*   get_pse_pin_from_SC()	Read the PIN for the SW-PSE from*/
/*				the SC and sets it in 		*/
/*			        "sct_stat_list[]".		*/
/*   open_app_on_SC()		If SC app not open, open it.	*/
/*   sec_sctest()		Check whether SCT/SC available. */
/*                                                              */
/*   aux_add_error()		Add error to error stack.	*/
/*                                                              */
/*--------------------------------------------------------------*/


int 
handle_in_SCTSC(key, SC_crypt)
	Key            *key;
	Boolean        SC_crypt;
{

	int		SCapp_available;
        AlgEnc 		alg;



	char           *proc = "handle_in_SCTSC";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif



	if (!key) {
		aux_add_error(EKEYSEL, "No key specified!", CNULL, 0, proc);
		return (-1);
	}


	if ((key->keyref == 0) && (key->pse_sel != (PSESel * ) 0) &&
	    (key->pse_sel->app_name)) {

		/*
		 *  Adress key with app_name and object_name
		 *
		 *   => Check whether application = SC application and
		 *      check whether SCT/SC available
		 */
				
		if ((SCapp_available = sec_sctest(key->pse_sel->app_name)) == -1) {
			if (aux_last_error() == EOPENDEV) 
				aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
			else
				aux_add_error(ECONFIG, "Error during SCT configuration.", CNULL, 0, proc);
			return (-1);
		}
		if (SCapp_available == FALSE) 
			return(FALSE);
		

		/*
		 * Intermediate result:  1. SC available and 
		 *			 2. application = SC application.
		 *
		 * Next to do:	         Open application on SC if not yet done.
		 */

		if (open_app_on_SC(key->pse_sel)) {
			aux_add_error(EAPP, "Application could not be opened", key->pse_sel->app_name, char_n, proc);
			return (-1);
		}

		/*
		 * Check whether object = SC object
		 */

		if (aux_AppObjName2SCObj(key->pse_sel->app_name, key->pse_sel->object.name)) {

			/* 
			 *  Object = SC object => SECSC-function is to be called 
			 */

			return (TRUE);
		} 
		else {

			/* 
			 *  A key on the SW-PSE shall be accessed!
			 *
			 *  => Get the PIN for the SW-PSE from the SC.
			 */

			strrep(&(key->pse_sel->pin), get_pse_pin_from_SC(key->pse_sel->app_name));
			if(!key->pse_sel->pin) {
				aux_add_error(EPSEPIN, "Can't get PIN for SW-PSE from SC", CNULL, 0, proc);
				return (-1);
			}
			strrep(&(key->pse_sel->object.pin), key->pse_sel->pin);

			return (FALSE);
		}
	} else {

		if ((key->keyref != 0) && (key->keyref != -1)) {

			/*
			 * Address key with keyref !
			 * 
			 * => Check whether keyref indicates SC/SCT as level of the key 
			 */

			if (((key->keyref & SC_KEY) == SC_KEY) ||
			    ((key->keyref & SCT_KEY) == SCT_KEY)) {

				/* 
				 * Keyref indicates SC/SCT as level of the key
				 *
				 * => check whether SCT/SC available
				 */
				
				if ((SCapp_available = sec_sctest(CNULL)) == -1) {
					if (aux_last_error() == EOPENDEV) 
						aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
					else
						aux_add_error(ECONFIG, "Error during SCT configuration.", CNULL, 0, proc);
					return (-1);
				}
				if (SCapp_available == TRUE) 
					return (TRUE);

			}
		}
		else {
			if (key->keyref == -1)
				return(FALSE);		
			else {

				if ((key->key != (KeyInfo *)0) && (SC_crypt == TRUE)) {

					/*
					 * Key delivered in key->key and 
					 *  crypto-function shall be performed in SCT/SC.
			 		 */

					if ((SCapp_available = sec_sctest(CNULL)) == -1) {
						if (aux_last_error() == EOPENDEV) 
							aux_add_error(EOPENDEV, "SCT is not available (device could not be opened)", CNULL, 0, proc);
						else
							aux_add_error(ECONFIG, "Error during SCT configuration.", CNULL, 0, proc);
						return (-1);
					}
					if (SCapp_available == TRUE) 
						return (TRUE);
					else {
						aux_add_error(EKEYSEL, "Crypto function shall be performed in SCT/SC, which are not available.", CNULL, 0, proc);
						return (-1);
					}

				}
			}
		}


	}		

	return (FALSE);

}				/* end handle_in_SCTSC */


PSEToc         *
read_SCToc(pse_sel)
	PSESel         *pse_sel;
{
	OctetString     ostr;
	PSEToc         *sc_toc;
	RC              rc;
	char           *obj;
	char           *proc = "read_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	obj = pse_sel->object.name;
	pse_sel->object.name = SCToc_name;


	/* If SC application not open => open it */
	if (open_app_on_SC(pse_sel)) {
		aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}

	rc = secsc_read(pse_sel, &ostr);
	if (rc < 0) {
		aux_add_error(EOBJNAME, "Can't read SC toc", pse_sel, PSESel_n, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}
	sc_toc = d_PSEToc(&ostr);
	free(ostr.octets);
	if (!sc_toc) {
		aux_add_error(EDAMAGE, "Can't decode SC toc", pse_sel, PSESel_n, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}
	pse_sel->object.name = obj;
	return (sc_toc);
}

RC 
write_SCToc(pse_sel, sc_toc)
	PSESel         *pse_sel;
	PSEToc         *sc_toc;
{
	OctetString    *ostr;
	RC              rc;
	char           *obj;
	char           *proc = "write_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	obj = pse_sel->object.name;
	pse_sel->object.name = SCToc_name;

	ostr = e_PSEToc(sc_toc);
	if (!ostr) {
		aux_add_error(EINVALID, "Can't encode SC toc", sc_toc, PSEToc_n, proc);
		pse_sel->object.name = obj;
		return (-1);
	}

	/* If SC application not open => open it */
	if (open_app_on_SC(pse_sel)) {
		aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
		pse_sel->object.name = obj;
		return (-1);
	}

	rc = secsc_write(pse_sel, ostr);
	aux_free_OctetString(&ostr);
	if (rc < 0) {
		aux_add_error(err_stack->e_number, "Can't write SC toc", pse_sel, PSESel_n, proc);
		pse_sel->object.name = obj;
		return (-1);
	}
	pse_sel->object.name = obj;
	return (0);
}

PSEToc         *
create_SCToc(pse_sel)
	PSESel         *pse_sel;
{
	RC              rc;
	char           *obj;
	char           *proc = "create_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	obj = pse_sel->object.name;
	pse_sel->object.name = SCToc_name;

	/* If SC application not open => open it */
	if (open_app_on_SC(pse_sel)) {
		aux_add_error(EAPP, "Application could not be opened", pse_sel->app_name, char_n, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}

	rc = secsc_create(pse_sel);
	if (rc < 0) {
		aux_add_error(err_stack->e_number, "Can't create SC toc", pse_sel, PSESel_n, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}
	sc_toc = (PSEToc *) malloc(sizeof(PSEToc));
	if (!sc_toc) {
		aux_add_error(EMALLOC, "sc_toc", CNULL, 0, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}
	sc_toc->owner = (char *) malloc(128);
	if (!sc_toc->owner) {
		aux_add_error(EMALLOC, "sc_toc", CNULL, 0, proc);
		pse_sel->object.name = obj;
		return ((PSEToc *) 0);
	}
	strcpy(sc_toc->owner, get_unixname());
	sc_toc->create = aux_current_UTCTime();
	sc_toc->update = aux_current_UTCTime();
	sc_toc->obj = (struct PSE_Objects *) 0;
	pse_sel->object.name = obj;
	return (sc_toc);
}

RC 
update_SCToc(pse_sel, length, st)
	PSESel         *pse_sel;
	int             length, st;
{
	OctetString    *ostr;
	RC              rc;
	struct PSE_Objects *nxt, *pre;
	char           *object;
	char           *proc = "update_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	object = pse_sel->object.name;

	/* Read SC toc */

	if (!(sc_toc = chk_SCToc(pse_sel))) {
		if (err_stack->e_number == EOBJNAME) {

			/* doesn't exist, create */

			sc_toc = create_SCToc(pse_sel);
			if (!sc_toc) {
				aux_add_error(ECREATEOBJ, "Can't create SC toc", pse_sel, PSESel_n, proc);
				return (-1);
			}
			aux_free_error();
		} else {
			aux_add_error(err_stack->e_number, "Can't read SC toc", pse_sel, PSESel_n, proc);
			return (-1);
		}
	}
	/* Check whether pse_sel->object.name already exists */

	nxt = sc_toc->obj;
	pre = (struct PSE_Objects *) 0;
	while (nxt) {
		if (strcmp(nxt->name, object) == 0) {

			/* yes, change update time */

			if (nxt->update)
				free(nxt->update);
			nxt->update = aux_current_UTCTime();
			if (sc_toc->update)
				free(sc_toc->update);
			sc_toc->update = aux_current_UTCTime();
			if (strcmp(sc_toc->owner, get_unixname())) {
				free(sc_toc->owner);
				sc_toc->owner = (char *) malloc(128);
				if (!sc_toc->owner) {
					aux_add_error(EMALLOC, "sc_toc", CNULL, 0, proc);
					return (-1);
				}
				strcpy(sc_toc->owner, get_unixname());
			}
			nxt->noOctets = length;
			nxt->status = st;
			goto write_sc_toc;
		}
		pre = nxt;
		nxt = nxt->next;
	}

	/* append new object */

	/* allocate memory for new element */

	nxt = (struct PSE_Objects *) malloc(sizeof(struct PSE_Objects));
	if (!nxt) {
		aux_add_error(EMALLOC, "new", CNULL, 0, proc);
		return (-1);
	}
	if (!(nxt->name = (char *) malloc(strlen(object) + 1))) {
		aux_add_error(EMALLOC, "next->name", CNULL, 0, proc);
		return (-1);
	}
	strcpy(nxt->name, object);
	nxt->create = aux_current_UTCTime();
	nxt->update = aux_current_UTCTime();
	sc_toc->update = aux_current_UTCTime();
	if (strcmp(sc_toc->owner, get_unixname())) {
		free(sc_toc->owner);
		sc_toc->owner = (char *) malloc(128);
		if (!sc_toc->owner) {
			aux_add_error(EMALLOC, "sc_toc", CNULL, 0, proc);
			return (-1);
		}
		strcpy(sc_toc->owner, get_unixname());
	}
	nxt->noOctets = length;
	nxt->status = st;
	nxt->next = (struct PSE_Objects *) 0;
	if (pre)
		pre->next = nxt;
	else
		sc_toc->obj = nxt;

write_sc_toc:

	rc = write_SCToc(pse_sel, sc_toc);

	if (rc < 0)
		aux_add_error(err_stack->e_number, "Can't write SC toc", sc_toc, PSEToc_n, proc);

	return (rc);
}

RC 
delete_SCToc(pse_sel)
	PSESel         *pse_sel;
{
	OctetString    *ostr;
	RC              rc;
	struct PSE_Objects *nxt, *pre;
	char           *object;
	char           *proc = "delete_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	object = pse_sel->object.name;

	/* Read SC toc */

	if (!(sc_toc = chk_SCToc(pse_sel))) {
		aux_add_error(err_stack->e_number, "Can't read SC toc", pse_sel, PSESel_n, proc);
		return (-1);

	}
	/* Check whether pse_sel->object.name already exists */

	nxt = sc_toc->obj;
	pre = (struct PSE_Objects *) 0;
	while (nxt) {
		if (strcmp(nxt->name, object) == 0) {

			/* yes, chain out */

			if (pre)
				pre->next = nxt->next;
			else
				sc_toc->obj = nxt->next;
			if (nxt->name)
				free(nxt->name);
			if (nxt->create)
				free(nxt->create);
			if (nxt->update)
				free(nxt->update);
			free(nxt);
			goto write_sc_toc;
		}
		pre = nxt;
		nxt = nxt->next;
	}

	/* object doesn't exist */

	aux_add_error(EOBJNAME, "object does not exist", object, char_n, proc);
	return (-1);


write_sc_toc:

	if (sc_toc->update)
		free(sc_toc->update);
	sc_toc->update = aux_current_UTCTime();

	rc = write_SCToc(pse_sel, sc_toc);

	if (rc < 0)
		aux_add_error(err_stack->e_number, "Can't write SC toc", sc_toc, PSEToc_n, proc);

	return (rc);
}

Boolean 
is_in_SCToc(pse_sel)
	PSESel         *pse_sel;
{
	OctetString    *ostr;
	RC              rc;
	struct PSE_Objects *nxt, *pre;
	char           *object;
	char           *proc = "is_in_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	object = pse_sel->object.name;

	/* Read SC toc */

	if (!(sc_toc = chk_SCToc(pse_sel))) {
		aux_add_error(err_stack->e_number, "Can't read SC toc", pse_sel, PSESel_n, proc);
		return (-1);

	}
	/* Check whether pse_sel->object.name already exists */

	nxt = sc_toc->obj;
	pre = (struct PSE_Objects *) 0;
	while (nxt) {
		if (strcmp(nxt->name, object) == 0) {

			/* yes */
			return (TRUE);

		}
		pre = nxt;
		nxt = nxt->next;
	}

	/* object doesn't exist */

	return (FALSE);
}


PSEToc         *
chk_SCToc(pse_sel)
	PSESel         *pse_sel;
{
	static char     last_pse_app_name[128];
	char           *proc = "chk_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	if (strcmp(last_pse_app_name, pse_sel->app_name)) {
		strcpy(last_pse_app_name, pse_sel->app_name);
		if (sc_toc) aux_free_PSEToc(&sc_toc);
		sc_toc = read_SCToc(pse_sel);
		return (sc_toc);
	} else {
		if (!sc_toc) sc_toc = read_SCToc(pse_sel);
		return (sc_toc);
	}
}



/*
 *  Get update time of object in SC-Toc
 */

RC
get_update_time_SCToc(pse_sel, update_time)
	PSESel	     *pse_sel;
	UTCTime	     **update_time;
{
	struct PSE_Objects *nxt, *pre;
	char           *object;
	char           *proc = "get_update_time_SCToc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);
#endif

	*update_time =  (UTCTime *)0;
	object = pse_sel->object.name;


	/* Read SC toc */

	if (!(sc_toc = chk_SCToc(pse_sel))) {
		if (err_stack->e_number == EOBJNAME) {

			/* doesn't exist, create */

			sc_toc = create_SCToc(pse_sel);
			if (!sc_toc) {
				aux_add_error(ECREATEOBJ, "Can't create SC toc", pse_sel, PSESel_n, proc);
				return (-1);
			}
			aux_free_error();
		} else {
			aux_add_error(err_stack->e_number, "Can't read SC toc", pse_sel, PSESel_n, proc);
			return (-1);
		}
	}

	/* Search entry of object in SCToc */

	nxt = sc_toc->obj;
	pre = (struct PSE_Objects *) 0;
	while (nxt) {
		if (strcmp(nxt->name, object) == 0) {

			/*  entry of object found */
			*update_time = nxt->update;
			return(0);
		}
		pre = nxt;
		nxt = nxt->next;
	}

	return (0);

}		/* get_update_time_SCToc */



#endif				/* SCA */


