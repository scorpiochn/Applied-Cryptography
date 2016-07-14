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

#include "af.h"
#include <stdio.h>

#ifdef MAC 
#include <stdlib.h>
#include <string.h>
#endif /* MAC */
#ifndef MAC
	static void clrpin();
#else
    void clrpin();
#endif /* MAC */

extern int	errno;


/****************************************************************************/

PSESel * af_pse_open(af_object, create)
ObjId  * af_object;
Boolean  create;
{
	PSESel     * pse;
	int	     i, obj_index;
	int          SCapp_available;
	char	   * proc = "af_pse_open";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse = (PSESel * )malloc(sizeof(PSESel)))) {
		aux_add_error(EMALLOC, "pse", CNULL, 0, proc);
		return ( (PSESel *) 0);
	}

	if (af_object) {
		for (obj_index = 0; obj_index < PSE_MAXOBJ; obj_index++) {
			if (aux_cmp_ObjId(af_object, AF_pse.object[obj_index].oid) == 0) 
				break;
		}
		if (obj_index == PSE_MAXOBJ) {
			aux_add_error(EINVALID, "Invalid ObjId", af_object, ObjId_n, proc);
			return ( (PSESel *) 0);
		}
	}

	pse->app_name = aux_cpy_String(AF_pse.app_name);
	pse->app_id   = AF_pse.app_id;
	pse->pin      = aux_cpy_String(AF_pse.pin);
	if (!af_object) {
		pse->object.name  = CNULL;
		pse->object.pin  = CNULL;
	} 
	else {
		pse->object.name = aux_cpy_String(AF_pse.object[obj_index].name);
		pse->object.pin = aux_cpy_String(AF_pse.object[obj_index].pin);
		if (!pse->object.pin) {
			pse->object.pin = aux_cpy_String(pse->pin);
			AF_pse.object[obj_index].pin = aux_cpy_String(pse->pin);
		}
		if (create) sec_create(pse);
	}


	/* check if already opened */
	SCapp_available = sec_sctest(pse->app_name);
#ifdef SCA
	if (SCapp_available == -1) {
		if (aux_last_error() == EOPENDEV) 
			aux_add_error(EOPENDEV, "Cannot open device for SCT (No such device or device busy).", CNULL, 0, proc);
		else	aux_add_error(ECONFIG, "Error during SC configuration.", CNULL, 0, proc);
		return ((PSESel *) 0);
	}
#endif

	if ((af_object && AF_pse.pin && AF_pse.object[obj_index].pin)
	   || (af_object && AF_pse.pin && (SCapp_available == TRUE)) 
           || (!af_object && AF_pse.pin) ) {
		return (pse);
	}

	/* open PSE */

	if (sec_open(pse) < 0) {
		aux_add_error(LASTERROR, "sec_open failed", pse, PSESel_n, proc);

		/* save PINs */

		AF_pse.app_id = pse->app_id;
		if (pse->pin) AF_pse.pin = aux_cpy_String(pse->pin);
		if (af_object && pse->object.pin) 
			AF_pse.object[obj_index].pin = aux_cpy_String(pse->object.pin);

		aux_free_PSESel(&pse);
		return ( (PSESel *) 0);
	}

	/* set PSE descriptor */

	AF_pse.app_id = pse->app_id;

	if(AF_pse.pin) {
		clrpin(AF_pse.pin);
        	free(AF_pse.pin);
		AF_pse.pin = CNULL;
	}
	if (af_object && AF_pse.object[obj_index].pin) {
		clrpin(AF_pse.object[obj_index].pin);
        	free(AF_pse.object[obj_index].pin);
		AF_pse.object[obj_index].pin = CNULL;
	}

	if (pse->pin) AF_pse.pin = aux_cpy_String(pse->pin);
/*	else AF_pse.pin = aux_cpy_String(""); */
	if (af_object && pse->object.pin) AF_pse.object[obj_index].pin = aux_cpy_String(pse->object.pin);

	return(pse);
}


/****************************************************************************/

PSESel * af_pse_create(af_object)
ObjId  * af_object;
{
	PSESel  * pse;
	int	  i, obj_index;
	char	* proc = "af_pse_create";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif


	if (!(pse = (PSESel * )malloc(sizeof(PSESel)))) {
		aux_add_error(EMALLOC, "pse", CNULL, 0, proc);
		return ( (PSESel *) 0);
	}

	if (af_object) {
		for (obj_index = 0; obj_index < PSE_MAXOBJ; obj_index++) {
			if (aux_cmp_ObjId(af_object, AF_pse.object[obj_index].oid) == 0) 
				break;
		}
		if (obj_index == PSE_MAXOBJ) {
			aux_add_error(EINVALID, "Invalid ObjId", af_object, ObjId_n, proc);
			free(pse);
			return ( (PSESel *) 0);
		}
	}

	pse->app_name = aux_cpy_String(AF_pse.app_name);
	pse->app_id   = AF_pse.app_id;
	pse->pin = aux_cpy_String(AF_pse.pin);
	if (!af_object) {
		pse->object.name  = CNULL;
		pse->object.pin  = CNULL;
	} else {
		pse->object.name = aux_cpy_String(AF_pse.object[obj_index].name);
		pse->object.pin = aux_cpy_String(AF_pse.object[obj_index].pin);
		if (!pse->object.pin) {
			pse->object.pin = aux_cpy_String(pse->pin);
			AF_pse.object[obj_index].pin = aux_cpy_String(pse->pin);
		}
	}

	/* create PSE */

	if (sec_create(pse) < 0) {    /* inherit error descriptor */
		aux_add_error(LASTERROR, "sec_create failed", pse, PSESel_n, proc);
		aux_free_PSESel(& pse);
		return ( (PSESel *) 0);
	}

	/* set PSE descriptor */
	AF_pse.pin = aux_cpy_String(pse->pin);
	AF_pse.app_id = pse->app_id;
	if (af_object) AF_pse.object[obj_index].pin = aux_cpy_String(pse->object.pin);

	return(pse);
}


/****************************************************************************/

RC
af_pse_close(af_object)
ObjId * af_object;
{
	PSESel         pse;
	int	       i, obj_index;
	char	     * proc = "af_pse_close";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (af_object) {
		for (obj_index = 0; obj_index < PSE_MAXOBJ; obj_index++) {
			if (aux_cmp_ObjId(af_object, AF_pse.object[obj_index].oid) == 0) 
				break;
		}
		if (obj_index == PSE_MAXOBJ) {
			aux_add_error(EINVALID, "Invalid ObjId", af_object, ObjId_n, proc);
			return (- 1);
		}
	}

	/* Check if already opened: If PSE or object "af_object" is not open, return error */
	if ((af_object && (!AF_pse.pin || !AF_pse.object[obj_index].pin)) || (!af_object && !AF_pse.pin)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return - 1;
	}

	if (!af_object) {  /* clear all PIN's */
		for (i = 0; i < PSE_MAXOBJ; i++) {
			if(AF_pse.object[i].pin) {
                                clrpin(AF_pse.object[i].pin);
     				free(AF_pse.object[i].pin);
			        AF_pse.object[i].pin = CNULL;
			}
		} 
		if (AF_pse.pin) {
                        clrpin(AF_pse.pin);
                        free(AF_pse.pin);
		        AF_pse.pin = CNULL;
                }

		/* close PSE */
		pse.app_name = AF_pse.app_name;
		pse.pin      = CNULL;
		pse.app_id   = AF_pse.app_id;
		pse.object.name  = CNULL;
		pse.object.pin   = CNULL;
	}
	else {  /* clear PIN of object identified by "af_object" */

		if (AF_pse.object[obj_index].pin) {	
			clrpin(AF_pse.object[obj_index].pin);
                        free(AF_pse.object[obj_index].pin);
		        AF_pse.object[obj_index].pin = CNULL;
                }

		/* close object on PSE */
		pse.app_name = AF_pse.app_name;
		pse.pin      = CNULL;
		pse.app_id   = AF_pse.app_id;
		pse.object.name  = AF_pse.object[obj_index].name;
		pse.object.pin   = CNULL;
	}

	if (sec_close(&pse) < 0) {    /* inherit error descriptor */
		aux_add_error(LASTERROR, "sec_close failed", &pse, PSESel_n, proc);
		return - 1;
	}

	return 0;
}


static void
clrpin(pin)
char	*pin;
{
	char	* proc = "clrpin";

	if(pin) while(*pin) *pin++ = '\0';
	return;
}




/****************************************************************************/

DName *af_pse_get_Name()
{
PSESel      * pse_sel;
OctetString   content;
DName       * afname;
ObjId         objid;
char	    * proc = "af_pse_get_Name";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(Name_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (NULLDNAME);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return (NULLDNAME);
	}
       	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, Name_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return (NULLDNAME);
	}

	afname = d_DName(&content);
	free(content.octets);

	if (! afname) {
		aux_add_error(EDECODE, "d_DName failed", CNULL, 0, proc);
		return (NULLDNAME);
	}

	return(afname);
}


/****************************************************************************/


AliasList *af_pse_get_AliasList()
{
PSESel      * pse_sel;
OctetString   content;
AliasList   * alist;
ObjId         objid;
char	    * proc = "af_pse_get_AliasList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(AliasList_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ((AliasList * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ((AliasList * ) 0);
	}
       	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, AliasList_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ((AliasList * ) 0);
	}

	alist = d_AliasList(&content);
	free(content.octets);

	if (! alist) {
		aux_add_error(EDECODE, "d_AliasList failed", CNULL, 0, proc);
		return ((AliasList * ) 0);
	}

	return(alist);
}


/****************************************************************************/


char *af_pse_get_QuipuPWD()
{
PSESel      * pse_sel;
OctetString   content;
char        * pwd;
ObjId         objid;
char	    * proc = "af_pse_get_QuipuPWD";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(QuipuPWD_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (CNULL);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return (CNULL);
	}
       	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, QuipuPWD_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return (CNULL);
	}

	pwd = d_GRAPHICString(&content);
	free(content.octets);

	if (! pwd) {
		aux_add_error(EDECODE, "d_GRAPHICString failed", CNULL, 0, proc);
		return (CNULL);
	}

	return(pwd);
}


/****************************************************************************/


SerialNumbers * af_pse_get_SerialNumbers()
{
PSESel      	     * pse_sel;
OctetString   	       content;
SerialNumbers        * serialnums;
ObjId         	       objid;
char	             * proc = "af_pse_get_SerialNumbers";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(SerialNumbers_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ((SerialNumbers * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ((SerialNumbers * ) 0);
	}
       	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, SerialNumbers_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ((SerialNumbers * ) 0);
	}

	serialnums = d_SerialNumbers(&content);
	free(content.octets);

	if (! serialnums) {
		aux_add_error(EDECODE, "d_SerialNumbers failed", CNULL, 0, proc);
		return ((SerialNumbers * ) 0);
	}

	return(serialnums);

}    /*af_pse_get_SerialNumbers()*/


/****************************************************************************/


Certificate *af_pse_get_Certificate(type, issuer, serial)
KeyType type;
DName * issuer;
int	serial;
{
	PSESel             * pse_sel;
	Certificate        * cert;
	OctetString          content;
        ObjId                objid;
	ObjId              * obj_type = NULLOBJID;
	SET_OF_Certificate * setofcert, *savesoc = (SET_OF_Certificate *) 0;
	Boolean		     onekeypaironly = FALSE;

	char	           * proc = "af_pse_get_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ((type != SIGNATURE) && (type != ENCRYPTION)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return ( (Certificate * )0);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return ( (Certificate * )0);
	}

	if (issuer) {
		if(onekeypaironly == TRUE)
			obj_type = CSet_OID;
		else{
			if (type == SIGNATURE) 
				obj_type = SignCSet_OID;
			else 
				obj_type = EncCSet_OID;
		}
	} 
	else {
		if(onekeypaironly == TRUE)
			obj_type = Cert_OID;
		else{
			if (type == SIGNATURE) 
				obj_type = SignCert_OID;
			else 
				obj_type = EncCert_OID;
		}
	}

	if (!(pse_sel = af_pse_open(obj_type, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (Certificate * )0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		return ( (Certificate * )0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, obj_type)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ( (Certificate * )0);
	}

	if (issuer) {
		if (!(setofcert = d_CertificateSet(&content)) ) {
			free(content.octets);
			aux_add_error(EDECODE, "d_CertificateSet failed", CNULL, 0, proc);
			return ( (Certificate * )0);
		}
		cert = (Certificate * )0;
		while (setofcert) {
			savesoc = setofcert;
			if (!cert && (setofcert->element->tbs->serialnumber == serial)
			     && (!aux_cmp_DName(setofcert->element->tbs->issuer, issuer)))
				cert = setofcert->element;
			else
				aux_free_Certificate(&setofcert->element);

			setofcert = setofcert->next;
			free(savesoc);

		}
	} else {
		if (!(cert = d_Certificate(&content))) {
			free(content.octets);
			aux_add_error(EDECODE, "d_Certificate failed", CNULL, 0, proc);
			return ( (Certificate * )0);
		}
	}
	free(content.octets);

	return(cert);

}   /* af_pse_get_Certificate() */


/****************************************************************************/

SET_OF_Certificate *af_pse_get_CertificateSet(type)
KeyType type;
{
	PSESel             * pse_sel;
	OctetString          content;
        ObjId                objid;
	ObjId              * obj_type = NULLOBJID;
	SET_OF_Certificate * cset;
	Boolean 	     onekeypaironly = FALSE;

	char	           * proc = "af_pse_get_CertificateSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if((type != SIGNATURE) && (type != ENCRYPTION)){
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return ( (SET_OF_Certificate * )0);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return ( (SET_OF_Certificate * )0);
	}

	if(onekeypaironly == TRUE) 
		obj_type = CSet_OID;
	else{
		switch (type) {
		case SIGNATURE:
			obj_type = SignCSet_OID;
			break;
		case ENCRYPTION:
			obj_type = EncCSet_OID;
			break;
		default:
			aux_add_error(EINVALID, "Invalid keytype", CNULL, 0, proc);
			return ( (SET_OF_Certificate * ) 0);
		}  /* switch */
	}

	if (!(pse_sel = af_pse_open(obj_type, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (SET_OF_Certificate * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		return ( (SET_OF_Certificate * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, obj_type)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ( (SET_OF_Certificate * ) 0);
	}

	if (!(cset = d_CertificateSet(&content))) {
		free(content.octets);
		aux_add_error(EDECODE, "d_CertificateSet failed", CNULL, 0, proc);
		return ( (SET_OF_Certificate * ) 0);
	}

	free(content.octets);

	return(cset);
}


/****************************************************************************/

SET_OF_CertificatePair *af_pse_get_CertificatePairSet()
{
	PSESel                 * pse_sel;
	OctetString              content;
        ObjId                    objid;
	SET_OF_CertificatePair * cpairset;
	char		       * proc = "af_pse_get_CertificatePairSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(CrossCSet_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ( (SET_OF_CertificatePair * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, CrossCSet_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * ) 0);
	}

	cpairset = d_CertificatePairSet(&content);
	free(content.octets);

	if (!cpairset) {
		aux_add_error(EDECODE, "d_CertificatePairSet failed", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * ) 0);
	}

	return(cpairset);
}


/****************************************************************************/

FCPath *af_pse_get_FCPath(name)
DName *name;
{
	PSESel            * pse_sel;
	FCPath            * fcpath;
        ObjId 		    objid;
	OctetString 	    content;
	CrossCertificates * crosscert;
	FCPath 		  * current_level_ref;
	int		    found = 0;
	char		  * proc = "af_pse_get_FCPath";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(FCPath_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (FCPath * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		return ( (FCPath * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, FCPath_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		return ( (FCPath * ) 0);
	}

	if (!(fcpath = d_FCPath(&content)) ) {
		free(content.octets);
		aux_add_error(EDECODE, "d_FCPath failed", CNULL, 0, proc);
		return ( (FCPath * ) 0);
	}

	free(content.octets);

	if (name)       /*return reduced forward certification path*/ {
		if (aux_cmp_DName(name, fcpath->liste->element->tbs->issuer) == 0) 
			aux_free_FCPath( &(fcpath->next_forwardpath) );
		else {
			current_level_ref = fcpath->next_forwardpath;
			while (current_level_ref) {
				crosscert = current_level_ref->liste;
				while (crosscert) {
					if (!found) {
						if (aux_cmp_DName(name, crosscert->element->tbs->issuer) > 0) {
							if (current_level_ref->next_forwardpath) {
								if (aux_cmp_DName(current_level_ref->next_forwardpath->liste->element->tbs->subject,
								     								     crosscert->element->tbs->issuer) > 0 )
/* code folded from here */
	aux_free2_Certificate( crosscert->element );
/* unfolding */
								else /*crosscert ist Hierarchie-Zertifikat*/			     {
/* code folded from here */
	if ( !( current_level_ref->liste->element = aux_cpy_Certificate(crosscert->element) ) ) {
		aux_add_error(EMALLOC, "aux_cpy_Certificate", CNULL, 0, proc);
		return ( (FCPath * ) 0);
	}
	current_level_ref->liste->next = (CrossCertificates * )0;
	aux_free_Certificate( &(crosscert->element) );
/* unfolding */
								}
							} else 
								aux_free_Certificate( &(crosscert->element) );
						} else {
							found = 1;
							if (!(current_level_ref->liste->element = aux_cpy_Certificate(crosscert->element))) {
								aux_add_error(EMALLOC, "aux_cpy_Certificate", CNULL, 0, proc);
								return ( (FCPath * ) 0);
							}
							current_level_ref->liste->next = (CrossCertificates * )0;
							aux_free_Certificate(&(crosscert->element));
						}
					}   /*if*/ else /*found = 1*/
						aux_free_Certificate( &(crosscert->element) );
					crosscert = crosscert->next;
				}  /*while*/

				current_level_ref = current_level_ref->next_forwardpath;
			}   /*while*/
		}  /*else*/
	}  /*if*/

	if (name && !found) {
		aux_add_error(EINVALID, "not found", name, DName_n, proc);
		return ( (FCPath * ) 0);
	}
	return(fcpath);

}  /*af_pse_get_FCPath()*/


/****************************************************************************/

Certificates *af_pse_get_Certificates(type, name)
KeyType type;
DName *name;
{
	Certificates * certs;
	Certificate  * cert;
	FCPath	     * fcpath;
	char	     * proc = "af_pse_get_Certificates";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(cert = af_pse_get_Certificate(type, NULLDNAME, 0)))  {
		aux_add_error(EREADPSE, "af_pse_get_Certificate failed", CNULL, 0, proc);
		return ( (Certificates * ) 0);
	}


	fcpath = af_pse_get_FCPath(name);

        if(!(certs = aux_create_Certificates(cert, fcpath))) {
		aux_add_error(EINVALID, "aux_create_Certificates failed", CNULL, 0, proc);
	}

        aux_free_Certificate(&cert);
	if(fcpath) aux_free_FCPath(&fcpath);

	return(certs);

}  /*af_pse_get_Certificates()*/


/****************************************************************************/

PKRoot *af_pse_get_PKRoot()
{
	PSESel      * pse_sel;
	PKRoot      * pkroot;
        ObjId         objid;
	OctetString   content;
	char	    * proc = "af_pse_get_PKRoot";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(PKRoot_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (PKRoot * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ( (PKRoot * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, PKRoot_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		free(content.octets);
		return ( (PKRoot * ) 0);
	}

	if (!(pkroot = d_PKRoot(&content))) {
		free(content.octets);
		aux_add_error(EDECODE, "d_PKRoot failed", CNULL, 0, proc);
		return ( (PKRoot * ) 0);
	}

	free(content.octets);

	return(pkroot);

}  /*af_pse_get_PKRoot()*/


/****************************************************************************/

PKList *af_pse_get_PKList(type)
KeyType type;
{
	PSESel      * pse_sel;
	PKList      * list;
	OctetString   content;
        ObjId	      objid;
	ObjId 	    * obj_type = NULLOBJID;
	int	      i;
	Boolean       onekeypaironly = FALSE;

	char	    * proc = "af_pse_get_PKList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ((type != ENCRYPTION) && (type != SIGNATURE)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return ( (PKList * ) 0);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return ( (PKList * )0);
	}

	if ((type == SIGNATURE) || (onekeypaironly == TRUE)) 
		obj_type = PKList_OID;
	else 
		obj_type = EKList_OID;

	if (!(pse_sel = af_pse_open(obj_type, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (PKList * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ( (PKList * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, obj_type)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		free(content.octets);
		return ( (PKList * ) 0);
	}

	if (!(list = d_PKList(&content))) {
		free(content.octets);
		aux_add_error(EDECODE, "d_PKList failed", CNULL, 0, proc);
		return ( (PKList * ) 0);
	}

	free(content.octets);

	return(list);

}   /*af_pse_get_PKList()*/


/****************************************************************************/


CrlSet * af_pse_get_CrlSet()
{
	PSESel       * pse_sel;
	OctetString    content;
        ObjId 	       objid;
	CrlSet   * crlset;
	char	     * proc = "af_pse_get_CrlSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(pse_sel = af_pse_open(CrlSet_OID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return ( (CrlSet * ) 0);
	}

	if (sec_read_PSE(pse_sel, &objid, &content) < 0 ) {
		aux_add_error(EREADPSE, "sec_read_PSE failed", pse_sel, PSESel_n, proc);
        	aux_free_PSESel(&pse_sel);
		return ( (CrlSet * ) 0);
	}
	aux_free_PSESel(&pse_sel);
        if(aux_cmp_ObjId(&objid, CrlSet_OID)) {
		aux_add_error(EDAMAGE, "PSE object has wrong objid", CNULL, 0, proc);
		free(content.octets);
		return ( (CrlSet * ) 0);
	}

	crlset = d_CrlSet(&content);
	free(content.octets);

	if (!crlset) {
		aux_add_error(EDECODE, "d_CrlSet failed", CNULL, 0, proc);
		return ( (CrlSet * ) 0);
	}

	return(crlset);
}


/****************************************************************************/


RC af_pse_update_Certificate(type, cert, hierarchy)
KeyType type;
Certificate *cert;
Boolean hierarchy;
{

	/* hierarchy = TRUE  (hierarchy certifiacte) updates SignCert Or EncCert 
                     = FALSE (crosscertificate) updates SignCSet or EncCSet      */

	PSESel 		   * pse_sel;
	OctetString 	   * content;
	ObjId 		   * obj_type = NULLOBJID;
	SET_OF_Certificate * setofcert, * savesoc = (SET_OF_Certificate * ) 0;
	Boolean		     onekeypaironly = FALSE;

	char		   * proc = "af_pse_update_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (((type != SIGNATURE) && (type != ENCRYPTION)) || !cert ) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (- 1);
	}

	if (hierarchy) {
		if(onekeypaironly == TRUE)
			obj_type = Cert_OID;
		else{
			if (type == SIGNATURE) 
				obj_type = SignCert_OID;
			else 
				obj_type = EncCert_OID;
		}
	} 
	else {
		if(onekeypaironly == TRUE)
			obj_type = CSet_OID;
		else{
			if (type == SIGNATURE) 
				obj_type = SignCSet_OID;
			else 
				obj_type = EncCSet_OID;
		}
	}

	if (!(pse_sel = af_pse_open(obj_type, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (hierarchy) {

		/* Hierarchy Certificate */

		if (!(content = e_Certificate(cert))) {
			aux_free_PSESel(&pse_sel);
			aux_add_error(EENCODE, "e_Certificate failed", CNULL, 0, proc);
			return (-1);
		}

		if (sec_write_PSE(pse_sel, obj_type, content) < 0) {
			aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
			aux_free_PSESel(&pse_sel);
			aux_free_OctetString(&content);
			return (-1);
		}
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);

	} 
        else {

		/* CertificateSet */

		if (!(setofcert = af_pse_get_CertificateSet(type))) {
			if (!(setofcert = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate)))) {
				aux_add_error(EMALLOC, "setofcert", CNULL, 0, proc);
				aux_free_PSESel(&pse_sel);
				return( -1);
			}
			setofcert->element = cert;
			setofcert->next = (SET_OF_Certificate * )0;
		} else {
			savesoc = setofcert;
			while (setofcert) {
				if ((aux_cmp_DName(setofcert->element->tbs->issuer, cert->tbs->issuer) == 0)
				     && (setofcert->element->tbs->serialnumber == cert->tbs->serialnumber)) {

					/* update existing member */

					setofcert->element = aux_cpy_Certificate(cert);
					break;
				}
				if (!setofcert->next) {

					/* add new member */

					if (!(setofcert->next = (SET_OF_Certificate * ) malloc(sizeof(SET_OF_Certificate)))) {
						aux_free_PSESel(&pse_sel);
						aux_add_error(EMALLOC, "setofcert->next", CNULL, 0, proc);
						aux_free_CertificateSet(&savesoc);
						return( -1);
					}
					setofcert = setofcert->next;
					setofcert->element = aux_cpy_Certificate(cert);
					setofcert->next = (SET_OF_Certificate * )0;
					break;
				}
				setofcert = setofcert->next;
			}

			setofcert = savesoc;
		}

		if (!(content = e_CertificateSet(setofcert)) ) {
			aux_free_PSESel(&pse_sel);
			aux_free_CertificateSet(&savesoc);
			aux_add_error(EENCODE, "e_CertificateSet failed", CNULL, 0, proc);
			return (-1);
		}
		aux_free_CertificateSet(&savesoc);

		if (sec_write_PSE(pse_sel, obj_type, content) < 0 ) {
			aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
			aux_free_PSESel(&pse_sel);
			aux_free_OctetString(&content);
			return (-1);
		}
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
	}

	return(0);

}   /*af_pse_update_Certificate()*/


/****************************************************************************/

RC af_pse_update_FCPath(fcpath)
FCPath *fcpath;
{
	PSESel 		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_FCPath";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!fcpath) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(FCPath_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_FCPath(fcpath)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_FCPath failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, FCPath_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_FCPath()*/


/****************************************************************************/

RC af_pse_update_CertificatePairSet(cpairset)
SET_OF_CertificatePair *cpairset;
{
	PSESel 		* pse_sel;
	OctetString	* content;
	char		* proc = "af_pse_update_CertificatePairSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif  

	if (!cpairset) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(CrossCSet_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_CertificatePairSet(cpairset)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_CertificatePairSet failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, CrossCSet_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_CertificatePairSet()*/


/****************************************************************************/

RC af_pse_update_Name(dname)
DName *dname;
{
	PSESel 		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_Name";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!dname) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(Name_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_DName(dname)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_DName failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, Name_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_Name()*/


/****************************************************************************/


RC af_pse_update_AliasList(alist)
AliasList *alist;
{
	PSESel 		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_AliasList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!alist) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(AliasList_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_AliasList(alist, useralias)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_DName failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, AliasList_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_AliasList()*/


/****************************************************************************/


RC af_pse_update_QuipuPWD(pwd)
char * pwd;
{
	PSESel 		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_QuipuPWD";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!pwd) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(QuipuPWD_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_GRAPHICString(pwd)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_GRAPHICString failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, QuipuPWD_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_QuipuPWD()*/


/****************************************************************************/


RC af_pse_update_SerialNumbers(serialnums)
SerialNumbers * serialnums;
{
	PSESel 		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_SerialNumbers";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! serialnums) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(SerialNumbers_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_SerialNumbers(serialnums)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_SerialNumbers failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, SerialNumbers_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_SerialNumbers()*/


/****************************************************************************/


RC af_pse_update_PKRoot(pkroot)
PKRoot *pkroot;
{
	PSESel		* pse_sel;
	OctetString 	* content;
	char		* proc = "af_pse_update_PKRoot";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!pkroot) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(PKRoot_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_PKRoot(pkroot))) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_PKRoot failed", CNULL, 0, proc);
		return (-1);
	}

	if ( sec_write_PSE(pse_sel, PKRoot_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_OctetString(&content);
		aux_free_PSESel(&pse_sel);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}  /*af_pse_update_PKRoot()*/


/****************************************************************************/

RC af_pse_update_PKList(type, list)
KeyType type;
PKList *list;
{
	PSESel      * pse_sel;
	OctetString * content;
	ObjId       * obj_type = NULLOBJID;
	Boolean       onekeypaironly = FALSE;

	char	    * proc = "af_pse_update_PKList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (((type != ENCRYPTION) && (type != SIGNATURE)) || !list ) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return(- 1);
	}

	if ((type == SIGNATURE) || (onekeypaironly == TRUE)) 
		obj_type = PKList_OID;
	else 
		obj_type = EKList_OID;

	if (!(pse_sel = af_pse_open(obj_type, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if ( !(content = e_PKList(list)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_Certificate failed", CNULL, 0, proc);
		return (-1);
	}

	if ( sec_write_PSE(pse_sel, obj_type, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_OctetString(&content);
		aux_free_PSESel(&pse_sel);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return(0);

}   /*af_pse_update_PKList()*/


/****************************************************************************/


RC af_pse_update_CrlSet(crlset)
CrlSet *crlset;
{
	PSESel		 * pse_sel;
	OctetString	 * content;
	char		 * proc = "af_pse_update_CrlSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!crlset) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(pse_sel = af_pse_open(CrlSet_OID, TRUE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return (-1);
	}

	if (!(content = e_CrlSet(crlset)) ) {
		aux_free_PSESel(&pse_sel);
		aux_add_error(EENCODE, "e_CrlSet failed", CNULL, 0, proc);
		return (-1);
	}

	if (sec_write_PSE(pse_sel, CrlSet_OID, content) < 0 ) {
		aux_add_error(EWRITEPSE, "sec_write_PSE failed", pse_sel, PSESel_n, proc);
		aux_free_PSESel(&pse_sel);
		aux_free_OctetString(&content);
		return (-1);
	}
	aux_free_PSESel(&pse_sel);
	aux_free_OctetString(&content);

	return (0);

}  /*af_pse_update_CrlSet()*/


/****************************************************************************/


RC af_pse_add_PK(type, tbs)
KeyType       type;
ToBeSigned  * tbs;
{
	PKList      * newlist,  * list, * np, * ahead_np;
	ToBeSigned  * found_tbs;
	ObjId       * obj_type = NULLOBJID;
	RC            rc;
	int	      error;
	char	    * proc = "af_pse_add_PK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (((type != ENCRYPTION) && (type != SIGNATURE)) || !tbs) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(newlist = (PKList * )malloc(sizeof(PKList))) ) {
		aux_add_error(EMALLOC, "newlist", CNULL, 0, proc);
		return ( - 1);
	}
	list = af_pse_get_PKList(type);

	for (np = list; np; np = np->next) {
		if (aux_cmp_DName(np->element->issuer, tbs->issuer) == 0
		     && np->element->serialnumber == tbs->serialnumber) {
			error = EPK;
			break;
		}
		if (aux_cmp_KeyInfo(np->element->subjectPK, tbs->subjectPK) == 0) {
			error = EPKCROSS;
			break;
		}
	}

	if (np) {         /* tbs with same issuer and serialnumber or with same subjectPK
	                     already exists in PKList */
		found_tbs = aux_cpy_ToBeSigned(np->element);
		aux_free_PKList(&list);
		free(newlist);
		aux_add_error(error, "tbs with same issuer and serialnumber or with same subjectPK", found_tbs, ToBeSigned_n, proc);  /* error is either EPK or EPKCROSS */
		return (-1);
	} 

	/* add new entry */
	newlist->element = aux_cpy_ToBeSigned(tbs);
	newlist->next    = list; /* NULL or existing list */

	/* update PKList/EKList on PSE */
	rc = af_pse_update_PKList(type, newlist);
	aux_free_PKList(&newlist);
	return(rc);                            

} /*af_pse_add_PK()*/


/****************************************************************************/

RC af_pse_delete_PK(type, name, issuer, serial)
KeyType type;
DName *name, *issuer;
int	serial;
{
	PKList  * list, * np, * ahead_np, * tmp_np;
	int	  found = 0;
	PSESel    pse;
	RC        rc;
	char	* proc = "af_pse_delete_PK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ENCRYPTION) && (type != SIGNATURE)) || (((serial < 0) || !issuer) && !name) ) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(list = af_pse_get_PKList(type)) ) {      /* List not found */

		aux_add_error(EOBJNAME, "PK/EK-List not found", CNULL, 0, proc);
		return (-1);
	}

	if (issuer) {
		for (np = list, ahead_np = (PKList *) 0; np; ahead_np = np, np = np->next) {
			if (aux_cmp_DName(np->element->issuer, issuer) == 0
			     && np->element->serialnumber == serial)
				break;
		}
		if (np) {      /* PK (to be deleted) found */
			if (!ahead_np) 
				list = np->next;     /* firstelement */
			else 
				ahead_np->next = np->next;    /* not first */
			np->next = (PKList *) 0;
			aux_free_PKList(&np);

			if ( !list ) {       /* last element deleted from list */
				pse.app_name = AF_pse.app_name;
				pse.pin      = AF_pse.pin;
				if ( type == ENCRYPTION )
					pse.object.name = EKList_name;
				else
					pse.object.name = PKList_name;
				pse.object.pin = getobjectpin(pse.object.name);
				rc = sec_delete(&pse);
			}
			else {
				rc = af_pse_update_PKList(type, list);
				aux_free_PKList(&list);
			}
			return(rc);
		} 
		else {      /* PK (to be deleted) not found */
			aux_free_PKList(&list);
			aux_add_error(EOBJNAME, "PK (to be deleted) not found", CNULL, 0, proc);
			return (-1);
		}
	} 
	else {   /*name is set*/
		np = list;
		ahead_np = (PKList *) 0;
		while (np) {
			if (aux_cmp_DName(np->element->subject, name) == 0) {
				if (!found) 
					found = 1;
				if (!ahead_np) 
					list = np->next;     /* firstelement */
				else 
					ahead_np->next = np->next;    /* not first */
				tmp_np = np->next;
				np->next = (PKList *) 0;
				aux_free_PKList(&np);
				np = tmp_np;
			} else {
				ahead_np = np;
				np = np->next;
			}
		}
		if (found) {
			if ( !list ) {       /* last element deleted from list */
				pse.app_name = AF_pse.app_name;
				pse.pin      = AF_pse.pin;
				if ( type == ENCRYPTION )
					pse.object.name = EKList_name;
				else
					pse.object.name = PKList_name;
				pse.object.pin = getobjectpin(pse.object.name);
				rc = sec_delete(&pse);
			}
			else {
				rc = af_pse_update_PKList(type, list);
				aux_free_PKList(&list);
			}
			return(rc);
		} else {
			aux_free_PKList(&list);
			aux_add_error(EOBJNAME, "PK with this name not found", name, DName_n, proc);
			return (-1);
		}
	}

}  /*af_pse_delete_PK()*/


/****************************************************************************/

RC af_pse_add_CertificatePairSet(cpairset)
SET_OF_CertificatePair *cpairset;
{
	SET_OF_CertificatePair * newset,  * set, * np_arg, * np_pse, * newset_tmp;
	RC     			 rc;
	int			 error;
	char		       * proc = "af_pse_add_CertificatePairSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	rc = 0;
	newset = (SET_OF_CertificatePair * ) 0;
	newset_tmp = (SET_OF_CertificatePair * ) 0;
	set = af_pse_get_CertificatePairSet();

	if (!set) {
		rc = af_pse_update_CertificatePairSet(cpairset);
		return(rc);
	}

	for (np_arg = cpairset; np_arg; np_arg = np_arg->next) {
		for (np_pse = set; np_pse; np_pse = np_pse->next) {
			if (!aux_cmp_CertificatePair(np_arg->element, np_pse->element))
				break;
		}
		if (!np_pse) {   /* add new entry */
			if (!(newset = (SET_OF_CertificatePair * )malloc(sizeof(SET_OF_CertificatePair))) ) {
				aux_add_error(EMALLOC, "newset", CNULL, 0, proc);
				return( -1);
			}
			newset->element = np_arg->element;
			if (!newset_tmp)
				newset->next = set;
			else
				newset->next = newset_tmp;
			newset_tmp = newset;
		}
	}

	if (newset)
		rc = af_pse_update_CertificatePairSet(newset);
	aux_free_CertificatePairSet(&set);
	return(rc);

} /*af_pse_add_CertificatePairSet()*/


/****************************************************************************/


RC af_pse_add_PemCRL(crlpse)
CrlPSE *crlpse;
{
	CrlSet     * newset, * set, * np, * ahead_np;
	RC           rc;
	char	   * proc = "af_pse_add_PemCRL";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!(newset = (CrlSet * )malloc(sizeof(CrlSet))) ) {
		aux_add_error(EMALLOC, "newset", CNULL, 0, proc);
		return( -1);
	}
	newset->element = aux_cpy_CrlPSE(crlpse);

	set = af_pse_get_CrlSet();

	if (!set) {
		newset->next = (CrlSet *)0;
		rc = af_pse_update_CrlSet(newset);
		aux_free_CrlSet(&newset);
		return(rc);
	}

	for (np = set, ahead_np = (CrlSet *) 0; np; ahead_np = np, np = np->next) {
		if (!aux_cmp_DName(crlpse->issuer, np->element->issuer))
			break;
	}

	if (np) {      /* overwrite obsolete entry */
		newset->next = np->next;  /* may be NULL pointer */
		np->next = (CrlSet *) 0;
		aux_free_CrlSet(&np);   /* delete obsolete entry */
		if (ahead_np) {     /* not first */
			ahead_np->next = newset;    
			rc = af_pse_update_CrlSet(set);
			aux_free_CrlSet(&set);
		}
		else {     /* first element to be overwritten */
			rc = af_pse_update_CrlSet(newset);
			aux_free_CrlSet(&newset);
		}
	} 
	else {   /* add new entry */
		newset->next = (CrlSet *)0;
		ahead_np->next = newset;
		rc = af_pse_update_CrlSet(set);
		aux_free_CrlSet(&set);
	}

	return(rc);

} /*af_pse_add_PemCRL()*/


/****************************************************************************/


RC af_pse_delete_PemCRL(issuer)
DName * issuer;
{
	CrlSet  * set, * np, * ahead_np;
	int	  found = 0;
	PSESel    pse_sel;
	RC        rc;
	char	* proc = "af_pse_delete_PemCRL";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! issuer){
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	set = af_pse_get_CrlSet();
	if(! set) {
		aux_add_error(EOBJNAME, "No set of revocation lists stored locally", CNULL, 0, proc);
		return (-1);
	}

	for (np = set, ahead_np = (CrlSet *) 0; np; ahead_np = np, np = np->next) {
		if (aux_cmp_DName(np->element->issuer, issuer) == 0)
			break;
	}

	if (np) {      /* Revocation list (to be deleted) found */
		if (! ahead_np) 
			set = np->next;     /* firstelement */
		else 
			ahead_np->next = np->next;    /* not first */

		np->next = (CrlSet *) 0;
		aux_free_CrlSet(&np);

		if (! set) {       /* last element deleted from set */
			pse_sel.app_name = AF_pse.app_name;
			pse_sel.pin      = AF_pse.pin;
			pse_sel.object.name = CrlSet_name;
			pse_sel.object.pin = getobjectpin(pse_sel.object.name);
			rc = sec_delete(&pse_sel);
		}
		else {
			rc = af_pse_update_CrlSet(set);
			aux_free_CrlSet(&set);
		}
		return(rc);
	} 
	else {      /* Revocation list (to be deleted) not found */
		aux_free_CrlSet(&set);
		aux_add_error(EOBJNAME, "Revocation list (to be deleted) not found", CNULL, 0, proc);
		return (-1);
	}


}  /*af_pse_delete_PemCRL()*/


/****************************************************************************/


RC af_pse_exchange_PK(type, tbs)
KeyType type;
ToBeSigned *tbs;
{
	PKList  * list, *np;
	RC        rc;
	char	* proc = "af_pse_exchange_PK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (((type != ENCRYPTION) && (type != SIGNATURE)) || !tbs) {
		/* public key identified by name, exchange by the new key pk */
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (-1);
	}

	if (!(list = af_pse_get_PKList(type))) {
		aux_add_error(EREADPSE, "af_pse_get_PKList failed", CNULL, 0, proc);
		return (-1);
	}

	for (np = list; np; np = np->next) {
		if (aux_cmp_DName(np->element->subject, tbs->subject) == 0
		     && aux_cmp_DName(np->element->issuer, tbs->issuer) == 0) 
			break;
	}

	if (np) {
		np->element = aux_cpy_ToBeSigned(tbs);
		rc = af_pse_update_PKList(type, list);
		aux_free_PKList(&list);
		return(rc);
	} else {         /* PK (to be changed) does not exist */
		aux_free_PKList(&list);
		aux_add_error(ENONAME, "PK (to be changed) does not exist", tbs->subject, DName_n, proc);
		return (-1);
	}

}  /*af_pse_exchange_PK()*/


/****************************************************************************/

DName *af_pse_get_owner(type, pk)
KeyType type;
KeyInfo *pk;
{
	PKList  * list;
	PKList  * np;
	char	* proc = "af_pse_get_owner";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ENCRYPTION) && (type != SIGNATURE)) || !pk) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return (NULLDNAME);
	}

	if ( !(list = af_pse_get_PKList(type)) ) {
		aux_add_error(EOBJNAME, "List does not exist", CNULL, 0, proc);
		return (NULLDNAME);
	}

	for ( np = list; np; np = np->next ) {
		if ( aux_cmp_KeyInfo(&(np->element->subjectPK), pk) == 0 )
			break;
	}

	if (np)
		return(np->element->subject);

	aux_add_error(ENOPK, "PK not found", CNULL, 0, proc);

	return (NULLDNAME);

}   /*af_pse_get_owner()*/


/****************************************************************************/

KeyInfo *af_pse_get_PK(type, subject, issuer, serial)
KeyType type;
DName *subject, *issuer;
int	serial;
{
	PKList  * list;
	PKList  * np;
	char	* proc = "af_pse_get_PK";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ((type != ENCRYPTION && type != SIGNATURE) || (!subject && !issuer)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return ((KeyInfo * )0);
	}

	if ( !(list = af_pse_get_PKList(type)) ) {
		aux_free_error();
		return ((KeyInfo * )0);
	}

	for ( np = list; 
	    np; 
	    np = np->next
	    ) {
		if(issuer && (aux_cmp_DName(np->element->issuer, issuer) == 0)
		     && (np->element->serialnumber == serial) && !subject) break;

		if(issuer && (aux_cmp_DName(np->element->issuer, issuer) == 0)
		     && (np->element->serialnumber == serial) && subject && aux_cmp_DName(np->element->subject, subject) == 0) break;

		 if(!issuer && subject && aux_cmp_DName(np->element->subject, subject) == 0)
			break;
	}

	if (np) return(np->element->subjectPK);

	aux_add_error(ENONAME, "Requested TBS not found in PKList/EKList", CNULL, 0, proc);

	return ((KeyInfo * )0);

}   /*af_pse_get_PK()*/


/****************************************************************************/

ToBeSigned *af_pse_get_TBS(type, subject, issuer, serial)
KeyType type;
DName *subject, *issuer;
int	serial;
{
	PKList  * list;
	PKList  * np;
	char	* proc = "af_pse_get_TBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ((type != ENCRYPTION && type != SIGNATURE) || (!subject && !issuer)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return ((ToBeSigned * )0);
	}

	if ( !(list = af_pse_get_PKList(type)) ) {
		aux_free_error();
		return ((ToBeSigned * )0);
	}

	for ( np = list; 
	    np; 
	    np = np->next
	    ) {
		if(issuer && (aux_cmp_DName(np->element->issuer, issuer) == 0)
		     && (np->element->serialnumber == serial) && !subject) break;

		if(issuer && (aux_cmp_DName(np->element->issuer, issuer) == 0)
		     && (np->element->serialnumber == serial) && subject && aux_cmp_DName(np->element->subject, subject) == 0) break;

		 if(!issuer && subject && aux_cmp_DName(np->element->subject, subject) == 0)
			break;
	}

	if (np)	return(np->element);

	aux_add_error(ENONAME, "Requested PK not found in PKList/EKList", CNULL, 0, proc);

	return ((ToBeSigned * )0);

}   /*af_pse_get_TBS()*/


/****************************************************************************/

RC
af_gen_key(key, ktype, replace)
Key	*key;
KeyType ktype;
Boolean replace;
{
	KeyType          keytype;
	PSESel         * pse;
	Boolean          onekeypaironly = FALSE;

	int	          rc;
	Certificate     * newcert;
	FCPath          * fcpath;
	PKRoot          * pkroot;

	char	        * proc = "af_gen_key";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif


	if (!key || !key->key || (ktype != SIGNATURE && ktype != ENCRYPTION)) {
		aux_add_error(EINVALID, "Invalid parameter", CNULL, 0, proc);
		return - 1;
	}

	if ( (key->keyref != 0) || (key->pse_sel != (PSESel *) 0) ) {
		if (sec_gen_key(key, replace) < 0) {
			aux_add_error(EINVALID, "sec_gen_key failed", CNULL, 0, proc);
			return - 1;
		} else return 0;
	}


	/* generate permanent key */

	pse = (PSESel * )calloc( 1, sizeof(PSESel));
	if (!pse) {
		aux_add_error(EMALLOC, "pse", CNULL, 0, proc);
		return - 1;
	}
	pse->app_name = aux_cpy_String(AF_pse.app_name);
	pse->pin      = aux_cpy_String(AF_pse.pin);
	pse->app_id   = AF_pse.app_id;

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (- 1);
	}

	if(onekeypaironly == TRUE){
		pse->object.name = aux_cpy_String(SKnew_name);
		pse->object.pin = aux_cpy_String(getobjectpin(SKnew_name));
	}
	else{
		switch (ktype) {
		case ENCRYPTION:
			pse->object.name = aux_cpy_String(DecSKnew_name);
			pse->object.pin = aux_cpy_String(getobjectpin(DecSKnew_name));
			keytype = ENCRYPTION;
			break;
		case SIGNATURE:
			pse->object.name = aux_cpy_String(SignSK_name);
			pse->object.pin = aux_cpy_String(getobjectpin(SignSK_name));
			keytype = SIGNATURE;
			break;
		default:
			aux_add_error(EALGID, "invalid algid", CNULL, 0, proc);
                	aux_free_PSESel(&pse);
			return - 1;
		} /* switch */
	}

	key->pse_sel = pse;
	if (sec_gen_key(key, replace) < 0) {
		aux_add_error(err_stack->e_number, "sec_gen_key failed", key->pse_sel, PSESel_n, proc);
                aux_free_PSESel(&pse);
		return - 1;
	}
        aux_free_PSESel(&pse);


	return (0);
}



AlgId *af_pse_get_signAI()
{
	PSESel	  pse;
	Key       skey;
        KeyInfo * keyinfo;
        KeyInfo * get_keyinfo_from_key();
        AlgId   * algid;
	Boolean   onekeypaironly = FALSE;

	char	* proc = "af_pse_get_signAI";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	skey.key = (KeyInfo *) 0;
	skey.keyref = 0;
	skey.pse_sel = &pse;
	pse.app_name = AF_pse.app_name;
	pse.pin      = AF_pse.pin;

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (NULLALGID);
	}

	if(onekeypaironly == TRUE){
		pse.object.name = SKnew_name;
		pse.object.pin = getobjectpin(SKnew_name);
	}
	else{
		pse.object.name = SignSK_name;
		pse.object.pin = getobjectpin(SignSK_name);
	}

        algid = NULLALGID;
        if((keyinfo = get_keyinfo_from_key(&skey))) {
                algid = aux_cpy_AlgId(keyinfo->subjectAI);
                aux_free_KeyInfo(&keyinfo);
        }
/*
        else aux_add_error(EOBJNAME, "can't get AlgId from SignSK", CNULL, 0, proc);
*/
	return(algid);
}


/***************************************************************************************
 *                                     getobjectpin                                    *
 ***************************************************************************************/

/*
 *  given: object name from AF_pse
 *  returns: object pin from AF_pse
 */

char	* getobjectpin(objectname)
char	* objectname;
{
	PSESel         * pse_sel;
	ObjId          * oid;
	register int	 i;
	char	       * proc = "getobjectpin";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	for (i = 0; i < PSE_MAXOBJ; i++)
		if (strcmp(objectname, AF_pse.object[i].name) == 0) {
			if (!AF_pse.object[i].pin) {
				oid = af_get_objoid(objectname);
				if(!(pse_sel = af_pse_open(oid, FALSE))) {
					aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
					return (CNULL);
				}
				if (!pse_sel->object.pin) {
					aux_free_PSESel(&pse_sel);
					return (CNULL);
				}
				aux_free_PSESel(&pse_sel);
				return (AF_pse.object[i].pin);
			}
			else return(AF_pse.object[i].pin);
		}

	return (CNULL);
}


/***************************************************************************************
 *                                     setobjectpin                                    *
 ***************************************************************************************/

/*
 *  given: object name from AF_pse and new pin
    action: set new pin for object in AF_pse
 *  returns: 0 or 1
 */

RC setobjectpin(objectname, newpin)
char	*objectname, *newpin;
{
	register  int	i;
	char	* proc = "setobjectpin";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	for (i = 0; i < PSE_MAXOBJ; i++) {
		if (strcmp(objectname, AF_pse.object[i].name) == 0) {
			AF_pse.object[i].pin = (char *)malloc(strlen(newpin) + 1);
			if (!AF_pse.object[i].pin ) {
				aux_add_error(EMALLOC, "AF_pse.object[i].pin", CNULL, 0, proc);
				return(1);
			}
			strcpy(AF_pse.object[i].pin, newpin);
			return(0);
		}
	}
	return(1);
}



/*******************************************************************************
 *                         af_check_if_onekeypaironly                          *
 *******************************************************************************/

RC
af_check_if_onekeypaironly(onekeypaironly)
Boolean * onekeypaironly;
{
	PSEToc  	* psetoc = (PSEToc * )0;
	PSESel          * psesel;
	int             SCapp_available;
	char            * proc = "af_check_if_onekeypaironly";


	if(! onekeypaironly){
		aux_add_error(EINVALID, "No parameter provided", CNULL, 0, proc);
		return(- 1);
	}

	if(!(psesel = af_pse_open(NULLOBJID, FALSE))) {
		aux_add_error(LASTERROR, "af_pse_open failed", CNULL, 0, proc);
		return(- 1);
	}

#ifdef SCA
	/* If SC available, try to read SC Toc */

	if((SCapp_available = sec_sctest(psesel->app_name)) == -1) {
		if (aux_last_error() == EOPENDEV) 
			aux_add_error(EOPENDEV, "Cannot open device for SCT (No such device or device busy).", CNULL, 0, proc);
		else
			aux_add_error(ECONFIG, "Error during SC configuration.", CNULL, 0, proc);
		return (-1);
	}

	if(SCapp_available == TRUE) {
		psetoc = chk_SCToc(psesel);
	}
#endif

	/* If no SCToc available, try to read SW-PSE Toc  */

	if (!(psetoc)) {
		if (!(psetoc = chk_toc(psesel, FALSE))) {
		        aux_add_error(EREADPSE, "Can't read Toc", psesel, PSESel_n, proc);
			return(- 1);
		}
	}


	if(psetoc->status & ONEKEYPAIRONLY) 
		* onekeypaironly = TRUE;
	else 
		* onekeypaironly = FALSE;

	return(0);
}

int
af_pse_incr_serial()
{
	SerialNumbers * serialnums;
	char          * proc = "af_pse_incr_serial";

	/* increments serial number (actual) and returns new value */

	serialnums = af_pse_get_SerialNumbers();
	if(! serialnums || serialnums->actual < 0 || (serialnums->actual < serialnums->initial)){
		aux_add_error(EDAMAGE, "af_pse_get_SerialNumbers returned negative serial number", CNULL, 0, proc);
		return(-1);
	}
	serialnums->actual ++;
	if(af_pse_update_SerialNumbers(serialnums) < 0){
		aux_add_error(EWRITEPSE, "af_pse_update_SerialNumbers failed", CNULL, 0, proc);
		return(-1);
	}

	return(serialnums->actual);
}



