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


#ifdef X500
#ifdef STRONG

#include "psap.h"
#include "osisec-stub.h"
#include "af.h"
#include "secude-stub.h"

#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/time.h>
#include "aux_time.h"

#include "x500as/AF-types.h"

#include "quipu/common.h"
#include "quipu/DAS-types.h"  /*for specifying the argument type*/

extern struct signature         * aux_SECUDEsign2QUIPUsign();
extern Signature                * aux_QUIPUsign2SECUDEsign();
extern Certificates             * aux_QUIPUcertlist2SECUDEocert();
extern PE 			  AlgId_enc();
extern DN 			  dn_dec();
extern UTCTime  		* get_date_of_expiry();



static struct certificate_list * certlist = (struct certificate_list * )0;
static 	AlgId                  * sig_alg;



/******************************/

/*static struct SecurityServices serv_secude = SECUDESERVICES;*/
struct SecurityServices serv_secude = SECUDESERVICES;

struct SecurityServices * use_serv_secude()
{
	return (&serv_secude);
}

/******************************/


struct signature * secudesigned(arg, type)
caddr_t      arg;
int          type;
{
	Token	                  * tok;
	struct ds_addentry_arg    * ds_addarg;
	struct ds_bind_arg        * ds_bindarg;
	struct ds_compare_arg     * ds_comparearg;
	struct ds_compare_result  * ds_compareres;
	struct ds_list_arg        * ds_listarg;
	struct ds_list_result     * ds_listres;
	struct ds_modifyentry_arg * ds_modifyentryarg;
	struct ds_modifyrdn_arg   * ds_modifyrdnarg;
	struct ds_read_arg        * ds_readarg;
	struct ds_read_result     * ds_readres;
	struct ds_removeentry_arg * ds_removearg;
	struct ds_search_arg      * ds_searcharg;
	struct ds_search_result   * ds_searchres;
	AddArgument	          * addarg;
	CompareArgument		  * comparearg;
	CompareResult		  * compareres;
	ListArgument	          * listarg;
	ListResult		  * listres;
	ModifyEntryArgument       * modifyentryarg;
	ModifyRDNArgument	  * modifyrdnarg;
	ReadArgument	          * readarg;
	ReadResult		  * readres;
	RemoveArgument		  * removearg;
	SearchArgument            * searcharg;
	SearchResult              * searchres;
	struct signature          * ret;
	char	                  * proc = "secudesigned";


	if(! arg )
		return((struct signature * )0);

	switch (type){

	case _ZTokenToSignDAS:
		ds_bindarg = (struct ds_bind_arg * )arg;

		tok = (Token * )malloc(sizeof(Token));
		if(! tok ){
			aux_add_error(EMALLOC, "tok", CNULL, 0, proc);
			return((struct signature * )0);
		}

		tok->tbs = aux_extract_TokenTBS_from_BindArg(ds_bindarg);
		if(! tok->tbs )
			return((struct signature * )0);

		if ((tok->tbs_DERcode = e_TokenTBS(tok->tbs))== NULLOCTETSTRING){
			aux_add_error(EENCODE, "e_TokenTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		tok->sig = (Signature * )malloc(sizeof(Signature));
		if (! tok->sig){
			aux_add_error(EMALLOC, "tok->sig", CNULL, 0, proc);
			return((struct signature * )0);
		}
		tok->sig->signAI = aux_cpy_AlgId(tok->tbs->signatureAI);
		if(af_sign(tok->tbs_DERcode, tok->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_Token (stderr, tok);

		ret = aux_SECUDEsign2QUIPUsign(tok->sig);
		aux_free_Token(&tok);

		break;

	case _ZAddEntryArgumentDataDAS:
		ds_addarg = (struct ds_addentry_arg * )arg;

		addarg = (AddArgument * )malloc(sizeof(AddArgument));
		if (! addarg) {
			aux_add_error(EMALLOC, "addarg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		addarg->tbs = aux_extract_AddArgumentTBS_from_AddArg(ds_addarg);
		if(! addarg->tbs )
			return((struct signature * )0);

		if ((addarg->tbs_DERcode = e_AddArgumentTBS(addarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_AddArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		addarg->sig = (Signature * )malloc(sizeof(Signature));
		if (! addarg->sig) {
			aux_add_error(EMALLOC, "addarg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		addarg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(addarg->tbs_DERcode, addarg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_AddArgument (stderr, addarg);

		ret = aux_SECUDEsign2QUIPUsign(addarg->sig);
		aux_free_AddArgument(&addarg);

		break;

	case _ZCompareArgumentDataDAS:
		ds_comparearg = (struct ds_compare_arg * )arg;

		comparearg = (CompareArgument * )malloc(sizeof(CompareArgument));
		if (! comparearg) {
			aux_add_error(EMALLOC, "comparearg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		comparearg->tbs = aux_extract_CompareArgumentTBS_from_CompareArg(ds_comparearg);
		if(! comparearg->tbs )
			return((struct signature * )0);

		if ((comparearg->tbs_DERcode = e_CompareArgumentTBS(comparearg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_CompareArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		comparearg->sig = (Signature * )malloc(sizeof(Signature));
		if (! comparearg->sig) {
			aux_add_error(EMALLOC, "comparearg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		comparearg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(comparearg->tbs_DERcode, comparearg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_CompareArgument (stderr, comparearg);

		ret = aux_SECUDEsign2QUIPUsign(comparearg->sig);
		aux_free_CompareArgument(&comparearg);

		break;

	case _ZCompareResultDataDAS:
		ds_compareres = (struct ds_compare_result * ) arg;

		compareres = (CompareResult * )malloc(sizeof(CompareResult));
		if (! compareres) {
			aux_add_error(EMALLOC, "compareres", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		compareres->tbs = aux_extract_CompareResultTBS_from_CompareRes(ds_compareres);
		if(! compareres->tbs )
			return((struct signature * )0);

		if ((compareres->tbs_DERcode = e_CompareResultTBS(compareres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_CompareResultTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		compareres->sig = (Signature * )malloc(sizeof(Signature));
		if (! compareres->sig) {
			aux_add_error(EMALLOC, "compareres->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		compareres->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(compareres->tbs_DERcode, compareres->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_CompareResult (stderr, compareres);

		ret = aux_SECUDEsign2QUIPUsign(compareres->sig);
		aux_free_CompareResult(&compareres);

		break;

	case _ZListArgumentDataDAS:
		ds_listarg = (struct ds_list_arg * )arg;

		listarg = (ListArgument * )malloc(sizeof(ListArgument));
		if (! listarg) {
			aux_add_error(EMALLOC, "listarg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		listarg->tbs = aux_extract_ListArgumentTBS_from_ListArg(ds_listarg);
		if(! listarg->tbs )
			return((struct signature * )0);

		if ((listarg->tbs_DERcode = e_ListArgumentTBS(listarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ListArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		listarg->sig = (Signature * )malloc(sizeof(Signature));
		if (!listarg->sig) {
			aux_add_error(EMALLOC, "listarg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		listarg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(listarg->tbs_DERcode, listarg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ListArgument (stderr, listarg);

		ret = aux_SECUDEsign2QUIPUsign(listarg->sig);
		aux_free_ListArgument(&listarg);

		break;

	case _ZListResultDataDAS:
		ds_listres = (struct ds_list_result * ) arg;

		listres = (ListResult * )malloc(sizeof(ListResult));
		if (! listres) {
			aux_add_error(EMALLOC, "listres", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		listres->tbs = aux_extract_ListResultTBS_from_ListRes(ds_listres);
		if(! listres->tbs )
			return((struct signature * )0);

		if ((listres->tbs_DERcode = e_ListResultTBS(listres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ListResultTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		listres->sig = (Signature * )malloc(sizeof(Signature));
		if (!listres->sig) {
			aux_add_error(EMALLOC, "listres->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		listres->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(listres->tbs_DERcode, listres->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ListResult (stderr, listres);

		ret = aux_SECUDEsign2QUIPUsign(listres->sig);
		aux_free_ListResult(&listres);

		break;

	case _ZModifyEntryArgumentDataDAS:
		ds_modifyentryarg = (struct ds_modifyentry_arg * ) arg;

		modifyentryarg = (ModifyEntryArgument * )malloc(sizeof(ModifyEntryArgument));
		if (! modifyentryarg) {
			aux_add_error(EMALLOC, "modifyentryarg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		modifyentryarg->tbs = aux_extract_ModifyEntryArgumentTBS_from_ModifyEntryArg(ds_modifyentryarg);
		if(! modifyentryarg->tbs )
			return((struct signature * )0);

		if ((modifyentryarg->tbs_DERcode = e_ModifyEntryArgumentTBS(modifyentryarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ModifyEntryArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		modifyentryarg->sig = (Signature * )malloc(sizeof(Signature));
		if (! modifyentryarg->sig) {
			aux_add_error(EMALLOC, "modifyentryarg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		modifyentryarg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(modifyentryarg->tbs_DERcode, modifyentryarg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ModifyEntryArgument (stderr, modifyentryarg);

		ret = aux_SECUDEsign2QUIPUsign(modifyentryarg->sig);
		aux_free_ModifyEntryArgument(&modifyentryarg);

		break;

	case _ZModifyRDNArgumentDataDAS:
		ds_modifyrdnarg = (struct ds_modifyrdn_arg * )arg;

		modifyrdnarg = (ModifyRDNArgument * )malloc(sizeof(ModifyRDNArgument));
		if (! modifyrdnarg) {
			aux_add_error(EMALLOC, "modifyrdnarg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		modifyrdnarg->tbs = aux_extract_ModifyRDNArgumentTBS_from_ModifyRDNArg(ds_modifyrdnarg);
		if(! modifyrdnarg->tbs )
			return((struct signature * )0);

		if ((modifyrdnarg->tbs_DERcode = e_ModifyRDNArgumentTBS(modifyrdnarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ModifyRDNArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		modifyrdnarg->sig = (Signature * )malloc(sizeof(Signature));
		if (! modifyrdnarg->sig) {
			aux_add_error(EMALLOC, "modifyrdnarg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		modifyrdnarg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(modifyrdnarg->tbs_DERcode, modifyrdnarg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ModifyRDNArgument (stderr, modifyrdnarg);

		ret = aux_SECUDEsign2QUIPUsign(modifyrdnarg->sig);
		aux_free_ModifyRDNArgument(&modifyrdnarg);

		break;

	case _ZReadArgumentDataDAS:
		ds_readarg = (struct ds_read_arg * )arg;

		readarg = (ReadArgument * )malloc(sizeof(ReadArgument));
		if (! readarg) {
			aux_add_error(EMALLOC, "readarg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		readarg->tbs = aux_extract_ReadArgumentTBS_from_ReadArg(ds_readarg);
		if(! readarg->tbs )
			return((struct signature * )0);

		if ((readarg->tbs_DERcode = e_ReadArgumentTBS(readarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ReadArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		readarg->sig = (Signature * )malloc(sizeof(Signature));
		if (! readarg->sig) {
			aux_add_error(EMALLOC, "readarg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		readarg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(readarg->tbs_DERcode, readarg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ReadArgument (stderr, readarg);

		ret = aux_SECUDEsign2QUIPUsign(readarg->sig);
		aux_free_ReadArgument(&readarg);

		break;

	case _ZReadResultDataDAS:
		ds_readres = (struct ds_read_result * )arg;

		readres = (ReadResult * )malloc(sizeof(ReadResult));
		if (! readres) {
			aux_add_error(EMALLOC, "readres", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		readres->tbs = aux_extract_ReadResultTBS_from_ReadRes(ds_readres);
		if(! readres->tbs )
			return((struct signature * )0);

		if ((readres->tbs_DERcode = e_ReadResultTBS(readres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ReadResultTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		readres->sig = (Signature * )malloc(sizeof(Signature));
		if (! readres->sig) {
			aux_add_error(EMALLOC, "readres->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		readres->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(readres->tbs_DERcode, readres->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_ReadResult (stderr, readres);

		ret = aux_SECUDEsign2QUIPUsign(readres->sig);
		aux_free_ReadResult(&readres);

		break;

	case _ZRemoveEntryArgumentDataDAS:
		ds_removearg = (struct ds_removeentry_arg * )arg;

		removearg = (RemoveArgument * )malloc(sizeof(RemoveArgument));
		if (! removearg) {
			aux_add_error(EMALLOC, "removearg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		removearg->tbs = aux_extract_RemoveArgumentTBS_from_RemoveArg(ds_removearg);
		if(! removearg->tbs )
			return((struct signature * )0);

		if ((removearg->tbs_DERcode = e_RemoveArgumentTBS(removearg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_RemoveArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		removearg->sig = (Signature * )malloc(sizeof(Signature));
		if (! removearg->sig) {
			aux_add_error(EMALLOC, "removearg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		removearg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(removearg->tbs_DERcode, removearg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_RemoveArgument(stderr, removearg);

		ret = aux_SECUDEsign2QUIPUsign(removearg->sig);
		aux_free_RemoveArgument(&removearg);

		break;

	case _ZSearchArgumentDataDAS:
		ds_searcharg = (struct ds_search_arg * )arg;

		searcharg = (SearchArgument * )malloc(sizeof(SearchArgument));
		if (! searcharg) {
			aux_add_error(EMALLOC, "searcharg", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		searcharg->tbs = aux_extract_SearchArgumentTBS_from_SearchArg(ds_searcharg);
		if(! searcharg->tbs )
			return((struct signature * )0);

		if ((searcharg->tbs_DERcode = e_SearchArgumentTBS(searcharg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_SearchArgumentTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		searcharg->sig = (Signature * )malloc(sizeof(Signature));
		if (! searcharg->sig) {
			aux_add_error(EMALLOC, "searcharg->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		searcharg->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(searcharg->tbs_DERcode, searcharg->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_SearchArgument(stderr, searcharg);

		ret = aux_SECUDEsign2QUIPUsign(searcharg->sig);
		aux_free_SearchArgument(&searcharg);

		break;

	case _ZSearchResultDataDAS:
		ds_searchres = (struct ds_search_result * )arg;

		searchres = (SearchResult * )malloc(sizeof(SearchResult));
		if (! searchres) {
			aux_add_error(EMALLOC, "searchres", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		searchres->tbs = aux_extract_SearchResultTBS_from_SearchRes(ds_searchres);
		if(! searchres->tbs )
			return((struct signature * )0);

		if ((searchres->tbs_DERcode = e_SearchResultTBS(searchres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_SearchResultTBS failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		searchres->sig = (Signature * )malloc(sizeof(Signature));
		if (! searchres->sig) {
			aux_add_error(EMALLOC, "searchres->sig", CNULL, 0, proc);
			return((struct signature * ) 0);
		}

		if(! sig_alg){
			sig_alg = af_pse_get_signAI();
			if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
				sig_alg = aux_cpy_AlgId(md2WithRsa);
		}
		searchres->sig->signAI = aux_cpy_AlgId(sig_alg);

		if(af_sign(searchres->tbs_DERcode, searchres->sig, END) < 0 ){
			aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
			return((struct signature * )0);
		}

		if(af_verbose) strong_fprint_SearchResult (stderr, searchres);

		ret = aux_SECUDEsign2QUIPUsign(searchres->sig);
		aux_free_SearchResult(&searchres);

		break;

	}  /* switch */


	return (ret);
}


int secudeverify()
{



}


int secude_ckpath(arg, quipu_cpath, quipu_sig, nameptr, type)
caddr_t     	          arg;
struct certificate_list * quipu_cpath;
struct signature        * quipu_sig;	
DN 	  	        * nameptr;  /* pointer(pointer) */
int 	  	          type;                
{

	Certificates              * or_cert;
	CertificationPath         * SECUDEcpath = (CertificationPath * )0;
	Token 	                  * tok;
	PE                          pe;
	int			    rc;
	struct ds_addentry_arg    * ds_addarg;
	struct ds_bind_arg        * ds_bindarg;
	struct ds_compare_arg     * ds_comparearg;
	struct ds_compare_result  * ds_compareres;
	struct ds_list_arg        * ds_listarg;
	struct ds_list_result     * ds_listres;
	struct ds_modifyentry_arg * ds_modifyentryarg;
	struct ds_modifyrdn_arg   * ds_modifyrdnarg;
	struct ds_read_arg        * ds_readarg;
	struct ds_read_result     * ds_readres;
	struct ds_removeentry_arg * ds_removearg;
	struct ds_search_arg      * ds_searcharg;
	struct ds_search_result   * ds_searchres;
	AddArgument	          * addarg;
	CompareArgument		  * comparearg;
	CompareResult		  * compareres;
	ListArgument	          * listarg;
	ListResult		  * listres;
	ModifyEntryArgument       * modifyentryarg;
	ModifyRDNArgument	  * modifyrdnarg;
	ReadArgument	          * readarg;
	ReadResult		  * readres;
	RemoveArgument		  * removearg;
	SearchArgument            * searcharg;
	SearchResult              * searchres;

/***/
PS rps;
/***/
	char	           * proc = "secude_ckpath";

/***/
rps = ps_alloc(std_open);
std_setup(rps, stdout);
/***/


	if(! arg || ! quipu_cpath || ! quipu_sig )
		return(- 1);

	switch (type) {

	case _ZTokenToSignDAS:
		ds_bindarg = (struct ds_bind_arg * )arg;

		tok = (Token * )malloc(sizeof(Token));
		if(! tok ) {
			aux_add_error(EMALLOC, "tok", CNULL, 0, proc);
			return(- 1);
		}

		tok->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! tok->sig )
			return(- 1);

		tok->tbs = aux_extract_TokenTBS_from_BindArg(ds_bindarg);
		if(! tok->tbs )
			return(- 1);

		if ((tok->tbs_DERcode = e_TokenTBS(tok->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_TokenTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_Token(stderr, tok);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (tok->tbs_DERcode, tok->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);
		
		aux_free_Token(&tok);

		break;

	case _ZAddEntryArgumentDataDAS:
		ds_addarg = (struct ds_addentry_arg * )arg;

		addarg = (AddArgument * )malloc(sizeof(AddArgument));
		if(! addarg ) {
			aux_add_error(EMALLOC, "addarg", CNULL, 0, proc);
			return(- 1);
		}

		addarg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! addarg->sig )
			return(- 1);

		addarg->tbs = aux_extract_AddArgumentTBS_from_AddArg(ds_addarg);
		if(! addarg->tbs )
			return(- 1);

		if ((addarg->tbs_DERcode = e_AddArgumentTBS(addarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_AddArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_AddArgument(stderr, addarg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (addarg->tbs_DERcode, addarg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_AddArgument(&addarg);

		break;

	case _ZCompareArgumentDataDAS:
		ds_comparearg = (struct ds_compare_arg * )arg;

		comparearg = (CompareArgument * )malloc(sizeof(CompareArgument));
		if(! comparearg ) {
			aux_add_error(EMALLOC, "comparearg", CNULL, 0, proc);
			return(- 1);
		}

		comparearg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! comparearg->sig )
			return(- 1);

		comparearg->tbs = aux_extract_CompareArgumentTBS_from_CompareArg(ds_comparearg);
		if(! comparearg->tbs )
			return(- 1);

		if ((comparearg->tbs_DERcode = e_CompareArgumentTBS(comparearg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_CompareArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_CompareArgument(stderr, comparearg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (comparearg->tbs_DERcode, comparearg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_CompareArgument(&comparearg);

		break;

	case _ZCompareResultDataDAS:
		ds_compareres = (struct ds_compare_result * )arg;

		compareres = (CompareResult * )malloc(sizeof(CompareResult));
		if(! compareres ) {
			aux_add_error(EMALLOC, "compareres", CNULL, 0, proc);
			return(- 1);
		}

		compareres->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! compareres->sig )
			return(- 1);

		compareres->tbs = aux_extract_CompareResultTBS_from_CompareRes(ds_compareres);
		if(! compareres->tbs )
			return(- 1);

		if ((compareres->tbs_DERcode = e_CompareResultTBS(compareres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_CompareResultTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_CompareResult(stderr, compareres);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (compareres->tbs_DERcode, compareres->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_CompareResult(&compareres);

		break;

	case _ZListArgumentDataDAS:
		ds_listarg = (struct ds_list_arg * )arg;

		listarg = (ListArgument * )malloc(sizeof(ListArgument));
		if(! listarg ) {
			aux_add_error(EMALLOC, "listarg", CNULL, 0, proc);
			return(- 1);
		}

		listarg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! listarg->sig )
			return(- 1);

		listarg->tbs = aux_extract_ListArgumentTBS_from_ListArg(ds_listarg);
		if(!listarg->tbs )
			return(- 1);

		if ((listarg->tbs_DERcode = e_ListArgumentTBS(listarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ListArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ListArgument(stderr, listarg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (listarg->tbs_DERcode, listarg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ListArgument(&listarg);

		break;

	case _ZListResultDataDAS:
		ds_listres = (struct ds_list_result * )arg;

		listres = (ListResult * )malloc(sizeof(ListResult));
		if(!listres ) {
			aux_add_error(EMALLOC, "listres", CNULL, 0, proc);
			return(- 1);
		}

		listres->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! listres->sig )
			return(- 1);

		listres->tbs = aux_extract_ListResultTBS_from_ListRes(ds_listres);
		if(! listres->tbs )
			return(- 1);

		if ((listres->tbs_DERcode = e_ListResultTBS(listres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ListResultTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ListResult(stderr, listres);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (listres->tbs_DERcode, listres->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ListResult(&listres);

		break;

	case _ZModifyEntryArgumentDataDAS:
		ds_modifyentryarg = (struct ds_modifyentry_arg * )arg;

		modifyentryarg = (ModifyEntryArgument * )malloc(sizeof(ModifyEntryArgument));
		if(! modifyentryarg ) {
			aux_add_error(EMALLOC, "modifyentryarg", CNULL, 0, proc);
			return(- 1);
		}

		modifyentryarg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! modifyentryarg->sig )
			return(- 1);

		modifyentryarg->tbs = aux_extract_ModifyEntryArgumentTBS_from_ModifyEntryArg(ds_modifyentryarg);
		if(! modifyentryarg->tbs )
			return(- 1);

		if ((modifyentryarg->tbs_DERcode = e_ModifyEntryArgumentTBS(modifyentryarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ModifyEntryArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ModifyEntryArgument(stderr, modifyentryarg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (modifyentryarg->tbs_DERcode, modifyentryarg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ModifyEntryArgument(&modifyentryarg);

		break;

	case _ZModifyRDNArgumentDataDAS:
		ds_modifyrdnarg = (struct ds_modifyrdn_arg * )arg;

		modifyrdnarg = (ModifyRDNArgument * )malloc(sizeof(ModifyRDNArgument));
		if(! modifyrdnarg ) {
			aux_add_error(EMALLOC, "modifyrdnarg", CNULL, 0, proc);
			return(- 1);
		}

		modifyrdnarg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! modifyrdnarg->sig )
			return(- 1);

		modifyrdnarg->tbs = aux_extract_ModifyRDNArgumentTBS_from_ModifyRDNArg(ds_modifyrdnarg);
		if(! modifyrdnarg->tbs )
			return(- 1);

		if ((modifyrdnarg->tbs_DERcode = e_ModifyRDNArgumentTBS(modifyrdnarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ModifyRDNArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ModifyRDNArgument(stderr, modifyrdnarg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (modifyrdnarg->tbs_DERcode, modifyrdnarg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ModifyRDNArgument(&modifyrdnarg);

		break;

	case _ZReadArgumentDataDAS:
		ds_readarg = (struct ds_read_arg * )arg;

		readarg = (ReadArgument * )malloc(sizeof(ReadArgument));
		if(! readarg ) {
			aux_add_error(EMALLOC, "readarg", CNULL, 0, proc);
			return(- 1);
		}

		readarg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! readarg->sig )
			return(- 1);

		readarg->tbs = aux_extract_ReadArgumentTBS_from_ReadArg(ds_readarg);
		if(! readarg->tbs )
			return(- 1);

		if ((readarg->tbs_DERcode = e_ReadArgumentTBS(readarg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ReadArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ReadArgument(stderr, readarg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify(readarg->tbs_DERcode, readarg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ReadArgument(&readarg);

		break;

	case _ZReadResultDataDAS:
		ds_readres = (struct ds_read_result * )arg;

		readres = (ReadResult * )malloc(sizeof(ReadResult));
		if(! readres ) {
			aux_add_error(EMALLOC, "readres", CNULL, 0, proc);
			return(- 1);
		}

		readres->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! readres->sig )
			return(- 1);

		readres->tbs = aux_extract_ReadResultTBS_from_ReadRes(ds_readres);
		if(! readres->tbs )
			return(- 1);

		if ((readres->tbs_DERcode = e_ReadResultTBS(readres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_ReadResultTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_ReadResult(stderr, readres);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify(readres->tbs_DERcode, readres->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_ReadResult(&readres);

		break;

	case _ZRemoveEntryArgumentDataDAS:
		ds_removearg = (struct ds_removeentry_arg * )arg;

		removearg = (RemoveArgument * )malloc(sizeof(RemoveArgument));
		if(! removearg ) {
			aux_add_error(EMALLOC, "removearg", CNULL, 0, proc);
			return(- 1);
		}

		removearg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! removearg->sig )
			return(- 1);

		removearg->tbs = aux_extract_RemoveArgumentTBS_from_RemoveArg(ds_removearg);
		if(! removearg->tbs )
			return(- 1);

		if ((removearg->tbs_DERcode = e_RemoveArgumentTBS(removearg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_RemoveArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_RemoveArgument(stderr, removearg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify (removearg->tbs_DERcode, removearg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_RemoveArgument(&removearg);

		break;

	case _ZSearchArgumentDataDAS:
		ds_searcharg = (struct ds_search_arg * )arg;

		searcharg = (SearchArgument * )malloc(sizeof(SearchArgument));
		if(! searcharg ) {
			aux_add_error(EMALLOC, "searcharg", CNULL, 0, proc);
			return(- 1);
		}

		searcharg->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! searcharg->sig )
			return(- 1);

		searcharg->tbs = aux_extract_SearchArgumentTBS_from_SearchArg(ds_searcharg);
		if(! searcharg->tbs )
			return(- 1);

		if ((searcharg->tbs_DERcode = e_SearchArgumentTBS(searcharg->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_SearchArgumentTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_SearchArgument(stderr, searcharg);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify(searcharg->tbs_DERcode, searcharg->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_SearchArgument(&searcharg);

		break;

	case _ZSearchResultDataDAS:
		ds_searchres = (struct ds_search_result * )arg;

		searchres = (SearchResult * )malloc(sizeof(SearchResult));
		if(! searchres ) {
			aux_add_error(EMALLOC, "searchres", CNULL, 0, proc);
			return(- 1);
		}

		searchres->sig = aux_QUIPUsign2SECUDEsign(quipu_sig);
		if(! searchres->sig )
			return(- 1);

		searchres->tbs = aux_extract_SearchResultTBS_from_SearchRes(ds_searchres);
		if(! searchres->tbs )
			return(- 1);

		if ((searchres->tbs_DERcode = e_SearchResultTBS(searchres->tbs)) == NULLOCTETSTRING) {
			aux_add_error(EENCODE, "e_SearchResultTBS failed", CNULL, 0, proc);
			return(- 1);
		}

		if(af_verbose) strong_fprint_SearchResult(stderr, searchres);

		or_cert = aux_QUIPUcertlist2SECUDEocert(quipu_cpath);
		if(! or_cert )
			return(- 1);

		rc = af_verify(searchres->tbs_DERcode, searchres->sig, END, or_cert, CNULL, (PKRoot * )0);
		if(af_verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);

		aux_free_SearchResult(&searchres);

		break;

	}  /* switch */

	build_IF_Name(&pe, 1, 0, NULLCP, or_cert->usercertificate->tbs->subject);
	* nameptr = dn_dec(pe);
	if (pe)
		pe_free(pe);

	aux_free_Certificates(&or_cert);

	return(rc);
}



struct certificate_list *secude_mkpath()
{
	Certificates   * or_cert;
	char	       * proc = "secude_mkpath";


	if(! certlist){
		or_cert = af_pse_get_Certificates(SIGNATURE, NULLDNAME);
		certlist = aux_SECUDEocert2QUIPUcertlist(or_cert);
	}

	return (certlist);
}


struct encrypted *secudeencrypted()
{

}



int secudedecrypted()
{

}



struct Nonce *secudemknonce()
{
	struct Nonce   * ret;
	BitString      * random_bstr;
	struct alg_id  * quipu_alg;
	PE	         pe;
	int              i, nob, result;
	char	       * proc = "secudemknonce";


	if((ret = (struct Nonce * )malloc(sizeof(struct Nonce))) == (struct Nonce * )0) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return((struct Nonce * )0);
	}

	random_bstr = sec_random_bstr(64);

	ret->non_r1.n_bits = random_bstr->nbits;
	nob = ret->non_r1.n_bits / 8;
	if(ret->non_r1.n_bits % 8 )
		nob++;
	if((ret->non_r1.value = (char *)malloc(nob)) == (char * )0 ) {
		aux_add_error(EMALLOC, "ret->non_r1.value", CNULL, 0, proc);
		return((struct Nonce * )0);
	}
	for(i = 0; i < nob; i++) {
		ret->non_r1.value[i] = random_bstr->bits[i];
	}
	aux_free_BitString(&random_bstr);

	ret->non_r2.n_bits = 0;
	ret->non_r2.value = CNULL;

	ret->non_time1 = get_date_of_expiry();
	ret->non_time2 = CNULL;

	if(! sig_alg){
		sig_alg = af_pse_get_signAI();
		if(! sig_alg || aux_ObjId2AlgType(sig_alg->objid) == ASYM_ENC )
			sig_alg = aux_cpy_AlgId(md2WithRsa);
	}

	pe = AlgId_enc(sig_alg);
	result = decode_AF_AlgorithmIdentifier (pe, 0, NULLIP, NULLVP, &quipu_alg);
	pe_free(pe);
	if (result == NOTOK) {
		aux_add_error(EDECODE, "ret", CNULL, 0, proc);
		return((struct Nonce * )0);
	}
	alg_cpy(&(ret->non_alg), quipu_alg);

	return (ret);

}


int secudecknonce(nonce)
struct Nonce *nonce;
{
	char	     * proc = "secudecknonce";

	return 0;
}

#endif

#else
/* dummy */
secude_int_dummy() 
{
	return(0);
}

#endif

