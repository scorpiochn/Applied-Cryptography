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

#include "secude-stub.h"

/********************** IF Section **********************/

void    aux_free2_Attr(attr)
register Attr * attr;
{
	char	 * proc = "aux_free2_Attr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(attr){
		aux_free_ObjId(((ObjId **)& (attr->type)) );
		if(attr->values)
			aux_free_type_IF_AttributeValues(&(attr->values));
	}
	return;
}


void    aux_free_Attr(attr)
Attr ** attr;
{
	char	 * proc = "aux_free_Attr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(attr && * attr){
		aux_free2_Attr(* attr);
		free(* attr);
		* attr = (Attr * )0;
	}
	return;
}


void    aux_free_type_IF_AttributeValues(set)
struct type_IF_AttributeValues ** set;
{
	register struct type_IF_AttributeValues * eptr;
	register struct type_IF_AttributeValues * next;

	char * proc = "aux_free_type_IF_AttributeValues";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (struct type_IF_AttributeValues * )0; eptr = next){
			next = eptr->next;
			if(eptr->member_IF_1) pe_free(eptr->member_IF_1);
			free((char * )eptr);
			eptr = (struct type_IF_AttributeValues * )0;
		}
	}
	return;
}


void    aux_free_SET_OF_Attr(set)
SET_OF_Attr ** set;
{
	register SET_OF_Attr * eptr;
	register SET_OF_Attr * next;

	char * proc = "aux_free_SET_OF_Attr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_Attr * )0; eptr = next){
			next = eptr->next;
			aux_free_Attr(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_Attr * )0;
		}
	}
	return;
}


void    aux_free2_AttrAttrTypeCHOICE(choice)
register AttrAttrTypeCHOICE * choice;
{
	char	 * proc = "aux_free2_AttrAttrTypeCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(choice){
		if(choice->offset == 1)
			aux_free_ObjId(&(choice->choice_un.choice_un_attrtype));
		else aux_free_SET_OF_Attr(&(choice->choice_un.choice_un_attr));
	}
	return;
}


void    aux_free_AttrAttrTypeCHOICE(choice)
AttrAttrTypeCHOICE ** choice;
{
	char	 * proc = "aux_free_AttrAttrTypeCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(choice && * choice){
		aux_free2_AttrAttrTypeCHOICE(* choice);
		free(* choice);
		* choice = (AttrAttrTypeCHOICE * )0;
	}
	return;
}


void    aux_free_SET_OF_AttrAttrTypeCHOICE(set)
SET_OF_AttrAttrTypeCHOICE ** set;
{
	register SET_OF_AttrAttrTypeCHOICE * eptr;
	register SET_OF_AttrAttrTypeCHOICE * next;

	char * proc = "aux_free_SET_OF_AttrAttrTypeCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_AttrAttrTypeCHOICE * )0; eptr = next){
			next = eptr->next;
			aux_free_AttrAttrTypeCHOICE(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_AttrAttrTypeCHOICE * )0;
		}
	}
	return;
}


void    aux_free2_Ava(ava)
register struct type_IF_AttributeValueAssertion * ava;
{
	char	 * proc = "aux_free2_Ava";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ava){
		if(ava->element_IF_0)
			aux_free_ObjId(((ObjId ** )&(ava->element_IF_0)));
		if(ava->element_IF_1)
			pe_free(ava->element_IF_1);
	}
	return;
}


void    aux_free_Ava(ava)
struct type_IF_AttributeValueAssertion ** ava;
{
	char	 * proc = "aux_free_Ava";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ava && * ava){
		aux_free2_Ava(* ava);
		free(* ava);
		* ava = (struct type_IF_AttributeValueAssertion * )0;
	}
	return;
}


/******************* END of IF Section ******************/



void    aux_free2_EntryINFO(ent)
register EntryINFO * ent;
{
	char	 * proc = "aux_free2_EntryINFO";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ent){
		if(ent->ent_dn)
			aux_free_DName(&(ent->ent_dn));
		if(ent->ent_attr)
			aux_free_SET_OF_AttrAttrTypeCHOICE(&(ent->ent_attr));
	}
	return;
}


void    aux_free_EntryINFO(ent)
EntryINFO ** ent;
{
	char	 * proc = "aux_free_EntryINFO";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ent && * ent){
		aux_free2_EntryINFO(* ent);
		free(* ent);
		* ent = (EntryINFO * )0;
	}
	return;
}


void    aux_free_SET_OF_EntryINFO(set)
SET_OF_EntryINFO ** set;
{
	register SET_OF_EntryINFO * eptr;
	register SET_OF_EntryINFO * next;

	char * proc = "aux_free_SET_OF_EntryINFO";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_EntryINFO * )0; eptr = next){
			next = eptr->next;
			aux_free_EntryINFO(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_EntryINFO * )0;
		}
	}
	return;
}


void    aux_free_SET_OF_ObjId(set)
SET_OF_ObjId ** set;
{
	register SET_OF_ObjId * eptr;
	register SET_OF_ObjId * next;

	char * proc = "aux_free_SET_OF_ObjId";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_ObjId * )0; eptr = next){
			next = eptr->next;
			aux_free_ObjId(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_ObjId * )0;
		}
	}
	return;
}


void    aux_free2_EntryInfoSEL(eis)
register EntryInfoSEL * eis;
{
	char	 * proc = "aux_free2_EntryInfoSEL";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(eis){
		if(eis->eis_select)
			aux_free_SET_OF_ObjId(&(eis->eis_select));
	}
	return;
}


void    aux_free_EntryInfoSEL(eis)
EntryInfoSEL ** eis;
{
	char	 * proc = "aux_free_EntryInfoSEL";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(eis && * eis){
		aux_free2_EntryInfoSEL(* eis);
		free(* eis);
		* eis = (EntryInfoSEL * )0;
	}
	return;
}


void    aux_free2_SecurityParameters(sp)
register SecurityParameters * sp;
{
	char	 * proc = "aux_free2_SecurityParameters";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sp){
		if(sp->certPath)
			aux_free_CertificationPath(&(sp->certPath));
		if(sp->name)
			aux_free_DName(&(sp->name));
		if(sp->time) 
			free(sp->time);
		if(sp->random) 
			aux_free_BitString(&(sp->random));
	}
	return;
}


void    aux_free_SecurityParameters(sp)
SecurityParameters ** sp;
{
	char	 * proc = "aux_free_SecurityParameters";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sp && * sp){
		aux_free2_SecurityParameters(* sp);
		free(* sp);
		* sp = (SecurityParameters * )0;
	}
	return;
}


void    aux_free2_ServiceControls(sc)
register ServiceControls * sc;
{
	char	 * proc = "aux_free2_ServiceControls";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sc){
		if(sc->svc_tmp){
			free(sc->svc_tmp);
			sc->svc_tmp = CNULL;
		}
	}
	return;
}


void    aux_free_ServiceControls(sc)
ServiceControls ** sc;
{
	char	 * proc = "aux_free_ServiceControls";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sc && * sc){
		aux_free2_ServiceControls(* sc);
		free(* sc);
		* sc = (ServiceControls * )0;
	}
	return;
}


void    aux_free2_CommonArguments(ca)
register CommonArguments * ca;
{
	char	 * proc = "aux_free2_CommonArguments";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ca){
		if(ca->svc)
			aux_free_ServiceControls(&(ca->svc));
		if(ca->sec_parm)
			aux_free_SecurityParameters(&(ca->sec_parm));
		if(ca->requestor) 
			aux_free_DName(&(ca->requestor));
		if(ca->progress){
			free(ca->progress);
			ca->progress = (OperationProgress * )0;
		}
		if(ca->ext) 
			aux_free_SET_OF_SECExtension(&(ca->ext));
	}
	return;
}


void    aux_free_CommonArguments(ca)
CommonArguments ** ca;
{
	char	 * proc = "aux_free_CommonArguments";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(ca && * ca){
		aux_free2_CommonArguments(* ca);
		free(* ca);
		* ca = (CommonArguments * )0;
	}
	return;
}


void    aux_free2_CommonRes(cr)
register CommonRes * cr;
{
	char	 * proc = "aux_free2_CommonRes";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(cr){
		if(cr->sec_parm)
			aux_free_SecurityParameters(&(cr->sec_parm));
		if(cr->performer) 
			aux_free_DName(&(cr->performer));
	}
	return;
}


void    aux_free_CommonRes(cr)
CommonRes ** cr;
{
	char	 * proc = "aux_free_CommonRes";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(cr && * cr){
		aux_free2_CommonRes(* cr);
		free(* cr);
		* cr = (CommonRes * )0;
	}
	return;
}


void    aux_free2_SECExtension(secext)
register SECExtension * secext;
{
	char	 * proc = "aux_free2_SECExtension";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(secext){
		if(secext->ext_item) 
			pe_free(secext->ext_item);
	}
	return;
}


void    aux_free_SECExtension(secext)
SECExtension ** secext;
{
	char	 * proc = "aux_free_SECExtension";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(secext && * secext){
		aux_free2_SECExtension(* secext);
		free(* secext);
		* secext = (SECExtension * )0;
	}
	return;
}


void    aux_free_SET_OF_SECExtension(set)
SET_OF_SECExtension ** set;
{
	register SET_OF_SECExtension * eptr;
	register SET_OF_SECExtension * next;
	char	                     * proc = "aux_free_SET_OF_SECExtension";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_SECExtension * )0; eptr = next){
			next = eptr->next;
			aux_free_SECExtension(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_SECExtension * )0;
		}
	}
	return;
}


void    aux_free2_TokenTBS(tbs)
register TokenTBS * tbs;
{
	char	 * proc = "aux_free2_TokenTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		aux_free_AlgId(&(tbs->signatureAI));
		if(tbs->dname) 
			aux_free_DName(&(tbs->dname));
		if(tbs->time) 
			free(tbs->time);
		if(tbs->random)
			aux_free_BitString(&(tbs->random));
	}
	return;
}


void    aux_free_TokenTBS(tbs)
TokenTBS ** tbs;
{
	char	 * proc = "aux_free_TokenTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_TokenTBS(* tbs);
		free(* tbs);
		* tbs = (TokenTBS * )0;
	}
	return;
}


void    aux_free2_AddArgumentTBS(tbs)
register AddArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_AddArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->ada_object) 
			aux_free_DName(&(tbs->ada_object));
		if(tbs->ada_entry) 
			aux_free_SET_OF_Attr(&(tbs->ada_entry));
		if(tbs->ada_common) 
			aux_free_CommonArguments(&(tbs->ada_common));
	}
	return;
}


void    aux_free_AddArgumentTBS(tbs)
AddArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_AddArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_AddArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (AddArgumentTBS * )0;
	}
	return;
}


void    aux_free2_CompareArgumentTBS(tbs)
register CompareArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_CompareArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->cma_object) 
			aux_free_DName(&(tbs->cma_object));
		if(tbs->cma_purported)

		if(tbs->cma_common) 
			aux_free_CommonArguments(&(tbs->cma_common));
	}
	return;
}


void    aux_free_CompareArgumentTBS(tbs)
CompareArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_CompareArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_CompareArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (CompareArgumentTBS * )0;
	}
	return;
}


void    aux_free2_CompareResultTBS(tbs)
register CompareResultTBS * tbs;
{
	char	 * proc = "aux_free2_CompareResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->cmr_object) 
			aux_free_DName(&(tbs->cmr_object));
		if(tbs->cmr_common)
			aux_free_CommonRes(&(tbs->cmr_common));
	}
	return;
}


void    aux_free_CompareResultTBS(tbs)
CompareResultTBS ** tbs;
{
	char	 * proc = "aux_free_CompareResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_CompareResultTBS(* tbs);
		free(* tbs);
		* tbs = (CompareResultTBS * )0;
	}
	return;
}


void    aux_free2_ListArgumentTBS(tbs)
register ListArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_ListArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->object) 
			aux_free_DName(&(tbs->object));
		if(tbs->lsa_common) 
			aux_free_CommonArguments(&(tbs->lsa_common));
	}
	return;
}


void    aux_free_ListArgumentTBS(tbs)
ListArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_ListArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ListArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (ListArgumentTBS * )0;
	}
	return;
}


void    aux_free2_SubordEntry(sub)
register SubordEntry * sub;
{
	char	 * proc = "aux_free2_SubordEntry";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sub){
		if(sub->sub_rdn) 
			aux_free_RDName(&(sub->sub_rdn));
	}
	return;
}


void    aux_free_SubordEntry(sub)
SubordEntry ** sub;
{
	char	 * proc = "aux_free_SubordEntry";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(sub && * sub){
		aux_free2_SubordEntry(* sub);
		free(* sub);
		* sub = (SubordEntry * )0;
	}
	return;
}


void    aux_free_SET_OF_SubordEntry(set)
SET_OF_SubordEntry ** set;
{
	register SET_OF_SubordEntry * eptr;
	register SET_OF_SubordEntry * next;

	char * proc = "aux_free_SET_OF_SubordEntry";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_SubordEntry * )0; eptr = next){
			next = eptr->next;
			aux_free_SubordEntry(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_SubordEntry * )0;
		}
	}
	return;
}


void    aux_free2_ListInfo(info)
register ListInfo * info;
{
	char	 * proc = "aux_free2_ListInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(info){
		if(info->lsr_object) 
			aux_free_DName(&(info->lsr_object));
		if(info->lsr_subordinates) 
			aux_free_SET_OF_SubordEntry(&(info->lsr_subordinates));
		if(info->lsr_poq) 
			aux_free_PartialOutQual(&info->lsr_poq);
		if(info->lsr_common) 
			aux_free_CommonRes(&(info->lsr_common));
	}
	return;
}


void    aux_free_ListInfo(info)
ListInfo ** info;
{
	char	 * proc = "aux_free_ListInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(info && * info){
		aux_free2_ListInfo(* info);
		free(* info);
		* info = (ListInfo * )0;
	}
	return;
}


void    aux_free2_ListResultTBS(tbs)
register ListResultTBS * tbs;
{
	char	 * proc = "aux_free2_ListResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->lsr_type == 1)
			aux_free_ListInfo(&(tbs->lsrtbs_un.listinfo));
		else aux_free_SET_OF_ListResult(&(tbs->lsrtbs_un.uncorrel_listinfo));
	}
	return;
}


void    aux_free_ListResultTBS(tbs)
ListResultTBS ** tbs;
{
	char	 * proc = "aux_free_ListResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ListResultTBS(* tbs);
		free(* tbs);
		* tbs = (ListResultTBS * )0;
	}
	return;
}


void    aux_free2_EntryModification(em)
register EntryModification * em;
{
	char	 * proc = "aux_free2_EntryModification";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(em){
		switch(em->em_type){
		case EM_ADDATTRIBUTE:
			aux_free_Attr(&(em->em_un.em_un_attr));
			break;
		case EM_REMOVEATTRIBUTE:
			aux_free_ObjId(&(em->em_un.em_un_attrtype));
			break;
		case EM_ADDVALUES:
			aux_free_Attr(&(em->em_un.em_un_attr));
			break;
		case EM_REMOVEVALUES:
			aux_free_Attr(&(em->em_un.em_un_attr));
			break;
		default:
			aux_add_error(EINVALID, "em->em_type has bad value", CNULL, 0, proc);
			return;
		}
	}
	return;
}


void    aux_free_EntryModification(em)
EntryModification ** em;
{
	char	 * proc = "aux_free_EntryModification";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(em && * em){
		aux_free2_EntryModification(* em);
		free(* em);
		* em = (EntryModification * )0;
	}
	return;
}


void    aux_free_SEQUENCE_OF_EntryModification(set)
SEQUENCE_OF_EntryModification ** set;
{
	register SEQUENCE_OF_EntryModification * eptr;
	register SEQUENCE_OF_EntryModification * next;

	char * proc = "aux_free_SEQUENCE_OF_EntryModification";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SEQUENCE_OF_EntryModification * )0; eptr = next){
			next = eptr->next;
			aux_free_EntryModification(&(eptr->element));
			free((char * )eptr);
			eptr = (SEQUENCE_OF_EntryModification * )0;
		}
	}
	return;
}


void    aux_free2_ModifyEntryArgumentTBS(tbs)
register ModifyEntryArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_ModifyEntryArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->mea_common) 
			aux_free_CommonArguments(&(tbs->mea_common));
		if(tbs->mea_object) 
			aux_free_DName(&(tbs->mea_object));
		if(tbs->mea_changes) 
			aux_free_SEQUENCE_OF_EntryModification(&(tbs->mea_changes));
	}
	return;
}


void    aux_free_ModifyEntryArgumentTBS(tbs)
ModifyEntryArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_ModifyEntryArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ModifyEntryArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (ModifyEntryArgumentTBS * )0;
	}
	return;
}


void    aux_free2_ModifyRDNArgumentTBS(tbs)
register ModifyRDNArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_ModifyRDNArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->mra_object) 
			aux_free_DName(&(tbs->mra_object));
		if(tbs->mra_newrdn) 
			aux_free_RDName(&(tbs->mra_newrdn));
		if(tbs->mra_common) 
			aux_free_CommonArguments(&(tbs->mra_common));
	}
	return;
}


void    aux_free_ModifyRDNArgumentTBS(tbs)
ModifyRDNArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_ModifyRDNArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ModifyRDNArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (ModifyRDNArgumentTBS * )0;
	}
	return;
}


void    aux_free2_ReadArgumentTBS(tbs)
register ReadArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_ReadArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->rda_common) 
			aux_free_CommonArguments(&(tbs->rda_common));
		if(tbs->object) 
			aux_free_DName(&(tbs->object));
		if(tbs->rda_eis) 
			aux_free_EntryInfoSEL(&(tbs->rda_eis));
	}
	return;
}


void    aux_free_ReadArgumentTBS(tbs)
ReadArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_ReadArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ReadArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (ReadArgumentTBS * )0;
	}
	return;
}


void    aux_free2_ReadResultTBS(tbs)
register ReadResultTBS * tbs;
{
	char	 * proc = "aux_free2_ReadResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->rdr_entry) 
			aux_free_EntryINFO(&(tbs->rdr_entry));
		if(tbs->rdr_common) 
			aux_free_CommonRes(&(tbs->rdr_common));
	}
	return;
}


void    aux_free_ReadResultTBS(tbs)
ReadResultTBS ** tbs;
{
	char	 * proc = "aux_free_ReadResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_ReadResultTBS(* tbs);
		free(* tbs);
		* tbs = (ReadResultTBS * )0;
	}
	return;
}


void    aux_free2_RemoveArgumentTBS(tbs)
register RemoveArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_RemoveArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->rma_object) 
			aux_free_DName(&(tbs->rma_object));
		if(tbs->rma_common) 
			aux_free_CommonArguments(&(tbs->rma_common));
	}
	return;
}


void    aux_free_RemoveArgumentTBS(tbs)
RemoveArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_RemoveArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_RemoveArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (RemoveArgumentTBS * )0;
	}
	return;
}


void    aux_free_SET_OF_PE(set)
SET_OF_PE ** set;
{
	register SET_OF_PE * eptr;
	register SET_OF_PE * next;

	char * proc = "aux_free_SET_OF_PE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_PE * )0; eptr = next){
			next = eptr->next;
			pe_free(eptr->element);
			free((char * )eptr);
			eptr = (SET_OF_PE * )0;
		}
	}
	return;
}


void    aux_free_OperationProgress(op)
OperationProgress ** op;
{
	char	 * proc = "aux_free_OperationProgress";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(op && * op){
		free(* op);
		* op = (OperationProgress * )0;
	}
	return;
}


void    aux_free_SET_OF_OctetString(set)
SET_OF_OctetString ** set;
{
	register SET_OF_OctetString * eptr;
	register SET_OF_OctetString * next;

	char * proc = "aux_free_SET_OF_OctetString";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_OctetString * )0; eptr = next){
			next = eptr->next;
			aux_free_OctetString(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_OctetString * )0;
		}
	}
	return;
}


void    aux_free2_PSAPaddr(psap)
register typeDSE_PSAPaddr * psap;
{
	char	 * proc = "aux_free2_PSAPaddr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(psap){
		if (psap->pSelector.octets) 
			free(psap->pSelector.octets);
		if (psap->sSelector.octets) 
			free(psap->sSelector.octets);
		if (psap->tSelector.octets) 
			free(psap->tSelector.octets);
		if(psap->nAddress) 
			aux_free_SET_OF_OctetString(&(psap->nAddress));
	}
	return;
}


void    aux_free_PSAPaddr(psap)
typeDSE_PSAPaddr ** psap;
{
	char	 * proc = "aux_free_PSAPaddr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(psap && * psap){
		aux_free2_PSAPaddr(* psap);
		free(* psap);
		* psap = (typeDSE_PSAPaddr * )0;
	}
	return;
}


void    aux_free2_AccessPoint(accpoint)
register AccessPoint * accpoint;
{
	char	 * proc = "aux_free2_AccessPoint";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(accpoint){
		if(accpoint->ap_name) 
			aux_free_DName(&(accpoint->ap_name));
		if(accpoint->ap_address) 
			aux_free_PSAPaddr(&(accpoint->ap_address));
	}
	return;
}


void    aux_free_AccessPoint(accpoint)
AccessPoint ** accpoint;
{
	char	 * proc = "aux_free_AccessPoint";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(accpoint && * accpoint){
		aux_free2_AccessPoint(* accpoint);
		free(* accpoint);
		* accpoint = (AccessPoint * )0;
	}
	return;
}


void    aux_free_SET_OF_AccessPoint(set)
SET_OF_AccessPoint ** set;
{
	register SET_OF_AccessPoint * eptr;
	register SET_OF_AccessPoint * next;

	char * proc = "aux_free_SET_OF_AccessPoint";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_AccessPoint * )0; eptr = next){
			next = eptr->next;
			aux_free_AccessPoint(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_AccessPoint * )0;
		}
	}
	return;
}


void    aux_free2_ContReference(cref)
register ContReference * cref;
{
	char	 * proc = "aux_free2_ContReference";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(cref){
		if(cref->cr_name) 
			aux_free_DName(&(cref->cr_name));
		if(cref->cr_progress) 
			aux_free_OperationProgress(&(cref->cr_progress));
		if(cref->cr_accesspoints) 
			aux_free_SET_OF_AccessPoint(&cref->cr_accesspoints);
	}
	return;
}


void    aux_free_ContReference(cref)
ContReference ** cref;
{
	char	 * proc = "aux_free_ContReference";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(cref && * cref){
		aux_free2_ContReference(* cref);
		free(* cref);
		* cref = (ContReference * )0;
	}
	return;
}


void    aux_free_SET_OF_ContReference(set)
SET_OF_ContReference ** set;
{
	register SET_OF_ContReference * eptr;
	register SET_OF_ContReference * next;

	char * proc = "aux_free_SET_OF_ContReference";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_ContReference * )0; eptr = next){
			next = eptr->next;
			aux_free_ContReference(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_ContReference * )0;
		}
	}
	return;
}


void    aux_free2_PartialOutQual(poq)
register PartialOutQual * poq;
{
	char	 * proc = "aux_free2_PartialOutQual";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(poq){
		if(poq->poq_cref) 
			aux_free_SET_OF_ContReference(&(poq->poq_cref));
	}
	return;
}


void    aux_free_PartialOutQual(poq)
PartialOutQual ** poq;
{
	char	 * proc = "aux_free_PartialOutQual";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(poq && * poq){
		aux_free2_PartialOutQual(* poq);
		free(* poq);
		* poq = (PartialOutQual * )0;
	}
	return;
}


void    aux_free2_SearchInfo(info)
register SearchInfo * info;
{
	char	 * proc = "aux_free2_SearchInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(info){
		if(info->srr_object) 
			aux_free_DName(&(info->srr_object));
		if(info->srr_entries) 
			aux_free_SET_OF_EntryINFO(&(info->srr_entries));
		if(info->srr_poq) 
			aux_free_PartialOutQual(&info->srr_poq);
		if(info->srr_common) 
			aux_free_CommonRes(&(info->srr_common));
	}
	return;
}


void    aux_free_SearchInfo(info)
SearchInfo ** info;
{
	char	 * proc = "aux_free_SearchInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(info && * info){
		aux_free2_SearchInfo(* info);
		free(* info);
		* info = (SearchInfo * )0;
	}
	return;
}


void    aux_free2_SFilterSubstrings(substrgs)
register SFilterSubstrings * substrgs;
{
	char	 * proc = "aux_free2_SFilterSubstrings";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(substrgs){
		if(substrgs->type) 
			aux_free_ObjId(((ObjId ** )&(substrgs->type)));
		if(substrgs->seq) 
			aux_free_SEQUENCE_OF_StringsCHOICE(&(substrgs->seq));
	}
	return;
}


void    aux_free_SFilterSubstrings(substrgs)
SFilterSubstrings ** substrgs;
{
	char	 * proc = "aux_free_SFilterSubstrings";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(substrgs && * substrgs){
		aux_free2_SFilterSubstrings(* substrgs);
		free(* substrgs);
		* substrgs = (SFilterSubstrings * )0;
	}
	return;
}


void    aux_free2_SFilterItem(fi)
register SFilterItem * fi;
{
	char	 * proc = "aux_free2_SFilterItem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(fi){
		switch(fi->fi_type){
		case FILTERITEM_EQUALITY:
			aux_free_Ava(&(fi->fi_un.fi_un_ava));
			break;
		case FILTERITEM_SUBSTRINGS:
			aux_free_SFilterSubstrings(&(fi->fi_un.fi_un_substrings));
			break;
		case FILTERITEM_GREATEROREQUAL:
			aux_free_Ava(&(fi->fi_un.fi_un_ava));
			break;
		case FILTERITEM_LESSOREQUAL:
			aux_free_Ava(&(fi->fi_un.fi_un_ava));
			break;
		case FILTERITEM_PRESENT:
			aux_free_ObjId(((ObjId ** )&(fi->fi_un.fi_un_type)));
			break;
		case FILTERITEM_APPROX:
			aux_free_Ava(&(fi->fi_un.fi_un_ava));
			break;
		default:
			aux_add_error(EINVALID, "fi->fi_type has bad value", CNULL, 0, proc);
			return;
		}
	}
	return;
}


void    aux_free_SFilterItem(fi)
SFilterItem ** fi;
{
	char	 * proc = "aux_free_SFilterItem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(fi && * fi){
		aux_free2_SFilterItem(* fi);
		free(* fi);
		* fi = (SFilterItem * )0;
	}
	return;
}


void    aux_free2_SFilter(flt)
register SFilter * flt;
{
	char	 * proc = "aux_free2_SFilter";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(flt){
		switch(flt->flt_type){
		case FILTER_ITEM:
			aux_free_SFilterItem(&(flt->flt_un.flt_un_item));
			break;
		case FILTER_AND:
			aux_free_SET_OF_SFilter(&(flt->flt_un.flt_un_filterset));
			break;
		case FILTER_OR:
			aux_free_SET_OF_SFilter(&(flt->flt_un.flt_un_filterset));
			break;
		case FILTER_NOT:
			aux_free_SFilter(&(flt->flt_un.flt_un_filter));
			break;
		default:
			aux_add_error(EINVALID, "flt->flt_type has bad value", CNULL, 0, proc);
			return;
		}
	}
	return;
}


void    aux_free_SFilter(flt)
SFilter ** flt;
{
	char	 * proc = "aux_free_SFilter";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(flt && * flt){
		aux_free2_SFilter(* flt);
		free(* flt);
		* flt = (SFilter * )0;
	}
	return;
}


void    aux_free_SET_OF_SFilter(set)
SET_OF_SFilter ** set;
{
	register SET_OF_SFilter * eptr;
	register SET_OF_SFilter * next;

	char * proc = "aux_free_SET_OF_SFilter";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_SFilter * )0; eptr = next){
			next = eptr->next;
			aux_free_SFilter(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_SFilter * )0;
		}
	}
	return;
}


void    aux_free2_StringsCHOICE(choice)
register StringsCHOICE * choice;
{
	char	 * proc = "aux_free2_StringsCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(choice){
		switch(choice->strings_type){
		case STRINGS_INITIAL:
			pe_free(choice->strings_un.initial);
			break;
		case STRINGS_ANY:
			pe_free(choice->strings_un.any);
			break;
		case STRINGS_FINAL:
			pe_free(choice->strings_un.final);
			break;
		default:
			aux_add_error(EINVALID, "choice->strings_type has bad value", CNULL, 0, proc);
			return;
		}
	}
	return;
}


void    aux_free_StringsCHOICE(choice)
StringsCHOICE ** choice;
{
	char	 * proc = "aux_free_StringsCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(choice && * choice){
		aux_free2_StringsCHOICE(* choice);
		free(* choice);
		* choice = (StringsCHOICE * )0;
	}
	return;
}


void    aux_free_SEQUENCE_OF_StringsCHOICE(seq)
SEQUENCE_OF_StringsCHOICE ** seq;
{
	register SEQUENCE_OF_StringsCHOICE * eptr;
	register SEQUENCE_OF_StringsCHOICE * next;

	char * proc = "aux_free_SEQUENCE_OF_StringsCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(seq && * seq){
		for(eptr = * seq; eptr != (SEQUENCE_OF_StringsCHOICE * )0; eptr = next){
			next = eptr->next;
			aux_free_StringsCHOICE(&(eptr->element));
			free((char * )eptr);
			eptr = (SEQUENCE_OF_StringsCHOICE * )0;
		}
	}
	return;
}


void    aux_free2_SearchArgumentTBS(tbs)
register SearchArgumentTBS * tbs;
{
	char	 * proc = "aux_free2_SearchArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if(tbs->sra_common) 
			aux_free_CommonArguments(&(tbs->sra_common));
		if(tbs->baseobject) 
			aux_free_DName(&(tbs->baseobject));
		if(tbs->filter) 
			aux_free_SFilter(&(tbs->filter));
		if(tbs->sra_eis) 
			aux_free_EntryInfoSEL(&(tbs->sra_eis));
	}
	return;
}


void    aux_free_SearchArgumentTBS(tbs)
SearchArgumentTBS ** tbs;
{
	char	 * proc = "aux_free_SearchArgumentTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_SearchArgumentTBS(* tbs);
		free(* tbs);
		* tbs = (SearchArgumentTBS * )0;
	}
	return;
}


void    aux_free2_SearchResultTBS(tbs)
register SearchResultTBS * tbs;
{
	char	 * proc = "aux_free2_SearchResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs){
		if (tbs->srr_correlated == FALSE)
			aux_free_SET_OF_SearchResult(&(tbs->srrtbs_un.uncorrel_searchinfo));
		else
			aux_free_SearchInfo(&(tbs->srrtbs_un.searchinfo));
	}
	return;
}


void    aux_free_SearchResultTBS(tbs)
SearchResultTBS ** tbs;
{
	char	 * proc = "aux_free_SearchResultTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tbs && * tbs){
		aux_free2_SearchResultTBS(* tbs);
		free(* tbs);
		* tbs = (SearchResultTBS * )0;
	}
	return;
}


void    aux_free2_Token(tok)
register Token * tok;
{
	char	 * proc = "aux_free2_Token";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tok){
		if(tok->tbs_DERcode) 
			aux_free_OctetString(&(tok->tbs_DERcode));
		aux_free_TokenTBS(&(tok->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(tok->sig)));
	}
	return;
}


void    aux_free_Token(tok)
Token ** tok;
{
	char	 * proc = "aux_free_Token";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(tok && * tok){
		aux_free2_Token(* tok);
		free(* tok);
		* tok = (Token * )0;
	}
	return;
}


void    aux_free2_AddArgument(addarg)
register AddArgument * addarg;
{
	char	 * proc = "aux_free2_AddArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(addarg){
		if(addarg->tbs_DERcode) 
			aux_free_OctetString(&(addarg->tbs_DERcode));
		aux_free_AddArgumentTBS(&(addarg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(addarg->sig)));
	}
	return;
}


void    aux_free_AddArgument(addarg)
AddArgument ** addarg;
{
	char	 * proc = "aux_free_AddArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(addarg && * addarg){
		aux_free2_AddArgument(* addarg);
		free(* addarg);
		* addarg = (AddArgument * )0;
	}
	return;
}


void    aux_free2_CompareArgument(comparearg)
register CompareArgument * comparearg;
{
	char	 * proc = "aux_free2_CompareArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(comparearg){
		if(comparearg->tbs_DERcode) 
			aux_free_OctetString(&(comparearg->tbs_DERcode));
		aux_free_CompareArgumentTBS(&(comparearg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(comparearg->sig)));
	}
	return;
}


void    aux_free_CompareArgument(comparearg)
CompareArgument ** comparearg;
{
	char	 * proc = "aux_free_CompareArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(comparearg && * comparearg){
		aux_free2_CompareArgument(* comparearg);
		free(* comparearg);
		* comparearg = (CompareArgument * )0;
	}
	return;
}


void    aux_free2_CompareResult(compareres)
register CompareResult * compareres;
{
	char	 * proc = "aux_free2_CompareResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(compareres){
		if(compareres->tbs_DERcode) 
			aux_free_OctetString(&(compareres->tbs_DERcode));
		aux_free_CompareResultTBS(&(compareres->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(compareres->sig)));
	}
	return;
}


void    aux_free_CompareResult(compareres)
CompareResult ** compareres;
{
	char	 * proc = "aux_free_CompareResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(compareres && * compareres){
		aux_free2_CompareResult(* compareres);
		free(* compareres);
		* compareres = (CompareResult * )0;
	}
	return;
}


void    aux_free2_ListArgument(listarg)
register ListArgument * listarg;
{
	char	 * proc = "aux_free2_ListArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(listarg){
		if(listarg->tbs_DERcode) 
			aux_free_OctetString(&(listarg->tbs_DERcode));
		aux_free_ListArgumentTBS(&(listarg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(listarg->sig)));
	}
	return;
}


void    aux_free_ListArgument(listarg)
ListArgument ** listarg;
{
	char	 * proc = "aux_free_ListArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(listarg && * listarg){
		aux_free2_ListArgument(* listarg);
		free(* listarg);
		* listarg = (ListArgument * )0;
	}
	return;
}


void    aux_free2_ListResult(listres)
register ListResult * listres;
{
	char	 * proc = "aux_free2_ListResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(listres){
		if(listres->tbs_DERcode) 
			aux_free_OctetString(&(listres->tbs_DERcode));
		aux_free_ListResultTBS(&(listres->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(listres->sig)));
	}
	return;
}


void    aux_free_ListResult(listres)
ListResult ** listres;
{
	char	 * proc = "aux_free_ListResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(listres && * listres){
		aux_free2_ListResult(* listres);
		free(* listres);
		* listres = (ListResult * )0;
	}
	return;
}


void    aux_free_SET_OF_ListResult(set)
SET_OF_ListResult ** set;
{
	register SET_OF_ListResult * eptr;
	register SET_OF_ListResult * next;

	char * proc = "aux_free_SET_OF_ListResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_ListResult * )0; eptr = next){
			next = eptr->next;
			aux_free_ListResult(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_ListResult * )0;
		}
	}
	return;
}


void    aux_free2_ModifyEntryArgument(modifyentryarg)
register ModifyEntryArgument * modifyentryarg;
{
	char	 * proc = "aux_free2_ModifyEntryArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(modifyentryarg){
		if(modifyentryarg->tbs_DERcode) 
			aux_free_OctetString(&(modifyentryarg->tbs_DERcode));
		aux_free_ModifyEntryArgumentTBS(&(modifyentryarg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(modifyentryarg->sig)));
	}
	return;
}


void    aux_free_ModifyEntryArgument(modifyentryarg)
ModifyEntryArgument ** modifyentryarg;
{
	char	 * proc = "aux_free_ModifyEntryArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(modifyentryarg && * modifyentryarg){
		aux_free2_ModifyEntryArgument(* modifyentryarg);
		free(* modifyentryarg);
		* modifyentryarg = (ModifyEntryArgument * )0;
	}
	return;
}


void    aux_free2_ModifyRDNArgument(modifyrdnarg)
register ModifyRDNArgument * modifyrdnarg;
{
	char	 * proc = "aux_free2_ModifyRDNArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(modifyrdnarg){
		if(modifyrdnarg->tbs_DERcode) 
			aux_free_OctetString(&(modifyrdnarg->tbs_DERcode));
		aux_free_ModifyRDNArgumentTBS(&(modifyrdnarg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(modifyrdnarg->sig)));
	}
	return;
}


void    aux_free_ModifyRDNArgument(modifyrdnarg)
ModifyRDNArgument ** modifyrdnarg;
{
	char	 * proc = "aux_free_ModifyRDNArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(modifyrdnarg && * modifyrdnarg){
		aux_free2_ModifyRDNArgument(* modifyrdnarg);
		free(* modifyrdnarg);
		* modifyrdnarg = (ModifyRDNArgument * )0;
	}
	return;
}


void    aux_free2_ReadArgument(readarg)
register ReadArgument * readarg;
{
	char	 * proc = "aux_free2_ReadArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(readarg){
		if(readarg->tbs_DERcode) 
			aux_free_OctetString(&(readarg->tbs_DERcode));
		aux_free_ReadArgumentTBS(&(readarg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(readarg->sig)));
	}
	return;
}


void    aux_free_ReadArgument(readarg)
ReadArgument ** readarg;
{
	char	 * proc = "aux_free_ReadArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(readarg && * readarg){
		aux_free2_ReadArgument(* readarg);
		free(* readarg);
		* readarg = (ReadArgument * )0;
	}
	return;
}


void    aux_free2_ReadResult(readres)
register ReadResult * readres;
{
	char	 * proc = "aux_free2_ReadResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(readres){
		if(readres->tbs_DERcode) 
			aux_free_OctetString(&(readres->tbs_DERcode));
		aux_free_ReadResultTBS(&(readres->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(readres->sig)));
	}
	return;
}


void    aux_free_ReadResult(readres)
ReadResult ** readres;
{
	char	 * proc = "aux_free_ReadResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(readres && * readres){
		aux_free2_ReadResult(* readres);
		free(* readres);
		* readres = (ReadResult * )0;
	}
	return;
}


void    aux_free2_RemoveArgument(removearg)
register RemoveArgument * removearg;
{
	char	 * proc = "aux_free2_RemoveArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(removearg){
		if(removearg->tbs_DERcode) 
			aux_free_OctetString(&(removearg->tbs_DERcode));
		aux_free_RemoveArgumentTBS(&(removearg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(removearg->sig)));
	}
	return;
}


void    aux_free_RemoveArgument(removearg)
RemoveArgument ** removearg;
{
	char	 * proc = "aux_free_RemoveArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(removearg && * removearg){
		aux_free2_RemoveArgument(* removearg);
		free(* removearg);
		* removearg = (RemoveArgument * )0;
	}
	return;
}


void    aux_free2_SearchArgument(searcharg)
register SearchArgument * searcharg;
{
	char	 * proc = "aux_free2_SearchArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(searcharg){
		if(searcharg->tbs_DERcode) 
			aux_free_OctetString(&(searcharg->tbs_DERcode));
		aux_free_SearchArgumentTBS(&(searcharg->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(searcharg->sig)));
	}
	return;
}


void    aux_free_SearchArgument(searcharg)
SearchArgument ** searcharg;
{
	char	 * proc = "aux_free_SearchArgument";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(searcharg && * searcharg){
		aux_free2_SearchArgument(* searcharg);
		free(* searcharg);
		* searcharg = (SearchArgument * )0;
	}
	return;
}


void    aux_free2_SearchResult(searchres)
register SearchResult * searchres;
{
	char	 * proc = "aux_free2_SearchResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(searchres){
		if(searchres->tbs_DERcode) 
			aux_free_OctetString(&(searchres->tbs_DERcode));
		aux_free_SearchResultTBS(&(searchres->tbs));
		aux_free_KeyInfo(((KeyInfo ** )&(searchres->sig)));
	}
	return;
}


void    aux_free_SearchResult(searchres)
SearchResult ** searchres;
{
	char	 * proc = "aux_free_SearchResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(searchres && * searchres){
		aux_free2_SearchResult(* searchres);
		free(* searchres);
		* searchres = (SearchResult * )0;
	}
	return;
}


void    aux_free_SET_OF_SearchResult(set)
SET_OF_SearchResult ** set;
{
	register SET_OF_SearchResult * eptr;
	register SET_OF_SearchResult * next;

	char * proc = "aux_free_SET_OF_SearchResult";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(set && * set){
		for(eptr = * set; eptr != (SET_OF_SearchResult * )0; eptr = next){
			next = eptr->next;
			aux_free_SearchResult(&(eptr->element));
			free((char * )eptr);
			eptr = (SET_OF_SearchResult * )0;
		}
	}
	return;
}

#endif


#else
/* dummy */
strong_free_dummy() 
{
	return(0);
}

#endif
