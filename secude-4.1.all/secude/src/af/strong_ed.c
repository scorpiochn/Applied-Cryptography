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
#include "secude-stub.h"

OctetString         *aux_PE2OctetString(/* PE */);
PE                   aux_OctetString2PE(/* (OctetString *) */);


OctetString  * e_TokenTBS(token_tbs)
TokenTBS * token_tbs;
{
	PE             P_TBSToken;
	OctetString  * ret;

	if(! token_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_TokenTBS(&P_TBSToken, 1, 0, CNULL, token_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSToken);
	pe_free(P_TBSToken);

	return(ret);
}


OctetString     * e_AddArgumentTBS(addarg_tbs)
AddArgumentTBS * addarg_tbs;
{
	PE             P_TBSAddArgument;
	OctetString  * ret;

	if(! addarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_AddArgumentTBS(&P_TBSAddArgument, 1, 0, CNULL, addarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSAddArgument);
	pe_free(P_TBSAddArgument);

	return(ret);
}


OctetString     * e_CompareArgumentTBS(cmparg_tbs)
CompareArgumentTBS * cmparg_tbs;
{
	PE             P_TBSCompareArgument;
	OctetString  * ret;

	if(! cmparg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_CompareArgumentTBS(&P_TBSCompareArgument, 1, 0, CNULL, cmparg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSCompareArgument);
	pe_free(P_TBSCompareArgument);

	return(ret);
}


OctetString     * e_CompareResultTBS(cmpres_tbs)
CompareResultTBS * cmpres_tbs;
{
	PE             P_TBSCompareResult;
	OctetString  * ret;

	if(! cmpres_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_CompareResultTBS(&P_TBSCompareResult, 1, 0, CNULL, cmpres_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSCompareResult);
	pe_free(P_TBSCompareResult);

	return(ret);
}


OctetString  * e_ListArgumentTBS(listarg_tbs)
ListArgumentTBS * listarg_tbs;
{
	PE             P_TBSListArgument;
	OctetString  * ret;

	if(! listarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ListArgumentTBS(&P_TBSListArgument, 1, 0, CNULL, listarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSListArgument);
	pe_free(P_TBSListArgument);

	return(ret);
}


OctetString  * e_ListResultTBS(listres_tbs)
ListResultTBS * listres_tbs;
{
	PE             P_TBSListResult;
	OctetString  * ret;

	if(! listres_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ListResultTBS(&P_TBSListResult, 1, 0, CNULL, listres_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSListResult);
	pe_free(P_TBSListResult);

	return(ret);
}


OctetString  * e_ListResult(listres)
ListResult * listres;
{
	PE             P_ListResult;
	OctetString  * ret;

	if(! listres)
		return(NULLOCTETSTRING);

	if(build_STRONG_ListResult(&P_ListResult, 1, 0, CNULL, listres) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_ListResult);
	pe_free(P_ListResult);

	return(ret);
}


OctetString     * e_ModifyEntryArgumentTBS(modarg_tbs)
ModifyEntryArgumentTBS * modarg_tbs;
{
	PE             P_TBSModifyEntryArgument;
	OctetString  * ret;

	if(! modarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ModifyEntryArgumentTBS(&P_TBSModifyEntryArgument, 1, 0, CNULL, modarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSModifyEntryArgument);
	pe_free(P_TBSModifyEntryArgument);

	return(ret);
}


OctetString     * e_ModifyRDNArgumentTBS(modrdnarg_tbs)
ModifyRDNArgumentTBS * modrdnarg_tbs;
{
	PE             P_TBSModifyRDNArgument;
	OctetString  * ret;

	if(! modrdnarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ModifyRDNArgumentTBS(&P_TBSModifyRDNArgument, 1, 0, CNULL, modrdnarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSModifyRDNArgument);
	pe_free(P_TBSModifyRDNArgument);

	return(ret);
}


OctetString     * e_ReadArgumentTBS(readarg_tbs)
ReadArgumentTBS * readarg_tbs;
{
	PE             P_TBSReadArgument;
	OctetString  * ret;

	if(! readarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ReadArgumentTBS(&P_TBSReadArgument, 1, 0, CNULL, readarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSReadArgument);
	pe_free(P_TBSReadArgument);

	return(ret);
}


OctetString     * e_ReadResultTBS(readres_tbs)
ReadResultTBS * readres_tbs;
{
	PE             P_TBSReadResult;
	OctetString  * ret;

	if(! readres_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_ReadResultTBS(&P_TBSReadResult, 1, 0, CNULL, readres_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSReadResult);
	pe_free(P_TBSReadResult);

	return(ret);
}


OctetString     * e_RemoveArgumentTBS(remarg_tbs)
RemoveArgumentTBS * remarg_tbs;
{
	PE             P_TBSRemoveArgument;
	OctetString  * ret;

	if(! remarg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_RemoveArgumentTBS(&P_TBSRemoveArgument, 1, 0, CNULL, remarg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSRemoveArgument);
	pe_free(P_TBSRemoveArgument);

	return(ret);
}


OctetString     * e_SearchArgumentTBS(searcharg_tbs)
SearchArgumentTBS * searcharg_tbs;
{
	PE             P_TBSSearchArgument;
	OctetString  * ret;

	if(! searcharg_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_SearchArgumentTBS(&P_TBSSearchArgument, 1, 0, CNULL, searcharg_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSSearchArgument);
	pe_free(P_TBSSearchArgument);

	return(ret);
}


OctetString     * e_SearchResultTBS(searchres_tbs)
SearchResultTBS * searchres_tbs;
{
	PE             P_TBSSearchResult;
	OctetString  * ret;

	if(! searchres_tbs)
		return(NULLOCTETSTRING);

	if(build_STRONG_SearchResultTBS(&P_TBSSearchResult, 1, 0, CNULL, searchres_tbs) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_TBSSearchResult);
	pe_free(P_TBSSearchResult);

	return(ret);
}


OctetString * e_SearchResult(searchres)
SearchResult * searchres;
{
	PE             P_SearchResult;
	OctetString  * ret;

	if(! searchres)
		return(NULLOCTETSTRING);

	if(build_STRONG_SearchResult(&P_SearchResult, 1, 0, CNULL, searchres) == NOTOK)
		return(NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_SearchResult);
	pe_free(P_SearchResult);

	return(ret);
}


OctetString  * e_SECExtension(secext)
SECExtension  * secext;
{
	PE                 P_SecExt;
	OctetString      * ret;
	char	   	 * proc = "e_SECExtension";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! secext)
		return (NULLOCTETSTRING);

	if (build_STRONG_SECExtension(&P_SecExt, 1, 0, CNULL, secext) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_SecExt);
	pe_free(P_SecExt);

	return (ret);
}


OctetString  * e_AttrAttrTypeCHOICE(choice)
AttrAttrTypeCHOICE  * choice;
{
	PE                 P_CHOICE;
	OctetString      * ret;
	char	   	 * proc = "e_AttrAttrTypeCHOICE";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! choice)
		return (NULLOCTETSTRING);

	if (build_STRONG_AttrAttrTypeCHOICE(&P_CHOICE, 1, 0, CNULL, choice) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_CHOICE);
	pe_free(P_CHOICE);

	return (ret);
}


OctetString  * e_EntryINFO(einfo)
EntryINFO  * einfo;
{
	PE                 P_EntryInfo;
	OctetString      * ret;
	char	   	 * proc = "e_EntryINFO";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! einfo)
		return (NULLOCTETSTRING);

	if (build_STRONG_EntryINFO(&P_EntryInfo, 1, 0, CNULL, einfo) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_EntryInfo);
	pe_free(P_EntryInfo);

	return (ret);
}


OctetString  * e_Filter(sfilter)
SFilter  * sfilter;
{
	PE                 P_SFilter;
	OctetString      * ret;
	char	   	 * proc = "e_Filter";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! sfilter)
		return (NULLOCTETSTRING);

	if (build_STRONG_Filter(&P_SFilter, 1, 0, CNULL, sfilter) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_SFilter);
	pe_free(P_SFilter);

	return (ret);
}


OctetString  * e_SubordEntry(subord)
SubordEntry  * subord;
{
	PE                 P_SubordEntry;
	OctetString      * ret;
	char	   	 * proc = "e_SubordEntry";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! subord)
		return (NULLOCTETSTRING);

	if (build_STRONG_SubordEntry(&P_SubordEntry, 1, 0, CNULL, subord) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_SubordEntry);
	pe_free(P_SubordEntry);

	return (ret);
}


OctetString  * e_ACLInfo(aclinfo)
aclInfo  * aclinfo;
{
	PE                 P_ACLInfo;
	OctetString      * ret;
	char	   	 * proc = "e_ACLInfo";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! aclinfo)
		return (NULLOCTETSTRING);

	if (build_STRONG_ACLInfo(&P_ACLInfo, 1, 0, CNULL, aclinfo) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_ACLInfo);
	pe_free(P_ACLInfo);

	return (ret);
}


OctetString  * e_ACLAttr(aclattr)
aclAttr  * aclattr;
{
	PE                 P_ACLAttr;
	OctetString      * ret;
	char	   	 * proc = "e_ACLAttr";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! aclattr)
		return (NULLOCTETSTRING);

	if (build_STRONG_AttributeACL(&P_ACLAttr, 1, 0, CNULL, aclattr) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_ACLAttr);
	pe_free(P_ACLAttr);

	return (ret);
}


OctetString  * e_ACL(acl)
AccessControlList  * acl;
{
	PE                 P_ACL;
	OctetString      * ret;
	char	   	 * proc = "e_ACL";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! acl)
		return (NULLOCTETSTRING);

	if (build_STRONG_ACL(&P_ACL, 1, 0, CNULL, acl) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_ACL);
	pe_free(P_ACL);

	return (ret);
}


OctetString  * e_ContReference(cref)
ContReference  * cref;
{
	PE                 P_ContReference;
	OctetString      * ret;
	char	   	 * proc = "e_ContReference";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! cref)
		return (NULLOCTETSTRING);

	if (build_STRONG_ContinuationReference(&P_ContReference, 1, 0, CNULL, cref) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_ContReference);
	pe_free(P_ContReference);

	return (ret);
}


OctetString  * e_AccessPoint(cref)
AccessPoint  * cref;
{
	PE                 P_AccessPoint;
	OctetString      * ret;
	char	   	 * proc = "e_AccessPoint";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! cref)
		return (NULLOCTETSTRING);

	if (build_STRONG_AccessPoint(&P_AccessPoint, 1, 0, CNULL, cref) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_AccessPoint);
	pe_free(P_AccessPoint);

	return (ret);
}


typeDSE_PSAPaddr * PSAPaddr_dec(pe)
PE pe;
{
	typeDSE_PSAPaddr * ret;
	int	           result;
	char	         * proc = "PSAPaddr_dec";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( pe == NULLPE )
		return( (typeDSE_PSAPaddr * )0 );

	/*NOTE: Space for PSAPaddr is allocated by parse_STRONG_PSAPaddr,*/
	/*parameter is of type typeDSE_PSAPaddr ** (not *!) */

	result = parse_STRONG_PSAPaddr (pe, 1, NULLIP, NULLVP, &ret);

	return (result ? (typeDSE_PSAPaddr * )0 : ret);
}


#endif


#else
/* dummy */
strong_ed_dummy() 
{
	return(0);
}

#endif

