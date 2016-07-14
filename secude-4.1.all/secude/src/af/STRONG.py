STRONG    DEFINITIONS ::=

%{	/* surrounding global definitions	*/
#include        "secude-stub.h"

static PE             build_token_tbs();
static PE	      build_addarg_tbs();
static PE	      build_comparearg_tbs();
static PE	      build_compareres_tbs();
static PE	      build_listarg_tbs();
static PE	      build_listres_tbs();
static PE	      build_modifyentryarg_tbs();
static PE	      build_modifyrdnarg_tbs();
static PE	      build_readarg_tbs();
static PE	      build_readres_tbs();
static PE	      build_removearg_tbs();
static PE	      build_searcharg_tbs();
static PE	      build_searchres_tbs();
static char 	    * aux_int2strb_alloc();
static PE 	      encode_STRONG_DER_SET_OF();

extern void           encode_DO_AccessPoint ();  /* from ISODE */

PE 	              aux_OctetString2PE();
OctetString         * aux_PE2OctetString();
%}

BEGIN
-- EXPORTS
--              TokenTBS, Token
--
-- IMPORTS	
--		Name
--			FROM InformationFramework(IF)
--
--              UTCTime, BITSTRING
--			FROM UNIV
--
--              AlgorithmIdentifier
--                      FROM SecurityFramework(SEC)
--

ENCODER build


TokenTBS [[P TokenTBS *]] ::=
        SEQUENCE {
	    signature
                [0] SEC.AlgorithmIdentifier
                [[p parm->signatureAI ]],

            name
                [1] IF.Name
                [[p parm->dname ]],

	    time
                [2] UTCTime
		[[s parm->time ]],

	    random
                [3] BITSTRING
		[[x parm->random->bits $ parm->random->nbits ]]

        }


Token [[P Token *]]
%{	PE	tbs;
%}
    ::= SEQUENCE { -- SIGNED
		-- TokenTBS
		ANY
		[[ a (build_token_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

                SEC.AlgorithmIdentifier
                [[p parm->sig->signAI ]],

		-- ENCRYPTED OCTET STRING -- BITSTRING
		[[ x parm->sig->signature.bits $
		     parm->sig->signature.nbits ]]

        }


AddArgumentTBS [[P AddArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->ada_object ]],

	    entry
		[1] SETOFAttribute
		[[p parm->ada_entry ]],

	    extensions
		[25] SECExtensionSet
                [[p parm->ada_common->ext ]]
		OPTIONAL <<parm->ada_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->ada_common->aliasedRDNs ]]
		OPTIONAL <<parm->ada_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->ada_common->progress ]]
		OPTIONAL <<parm->ada_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->ada_common->requestor ]]
		OPTIONAL <<parm->ada_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->ada_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->ada_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->ada_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->ada_common->svc>>
	}


AddArgument [[P AddArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>> 
	{
		ANY
		[[ a (build_addarg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- AddArgumentTBS
			ANY
			[[ a (build_addarg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
        	}
	}


CompareArgumentTBS [[P CompareArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->cma_object ]],

	    purported
		[1] IF.AttributeValueAssertion
		[[p parm->cma_purported ]],

	    extensions
		[25] SECExtensionSet
                [[p parm->cma_common->ext ]]
		OPTIONAL <<parm->cma_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->cma_common->aliasedRDNs ]]
		OPTIONAL <<parm->cma_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->cma_common->progress ]]
		OPTIONAL <<parm->cma_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->cma_common->requestor ]]
		OPTIONAL <<parm->cma_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->cma_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->cma_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->cma_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->cma_common->svc>>
	}


CompareArgument [[P CompareArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_comparearg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- CompareArgumentTBS
			ANY
			[[ a (build_comparearg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
        	}
	}


CompareResultTBS [[P CompareResultTBS *]] ::=
        SET {
	        IF.Name
                [[p parm->cmr_object ]]
		OPTIONAL <<parm->cmr_object>>,

	      matched
		[0] BOOLEAN
		[[b parm->cmr_matched ]],

	      fromEntry
		[1] BOOLEAN
		[[b parm->cmr_fromEntry ]]
		DEFAULT TRUE <<parm->cmr_fromEntry != TRUE>>,

	      aliasDereferenced
		[28] BOOLEAN 
		[[b parm->cmr_common->aliasDereferenced]]
		DEFAULT FALSE <<parm->cmr_common->aliasDereferenced>>,

              performer
                [29] IF.Name
                [[p parm->cmr_common->performer ]]
		OPTIONAL <<parm->cmr_common->performer>>,

	      secparm
		[30] SecurityParameters
		[[p parm->cmr_common->sec_parm ]]
		OPTIONAL <<parm->cmr_common->sec_parm>>	
	}


CompareResult [[P CompareResult *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_compareres_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- CompareResultTBS
			ANY
			[[ a (build_compareres_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


ListArgumentTBS [[P ListArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->object ]],

	    extensions
		[25] SECExtensionSet
                [[p parm->lsa_common->ext ]]
		OPTIONAL <<parm->lsa_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->lsa_common->aliasedRDNs ]]
		OPTIONAL <<parm->lsa_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->lsa_common->progress ]]
		OPTIONAL <<parm->lsa_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->lsa_common->requestor ]]
		OPTIONAL <<parm->lsa_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->lsa_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->lsa_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->lsa_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->lsa_common->svc>>
	}


ListArgument [[P ListArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_listarg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ListArgumentTBS
			ANY
			[[ a (build_listarg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

               	 	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


ListResultTBS [[P ListResultTBS *]] ::=
	CHOICE <<parm->lsr_type>>
	{
	      listInfo
		ListInfo
		[[p parm->lsrtbs_un.listinfo]],

	      uncorrelatedListInfo
		[0] SETOFListResult
		[[p parm->lsrtbs_un.uncorrel_listinfo]]
	}


ListResult [[P ListResult *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_listres_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ListResultTBS
			ANY
			[[ a (build_listres_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


SETOFListResult [[P SET_OF_ListResult *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--      	<<; parm; parm = parm->next>>
--            	ListResult
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, LISTRESULTSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


ModifyEntryArgumentTBS [[P ModifyEntryArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->mea_object ]],

	    changes
		[1] EntryModificationSequence
		[[p parm->mea_changes ]],

	    extensions
		[25] SECExtensionSet
                [[p parm->mea_common->ext ]]
		OPTIONAL <<parm->mea_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->mea_common->aliasedRDNs ]]
		OPTIONAL <<parm->mea_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->mea_common->progress ]]
		OPTIONAL <<parm->mea_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->mea_common->requestor ]]
		OPTIONAL <<parm->mea_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->mea_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->mea_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->mea_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->mea_common->svc>>
	}


ModifyEntryArgument [[P ModifyEntryArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_modifyentryarg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ModifyEntryArgumentTBS
			ANY
			[[ a (build_modifyentryarg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


ModifyRDNArgumentTBS [[P ModifyRDNArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->mra_object ]],

	    newRDN
		[1] IF.RelativeDistinguishedName
		[[p parm->mra_newrdn ]],

	    deleteOldRDN
		[2] BOOLEAN
		[[b parm->deleterdn ]]
		DEFAULT FALSE <<parm->deleterdn>>,

	    extensions
		[25] SECExtensionSet
                [[p parm->mra_common->ext ]]
		OPTIONAL <<parm->mra_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->mra_common->aliasedRDNs ]]
		OPTIONAL <<parm->mra_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->mra_common->progress ]]
		OPTIONAL <<parm->mra_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->mra_common->requestor ]]
		OPTIONAL <<parm->mra_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->mra_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->mra_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->mra_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->mra_common->svc>>
	}


ModifyRDNArgument [[P ModifyRDNArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_modifyrdnarg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ModifyRDNArgumentTBS
			ANY
			[[ a (build_modifyrdnarg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


ReadArgumentTBS [[P ReadArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->object ]],

	    selection
		[1] EntryInfoSEL
		[[p parm->rda_eis ]]
		-- DEFAULT {},
		OPTIONAL <<parm->rda_eis>>,

	    extensions
		[25] SECExtensionSet
                [[p parm->rda_common->ext ]]
		OPTIONAL <<parm->rda_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->rda_common->aliasedRDNs ]]
		OPTIONAL <<parm->rda_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->rda_common->progress ]]
		OPTIONAL <<parm->rda_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->rda_common->requestor ]]
		OPTIONAL <<parm->rda_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->rda_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->rda_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->rda_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->rda_common->svc>>
	}


ReadArgument [[P ReadArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_readarg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ReadArgumentTBS
			ANY
			[[ a (build_readarg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


ReadResultTBS [[P ReadResultTBS *]] ::=
        SET {
	      entry
		[0] EntryINFO
		[[p parm->rdr_entry ]],

	      aliasDereferenced
		[28] BOOLEAN 
		[[b parm->rdr_common->aliasDereferenced]]
		DEFAULT FALSE <<parm->rdr_common->aliasDereferenced>>,

              performer
                [29] IF.Name
                [[p parm->rdr_common->performer ]]
		OPTIONAL <<parm->rdr_common->performer>>,

	      secparm
		[30] SecurityParameters
		[[p parm->rdr_common->sec_parm ]]
		OPTIONAL <<parm->rdr_common->sec_parm>>
	}


ReadResult [[P ReadResult *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_readres_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- ReadResultTBS
			ANY
			[[ a (build_readres_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


RemoveArgumentTBS [[P RemoveArgumentTBS *]] ::=
        SET {
            object
                [0] IF.Name
                [[p parm->rma_object ]],

	    extensions
		[25] SECExtensionSet
                [[p parm->rma_common->ext ]]
		OPTIONAL <<parm->rma_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->rma_common->aliasedRDNs ]]
		OPTIONAL <<parm->rma_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->rma_common->progress ]]
		OPTIONAL <<parm->rma_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->rma_common->requestor ]]
		OPTIONAL <<parm->rma_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->rma_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->rma_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->rma_common->svc ]]
		-- DEFAULT {},
		OPTIONAL <<parm->rma_common->svc>>
	}


RemoveArgument [[P RemoveArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_removearg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- RemoveArgumentTBS
			ANY
			[[ a (build_removearg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


SearchArgumentTBS [[P SearchArgumentTBS *]] ::=
        SET {
	    baseObject
		[0] IF.Name 
		[[p parm->baseobject]],

	    subset
		[1] INTEGER 
		[[i parm->subset]]
		{
		baseObject(0) ,
		oneLevel(1) ,
		wholeSubtree(2)
		}
		DEFAULT baseObject <<parm->subset != 0>>,

	    filter
		[2] Filter 
		[[p parm->filter]]
		OPTIONAL <<parm->filter>>,

	    searchAliases
		[3] BOOLEAN 
		[[b parm->searchaliases]]
		DEFAULT TRUE <<parm->searchaliases != TRUE>>,

	    selection
		[4] EntryInfoSEL
		[[p parm->sra_eis ]]
		-- DEFAULT {},
		OPTIONAL <<parm->sra_eis>>,

	    extensions
		[25] SECExtensionSet
                [[p parm->sra_common->ext ]]
		OPTIONAL <<parm->sra_common->ext>>,

            aliasedRDNs
                [26] INTEGER
                [[i parm->sra_common->aliasedRDNs ]]
		OPTIONAL <<parm->sra_common->aliasedRDNs != CA_NO_ALIASDEREFERENCED>>,

	    progress
	        [27] OperationProgress
	        [[p parm->sra_common->progress ]]
		OPTIONAL <<parm->sra_common->progress>>,

	    requestor
                [28] IF.Name
                [[p parm->sra_common->requestor ]]
		OPTIONAL <<parm->sra_common->requestor>>,

	    secparm
		[29] SecurityParameters
		[[p parm->sra_common->sec_parm ]]
		-- DEFAULT {},
		OPTIONAL <<parm->sra_common->sec_parm>>,

	    servcontr
		[30] ServiceControls
		[[p parm->sra_common->svc ]]
		-- DEFAULT {}
		OPTIONAL <<parm->sra_common->svc>>
	}


SearchArgument [[P SearchArgument *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_searcharg_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- SearchArgumentTBS
			ANY
			[[ a (build_searcharg_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
                	[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


SearchResultTBS [[P SearchResultTBS *]] ::=
	CHOICE <<((parm->srr_correlated == FALSE) ? 2 : 1)>>
	{
	      searchInfo
		SearchInfo
		[[p parm->srrtbs_un.searchinfo]],

	      uncorrelatedSearchInfo
		[0] SETOFSearchResult
		[[p parm->srrtbs_un.uncorrel_searchinfo]]
	}


SearchResult [[P SearchResult *]]
%{	PE	tbs;
%}
    ::= CHOICE <<parm->sig? 2:1>>
	{
		ANY
		[[ a (build_searchres_tbs(parm,&tbs)) ]]
		%{    pe_free(tbs);
		%} ,

		SEQUENCE { -- SIGNED
			-- SearchResultTBS
			ANY
			[[ a (build_searchres_tbs(parm,&tbs)) ]]
			%{    pe_free(tbs);
			%} ,

                	SEC.AlgorithmIdentifier
			[[p parm->sig->signAI ]],

			-- ENCRYPTED OCTET STRING -- BITSTRING
			[[ x parm->sig->signature.bits $
		     	parm->sig->signature.nbits ]]
		}
	}


SETOFSearchResult [[P SET_OF_SearchResult *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--      SET OF
--      	<<; parm; parm = parm->next>>
--            	SearchResult
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, SEARCHRESULTSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


EntryModification [[P EntryModification *]] ::=
	CHOICE << parm->em_type >>
	{
	addAttribute
		[0] IF.Attribute 
		[[p parm->em_un.em_un_attr ]],

	removeAttribute
		[1] OBJECT IDENTIFIER
		[[ O parm->em_un.em_un_attrtype ]],

	addValues
		[2] IF.Attribute 
		[[p parm->em_un.em_un_attr ]],

	removeValues
		[3] IF.Attribute 
		[[p parm->em_un.em_un_attr ]]
	}


EntryModificationSequence [[ P SEQUENCE_OF_EntryModification *]] ::=
	SEQUENCE OF
		<<; parm; parm = parm->next>>
		EntryModification
		[[ p parm->element ]]


ServiceControls [[P ServiceControls *]] ::=
	%{
	if (parm->svc_options != 0) {
		parm->svc_len = 5;
		parm->svc_tmp = aux_int2strb_alloc (parm->svc_options,parm->svc_len);
	}
	%}
	SET {
	    options
		[0] BITSTRING
		[[ x parm->svc_tmp $ parm->svc_len ]]
		{
		preferChaining(0) ,
		chainingProhibited(1) ,
		localScope(2) ,
		dontUseCopy(3) ,
		dontDereferenceAliases(4)
		}
		%{
		if (parm->svc_tmp){
			free (parm->svc_tmp);
			parm->svc_tmp = CNULL;
		}
		%}
		OPTIONAL <<parm->svc_options != 0>>,

            priority
                [1] INTEGER
                [[i parm->svc_prio ]]
		{
		low(0) ,
		medium(1) ,
		high(2)
		}
		DEFAULT medium <<parm->svc_prio != 1>>,

            timeLimit
                [2] INTEGER
                [[i parm->svc_timelimit ]]
		OPTIONAL <<parm->svc_timelimit != SVC_NOTIMELIMIT>>,

            sizeLimit
                [3] INTEGER
                [[i parm->svc_sizelimit ]]
		OPTIONAL <<parm->svc_sizelimit != SVC_NOSIZELIMIT>>,

            scopeOfReferral
                [4] INTEGER
                [[i parm->svc_scopeofreferral ]]
		{
		dmd(0) ,
		country(1)
		}
		OPTIONAL <<parm->svc_scopeofreferral != SVC_REFSCOPE_NONE>>
        }


SecurityParameters [[P SecurityParameters *]] ::=
	SET {
	    certificationPath
		[0] AF.CertificationPath
		[[p parm->certPath ]]
		OPTIONAL <<parm->certPath>>,

	    name
		[1] IF.Name
		[[p parm->name ]]
		OPTIONAL <<parm->name>>,

	    time
                [2] UTCTime
                [[s parm->time ]]
		OPTIONAL <<parm->time>>,

	    random
	        [3] BITSTRING
		[[x parm->random->bits $ parm->random->nbits ]]
		OPTIONAL <<parm->random>>,

            target
                [4] INTEGER
                [[i parm->target ]]
		{
		none(0) ,
		signed(1)
		}
		-- OPTIONAL <<parm->target>>
		DEFAULT 0 <<parm->target != 0>>
        }


OperationProgress [[P OperationProgress *]] ::=
	%{
	if (parm->opResolutionPhase < 0)
		parm->opResolutionPhase = 1;
	else if (parm->opResolutionPhase > 3)
		parm->opResolutionPhase = 3;
	%}
        SET {
            opResolutionPhase
                [0] ENUMERATED
                [[i parm->opResolutionPhase ]]
		{
		notStarted(1) ,
		proceeding(2) ,
		completed(3)
		},

            opNextRDNToBeResolved
                [1] INTEGER
                [[i parm->opNextRDNToBeResolved ]]
	        OPTIONAL <<parm->opNextRDNToBeResolved != -1>>
        }


SECExtensionSet [[P SET_OF_SECExtension *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--      SET OF
--      	<<; parm; parm = parm->next>>
--            	SECExtension
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, SECEXTENSIONSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


SECExtension [[P SECExtension *]] ::= 
	SET {
            identifier
                [0] INTEGER
                [[i parm->ext_id ]],

            critical
                [1] BOOLEAN
                [[b parm->ext_critical ]]
		DEFAULT FALSE <<parm->ext_critical>>,

	    item
		[2] ANY
		[[ a parm->ext_item ]]
        }


SETOFAttributeType [[ P SET_OF_AttrType *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		OBJECT IDENTIFIER
--		[[ O parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ATTRTYPESET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


SETOFAttribute [[ P SET_OF_Attr *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		IF.Attribute
--		[[ p parm->element ]]
--
-- 
--
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ATTRSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


SETOFAttrAttrTypeCHOICE [[ P SET_OF_AttrAttrTypeCHOICE *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		AttrAttrTypeCHOICE
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ATTRATTRTYPECHOICESET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


AttrAttrTypeCHOICE [[ P AttrAttrTypeCHOICE *]] ::=
	CHOICE <<parm->offset>>
	{
		OBJECT IDENTIFIER
		[[ O parm->choice_un.choice_un_attrtype ]],

		IF.Attribute
		[[ p parm->choice_un.choice_un_attr->element ]]
	}


EntryInfoSEL [[P EntryInfoSEL *]]
	::=
	SET {
	attributeTypes
		CHOICE << parm->eis_allattributes ? 1 : 2 >>
		{
		allAttributes
			[0] NULL,

		select
			[1] SETOFAttributeType 
			[[p parm->eis_select]]
		}
		-- DEFAULT allAttributes NULL,
		OPTIONAL <<parm->eis_allattributes != TRUE>>,
	infoTypes
		[2] INTEGER 
		[[i parm->eis_infotypes]]
		{
		attributeTypesOnly(0) ,
		attributeTypesAndValues(1)
		}
		DEFAULT attributeTypesAndValues <<parm->eis_infotypes != 1>>
	}


SETOFEntryINFO [[P SET_OF_EntryINFO *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		EntryINFO
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ENTRYINFOSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


EntryINFO [[P EntryINFO *]]
	::=
	SEQUENCE {
	    name
		IF.Name
		[[p parm->ent_dn ]],

	    fromEntry
		BOOLEAN 
		[[b parm->ent_fromentry]]
		DEFAULT TRUE <<parm->ent_fromentry != TRUE>>,

		SETOFAttrAttrTypeCHOICE
		[[p parm->ent_attr]]
		OPTIONAL <<parm->ent_attr>>
	}


StringsCHOICE [[P StringsCHOICE *]]
	::=
	CHOICE << parm->strings_type >>
	{
	initial
		[0] ANY
		[[a parm->strings_un.initial ]],
	any
		[1] ANY
		[[a parm->strings_un.any ]],
	final
		[2] ANY
		[[a parm->strings_un.final ]]
	}


SEQUENCEOFStringsCHOICE [[P SEQUENCE_OF_StringsCHOICE *]] ::=
	SEQUENCE OF
		<<; parm; parm = parm->next>>
		StringsCHOICE
		[[ p parm->element ]]


FilterSubstrings [[P SFilterSubstrings *]] 
	::=
	SEQUENCE {
		type
		  OBJECT IDENTIFIER
		  [[O parm->type]],

		strings
		  SEQUENCEOFStringsCHOICE 
		  [[p parm->seq ]]
	}


FilterItem [[P SFilterItem *]]
	::=
	CHOICE << parm->fi_type >>
	{
	equality
		[0] IF.AttributeValueAssertion 
		[[p parm->fi_un.fi_un_ava]],
	substrings 
		[1] FilterSubstrings
		[[p parm->fi_un.fi_un_substrings]], 
	greaterOrEqual
		[2] IF.AttributeValueAssertion 
		[[p parm->fi_un.fi_un_ava]],
	lessOrEqual
		[3] IF.AttributeValueAssertion 
		[[p parm->fi_un.fi_un_ava]],
	present
		[4] OBJECT IDENTIFIER 
		[[O parm->fi_un.fi_un_type]],
	approximateMatch
		[5] IF.AttributeValueAssertion 
		[[p parm->fi_un.fi_un_ava]]
	}


SETOFFilter [[ P SET_OF_SFilter *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		Filter
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, FILTERSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


Filter [[P SFilter *]]
	::=
	CHOICE << parm->flt_type >>
	{
	      item
		[0] FilterItem 
		[[p parm->flt_un.flt_un_item]],
	      and
		[1] SETOFFilter
		[[p parm->flt_un.flt_un_filter ]],
	      or
		[2] SETOFFilter
	        [[p parm->flt_un.flt_un_filter ]],
	      not
		[3] Filter 
		[[p parm->flt_un.flt_un_filter]]
	}


SETOFSubordEntry [[P SET_OF_SubordEntry *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		SubordEntry
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, SUBORDENTRYSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


SubordEntry [[P SubordEntry *]] ::=
	SEQUENCE {
		IF.RelativeDistinguishedName
		[[p parm->sub_rdn]],

	      aliasEntry
		[0] BOOLEAN 
		[[b parm->sub_aliasentry]] 
		DEFAULT FALSE <<parm->sub_aliasentry>>,

	      fromEntry
		[1] BOOLEAN 
		[[b parm->sub_copy]]
		DEFAULT TRUE <<parm->sub_copy != TRUE>>
	}


ListInfo [[P ListInfo *]] ::=
	SET {
		IF.Name
		[[p parm->lsr_object]]
		OPTIONAL <<parm->lsr_object>>,

	      subordinates
		[1] SETOFSubordEntry
		[[p parm->lsr_subordinates]],

	      partialOutcomeQualifier
		[2] PartialOutcomeQualifier
		[[p parm->lsr_poq]] 
		OPTIONAL <<
			  (parm->lsr_poq &&
			   ( ((parm->lsr_poq->poq_limitproblem != LSR_NOLIMITPROBLEM) || 
			      (parm->lsr_poq->poq_cref != (SET_OF_ContReference * )0)) ) )
			 >>,

	      aliasDereferenced
		[28] BOOLEAN 
		[[b parm->lsr_common->aliasDereferenced]]
		DEFAULT FALSE <<parm->lsr_common->aliasDereferenced>>,

              performer
                [29] IF.Name
                [[p parm->lsr_common->performer ]]
		OPTIONAL <<parm->lsr_common->performer>>,

	      secparm
		[30] SecurityParameters
		[[p parm->lsr_common->sec_parm ]]
		OPTIONAL <<parm->lsr_common->sec_parm>>
}


SearchInfo [[P SearchInfo *]] ::=
	SET {
		IF.Name
		[[p parm->srr_object]]
		OPTIONAL <<parm->srr_object>>,

	      entries
		[0] SETOFEntryINFO
		[[p parm->srr_entries]],

	      partialOutcomeQualifier
		[2] PartialOutcomeQualifier
		[[p parm->srr_poq]] 
		OPTIONAL <<
			  (parm->srr_poq &&
			   ( ((parm->srr_poq->poq_limitproblem != LSR_NOLIMITPROBLEM) || 
			   (parm->srr_poq->poq_cref != (SET_OF_ContReference * )0)) ) )
			 >>,

	      aliasDereferenced
		[28] BOOLEAN 
		[[b parm->srr_common->aliasDereferenced]]
		DEFAULT FALSE <<parm->srr_common->aliasDereferenced>>,

              performer
                [29] IF.Name
                [[p parm->srr_common->performer ]]
		OPTIONAL <<parm->srr_common->performer>>,

	      secparm
		[30] SecurityParameters
		[[p parm->srr_common->sec_parm ]]
		OPTIONAL <<parm->srr_common->sec_parm>>
}


SETOFObjId [[P SET_OF_ObjId *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		OBJECT IDENTIFIER
--		[[ O parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, OBJIDSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


SETOFDName [[P SET_OF_DName *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		IF.Name
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, DNAMESET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


AccessSelector [[P aclInfo *]]
        ::=
        CHOICE <<parm->acl_selector_type>>
        {
        entry
                [0] NULL ,
        other
                [2] NULL ,
        prefix
                [3] SETOFDName 
		[[p parm->acl_name]] ,
        group
                [4] SETOFDName 
		[[p parm->acl_name]]
        }


AccessCategories [[P aclInfo *]]
        ::=
        ENUMERATED [[i parm->acl_categories]]
        {
                none (0) ,
                detect (1) ,
                compare (2) ,
                read (3) ,
                add (4) ,
                write (5)
        }


ACLInfo [[P aclInfo *]]
        ::=
        SEQUENCE {
        	AccessSelector [[p parm]] ,
                AccessCategories [[p parm]]
        }


SETOFACLInfo [[P SET_OF_aclInfo *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		ACLInfo
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ACLINFOSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


AttributeACL [[P aclAttr *]]
        ::=
        SEQUENCE
        {
                SETOFObjId 
		[[p parm->aa_types]],

                SETOFACLInfo 
		[[p parm->aa_acl]]
                -- DEFAULT {{other , read}, {entry, write}}
                OPTIONAL <<parm->aa_acl>>
        }


SETOFAttributeACL [[P SET_OF_aclAttr *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--		<<; parm; parm = parm->next>>
--		AttributeACL
--		[[ p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ATTRACLSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


ACL [[P AccessControlList *]]
        ::=
        SEQUENCE
        {
        childACL
                [0] SETOFACLInfo 
		[[p parm->ac_child]]
                -- DEFAULT {{other , read}, {entry, write}} ,
                OPTIONAL <<parm->ac_child>>,

        entryACL
                [1] SETOFACLInfo 
		[[p parm->ac_entry]]
                -- DEFAULT {{other , read}, {entry, write}} ,
                OPTIONAL <<parm->ac_entry>>,

        defaultAttributeACL
                [2] SETOFACLInfo 
		[[p parm->ac_default]]
                -- DEFAULT {{other , read}, {entry, write}} ,
                OPTIONAL <<parm->ac_default>>,

                [3] SETOFAttributeACL 
		[[p parm->ac_attributes]]
        }


PartialOutcomeQualifier [[P PartialOutQual *]]
	::=
	SET
	{
	limitProblem
		[0] LimitProblem 
		[[i parm->poq_limitproblem]]
		OPTIONAL <<parm->poq_limitproblem != LSR_NOLIMITPROBLEM>>,					 
	unexplored
		[1] SETOFContinuationReference
		[[p parm->poq_cref]]
		OPTIONAL <<parm->poq_cref>>,

	unavailableCriticalExtensions
		[2] BOOLEAN 
		[[b parm->poq_no_ext]]
		DEFAULT FALSE
	}


-- This is pulled up as an 'i' type, so no parameters are needed.
ReferenceType
        ::=
        ENUMERATED
        {
        superior(1) ,
        subordinate(2) ,
        cross(3) ,
        nonSpecificSubordinate(4)
        }


-- Pulled up
LimitProblem
	::=
	INTEGER 
	{
	timeLimitExceeded(0) ,
	sizeLimitExceeded(1) ,
	administrativeLimitExceeded(2)
	}


SETOFContinuationReference [[P SET_OF_ContReference *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--      	<<; parm; parm = parm->next>>
--            	ContinuationReference
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, CONTREFSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


ContinuationReference [[P ContReference * ]]
        ::=
        SET
        {
        targetObject
                [0] IF.Name 
		[[p parm->cr_name]],

        aliasedRDNs
                [1] INTEGER 
		[[i parm->cr_aliasedRDNs]]
                OPTIONAL << parm->cr_aliasedRDNs != CR_NOALIASEDRDNS>>,

        operationProgress
                [2] OperationProgress 
		[[p parm->cr_progress]],

        rdnsResolved
                [3] INTEGER 
		[[i parm->cr_rdn_resolved]]
                OPTIONAL << parm->cr_rdn_resolved != CR_RDNRESOLVED_NOTDEFINED>>,

        referenceType
                [4] ReferenceType 
		[[i parm->cr_reftype]]
                OPTIONAL << parm->cr_reftype != RT_UNDEFINED>>,

        accessPoints
		[5] SETOFAccessPoint 
		[[p parm->cr_accesspoints]]
	}


SETOFAccessPoint [[P SET_OF_AccessPoint *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--      	<<; parm; parm = parm->next>>
--            	AccessPoint
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, ACCESSPOINTSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


AccessPoint [[P AccessPoint *]]
        ::=
        SET
        {
                [0] IF.Name 
		[[p parm->ap_name]],

                [1] PSAPaddr 
		[[p parm->ap_address ]]				
        }


SETOFOctetString [[P SET_OF_OctetString *]]
-- non-compliant with DER restriction (X.509, 8.7):
--	::=
--	SET OF
--      	<<; parm; parm = parm->next>>
--            	SEC.OctetString
--            	[[p parm->element ]]
-- compliant with DER restriction (X.509, 8.7):
	%{
	PE pe_enc = encode_STRONG_DER_SET_OF(parm, OSTRSET);
	%}
	::=
	ANY [[ a pe_enc ]]
	%{
	pe_free(pe_enc);
	%}


PSAPaddr [[P typeDSE_PSAPaddr *]]
	::=
	SEQUENCE {
	    pSelector
		[0] OCTET STRING
		[[ o parm->pSelector.octets $
		     parm->pSelector.noctets   ]]
		OPTIONAL <<parm->pSelector.noctets > 0>>,

	    sSelector
		[1] OCTET STRING
		[[ o parm->sSelector.octets $
		     parm->sSelector.noctets   ]]
		OPTIONAL <<parm->sSelector.noctets > 0>>,

	    tSelector
		[2] OCTET STRING
		[[ o parm->tSelector.octets $
	             parm->tSelector.noctets   ]]
		OPTIONAL <<parm->tSelector.noctets > 0>>,

	    nAddress
		[3] SETOFOctetString
		[[ p parm->nAddress]]
	}



DECODER parse


PSAPaddr [[ P typeDSE_PSAPaddr **]]
    ::= 
        %{
            if ((*(parm) = (typeDSE_PSAPaddr *)
                    calloc (1, sizeof **(parm))) == ((typeDSE_PSAPaddr *) 0)) {
                advise (NULLCP, "out of memory");
                return NOTOK;
            }
	    (*parm)->nAddress = (SET_OF_OctetString *)0;
	    (*parm)->pSelector.octets = CNULL;
	    (*parm)->pSelector.noctets = 0;
	    (*parm)->sSelector.octets = CNULL;
	    (*parm)->sSelector.noctets = 0;
	    (*parm)->tSelector.octets = CNULL;
	    (*parm)->tSelector.noctets = 0;
	%}	
        SEQUENCE
        {
	    pSelector
		[0] OCTET STRING
		[[ o (*parm)->pSelector.octets $
		     (*parm)->pSelector.noctets   ]]
		OPTIONAL,

	    sSelector
		[1] OCTET STRING
		[[ o (*parm)->sSelector.octets $
		     (*parm)->sSelector.noctets   ]]
		OPTIONAL,

	    tSelector
		[2] OCTET STRING
		[[ o (*parm)->tSelector.octets $
	             (*parm)->tSelector.noctets   ]]
		OPTIONAL,

            nAddress
		[3] SETOFOctetString
		[[ p &((*parm)->nAddress) ]]
		OPTIONAL
        }


OctetString [[P OctetString **]] ::=
        %{
            if ((*(parm) = (OctetString *)
                    calloc (1, sizeof **(parm))) == ((OctetString *) 0)) {
                advise (NULLCP, "out of memory");
                return NOTOK;
            }
	%}
	OCTETSTRING
	[[ o (*parm)->octets $
	     (*parm)->noctets   ]]


SETOFOctetString [[P SET_OF_OctetString **]] ::=
        SET OF
            %{
                if ((*(parm) = (SET_OF_OctetString *)
                        calloc (1, sizeof **(parm))) == ((SET_OF_OctetString *) 0)) {
                    advise (NULLCP, "out of memory");
                    return NOTOK;
                }
            %}
            OctetString
            [[p &((*parm) -> element)]]
            %{ parm = &((*parm) -> next); %}

END



%{
/************************ local functions: ************************/


static
PE	build_token_tbs(token,save)
Token   * token;
PE      * save;
{
	(* save) = NULLPE;

	if( token->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_TokenTBS(save,1,0,NULLCP,token->tbs) == NOTOK)
		return NULLPE;
	    token->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(token->tbs_DERcode);

	return (* save);
}


static
PE	build_addarg_tbs(addarg,save)
AddArgument   * addarg;
PE            * save;
{
	(* save) = NULLPE;

	if( addarg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_AddArgumentTBS(save,1,0,NULLCP,addarg->tbs) == NOTOK)
		return NULLPE;
	    addarg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(addarg->tbs_DERcode);

	return (* save);
}


static
PE	build_comparearg_tbs(comparearg,save)
CompareArgument   * comparearg;
PE                * save;
{
	(* save) = NULLPE;

	if( comparearg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_CompareArgumentTBS(save,1,0,NULLCP,comparearg->tbs) == NOTOK)
		return NULLPE;
	    comparearg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(comparearg->tbs_DERcode);

	return (* save);
}


static
PE	build_compareres_tbs(compareres,save)
CompareResult   * compareres;
PE              * save;
{
	(* save) = NULLPE;

	if( compareres->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_CompareResultTBS(save,1,0,NULLCP,compareres->tbs) == NOTOK)
		return NULLPE;
	    compareres->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(compareres->tbs_DERcode);

	return (* save);
}


static
PE	build_listarg_tbs(listarg,save)
ListArgument   * listarg;
PE             * save;
{
	(* save) = NULLPE;

	if( listarg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ListArgumentTBS(save,1,0,NULLCP,listarg->tbs) == NOTOK)
		return NULLPE;
	    listarg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(listarg->tbs_DERcode);

	return (* save);
}


static
PE	build_listres_tbs(listres,save)
ListResult   * listres;
PE           * save;
{
	(* save) = NULLPE;

	if( listres->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ListResultTBS(save,1,0,NULLCP,listres->tbs) == NOTOK)
		return NULLPE;
	    listres->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(listres->tbs_DERcode);

	return (* save);
}


static
PE	build_modifyentryarg_tbs(modifyentryarg,save)
ModifyEntryArgument * modifyentryarg;
PE                  * save;
{
	(* save) = NULLPE;

	if( modifyentryarg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ModifyEntryArgumentTBS(save,1,0,NULLCP,modifyentryarg->tbs) == NOTOK)
		return NULLPE;
	    modifyentryarg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(modifyentryarg->tbs_DERcode);

	return (* save);
}


static
PE	build_modifyrdnarg_tbs(modifyrdnarg,save)
ModifyRDNArgument * modifyrdnarg;
PE                * save;
{
	(* save) = NULLPE;

	if( modifyrdnarg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ModifyRDNArgumentTBS(save,1,0,NULLCP,modifyrdnarg->tbs) == NOTOK)
		return NULLPE;
	    modifyrdnarg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(modifyrdnarg->tbs_DERcode);

	return (* save);
}


static
PE	build_readarg_tbs(readarg,save)
ReadArgument   * readarg;
PE             * save;
{
	(* save) = NULLPE;

	if( readarg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ReadArgumentTBS(save,1,0,NULLCP,readarg->tbs) == NOTOK)
		return NULLPE;
	    readarg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(readarg->tbs_DERcode);

	return (* save);
}


static
PE	build_readres_tbs(readres,save)
ReadResult   * readres;
PE           * save;
{
	(* save) = NULLPE;

	if( readres->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_ReadResultTBS(save,1,0,NULLCP,readres->tbs) == NOTOK)
		return NULLPE;
	    readres->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(readres->tbs_DERcode);

	return (* save);
}


static
PE	build_removearg_tbs(removearg,save)
RemoveArgument   * removearg;
PE               * save;
{
	(* save) = NULLPE;

	if( removearg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_RemoveArgumentTBS(save,1,0,NULLCP,removearg->tbs) == NOTOK)
		return NULLPE;
	    removearg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(removearg->tbs_DERcode);

	return (* save);
}


static
PE	build_searcharg_tbs(searcharg,save)
SearchArgument * searcharg;
PE             * save;
{
	(* save) = NULLPE;

	if( searcharg->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_SearchArgumentTBS(save,1,0,NULLCP,searcharg->tbs) == NOTOK)
		return NULLPE;
	    searcharg->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(searcharg->tbs_DERcode);

	return (* save);
}


static
PE	build_searchres_tbs(searchres,save)
SearchResult * searchres;
PE             * save;
{
	(* save) = NULLPE;

	if( searchres->tbs_DERcode == (OctetString * )0 ) {
	    if (build_STRONG_SearchResultTBS(save,1,0,NULLCP,searchres->tbs) == NOTOK)
		return NULLPE;
	    searchres->tbs_DERcode = aux_PE2OctetString(* save);
	}
	else   (* save) = aux_OctetString2PE(searchres->tbs_DERcode);

	return (* save);
}




/* from ISODEDIR/dsap/x500as/DAS_tables.c */
static
char   * aux_int2strb_alloc (n, len)
register int    n;
int     len;
{
	register int    i;
	static char *buffer;

	buffer = calloc (1,sizeof (int) + 1);

	for (i = 0; i < len; i++)
		if (n & (1 << i))
			buffer[i / 8] |= (1 << (7 - (i % 8)));

	return buffer;
}



static
PE encode_STRONG_DER_SET_OF(arg, type)
caddr_t    arg;
int 	   type;
{
	SET_OF_ListResult 	  * setof_listres, * tmp_setof_listres;
	SET_OF_SearchResult 	  * setof_searchres, * tmp_setof_searchres;
	SET_OF_SECExtension 	  * setof_secext, * tmp_setof_secext;
	SET_OF_AttrType 	  * setof_attrtype, * tmp_setof_attrtype;
	SET_OF_Attr  		  * setof_attr, * tmp_setof_attr;
	SET_OF_AttrAttrTypeCHOICE * setof_attrattrtypechoice, * tmp_setof_attrattrtypechoice;
	SET_OF_EntryINFO 	  * setof_einfo, * tmp_setof_einfo;
	SET_OF_SFilter 		  * setof_sfilter, * tmp_setof_sfilter;
	SET_OF_SubordEntry 	  * setof_subord, * tmp_setof_subord;
	SET_OF_DName  		  * setof_dname, * tmp_setof_dname;
	SET_OF_ObjId		  * setof_objid, * tmp_setof_objid;
	SET_OF_aclInfo		  * setof_aclinfo, * tmp_setof_aclinfo;
	SET_OF_aclAttr		  * setof_aclattr, * tmp_setof_aclattr;
	SET_OF_AccessPoint	  * setof_accpoint, * tmp_setof_accpoint;
	SET_OF_ContReference	  * setof_cref, * tmp_setof_cref;
	SET_OF_OctetString	  * setof_ostr, * tmp_setof_ostr;
	OctetString 		 ** oSTK, * tmp_ostr;
	PE			    p24 = NULLPE, p25 = NULLPE, pe;
	unsigned char  		    a, b;
	int 	       		    n, i, k, j, s, cnt;


	if (! arg){
		if (type == CONTREFSET)
			/* pe_enc is OPTIONAL */
			return(NULLPE);
		else {
			/* Force an empty set to be coded */
			pe = pe_alloc (PE_CLASS_UNIV, PE_FORM_CONS, PE_CONS_SET);
			return(pe);
		}
	}


	/* Individual encoding of components of Set-of type */

	switch(type) {

	case ACCESSPOINTSET:
		setof_accpoint = (SET_OF_AccessPoint * )arg;

		for (tmp_setof_accpoint = setof_accpoint, cnt = 0; tmp_setof_accpoint; 
			tmp_setof_accpoint = tmp_setof_accpoint->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_accpoint = setof_accpoint;

		while (tmp_setof_accpoint){
			tmp_ostr = e_AccessPoint(tmp_setof_accpoint->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_accpoint = tmp_setof_accpoint->next;
		}
		break;

	case ACLINFOSET:
		setof_aclinfo = (SET_OF_aclInfo * )arg;

		for (tmp_setof_aclinfo = setof_aclinfo, cnt = 0; tmp_setof_aclinfo; 
			tmp_setof_aclinfo = tmp_setof_aclinfo->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_aclinfo = setof_aclinfo;

		while (tmp_setof_aclinfo){
			tmp_ostr = e_ACLInfo(tmp_setof_aclinfo->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_aclinfo = tmp_setof_aclinfo->next;
		}
		break;

	case ATTRACLSET:
		setof_aclattr = (SET_OF_aclAttr * )arg;

		for (tmp_setof_aclattr = setof_aclattr, cnt = 0; tmp_setof_aclattr; 
			tmp_setof_aclattr = tmp_setof_aclattr->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_aclattr = setof_aclattr;

		while (tmp_setof_aclattr){
			tmp_ostr = e_ACLAttr(tmp_setof_aclattr->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_aclattr = tmp_setof_aclattr->next;
		}
		break;

	case ATTRATTRTYPECHOICESET:
		setof_attrattrtypechoice = (SET_OF_AttrAttrTypeCHOICE * )arg;

		for (tmp_setof_attrattrtypechoice = setof_attrattrtypechoice, cnt = 0; 
			tmp_setof_attrattrtypechoice; tmp_setof_attrattrtypechoice = tmp_setof_attrattrtypechoice->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_attrattrtypechoice = setof_attrattrtypechoice;

		while (tmp_setof_attrattrtypechoice){
			tmp_ostr = e_AttrAttrTypeCHOICE(tmp_setof_attrattrtypechoice->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_attrattrtypechoice = tmp_setof_attrattrtypechoice->next;
		}
		break;

	case ATTRSET:
		setof_attr = (SET_OF_Attr * )arg;

		for (tmp_setof_attr = setof_attr, cnt = 0; tmp_setof_attr; 
			tmp_setof_attr = tmp_setof_attr->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_attr = setof_attr;

		while (tmp_setof_attr){
			tmp_ostr = e_Attribute(tmp_setof_attr->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_attr = tmp_setof_attr->next;
		}
		break;

	case ATTRTYPESET:
		setof_attrtype = (SET_OF_AttrType * )arg;

		for (tmp_setof_attrtype = setof_attrtype, cnt = 0; 
			tmp_setof_attrtype; tmp_setof_attrtype = tmp_setof_attrtype->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_attrtype = setof_attrtype;

		while (tmp_setof_attrtype){
			tmp_ostr = e_AttributeType(tmp_setof_attrtype->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_attrtype = tmp_setof_attrtype->next;
		}
		break;

	case CONTREFSET:
		setof_cref = (SET_OF_ContReference * )arg;

		for (tmp_setof_cref = setof_cref, cnt = 0; tmp_setof_cref; 
			tmp_setof_cref = tmp_setof_cref->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_cref = setof_cref;

		while (tmp_setof_cref){
			tmp_ostr = e_ContReference(tmp_setof_cref->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_cref = tmp_setof_cref->next;
		}
		break;

	case DNAMESET:
		setof_dname = (SET_OF_DName * )arg;

		for (tmp_setof_dname = setof_dname, cnt = 0; tmp_setof_dname; 
			tmp_setof_dname = tmp_setof_dname->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_dname = setof_dname;

		while (tmp_setof_dname){
			tmp_ostr = e_DName(tmp_setof_dname->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_dname = tmp_setof_dname->next;
		}
		break;

	case ENTRYINFOSET:
		setof_einfo = (SET_OF_EntryINFO * )arg;

		for (tmp_setof_einfo = setof_einfo, cnt = 0; tmp_setof_einfo; 
			tmp_setof_einfo = tmp_setof_einfo->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_einfo = setof_einfo;

		while (tmp_setof_einfo){
			tmp_ostr = e_EntryINFO(tmp_setof_einfo->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_einfo = tmp_setof_einfo->next;
		}
		break;

	case FILTERSET:
		setof_sfilter = (SET_OF_SFilter * )arg;

		for (tmp_setof_sfilter = setof_sfilter, cnt = 0; 
			tmp_setof_sfilter; tmp_setof_sfilter = tmp_setof_sfilter->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_sfilter = setof_sfilter;

		while (tmp_setof_sfilter){
			tmp_ostr = e_Filter(tmp_setof_sfilter->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_sfilter = tmp_setof_sfilter->next;
		}
		break;

	case LISTRESULTSET:
		setof_listres = (SET_OF_ListResult * )arg;

		for (tmp_setof_listres = setof_listres, cnt = 0; 
			tmp_setof_listres; tmp_setof_listres = tmp_setof_listres->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_listres = setof_listres;

		while (tmp_setof_listres){
			tmp_ostr = e_ListResult(tmp_setof_listres->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_listres = tmp_setof_listres->next;
		}
		break;

	case OSTRSET:
		setof_ostr = (SET_OF_OctetString * )arg;

		for (tmp_setof_ostr = setof_ostr, cnt = 0; tmp_setof_ostr; 
			tmp_setof_ostr = tmp_setof_ostr->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_ostr = setof_ostr;

		while (tmp_setof_ostr){
			tmp_ostr = e_OctetString(tmp_setof_ostr->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_ostr = tmp_setof_ostr->next;
		}
		break;

	case OBJIDSET:
		setof_objid = (SET_OF_ObjId * )arg;

		for (tmp_setof_objid = setof_objid, cnt = 0; tmp_setof_objid; 
			tmp_setof_objid = tmp_setof_objid->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_objid = setof_objid;

		while (tmp_setof_objid){
			tmp_ostr = e_AttributeType(tmp_setof_objid->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_objid = tmp_setof_objid->next;
		}
		break;

	case SEARCHRESULTSET:
		setof_searchres = (SET_OF_SearchResult * )arg;

		for (tmp_setof_searchres = setof_searchres, cnt = 0; 
			tmp_setof_searchres; tmp_setof_searchres = tmp_setof_searchres->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_searchres = setof_searchres;

		while (tmp_setof_searchres){
			tmp_ostr = e_SearchResult(tmp_setof_searchres->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_searchres = tmp_setof_searchres->next;
		}
		break;

	case SECEXTENSIONSET:
		setof_secext = (SET_OF_SECExtension * )arg;

		for (tmp_setof_secext = setof_secext, cnt = 0; tmp_setof_secext; 
			tmp_setof_secext = tmp_setof_secext->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_secext = setof_secext;

		while (tmp_setof_secext){
			tmp_ostr = e_SECExtension(tmp_setof_secext->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_secext = tmp_setof_secext->next;
		}
		break;

	case SUBORDENTRYSET:
		setof_subord = (SET_OF_SubordEntry * )arg;

		for (tmp_setof_subord = setof_subord, cnt = 0; tmp_setof_subord; 
			tmp_setof_subord = tmp_setof_subord->next, cnt++)
			/* count */;
	
		oSTK = (OctetString ** )calloc(cnt, sizeof(OctetString * ));
		if(! oSTK)
			return(NULLPE);
	
		i = 0;
		tmp_setof_subord = setof_subord;

		while (tmp_setof_subord){
			tmp_ostr = e_SubordEntry(tmp_setof_subord->element);		
			oSTK[i] = aux_cpy_OctetString(tmp_ostr);
			aux_free_OctetString(&tmp_ostr);
			if(! oSTK[i++])
				return(NULLPE);
			tmp_setof_subord = tmp_setof_subord->next;
		}
		break;

	default:
		return(NULLPE);

	} /* switch */


	
	/* sort elements of oSTK in ascending order */

	for (i = 0; i < cnt - 1; i++) {
		k = i;
		tmp_ostr = oSTK[i];
		for (j = i + 1; j < cnt; j++) {

			/* n = min(tmp_ostr->noctets, oSTK[j]->noctets) */
			n = tmp_ostr->noctets;
			if(oSTK[j]->noctets < tmp_ostr->noctets)
				n = oSTK[j]->noctets;

			s = 0;
			while (oSTK[j]->octets[s] == tmp_ostr->octets[s] && s < n)
				s++;
			if(s < n && (a = oSTK[j]->octets[s]) < (b = tmp_ostr->octets[s])){
				k = j;
				tmp_ostr = oSTK[j];
			} /* if */

		}  /* for */
		oSTK[k] = oSTK[i];
		oSTK[i] = tmp_ostr;
	}  /* for */


    	if ((pe = pe_alloc (PE_CLASS_UNIV, PE_FORM_CONS, PE_CONS_SET)) == NULLPE)
        	return NULLPE;

    	for(i = 0; i < cnt; i++) {
		p25 = aux_OctetString2PE(oSTK[i]);

        	(void) set_addon (pe, p24, p25);
        	p24 = p25;
    	}


	for(i = 0; i < cnt; i++)
		aux_free_OctetString(&oSTK[i]);

	free (oSTK);

	return(pe);
}


%}
