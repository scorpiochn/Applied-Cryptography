--
--                 AlgorithmIdentifier and KeyInfo from:
--            X.509 The Directory - Authentication Framework
--                   Subset of Definitions in Annex G.
--
--                KeyBits and PSEToc from SecureDFN Project

-- AuthenticationFramework
SEC      DEFINITIONS ::=

%{      /* surrounding global definitions       */
#include        "secure.h"


PE              aux_OctetString2PE();
OctetString    *aux_PE2OctetString();

RC 		dec_RSAAlgorithm();
RC 		dec_DSAAlgorithm();
%}

BEGIN
-- EXPORTS
--              AlgorithmIdentifier, KeyInfo, DigestInfo, EncryptedKey,
--              KeyBits, PSEToc
--
-- IMPORTS	
--              UTCTime, BITSTRING, OCTETSTRING, INTEGER, PrintableString
--			FROM UNIV
--
-- functions symmetric for both parsing and building
SECTIONS build  parse none



OctetString [[ P struct OctetString * ]]
   	::= 
	OCTETSTRING 
	[[ o parm->octets $ parm->noctets ]]


OURINTEGER [[ P OctetString * ]]
	::=
	[UNIVERSAL 2] IMPLICIT OCTETSTRING
	[[ o parm->octets $
	     parm->noctets   ]]


ENCODER build


GRAPHICString [[ P char * ]] 
	::=
	GraphicString
	[[s parm]]


KeyBits [[ P KeyBits * ]]
	%{
	OctetString * tmp_ostr1, * tmp_ostr2 = NULLOCTETSTRING, * tmp_ostr3 = NULLOCTETSTRING, * tmp_ostr4 = NULLOCTETSTRING;
	int           i, j;
	int	      choice = 1;
	%}
        ::= 
	%{

	/* valid constellation:

	   (parm->part2.noctets = 0 && parm->part3.noctets = 0 && parm->part4.noctets = 0) ||
	   (parm->part2.noctets > 0 && parm->part3.noctets = 0 && parm->part4.noctets = 0) ||
	   (parm->part2.noctets > 0 && parm->part3.noctets > 0 && parm->part4.noctets > 0)
	*/

	if ((parm->part1.noctets == 0) ||
	    ((parm->part2.noctets > 0 || parm->part3.noctets > 0 || parm->part4.noctets > 0) &&
	     (parm->part2.noctets == 0 || parm->part3.noctets > 0 || parm->part4.noctets > 0) &&
	     (parm->part2.noctets == 0 || parm->part3.noctets == 0 || parm->part4.noctets == 0)))
		return(NOTOK);

	if (parm->part2.noctets == 0 && parm->part3.noctets == 0 && parm->part4.noctets == 0)
		choice = 3;

	if (parm->part2.noctets > 0 && parm->part3.noctets > 0 && parm->part4.noctets > 0)
		choice = 2;

	tmp_ostr1 = (OctetString * )malloc(sizeof(OctetString));

	if(parm->part1.octets[0] & MSBITINBYTE){

	        /* Most significant bit in most significant byte is 1. */
		/* Therefore, leading 0 byte is required to conform to ASN-1 integer encoding */

		tmp_ostr1->noctets = parm->part1.noctets + 1;
		tmp_ostr1->octets = (char * ) calloc( 1 , tmp_ostr1->noctets );
		tmp_ostr1->octets[0] = 0x00;
		for ( i = 0, j = 1; i < parm->part1.noctets; i++, j++)
			tmp_ostr1->octets[j] = parm->part1.octets[i];
	}
	else{
		tmp_ostr1->noctets = parm->part1.noctets;
		tmp_ostr1->octets = (char * ) calloc( 1 , tmp_ostr1->noctets );
		for ( i = 0; i < parm->part1.noctets; i++)
			tmp_ostr1->octets[i] = parm->part1.octets[i];
	}

	if (parm->part2.noctets > 0) {
		tmp_ostr2 = (OctetString * )malloc(sizeof(OctetString));

		if(parm->part2.octets[0] & MSBITINBYTE){
	
			/* Most significant bit in most significant byte is 1. */
			/* Therefore, leading 0 byte is required to conform to ASN-1 integer encoding */
	
			tmp_ostr2->noctets = parm->part2.noctets + 1;
			tmp_ostr2->octets = (char * ) calloc( 1 , tmp_ostr2->noctets );
			tmp_ostr2->octets[0] = 0x00;
			for ( i = 0, j = 1; i < parm->part2.noctets; i++, j++)
				tmp_ostr2->octets[j] = parm->part2.octets[i];
		}
		else{
			tmp_ostr2->noctets = parm->part2.noctets;
			tmp_ostr2->octets = (char * ) calloc( 1 , tmp_ostr2->noctets );
			for ( i = 0; i < parm->part2.noctets; i++)
				tmp_ostr2->octets[i] = parm->part2.octets[i];
		}
	}

	if (parm->part3.noctets > 0) {
		tmp_ostr3 = (OctetString * )malloc(sizeof(OctetString));

		if(parm->part3.octets[0] & MSBITINBYTE){
	
			/* Most significant bit in most significant byte is 1. */
			/* Therefore, leading 0 byte is required to conform to ASN-1 integer encoding */
	
			tmp_ostr3->noctets = parm->part3.noctets + 1;
			tmp_ostr3->octets = (char * ) calloc( 1 , tmp_ostr3->noctets );
			tmp_ostr3->octets[0] = 0x00;
			for ( i = 0, j = 1; i < parm->part3.noctets; i++, j++)
				tmp_ostr3->octets[j] = parm->part3.octets[i];
		}
		else{
			tmp_ostr3->noctets = parm->part3.noctets;
			tmp_ostr3->octets = (char * ) calloc( 1 , tmp_ostr3->noctets );
			for ( i = 0; i < parm->part3.noctets; i++)
				tmp_ostr3->octets[i] = parm->part3.octets[i];
		}
	}

	if (parm->part4.noctets > 0) {
		tmp_ostr4 = (OctetString * )malloc(sizeof(OctetString));

		if(parm->part4.octets[0] & MSBITINBYTE){
	
			/* Most significant bit in most significant byte is 1. */
			/* Therefore, leading 0 byte is required to conform to ASN-1 integer encoding */
	
			tmp_ostr4->noctets = parm->part4.noctets + 1;
			tmp_ostr4->octets = (char * ) calloc( 1 , tmp_ostr4->noctets );
			tmp_ostr4->octets[0] = 0x00;
			for ( i = 0, j = 1; i < parm->part4.noctets; i++, j++)
				tmp_ostr4->octets[j] = parm->part4.octets[i];
		}
		else{
			tmp_ostr4->noctets = parm->part4.noctets;
			tmp_ostr4->octets = (char * ) calloc( 1 , tmp_ostr4->noctets );
			for ( i = 0; i < parm->part4.noctets; i++)
				tmp_ostr4->octets[i] = parm->part4.octets[i];
		}
	}
	%}

	SEQUENCE {
	    part1       OURINTEGER
			[[ p tmp_ostr1 ]]
	    ,
	    CHOICE <<choice>>
	    {
			part2       OURINTEGER
				    [[ p tmp_ostr2 ]]

	    		,

			SEQUENCE {
			prime1      [0] OURINTEGER
				    [[ p tmp_ostr2 ]]
			,
			prime2      [1] OURINTEGER
				    [[ p tmp_ostr3 ]]
			,
			base        [2] OURINTEGER
				    [[ p tmp_ostr4 ]]
	    		}
	    } OPTIONAL <<choice == 1 || choice == 2>>
	}

	%{
	if(tmp_ostr1) aux_free_OctetString(&tmp_ostr1);
	if(tmp_ostr2) aux_free_OctetString(&tmp_ostr2);
	if(tmp_ostr3) aux_free_OctetString(&tmp_ostr3);
	if(tmp_ostr4) aux_free_OctetString(&tmp_ostr4);
	%}



KeyInfo [[ P KeyInfo * ]]
    ::= SEQUENCE {
	    algorithm   AlgorithmIdentifier
			[[ p parm->subjectAI ]],

	    key         BITSTRING
			[[ x parm->subjectkey.bits $
			     parm->subjectkey.nbits ]]
	}


DigestInfo [[ P DigestInfo * ]]
    ::= SEQUENCE {
	    digestai    AlgorithmIdentifier
			[[ p parm->digestAI ]],

	    digest      OCTETSTRING
			[[ o parm->digest.octets $
			     parm->digest.noctets ]]
	}


EncryptedKey [[ P EncryptedKey * ]]
    ::= SEQUENCE {
	    algorithm   AlgorithmIdentifier
			[[ p parm->encryptionAI ]],

	    algorithm   AlgorithmIdentifier
			[[ p parm->subjectAI ]],

	    key         BITSTRING
			[[ x parm->subjectkey.bits $
			     parm->subjectkey.nbits ]]
	}


AlgorithmIdentifier [[ P AlgId * ]]
    %{
	int paramchoice;
    %}
    ::= SEQUENCE {
	    objectid    OBJECT IDENTIFIER
			[[ O parm->objid ]]
			-- for all algorithms true --
     %{
	    paramchoice=aux_ObjId2ParmType( parm->objid );
	    if( !(parm->parm) || (paramchoice < 0) ) paramchoice=4;
     %}
	    ,
	    parameters  CHOICE << paramchoice >>
		{
		  keysize   INTEGER             --- RSA Algorithms
		  [[ i *(rsa_parm_type *)(parm->parm) ]]
		     -- ignore blocksize
		  ,
		  desIv     OCTETSTRING         --- DES Algorithms
		  [[ o ((desCBC_parm_type *)(parm->parm))->octets $
		       ((desCBC_parm_type *)(parm->parm))->noctets   ]]
		  ,
		  blocksize INTEGER             --- Hash Algorithms
		  [[ i *(rsa_parm_type *)(parm->parm) ]]
		  ,
		  NULL
		}  
	}

PSEToc [[ P PSEToc *]]
    ::= SEQUENCE {
	    owner      PrintableString [[ s parm->owner ]] ,
	    create     UTCTime         [[ s parm->create ]] ,
	    update     UTCTime         [[ s parm->update ]] ,
	    status     INTEGER         [[ i parm->status ]]
		       DEFAULT 0 <<parm -> status != 0>>,
	    sCObjects  PSEObjects       [[ p parm->obj   ]]
		       OPTIONAL << parm->obj >>
	    }

PSEObjects [[ P struct PSE_Objects * ]]
    ::= SET OF  << ; parm ; parm=parm->next >>
	     SEQUENCE {
		 name       PrintableString [[ s parm->name ]] ,
		 create     UTCTime         [[ s parm->create ]] ,
		 update     UTCTime         [[ s parm->update ]],
		 noOctets   [0] INTEGER     [[ i parm->noOctets ]],
		 status     [1] INTEGER     [[ i parm->status ]]
		            DEFAULT 0 <<parm -> status != 0>>
		 }

PSEObject [[ P PSEObject * ]]
     %{
	PE new_pe;
     %}
    ::= SEQUENCE {
	    type        OBJECT IDENTIFIER
			[[ O parm->objectType ]]  
			-- for all algorithms true --
     %{
	    new_pe = aux_OctetString2PE(parm->objectValue);
     %}
	    ,		
	    value       ANY
			[[ a new_pe ]]
			%{
			  pe_free(new_pe);
			%}
	}


DECODER parse


GRAPHICString [[ P char ** ]] 
	::=
	GraphicString
	[[s *parm]]


RSAAlgorithm [[ P KeyBits * ]]
	::=
	OURINTEGER
	[[ p &parm->part2]]


DSAAlgorithm [[ P KeyBits * ]]
	::=
	SEQUENCE {
	prime1      [0] OURINTEGER
		    [[ p &parm->part2]]
	,
	prime2      [1] OURINTEGER
		    [[ p &parm->part3]]
	,
	base        [2] OURINTEGER
		    [[ p &parm->part4]]
	}


KeyBits [[ P KeyBits * ]]
        %{
	int i, rc;
	OctetString * ostr;
	PE parts = NULLPE;
        %} 
	::= 
        %{
	parm->part2.noctets = 0;
	parm->part2.octets = CNULL;
	parm->part3.noctets = 0;
	parm->part3.octets = CNULL;
	parm->part4.noctets = 0;
	parm->part4.octets = CNULL;
        %}
	SEQUENCE {
	    part1       
		OURINTEGER
		[[ p &parm->part1]],

		ANY
	      	[[ a parts ]]
		OPTIONAL
	}

	%{

	if (parts) {
		ostr = aux_PE2OctetString(parts);
		if (! ostr)
			return (NOTOK);
		if (! (ostr->octets[0] & 0xCF))
			/* ostr->octets[0] = '30' */
			rc = dec_DSAAlgorithm(parts, parm);
		else
			rc = dec_RSAAlgorithm(parts, parm);
	}

	if(! (parm->part1.octets[0] | 0x00) ){    

		/* The bits of the most significant byte are all 0, so delete them */

		for ( i = 0; i < parm->part1.noctets - 1; i++)
		    parm->part1.octets[i] = parm->part1.octets[i + 1];
		parm->part1.noctets -= 1;
		parm->part1.octets = (char *)realloc(parm->part1.octets, parm->part1.noctets);
	}

	if (parm->part2.noctets > 0) {
		if (! (parm->part2.octets[0] | 0x00) ){

		    /* The bits of the most significant byte are all 0, so delete them */

		    for ( i = 0; i < parm->part2.noctets - 1; i++)
			    parm->part2.octets[i] = parm->part2.octets[i + 1];
		    parm->part2.noctets -= 1;
		    parm->part2.octets = (char *)realloc(parm->part2.octets, parm->part2.noctets);
		}
	}

	if (parm->part3.noctets > 0) {
		if (! (parm->part3.octets[0] | 0x00) ){

		    /* The bits of the most significant byte are all 0, so delete them */

		    for ( i = 0; i < parm->part3.noctets - 1; i++)
			    parm->part3.octets[i] = parm->part3.octets[i + 1];
		    parm->part3.noctets -= 1;
		    parm->part3.octets = (char *)realloc(parm->part3.octets, parm->part3.noctets);
		}
	}

	if (parm->part4.noctets > 0) {
		if (! (parm->part4.octets[0] | 0x00) ){
	
		    /* The bits of the most significant byte are all 0, so delete them */
    
		    for ( i = 0; i < parm->part4.noctets - 1; i++)
			    parm->part4.octets[i] = parm->part4.octets[i + 1];
		    parm->part4.noctets -= 1;
		    parm->part4.octets = (char *)realloc(parm->part4.octets, parm->part4.noctets);
		}
	}
	%}


KeyInfo [[ P KeyInfo * ]]
    ::= SEQUENCE {
	    algorithm   AlgorithmIdentifier
			[[ p &parm->subjectAI ]],

	    key         BITSTRING
			[[ x parm->subjectkey.bits $
			     parm->subjectkey.nbits ]]
	}


DigestInfo [[ P DigestInfo * ]]
    ::= SEQUENCE {
	    digestai    AlgorithmIdentifier
			[[ p &parm->digestAI ]],

	    digest      OCTETSTRING
			[[ o parm->digest.octets $
			     parm->digest.noctets ]]
	}


EncryptedKey [[ P EncryptedKey * ]]
    ::= SEQUENCE {
	    algorithm   AlgorithmIdentifier
			[[ p &parm->encryptionAI ]],

	    algorithm   AlgorithmIdentifier
			[[ p &parm->subjectAI ]],

	    key         BITSTRING
			[[ x parm->subjectkey.bits $
			     parm->subjectkey.nbits ]]
	}


AlgorithmIdentifier [[ P AlgId ** ]]
    %{
	int paramchoice, keyorblocksize;
	PE  errorparm;
	rsa_parm_type     *rsa_parm;
	desCBC_parm_type *des_parm;
    %}
    ::=
    %{
        if ((*(parm) = (AlgId *)
                calloc (1, sizeof **(parm))) == ((AlgId *) 0)) {
            advise (NULLCP, "out of memory");
            return NOTOK;
        }
    %}
SEQUENCE {
	    objectid    OBJECT IDENTIFIER
			[[ O (*parm)->objid ]]
			-- for all algorithms true --
     %{
	    (*parm)->parm = (char *)0;
	    paramchoice=aux_ObjId2ParmType( (*parm)->objid );
	    if( paramchoice<0 ) paramchoice=4;
	    errorparm=int2prim(0); /*set errorparm to 0-INTEGER*/
	    des_parm=(desCBC_parm_type *)malloc(sizeof(desCBC_parm_type));
     %}
	    ,
	    parameters  CHOICE
		{
		  keysize   INTEGER    --- RSA or Hash Algorithms
		  [[ i keyorblocksize ]]
     %{
		  free( des_parm );
		  if( paramchoice == 1) { /*RSA:*/
		     rsa_parm=(rsa_parm_type *)malloc(sizeof(rsa_parm_type));
		     *rsa_parm=keyorblocksize;
		     (*parm)->parm=(char *)rsa_parm;
		     }
		  else if( paramchoice == 3) { /*Hash:*/
		     rsa_parm=(rsa_parm_type *)malloc(sizeof(rsa_parm_type));
		     *rsa_parm=keyorblocksize;
		     (*parm)->parm=(char *)rsa_parm;
		     }
		   else { /*erraneous parameter:*/
		     (*parm)->parm = (char *)0;
		     }
     %}
		  ,
		  OCTETSTRING         --- DES Algorithms
		  [[ o des_parm->octets $ des_parm->noctets ]]
     %{
		  (*parm)->parm=(char *)des_parm;
     %}
		  ,
		  ANY                 --- undefined objids
		  [[ a errorparm ]]
     %{
		  (*parm)->parm = (char *)0;
		  free( des_parm );
     %}
		}   OPTIONAL
	 }


PSEToc [[ P PSEToc *]]
    ::= SEQUENCE
	    %{
	      parm->obj=(struct PSE_Objects *)0;
	      parm->status = 0;
	    %} {
	    owner      PrintableString  [[ s parm->owner ]] ,
	    create     UTCTime          [[ s parm->create ]] ,
	    update     UTCTime          [[ s parm->update ]] ,
	    status     INTEGER		[[ i parm->status ]]
		       OPTIONAL << parm->status >>,
	    sCObjects  PSEObjects       [[ p &(parm->obj) ]]
		       OPTIONAL << parm->obj >>
	    }

PSEObjects [[ P struct PSE_Objects ** ]]
    ::= SET OF
	    %{
	      if( (*parm=(struct PSE_Objects *)malloc(sizeof(struct PSE_Objects)))
		  == (struct PSE_Objects *)0 ){
		    advise (NULLCP, "out of memory");
		    return( NOTOK );
		    }
	      (*parm)->noOctets = 0;
	      (*parm)->status = 0;
	      (*parm)->next=(struct PSE_Objects *)0;
	    %}
		SEQUENCE {
		    name       PrintableString [[ s (*parm)->name ]] ,
		    create     UTCTime         [[ s (*parm)->create ]] ,
		    update     UTCTime         [[ s (*parm)->update ]],
		    noOctets   [0] INTEGER     [[ i (*parm)->noOctets ]]
			       OPTIONAL,
		    status     [1] INTEGER     [[ i (*parm)->status ]]
			       OPTIONAL << (*parm)->status >>
		    }
	    %{
	      parm = &((*parm)->next);
	    %}

PSEObject [[ P PSEObject * ]]
%{
PE any = NULLPE;
%}
    ::= SEQUENCE {
	    type        OBJECT IDENTIFIER
			[[ O parm->objectType ]]
			-- for all algorithms true --
	    ,
	    value       ANY
			[[ a any ]]
			%{
			  parm->objectValue = aux_PE2OctetString(any);
			  pe_free(any);
			%}
	}


END
