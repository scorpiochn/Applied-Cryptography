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
 ************************************************************************/

/*-----------------------af-encdec.c------------------------------------*/
/*----------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               	*/
/* Rheinstr. 75 / Dolivostr. 15                                     	*/
/* 6100 Darmstadt                                                  	*/
/* Project ``Secure DFN'' 1990                                      	*/
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 	*/
/*----------------------------------------------------------------------*/
/*                                                                  	*/
/* PACKAGE   encode-decode   VERSION   1.3                          	*/
/*                              DATE   27.09.1990                   	*/
/*                                BY   Nausester/Grimm              	*/
/*                                                                  	*/
/*                            REVIEW                                	*/
/*                              DATE                                	*/
/*                                BY                                	*/
/* DESCRIPTION                                                      	*/
/*   This modul presents     functions to encode and                    */
/*   decode X509-Octetstrings into/from C-structures               	*/
/*   ``Encode'': C-structure ---> ASN.1-Octetstring                 	*/
/*   ``Decode'': ASN.1-Octetstring ---> C-structure                 	*/
/*                                                                  	*/
/*                                                                  	*/
/* EXPORT                    DESCRIPTION                            	*/
/*                                                                  	*/
/*  e_DName()                  Encodes DName structure           	*/
/*  d_DName()                  Decodes DName structure         	        */
/*                                                                  	*/
/*  e_Certificates()           Encodes certificates                 	*/
/*  d_Certificates()           Decodes certificates                 	*/
/*                                                                  	*/
/*  e_Certificate ()           Encodes one certiciate               	*/
/*  d_Certificate ()           Decodes one certificate              	*/
/*                                                                  	*/
/*  e_CertificateSet ()        Encodes one certificateSet           	*/
/*  d_CertificateSet ()        Decodes one certificateSet           	*/
/*                                                                  	*/
/*  e_CertificatePairSet ()    Encodes one CrossCertificatePairSet  	*/
/*  d_CertificatePairSet ()    Decodes one CrossCertificatePairSet  	*/
/*                                                                 	*/
/*  e_Crl ()    	       Encodes one Revocation List (X.500) 	*/
/*  d_Crl ()                   Decodes one Revocation List (X.500)      */
/*                                                                      */
/*  e_RevCert ()    	       Encodes one Revoked Certificate (X.500)  */
/*  d_RevCert ()               Decodes one Revoked Certificate (X.500)  */
/*                                                                      */
/*  e_PemCrl ()                Encodes one Revocation List (PEM)        */
/*  d_PemCrl ()                Decodes one Revocation List (PEM)        */
/*                                                                      */
/*  e_RevCertPem ()    	       Encodes one Revoked Certificate (PEM)    */
/*  d_RevCertPem ()            Decodes one Revoked Certificate (PEM)    */
/*                                                                      */
/*  e_CrlSet ()    	       Encodes a CrlSet                         */
/*  d_CrlSet ()                Decodes a CrlSet                         */
/*                                                                      */
/*  e_ToBeSigned()             Encodes the ToBeSigned                   */
/*                             subfield of a Certificate          	*/
/*                                                                	*/
/*  e_FCPath()                 Encodes an FCPath                   	*/
/*  d_FCPath()                 Decodes an FCPath                   	*/
/*                                                                 	*/
/*  e_PKRoot()                 Encodes a PKRoot table              	*/
/*  d_PKRoot()                 Decodes a PKRoot table              	*/
/*                                                                 	*/
/*  e_PKList()                 Encodes a PKList table              	*/
/*  d_PKList()                 Decodes a PKList table              	*/
/*                                                                      */
/*  more encode-decode functions are defined                       	*/
/*  in sec-encdec.c:                                                	*/
/*                                                                  	*/
/*  e_AlgId()                  Encodes an algorithm id             	*/
/*  d_AlgId()                  Decodes an algorithm id             	*/
/*  d2_AlgId()                 Decodes an algorithm id                  */
/*                             into a given struct AlgId            	*/
/*                                                                      */
/*  e_KeyInfo()                Encodes a KeyInfo                   	*/
/*  d_KeyInfo()                Decodes a KeyInfo                   	*/
/*  d2_KeyInfo()               Decodes a KeyInfo into a            	*/
/*                             given struct KeyInfo                	*/
/*                                                                 	*/
/*  e_KeyBits()                Encodes KeyBits                      	*/
/*  d_KeyBits()                Decodes KeyBits                      	*/
/*                                                                  	*/
/*  e_PSEToc()                 Encodes PSEToc table                 	*/
/*  d_PSEToc()                 Decodes PSEToc table                 	*/
/*                                                                  	*/
/*                                                                      */
/* IMPORT                    DESCRIPTION                            	*/
/*                                                                  	*/
/*  build_..., parse_...       ISODE-PEPY resulted                  	*/
/*                             encode-decode functions             	*/
/*                             from: AF.py, IF.py, SEC.py          	*/
/*                                                                 	*/
/*  free_Octetstring()         Releases Octetstring memory          	*/
/*  free_Certificates()        Releases Certificates mem.          	*/
/*  err_Certficates()          error diagnostic                     	*/
/*                             from: sec-encdec.c                  	*/
/*                                                                 	*/
/*  aux_DName2Name()          Map between ISODE-PEPY               	*/
/*  aux_Name2DName()          defined C-structures and             	*/
/*                             "C=de;..." printable                 	*/
/*                             representations of Names             	*/
/*                             from: aux-encdec.c                   	*/
/*                                                                  	*/
/*  aux_PE2OctetString(),             Map between ISODE-PE              */
/*  aux_OctetString2PE()              (presentation elements)           */
/*                             and ASN.1 Octetstrings               	*/
/*                             from: aux-encdec.c                   	*/
/*                                                                  	*/
/*----------------------------------------------------------------------*/

#include "psap.h"
#include "af.h"
#ifdef TEST
#include <stdio.h>
#endif


OctetString         *aux_PE2OctetString(/* PE */);
PE                   aux_OctetString2PE(/* (OctetString *) */);
struct type_IF_Name *aux_Name2DName(/* char * */);
char	*aux_DName2Name(/* struct type_IF_Name */);


OctetString  *e_DName(namestruct)
DName  *namestruct;
{
	PE                 P_Name;
	OctetString      * ret;
	char	   	 * proc = "e_DName";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (namestruct == NULLDNAME)
		return (OctetString * ) 0;

	if (build_IF_Name(&P_Name, 1, 0, CNULL, namestruct) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_Name);
	pe_free(P_Name);

	return (ret);
}


DName *d_DName(asn1_string)
OctetString *asn1_string;
{
	PE		P_Name;
	int		result;
	DName         * namestruct;
	char	      * proc = "d_DName";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (NULLDNAME);

	P_Name = aux_OctetString2PE(asn1_string);

	if (P_Name == NULLPE)
		return (NULLDNAME);

	result = parse_IF_Name(P_Name, 1, NULLIP, NULLVP, &namestruct);
	pe_free(P_Name);

	return (result ? NULLDNAME : namestruct);
}


OctetString  * e_Attribute(attr)
Attr  * attr;
{
	PE                 P_Attribute;
	OctetString      * ret;
	char	   	 * proc = "e_Attribute";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! attr)
		return (NULLOCTETSTRING);

	if (build_IF_Attribute(&P_Attribute, 1, 0, CNULL, attr) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_Attribute);
	pe_free(P_Attribute);

	return (ret);
}


OctetString  * e_AttributeType(attrtype)
AttrType  * attrtype;
{
	PE                 P_AttributeType;
	OctetString      * ret;
	char	   	 * proc = "e_AttributeType";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! attrtype)
		return (NULLOCTETSTRING);

	if (build_IF_AttributeType(&P_AttributeType, 1, 0, CNULL, attrtype) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_AttributeType);
	pe_free(P_AttributeType);

	return (ret);
}


OctetString  * e_AttributeValueAssertion(ava)
AttributeValueAssertion  * ava;
{
	PE                 P_AVA;
	OctetString      * ret;
	char	   	 * proc = "e_AttributeValueAssertion";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! ava)
		return (NULLOCTETSTRING);

	if (build_IF_AttributeValueAssertion(&P_AVA, 1, 0, CNULL, ava) == NOTOK)
		return (NULLOCTETSTRING);

	ret = aux_PE2OctetString(P_AVA);
	pe_free(P_AVA);

	return (ret);
}


OctetString  * e_SerialNumbers (serialnums )
SerialNumbers  * serialnums ;
{
	PE             P_SerialNums ;
	OctetString  * ret;
	char	     * proc = "e_SerialNumbers";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (serialnums  == (SerialNumbers  * )0)
		return (OctetString * ) 0;

	if (build_AF_SerialNumbers (&P_SerialNums , 1, 0, CNULL, serialnums ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_SerialNums );
	pe_free(P_SerialNums );

	return (ret);
}


SerialNumbers  * d_SerialNumbers (asn1_string)
OctetString * asn1_string;
{
	PE               P_SerialNums ;
	SerialNumbers  * ret;
	int		 result;
	char	       * proc = "d_SerialNumbers";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (SerialNumbers  * ) 0;

	P_SerialNums  = aux_OctetString2PE(asn1_string);

	if (P_SerialNums  == NULLPE)
		return (SerialNumbers  * ) 0;

	result = parse_AF_SerialNumbers (P_SerialNums , 1, NULLIP, NULLVP, &ret);
	pe_free(P_SerialNums);

	return (result ? (SerialNumbers  * ) 0 : ret);
}


OctetString  *e_Certificates(certificates)
Certificates *certificates;
{
	PE             P_Certificates;
	OctetString  * ret;
	char	     * proc = "e_Certificates";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (certificates == (Certificates * )0)
		return (OctetString * ) 0;

	if (build_AF_Certificates(&P_Certificates, 1, 0, CNULL, certificates) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_Certificates);
	pe_free(P_Certificates);

	return (ret);
}


Certificates *d_Certificates(asn1_string)
OctetString *asn1_string;
{
	PE              P_Certificates;
	Certificates  * ret;
	int		result;
	char	      * proc = "d_Certificates";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (Certificates * ) 0;

	P_Certificates = aux_OctetString2PE(asn1_string);

	if (P_Certificates == NULLPE)
		return (Certificates * ) 0;

	result = parse_AF_Certificates(P_Certificates, 1, NULLIP, NULLVP, &ret);
	pe_free(P_Certificates);

	return (result ? (Certificates * ) 0 : ret);
}


OctetString  *e_Certificate (certificate )
Certificate  *certificate ;
{
	PE             P_Certificate ;
	OctetString  * ret;
	char	     * proc = "e_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (certificate  == (Certificate  * )0)
		return (OctetString * ) 0;

	if (build_AF_Certificate (&P_Certificate , 1, 0, CNULL, certificate ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_Certificate );
	pe_free(P_Certificate );

	return (ret);
}


Certificate  *d_Certificate (asn1_string)
OctetString *asn1_string;
{
	PE             P_Certificate ;
	Certificate  * ret;
	int	       result;
	char	     * proc = "d_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (Certificate  * ) 0;

	P_Certificate  = aux_OctetString2PE(asn1_string);

	if (P_Certificate  == NULLPE)
		return (Certificate  * ) 0;


	/*    space for objid's is allocated by oid_cpy in
      parse_AF_AlgorithmIdentifier !
*/
	/*NOTE:                                                        */
	/*space for FCPath structure allocated by parse_AF_Certificate,*/
	/*parameter is of type Certificate * (not **!)                 */
	result = parse_AF_Certificate (P_Certificate , 1, NULLIP, NULLVP, &ret);
	pe_free(P_Certificate);

	return (result ? (Certificate  * ) 0 : ret);
}


OctetString  *e_CertificateSet (certset )
SET_OF_Certificate  *certset ;
{
	PE             P_CertSet ;
	OctetString  * ret;
	char	     * proc = "e_CertificateSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (certset  == (SET_OF_Certificate  * )0)
		return (OctetString * ) 0;

	if (build_AF_CertificateSet (&P_CertSet , 1, 0, CNULL, certset ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_CertSet );
	pe_free(P_CertSet );

	return (ret);
}


SET_OF_Certificate  *d_CertificateSet (asn1_string)
OctetString *asn1_string;
{
	PE                    P_CertSet ;
	SET_OF_Certificate  * ret;
	int		      result;
	char		    * proc = "d_CertificateSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (SET_OF_Certificate  * ) 0;

	P_CertSet  = aux_OctetString2PE(asn1_string);

	if (P_CertSet  == NULLPE)
		return (SET_OF_Certificate  * ) 0;

	result = parse_AF_CertificateSet (P_CertSet , 1, NULLIP, NULLVP, &ret);
	pe_free(P_CertSet);

	return (result ? (SET_OF_Certificate  * ) 0 : ret);
}


OctetString  *e_CertificatePairSet (cpairset)
SET_OF_CertificatePair  *cpairset;
{
	PE             P_CPairSet ;
	OctetString  * ret;
	char	     * proc = "e_CertificatePairSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (cpairset  == (SET_OF_CertificatePair  * )0)
		return (OctetString * ) 0;

	if (build_AF_CrossCertificatePair (&P_CPairSet , 1, 0, CNULL, cpairset ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_CPairSet );
	pe_free(P_CPairSet );

	return (ret);
}


SET_OF_CertificatePair  *d_CertificatePairSet (asn1_string)
OctetString *asn1_string;
{
	PE           		  P_Cpairset ;
	SET_OF_CertificatePair  * ret;
	int			  result;
	char			* proc = "d_CertificatePairSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (SET_OF_CertificatePair  * ) 0;

	P_Cpairset  = aux_OctetString2PE(asn1_string);

	if (P_Cpairset  == NULLPE)
		return (SET_OF_CertificatePair  * ) 0;

	result = parse_AF_CrossCertificatePair (P_Cpairset , 1, NULLIP, NULLVP, &ret);
	pe_free(P_Cpairset);

	return (result ? (SET_OF_CertificatePair  * ) 0 : ret);
}


OctetString  *e_ToBeSigned(tobesigned)
ToBeSigned *tobesigned;
{
	PE             P_TBSCertificate;
	OctetString  * ret;
	char	     * proc = "e_ToBeSigned";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (tobesigned == (ToBeSigned * )0)
		return (OctetString * ) 0;

	if (build_AF_TBSCertificate(&P_TBSCertificate, 1, 0, CNULL, tobesigned) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_TBSCertificate);
	pe_free(P_TBSCertificate);

	return (ret);
}


#ifdef COSINE
OctetString  *e_AuthorisationAttributes(authattrbts)
AuthorisationAttributes       *authattrbts;
{
	PE             P_AuthorisationAttributes;
	OctetString  * ret;
	char	     * proc = "e_AuthorisationAttributes";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (authattrbts == (AuthorisationAttributes * )0)
		return (OctetString * ) 0;

	if (build_AF_AuthorisationAttributes(&P_AuthorisationAttributes, 1, 0, CNULL, authattrbts)
	     == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_AuthorisationAttributes);
	pe_free(P_AuthorisationAttributes);

	return (ret);
}


AuthorisationAttributes *d_AuthorisationAttributes(asn1_string)
OctetString *asn1_string;
{
	PE                         P_AuthorisationAttributes;
	AuthorisationAttributes  * ret;
	int			   result;
	char			 * proc = "d_AuthorisationAttributes";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (AuthorisationAttributes * ) 0;

	P_AuthorisationAttributes = aux_OctetString2PE(asn1_string);

	if (P_AuthorisationAttributes == NULLPE)
		return (AuthorisationAttributes * ) 0;

	/*NOTE:                                                       */
	/*space for AuthorisationAttributes structure allocated by    */
	/*parse_AF_AuthorisationAttributes,			      */
	/*parameter is of type AuthorisationAttributes ** (not *!)    */

	result = parse_AF_AuthorisationAttributes(P_AuthorisationAttributes, 1, NULLIP, NULLVP, &ret);
	pe_free(P_AuthorisationAttributes);

	return (result ? (AuthorisationAttributes * ) 0 : ret);
}
#endif


OctetString  *e_FCPath(fcpath)
FCPath       *fcpath;
{
	PE             P_FCPath;
	OctetString  * ret;
	char	     * proc = "e_FCPath";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (fcpath == (FCPath * )0)
		return (OctetString * ) 0;

	if (build_AF_ForwardCertificationPath(&P_FCPath, 1, 0, CNULL, fcpath)
	     == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_FCPath);
	pe_free(P_FCPath);

	return (ret);
}


FCPath *d_FCPath(asn1_string)
OctetString *asn1_string;
{
	PE            P_FCPath;
	FCPath      * ret;
	int	      result;
	char	    * proc = "d_FCPath";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (FCPath * ) 0;

	P_FCPath = aux_OctetString2PE(asn1_string);

	if (P_FCPath == NULLPE)
		return (FCPath * ) 0;

	/*NOTE:                                                       */
	/*space for FCPath structure allocated by parse_AF_Fo.Ce.Path,*/
	/*parameter is of type FCPath ** (not *!)                     */

	result = parse_AF_ForwardCertificationPath(P_FCPath, 1, NULLIP, NULLVP, &ret);
	pe_free(P_FCPath);

	return (result ? (FCPath * ) 0 : ret);
}


OctetString  *e_PKRoot (pkroot )
PKRoot       *pkroot ;
{
	PE             P_PKRoot ;
	OctetString  * ret;
	char	     * proc = "e_PKRoot";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (pkroot  == (PKRoot  * )0)
		return (OctetString * ) 0;

	if (build_AF_PKRoot (&P_PKRoot , 1, 0, CNULL, pkroot ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_PKRoot );
	pe_free(P_PKRoot );

	return (ret);
}


PKRoot  *d_PKRoot (asn1_string)
OctetString *asn1_string;
{
	PE            P_PKRoot ;
	PKRoot      * ret;
	int	      result;
	char	    * proc = "d_PKRoot";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (PKRoot  * ) 0;

	P_PKRoot  = aux_OctetString2PE(asn1_string);

	if (P_PKRoot  == NULLPE)
		return (PKRoot  * ) 0;

	/*NOTE:                                                       */
	/*space for PKRoot structure allocated by parse_AF_PKRoot,*/

	/*NOTE: parameter is of type PKRoot * (not **!) */
	result = parse_AF_PKRoot (P_PKRoot , 1, NULLIP, NULLVP, &ret);
	pe_free(P_PKRoot);

	return (result ? (PKRoot  * ) 0 : ret);
}


OctetString  *e_PKList(pklist)
PKList       *pklist;
{
	PE             P_PKList;
	OctetString  * ret;
	char	     * proc = "e_PKList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (pklist == (PKList * )0)
		return (OctetString * ) 0;

	if (build_AF_PKList(&P_PKList, 1, 0, CNULL, pklist) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_PKList);
	pe_free(P_PKList);

	return (ret);
}


PKList *d_PKList(asn1_string)
OctetString *asn1_string;
{
	PE            P_PKList;
	PKList      * ret;
	int	      result;
	char	    * proc = "d_PKList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (PKList * ) 0;

	P_PKList = aux_OctetString2PE(asn1_string);

	if (P_PKList == NULLPE)
		return (PKList * ) 0;

	/*NOTE:                                                   */
	/*space for PKList structure allocated by parse_AF_PKList,*/
	/*parameter is of type PKList ** (not *!)                 */

	result = parse_AF_PKList(P_PKList, 1, NULLIP, NULLVP, &ret);
	pe_free(P_PKList);

	return (result ? (PKList * ) 0 : ret);
}


OctetString *e_Crl (crl)
Crl     *crl;
{
	PE            P_Crl;
	OctetString * ret;
	char	    * proc = "e_Crl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( crl == (Crl * )0 )
		return( (OctetString * )0 );

	if ( build_AF_Crl (&P_Crl, 1, 0, CNULL, crl) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_Crl);
	pe_free(P_Crl);

	return (ret);
}


Crl *d_Crl (asn1_string)
OctetString *asn1_string;
{
	PE           P_Crl;
	Crl    * ret;
	int	     result;
	char	   * proc = "d_Crl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( asn1_string == (OctetString * )0 )
		return( (Crl * )0 );

	P_Crl = aux_OctetString2PE(asn1_string);

	if ( P_Crl == NULLPE )
		return( (Crl * )0 );

	/*NOTE: Space for Crl is allocated by parse_AF_Crl,*/
	/*parameter is of type Crl ** (not *!) */

	result = parse_AF_Crl (P_Crl, 1, NULLIP, NULLVP, &ret);
	pe_free(P_Crl);

	return ( result ? (Crl * )0 : ret );
}


OctetString *e_RevCert (revcert)
RevCert	           *revcert;
{
	PE 		     P_RevCert;
	OctetString	   * ret;
	char		   * proc = "e_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( revcert == (RevCert * )0 )
		return( (OctetString * )0 );

	if ( build_AF_RevCert (&P_RevCert, 1, 0, CNULL, revcert) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_RevCert);
	pe_free(P_RevCert);

	return (ret);
}


RevCert *d_RevCert (asn1_string)
OctetString        *asn1_string;
{
	PE                  P_RevCert;
	RevCert 	  * ret;
	int		    result;
	char		  * proc = "d_RevCert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0 )
		return( (RevCert * )0 );

	P_RevCert = aux_OctetString2PE(asn1_string);

	if ( P_RevCert == NULLPE )
		return( (RevCert * )0 );

	/*NOTE: Space for RevCert is allocated by parse_AF_RevCert ,*/
	/*parameter is of type RevCert ** (not *!) */

	result = parse_AF_RevCert (P_RevCert, 1, NULLIP, NULLVP, &ret);
	pe_free(P_RevCert);

	return ( result ? (RevCert * )0 : ret );
}


OctetString *e_RevCertSequence (seq)
SEQUENCE_OF_RevCert	  *seq;
{
	PE                          P_RevCertSeq;
	OctetString               * ret;
	char			  * proc = "e_RevCertSequence";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( seq == (SEQUENCE_OF_RevCert * )0 )
		return( (OctetString * )0 );

	if ( build_AF_RevCertSequence (&P_RevCertSeq, 1, 0, CNULL, seq) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_RevCertSeq);
	pe_free(P_RevCertSeq);

	return (ret);
}


SEQUENCE_OF_RevCert *d_RevCertSequence (asn1_string)
OctetString               *asn1_string;
{
	PE                         P_RevCertSeq;
	SEQUENCE_OF_RevCert	 * ret;
	int			   result;
	char			 * proc = "d_RevCertSequence";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( asn1_string == (OctetString * )0 )
		return( (SEQUENCE_OF_RevCert * )0 );

	P_RevCertSeq = aux_OctetString2PE(asn1_string);

	if ( P_RevCertSeq == NULLPE )
		return( (SEQUENCE_OF_RevCert * )0 );

	result = parse_AF_RevCertSequence (P_RevCertSeq, 1, NULLIP, NULLVP, &ret);
	pe_free(P_RevCertSeq);

	return ( result ? (SEQUENCE_OF_RevCert * )0 : ret );
}


OctetString *e_PemCrl (pemcrl)
PemCrl      *pemcrl;
{
	PE                 P_PemCrl;
	OctetString 	 * ret;
	char		 * proc = "e_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( pemcrl == (PemCrl * )0 )
		return( (OctetString * )0 );

	if ( build_AF_PemCrl (&P_PemCrl, 1, 0, CNULL, pemcrl) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_PemCrl);
	pe_free(P_PemCrl);

	return (ret);
}


PemCrl *d_PemCrl (asn1_string)
OctetString *asn1_string;
{
	PE         	   P_PemCrl;
	PemCrl 	 * ret;
	int		   result;
	char		 * proc = "d_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( asn1_string == (OctetString * )0 )
		return( (PemCrl * )0 );

	P_PemCrl = aux_OctetString2PE(asn1_string);

	if ( P_PemCrl == NULLPE )
		return( (PemCrl * )0 );

	/*NOTE: Space for PemCrl is allocated by parse_AF_PemCrl,*/
	/*parameter is of type PemCrl ** (not *!) */

	result = parse_AF_PemCrl (P_PemCrl, 1, NULLIP, NULLVP, &ret);
	pe_free(P_PemCrl);

	return ( result ? (PemCrl * )0 : ret );
}


OctetString *e_RevCertPem (revcertpem)
RevCertPem 	   *revcertpem;
{
	PE 		     P_RevCertPem;
	OctetString	   * ret;
	char		   * proc = "e_RevCertPem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( revcertpem == (RevCertPem * )0 )
		return( (OctetString * )0 );

	if ( build_AF_RevCertPem (&P_RevCertPem, 1, 0, CNULL, revcertpem) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_RevCertPem);
	pe_free(P_RevCertPem);

	return (ret);
}


RevCertPem *d_RevCertPem (asn1_string)
OctetString        *asn1_string;
{
	PE                   P_RevCertPem;
	RevCertPem	   * ret;
	int		     result;
	char	 	   * proc = "d_RevCertPem";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0 )
		return( (RevCertPem * )0 );

	P_RevCertPem = aux_OctetString2PE(asn1_string);

	if ( P_RevCertPem == NULLPE )
		return( (RevCertPem * )0 );

	/*NOTE: Space for RevCertPem is allocated by parse_AF_RevCertPem ,*/
	/*parameter is of type RevCertPem ** (not *!) */

	result = parse_AF_RevCertPem (P_RevCertPem, 1, NULLIP, NULLVP, &ret);
	pe_free(P_RevCertPem);

	return ( result ? (RevCertPem * )0 : ret );
}


OctetString *e_RevCertPemSequence (seq)
SEQUENCE_OF_RevCertPem 	  *seq;
{
	PE                          P_RevCertPemSeq;
	OctetString               * ret;
	char			  * proc = "e_RevCertPemSequence";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( seq == (SEQUENCE_OF_RevCertPem * )0 )
		return( (OctetString * )0 );

	if ( build_AF_RevCertPemSequence (&P_RevCertPemSeq, 1, 0, CNULL, seq) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_RevCertPemSeq);
	pe_free(P_RevCertPemSeq);

	return (ret);
}


SEQUENCE_OF_RevCertPem *d_RevCertPemSequence (asn1_string)
OctetString               *asn1_string;
{
	PE                          P_RevCertPemSeq;
	SEQUENCE_OF_RevCertPem    * ret;
	int			    result;
	char			  * proc = "d_RevCertPemSequence";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( asn1_string == (OctetString * )0 )
		return( (SEQUENCE_OF_RevCertPem * )0 );

	P_RevCertPemSeq = aux_OctetString2PE(asn1_string);

	if ( P_RevCertPemSeq == NULLPE )
		return( (SEQUENCE_OF_RevCertPem * )0 );

	result = parse_AF_RevCertPemSequence (P_RevCertPemSeq, 1, NULLIP, NULLVP, &ret);
	pe_free(P_RevCertPemSeq);

	return ( result ? (SEQUENCE_OF_RevCertPem * )0 : ret );
}


OctetString *e_OCList (ocl)
OCList      *ocl;
{
	PE            P_Ocl;
	OctetString * ret;
	char	    * proc = "e_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ocl == (OCList * )0 )
		return( (OctetString * )0 );

	if ( build_AF_OldCertificateList (&P_Ocl, 1, 0, CNULL, ocl) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_Ocl);
	pe_free(P_Ocl);

	return (ret);
}


OCList      *d_OCList (asn1_string)
OctetString *asn1_string;
{
	PE             P_Ocl;
	OCList       * ret;
	int	       result;
	char	     * proc = "d_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( asn1_string == (OctetString * )0 )
		return( (OCList * )0 );

	P_Ocl = aux_OctetString2PE(asn1_string);

	if ( P_Ocl == NULLPE )
		return( (OCList * )0 );

	result = parse_AF_OldCertificateList (P_Ocl, 1, NULLIP, NULLVP, &ret);
	pe_free(P_Ocl);

	return ( result ? (OCList * )0 : ret );
}


OctetString  *e_CrlSet (crlset )
CrlSet  *crlset ;
{
	PE              P_CrlSet ;
	OctetString   * ret;
	char	      * proc = "e_CrlSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (crlset  == (CrlSet  * )0)
		return (OctetString * ) 0;

	if (build_AF_CrlSet (&P_CrlSet , 1, 0, CNULL, crlset ) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_CrlSet );
	pe_free(P_CrlSet );

	return (ret);
}


CrlSet  *d_CrlSet (asn1_string)
OctetString *asn1_string;
{
	PE             P_CrlSet ;
	CrlSet   * ret;
	int            result;
	char	     * proc = "d_CrlSet";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (CrlSet  * ) 0;

	P_CrlSet  = aux_OctetString2PE(asn1_string);

	if (P_CrlSet  == NULLPE)
		return (CrlSet  * ) 0;

	result = parse_AF_CrlSet (P_CrlSet , 1, NULLIP, NULLVP, &ret);
	pe_free(P_CrlSet);

	return (result ? (CrlSet  * ) 0 : ret);
}


OctetString *e_CrlTBS (tbs)
CrlTBS *tbs;
{
	PE            P_CrlTBS;
	OctetString * ret;
	char	    * proc = "e_CrlTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( tbs == (CrlTBS * )0 )
		return( (OctetString * )0 );

	if ( build_AF_TBSCrl (&P_CrlTBS, 1, 0, CNULL, tbs) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_CrlTBS);
	pe_free(P_CrlTBS);

	return (ret);
}


OctetString *e_RevCertTBS (tbs)
RevCertTBS 	      *tbs;
{
	PE                      P_RevCertTBS;
	OctetString           * ret;
	char		      * proc = "e_RevCertTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( tbs == (RevCertTBS * )0 )
		return( (OctetString * )0 );

	if ( build_AF_TBSRevCert (&P_RevCertTBS, 1, 0, CNULL, tbs) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_RevCertTBS);
	pe_free(P_RevCertTBS);

	return (ret);
}


OctetString *e_PemCrlTBS (tbs)
PemCrlTBS *tbs;
{
	PE            P_PemCrlTBS;
	OctetString * ret;
	char	    * proc = "e_PemCrlTBS";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( tbs == (PemCrlTBS * )0 )
		return( (OctetString * )0 );

	if ( build_AF_TBSPemCrl (&P_PemCrlTBS, 1, 0, CNULL, tbs) == NOTOK )
		return( (OctetString * )0 );

	ret = aux_PE2OctetString(P_PemCrlTBS);
	pe_free(P_PemCrlTBS);

	return (ret);
}


PE certificate_enc(parm)
Certificate *parm;
{
	PE	   pe;
	char	 * proc = "certificate_enc";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	(void) build_AF_Certificate (&pe, 0, 0, CNULL, parm);
	return (pe);
}


Certificate *certificate_dec(pe)
PE pe;
{
	Certificate * ret;
	int	      result;
	char	    * proc = "certificate_dec";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( pe == NULLPE )
		return( (Certificate * )0 );

	/*NOTE: Space for Certificate is allocated by parse_AF_Certificate,*/
	/*parameter is of type Certificate ** (not *!) */

	result = parse_AF_Certificate (pe, 1, NULLIP, NULLVP, &ret);

	return (result ? (Certificate * )0 : ret);
}


OctetString  * e_PemCrlWithCerts(arg)
PemCrlWithCerts * arg;
{
	PE             P_PemCrlWithCerts;
	OctetString  * ret;
	char	     * proc = "e_PemCrlWithCerts";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (arg == (PemCrlWithCerts * )0)
		return (OctetString * ) 0;

	if (build_AF_PemCrlWithCerts(&P_PemCrlWithCerts, 1, 0, CNULL, arg) == NOTOK)
		return (OctetString * ) 0;

	ret = aux_PE2OctetString(P_PemCrlWithCerts);
	pe_free(P_PemCrlWithCerts);

	return (ret);
}


PemCrlWithCerts * d_PemCrlWithCerts(asn1_string)
OctetString * asn1_string;
{
	PE                        P_PemCrlWithCerts;
	PemCrlWithCerts         * ret;
	int		          result;
	char	      		* proc = "d_PemCrlWithCerts";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == (OctetString * )0)
		return (PemCrlWithCerts * ) 0;

	P_PemCrlWithCerts = aux_OctetString2PE(asn1_string);

	if (P_PemCrlWithCerts == NULLPE)
		return (PemCrlWithCerts * ) 0;

	result = parse_AF_PemCrlWithCerts(P_PemCrlWithCerts, 1, NULLIP, NULLVP, &ret);
	pe_free(P_PemCrlWithCerts);

	return (result ? (PemCrlWithCerts * ) 0 : ret);
}


OctetString  * e_AliasList(alist, aliasf)
AliasList  * alist;
AliasFile    aliasf;
{
	PE                 P_AliasList;
	AliasList	 * aa, * bb;
	OctetString      * ret;
	Aliases		 * aliasmember, * tmp_aliasmember;
	int		   first_a_flag, aa_equal_bb_flag;
	char	   	 * proc = "e_AliasList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! alist || (aliasf != useralias && aliasf != systemalias))
		return (NULLOCTETSTRING);

	aa = bb = (AliasList * )malloc(sizeof(AliasList));
	if (! aa)
		return (NULLOCTETSTRING);

	bb->dname = CNULL;
	bb->next = (AliasList * ) 0;
	bb->a = (Aliases * ) 0;

	aa_equal_bb_flag = 1;

	while (alist) {
		aliasmember = alist->a;
		first_a_flag = 1;
		while (aliasmember) {
			if(aliasmember->aliasfile == aliasf) {
				if (first_a_flag) {
					if (! aa_equal_bb_flag) {
						bb->next = (AliasList * )malloc(sizeof(AliasList));
						bb = bb->next;
					}
					first_a_flag = aa_equal_bb_flag = 0;
					bb->a = tmp_aliasmember = (Aliases * )malloc(sizeof(Aliases));
					bb->dname = aux_cpy_Name(alist->dname);
					bb->next = (AliasList * ) 0;
					tmp_aliasmember->aname = aux_cpy_Name(aliasmember->aname);
					tmp_aliasmember->aliasfile = aliasmember->aliasfile;
					tmp_aliasmember->next = (Aliases * ) 0;
				}
				else {
					tmp_aliasmember->next = (Aliases * )malloc(sizeof(Aliases));
					tmp_aliasmember = tmp_aliasmember->next;
					tmp_aliasmember->aname = aux_cpy_Name(aliasmember->aname);
					tmp_aliasmember->aliasfile = aliasmember->aliasfile;
					tmp_aliasmember->next = (Aliases * ) 0;
				}
			}
			aliasmember = aliasmember->next;
		}
		alist = alist->next;
	}

	if (build_AF_AliasList(&P_AliasList, 1, 0, CNULL, aa) == NOTOK)
		return (NULLOCTETSTRING);

	aux_free_AliasList(&aa);

	ret = aux_PE2OctetString(P_AliasList);
	pe_free(P_AliasList);

	return (ret);
}


AliasList * d_AliasList(asn1_string)
OctetString * asn1_string;
{
	PE		P_AliasList;
	int		result;
	AliasList     * alist;
	char	      * proc = "d_AliasList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (asn1_string == NULLOCTETSTRING)
		return ((AliasList * )0);

	P_AliasList = aux_OctetString2PE(asn1_string);

	if (P_AliasList == NULLPE)
		return ((AliasList * )0);

	result = parse_AF_AliasList(P_AliasList, 1, NULLIP, NULLVP, &alist);
	pe_free(P_AliasList);

	return (result ? (AliasList * )0 : alist);
}
