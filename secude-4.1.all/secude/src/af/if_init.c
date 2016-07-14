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

/*-----------------------------------------------------------------------*/
/* FILE  if_init.c                                                       */
/* Initialization of selected X.520 attribute OIDs                       */
/*-----------------------------------------------------------------------*/

#include "af.h"

#if defined(MAC) || defined(__HP__)
#define ObjectIdentifier(keyword)                                            \
        unsigned int keyword##_oid_elements[] = keyword##_OID;               \
        ObjId keyword##_oid = {                                              \
        sizeof(keyword##_oid_elements)/sizeof(int), keyword##_oid_elements };\
	ObjId *keyword = &keyword##_oid
#else
#define ObjectIdentifier(keyword)                                                \
        unsigned int keyword/**/_oid_elements[] = keyword/**/_OID;               \
        ObjId keyword/**/_oid = {                                                \
        sizeof(keyword/**/_oid_elements)/sizeof(int), keyword/**/_oid_elements };\
	ObjId *keyword = &keyword/**/_oid;
#endif /* MAC */


/* X.520 defined */

#define countryName_OID                          { 2, 5, 4, 6 }
#define orgName_OID                              { 2, 5, 4, 10 }
#define orgUnitName_OID                          { 2, 5, 4, 11 }
#define commonName_OID                           { 2, 5, 4, 3 }
#define surName_OID                              { 2, 5, 4, 4 }
#define localityName_OID                         { 2, 5, 4, 7 }
#define streetAddress_OID                        { 2, 5, 4, 9 }
#define title_OID                                { 2, 5, 4, 12 }
#define serialNumber_OID                         { 2, 5, 4, 5 }
#define businessCategory_OID                     { 2, 5, 4, 15 }
#define description_OID				 { 2, 5, 4, 13 }
#define stateOrProvinceName_OID			 { 2, 5, 4, 8 }

#define CountryString_OID                        { 1, 3, 36, 4, 1 }
#define CaseIgnoreString_OID                     { 2, 5, 5, 4 }
#define PrintableString_OID                      { 2, 5, 5, 5 }

ObjectIdentifier (countryName);
ObjectIdentifier (orgName);
ObjectIdentifier (orgUnitName);
ObjectIdentifier (commonName);
ObjectIdentifier (surName);
ObjectIdentifier (localityName);
ObjectIdentifier (streetAddress);
ObjectIdentifier (title);
ObjectIdentifier (serialNumber);
ObjectIdentifier (businessCategory);
ObjectIdentifier (description);
ObjectIdentifier (stateOrProvinceName);

ObjectIdentifier (CountryString);
ObjectIdentifier (CaseIgnoreString);
ObjectIdentifier (PrintableString);

AttrList attrlist[] = {
            { "C",     "COUNTRY",             &countryName_oid,         &CountryString_oid } ,
            { "O",     "ORGANIZATION",        &orgName_oid,             &CaseIgnoreString_oid } ,
            { "OU",    "ORGANIZATIONAL UNIT", &orgUnitName_oid,         &CaseIgnoreString_oid } ,
            { "CN",    "COMMON NAME",         &commonName_oid,          &CaseIgnoreString_oid } ,
            { "S",     "SURNAME",             &surName_oid,             &CaseIgnoreString_oid } ,
            { "L",     "LOCALITY",            &localityName_oid,        &CaseIgnoreString_oid } ,
            { "ST",    "STREET ADDRESS",      &streetAddress_oid,       &CaseIgnoreString_oid } ,
            { "T",     "TITLE",               &title_oid,               &CaseIgnoreString_oid } ,
            { "SN",    "SERIAL NUMBER",       &serialNumber_oid,        &PrintableString_oid } ,
            { "BC",    "BUSINESS CATEGORY",   &businessCategory_oid,    &CaseIgnoreString_oid } ,
            { "D",     "DESCRIPTION",         &description_oid, 	&CaseIgnoreString_oid } ,
            { "SP",    "STATE OR PROVINCE",   &stateOrProvinceName_oid, &CaseIgnoreString_oid } ,
	    { CNULL } 
};



