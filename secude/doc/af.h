{\small
\begin{verbatim}
/*-----------------------------------------------------------------------*/
/*  INCLUDE FILE  af.h  (Authentication Framework Interface)             */
/*  Definition of structures and types for Authentication Framework      */
/*-----------------------------------------------------------------------*/

#ifndef _AF_
#define _AF_

/*
 *   secure.h defines:
 *
 *          AlgId               (typedef struct AlgId)
 *          ObjId               (typedef struct ObjId)
 *          OctetString         (typedef struct OctetString)
 *          BitString           (typedef struct BitString)
 *          ENCRYPTED           (typedef struct BitString)
 *          UTCTime             (typedef char)
 *          KeyInfo             (typedef struct KeyInfo) 
 *          Signature           (typedef struct Signature)
 */

#ifndef _module_IF_defined_
#include "If-types.h"           /* from ISODE */
#endif

#ifndef _SECURE_
#include "secure.h"
#endif

#if defined(MAC) || defined(__HP__)
#define SET_OF(t) struct set_of_##t {               \
        t *element;                                 \
        struct set_of_##t *next;                    \
}
#define SEQUENCE_OF(t) struct sequence_of_##t {     \
        t *element;                                 \
        struct sequence_of_##t *next;               \
}
#else
#define SET_OF(t) struct set_of_/**/t {             \
        t *element;                                 \
        struct set_of_/**/t *next;                  \
}
#define SEQUENCE_OF(t) struct sequence_of_/**/t {   \
        t *element;                                 \
        struct sequence_of_/**/t *next;             \
}
#endif /* MAC */

/*-----------------------------------------------------------------------*/
/*    T y p e d e f ' s   f o r   A F                                    */
/*-----------------------------------------------------------------------*/

typedef struct ToBeSigned                       ToBeSigned;
typedef struct ToBeSigned                       CertificateTBS;
typedef struct Certificate                      Certificate;
typedef struct Certificates                     Certificates;
typedef SET_OF(Certificate)                     SET_OF_Certificate;
typedef SET_OF(ToBeSigned)                      SET_OF_ToBeSigned;
typedef struct AF_PSE_Sel                       AFPSESel;
typedef enum { SIGNATURE, ENCRYPTION }          KeyType;
typedef SET_OF_Certificate                      CrossCertificates;
typedef struct Attribute                        Attribute;
typedef struct OCList                           OCList;
typedef int                                     CertificateSerialNumber;
typedef struct Serial                           Serial;
typedef struct RevCertTBS                       RevCertTBS;
typedef struct RevCert                          RevCert;
typedef struct RevCertPem                       RevCertPem;
typedef SET_OF(OctetString)                     SET_OF_OctetString;
typedef SEQUENCE_OF(RevCert)                    SEQUENCE_OF_RevCert;
typedef SEQUENCE_OF(RevCertPem)                 SEQUENCE_OF_RevCertPem;
typedef struct CrlTBS                           CrlTBS;
typedef struct Crl                              Crl;
typedef struct CertificatePair                  CertificatePair;
typedef SEQUENCE_OF(CertificatePair)            SEQUENCE_OF_CertificatePair;
typedef SET_OF(CertificatePair)                 SET_OF_CertificatePair;
typedef struct set_of_int                       SET_OF_int;
typedef struct SerialNumbers                    SerialNumbers;
typedef struct CrlPSE                           CrlPSE;
typedef SET_OF(CrlPSE)                          SET_OF_CrlPSE;
typedef enum { ARL, CRL }                       RevokeType;
typedef enum { userCertificate, cACertificate } CertificateType;
typedef struct CertificationPath                CertificationPath;
typedef struct CertificatePairs                 CertificatePairs;
typedef struct VerificationResult               VerificationResult;
typedef struct VerificationStep                 VerificationStep;

#define NULLCERTIFICATE                         ((Certificate *) 0)


/* PEM SPECIALs */
typedef struct PemCrlTBS                        PemCrlTBS;
typedef struct PemCrl                           PemCrl;
typedef struct PemCrlWithCerts                  PemCrlWithCerts;    
typedef SET_OF(PemCrlWithCerts)                 SET_OF_PemCrlWithCerts;


/*    P S E - O b j e c t s      */

typedef Certificate              SignCert;
typedef Certificate              EncCert;
typedef SET_OF_Certificate       SignCSet;
typedef SET_OF_Certificate       EncCSet;
typedef KeyInfo                  SignSK;
typedef KeyInfo                  DecSKnew;
typedef KeyInfo                  DecSKold;
typedef struct FCPath            FCPath;
typedef struct PKRoot            PKRoot; 
typedef SET_OF_ToBeSigned        PKList;
typedef SET_OF_ToBeSigned        EKList;
typedef SET_OF_CertificatePair   CrossCSet;
typedef SET_OF_CrlPSE            CrlSet;

/*    DistinguishedName - H a n d l i n g   */

typedef char                                       Name;
typedef struct type_IF_Name                        DName;
typedef struct type_IF_RelativeDistinguishedName   RDName;
typedef struct Attrlist                            AttrList;
typedef SET_OF(DName)                              SET_OF_DName;
typedef struct type_IF_Attribute                   Attr;
typedef SET_OF(Attr)                               SET_OF_Attr;


#define NULLDNAME ((DName *) 0)
#define NULLRDNAME ((RDName *) 0)


#ifdef X500
#define DBA_AUTH_NONE 0
#define DBA_AUTH_SIMPLE 1
#define DBA_AUTH_STRONG 2
#endif

#ifdef COSINE
typedef struct AuthorisationAttributes AuthorisationAttributes;

typedef char CountryId;
typedef char GroupId;
typedef enum { Normal, Privileged } ClassId;

struct AuthorisationAttributes {
        CountryId  *country;
        GroupId    *group;
        ClassId    class;
};
#endif


/*-----------------------------------------------------------------------*/
/*     SET_OF, Attribute                                                 */
/*-----------------------------------------------------------------------*/

struct Attribute {
        ObjId           type;
        SET_OF(char)   *value;
};

/*-----------------------------------------------------------------------*/
/*     Certificate and Certificates                                      */
/*-----------------------------------------------------------------------*/

struct ToBeSigned {
        int             version;
        int             serialnumber;
        AlgId          *signatureAI;  /* algorithm of issuer's signature */
        DName          *issuer;
        UTCTime        *notbefore;
        UTCTime        *notafter;
        DName          *subject;
        KeyInfo        *subjectPK;
#ifdef COSINE
        AuthorisationAttributes *authatts;
#endif
};

struct Certificate {
        OctetString    *tbs_DERcode; /* Return-Parameter of e_ToBeSigned */
        ToBeSigned     *tbs;
        Signature      *sig;         /* issuer's signature               */
};

struct FCPath {
        SET_OF_Certificate *liste;
        FCPath         *next_forwardpath;
};

struct Certificates {
        Certificate    *usercertificate;
        FCPath         *forwardpath;
};

struct CertificationPath {
        Certificate        * userCertificate;
        CertificatePairs   * theCACertificates;
};

struct CertificatePairs {
        SEQUENCE_OF_CertificatePair * liste;
        CertificatePairs   * superior;
};

/*-----------------------------------------------------------------------*/
/*     Revoked Certificates, according to PEM                            */
/*-----------------------------------------------------------------------*/

struct RevCertPem {
        int              serialnumber;
        UTCTime         *revocationDate;
};

struct  PemCrlTBS {
        AlgId                    *signatureAI;
        DName                    *issuer;
        SEQUENCE_OF_RevCertPem   *revokedCertificates;
        UTCTime                  *lastUpdate;
        UTCTime                  *nextUpdate;
};

struct  PemCrl {
        OctetString     *tbs_DERcode;  /* Return-Parameter of e_PemCrlTBS */
        PemCrlTBS       *tbs;
        Signature       *sig;          /* issuing CA's signature          */
};

struct PemCrlWithCerts {
        PemCrl          * pemcrl;
        Certificates    * certificates;
};


/*-----------------------------------------------------------------------*/
/*     Old Certificates                                                  */
/*-----------------------------------------------------------------------*/

struct OCList {
        int             serialnumber;
        Certificate    *ccert;
        OCList         *next;
};


/*-----------------------------------------------------------------------*/
/*     Structures used for Verification of Certification Paths           */
/*-----------------------------------------------------------------------*/

struct VerificationResult {
        VerificationStep     ** verifstep;
        int                     trustedKey;
        Boolean                 success;
        Boolean                 textverified;
        Name                  * top_name;
        UTCTime               * date;
        int                     top_serial;
};


struct VerificationStep {
        Certificate           * cert;
        int                     crlcheck;
        UTCTime               * date;
        int                     supplied;
};

extern VerificationResult * verifresult;

#define REVOKED 1
#define NOT_REVOKED 2
#define CRL_NOT_AVAILABLE 3
#define CRL_OUT_OF_DATE 4
#define NOT_REQUESTED 5

/*--------------------------------------------------------------------------*/
/*       Revoked Certificates, according to X.509                           */
/*--------------------------------------------------------------------------*/

struct RevCertTBS {
        AlgId                      *signatureAI;
        DName                      *issuer;
        CertificateSerialNumber     subject;
        UTCTime                    *revocationdate;
};


struct RevCert {
        OctetString                *tbs_DERcode;
        RevCertTBS                 *tbs;
        Signature                  *sig;    /* revoking CA's signature */
};


struct CrlTBS {
        AlgId                      *signatureAI;
        DName                      *issuer;
        UTCTime                    *lastupdate;
        SEQUENCE_OF_RevCert        *revokedcertificates;
};


struct Crl {
        OctetString                *tbs_DERcode;
        CrlTBS                     *tbs;
        Signature                  *sig;    /* issuing CA's signature */
};


/*--------------------------------------------------------------------------*/
/*       CertificatePair, according to X.509                                */
/*--------------------------------------------------------------------------*/

struct CertificatePair {
        Certificate     *forward;
        Certificate     *reverse;
};

/*-----------------------------------------------------------------------*/
/*     P S E  -  O b j e c t s                                           */
/*-----------------------------------------------------------------------*/


/*
 *      Names of PSE Objects (File-Names in the PSE)
 */

#define SignCert_name   "SignCert"   /* Cert for Public Signature Key                          */
#define EncCert_name    "EncCert"    /* Cert for Public Encryption Key                         */
#define Cert_name       "Cert"       /* Cert for Public Signature/Encryption Key               */
#define SignCSet_name   "SignCSet"   /* Set of CrossCertificates for own Public Signature Key  */
#define EncCSet_name    "EncCSet"    /* Set of CrossCertificates for own Public Encryption Key */
#define CSet_name       "CSet"       /* Set of CrossCertificates for own Public Sign./Encr.Key */
#define SignSK_name     "SignSK"     /* Secret Signature Key                                   */
#define DecSKnew_name   "DecSKnew"   /* Secret Decrypt. Key (new)                              */
#define DecSKold_name   "DecSKold"   /* Secret Decrypt. Key (old)                              */
#define SKnew_name      "SKnew"      /* Secret Key (new)                                       */
#define SKold_name      "SKold"      /* Secret Key (old)                                       */
#define FCPath_name     "FCPath"     /* Forward Certification Path                             */
#define PKRoot_name     "PKRoot"     /* PK of Top-Level Ca (old/new)                           */
#define PKList_name     "PKList"     /* Trusted Public Verific. Keys                           */
#define EKList_name     "EKList"     /* Trusted Public Encrypt. Keys                           */
#define CrossCSet_name  "CrossCSet"  /* Set of CrossCertificatePairs                           */
#define CrlSet_name     "CrlSet"     /* Revocation lists of known CAs                          */
#define Name_name       "Name"       /* subject's name                                         */
#define SerialNumbers_name "SerialNumbers"   /* Serial numbers (for CA's only)                 */
#define EDBKey_name     "EDBKey"     /* Symmetric Key for EDB encryption (for DSA's only)      */
#define AliasList_name  "AliasList"  /* User's AliasList                                       */
#define QuipuPWD_name   "QuipuPWD"   /* User's X.500 password                                  */
#define PSE_MAXOBJ      22           /* # of objects defined within af                         */

#define PSE_tmpSignatureSK      "SignSKtmp"       /* temporary PSE object */
#define PSE_tmpDecryptionSK     "DecSKtmp"        /* temporary PSE object */
#define PSE_tmpSK               "SKtmp"           /* temporary PSE object */


/*
 *      Object Identifiers of PSE Objects (extern: af-init.c)
 */

extern ObjId *SignCert_OID;
extern ObjId *EncCert_OID;
extern ObjId *Cert_OID;
extern ObjId *SignCSet_OID;
extern ObjId *EncCSet_OID;
extern ObjId *CSet_OID;
extern ObjId *SignSK_OID;
extern ObjId *DecSKnew_OID;
extern ObjId *DecSKold_OID;
extern ObjId *SKnew_OID;
extern ObjId *SKold_OID;
extern ObjId *FCPath_OID;
extern ObjId *PKRoot_OID;
extern ObjId *PKList_OID;
extern ObjId *EKList_OID;
extern ObjId *CrossCSet_OID;
extern ObjId *CrlSet_OID;
extern ObjId *Name_OID;
extern ObjId *SerialNumbers_OID;
extern ObjId *EDBKey_OID;
extern ObjId *AliasList_OID;
extern ObjId *QuipuPWD_OID;
extern ObjId *RSA_SK_OID;
extern ObjId *RSA_PK_OID;
extern ObjId *DSA_SK_OID;
extern ObjId *DSA_PK_OID;
extern ObjId *DES_OID;
extern ObjId *DES3_OID;
extern ObjId *Uid_OID;

/*
 *     List of all PSE Objects
 */

struct AF_PSE_Sel {
        char    *app_name;
        char    *pin;
        struct {
            char *name;
            char *pin;
            ObjId *oid;
        }        object[PSE_MAXOBJ];
        int      app_id;
};

extern AFPSESel AF_pse;

/*
 *     External initialization of variable AF_pse:
 *
 *     AFPSESel AF_pse = { 
 *              DEF_PSE, 0,
 *              SignSK_name, 0, SignSK_OID,
 *              DecSKnew_name, 0, DecSKnew_OID,
 *              DecSKold_name, 0, DecSKold_OID,
 *              SKnew_name, 0, SKnew_OID,
 *              SKold_name, 0, SKold_OID,
 *              SignCert_name, 0, SignCert_OID,
 *              EncCert_name, 0, EncCert_OID,
 *              Cert_name, 0, Cert_OID,
 *              FCPath_name, 0, FCPath_OID,
 *              PKRoot_name, 0, PKRoot_OID,
 *              PKList_name, 0, PKList_OID,
 *              EKList_name, 0, EKList_OID,
 *              CrossCSet_name, 0, CrossCSet_OID,
 *              CrlSet_name, 0, CrlSet_OID,
 *              Name_name, 0, Name_OID,
 *              SerialNumbers_name, 0, SerialNumbers_OID,
 *              SignCSet_name, 0, SignCSet_OID,
 *              EncCSet_name, 0, EncCSet_OID,
 *              CSet_name, 0, CSet_OID,
 *              EDBKey_name, 0, EDBKey_OID,
 *              AliasList_name, 0, AliasList_OID,
 *              QuipuPWD_name, 0, QuipuPWD_OID,
 *              0, 0 
 *     };
 */

/*
 *      Formats of other PSE Objects
 */

/*      PKRoot          */
/*      ======          */

struct PKRoot {
        DName              *ca;
        struct Serial      *newkey;
        struct Serial      *oldkey;
};

struct Serial {           /* Public Key and serial number */
        int            serial;
        int            version;
        KeyInfo       *key;
        UTCTime       *notbefore;
        UTCTime       *notafter;
        Signature     *sig;
};



/*      CrlSet          */
/*      ==========      */

struct set_of_int {             
        int                  element;                                 
        struct set_of_int   *next;                  
};

struct CrlPSE {
        DName                   *issuer;
        UTCTime                 *nextUpdate;
        SEQUENCE_OF_RevCertPem  *revcerts;
};
 


/*      SerialNumbers          */
/*      =============          */

struct SerialNumbers {
        int   initial;
        int   actual;
};


/*-----------------------------------------------------------------------*/
/*       DistinguishedName - Handling                                    */
/*-----------------------------------------------------------------------*/

struct Attrlist {
        char            *abbrev;
        char            *keyword;
        ObjId           *objid;
        ObjId           *syntax_oid;
};

/* ObjId addresses */

extern ObjId *countryName;
extern ObjId *orgName;
extern ObjId *orgUnitName;
extern ObjId *commonName;
extern ObjId *surName;
extern ObjId *localityName;
extern ObjId *streetAddress;
extern ObjId *title;
extern ObjId *serialNumber;
extern ObjId *businessCategory;
extern ObjId *description;
extern ObjId *stateOrProvinceName;

extern ObjId *CountryString;
extern ObjId *CaseIgnoreString;
extern ObjId *PrintableString;

extern AttrList attrlist[];

/*
 * External initialization of attrlist[]:
 *

AttrList attrlist[] = {

"C",     "COUNTRY",             &countryName_oid,         &CountryString_oid,
"O",     "ORGANIZATION",        &orgName_oid,             &CaseIgnoreString_oid,
"OU",    "ORGANIZATIONAL UNIT", &orgUnitName_oid,         &CaseIgnoreString_oid,
"CN",    "COMMON NAME",         &commonName_oid,          &CaseIgnoreString_oid,
"S",     "SURNAME",             &surName_oid,             &CaseIgnoreString_oid,
"L",     "LOCALITY",            &localityName_oid,        &CaseIgnoreString_oid,
"ST",    "STREET ADDRESS",      &streetAddress_oid,       &CaseIgnoreString_oid,
"T",     "TITLE",               &title_oid,               &CaseIgnoreString_oid,
"SN",    "SERIAL NUMBER",       &serialNumber_oid,        &PrintableString_oid,
"BC,     "BUSINESS CATEGORY",   &businessCategory_oid,    &CaseIgnoreString_oid,
"D",     "DESCRIPTION",         &description_oid,         &CaseIgnoreString_oid,
"SP",    "STATE OR PROVINCE",   &stateOrProvinceName_oid, &CaseIgnoreString_oid,
0 };

*/


/*-----------------------------------------------------------------------*/
/*       CA Database - Handling  (cadb)                                  */
/*-----------------------------------------------------------------------*/

typedef struct IssuedCertificate        IssuedCertificate;
typedef SET_OF(IssuedCertificate)       SET_OF_IssuedCertificate;
typedef SET_OF(Name)                    SET_OF_Name;


struct IssuedCertificate {
        int        serial;
        UTCTime   *date_of_issue;
};


/*-----------------------------------------------------------------------*/
/*    Aliases                                                            */
/*-----------------------------------------------------------------------*/

typedef enum { useralias, systemalias } AliasFile;

struct aliaslist {
        struct aliases {
                char          *aname; /* alias names */
                AliasFile  aliasfile; /* SYSTEM or USER Alias File */
                struct aliases *next;
        } *a;
        Name    *dname;               /* distinguished name */
        struct aliaslist *next;
};
typedef struct aliaslist AliasList;
typedef struct aliases Aliases;

Boolean aux_alias();
Name *aux_alias2Name();
DName *aux_alias2DName();
char *aux_Name2alias();
char *aux_DName2alias();
char *aux_Name2aliasf();
char *aux_DName2aliasf();
Boolean aux_get_AliasList();
void aux_put_AliasList();
void aux_free_AliasList();
Name *aux_search_AliasList();
Name *aux_next_AliasList();
Name *aux_alias_nxtname();
Boolean aux_alias_chkfile();
char *aux_alias_getall();
Boolean aux_check_AliasList();
AliasList * af_pse_get_AliasList();


/* Aliastypes */

typedef enum { 
        ANYALIAS,
        RFCMAIL, 
        X400MAIL, 
        LOCALNAME
} AliasType;


/*-----------------------------------------------------------------------*/
/*     Definition of function types of AF  (if not int)                  */
/*-----------------------------------------------------------------------*/

DName                   * af_pse_get_Name();
SerialNumbers           * af_pse_get_SerialNumbers();
Certificate             * af_pse_get_Certificate();
Certificates            * af_pse_get_Certificates();
SET_OF_Certificate      * af_pse_get_CertificateSet();
SET_OF_CertificatePair  * af_pse_get_CertificatePairSet();
FCPath                  * af_pse_get_FCPath();
PKRoot                  * af_pse_get_PKRoot();
PKList                  * af_pse_get_PKList();
KeyInfo                 * af_pse_get_PK();
ToBeSigned              * af_pse_get_TBS();
CrlSet                  * af_pse_get_CrlSet();
DName                   * af_pse_get_owner();
char                    * af_pse_get_QuipuPWD();
SET_OF_Certificate      * af_dir_retrieve_Certificate();
SET_OF_CertificatePair  * af_dir_retrieve_CertificatePair();
Crl                     * af_dir_retrieve_Crl();
PemCrl                  * af_dir_retrieve_PemCrl();
OCList                  * af_dir_retrieve_OCList();

SET_OF_Certificate      * af_afdb_retrieve_Certificate();
SET_OF_CertificatePair  * af_afdb_retrieve_CertificatePair();
PemCrl                  * af_afdb_retrieve_PemCrl();

Certificate             * af_create_Certificate();
Certificate             * af_search_Certificate();
Certificate             * af_PKRoot2Protocert();
FCPath                  * reduce_FCPath_to_HierarchyPath();
Certificates            * transform_reducedFCPath_into_Certificates();
Crl                     * af_create_Crl();
ObjId                   * af_get_objoid();
PSESel                  * af_pse_open();
PSESel                  * af_pse_create();
AlgId                   * af_pse_get_signAI();
PemCrl                  * af_create_PemCrl();
RevCertPem              * af_create_RevCertPem();

OctetString             * af_SignedFile2OctetString();

/*
 *     Encoding/Decoding Functions
 */

OctetString         *e_DName           (/* DName *              */);
DName               *d_DName           (/* OctetString *        */);

OctetString         *e_Attribute       (/* Attr *               */);
Attribute           *d_Attribute       (/* OctetString *        */);

OctetString         *e_AttributeType   (/* AttrType *           */);
OctetString         *e_AttributeValueAssertion (/* AttributeValueAssertion *      */);

OctetString         *e_SerialNumbers   (/* SerialNumbers *      */);
SerialNumbers       *d_SerialNumbers   (/* OctetString *        */);

OctetString         *e_Certificates    (/* Certificates *       */);
Certificates        *d_Certificates    (/* OctetString *        */);

OctetString         *e_Certificate     (/* Certificate *        */);
Certificate         *d_Certificate     (/* OctetString *        */);
OctetString         *e_ToBeSigned      (/* ToBeSigned *         */);

#ifdef COSINE
OctetString         *e_AuthorisationAttributes      (/* AuthorisationAttributes *  */);
AuthorisationAttributes  *d_AuthorisationAttributes (/* OctetString *              */);
#endif
                                                   
OctetString         *e_CertificateSet  (/* SET_OF_Certificate * */);
SET_OF_Certificate  *d_CertificateSet  (/* OctetString *        */);

OctetString         *e_CertificatePairSet (/* SET_OF_CertificatePair * */);
SET_OF_CertificatePair  *d_CertificatePairSet (/* OctetString * */);
                                                   
OctetString         *e_FCPath          (/* FCPath *             */);
FCPath              *d_FCPath          (/* OctetString *        */);

OctetString         *e_PKRoot          (/* PKRoot *             */);
PKRoot              *d_PKRoot          (/* OctetString*         */);

OctetString         *e_PKList          (/* PKList *             */);
PKList              *d_PKList          (/* OctetString *        */);

OctetString         *e_OCList   ();
OCList              *d_OCList   ();

OctetString         *e_Crl             (/* Crl *                */);
Crl                 *d_Crl             (/* OctetString *        */);
OctetString         *e_CrlTBS          (/* CrlTBS *             */);
                                                                          
OctetString         *e_RevCert         (/* RevCert *            */);
RevCert             *d_RevCert         (/* OctetString *        */);
OctetString         *e_RevCertTBS      (/* RevCertTBS *         */);

OctetString         *e_RevCertSequence (/* SEQUENCE_OF_RevCert **/);
SEQUENCE_OF_RevCert *d_RevCertSequence (/* OctetString *        */);

OctetString         *e_PemCrl          (/* PemCrl *             */);
PemCrl              *d_PemCrl          (/* OctetString *        */);
OctetString         *e_PemCrlTBS       (/* PemCrlTBS *          */);
                                                                          
OctetString         *e_RevCertPem      (/* RevCertPem *         */);
RevCertPem          *d_RevCertPem      (/* OctetString *        */);

OctetString         *e_PemCrlWithCerts  (/* PemCrlWithCerts *    */);
PemCrlWithCerts     *d_PemCrlWithCerts  (/* OctetString *        */);

OctetString         *e_RevCertSequence (/* SEQUENCE_OF_RevCert **/);
SEQUENCE_OF_RevCert *d_RevCertSequence (/* OctetString *        */);

OctetString         *e_CrlSet          (/* CrlSet *             */);
CrlSet              *d_CrlSet          (/* OctetString *        */);

OctetString         *e_OCList          (/* OCList *             */);
OCList              *d_OCList          (/* OctetString *        */);

OctetString         *e_AliasList       (/* AliasList *          */);
AliasList           *d_AliasList       (/* OctetString *        */);
                               
OctetString              *e_SET_OF_IssuedCertificate (/* SET_OF_IssuedCertificate * */);
SET_OF_IssuedCertificate *d_SET_OF_IssuedCertificate (/* OctetString *              */);

PE                  revcert_enc        (/*  RevCert *           */);
RevCert             *revcert_dec       (/*  PE                  */);
                                                                               
PE                  revcerttbs_enc     (/*  RevCertTBS *        */);
RevCertTBS          *revcerttbs_dec    (/*  PE                  */);

PE                  revcertseq_enc     (/*  SEQUENCE_OF_RevCert **/);
SEQUENCE_OF_RevCert *revcertseq_dec    (/*  PE                  */);

PE                  certlist_enc       (/*  Crl *               */);
Crl                 *certlist_dec      (/*  PE                  */);

PE                  certlisttbs_enc    (/*  CrlTBS *            */);
CrlTBS              *certlisttbs_dec   (/*  PE                  */);

PE                  certificate_enc    (/*  Certificate *       */);
Certificate         *certificate_dec   (/*  PE                  */);

PE                  oclist_enc         (/*  OCList *            */);
OCList              *oclist_dec        (/*  PE                  */);




/*
 *      others
 */

struct Serial *aux_cpy_Serial();

extern Boolean  af_verbose;
extern Boolean  af_chk_crl, af_access_directory;
extern Boolean  af_FCPath_is_trusted;
extern Boolean  chk_PEM_subordination;
extern Boolean  accept_alias_without_verification;
extern Boolean  af_x500;
extern Boolean  af_strong;
extern Boolean  af_COSINE;


#ifdef X500
extern DName * directory_user_dname;     /* defined in af_init.c */
extern int     af_x500_count;            /* defined in af_init.c */
extern char ** af_x500_vecptr;           /* defined in af_init.c */
extern int     auth_level;               /* defined in af_init.c */
#endif


char          *aux_oid2keyword(), *getobjectpin();
void          aux_free_ToBeSigned(), aux_free2_ToBeSigned(), aux_free_Certificate();
void          aux_free2_Certificate(), aux_free_CrossCertificates(), aux_free_OCList();
void          aux_free_FCPath(), aux_free_Certificates(), aux_free2_CrossCertificates();
void          aux_free_RootInfo();
void          aux_free2_RevCert(), aux_free_RevCertTBS(), aux_free2_RevCertTBS();
void          aux_free_SEQUENCE_OF_RevCert(), aux_free2_Crl(), aux_free_RevCert();
void          aux_free_Crl(), aux_free_CrlTBS(), aux_free2_CrlTBS();
void          aux_free2_RevCertPem(), aux_free_RevCertPem();
void          aux_free_SEQUENCE_OF_RevCertPem(), aux_free2_PemCrl();
void          aux_free_PemCrl(), aux_free2_PemCrlTBS(), aux_free_PemCrlTBS();
void          aux_free2_CrlPSE(), aux_free_CrlPSE(), aux_free_CrlSet();
void          aux_free_PemCrlWithCerts(), aux_free_SET_OF_PemCrlWithCerts();
void          aux_free_CertificationPath(), aux_free_CertificatePairs();
void          aux_free_SerialNumbers(), aux_free_SEQUENCE_OF_CertificatePair();
void          aux_free_IssuedCertificate(), aux_free_SET_OF_IssuedCertificate();
void          aux_free_VerificationResult(), aux_free_VerificationStep();
DName         *aux_cpy_DName(), *aux_Name2DName();
char          *aux_DName2CAPITALName();
char          *aux_DName2Attr();
Name          *aux_cpy_Name(), *aux_DName2Name();
Name          *aux_ObjId2Name();
FCPath        *aux_cpy_FCPath();
PKList        *aux_cpy_PKList();
PKRoot        *aux_cpy_PKRoot(), *aux_create_PKRoot();
Certificate   *aux_create_Certificate(), *aux_cpy_Certificate();
ToBeSigned    *aux_cpy_ToBeSigned();
Certificates  *aux_create_Certificates(), *aux_cpy_Certificates();
ObjId         *aux_keyword2oid();
RevCert       *aux_cpy_RevCert();
RevCertTBS    *aux_cpy_RevCertTBS();
RevCertPem    *aux_cpy_RevCertPem();
Crl           *aux_cpy_Crl();
CrlTBS        *aux_cpy_CrlTBS();
PemCrl        *aux_cpy_PemCrl();
PemCrlTBS     *aux_cpy_PemCrlTBS();
OCList        *aux_cpy_OCList();
CrlSet        *aux_cpy_CrlSet();
CrlPSE        *aux_cpy_CrlPSE();
SET_OF_int    *aux_cpy_SerialSet();
IssuedCertificate           *aux_cpy_IssuedCertificate();
SET_OF_IssuedCertificate    *aux_cpy_SET_OF_IssuedCertificate();
SET_OF_Name                 *aux_cpy_SET_OF_Name();
CertificatePair             *aux_cpy_CertificatePair();
SET_OF_Certificate          *aux_cpy_SET_OF_Certificate();
SET_OF_CertificatePair      *aux_cpy_SET_OF_CertificatePair();
SEQUENCE_OF_RevCert         *aux_cpy_SEQUENCE_OF_RevCert();
SEQUENCE_OF_RevCertPem      *aux_cpy_SEQUENCE_OF_RevCertPem();
UTCTime       * get_nextUpdate();
CrlPSE        * PemCrl2CrlPSE();

#endif

\end{verbatim}
}
