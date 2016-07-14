{\small
\begin{verbatim}
/*-----------------------------------------------------------------------*/
/* FILE  af_init.c                                                       */
/* Initialization of global variables of AF-IF                           */
/*-----------------------------------------------------------------------*/

#include "af.h"

/*-----------------------------------------------------------------------*/
/*    Object Identifiers of PSE-Objects                                  */
/*-----------------------------------------------------------------------*/

/*
 *    ObjectIdentifier macro (parameter obj) builds 
 *               ObjId <obj>_oid
 *    from <obj>_OID 
 *
 */

#if !defined(MAC) && !defined(__HP__)
#define ObjectIdentifier(obj)                                             \
        unsigned int obj/**/_oid_elements[] = obj/**/_oid_EL;             \
        ObjId obj/**/_oid = {                                             \
        sizeof(obj/**/_oid_elements)/sizeof(int), obj/**/_oid_elements }; \
        ObjId *obj/**/_OID = &obj/**/_oid;

#else
#define ObjectIdentifier(obj)                                             \
        unsigned int obj##_oid_elements[] = obj##_oid_EL;                 \
        ObjId obj##_oid = {                                               \
        sizeof(obj##_oid_elements)/sizeof(int), obj##_oid_elements };     \
        ObjId *obj##_OID = &obj##_oid
#endif /* MAC */

#define SignCert_oid_EL       { 1, 3, 36, 2, 1, 1 }
#define EncCert_oid_EL        { 1, 3, 36, 2, 1, 2 }
#define Cert_oid_EL           { 1, 3, 36, 2, 1, 3 }
#define SignCSet_oid_EL       { 1, 3, 36, 2, 2, 1 }
#define EncCSet_oid_EL        { 1, 3, 36, 2, 2, 2 }
#define CSet_oid_EL           { 1, 3, 36, 2, 2, 3 }
#define SignSK_oid_EL         { 1, 3, 36, 2, 3, 1 }
#define DecSKnew_oid_EL       { 1, 3, 36, 2, 3, 2 }
#define DecSKold_oid_EL       { 1, 3, 36, 2, 3, 3 }
#define SKnew_oid_EL          { 1, 3, 36, 2, 3, 4 }
#define SKold_oid_EL          { 1, 3, 36, 2, 3, 5 }
#define FCPath_oid_EL         { 1, 3, 36, 2, 4, 1 }
#define PKRoot_oid_EL         { 1, 3, 36, 2, 5, 1 }
#define PKList_oid_EL         { 1, 3, 36, 2, 6, 1 }
#define EKList_oid_EL         { 1, 3, 36, 2, 6, 2 }
#define CrossCSet_oid_EL      { 1, 3, 36, 2, 8, 1 }
#define CrlSet_oid_EL         { 1, 3, 36, 2, 9, 1 }
#define Name_oid_EL           { 1, 3, 36, 2, 7, 1 }
#define SerialNumbers_oid_EL  { 1, 3, 36, 2, 10, 1 }
#define EDBKey_oid_EL         { 1, 3, 36, 2, 11, 1 }
#define AliasList_oid_EL      { 1, 3, 36, 2, 12, 1 }
#define QuipuPWD_oid_EL       { 1, 3, 36, 2, 13, 1 }
#define RSA_SK_oid_EL         { 1, 3, 36, 2, 99, 1 }
#define RSA_PK_oid_EL         { 1, 3, 36, 2, 99, 2 }
#define DSA_SK_oid_EL         { 1, 3, 36, 2, 99, 3 }
#define DSA_PK_oid_EL         { 1, 3, 36, 2, 99, 4 }
#define DES_oid_EL            { 1, 3, 36, 2, 99, 5 }
#define DES3_oid_EL           { 1, 3, 36, 2, 99, 6 }
#define Uid_oid_EL            { 1, 3, 36, 2, 0 }

ObjectIdentifier(SignCert);
ObjectIdentifier(EncCert);
ObjectIdentifier(Cert);
ObjectIdentifier(SignCSet);
ObjectIdentifier(EncCSet);
ObjectIdentifier(CSet);
ObjectIdentifier(SignSK);
ObjectIdentifier(DecSKnew);
ObjectIdentifier(DecSKold);
ObjectIdentifier(SKnew);
ObjectIdentifier(SKold);
ObjectIdentifier(FCPath);
ObjectIdentifier(PKRoot);
ObjectIdentifier(PKList);
ObjectIdentifier(EKList);
ObjectIdentifier(CrossCSet);
ObjectIdentifier(CrlSet);
ObjectIdentifier(Name);
ObjectIdentifier(SerialNumbers);
ObjectIdentifier(EDBKey);
ObjectIdentifier(AliasList);
ObjectIdentifier(QuipuPWD);
ObjectIdentifier(RSA_SK);
ObjectIdentifier(RSA_PK);
ObjectIdentifier(DSA_SK);
ObjectIdentifier(DSA_PK);
ObjectIdentifier(DES);
ObjectIdentifier(DES3);
ObjectIdentifier(Uid);

AFPSESel AF_pse = {
        DEF_PSE, CNULL,
        SignSK_name, CNULL, &SignSK_oid,
        DecSKnew_name, CNULL, &DecSKnew_oid,
        DecSKold_name, CNULL, &DecSKold_oid,
        SKnew_name, CNULL, &SKnew_oid,
        SKold_name, CNULL, &SKold_oid,
        SignCert_name, CNULL, &SignCert_oid,
        EncCert_name, CNULL, &EncCert_oid,
        Cert_name, CNULL, &Cert_oid,
        FCPath_name, CNULL, &FCPath_oid,
        PKRoot_name, CNULL, &PKRoot_oid,
        PKList_name, CNULL, &PKList_oid,
        EKList_name, CNULL, &EKList_oid,
        CrossCSet_name, CNULL, &CrossCSet_oid,
        CrlSet_name, CNULL, &CrlSet_oid,
        Name_name, CNULL, &Name_oid,
        SignCSet_name, CNULL, &SignCSet_oid,
        EncCSet_name, CNULL, &EncCSet_oid,
        CSet_name, CNULL, &CSet_oid,
        SerialNumbers_name, CNULL, &SerialNumbers_oid,
        EDBKey_name, CNULL, &EDBKey_oid,
        AliasList_name, CNULL, &AliasList_oid,
        QuipuPWD_name, CNULL, &QuipuPWD_oid,
        0 
};

VerificationResult * verifresult = (VerificationResult * )0;

Boolean    af_verbose = FALSE;
Boolean    af_chk_crl = FALSE;
Boolean    af_access_directory = FALSE;
Boolean    af_FCPath_is_trusted = FALSE;
Boolean    chk_PEM_subordination = FALSE;
Boolean    accept_alias_without_verification = FALSE;

#ifdef X500
Boolean    af_x500 = TRUE;

/* argc and argv parameters passed to your "main()" routine, evaluated by dsap_init() in af_dir.c */
int        af_x500_count;
char    ** af_x500_vecptr;

DName    * directory_user_dname = NULLDNAME;
int        auth_level = DBA_AUTH_NONE;
#ifdef STRONG
Boolean    af_strong = TRUE;
#else
Boolean    af_strong = FALSE;
#endif
#else
Boolean    af_x500 = FALSE;
Boolean    af_strong = FALSE;
#endif
#ifdef COSINE
Boolean    af_COSINE = TRUE;
#else
Boolean    af_COSINE = FALSE;
#endif
\end{verbatim}
}
