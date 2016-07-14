{\small
\begin{verbatim}
/*-----------------------------------------------------------------------*/
/* INCLUDE FILE  secure.h                                                */
/* Definition of structures and types for the basic security functions   */
/*-----------------------------------------------------------------------*/

#ifndef _SECURE_
#define _SECURE_

#include <string.h>
char *getenv();

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define CNULL (char *)0

#ifndef NULL
#ifndef MAC
#define NULL        0
#else
#define NULL        (void *)0
#endif /* MAC */
#endif /* NULL */

#ifdef __HP__

#include <sys/types.h>
#define timelocal        mktime                        /* correct time zone */

#endif

#include <sys/time.h>
struct timeval sec_tp1, sec_tp2;
struct timezone sec_tzp1, sec_tzp2;
long hash_sec, hash_usec, rsa_sec, rsa_usec, dsa_sec, dsa_usec, des_sec, des_usec;

/*
 *    SecuDe Version
 */

extern char *secude_version;

/*-----------------------------------------------------------------------*/
/*    T y p e d e f ' s   f o r   s e c                                  */
/*-----------------------------------------------------------------------*/

/* MPW-C defines 'Boolean', too */
#ifdef applec
#include <types.h>
#else
typedef char                    Boolean;
#endif

typedef int                     RC;
typedef char                    UTCTime;
typedef enum { END, MORE }      More;
typedef struct OctetString      OctetString;
typedef struct BitString        BitString;
typedef struct BitString        ENCRYPTED;
#ifdef _PSAP_
typedef OIDentifier             ObjId;
#else
typedef struct OIDentifier      ObjId, OIDentifier;
#endif
typedef struct AlgId            AlgId;
typedef struct AlgList          AlgList;
typedef struct KeyInfo          KeyInfo;
typedef struct DigestInfo       DigestInfo;
typedef struct Key              Key;
typedef struct KeyBits          KeyBits;
typedef struct EncryptedKey     EncryptedKey;  /* e.g. for rsa-encrypted 
                                                  DES-keys               */ 
typedef struct Signature        Signature; 
typedef int                     KeyRef;
typedef struct PSE_Sel          PSESel;
typedef struct PSE_Toc          PSEToc;
typedef struct PSE_Object       PSEObject;

typedef struct ErrStack         ErrStack;


#define NULLOBJID ((ObjId *) 0)
#define NULLALGID ((AlgId *) 0)
#define NULLOCTETSTRING ((OctetString *) 0)
#define NULLBITSTRING   ((BitString *) 0)

/*-----------------------------------------------------------------------*/
/*    E r r o r s                                                        */
/*-----------------------------------------------------------------------*/

#define EALGID          1
#define EAPP            2
#define EAPPNAME        3
#define ECREATEAPP      4
#define EOBJ            5
#define EOBJNAME        6
#define ECREATEOBJ      7
#define EPIN            8
#define EVERIFY         9
#define ESYSTEM         10
#define EINVALID        11
#define EDAMAGE         12
#define EMALLOC         13
#define EDECRYPT        14
#define EENCRYPT        15
#define EHASH           16
#define EENCODE         17
#define EDECODE         18
#define ESIGN           19
#define EVERIFICATION   20
#define EACCPSE         21
#define EREADPSE        22
#define EWRITEPSE       23
#define EPATH           24
#define ECHKREVLIST     25
#define ESECOPEN       100
#define EVALIDITY      101
#define EPK            102
#define ENAME          103
#define ENOPK          104
#define ENONAME        105
#define EROOTKEY       106
#define ENODIR         107
#define ENAMEDIR       108
#define EACCDIR        109
#define EATTRDIR       110
#define EUPDATE        111
#define EPARSE         112
#define EPKCROSS       113
#define EREVOKE        114
#define EAVAILABLE     115
#define EPOINTER       202
#define EINTEGER       203
#define ERETURN        204
#define EMSGBUF        205
#define EMIC           206
#define ECTFOWNER      207
#define EMYNAME        208
#define EENCRMIC       209
#define EENCRBODY      210
#define EDECRMIC       211
#define EDECRBODY      212
#define EPEMBOUND      213
#define ESC            214
#define ESIGNATURE     215
#define EOPENDEV       216

struct ErrList {
        int  id;
        char *msg;
};
typedef enum{
        char_n,
        DName_n,
        OctetString_n,
        BitString_n,                       
        Certificate_n,
        Certificates_n,
        CertificatePair_n,
        PKList_n,
        SET_OF_Certificate_n,
        SET_OF_CertificatePair_n,
        OCList_n,
        AlgId_n,
        CrlTBS_n,
        Crl_n,
        RevCert_n,
        PemCrlTBS_n,
        PemCrl_n,
        RevCertPem_n,
        CrlSet_n,
        CrlPSE_n,
        PemInfo_n,
        KeyInfo_n,
        FCPath_n,
        PKRoot_n,
        IssuedCertificate_n,
        SET_OF_IssuedCertificate_n,
        SET_OF_Name_n,
        ToBeSigned_n,
        ObjId_n,
        KeyBits_n,
        PSEToc_n,
        PSESel_n,
        PemCrlWithCerts_n,
        SET_OF_PemCrlWithCerts_n,
        int_n
} Struct_No;

struct ErrStack{
        int              e_number;
        char            *e_text;
        char            *e_addr;
        Struct_No        e_addrtype;
        char            *e_proc;
        struct ErrStack *next;
} ;
extern struct ErrList  err_list[];
extern struct ErrStack *err_stack;
extern struct ErrStack err_malloc;
#define LASTERROR err_stack->e_number

/*-----------------------------------------------------------------------*/
/*    B i t s t r i n g   and   O c t e t s t r i n g                    */
/*-----------------------------------------------------------------------*/

struct OctetString {
        unsigned int    noctets;
        char           *octets;
};

struct BitString {
        unsigned int    nbits;
        char           *bits;
};

/*-----------------------------------------------------------------------*/
/*    O I D ' s  and  A L G I d 's                                       */
/*-----------------------------------------------------------------------*/

/*
 *    Parameter types (parmtype member of struct AlgList, 
 *    returned by aux_ObjId2ParmType())
 */

typedef enum {
        PARM_ABSENT,
        PARM_INTEGER,
        PARM_OctetString,
        PARM_NULL
} ParmType;

/*
 *    Algorithm types (algtype member of struct AlgList, 
 *    returned by aux_ObjId2AlgType())
 */

typedef enum { 
        OTHER_ALG,
        SYM_ENC, 
        ASYM_ENC, 
        HASH, 
        SIG 
} AlgType;

extern char *algtype_name[];

/*
 *    Encryption method of algorithm (algenc member of struct AlgList, 
 *    returned by aux_ObjId2AlgEnc())
 */

typedef enum { 
        NOENC,
        RSA, 
        DES, 
        DES3,
        DSA
} AlgEnc;

extern char *algenc_name[];

/*
 *    Encryption mode of algorithm (algmode member of struct AlgList, 
 *    returned by aux_ObjId2AlgMode())
 */

typedef enum { 
        NOMODE,
        ECB, 
        CBC
} AlgMode;

/*
 *    Hash method of algorithm (alghash member of struct AlgList, 
 *    returned by aux_ObjId2AlgHash())
 */

typedef enum { 
        NOHASH,
        SQMODN, 
        MD2, 
        MD4,
        MD5,
        SHA
} AlgHash;

extern char *alghash_name[];

typedef enum { 
        NOSPECIAL,
        PKCS_BT_01,
        PKCS_BT_02,
        WITH_PADDING,
        WITH_PEM_PADDING,
        PKCS_BT_TD
} AlgSpecial;

#ifndef _PSAP_
struct OIDentifier {
        int             oid_nelem;
        unsigned int   *oid_elements;
};
#endif


struct AlgId {
        ObjId          *objid;
        char           *parm;
};

struct AlgList {
        char           *name;
        AlgId          *algid;
        ParmType       parmtype;
        AlgType        algtype;
        AlgEnc         algenc;
        AlgHash        alghash;
        AlgSpecial     algspecial;
        AlgMode        algmode;
};

/*
 *    Algorithm parameter types
 */

#define null_parm  0

typedef unsigned int            rsa_parm_type;
typedef unsigned int            dsaSK_parm_type;
typedef unsigned int            sqmodn_parm_type;
typedef unsigned int            sqmodnWithRsa_parm_type;
typedef struct OctetString      desCBC_parm_type;
typedef struct OctetString      desCBC_pad_parm_type;
typedef struct OctetString      desCBC3_parm_type;
typedef struct OctetString      desCBC3_pad_parm_type;


#define DEF_RSA_KEYSIZE 512
#define DEF_DSA_KEYSIZE 512
#define MIN_ASYM_KEYSIZE 256
#define MAX_ASYM_KEYSIZE 2048

extern int public_modulus_length;
extern UTCTime *sec_SignatureTimeDate;

#define RSA_PARM(x) (( x ? *(int *)(x) : (public_modulus_length ? public_modulus_length : DEF_RSA_KEYSIZE)))

#define DES_PARM(x) ((OctetString *) (x))
                 

/* AlgId addresses */

extern AlgId    *rsa;
extern AlgId    *sqmodn;
extern AlgId    *sqmodnWithRsa;
extern AlgId    *dsaSK;

extern AlgId    *md2;
extern AlgId    *md4;
extern AlgId    *md5;
extern AlgId    *md2WithRsa;
extern AlgId    *md4WithRsa;
extern AlgId    *md5WithRsa;
extern AlgId    *sha;
extern AlgId    *dsa;
extern AlgId    *dsaWithSHA;

extern AlgId    *desECB;
extern AlgId    *desCBC;
extern AlgId    *desEDE;

extern AlgId    *desCBC_pad;
extern AlgId    *desCBC3;
extern AlgId    *desCBC3_pad;

extern AlgId    *rsaEncryption;
extern AlgId    *md2WithRsaEncryption;
extern AlgId    *md4WithRsaEncryption;
extern AlgId    *md5WithRsaEncryption;

extern AlgId    *md2WithRsaTimeDate;
extern AlgId    *md4WithRsaTimeDate;
extern AlgId    *md5WithRsaTimeDate;



/*
 *     External initialization of the known AlgId's:
 *


AlgId *                 ObjectIdentifier               Parameter

 rsa                    { 2, 5, 8, 1, 1 }              INTEGER (default 512)
 sqmodn                 { 2, 5, 8, 2, 1 }              INTEGER (default 512)
 sqmodnWithRsa          { 2, 5, 8, 3, 1 }              INTEGER (default 512)
 md2                    { 1, 2, 840, 113549, 2, 2 }    NULL
 md4                    { 1, 2, 840, 113549, 2, 4 }    NULL
 md5                    { 1, 2, 840, 113549, 2, 5 }    NULL
 md2WithRsa             { 1, 3, 14, 7, 2, 3, 1 }       NULL
 md4WithRsa             { 1, 3, 14, 3, 2, 2 }          NULL
 md5WithRsa             { 1, 3, 14, 3, 2, 3 }          NULL
 dsa                    { 1, 3, 14, 3, 2, 12 }         NULL
 sha                    { 1, 3, 14, 3, 2, 18 }         NULL 
 dsaSK                  { 1, 3, 36, 3, 1, 20 }         INTEGER (default 512)
 dsaWithSHA             { 1, 3, 14, 3, 2, 13 }         NULL
 desECB                 { 1, 3, 14, 3, 2, 6 }          NULL
 desCBC                 { 1, 3, 14, 3, 2, 7 }          {0, ""}
 desEDE                 { 1, 3, 14, 3, 2, 17 }         NULL
 desCBC_pad             { 1, 3, 36, 3, 1, 5 }          {0, ""}
 desCBC3                { 1, 3, 36, 3, 1, 11 }         {0, ""}
 desCBC3_pad            { 1, 3, 36, 3, 1, 13 }         {0, ""}
 rsaEncryption          { 1, 2, 840, 113549, 1, 1, 1 } NULL
 md2WithRsaEncryption   { 1, 2, 840, 113549, 1, 1, 2 } NULL
 md4WithRsaEncryption   { 1, 3, 14, 3, 2, 4 }          NULL
 md5WithRsaEncryption   { 1, 2, 840, 113549, 1, 1, 4 } NULL
 md2WithRsaTimeDate     { 1, 3, 36, 3, 1, 22 }         NULL
 md4WithRsaTimeDate     { 1, 3, 36, 3, 1, 24 }         NULL
 md5WithRsaTimeDate     { 1, 3, 36, 3, 1, 25 }         NULL



 */

/*
 *     List of all known algorithms
 */

extern AlgList  alglist[];

/*
 * External initialization of alglist[]:
 *  
AlgList         alglist[] = {
        "DES-ECB", &desECB_aid, PARM_NULL, SYM_ENC, DES, NOHASH, NOSPECIAL,ECB,
        "DES-CBC", &desCBC_aid, PARM_OctetString, SYM_ENC, DES, NOHASH, WITH_PEM_PADDING,CBC,
        "DES-EDE",  &desEDE_aid, PARM_NULL, SYM_ENC, DES3, NOHASH, NOSPECIAL,ECB,
        "RSA-MD2", &md2_aid, PARM_NULL, HASH, NOENC, MD2, NOSPECIAL,NOMODE,
        "RSA-MD5", &md5_aid, PARM_NULL, HASH, NOENC, MD5, NOSPECIAL,NOMODE,
        "RSA", &rsaEncryption_aid, PARM_NULL, ASYM_ENC, RSA, NOHASH, PKCS_BT_02,NOMODE,
        "NIST-SHA", &sha_aid, PARM_NULL, HASH, NOENC, SHA, NOSPECIAL,NOMODE,
        "NIST-DSA", &dsa_aid, PARM_NULL, ASYM_ENC, DSA, NOHASH, NOSPECIAL,NOMODE,
        "rsa", &rsa_aid, PARM_INTEGER, ASYM_ENC, RSA, NOHASH, NOSPECIAL,NOMODE,
        "sqmodn", &sqmodn_aid, PARM_INTEGER, HASH, NOENC, SQMODN, NOSPECIAL,NOMODE,
        "sqmodnWithRsa", &sqmodnWithRsa_aid, PARM_INTEGER, SIG, RSA, SQMODN, NOSPECIAL,NOMODE,
        "md2", &md2_aid, PARM_NULL, HASH, NOENC, MD2, NOSPECIAL,NOMODE,
        "md4", &md4_aid, PARM_NULL, HASH, NOENC, MD4, NOSPECIAL,NOMODE,
        "md5", &md5_aid, PARM_NULL, HASH, NOENC, MD5, NOSPECIAL,NOMODE,
        "md2WithRsa", &md2WithRsa_aid, PARM_NULL, SIG, RSA, MD2, NOSPECIAL,NOMODE,
        "md4WithRsa", &md4WithRsa_aid, PARM_NULL, SIG, RSA, MD4, NOSPECIAL,NOMODE,
        "md5WithRsa", &md5WithRsa_aid, PARM_NULL, SIG, RSA, MD5, NOSPECIAL,NOMODE,
        "sha", &sha_aid, PARM_NULL, HASH, NOENC, SHA, NOSPECIAL,NOMODE,
        "dsa", &dsa_aid, PARM_NULL, ASYM_ENC, DSA, NOHASH, NOSPECIAL,NOMODE,
        "dsaSK", &dsaSK_aid, PARM_INTEGER, ASYM_ENC, DSA, NOHASH, NOSPECIAL,NOMODE,
        "dsaWithSHA", &dsaWithSHA_aid, PARM_NULL, SIG, DSA, SHA, NOSPECIAL,NOMODE,
        "desECB", &desECB_aid, PARM_NULL, SYM_ENC, DES, NOHASH, NOSPECIAL,ECB,
        "desCBC", &desCBC_aid, PARM_OctetString, SYM_ENC, DES, NOHASH, WITH_PEM_PADDING,CBC,
        "desEDE", &desEDE_aid, PARM_NULL, SYM_ENC, DES3, NOHASH, NOSPECIAL,ECB,
        "desCBC_pad", &desCBC_pad_aid, PARM_OctetString, SYM_ENC, DES, NOHASH, WITH_PADDING,CBC,
        "desECB3", &desEDE_aid, PARM_NULL, SYM_ENC, DES3, NOHASH, NOSPECIAL,ECB,
        "desCBC3", &desCBC3_aid, PARM_OctetString, SYM_ENC, DES3, NOHASH, WITH_PEM_PADDING,CBC,
        "desCBC3_pad", &desCBC3_pad_aid, PARM_OctetString, SYM_ENC, DES3, NOHASH, WITH_PADDING,CBC,
        "md2WithRsaEncryption", &md2WithRsaEncryption_aid, PARM_NULL, SIG, RSA, MD2, PKCS_BT_01,NOMODE,
        "md4WithRsaEncryption", &md4WithRsaEncryption_aid, PARM_NULL, SIG, RSA, MD4, PKCS_BT_01,NOMODE,
        "md5WithRsaEncryption", &md5WithRsaEncryption_aid, PARM_NULL, SIG, RSA, MD5, PKCS_BT_01,NOMODE,
        "md2WithRsaTimeDate", &md2WithRsaTimeDate_aid, PARM_NULL, SIG, RSA, MD2, PKCS_BT_TD,NOMODE,
        "md4WithRsaTimeDate", &md4WithRsaTimeDate_aid, PARM_NULL, SIG, RSA, MD4, PKCS_BT_TD,NOMODE,
        "md5WithRsaTimeDate", &md5WithRsaTimeDate_aid, PARM_NULL, SIG, RSA, MD5, PKCS_BT_TD,NOMODE,
         CNULL
};


*/

extern int sec_dsa_keysize;
extern Boolean sec_dsa_predefined;

/*
 *  Bad DES keys  (initialized in sec_init.c)
 */

extern unsigned char *bad_des_keys[];
extern int no_of_bad_des_keys;


/*
 *  HashInput
 */

typedef BitString       SQMODN_input;

typedef union Hashinput {
        SQMODN_input sqmodn_input;
} HashInput;

/*-----------------------------------------------------------------------*/
/*    P S E                                                              */
/*-----------------------------------------------------------------------*/

#define DEF_PSE    ".pse"        /* Default PSE Name                */
#define DEF_CAPSE  ".capse"      /* Default PSE Name                */

struct PSE_Sel {
        char    *app_name;       /* Appl name or PSE name           */
        char    *pin;            /* PSE-PIN or password             */
        struct {
           char *name;
           char *pin;
        }        object;         /* object name and PIN             */
        int      app_id;         /* application id, 0 if default    */
};


/*
 *      Table of Contents of PSE
 */

struct PSE_Toc {
        char                    *owner;
        UTCTime                 *create;
        UTCTime                 *update;
        unsigned int            status;
        struct PSE_Objects      *obj;
};

struct PSE_Objects {
        char                    *name;
        UTCTime                 *create;
        UTCTime                 *update;
        int                     noOctets;
        unsigned int            status;
        struct PSE_Objects      *next;
};

struct PSE_Object {
        ObjId         *objectType;
        OctetString   *objectValue;
};

PSEToc *sec_read_toc();
int     sec_write_toc();



typedef enum {
        NOT_ON_SC, 
        APP_ON_SC, 
        FILE_ON_SC, 
        KEY_ON_SC
} PSEType;

PSEType sec_psetest();




/*-----------------------------------------------------------------------*/
/*    K e y ' s   and   S i g n a t u r e                                */
/*-----------------------------------------------------------------------*/

struct Signature {                   /* algorithm of subject's signature */
        AlgId     *signAI;
        BitString signature;
};

struct KeyInfo {
        AlgId     *subjectAI;
        BitString subjectkey;
};

struct DigestInfo {        /* DigestInfo as defined in PKCS#1 and PEM    */
        AlgId       *digestAI;
        OctetString digest;
};

struct KeyBits {           /* internal structure of BitString subjectkey
                              in case of rsa keys. 
                              In case of secret keys, part1 and part2 
                              contain the prime numbers p and q.
                              In case of public keys, part1 and part2
                              contain the modulus m and the exponent e.  */
        OctetString part1;
        OctetString part2;
        OctetString part3;
        OctetString part4;
};

struct EncryptedKey {
        AlgId     *encryptionAI;
        AlgId     *subjectAI;
        ENCRYPTED subjectkey;
};

struct Key {
        KeyInfo  *key;
        KeyRef    keyref;
        PSESel   *pse_sel;
        AlgId    *alg;
};

KeyRef sec_put_key();

/*-----------------------------------------------------------------------*/
/*  The key reference (integer) of the SEC-IF can be used to address     */
/*      - a key stored on the SC (DF-level) or                           */
/*      - a key stored in the SCT or                                     */
/*      - a key stored in the key pool (SW-PSE).                         */
/*  The following masks are used to indicate the address of the key.     */
/*-----------------------------------------------------------------------*/

#define        SC_KEY      0xFF010000  /* Address a key on the SC on DF-level   */
#define        SCT_KEY     0xFF020000  /* Address a key in the SCT              */
#define        KeyPool_KEY 0x00000000  /* Address a key in the keypool (SW-PSE) */


/*-----------------------------------------------------------------------*/
/*    Encoding/Decoding Routines                                         */
/*-----------------------------------------------------------------------*/

OctetString     *e_KeyInfo       (/* KeyInfo *        */);
KeyInfo         *d_KeyInfo       (/* OctetString *    */);

OctetString     *e_DigestInfo    (/* DigestInfo *     */);
DigestInfo      *d_DigestInfo    (/* OctetString *    */);

OctetString     *e_EncryptedKey  (/* EncryptedKey *   */);
EncryptedKey    *d_EncryptedKey  (/* OctetString *    */);

OctetString     *e_Signature     (/* Signature *      */);
Signature       *d_Signature     (/* OctetString *    */);

OctetString     *e_AlgId         (/* algid *          */);
AlgId           *d_AlgId         (/* OctetString *    */);

/*
 *    The following routines are intended for internal use within the
 *    sec_* functions
 */

BitString       *e_KeyBits  (/* KeyBits *        */);
KeyBits         *d_KeyBits  (/* BitString *      */);

OctetString     *e_PSEToc  (/* PSEToc *          */);
PSEToc          *d_PSEToc  (/* OctetString *     */);

OctetString     *e_OctetString  (/* OctetString *     */);
OctetString     *d_OctetString  (/* OctetString *     */);

OctetString     *e_PSEObject();
OctetString     *d_PSEObject();

/*-----------------------------------------------------------------------*/
/*    Other declarations                                                 */
/*-----------------------------------------------------------------------*/

OctetString     *e_GRAPHICString (/* char *           */);
char            *d_GRAPHICString (/* OctetString *    */);

char *aux_cpy_String(), *aux_cpy_ReducedString(); 
OctetString *sec_random_ostr();
BitString *sec_random_bstr();
char *sec_random_str(), *sec_read_pin();
long sec_random_long(); 
OctetString *aux_file2OctetString(), *aux_create_OctetString();
OctetString *aux_new_OctetString(), *aux_create_PKCSBlock(), *aux_create_PKCS_MIC_D();
OctetString *aux_encrfc(), *aux_decrfc(), *aux_enchex(), *aux_dechex();
OctetString *aux_encap(), *aux_decap(), *aux_rfc2hex(), *aux_hex2rfc();
OctetString *aux_hex2ap(), *aux_ap2hex(), *aux_rfc2ap(), *aux_ap2rfc();
AlgType aux_ObjId2AlgType(), aux_Name2AlgType();
ParmType aux_ObjId2ParmType(), aux_Name2ParmType();
AlgEnc aux_ObjId2AlgEnc(), aux_Name2AlgEnc();
AlgHash aux_ObjId2AlgHash(), aux_Name2AlgHash();
AlgSpecial aux_ObjId2AlgSpecial(), aux_Name2AlgSpecial();
AlgMode aux_ObjId2AlgMode(), aux_Name2AlgMode();
void aux_free_OctetString(), aux_free_BitString(), aux_free_ObjId(), aux_free_AlgId();
void aux_free_Key(), strzfree(), aux_free2_ObjId();
void aux_free_PSESel();
void aux_free_KeyInfo(), aux_free2_KeyInfo(), aux_print_OctetString();
void aux_free_Signature(), aux_free2_Signature();
void aux_free_DigestInfo(), aux_free2_DigestInfo();
void aux_xdump(), aux_fxdump();
void aux_xdump2(), aux_fxdump2();
ObjId *aux_cpy_ObjId(), *aux_Name2ObjId();
AlgId *aux_cpy_AlgId(), *aux_ObjId2AlgId(), *aux_Name2AlgId();
KeyInfo *aux_cpy_KeyInfo();
PSESel *aux_cpy_PSESel();
BitString *aux_cpy_BitString();
OctetString *aux_cpy_OctetString();
int aux_cpy2_OctetString();
int aux_cpy2_BitString();
Key *aux_cpy_Key();
KeyBits *aux_cpy_KeyBits();
PSEToc *aux_cpy_PSEToc();
struct PSE_Objects *aux_cpy_PSEObjects();
PSEObject *aux_cpy_PSEObject();
Signature *aux_cpy_Signature();
PSEToc *chk_toc();


UTCTime *aux_current_UTCTime(), *aux_delta_UTCTime();
char *aux_readable_UTCTime();
void aux_add_error(), aux_fprint_error(), aux_free_error();

/*
 *  sec_asn1_length_encoding controls the ASN.1 length encoding of the 
 *  e_*() functions. DEFINITE or INDEFINITE encoding can be chosen.
 *  For the sake of distinguished ASN.1 encoding either of the two 
 *  methods must be agreed and fixed between all participants of the
 *  security infrastructure. X.509 says DEFINITE shall be used for
 *  DER encoding. sec_asn1_length_encoding is defined in sec_init.c
 *  and set to DEFINITE by default.
 *
 *  Don't change this parameter unless you are sure what you are doing, 
 *  otherwise the verification of certificates could yield some surprises.
 */ 

extern int sec_asn1_length_encoding;
#define INDEFINITE 1
#define DEFINITE   2

extern Boolean aux_localtime;   /* if TRUE, UTCTime is generated as local time
                                   else UTCTime is generated as GMT time  */

extern Boolean sec_verbose;     /* if FALSE, RSA stuff is silent          */
extern char print_keyinfo_flag; /* controls aux_fprint_KeyInfo() : 
                                   ALGID:   AlgId
                                   BSTR:    DER-Code of BitString subjectkey
                                   KEYBITS: OctetString of KeyBits part1 and
                                            part2 or any combination      */

extern Boolean sec_time, sec_onekeypair;

#define ALGID     1
#define BSTR      2
#define KEYBITS   4
#define PK        8
#define SK       16

extern char print_cert_flag;    /* controls aux_fprint_Certificate() :           */
#define DER     1
#define TBS     2
#define KEYINFO 4
#define VAL     8
#define ISSUER 16
#define ALG    32
#define SIGNAT 64
#define HSH   128 

#define SHORT_HELP 0
#define LONG_HELP 1

#define ONEKEYPAIRONLY   1

#define MSBITINBYTE 0x80

#ifdef SCA
#include "secsc.h"
#endif
extern Boolean sec_sca;

#include "MF_check.h"

extern int sec_debug;
char *aux_cpy_Name();   /* is defined as (Name *) in ah.h */
#define aux_cpy_String(STRINGFROM) aux_cpy_Name(STRINGFROM)
#endif
\end{verbatim}
}
