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
/*  INCLUDE FILE  x400.h (Secure X.400 Interface)                        */
/*  Definition of structures and types for X.400 Security Extensions     */
/*-----------------------------------------------------------------------*/

#ifndef _X4_
#define _X4_

/*
 *   secure.h/af.h define:
 *
 *          AlgId               (typedef struct AlgId)
 *          OctetString         (typedef struct OctetString)
 *          BitString           (typedef struct BitString)
 *          ENCRYPTED           (typedef struct BitString)
 *          UTCTime             (typedef char)
 *          KeyInfo             (typedef struct KeyInfo) 
 *          Signature           (typedef struct Signature)
 *          Certificate         (typedef struct Certificate)
 *          SET_OF              (typedef struct set_of)
 *          Attribute           (typedef struct Attribute)
 */

#ifndef _AF_
#include "af.h"
#endif

/*-----------------------------------------------------------------------*/
/*    T y p e d e f ' s   f o r   X.4 0 0                                */
/*-----------------------------------------------------------------------*/

typedef struct env_ext           EnvExtension;
typedef struct label             Label;
typedef struct macTBS            MACTBS;
typedef struct mac               MAC;
typedef struct mac               MIC;
typedef struct tokenTBE          TokenTBE;
typedef struct mtokenTBS         MsgTokenTBS;
typedef struct mtoken            MsgToken;
typedef struct btokenTBS         BindTokenTBS;
typedef struct btoken            BindToken;
typedef struct sec_cont          SecurityContext;
typedef struct credents          Credentials;

/*-----------------------------------------------------------------------*/
/*    E r r o r s                                                        */
/*-----------------------------------------------------------------------*/

#define ELABEL         401
#define EPOLICY        402
#define ENOTOKEN       403
#define ERECIPNAME     404
#define ERECIPKEY      405
#define ESECCONTEXT    406
#define EMAC           407
#define ETOKENCRYPT    408
#define ETOKSIGN       409
#define ETOKRANDOM     410
#define ETOKTIME       411
#define ECREDCERT      412
#define ECREDKEY       413

/* from af.h:
 * typedef struct {
 *         int             number;
 *         int             data;
 *         char           *addr;
 *         Certificate    *cert;
 * } AF_Error;
 *
 * extern AF_Error af_error;
*/

/*-----------------------------------------------------------------------*/
/*     envelope security extensions                                      */
/*-----------------------------------------------------------------------*/

struct env_ext {
        int             type;
        BitString       criticality;
        char           *value; /* address of extension element */
};


/* originator certificate same as Certificates */

struct label {
        ObjId     policy;
        int            *class;
        char           *mark;
        char           *categs; /* address of security categories */
};


struct macTBS {
        AlgId          *signatureAI;
        OctetString    *content;
        char           *content_id;
        Label          *label;
}; /* unused subfields set to NULL */

struct mac {
        OctetString    *tbs_DERcode;
        MACTBS          tbs;
        Signature       sig;         /* sender's signature */
};


struct tokenTBE {
        BitString      *cckey;
        MIC            *cic;
        Label          *label;
        BitString      *cikey;
        int            *mseq;
}; /* unused subfields set to NULL */

struct mtokenTBS {
        AlgId          *signatureAI;
        DName          *recipient;
        UTCTime        *time;
        AlgId          *confidAI;
        MIC            *cic;
        Label          *label;
        int            *pod_req;
        int            *mseq;
        AlgId          *encryptionAI;
        ENCRYPTED      *encrypted; /* from TokenTBE */
}; /* unused subfields set to NULL */

struct mtoken {
        ObjId    *token_type;  /* id-tok-asymmetricToken */
        OctetString    *tbs_DERcode;
        MsgTokenTBS     tbs;
        Signature       sig;         /* sender's signature */
};

/*-----------------------------------------------------------------------*/
/*     bind security extensions                                          */
/*-----------------------------------------------------------------------*/

struct btokenTBS {
        AlgId          *signatureAI;
        DName          *recipient;
        UTCTime        *time;
        BitString      *random;
        AlgId          *encryptionAI;
        ENCRYPTED      *encrypted; /* from tokenTBE */
}; /* unused subfields set to NULL */

struct btoken {
        ObjId    *token_type;  /* id-tok-asymmetricToken */
        OctetString    *tbs_DERcode;
        BindTokenTBS    tbs;
        Signature       sig;         /* initiator's signature */
};


struct sec_cont {
        Label           *label;
        struct sec_cont *next;
};


struct credents {
        BindToken       *btoken;
        Certificates    *ocert;
};

/*-----------------------------------------------------------------------*/
/*     Definition of function types of X400 (if not int)                 */
/*-----------------------------------------------------------------------*/

/*
 *     Encoding/Decoding Functions
 */

OctetString     *e_MACTBS       (/* MacTBS *        */);
OctetString     *e_TokenTBE     (/* TokenTBE *      */);
OctetString     *e_MsgTokenTBS  (/* MsgTokenTBS *   */);
OctetString     *e_BindTokenTBS (/* BindTokenTBS *  */);

#endif
