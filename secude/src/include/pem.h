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

/*-----------------------pem.h--------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/*         Grimm/Nausester/Schneider/Viebeg/Vollmer/                */
/*         Surkau/Reichelt/Kolletzki et alii                        */
/*------------------------------------------------------------------*/

#ifndef _PEM_
#define _PEM_

/*
 *  P E M : Privacy Enhanced Mail (RFC 1421 - 1424) interface definition
 *
 */

#ifndef _AF_
#include "af.h"
#endif
#include <fcntl.h>
#include <stdio.h>

#define DEFAULT_MSG_ENC_ALG  "DES-CBC"
#define DEFAULT_MIC_ALG      "RSA-MD5"
#define DEFAULT_MIC_ENC_ALG  "RSA"
#define DEFAULT_DEK_ENC_ALG  "RSA"


/*
 * External initialization of PEM RFC 1421 - 1424 Definitions (pem_init.c):
 *
 *
 *
 * struct SKW  proc_type_v[] = {
 *         { "4",          PEM_4          },
 *         { 0,            0              }
 * };
 * 
 * struct SKW  proc_type_t[] = {
 *         { "ENCRYPTED",  PEM_ENC        },
 *         { "CRL",        PEM_CRL        },
 *         { "CRL-RETRIEVAL-REQUEST",  PEM_CRL_RETRIEVAL_REQUEST        },
 *         { "MIC-ONLY",   PEM_MCO        },
 *         { "MIC-CLEAR",  PEM_MCC        },
 *         { 0,            0              }
 * };
 * 
 * struct SKW content_domain[] = {
 *         { "RFC822",     PEM_RFC822     },
 *         { "MIME",       PEM_MIME       },
 *         { 0,            0              }
 * };
 * 
 * 
 * struct SKW  rXH_kwl[] =  { 
 *         { "Proc-Type",                PEM_PROC_TYPE           },
 *         { "CRL",                      PEM_CRL_                },
 *         { "Content-Domain",           PEM_CONTENT_DOMAIN      },
 *         { "DEK-Info",                 PEM_DEK_INFO            },
 *         { "Originator-ID-Asymmetric", PEM_SENDER_ID           },
 *         { "Originator-ID-Symmetric",  PEM_SENDER_IDS          },
 *         { "Originator-Certificate",   PEM_CERTIFICATE         },
 *         { "Issuer-Certificate",       PEM_ISSUER_CERTIFICATE  },
 *         { "MIC-Info",                 PEM_MIC_INFO            },
 *         { "Recipient-ID-Asymmetric",  PEM_RECIPIENT_ID        },
 *         { "Recipient-ID-Symmetric",   PEM_ID_SYMMETRIC        },
 *         { "Key-Info",                 PEM_KEY_INFO            },
 *         { "Issuer",                   PEM_ISSUER              },
 *         { 0,                          0                       }
 * };                           
 * 
 * char    PEM_Boundary_Begin[] = "-----BEGIN PRIVACY-ENHANCED MESSAGE-----";
 * char    PEM_Boundary_End[]   = "-----END PRIVACY-ENHANCED MESSAGE-----";
 * char    PEM_Boundary_Com[]   = "PRIVACY-ENHANCED MESSAGE-----";
 * char    PEM_Boundary_BB[]    = "-----BEGIN ";
 * char    PEM_Boundary_EB[]    = "-----END ";
 * 
 *
 *       Default Algorithms:
 *
 * 
 * char  *DEK_ENC_ALG = DEFAULT_DEK_ENC_ALG;    "RSA"    
 * char  *MIC_ALG     = DEFAULT_MIC_ALG;        "RSA-MD5"
 * char  *MIC_ENC_ALG = DEFAULT_MIC_ENC_ALG;    "RSA"   
 * char  *MSG_ENC_ALG = DEFAULT_MSG_ENC_ALG;    "DES-CBC"
 * 
 */


/*
 *       PemInfo Structure
 */

typedef struct reclist {
        Certificate    *recpcert;       /* recipient's user certificate     */
        OctetString    *key;            /* RSA-encrypted DES-key            */
        struct reclist *next;
}               RecpList;

typedef struct {
        Boolean         confidential;   /* TRUE if PEM shall be encrypted   */
        Boolean         clear;          /* TRUE if PEM shall be unencoded   */
        Key            *encryptKEY;     /* plain DES-key                    */
        Certificates   *origcert;       /* originator certificates          */
        PKRoot         *rootKEY;        /* root key                         */
        AlgId          *signAI;         /* signature algorithm id           */
        RecpList       *recplist;       /* list of recipients' informations */
}               PemInfo;

struct SKW {
        char           *name;
        int             value;
};

extern struct SKW update_modes[];    /* modes for installing CRLs             */
extern struct SKW content_domain[];  /* valid content domains                 */
extern struct SKW proc_type_v[];     /* valid Proc-Type values                */
extern struct SKW proc_type_t[];     /* valid Proc-Type types                 */
extern struct SKW rXH_kwl[];         /* header field specifiers               */

extern char   PEM_Boundary_Begin[];  /* PEM Boundary line Pre-EB              */
extern char   PEM_Boundary_End[];    /* PEM Boundary line Post-EB             */
extern char   PEM_Boundary_Com[];    /* equal portion of boundary line        */
extern char   PEM_Boundary_BB[];     /* begin portion of boundary begin line  */
extern char   PEM_Boundary_EB[];     /* begin portion of boundary end line    */

extern char   pem_verbose_0, pem_verbose_1, pem_verbose_2;
extern char   pem_verbose_level, pem_insert_cert, pem_option_r, pem_option_K,
              pem_cert_num;
extern char   *DEK_ENC_ALG, *MIC_ALG, *MIC_ENC_ALG, *MSG_ENC_ALG;
extern char   pem_enter_certificate_into_pklist;
extern int    pem_Depth, pem_content_domain;
extern Boolean isCA, PEM_Conformance_Requested;
extern OctetString **mic_for_certification;


typedef enum {
        RXH_empty,
        RXH_PROC_TYPE,
        RXH_CRL_,
        RXH_CONTENT_DOMAIN,
        RXH_DEK_INFO,
        RXH_SENDER_ID,
        RXH_SENDER_IDS,
        RXH_CERTIFICATE,
        RXH_ISSUER_CERTIFICATE,
        RXH_MIC_INFO,
        RXH_RECIPIENT_ID,
        RXH_ID_SYMMETRIC,
        RXH_KEY_INFO,
        RXH_ISSUER
}               RXH_Header_Fields;

typedef enum {
        PEM_PROC_TYPE,
        PEM_CRL_,
        PEM_CONTENT_DOMAIN,
        PEM_DEK_INFO,
        PEM_SENDER_ID,
        PEM_SENDER_IDS,
        PEM_CERTIFICATE,
        PEM_ISSUER_CERTIFICATE,
        PEM_MIC_INFO,
        PEM_RECIPIENT_ID,
        PEM_ID_SYMMETRIC,
        PEM_KEY_INFO,
        PEM_ISSUER
}               PEM_Header_Fields;

typedef enum {
        PEM_4
}               PEM_Proc_Type_values;

typedef enum {
        PEM_ENC,
        PEM_CRL,
        PEM_CRL_RETRIEVAL_REQUEST,
        PEM_MCO,
        PEM_MCC
}               PEM_Proc_Types;

typedef enum {
        PEM_RFC822,
        PEM_MIME
}               PEM_Content_Domains;


typedef enum         {
        NO_CRL_MESSAGE, 
        CRL_MESSAGE, 
        CRL_RETRIEVAL_REQUEST_MESSAGE 
}        PEM_CRL_Mode;

typedef enum         {
        UPDATE_ASK,
        UPDATE_NO,
        UPDATE_CADB,
        UPDATE_PSE,
        UPDATE_YES
}        UPDATE_Mode;

extern UPDATE_Mode update_mode;

#define ONCE_MAX      4   /* number of header fields which appear only  */
                          /* once in a message                          */
                          /* these have to be declared at first in the  */
                          /* rXH_kwl structure (see pem_init.c)         */

#define ELEVEL      302
#define EPSEOPEN    303
#define EPROCT      304
#define EORIGCERT   305
#define EISSCERTF   306
#define EMICINFO    307
#define EDEKINFO    308
#define ERECID      309
#define EKEYINF     310
#define ERIFILE     311
#define ECODE       312
#define ESYMM       313

#define CERTIFY     1
#define SCAN        0

extern VerificationResult *pem_VerifResult;

PemInfo        *aux_cpy_PemInfo();
RecpList       *aux_cpy_RecpList();
void            aux_free_RecpList();
void            aux_free_PemInfo();
Certificate    *af_search_Certificate();

#endif
