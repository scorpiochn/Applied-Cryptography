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

/*----------------------pem_init.c----------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/*         Grimm/Nausester/Schneider/Viebeg/Vollmer/                */
/*         Surkau/Reichelt/Kolletzki et alii                        */
/*------------------------------------------------------------------*/

#include "pem.h"

/*
 *	PEM RFC 1421 - 1424 Definitions:
 */

struct SKW  proc_type_v[] = {
        { "4",          PEM_4          },
        { 0,            0              }
};

struct SKW  proc_type_t[] = {
        { "ENCRYPTED",  PEM_ENC        },
        { "CRL",        PEM_CRL        },
        { "CRL-RETRIEVAL-REQUEST",  PEM_CRL_RETRIEVAL_REQUEST        },
        { "MIC-ONLY",   PEM_MCO        },
        { "MIC-CLEAR",  PEM_MCC        },
        { 0,            0              }
};

struct SKW content_domain[] = {
        { "RFC822",     PEM_RFC822     },
        { "MIME",       PEM_MIME       },
        { 0,            0              }
};


struct SKW  rXH_kwl[] =  { /* before changing please read remarks in pem.h  */
        { "Proc-Type",                PEM_PROC_TYPE           },
        { "CRL",                      PEM_CRL_                },
        { "Content-Domain",           PEM_CONTENT_DOMAIN      },
        { "DEK-Info",                 PEM_DEK_INFO            },
        { "Originator-ID-Asymmetric", PEM_SENDER_ID           },
        { "Originator-ID-Symmetric",  PEM_SENDER_IDS          },
        { "Originator-Certificate",   PEM_CERTIFICATE         },
        { "Issuer-Certificate",       PEM_ISSUER_CERTIFICATE  },
        { "MIC-Info",                 PEM_MIC_INFO            },
        { "Recipient-ID-Asymmetric",  PEM_RECIPIENT_ID        },
        { "Recipient-ID-Symmetric",   PEM_ID_SYMMETRIC        },
        { "Key-Info",                 PEM_KEY_INFO            },
        { "Issuer",                   PEM_ISSUER              },
        { 0,                          0                       }
};                           

char    PEM_Boundary_Begin[] = "-----BEGIN PRIVACY-ENHANCED MESSAGE-----";
char    PEM_Boundary_End[]   = "-----END PRIVACY-ENHANCED MESSAGE-----";
char    PEM_Boundary_Com[]   = "PRIVACY-ENHANCED MESSAGE-----";
char    PEM_Boundary_BB[]    = "-----BEGIN ";
char    PEM_Boundary_EB[]    = "-----END ";

/*
 *	Default Algorithms:
 */

char  *DEK_ENC_ALG = DEFAULT_DEK_ENC_ALG;   /* "RSA"     */
char  *MIC_ALG     = DEFAULT_MIC_ALG;       /* "RSA-MD5" */
char  *MIC_ENC_ALG = DEFAULT_MIC_ENC_ALG;   /* "RSA"     */
char  *MSG_ENC_ALG = DEFAULT_MSG_ENC_ALG;   /* "DES-CBC" */


/*
 *	Internal Definitions:
 */

struct SKW  update_modes[] = {
        { "ask",        UPDATE_ASK     },
        { "no",         UPDATE_NO      },
        { "cadb",       UPDATE_CADB    },
        { "pse",        UPDATE_PSE     },
        { "yes",        UPDATE_YES     },
        { 0,            0              },
};

char    pem_insert_cert, pem_option_r, pem_option_K, pem_cert_num = 200;
char    pem_enter_certificate_into_pklist;
char    pem_verbose_0, pem_verbose_1, pem_verbose_2, pem_verbose_level;
int     pem_Depth, pem_content_domain;
Boolean isCA = FALSE, PEM_Conformance_Requested = TRUE;

UPDATE_Mode update_mode = UPDATE_ASK;
OctetString **mic_for_certification = 0;
VerificationResult *pem_VerifResult;


