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
/* INCLUDE FILE  secsc_config.h                                          */
/* Default values for the configuration file.				 */
/* The configuration file contains the PSE objects stored on the SC.     */
/*-----------------------------------------------------------------------*/
/*
 *
 *   af.h defines:
 *           Names of PSE Objects (File-Names in the PSE)
 *
 *   secsc.h defines:
 *           SCObjEntry		(typedef struct SCObjEntry)
 *           SCAppEntry		(typedef struct SCAppEntry)
 *
 */

#ifndef _SCCONFIG_
#define _SCCONFIG_


#include "af.h"


/*
 *  Initialization of the smartcard application list with default values
 */

  char		*default_sc_app_list[] =
  {
    "polikom",
    "password",
    0
  };


  SCObjEntry	default_sc_obj_list[] =

/* test values without secure messaging */

/* keys: */
/*
  Name,		 Type,     	key-       not   key-   not     sm_SCT,  sm_SC_read     sm_SC_write   
                           	level,    used,  no,    used,            cdo.,  resp.,  cdo.,  resp., 
*/
  {
  SC_PIN_name,   SC_KEY_TYPE,   SC_DF,      0,    63,    0,      NORM,   NORM,  NORM,   NORM,  NORM,
  SC_PUK_name,   SC_KEY_TYPE,   SC_DF,      0,    62,    0,      NORM,   NORM,  NORM,   NORM,  NORM,
  SignSK_name,   SC_KEY_TYPE,   SC_DF,      0,     2,    0,      NORM,   NORM,  NORM,   NORM,  NORM,
  DecSKnew_name, SC_KEY_TYPE,   SC_DF,      0,     3,    0,      NORM,   NORM,  NORM,   NORM,  NORM,

/* files: */
/*
  Name,		 Type,     	file-     file-  file-  file-   sm_SCT,  sm_SC_read     sm_SC_write   
                           	level,    type,  name,  size,            cdo.,  resp.,  cdo.,  resp., 
*/
  PSE_PIN_name,  SC_FILE_TYPE,  DF_LEVEL,  WEF,    0,     8,     NORM,   NORM,  NORM,   NORM,  NORM,
  SCToc_name,    SC_FILE_TYPE,  DF_LEVEL,  WEF,    1,   480,     NORM,   NORM,  NORM,   NORM,  NORM,
  Name_name,     SC_FILE_TYPE,  DF_LEVEL,  WEF,    2,   128,     NORM,   NORM,  NORM,   NORM,  NORM,
  SignCert_name, SC_FILE_TYPE,  DF_LEVEL,  WEF,    3,   384,     NORM,   NORM,  NORM,   NORM,  NORM,
  EncCert_name,  SC_FILE_TYPE,  DF_LEVEL,  WEF,    4,   384,     NORM,   NORM,  NORM,   NORM,  NORM,
  PKRoot_name,   SC_FILE_TYPE,  DF_LEVEL,  WEF,    5,   192,     NORM,   NORM,  NORM,   NORM,  NORM,
  FCPath_name,   SC_FILE_TYPE,  DF_LEVEL,  WEF,    6,   384,     NORM,   NORM,  NORM,   NORM,  NORM, 
  0
  };

/*  real values     !!!!!!!!!!!!!!!!!! not uptodate !!!!!!!!!!!!!!!!!!!!

  {
  SC_PIN_name,   SC_KEY_TYPE,  SC_PIN_keyid,     NORM,   NORM, NORM,  CONC,  NORM,      0,
  SC_PUK_name,   SC_KEY_TYPE,  SC_PUK_keyid,    NORM,   NORM, NORM,  CONC,  NORM,      0,
  SignSK_name,   SC_KEY_TYPE,  SignSK_keyid,    NORM,   NORM, NORM,  NORM, NORM,     0,
  DecSKnew_name, SC_KEY_TYPE,  DecSKnew_keyid,  NORM,   NORM, NORM,  NORM, NORM,     0,
  DecSKold_name, SC_KEY_TYPE,  DecSKold_keyid,  NORM,   NORM, NORM,  NORM, NORM,     0,

  PSE_PIN_name,  SC_FILE_TYPE, PSE_PIN_fileid,  CONC,    CONC,  CONC,   NORM, NORM,     8,
  SCToc_name,    SC_FILE_TYPE, SCToc_fileid,    CONC,    CONC,  CONC,   CONC,  CONC,    480,
  Name_name,     SC_FILE_TYPE, Name_fileid,     NORM,    NORM,  NORM,   NORM,  NORM,    128,
  SignCert_name, SC_FILE_TYPE, SignCert_fileid, NORM,    NORM,  AUTH,   AUTH,  NORM,    448,
  EncCert_name,  SC_FILE_TYPE, EncCert_fileid,  NORM,    NORM,  AUTH,   AUTH,  NORM,    448,
  PKRoot_name,   SC_FILE_TYPE, PKRoot_fileid,   NORM,    NORM,  AUTH,   AUTH,  NORM,    192,
  0
  };  */






/*
 *  List of the mandatory objects belonging to one application on the SC:
 */
   
  char	*man_sc_obj_list[MAX_SCOBJ] =
  {
    SC_PIN_name,
    SC_PUK_name,
    PSE_PIN_name,
    SCToc_name,
    0
  };


/*
 *  List of the mandatory objects belonging to an SC-application with one key pair:
 */
   
  char	*onekeypair_sc_obj_list[MAX_SCOBJ] =
  {
    SKnew_name,
    SKold_name,
    Cert_name,
    PKRoot_name,
    0
  };


/*
 *  List of the mandatory objects belonging to an SC-application with two key pairs:
 */
   
  char	*twokeypairs_sc_obj_list[MAX_SCOBJ] =
  {
    SignSK_name,
    DecSKnew_name,
    SignCert_name,
    EncCert_name,
    PKRoot_name,
   0
  };


#endif
