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

/*------------------------------------------------------------------*/
/* FILE  sc_init.c                                                  */
/* Initialization of global variables of smartcard module           */
/*------------------------------------------------------------------*/

#ifdef SCA

#ifndef _SECSC_
#include "secsc.h"
#endif

Boolean         SC_verify = FALSE, SC_encrypt = FALSE, SC_ignore = FALSE;


/*
 *  Initialization of global variables:
 */

Boolean         SC_ignore_SWPSE = TRUE;	/* TRUE:  If the Software-PSE part	   */
					/* cannot be opened with the pin from	   */
					/* SC_PIN_name, sec_open ignores this	   */
					/* error. FALSE: sec_open returns -1	   */
					/* in this case          		   */

int		SC_timer = SC_WAITTIME;	/* During this time interval (in seconds)  */
					/* the SCT accepts the insertion of an SC. */




/*
 *  Initialization of sct_stat_list[]:
 */

SCTStatus       sct_stat_list[] = {
/*
 *      config	available,	sm_SCT,      app_name,	sw_pse_pin,     user_auth_done
 *	done			cmd,  resp.,
 */
	FALSE,	FALSE,	 	NORM, NORM,    "",	 "",		FALSE,  /* 0. SCT (not available) */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 1. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 2. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 3. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 4. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 5. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 6. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 7. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 8. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 9. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 10. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 11. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 12. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 13. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 14. SCT */
	FALSE,	FALSE,		NORM, NORM,    "",	 "",		FALSE,	/* 15. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 16. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 17. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 18. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE,	/* 19. SCT */
	FALSE,	FALSE,		NORM, NORM,    "", 	 "",		FALSE	/* 20. SCT */
};


/*
 *  Initialization of sc_app_list[]:
 */

SCAppEntry      sc_app_list[] = {0};




/*
 *  Initialization of sca_fct_list[]:
 */

SCAFctPar       sca_fct_list[] =

/*
   fct_name,		  sm_SCT,	   sm_SC
			cmd,   resp.	cmd,	resp.

*/
/* test values: without secure messaging */
{
	"sca_init_sc", NORM, NORM, NORM, NORM,
	"sca_get_sc_info", NORM, NORM, NORM, NORM,
	"sca_eject_sc", NORM, NORM, NORM, NORM,
	"sca_gen_user_key", NORM, NORM, NORM, NORM,
	"sca_del_user_key", NORM, NORM, NORM, NORM,
	"sca_sign", NORM, NORM, NORM, NORM,
	"sca_verify", NORM, NORM, NORM, NORM,
	"sca_encrypt", NORM, NORM, NORM, NORM,
	"sca_decrypt", NORM, NORM, NORM, NORM,
	"sca_enc_des_key", NORM, NORM, NORM, NORM,
	"sca_dec_des_key", NORM, NORM, NORM, NORM,
	"sca_auth", NORM, NORM, NORM, NORM,
	"sca_create_file", NORM, NORM, NORM, NORM,
	"sca_select_file", NORM, NORM, NORM, NORM,
	"sca_close_file", NORM, NORM, NORM, NORM,
	"sca_delete_file", NORM, NORM, NORM, NORM,
	"sca_set_mode", NORM, NORM, NORM, NORM,
	CNULL
};

/* real values:

  {
  "sca_init_sc",	NORM,   NORM,   NORM,	NORM,
  "sca_get_sc_info",	NORM,   NORM,   NORM,	NORM,
  "sca_eject_sc",	NORM,   NORM,   NORM,	NORM,
  "sca_gen_user_key",	NORM,   NORM,   NORM,	NORM,
  "sca_del_user_key",	NORM,   NORM,   NORM,	NORM,
  "sca_sign",		NORM,   NORM,   NORM,	NORM,
  "sca_verify",		NORM,   NORM,   NORM,	NORM,
  "sca_encrypt",	CONC,   NORM,   CONC,	NORM,
  "sca_decrypt",	NORM,   CONC,   NORM,	CONC,
  "sca_enc_des_key",	NORM,   NORM,   NORM,	NORM,
  "sca_dec_des_key",	NORM,   NORM,   NORM,	NORM,
  "sca_auth",		NORM,   NORM,   NORM,	NORM,
  "sca_create_file",	NORM,   NORM,   NORM,	NORM,
  "sca_select_file",	NORM,   NORM,   NORM,	NORM,
  "sca_close_file",	NORM,   NORM,   NORM,	NORM,
  "sca_delete_file",	NORM,   NORM,   NORM,	NORM,
  "sca_set_mode",	NORM,   NORM,   NORM,	NORM,
  0
  };
*/


/*
 *  Initialization for the SCT-/SC-Selection:
 *
 *	1      -> select first SCT in the installation file (list of the connected SCTs)
 */
SCSel           sc_sel = {1};





#else
int             secsc_dummy;

#endif


