
/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCCOM			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      scloc.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all  local define's and structures  */
/*	for the sccom-modul	         		       */
/*-------------------------------------------------------------*/

#define SCHEAD                  sc_cmd->sc_header
#define SCEXRND        		sc_cmd->sc_uval.sc_exrnd
#define SCGETCD     		sc_cmd->sc_uval.sc_get_cd
#define SCSETKEY		sc_cmd->sc_uval.sc_setkey
#define SCSELECT                sc_cmd->sc_uval.sc_select
#define SCREG                   sc_cmd->sc_uval.sc_register
#define SCCREATE                sc_cmd->sc_uval.sc_create
#define SCREADF                 sc_cmd->sc_uval.sc_readf
#define SCWRITEF                sc_cmd->sc_uval.sc_writef
#define SCCLOSE                 sc_cmd->sc_uval.sc_close
#define SCCHGPIN                sc_cmd->sc_uval.sc_chg_pin
#define SCAUTH                  sc_cmd->sc_uval.sc_auth
#define SCWRKEY                 sc_cmd->sc_uval.sc_write_key
#define SCDELFILE               sc_cmd->sc_uval.sc_delfile
#define SCDELREC                sc_cmd->sc_uval.sc_delrec
#define SCLOCKF                 sc_cmd->sc_uval.sc_lockfile
#define SCLOCKK                 sc_cmd->sc_uval.sc_lockkey
#define SCCRYPT                 sc_cmd->sc_uval.sc_crypt

#define HEADLEN                 5  /* CLA + INS + P1 + P2 + 1 Byte LEN */

#define SOURCE_DTE              0x01     /* Source Address = DTE */

#define BLANK                   0x20
