/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAPAC  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	STAMOD			VERSION 2.0	       */
/*					   DATE Januar 1992    */
/*					     BY Levona Eckstein*/
/*						Ursula Viebeg  */ 
/*							       */
/*    FILENAME			                 	       */
/*      scarc.h    		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all returncodes of the SCA          */
/*	STAPAC Application Interface         		       */
/*-------------------------------------------------------------*/

/*
 *   sctrc.h defines all return codes of the SCT-Interface
 */

#include "sctrc.h"

/*------------------------------------------------------------------*/
/*  Return codes of STAMOD                                          */
/*------------------------------------------------------------------*/

#define  M_SIGOK             1             /* signature correct,    */
                                           /* key too short         */
#define  M_KEYREPL           1             /* existing key replaced */
#define  M_KEYLEN            1       /* correct key length returned */


/*------------------------------------------------------------------*/
/*  Error codes of STAMOD                                           */
/*------------------------------------------------------------------*/

#define  M_NOERR             0             /* no error from STAMOD                */
#define  M_EALARM          151             /* invalid alarm value(FALSE, TRUE)    */
#define  M_EPIN            152             /* invalid PIN/PUK                     */
#define  M_ETIME           153             /* invalid time (allowed values: 0-255)*/
#define  M_ETEXT           154             /* invalid text-length                 */
                                           /* (allowed values: 1-32)              */
#define  M_EOUTDAT         155             /* output data not correct             */
#define  M_EINDATA         156             /* input data not correct              */
#define  M_ESECMESS        157             /* security mode(s) not correct        */
#define  M_EKEYATTR        158             /* invalid key attribute(s)            */
#define  M_ELEVEL          159             /* level of RSA key must be smartcard  */
#define  M_EKEYDEV         160             /* invalid KeyDevPurpose parameter     */
#define  M_EREADKEY        161             /* key from keycard not installed      */
#define  M_EHASHPAR        162             /* wrong hash_par                      */
#define  M_EFUNCTION       163             /* mixed function calls not allowed    */                                           /* (more)                              */
#define  M_EHASH           164             /* hash-function error                 */
#define  M_EPAR            165             /* wrong parameter                                   */
#define  M_EKEY            166             /* key invalid                         */
#define  M_EPROCID         167             /* illegal value of auth-proc-id       */
#define  M_EOBJECTID       168             /* illegal value of auth-object-id     */
#define  M_EFILEEMPTY      169             /* file empty or first RID not found                                    */
#define  M_ESECMODE        170             /* invalid transfer mode               */
#define  M_EPOINTER        171             /* NULL pointer                        */
#define  M_EDATASTRUC      172             /* illegal value of data_struc                                    */
#define  M_EMORE           173             /* more parameter invalid              */
#define  M_EMEMORY         182             /* memory error                        */







