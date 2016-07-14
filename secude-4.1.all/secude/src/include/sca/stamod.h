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
/*      stamod.h    		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all structures and types for the    */
/*	STAPAC Application Interface         		       */
/*-------------------------------------------------------------*/
/*
 *   sca.h defines structures and types for the application interface
 */

#include "sca.h"

/*
 *   starc.h defines all return codes for the application interface
 */

#include "scarc.h"


/*------------------------------------------------------------------*/
/*   Length for parameters of the application interface             */
/*------------------------------------------------------------------*/

#define  LEN_KEYHEAD        9              /* length of key_header */


/*------------------------------------------------------------------*/
/*  MAX values for parameters of the application interface          */
/*------------------------------------------------------------------*/

#define MAXL_SCT_DISPLAY    32             /* max length of SCT-display */

#define MAXL_DISPLAY_TEXT   64             /* max length of SCT-display-text */

#define MAXL_SU_PIN         16             /* max length of super pin */

#define MAXL_PIN            8              /* max length of pin */

#define MAXL_RNO            255            /* max length of random number */



#define MAX_TEXT_NO         255            /* max textno for SCT-display */

#define MAX_TIME            255            /* max value for time  (seconds) */

#define MAX_KEYID            63            /* max value for key_id.key_number */

#define MAX_KPFC             14            /* max value for key fault presentation counter */

#define MAX_EL_NO           255            /* max value for element_no */

#define MAX_NO              255            /* max value for number of elements */

#define MAX_REC_ID          254            /* max value for record_id */

#define MAX_REC_POS         255            /* max value for the position in record */

#define MAX_LSB             255            /* max value for lsb (transparent file) */

#define MAX_MSB             255            /* max value for msb (transparent file) */

#define MAX_FILEN           15             /* max value for filename */



/*------------------------------------------------------------------*/
/*  MIN values for parameters of the application interface          */
/*------------------------------------------------------------------*/

#define MINL_RSAKEY         512            /* min length of RSA-Keysize */



/*------------------------------------------------------------------*/
/*  Default values for parameters of the application interface      */
/*------------------------------------------------------------------*/

 


/*------------------------------------------------------------------*/
/*  Definitions for SCT-Interface                                   */
/*------------------------------------------------------------------*/

#define LEN_APDU_HEADER    5               /* length of APDU-Header */
 


/*------------------------------------------------------------------*/
/*  Error codes of STAMOD in starc.h                               */
/*------------------------------------------------------------------*/
#define  MIN_STAMOD_ERRNO  150             /* min.error number of   */
                                           /* STAMOD ( in contrast  */
                                           /* error numbers of the  */
                                           /* SCT-interface         */


/*------------------------------------------------------------------*/
/*  type definitions		                                    */
/*------------------------------------------------------------------*/
typedef enum {USER_KEY, PIN_KEY, PUK_KEY, DEVICE_KEY} KindOfKey;
                                           /* used for routine:     */
                                           /* check_key_attr_list   */








