/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCTLOC			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      sctloc.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all local define's and structures   */
/*	for the sctloc-modules   			       */
/*-------------------------------------------------------------*/

/* SW2 = SCT wait */
#define SCTWAIT                 0x01

#define SAD                     2       /* source address       */
#define DAD                     1       /* destination address  */

#define LHEADER                 4       /* Length of Header     */
                                        /* CLA+INS+P1+P2        */
#define LEN1                    1       /* 1 Byte, if L < 255   */
#define LEN3                    3       /* 3 Byte, if L >=255   */

#define S_NOTUSED               0x00

#define NON_INTER               0x80    /* Non interindustry command */
                                        /* set for class - byte */


#define RQP1                    request->rq_p1
#define RQP2                    request->rq_p2
#define RQDATA                  request->rq_datafield
#define RQDATENC                request->rq_datafield.enc
#define RQDATPUB                request->rq_datafield.public
#define RQDATVERIFY             request->rq_datafield.verify
#define RQDATDESKEY             request->rq_datafield.deskey
#define RQDATDEV                request->rq_datafield.dev_key_info
#define RQDATPIN                request->rq_datafield.pin
#define RQDATSESS               request->rq_datafield.session_key
#define RQDATWRITE              request->rq_datafield.write_keycard
#define RQDATKEYATTR            request->rq_datafield.keyattrlist





/*---------------------------------------------------------------------*/
/* Structur and initialization of SCTerror                             */
/*---------------------------------------------------------------------*/
#define TABLEN 124

typedef struct {
        unsigned int sw1;
        unsigned int sw2;
        char msg[128];
        }SCTerror;


