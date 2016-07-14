/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	T1			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      error.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all error codes dealing with T=1    */
/*	protocol operation       			       */
/*-------------------------------------------------------------*/

#define    TP1_OK           0
#define    RD_ERR        0x20
#define    WR_ERR        0x21
#define    EDC_ERR       0x22     /* To indicate invalid block received */
#define    MEMO_ERR      0x23     /* Memory alloc error  */
#define    OPEN_ERR      0x24     /* Faile for opening file or initiate port*/
#define    CLOSE_ERR     0x25
#define    BLK_TIMEOUT   0x26     /* Faile for receiving a block from SCT
                                     within the block waiting time */
#define    CHAR_TIMEOUT  0x27     /* Character is not come within
                                     character waiting time        */
#define    INVALID_LEN   0x28     /* Length of data field of a block is
                                     incompatiable with that allowed by PC */
#define    INVAL_TPDULEN 0x29     /* Length of TPDU-request is too long */
#define    INVALID_PORT  0x30     /* Not available port */
#define    SELECT_ERR    0x31     /* Error from system call    */
#define    PROT_RESYNCH  0x32     /* Protocol has been resynchronized. and
                                     communication can be started again with
                                     new protocol parameter state.        */
#define    SCT_RESET     0x33     /* Smart card terminal should be reset
                                     phsically due to errors unrecoverable */
#define    SYNTAX_ERR    0x34
