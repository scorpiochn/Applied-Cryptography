
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
/*      protocol.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all local define's and structures   */
/*	for the t1-programm	         		       */
/*-------------------------------------------------------------*/

#define    REQUEST      0xc0      /* For S_block */
#define    RESPONSE     0xe0      /* For S_block */
#define    RESYCH       0x00      /* For S_block */
#define    IFS          0x01
#define    ABORT        0x02
#define    WTX          0x03

#define    CHKERR       0x01
#define    FMATERR      0x02

#define    NS_0         0x00      /* Sending sequence number */
#define    NS_1         0x40

#define    T_MORE       0x20      /* More bit */
#define    NMORE        0x00

#define    NR_0         0x00      /* Receiving sequence number */
#define    NR_1         0x10

#define    BLKREPEAT    3
#define    LRC_LEN      1
#define    CRC_LEN      2

#define    I_BLOCK      0
#define    R_BLOCK      2
#define    S_BLOCK      3

#define    NEXTBLOCK      0
#define    ERROR         -1

#define    CONTINUE      -2

#define    BLKHDLEN    3          /* Node addr byte + PCB + Length byte */
#define    BLKLPOS     2

#define    NOT(x)       ( x == 0 ) ? 1 : 0
#define    BLOCK_WAIT     1
#define    CHAR_WAIT      2

typedef struct {
        int ms;                   /* More bit */
        int nr;                   /* Receiving sequence number */
        int blktype;              /* Type of block */
        int S_respbit;            /* Response bit of S_blocks */
        int S_ctl;                /* Control function of S_blocks */
        int inflen;               /* Length of data field of I_block */
        char *I_rqstr;            /* Data field of I_block */
        char *S_rqstr;            /* Data field of S_block */
        } BLOCKstru;

typedef struct {
        char *sub_rqstr[10];      /* Point to each chained block */
        int  sublen[10];          /* Length of each chained block */
        int  sequence;            /* Order of chained blocks */
        int  amount;              /* Amount of chained blocks */
        } CHAINstru;
