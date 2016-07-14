/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   T1                      VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*    FILENAME                                                 */
/*    t1.c                                                     */
/*                                                             */
/*    DESCRIPTION      Procedures necessary for communicating  */
/*                     with Smartcard Terminal.                */
/*    Notice:                                                  */
/*    1) For exchange of transmission control information,     */
/*       it supports only resynchronization.  S(RESYNCH, ...)  */
/*    2) For Error Detecte Code, LRC is used currently.        */
/*    3) First block to be sent to SCT is a S(RESYNCH,request) */
/*                                                             */
/*    EXPORT                                                   */
/*      COMinit()             Initiation of serial port        */
/*                                                             */
/*      COMreset()            Re-initiation of port            */
/*                                                             */
/*      COMtrans()            Communication with SCT           */
/*                                                             */
/*      tp1_err               Error number                     */
/*                                                             */
/*    USES                                                     */
/*      Module from assembly  If define DOS                    */
/*      routine siofunc.asm                                    */
/*                                                             */
/*      RS232_init()          Initiate RS232 interface         */
/*                                                             */
/*      sendstr()             To send string to RS232 interface*/
/*                                                             */
/*      recestr()             To receive string from RS232     */
/*                                                             */
/*    INTERNAL                                                 */
/*      COMsend()             To send a TPDU-request           */
/*                                                             */
/*      COMrece()             To receive a TPDU-response       */
/*                                                             */
/*      State_reset()         To reset sending and receiving   */
/*                            state variables                  */
/*                                                             */
/*      blk_process()         To process TPDU-response and     */
/*                            produce an appropriate block     */
/*                                                             */
/*      Resynch()             To resynchronize protocol        */
/*                                                             */
/*      blkvalidity()         To check validity of a block     */
/*                                                             */
/*      err_handle()          To produce an appropriate R_BLOCK*/
/*                                                             */
/*      divi_blk()            To divide a block into small     */
/*                            blocks                           */
/*                                                             */
/*      Is_lastblkResyResp()  To check whether the block last  */
/*                            sent a S(RESYNCH,response).      */
/*                                                             */
/*      Is_ResynchResp()      Is a S(RESYNCH,response)         */
/*                                                             */
/*      getbits()             To read bits  in a integer       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <fcntl.h>

#ifdef SUN
#include <sys/types.h>

#ifdef SYSV
#include <termio.h>
#else
#include <sgtty.h>
#endif
#include <sys/time.h>
#endif

#ifdef __HP__
#include <sys/types.h>

#define	getdtablesize()	(20)

#ifndef TIOCEXCL
#define	TIOCEXCL	_IO('t', 13)		/* set exclusive use of tty */
#endif

#ifdef FD_ZERO
#undef FD_ZERO
#endif
#define FD_ZERO(s)	    ((s)->fds_bits[0] = 0)

#ifdef SYSV
#include <termio.h>
#else
#include <sgtty.h>
#endif
#include <sys/time.h>
#endif

#ifdef MAC
#include <files.h>
#include <time.h>
#include <types.h>
#include <devices.h>
#endif

#include "protocol.h"
#include "sca.h"
#include "sctport.h"
#include <error.h>

/*-------------------------------------------------------------*/
/*   define informatin field size for PC                       */
/*-------------------------------------------------------------*/
#define IFSPC 254
/*-------------------------------------------------------------*/
/*   Extern parameters definition                              */
/*-------------------------------------------------------------*/
int             tp1_err = 0;	/* To include error code        */
#ifdef TRACE
FILE           *tp1_trfp = NULL;/* File descriptor of TRACE     */
#endif

/*-------------------------------------------------------------*/
/*   Local variables declaration                               */
/*-------------------------------------------------------------*/
#ifdef SUN
#ifdef SYSV
static struct termio o_par, n_par;
#else
static struct sgttyb o_par;
static struct sgttyb n_par;
#endif
#endif				/* from SUN */
#ifdef __HP__
#ifdef SYSV
static struct termio o_par, n_par;
#else
static struct sgttyb o_par;
static struct sgttyb n_par;
#endif
#endif				/* from __HP__ */
/*-------------------------------------------------------------*/
/*   Declare extern assembly module                            */
/*-------------------------------------------------------------*/
#ifdef DOS
/*-------------------------------------------------------------*/
/*   To initiate rs232 interface                               */
/*-------------------------------------------------------------*/
extern int far  RS232_init();

/*-------------------------------------------------------------*/
/*   To send protocol block to rs232 interface                 */
/*-------------------------------------------------------------*/
extern int far  sendstr(int, char far *, int);

/*-------------------------------------------------------------*/
/*   To receive protocol block from rs232 interface            */
/*-------------------------------------------------------------*/
extern int far  recestr(int, char far *, int, int);
#endif


#ifdef MAC
/* is maybe obsolete */
int COMinit(struct s_portparam *portpar);
int COMreset(struct s_portparam *portpar);
int COMclose(int fd);
int COMtrans(struct s_portparam *, char *, int , char[], int *);
#define MacOk 0
static ParamBlockRec InBlock, OutBlock;
#endif


/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure COMinit                 VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION             Initiation of the serial port    */
/*                                                             */
/*    INOUT                                                    */
/*      portpar               port parameter                   */
/*                            port_id will be set.             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Ok                               */
/*      -1                    Error                            */
/*-------------------------------------------------------------*/


int 
COMinit(portpar)
	struct s_portparam *portpar;
{
	int             fd;
	int             data_stru;
	int             ret;

#ifdef TRACE
	if (tp1_trfp == NULL)
		tp1_trfp = fopen("TRACE", "w");
#endif
#ifdef DOS
	if (!strncmp("COM1", portpar->port_name, 4))
		fd = 1;
	else if (!strncmp("COM2", portpar->port_name, 4))
		fd = 2;
	else {
		portpar->port_id = -1;
		tp1_err = INVALID_PORT;
		return (-1);
	}

	data_stru = portpar->databits | portpar->stopbits | (int) portpar->parity;
	if ((ret = RS232_init(fd, portpar->baud, data_stru)) != TP1_OK) {
		tp1_err = OPEN_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "error number=\n", tp1_err);
#endif
		return (-1);
	}
#endif
#ifdef SUN

	if ((fd = open(portpar->port_name, O_RDWR | O_NDELAY)) == -1) {
		portpar->port_id = -1;
		tp1_err = OPEN_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "  error = %x\n", tp1_err);
#endif
		return (-1);
	}

	/*
	 *  Set "exclusive-use" mode: 
	 *       no further opens are permitted until the file has been closed
	 */	
	ioctl(fd, TIOCEXCL, &o_par);


#ifdef SYSV
	ioctl(fd, TCGETA, &o_par);
	ioctl(fd, TCGETA, &n_par);
	n_par.c_iflag = 0;
	n_par.c_oflag = 0;
	n_par.c_cflag = portpar->baud | portpar->databits | portpar->stopbits
		| (int) portpar->parity | CREAD | CLOCAL;
	n_par.c_lflag = 0;
	ioctl(fd, TCSETAW, &n_par);
#else
	ioctl(fd, TIOCGETP, &o_par);
	ioctl(fd, TIOCGETP, &n_par);

	n_par.sg_ispeed = portpar->baud;
	n_par.sg_ospeed = portpar->baud;
	n_par.sg_flags = RAW;
	ioctl(fd, TIOCSETP, &n_par);
#endif
#endif				/* from SUN */
#ifdef __HP__

	if ((fd = open(portpar->port_name, O_RDWR | O_NDELAY)) == -1) {
		portpar->port_id = -1;
		tp1_err = OPEN_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "  error = %x\n", tp1_err);
#endif
		return (-1);
	}

	/*
	 *  Set "exclusive-use" mode: 
	 *       no further opens are permitted until the file has been closed
	 */	
	ioctl(fd, TIOCEXCL, &o_par);


#ifdef SYSV
	ioctl(fd, TCGETA, &o_par);
	ioctl(fd, TCGETA, &n_par);
	n_par.c_iflag = 0;
	n_par.c_oflag = 0;
	n_par.c_cflag = portpar->baud | portpar->databits | portpar->stopbits
		| (int) portpar->parity | CREAD | CLOCAL;
	n_par.c_lflag = 0;
	ioctl(fd, TCSETAW, &n_par);
#else
	ioctl(fd, TIOCGETP, &o_par);
	ioctl(fd, TIOCGETP, &n_par);

	n_par.sg_ispeed = portpar->baud;
	n_par.sg_ospeed = portpar->baud;
	n_par.sg_flags = RAW;
	ioctl(fd, TIOCSETP, &n_par);
#endif
#endif				/* from __HP__ */
#ifdef MAC
     fd = 1;          /* wird zwar bei MAC nicht gebraucht, mu§ aber != 0 sein */
     
     InBlock.ioParam.ioCompletion = NULL;
     InBlock.ioParam.ioNamePtr = (StringPtr) "\p.AIn";
     InBlock.ioParam.ioPermssn = fsRdPerm;
   
     ret = PBOpen(&InBlock, false);

     OutBlock.ioParam.ioCompletion = NULL;
     OutBlock.ioParam.ioNamePtr = (StringPtr) "\p.AOut";
     OutBlock.ioParam.ioPermssn = fsWrPerm;
   
     ret = PBOpen(&OutBlock, false);

     ret = SerReset(InBlock.ioParam.ioRefNum,
        portpar->baud | portpar->parity | portpar->databits | portpar->stopbits);   
     ret = SerReset(OutBlock.ioParam.ioRefNum,
        portpar->baud | portpar->parity | portpar->databits | portpar->stopbits);   

     if (ret != MacOk)
        {
        tp1_err = OPEN_ERR;
        portpar->port_id = -1;
#ifdef TRACE
        fprintf(tp1_trfp,"  error = %x\n",tp1_err);
#endif /* TRACE */
        return (-1);
        }
     
#endif /* from MAC */
#ifdef TRACE
	fprintf(tp1_trfp, "\nCOMinit :: \n\tSCT Id=%d\n", fd);
#endif
	portpar->port_id = fd;	/* To set port_id */
	portpar->first = 0;
	return (0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure COMreset                VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION             Initiation of the serial port    */
/*                                                             */
/*    INOUT                                                    */
/*      portpar               Port parameter                   */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Ok                               */
/*      -1                    Error                            */
/*-------------------------------------------------------------*/


int 
COMreset(portpar)
	struct s_portparam *portpar;
{
	int             data_stru;
	int             ret;

#ifdef DOS
	data_stru = portpar->databits | portpar->stopbits | (int) portpar->parity;
	if ((ret = RS232_init(portpar->port_id, portpar->baud, data_stru)) != TP1_OK) {
		tp1_err = OPEN_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "error number=\n", tp1_err);
#endif
		return (-1);
	}
#endif
#ifdef SUN
#ifdef SYSV
	n_par.c_iflag = 0;
	n_par.c_oflag = 0;
	n_par.c_cflag = portpar->baud | portpar->databits | portpar->stopbits
		| (int) portpar->parity | CREAD | CLOCAL;
	n_par.c_lflag = 0;
	ioctl(portpar->port_id, TCSETAW, &n_par);
#else
	n_par.sg_ispeed = portpar->baud;
	n_par.sg_ospeed = portpar->baud;
	n_par.sg_flags = RAW;
	ioctl(portpar->port_id, TIOCSETP, &n_par);
#endif
#endif				/* from SUN */
#ifdef __HP__
#ifdef SYSV
	n_par.c_iflag = 0;
	n_par.c_oflag = 0;
	n_par.c_cflag = portpar->baud | portpar->databits | portpar->stopbits
		| (int) portpar->parity | CREAD | CLOCAL;
	n_par.c_lflag = 0;
	ioctl(portpar->port_id, TCSETAW, &n_par);
#else
	n_par.sg_ispeed = portpar->baud;
	n_par.sg_ospeed = portpar->baud;
	n_par.sg_flags = RAW;
	ioctl(portpar->port_id, TIOCSETP, &n_par);
#endif
#endif				/* from __HP__ */
#ifdef MAC
/*	
	int fd;
     	fd = 1;          /* wird zwar bei MAC nicht gebraucht, muss aber != 0 sein */
     
     	InBlock.ioParam.ioCompletion = NULL;
     	InBlock.ioParam.ioNamePtr = (StringPtr) "\p.AIn";
     	InBlock.ioParam.ioPermssn = fsRdPerm;
   
     	ret = PBOpen(&InBlock, false);

    	 OutBlock.ioParam.ioCompletion = NULL;
    	 OutBlock.ioParam.ioNamePtr = (StringPtr) "\p.AOut";
    	 OutBlock.ioParam.ioPermssn = fsWrPerm;
   
     	ret = PBOpen(&OutBlock, false);

     	ret = SerReset(InBlock.ioParam.ioRefNum,
        portpar->baud | portpar->parity | portpar->databits | portpar->stopbits);   
     	ret = SerReset(OutBlock.ioParam.ioRefNum,
        portpar->baud | portpar->parity | portpar->databits | portpar->stopbits);   

     	if (ret != MacOk) {
 		tp1_err = OPEN_ERR;
      		portpar->port_id = -1;
#ifdef TRACE
        	fprintf(tp1_trfp,"  error = %x\n",tp1_err);
#endif /* TRACE */
        	return (-1);
        }
     
#endif /* from MAC */
#ifdef TRACE
#ifdef MAC
#else	
	fprintf(tp1_trfp, "\nCOMreset :: SCT Id=%d\n", portpar->port_id);
#endif
#endif
	return (0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure COMclose                VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION             Reseting the serial port         */
/*                                                             */
/*    INOUT                                                    */
/*      fd                    File descriptor of the port      */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Ok                               */
/*-------------------------------------------------------------*/


int 
COMclose(fd)
	int             fd;
{
	int             ret;
#ifdef TRACE
#ifdef MAC
     fprintf(tp1_trfp, "\nCOMclose :: SCT In=%d, Out=%d\n",
        InBlock.ioParam.ioRefNum, OutBlock.ioParam.ioRefNum);
#else
     fprintf(tp1_trfp,"\nCOMclose :: SCT Id=%d\n",fd);
#endif /* MAC */
#endif
#ifdef SUN
#ifdef SYSV
	ioctl(fd, TCSETAW, &o_par);
#else
	ioctl(fd, TIOCSETP, &o_par);
#endif
	close(fd);
#endif				/* from SUN */
#ifdef __HP__
#ifdef SYSV
	ioctl(fd, TCSETAW, &o_par);
#else
	ioctl(fd, TIOCSETP, &o_par);
#endif
	close(fd);
#endif				/* from __HP__ */
#ifdef MAC

   ret = PBClose(&InBlock, false);
#ifdef TRACE
   fprintf(tp1_trfp, "\tret PBClose(In) = %d", ret);
#endif

   ret = PBClose(&OutBlock, false);
#ifdef TRACE
   fprintf(tp1_trfp, "\tret PBClose(Out) = %d\n", ret);
#endif

#endif /* MAC */

	return (0);
	
} /* COMclose */



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  COMtrans               VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           To communicating with SCT for      */
/*                          transfering APDUs                  */
/*                                                             */
/*                                                             */
/*    IN                                                       */
/*      portpar             SCT parameter                      */
/*      APDU_reqstr         Request string                     */
/*      req_len             Length of APDU_reqstr              */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*      resp_len            Length of a complete APDU-response */
/*      APDU_respstr        Response string                    */
/*                                                             */
/*    USES                                                     */
/*     COMSend()            To send a TPDU request             */
/*     COMrece()            To receive a TPDU response         */
/*     blk_process()        To process response, and produce   */
/*                          an appropriate request             */
/*     Resynch()            To resynchronize protocol          */
/*     err_handle()         To indicate errors                 */
/*     divi_blk()           To get data for chaining           */
/*                                                             */
/*    RETURN                                                   */
/*     0                    Successful                         */
/*    -1                    Error occured                      */
/*                                                             */
/*-------------------------------------------------------------*/



int 
COMtrans(portpar, APDU_reqstr, req_len, APDU_respstr, resp_len)
	struct s_portparam *portpar;
	char           *APDU_reqstr;
	int             req_len;
	char            APDU_respstr[];
	int            *resp_len;
{
	int             repeat;
	int             ret;
	int             ret_send;
	int             ifsd;
	int             tpdulen;
	char            rpstr[512];
	BLOCKstru       block;
	CHAINstru       chaindata;


	tp1_err = 0;
	if (!portpar->first) {
		ret = Resynch(portpar);
		if (ret != 0)
			return (-1);
		portpar->first = 1;
	}
	ifsd = portpar->tpdusize - ((portpar->edc == E_LRC) ? 4 : 5);
	tpdulen = req_len + BLKHDLEN + ((portpar->edc == E_LRC) ? 1 : 2);
/*-------------------------------------------------------------*/
/*  Should chaining function be used ?                         */
/*-------------------------------------------------------------*/
	if (tpdulen > portpar->tpdusize) {
		if (portpar->chaining == C_OFF) {
			tp1_err = INVAL_TPDULEN;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (-1);
		}
/*-------------------------------------------------------------*/
/*  To prepare for chaining                                    */
/*-------------------------------------------------------------*/
		chaindata.amount = divi_blk(ifsd, APDU_reqstr, req_len, &chaindata);
		if (chaindata.amount < 0)
			return (-1);

/*-------------------------------------------------------------*/
/*  To send first chained block                                */
/*-------------------------------------------------------------*/
		block.I_rqstr = chaindata.sub_rqstr[0];
		block.inflen = chaindata.sublen[0];
/*-------------------------------------------------------------*/
/*  To set more bit in protocol control byte of I_BLOCK        */
/*-------------------------------------------------------------*/
		block.ms = T_MORE;
	} else {
/*-------------------------------------------------------------*/
/*  Chaing will not be used                                    */
/*-------------------------------------------------------------*/
		block.I_rqstr = APDU_reqstr;
		block.inflen = req_len;
		block.ms = 0;
	}
	block.blktype = I_BLOCK;
	do {
		repeat = 0;
		do {
			if ((ret_send = COMsend(*portpar, block)) == -1)
				return (-1);
			if ((ret = COMrece(portpar->port_id, rpstr, portpar->bwt, portpar->cwt)) == 0)
				ret = blk_process(rpstr, &portpar->ns, &portpar->rsv, &block, &chaindata,
						  APDU_respstr, resp_len);


			if (ret == -1 && repeat == BLKREPEAT - 1) {
#ifdef TRACE
				fprintf(tp1_trfp, "\nPC begins resynconizing SCT\n");
#endif
				Resynch(portpar);
				return (-1);
			}
			if (ret == -1) {
				repeat++;
				err_handle(portpar->rsv, &block.blktype, &block.nr);
			}
		} while ((repeat < BLKREPEAT) && (ret == -1));
		if (ret == PROT_RESYNCH) {
			tp1_err = PROT_RESYNCH;
			return (-1);
		}
	} while (ret != 0);

	return (0);

}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure State_reset             VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           To reset sending and receiving     */
/*                          state variables                    */
/*                                                             */
/*    IN                                                       */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*      ssv                 Sending state variable             */
/*      rsv                 Receiving state variable           */
/*                                                             */
/*    RETURN                                                   */
/*-------------------------------------------------------------*/
State_reset(ssv, rsv)
	int            *ssv;
	int            *rsv;
{
	*ssv = 0;
	*rsv = 1;

	return(0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  COMsend              VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION             To send a TPDU-request           */
/*                                                             */
/*    IN                                                       */
/*     portpar                Port parameters                  */
/*     block                  Protocol block                   */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    USES                                                     */
/*     Moudle from assembly                                    */
/*     routine siofunc.asm:                                    */
/*                                                             */
/*     sendstr()              if DOS                           */
/*                                                             */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Successful                       */
/*      -1                    Error occured                    */
/*-------------------------------------------------------------*/



int 
COMsend(portpar, block)
	struct s_portparam portpar;
	BLOCKstru       block;	/* BLOCKstru is defined in protocol.h */
{
	char            outstr[512];
	char           *piostr;
	int             len;
	int             i;
	int             k;
	int             ret;
	int             blklen, bcc, bcclen;

	piostr = &outstr[0];
/*-------------------------------------------------------------*/
/*   Node address :: DAD + SAD                                 */
/*-------------------------------------------------------------*/
	*piostr++ = (portpar.dad << 4) & 0xf0 | portpar.sad & 0x0f;

	switch (block.blktype) {
	case I_BLOCK:
/*-------------------------------------------------------------*/
/*   PCB of I_BLOCK :: NS + MS                                 */
/*-------------------------------------------------------------*/
		*piostr++ = portpar.ns | block.ms;
/*-------------------------------------------------------------*/
/*   Length field of I_BLOCK                                   */
/*-------------------------------------------------------------*/
		len = block.inflen;
		*piostr++ = len;
/*-------------------------------------------------------------*/
/*   Information field                                         */
/*-------------------------------------------------------------*/
		for (i = 0; i < len; i++)
			*piostr++ = *(block.I_rqstr + i);
		break;
	case S_BLOCK:
/*-------------------------------------------------------------*/
/*   Protocol control byte of S_BLOCK                          */
/*-------------------------------------------------------------*/
		*piostr++ = block.S_respbit | block.S_ctl;
/*-------------------------------------------------------------*/
/*   Length field of S_BLOCK                                   */
/*-------------------------------------------------------------*/
		len = 0;
		*piostr++ = len;

		/*
		 * for(i=0; i<len; i++) piostr++=*(block.S_rqstr + i);
		 */
		break;
	case R_BLOCK:
/*-------------------------------------------------------------*/
/*   Protocol control byte of R_BLOCK                          */
/*-------------------------------------------------------------*/
		*piostr++ = 0x80 | block.nr | 0x01;
/*-------------------------------------------------------------*/
/*   For R_BLOCK, length byte is 0                             */
/*-------------------------------------------------------------*/
		len = 0;
		*piostr++ = len;
		break;
	}
	bcclen = BLKHDLEN + len;
/*-------------------------------------------------------------*/
/*   Computing checksum  ( LRC version )                       */
/*-------------------------------------------------------------*/
	bcc = 0;
	for (i = 0; i < bcclen; i++)
		bcc = bcc ^ outstr[i];
	*piostr++ = bcc;
	*piostr = '\0';
	blklen = bcclen + LRC_LEN;

#ifdef TRACE
	fprintf(tp1_trfp, "\nTPDU_request:\n");
	for (i = 0; i < blklen; i++)
		fprintf(tp1_trfp, "%2x%c", (unsigned char) outstr[i], ((i + 1) % 24) ? ' ' : '\n');
	fprintf(tp1_trfp, "\nLength=%d\n", blklen);
#endif

/*-------------------------------------------------------------*/
/*   To send TPDU-request                                      */
/*-------------------------------------------------------------*/
	for (i = 0; i < blklen; i++) {
#ifdef DOS
		if ((ret = sendstr(portpar.port_id, &outstr[i], 1)) != TP1_OK)
#endif
#ifdef SUN
			if ((ret = write(portpar.port_id, &outstr[i], 1)) == -1)
#endif
#ifdef __HP__
			if ((ret = write(portpar.port_id, &outstr[i], 1)) == -1)
#endif
#ifdef MAC
      OutBlock.ioParam.ioBuffer = &outstr[i];
      OutBlock.ioParam.ioReqCount = 1;
      if ( (ret = PBWrite(&OutBlock, false)) != MacOk)
#endif 
			{
				tp1_err = WR_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "   error = %x\n", tp1_err);
#endif
				return (-1);
			}
	}
	return (0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  COMrece         VERSION 2.00                  */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION             To receive a TPDU-response       */
/*                                                             */
/*    IN                                                       */
/*      fd                    port identifier                  */
/*      bwt                   block waiting time               */
/*      cwt                   char  waiting time               */
/*                                                             */
/*    OUT                                                      */
/*      rpstr                 TPDU-response string             */
/*                                                             */
/*    USES                                                     */
/*     Module from assembly                                    */
/*     routine siofunc.asm:                                    */
/*     recestr()              if DOS                           */
/*                                                             */
/*     blkvalidity()          To check validity of response    */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Successful                       */
/*      -1                    Error occured                    */
/*-------------------------------------------------------------*/



int 
COMrece(fd, rpstr, bwt, cwt)
	int             fd;
	unsigned char  *rpstr;
	int             bwt;	/* block waiting time */
	int             cwt;	/* chars waiting time */
{

	int             i, ret;
	int             resplen;
	int             rdind;
	int             callrd;
	int             length;
	int             index;
	int             wt;	/* Waiting time */

#ifdef SUN
	int             wait_mark;
	int             width, nfds;
	fd_set          readfds, writefds, exceptfds;
	struct timeval  timeout;
	timerclear(&timeout);
#else
#ifdef __HP__
	int             wait_mark;
	int             width, nfds;
	int          readfds, writefds, exceptfds;
	struct timeval  timeout;
	timerclear(&timeout);
#endif
#endif
#ifdef MAC
        clock_t Start;
#endif /* MAC */

	resplen = BLKHDLEN;
	callrd = 2;
	index = 0;

	for (rdind = 0; rdind < callrd; rdind++) {
		for (i = 0; i < resplen; i++) {
#ifdef DOS
			wt = (!i && !rdind) ? (bwt * 18 + 1) : ((cwt * 18) / 10 + 1);
			if ((tp1_err = recestr(fd, rpstr + index + i, 1, wt)) != TP1_OK) {
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (-1);
			}
#endif
#ifdef SUN
/*-------------------------------------------------------------*/
/*   To check whether data on line is ready within waiting time*/
/*-------------------------------------------------------------*/
			if (!i && !rdind) {
				wt = bwt;
				wait_mark = BLOCK_WAIT;
			} else {
				wt = cwt;
				wait_mark = CHAR_WAIT;
			}
			INITforSELECT(fd, wait_mark, wt, &readfds, &writefds, &exceptfds, &timeout);
			width = getdtablesize();
			nfds = select(width, &readfds, &writefds, &exceptfds, &timeout);
			if (nfds == 0) {
/*-------------------------------------------------------------*/
/*  Time is out !                                              */
/*-------------------------------------------------------------*/
				tp1_err = (!i && !rdind) ? BLK_TIMEOUT : CHAR_TIMEOUT;
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (-1);
			} else if (nfds == -1) {
/*-------------------------------------------------------------*/
/*  Error occured from select system call                      */
/*-------------------------------------------------------------*/
				tp1_err = SELECT_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (-1);
			}
			if ((ret = read(fd, rpstr + index + i, 1)) != 1) {
				tp1_err = RD_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "  error = %x\n", tp1_err);
#endif
				return (-1);
			}
#endif				/* from define SUN */
#ifdef __HP__
/*-------------------------------------------------------------*/
/*   To check whether data on line is ready within waiting time*/
/*-------------------------------------------------------------*/
			if (!i && !rdind) {
				wt = bwt;
				wait_mark = BLOCK_WAIT;
			} else {
				wt = cwt;
				wait_mark = CHAR_WAIT;
			}
			INITforSELECT(fd, wait_mark, wt, &readfds, &writefds, &exceptfds, &timeout);
			width = getdtablesize();
			nfds = select(width, &readfds, &writefds, &exceptfds, &timeout);
			if (nfds == 0) {
/*-------------------------------------------------------------*/
/*  Time is out !                                              */
/*-------------------------------------------------------------*/
				tp1_err = (!i && !rdind) ? BLK_TIMEOUT : CHAR_TIMEOUT;
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (-1);
			} else if (nfds == -1) {
/*-------------------------------------------------------------*/
/*  Error occured from select system call                      */
/*-------------------------------------------------------------*/
				tp1_err = SELECT_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (-1);
			}
			if ((ret = read(fd, rpstr + index + i, 1)) != 1) {
				tp1_err = RD_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "  error = %x\n", tp1_err);
#endif
				return (-1);
			}
#endif				/* from define __HP__ */
#ifdef MAC

     /* Erst mal ermitteln, wieviele Clocks die BWT bzw. CWT sind
        Ganz zu Anfang gilt die Block-Waiting-Time, zwischen Chars eines Blocks
        gilt die Character-Waiting-Time */
            
     if( !i && !rdind )
        wt = bwt * CLOCKS_PER_SEC;
     else
        wt = cwt / 10.0 * CLOCKS_PER_SEC;

     /* NŠchstes Zeichen nach rpstr+index+i lesen */
     InBlock.ioParam.ioCompletion = NULL;
     InBlock.ioParam.ioBuffer = (Ptr)rpstr + index + i;
     InBlock.ioParam.ioReqCount = 1;

     /* Asynchronen Read-Request abschicken */
     ret = PBRead(&InBlock, true);
   
     /* Abwarten, bis Daten angekommen sind. Wenn's zulange dauert, Fehler! */
        
     /* Start-Clocks merken */
     Start = clock();
     /* und warten */
     while ((InBlock.ioParam.ioResult == 1) && (clock() - Start <= wt)) ; 
     
     /* TimeOut? */
     
     if (InBlock.ioParam.ioResult == 1)
        {
        tp1_err = (!i && !rdind) ? BLK_TIMEOUT : CHAR_TIMEOUT;

#ifdef TRACE
        fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif /* TRACE */

        /* Timeout, daher Read-Request noch killen */
       
        ret = PBKillIO(&InBlock, false); 
#ifdef TRACE
        fprintf(tp1_trfp, "ret PBKillIO(In) = %d\n", ret);
#endif

        return (-1);
        } /* if TimeOut */
     
     /* Lesefehler? */
        
     if ((InBlock.ioParam.ioResult != MacOk) || (InBlock.ioParam.ioActCount == 0))
        {
        tp1_err = RD_ERR;
        
#ifdef TRACE
     fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif /* TRACE */

        return (-1);
        } /* if Lesefehler */
        
#endif /* MAC */


		}       /* schoen, nicht ? */


		if (*(rpstr + BLKLPOS) > IFSPC) {
			tp1_err = INVALID_LEN;
#ifdef TRACE
			fprintf(tp1_trfp, "  Invalid length\n");
#endif
			return (-1);
		}
		resplen = *(rpstr + BLKLPOS) + 1;
		index = 3;
	}

#ifdef TRACE
	fprintf(tp1_trfp, "\nTPDU_response\n");
	for (i = 0; i < 3 + resplen; i++)
		fprintf(tp1_trfp, "%2x%c", *(rpstr + i), ((i + 1) % 24) ? ' ' : '\n');
	fprintf(tp1_trfp, "\nLength=%d\n", 3 + resplen);
#endif
/*-------------------------------------------------------------*/
/*   Is a valid response ?                                     */
/*-------------------------------------------------------------*/
	ret = blkvalidity(rpstr);
	return (ret);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  blkvalidity            VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION                                              */
/*      To check the validity of TPDU received                 */
/*                                                             */
/*                                                             */
/*    IN                                                       */
/*      rpstr               TPDU-response string               */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Valid                            */
/*      -1                    Invalid                          */
/*                                                             */
/*-------------------------------------------------------------*/
int 
blkvalidity(rpstr)		/* This is the LRC virsion */
	unsigned char   rpstr[];
{
	int             i;
	int             bcc, bcclen;
	int             ret;

	bcc = 0;
	bcclen = BLKHDLEN + rpstr[BLKLPOS];
	for (i = 0; i < bcclen; i++)
		bcc = bcc ^ rpstr[i];

	if (bcc != rpstr[bcclen]) {
		tp1_err = EDC_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "\nEDC_ERR\n");
#endif
		return (ERROR);
	} else
		return (TP1_OK);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  err_handle             VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           To recovey errors by producing     */
/*                          an appropriate R_BLOCK             */
/*                                                             */
/*    IN                                                       */
/*      rsv                 Receiving state variable           */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*      blktype             Type of protocol block             */
/*      nr                  Receiving sequence number          */
/*                                                             */
/*    RETURN                                                   */
/*      ERROR               Error indication                   */
/*-------------------------------------------------------------*/
int 
err_handle(rsv, blktype, nr)	/* to retransmite last block */
	int             rsv;
	int            *blktype;
	int            *nr;
{
	*blktype = R_BLOCK;
	*nr = (!NOT(rsv)) ? 0 : NR_1;
	return (ERROR);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  Is_lastblkResyResp     VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION      To check whether the block sent last    */
/*                     is a S(RESYNCH,response)                */
/*                                                             */
/*    IN                                                       */
/*      blktype        Type of block                           */
/*      S_ctl          Control function of S_BLOCK             */
/*      S_respbit      Responnse indication of S_BLOCK         */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                    Negative                         */
/*       1                    Positive                         */
/*                                                             */
/*-------------------------------------------------------------*/
int 
Is_lastblkResyResp(blktype, S_ctl, S_respbit)
	int             blktype;
	int             S_ctl;
	int             S_respbit;
{
	if (blktype != S_BLOCK)
		return (0);
	if (S_ctl != RESYCH)
		return (0);
	if (S_respbit != 1)
		return (0);
	return (1);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  INITforSELECT          VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           Initiation for select system call  */
/*                                                             */
/*                                                             */
/*                                                             */
/*    IN                                                       */
/*      fd                  SCT identifier                     */
/*      wt                  Waiting time when receiving        */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*      readfds                                                */
/*      writefds                                               */
/*      exceptfds                                              */
/*      timeout                                                */
/*                                                             */
/*-------------------------------------------------------------*/
#ifdef SUN
INITforSELECT(fd, waitmk, wt, readfds, writefds, exceptfds, timeout)
	int             fd;
	int             waitmk;
	int             wt;
	fd_set         *readfds, *writefds, *exceptfds;
	struct timeval *timeout;
{
	FD_ZERO(readfds);
	FD_ZERO(writefds);
	FD_ZERO(exceptfds);
/*-------------------------------------------------------------*/
/*  To check fd in read file descriptor set                    */
/*-------------------------------------------------------------*/
	FD_SET(fd, readfds);
/*-------------------------------------------------------------*/
/*  To set tioimout value                                      */
/*-------------------------------------------------------------*/
	if (waitmk == BLOCK_WAIT) {
		timeout->tv_sec = wt;
		timeout->tv_usec = 0;
	} else {
		timeout->tv_sec = 0;
		timeout->tv_usec = wt * 100000;
	}

	return(0);
}
#endif

#ifdef __HP__
INITforSELECT(fd, waitmk, wt, readfds, writefds, exceptfds, timeout)
	int             fd;
	int             waitmk;
	int             wt;
	fd_set         *readfds, *writefds, *exceptfds;
	struct timeval *timeout;
{

	FD_ZERO(readfds);
	FD_ZERO(writefds);
	FD_ZERO(exceptfds);

/*-------------------------------------------------------------*/
/*  To check fd in read file descriptor set                    */
/*-------------------------------------------------------------*/
	FD_SET(fd, readfds);
/*-------------------------------------------------------------*/
/*  To set tioimout value                                      */
/*-------------------------------------------------------------*/
	if (waitmk == BLOCK_WAIT) {
		timeout->tv_sec = wt;
		timeout->tv_usec = 0;
	} else {
		timeout->tv_sec = 0;
		timeout->tv_usec = wt * 100000;
	}
}
#endif



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  getbits                VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           To read bits in an integer         */
/*                                                             */
/*                                                             */
/*                                                             */
/*    IN                                                       */
/*      x                   Unsigned integer to read           */
/*      p                   Position from which bits is read   */
/*      n                   Amount of bits to read             */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                Value has been read                */
/*                                                             */
/*-------------------------------------------------------------*/
int 
getbits(x, p, n)
	unsigned        x, p, n;
{
	return ((x >> (p + 1 - n)) & ~(~0 << n));
}




/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  blk_process            VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION                                              */
/*      To process the block received, and produce             */
/*      appropriate block                                      */
/*                                                             */
/*    IN                                                       */
/*      rpstr                 Response string                  */
/*                                                             */
/*    INOUT                                                    */
/*      ssv                   Sending state variable           */
/*      rsv                   Receiving state variable         */
/*      block                 Protocol block data              */
/*      chaindata             Data for chaining                */
/*      outlen                Length of APDU                   */
/*                                                             */
/*    USES                                                     */
/*      getbits()             To get bits in an integer        */
/*      Is_lastblkResyResp()  To check whether the block sent  */
/*                            last is a S(RESYNCH,response)    */
/*                                                             */
/*    OUT                                                      */
/*      outdata               APDU response                    */
/*                                                             */
/*    RETURN                                                   */
/*        0                   Procession is finished           */
/*       -1                   Error occured                    */
/*       -2                   To continue receiving data       */
/*     PROT_RESYNCH           Protocol is resynchronized       */
/*                                                             */
/*-------------------------------------------------------------*/



int 
blk_process(rpstr, ssv, rsv, block, chaindata, outdata, outlen)
	unsigned char   rpstr[];
	int            *ssv;
	int            *rsv;
	BLOCKstru      *block;
	CHAINstru      *chaindata;
	unsigned char   outdata[];
	int            *outlen;
{
	int             i;
	int             Pcb;	/* Protocol control byte */
	int             BLK_TYPE;
	int             k;
	int             R_nr;	/* The N(R) of rpstr received */
	int             Mr;	/* More bit of PCB of respones */
	int             New_rsv;
	int             ret;

	Pcb = rpstr[1];		/* Protocol control byte */
	BLK_TYPE = getbits(Pcb, 7, 2);
	switch (BLK_TYPE) {
	case R_BLOCK:
/*-------------------------------------------------------------*/
/*   Length byte of R_BLOCK should be zero                     */
/*-------------------------------------------------------------*/
		if (rpstr[BLKLPOS]) {
			tp1_err = SYNTAX_ERR;
#ifdef TRACE

			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
		}
		R_nr = (Pcb & NR_1) ? NS_1 : 0;
		if (Is_lastblkResyResp(block->blktype, block->S_ctl, block->S_respbit))
/*-------------------------------------------------------------*/
/*   After PC sent S(RESYNCH,response), a block R(0) should be */
/*   received                                                  */
/*-------------------------------------------------------------*/
		{
			if (R_nr) {
				tp1_err = SYNTAX_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "errno =%x\n", tp1_err);
#endif
				return (ERROR);
			} else {
/*-------------------------------------------------------------*/
/*   To reset sending- and receiving state variables           */
/*-------------------------------------------------------------*/
				State_reset(ssv, rsv);
				return (PROT_RESYNCH);
			}
		}
		if (R_nr == *ssv)
/*-------------------------------------------------------------*/
/*   To retransmit I_BLOCK last sent                           */
/*-------------------------------------------------------------*/
		{
			block->blktype = I_BLOCK;
			return (CONTINUE);
		} else if (block->ms) {	/* With chain_function at PC */
/*-------------------------------------------------------------*/
/*   To ask to transmit I_block with sending sequence number   */
/*   equal to R_nr                                             */
/*-------------------------------------------------------------*/
			block->blktype = I_BLOCK;
			*ssv = (R_nr == 0) ? 0 : NS_1;
			chaindata->sequence++;
/*-------------------------------------------------------------*/
/*   Is the last chained block ? yes, More bit is cleared      */
/*-------------------------------------------------------------*/
			if (chaindata->sequence == chaindata->amount - 1)
				block->ms = 0;
			else
				block->ms = T_MORE;

			block->I_rqstr = chaindata->sub_rqstr[chaindata->sequence];
			block->inflen = chaindata->sublen[chaindata->sequence];
			return (CONTINUE);
		} else {
			tp1_err = SYNTAX_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
		}
		break;
	case S_BLOCK:

		i = getbits(Pcb, 2, 3);
		switch (i) {
		case RESYCH:
			if (Pcb & 0x20) {	/* Is response ? */
				/*-------------------------------------------------------------*/
				/*
				 * S(RESYNCH,response) should be received in
				 * procedure Resynch()
				 */
				/*-------------------------------------------------------------*/
				tp1_err = SYNTAX_ERR;
#ifdef TRACE
				fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
				return (ERROR);
			}
/*-------------------------------------------------------------*/
/*   To send S(RESYNCH,response)                               */
/*-------------------------------------------------------------*/
			block->blktype = S_BLOCK;
			block->S_respbit = RESPONSE;
			block->S_ctl = RESYCH;
			return (CONTINUE);
			break;
/*-------------------------------------------------------------*/
/*   Currently, another control functions are not used         */
/*-------------------------------------------------------------*/
		default:	/* This is invalid rpstr */
			tp1_err = SYNTAX_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
			break;
		}
	case 1:
	case I_BLOCK:
		if (Is_lastblkResyResp(block->blktype, block->S_ctl, block->S_respbit)) {
			tp1_err = SYNTAX_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
		}
		if (block->ms == T_MORE)
/*-------------------------------------------------------------*/
/*   Chaining is only possible in one direction at a time      */
/*-------------------------------------------------------------*/
		{
			tp1_err = SYNTAX_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
		}
		New_rsv = getbits(Pcb, 6, 1);
		Mr = getbits(Pcb, 5, 1);

		k = New_rsv - *rsv;
/*-------------------------------------------------------------*/
/*   To keep new receiving state variable                      */
/*-------------------------------------------------------------*/
		*rsv = New_rsv;
		if (k == 0)
/*-------------------------------------------------------------*/
/*   It is correct that sending sequence number of block       */
/*   received is diffrent from that received last              */
/*-------------------------------------------------------------*/
		{
			tp1_err = SYNTAX_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "error number=%x\n", tp1_err);
#endif
			return (ERROR);
		}
/*-------------------------------------------------------------*/
/*   To saveing data of I_BLOCK                                */
/*-------------------------------------------------------------*/
		for (i = 0; i < rpstr[2]; i++)
			outdata[*outlen + i] = rpstr[3 + i];
		*outlen += rpstr[2];

		if (Mr)
/*-------------------------------------------------------------*/
/*   SCT sends data with chaining function                     */
/*-------------------------------------------------------------*/
		{
			block->blktype = R_BLOCK;
/*-------------------------------------------------------------*/
/*  To expect next chained block from SCT with sendind         */
/*  sequence number ns equal to new nr                         */
/*-------------------------------------------------------------*/
			block->nr = (!NOT(*rsv)) ? 0 : NR_1;
			return (CONTINUE);
		} else {
/*-------------------------------------------------------------*/
/*   The complete APDU response has been received. It is ready */
/*   to send next APDU request for PC                          */
/*-------------------------------------------------------------*/
			*ssv = (!NOT(*ssv)) ? 0 : NS_1;
			return (0);
		}
		break;
	}

	return (0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  Resynch                VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION           To resynchronize protocol by       */
/*                          sending S(RESYNCH,request)         */
/*                                                             */
/*    IN                                                       */
/*                                                             */
/*    INOUT                                                    */
/*      portpar             SCT parameters                     */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0                  Protocol is resynchronized         */
/*      -1                  Error                              */
/*                                                             */
/*-------------------------------------------------------------*/


int 
Resynch(portpar)
	struct s_portparam *portpar;
{

	int             reapeat;
	int             ret;
	int             ret_ansys;
	char            rpstr[255];
	BLOCKstru       block;

/*-------------------------------------------------------------*/
/*   To send S(RESYNCH,request)                                */
/*-------------------------------------------------------------*/
	block.blktype = S_BLOCK;
	block.S_respbit = REQUEST;
	block.S_ctl = RESYCH;

	reapeat = 0;
	do {
		if ((ret = COMsend(*portpar, block)) == -1)
			return (-1);
		if (((ret = COMrece(portpar->port_id, rpstr, portpar->bwt, portpar->cwt)) == -1)
		    && (reapeat == BLKREPEAT - 1)) {
#ifdef TRACE
			fprintf(tp1_trfp, "\nSCT should be reset phsically!\n");
#endif
			State_reset(&portpar->ns, &portpar->rsv);
			tp1_err = SCT_RESET;
			return (-1);
		}
		reapeat++;
	}
	while ((ret == -1 || (ret_ansys = Is_ResynchResp(rpstr)) == -1)
	       && reapeat < BLKREPEAT);
#ifdef TRACE
	fprintf(tp1_trfp, "\nProtocol is resynchronized\n");
#endif
	State_reset(&portpar->ns, &portpar->rsv);
	tp1_err = PROT_RESYNCH;
	return (0);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  divi_blk               VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION       To divide a langer string into small   */
/*                      strings                                */
/*                                                             */
/*    IN                                                       */
/*      ifsd            Max. length of each divided string     */
/*      rqstr           String to be divided                   */
/*      len             Length of the string                   */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*      chaindata       Data for chainging, CHAINstru is       */
/*                      defined in protocol.h                  */
/*    RETURN                                                   */
/*      sequce          The amount of strings                  */
/*      -1              Memory alloc error                     */
/*-------------------------------------------------------------*/


int 
divi_blk(ifsd, rqstr, len, chaindata)
	int             ifsd;
	char           *rqstr;
	int             len;
	CHAINstru      *chaindata;
{
	int             i;
	int             length;
	int             index = 0;
	int             sequce = 0;
	char           *tmp, *p;
	length = len;


	do {
		if ((tmp = malloc(ifsd)) == NULL) {
			tp1_err = MEMO_ERR;
#ifdef TRACE
			fprintf(tp1_trfp, "\nMemory alloc error!\n");
#endif
			return (-1);
		}
		p = tmp;
		for (i = 0; i < ifsd; i++)
			*tmp++ = *(rqstr + i + index);
		chaindata->sub_rqstr[sequce] = p;
		chaindata->sublen[sequce] = ifsd;
		sequce++;
		index += ifsd;
		length = length - ifsd;
	} while (length > ifsd);

	if ((tmp = malloc(length)) == NULL) {
		tp1_err = MEMO_ERR;
#ifdef TRACE
		fprintf(tp1_trfp, "\nMemory alloc error!\n");
#endif
		return (-1);
	}
	p = tmp;
	for (i = 0; i < length; i++)
		*tmp++ = *(rqstr + i + index);
	chaindata->sub_rqstr[sequce] = p;
	chaindata->sublen[sequce] = length;
	sequce++;
	chaindata->sequence = 0;
	free(p);
	return (sequce);
}



/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    Procedure  Is_ResynchResp         VERSION 2.00           */
/*                                         DATE                */
/*                                           BY Zhou           */
/*                                                             */
/*                                                             */
/*    DESCRIPTION       To check whether the block is a        */
/*                      S(RESYNCH,response)                    */
/*                                                             */
/*    IN                                                       */
/*      rpstr           String to be check                     */
/*                                                             */
/*    INOUT                                                    */
/*                                                             */
/*    OUT                                                      */
/*                                                             */
/*    RETURN                                                   */
/*       0              Positive                               */
/*      -1              Negative                               */
/*-------------------------------------------------------------*/
int 
Is_ResynchResp(rpstr)
	char            rpstr[];
{
	if (getbits(rpstr[1], 7, 2) != S_BLOCK)
		return (-1);
	if (getbits(rpstr[1], 2, 3) != RESYCH)
		return (-1);
	if (getbits(rpstr[1], 5, 1) != 1)
		return (-1);
	return (0);
}
