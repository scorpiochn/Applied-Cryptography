/*-------------------------------------------------------+-----*/
/*							 | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0			 +-----*/
/*							       */
/*-------------------------------------------------------------*/
/*							       */
/*    PACKAGE	SCTINT			VERSION 2.0	       */
/*					   DATE November 1991  */
/*					     BY Levona Eckstein*/
/*							       */
/*    FILENAME			                 	       */
/*      sctport.h 		         		       */
/*							       */
/*    DESCRIPTION					       */
/*      This file contains all local define's and structures   */
/*	for the port-memory      			       */
/*-------------------------------------------------------------*/


#define LSCTNAME        8       /* max. length of sct name */
#define LPORTNAME       24      /* max. length of port name */

#define B_19200        19200

#ifdef SYSTEMV
#define STOP_1      0x00
#define STOP_2      64
#define DATA_8      48
#define DATA_7      32
#define PARNONE     0
#define PARODD      768
#define PAREVEN     256
#endif
#ifdef DOS
#define STOP_1      0x00
#define STOP_2      0x01
#define DATA_8      0x03
#define DATA_7      0x02
#define PARNONE     0
#define PARODD      1
#define PAREVEN     2
#endif
#ifdef BSD
#define STOP_1      0x00
#define STOP_2      64
#define DATA_8      48
#define DATA_7      32
#define PARNONE     0
#define PARODD      768
#define PAREVEN     256
#endif
#ifdef MAC
#include <Serial.h>
#define STOP_1      stop10
#define STOP_2      stop20
#define DATA_8      data8
#define DATA_7      data7
#define PARNONE     noParity
#define PARODD      oddParity
#define PAREVEN     evenParity
#endif

#define PORTNULL        (struct s_portparam *)0
typedef enum {P_NONE,P_ODD,P_EVEN} ParityType;
typedef enum {E_LRC,E_CRC} EdcType;
typedef enum {C_OFF,C_ON} Chain;

struct s_portparam {
                      char      port_name[LPORTNAME+1];     /* + 1 for \0 */
                      int       bwt;
                      int       cwt;
                      int       baud;
                      int       databits;
                      int       stopbits;
                      ParityType parity;
                      int       dataformat;
                      int       tpdusize;
                      int       apdusize;
                      EdcType   edc;
                      int       protocoltype;    /* set, when S_RESET response*/
						 /* received		      */
                      Chain     chaining;        /* initialized with C_ON in */
					         /* sctmem.c -> init_elem    */

                      int       ns;		 /* set in t1.c		     */
                      int       rsv;		 /* set in t1.c              */
                      int       sad;		 /* set in scctint.c -> sct_reset*/
                      int       dad;		 /* set in sctint.c -> sct_reset*/
                      char      *schistory;
                      int       port_id;         /* = FD of OPEN PORT */
                      int       first;		 /* set in t1.c              */
		      int       setmode;         /* set in sta_setmode      */
		      KeyInfo   session_key;     /* temporary session_key */
                      int       ssc;             /* send sequence counter */
                      SecMess   secure_messaging; /* secure messaging 
						    between dte and sct */
		      unsigned int sc_request;  	
                      struct s_portparam *p_next;
                 };


#ifdef PROCDAT

struct s_help_portparam {
                      char      port_name[LPORTNAME+1];     /* + 1 for \0 */
                      int       bwt;
                      int       cwt;
                      int       baud;
                      int       databits;
                      int       stopbits;
                      ParityType parity;
                      int       dataformat;
                      int       tpdusize;
                      int       apdusize;
                      EdcType   edc;
                      int       protocoltype;    /* set, when S_RESET response*/
						 /* received		      */
                      Chain     chaining;        /* initialized with C_ON in */
					         /* sctmem.c -> init_elem    */

                      int       ns;		 /* set in t1.c		     */
                      int       rsv;		 /* set in t1.c              */
                      int       sad;		 /* set in scctint.c -> sct_reset*/
                      int       dad;		 /* set in sctint.c -> sct_reset*/
                      char      schistory[64];
                      int       port_id;         /* = FD of OPEN PORT */
                      int       first;		 /* set in t1.c              */
		      int       setmode;         /* set in sta_setmode      */
		      KeyInfo   session_key;     /* temporary session_key */
                      int       ssc;             /* send sequence counter */
                      SecMess   secure_messaging; /* secure messaging 
						    between dte and sct */
		      unsigned int sc_request;  	
                 };

#endif 	/* PROCDAT */
