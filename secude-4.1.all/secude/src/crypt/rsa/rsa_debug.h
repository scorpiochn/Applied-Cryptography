/*
 *  SecuDE Release 4.1 (GMD)
 */
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

#include <stdio.h>
extern int  RSAgenCountDown;
extern char sec_verbose;

#ifdef	DEBUG
#define Random(l,z)	{ fprintf(stderr," Random: (%d,size LZ %d)\n",l,sizeof z);\
			  rndm(l,z); }

#define	Shift(a,b,c)	{ fprintf(stderr," Shifting: \r\t\t%+8d\r",b); \
			  fflush(stderr);	\
			  shift(a,b,c); }

#define ShiftSeed(a,b,c) { fprintf(stderr,"Seed"); Shift(a,b,c); }

#define RabinsParm(r,d) fprintf(stderr,"RabinsTest: (%4d)   DIV %4d\n",r,d)
#define PrintRabinstest	/* NOP */
#define PrintRabinsCount(rt)	/* NOP */
#define PrintGenRSA(string)	{ fprintf(stderr,string); fflush(stderr); }
#define PrintNote(string)       /* NOP */
#define PrintSTART(s,c)         /* NOP */
static void
PrintL_NUMBER(X,cnum)
register L_NUMBER *X;
char    *cnum;
   {
	char txt[WBYTES*MAXLGTH];
	struct {int noctets; char *octets; }
		bytes;

	bytes.octets = txt;
	lntoINTEGER(X,&bytes);
	fprintf(stderr,"INTEGER value of %s.\n",cnum);
	aux_xdump(txt,bytes.noctets,0);
	return;
   }
	
#else
static char Cycle[5] = "-\\|/";
#define	PrintCycle(i)	{ if(sec_verbose) {fprintf(stderr,"%c\b",Cycle[i%4]); fflush(stderr);} }
/*
#define PrintCycleCnt(c) { fprintf(stderr,"\r\t\t\t            \r",c); }
*/
#define PrintCycleCnt(c) /* NOP */
#define	Shift(a,b,c)	shift(a,b,c)
#define ShiftSeed(a,b,c) shift(a,b,c)
#define Random	rndm
#define RabinsParm(r,d)		PrintCycle(r)
#define PrintRabinstest { if(sec_verbose) {fprintf(stderr,"\b\b\b%d: ",RSAgenCountDown--); fflush(stderr);} }
#define PrintRabinsCount(rt)	PrintCycleCnt(rt)
#define PrintGenRSA(string)   /* NOP */
#define PrintL_NUMBER(x,txt)    /* NOP */
#define PrintNote(string)     { if(sec_verbose) {fprintf(stderr,string); fflush(stderr);} }
#define PrintSTART(s,c) { if(sec_verbose) {PrintNote(s); RSAgenCountDown = c;} }
#endif
