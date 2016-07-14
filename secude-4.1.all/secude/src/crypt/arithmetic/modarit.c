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

/*                                                             */
/*    PACKAGE   MODARIT                 VERSION 1.10b          */
/*                                         DATE 04.08.88       */
/*                                           BY Wolfgang Bott  */
/*                                          And Stephan Thiele */
/*                                                             */
/*    DESCRIPTION                                              */
/*      In MODARIT  sind die Modulo-Rechenroutinen             */
/*      zusammengefasst.                                       */
/*                                                             */
/*                                                             */
/*    EXPORT          DESCRIPTION                              */
/*      madd()          Modulo - Addition                      */
/*      msub()          Modulo - Subtraktion                   */
/*      mmult()         Modulo - Multiplikation                */
/*      mdiv()          Modulo - Division                      */
/*      mexp()          Modulo - Exponentiation                */
/*                                                             */
/*    USES            DESCRIPTION                              */
/*      add             Addition                               */
/*      comp            Vergleich                              */
/*      div             Division                               */
/*      mult            Multiplikation                         */
/*      sub             Subtraktion                            */
/*      trans           Uebertragen                            */
/*                                                             */
/*    INTERNAL        DESCRIPTION                              */
/*                                                             */
/*    BUGS                                                     */
/*      MODARIT ist fuer BS2000 nicht geeignet (wegen mexp     */
/*      werden dort die Assembler-Versionen verwendet)         */
/*                                                             */
/*-------------------------------------------------------------*/
 
/*-------------------------------------------------------------*/
/*   include-Dateien                                           */
/*-------------------------------------------------------------*/
 
#include "arithmetic.h"
 
/*-------------------------------------------------------------*/
/*   Preprocessor - Definitionen   (siehe token.h)             */
/*-------------------------------------------------------------*/
 
/*-------------------------------------------------------------*/
/*   Typ - Definitionen  ( siehe token.h )                     */
/*-------------------------------------------------------------*/
 
/*-------------------------------------------------------------*/
/*   externe Variablen - Deklarationen                         */
/*-------------------------------------------------------------*/
 
extern L_NUMBER  lz_null [];
extern L_NUMBER  lz_eins [];

/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   PROC madd                           VERSION 1.10b   +-----*/
/*                                          DATE 03.08.88      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Moduloaddition.                              */
/*                Akzeptiert beliebige Zahlen als Eingabe,     */
/*                liefert aber garantiert einen Wert zwischen  */
/*                '0' und 'modulu - 1' zurueck.                */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     op1                1. Summand                           */
/*     op2                2. Summand                           */
/*     modul              Modul bez. dem gerechnet wird.       */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     erg                Summe von op1 und op2 mod. modul     */
/*                                                             */
/*-------------------------------------------------------------*/
 
madd(op1,op2,erg,modul)
 
  L_NUMBER op1[];
  L_NUMBER op2[];
  L_NUMBER erg[];
  L_NUMBER modul[];
 
{
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
 
   add(op1,op2,erg);
   if(comp(erg,modul) < 0)
        {
        return(0);
        }
   else
        {
        sub(erg,modul,erg);
        if (comp(erg,modul) < 0)
                {
                return(0);
                }
        else
                {
                div(erg,modul,erg,erg);
                }
        }  /* end else   */
 
	return(0);
}  /* end madd          */
 
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  madd                       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   PROC msub                           VERSION 1.10b   +-----*/
/*                                          DATE 03.08.88      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Modulosubtraktion.                           */
/*                Akzeptiert beliebige Zahlen als Eingabe,     */
/*                liefert aber garantiert einen Wert zwischen  */
/*                '0' und 'modul - 1' zurueck.                 */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     op1                Subtrahend als lange Zahl            */
/*     op2                Minuend als lange Zahl               */
/*     modul              Modul bez. dem gerechnet wird.       */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     erg                Differenz aus Subtrahend und Minuend */
/*                                                             */
/*-------------------------------------------------------------*/
 
msub(op1,op2,erg,modul)
 
  L_NUMBER op1[];
  L_NUMBER op2[];
  L_NUMBER erg[];
  L_NUMBER modul[];
 
  {
 
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
 
    L_NUMBER temp[MAXLGTH];    /* Hilfsfeld um Zwischen-       */
                               /* ergebnis zu speichern        */

   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
 
   if (comp(op1,op2) >= 0)
        {
        sub(op1,op2,erg);
        if (comp(erg,modul) >= 0) div(erg,modul,erg,erg);
        }
    else
        {
        add(op1,modul,temp);
        if (comp(temp,op2) >= 0)
                {
                sub(temp,op2,erg);
                if (comp(erg,modul) >= 0) div(erg,modul,erg,erg);
                }
           else
                {
                div(op2,modul,erg,erg);
                sub(temp,erg,erg);
                div(erg,modul,erg,erg);
                } /* end inner else                            */
        } /* end outer else                                    */

	return(0);
  }  /* end msub                                               */
 
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  msub                       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   PROC mmult                          VERSION 1.10b   +-----*/
/*                                          DATE 03.08.88      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Modulomultiplikation.                        */
/*                Akzeptiert beliebige Zahlen als Eingabe,     */
/*                liefert aber garantiert einen Wert zwischen  */
/*                '0' und 'modul - 1' zurueck.                 */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     op1                Die beiden faktoren als              */
/*     op2                lange Zahlen                         */
/*     modul              Der Modul bez. dem gerechnet wird    */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     erg                Das Produkt mod. modul               */
/*                                                             */
/*-------------------------------------------------------------*/
 
mmult(op1,op2,erg,modul)
 
  L_NUMBER op1[];
  L_NUMBER op2[];
  L_NUMBER erg[];
  L_NUMBER modul[];
 
{
 
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
 
   static  L_NUMBER temp[2 * MAXLGTH];
                                       /*Hilfsfeld um Zwischen-*/
                                       /*ergebnis zu speichern */
 
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
 
   mult(op1,op2,temp);
   div(temp,modul,erg,erg);
 

	return(0);
}  /* end mmult                                                */
 
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  mmult                      */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   PROC mdiv                           VERSION 1.10b   +-----*/
/*                                          DATE 03.08.88      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Modulodivision.                              */
/*                Akzeptiert beliebige Zahlen als Eingabe,     */
/*                liefert aber garantiert einen Wert zwischen  */
/*                '0' und 'modul - 1' zurueck.                 */
/*                                                             */
/*   IN                 Description                            */
/*     op1                Divident als lange Zahl              */
/*     op2                Divisor als lange Zahl               */
/*     modul              Modul bez. dem gerechnet werden soll */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     erg                Quotient mod. Modul                  */
/*                                                             */
/*   RET                                                       */
/*     -1                 Division durch 0                     */
/*                                                             */
/*-------------------------------------------------------------*/
 
mdiv(op1,op2,erg,modul)
 
  L_NUMBER op1[];
  L_NUMBER op2[];
  L_NUMBER erg[];
  L_NUMBER modul[];
{
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   /*   Hilfsfelder                                            */
   /*----------------------------------------------------------*/
   static  L_NUMBER  x[MAXLGTH];
   static  L_NUMBER  y[MAXLGTH];
   static  L_NUMBER  r[MAXLGTH];
   static  L_NUMBER  s[MAXLGTH];
   static  L_NUMBER a1[MAXLGTH];
   static  L_NUMBER a2[MAXLGTH];
 
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*  Division durch Null ?                                   */
   /*----------------------------------------------------------*/
 
   if (comp(op2,lz_null) == 0) {
           return(-1);
   }
   else {

   /*----------------------------------------------------------*/
   /*  Beginn des erweiterten Euklidischen Algorithmus'        */
   /*  Arbeitsfelder initialiseren                             */
   /*----------------------------------------------------------*/
           trans(modul,x);
           trans(op2,y);
           trans(lz_null,a1);
           trans(lz_eins,a2);
 
   /*----------------------------------------------------------*/
   /*  Erweiterter Euklidischer Algorithmus                    */
   /*----------------------------------------------------------*/
           div(x,y,s,r);
           while (comp(r,lz_null) != 0) {
                 mmult(s,a2,s,modul);
                 msub(a1,s,s,modul);
                 trans(a2,a1);
                 trans(s,a2);
                 trans(y,x);
                 trans(r,y);
                 div(x,y,s,r);
           } 
   /*----------------------------------------------------------*/
   /*  GGT bestimmt. Nun kann entschieden werden, ob die       */
   /*  Division moeglich ist                                   */
   /*----------------------------------------------------------*/
           if (comp(y,lz_eins) == 0) {
                mmult(a2,op1,erg,modul);
                return(0);
           }
           else {
                div(op1,y,y,s);
                if (comp(s,lz_null) == 0) {
                        mmult(a2,y,erg,modul);
                        return(0);
                }
                else return(-1);
           }
   }

 } 
 
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  mdiv                       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   PROC mexp                           VERSION 1.10b   +-----*/
/*                                          DATE 03.08.88      */
/*                                            BY Bott Wolfgang */
/*                                           UND Stephan Thiele*/
/*                                                             */
/*   DESCRIPTION: Moduloexponentiation.                        */
/*                Akzeptiert beliebige Zahlen als Eingabe,     */
/*                liefert aber garantiert einen Wert zwischen  */
/*                '0' und 'modul - 1' zurueck.                 */
/*                                                             */
/*   IN                 Description                            */
/*     bas                Basis als lange Zahl                 */
/*     exp                Exponent als lange Zahl              */
/*     modul              Modul bez. dem gerechnet wird        */
/*                                                             */
/*   OUT                                                       */
/*     erg                Basis (Hoch) Exponent --> Ergebnis   */
/*                                                             */
/*-------------------------------------------------------------*/
 
mexp(bas,exp,erg,modul)
 
  L_NUMBER bas[];
  L_NUMBER exp[];
  L_NUMBER erg[];
  L_NUMBER modul[];
 
{
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
 
   static  L_NUMBER acc[MAXLGTH];    /* Akkumulator            */
                   int i,j,k,l;      /* Schleifenvariablen     */
 
   /*----------------------------------------------------------*/
   /*  Arbeitsfelder                                           */
   /*----------------------------------------------------------*/
 
   static  L_NUMBER a2[MAXLGTH];
   static  L_NUMBER a3[MAXLGTH];
   static  L_NUMBER a4[MAXLGTH];
   static  L_NUMBER a5[MAXLGTH];
   static  L_NUMBER a6[MAXLGTH];
   static  L_NUMBER a7[MAXLGTH];
   static  L_NUMBER a8[MAXLGTH];
   static  L_NUMBER a9[MAXLGTH];
   static  L_NUMBER a10[MAXLGTH];
   static  L_NUMBER a11[MAXLGTH];
   static  L_NUMBER a12[MAXLGTH];
   static  L_NUMBER a13[MAXLGTH];
   static  L_NUMBER a14[MAXLGTH];
   static  L_NUMBER a15[MAXLGTH];
 
   unsigned int *plist[16];

   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*  Zeigerliste initialisieren                              */
   /*----------------------------------------------------------*/
 
   plist[2] = a2;
   plist[3] = a3;
   plist[4] = a4;
   plist[5] = a5;
   plist[6] = a6;
   plist[7] = a7;
   plist[8] = a8;
   plist[9] = a9;
   plist[10] = a10;
   plist[11] = a11;
   plist[12] = a12;
   plist[13] = a13;
   plist[14] = a14;
   plist[15] = a15;
 
   /*----------------------------------------------------------*/
   /*  Beginn der Exponentiation                               */
   /*----------------------------------------------------------*/
 
    if (comp(exp,lz_null) == 0)
             {
             trans (lz_eins,erg);
             }
        else
             {
             mmult(bas,bas,a2,modul);
             for (i=3; i<=15; i++)
                   {
                   mmult(bas,plist[i-1],plist[i],modul);
                   }
             trans (lz_eins,acc);
             
#define START              (WLNG-4)
             /*------------------------------------------------*/
             /*  Schleife ueber die Zahl der Worte des         */
             /*  Exponenten                                    */
             /*------------------------------------------------*/
 
             for(i=lngofln(exp); i>0; i--)
                  {
                  /*-------------------------------------------*/
                  /*  Schleife ueber die Zahl der Nibble in    */
                  /*  einem Wort                               */
                  /*-------------------------------------------*/
                  for (j=START; j>=0; j=j-4)
                         {
                         k = (exp[i] >> j) & 017;
                         for (l=1; l<=4; l++)
                                {
                                mmult(acc,acc,acc,modul);
                                }
                         if (k != 0)
                                {
                                if (k == 1)
                                      {
                                      mmult(acc,bas,acc,modul);
                                      }
                                 else
                                      {
                                      mmult(acc,plist[k],acc,modul);
                                      }
                                 }
                         } /* end innere Schleife     */
                  } /* end aeussere Schleife      */
 
 
             /*------------------------------------------------*/
             /*  Ergebnis uebertragen                          */
             /*------------------------------------------------*/
             trans(acc,erg);
             } /* end else                                     */

	return(0);
 }  /* end mexp                                                */
 
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E   mexp                      */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC mexp2                          VERSION 1.0     +-----*/
/*                                          DATE 13.10.87      */
/*                                            BY Wolfgang Bott */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Moduloexponentiation zur Basis 2.            */
/*                Akzeptiert beliebig lange Zahlen als Eingabe */
/*                Das Ergebnis ist garantiert zwischen         */
/*                '0' und 'modul - 1'.                         */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     exp                Exponent als lange Zahl              */
/*     modul              Modul bez. dem gerechnet wird        */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     erg                Ergebnis der Rechnung als lange Zahl */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     mmult            Modulo - Multiplikation                */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     div              Division                               */
/*     trans            Uebertragen                            */
/*     shift            Shiften einer Zahl um n Bit            */
/*                                                             */
/*-------------------------------------------------------------*/

static	void
wshift(expword,erg,modul,first)
L_NUMBER	expword;
L_NUMBER	erg[];		/* assumes double L_NUMBER for shifting */
L_NUMBER	modul[];
int		first;		/* if first word		*/
{
	unsigned int	x, i, j;

	for ( i=0 ; i<WBYTES ; i++)
	{
		x = ( expword & HSBYTE ) >> (WLNG-BYTEL); /* should be unsigned */
		expword <<= BYTEL;
		if (!first || (x>0)){
			if(!first)	/* erg = LZ_EINS */
			   for (j=1; j<=BYTEL; j++)  mmult (erg,erg,erg,modul);
			shift (erg,x,erg);
			div(erg,modul,erg,erg);
			first = 0;/* FALSE */
		}
	}
	return;		
}

void
mexp2(exp,erg,modul)
L_NUMBER exp[];
L_NUMBER erg[];
L_NUMBER modul[];
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   L_NUMBER acc[2*MAXLGTH];                   /* Akkumulator        */
   int x,i,j;                            /* Schleifenvariablen */
	int	first;			/* designator for first word */
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   inttoln(1,acc);
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   if (exp[0] == 0)
        {
        trans(acc,erg);
        return;
        }
   first = 1; /* TRUE */
   for( i = lngofln(exp); i>0; i-- ){
	wshift ( exp[i], acc, modul, first);
	first = 0; /* FALSE */
	}

   trans(acc,erg);
   return;
 }
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  mexp2                      */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------------*/
/* E N D   O F   P A C K A G E      modarit                    */
/*-------------------------------------------------------------*/
