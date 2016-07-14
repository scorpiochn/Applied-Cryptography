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
/*   PACKAGE random                      VERSION 1.0           */
/*                                          DATE 09.03.88      */
/*                                            BY Wolfgang Bott */
/*                                                             */
/*                                                             */
/*   DESCRIPTION Programme zum erzeugen und verwalten der      */
/*               Zufallszahlen.                                */
/*                                                             */
/*   EXPORT          DESCRIPTION                               */
/*      start ()        Erzeugt einen Startwert.               */
/*                                                             */
/*   USES                                                      */
/*      rndm()          Erzeugt eine Zufallszahl gewaenschter  */
/*                      Laenge.                                */
/*      lngtouse()        Laenge einer Zahl in BIT             */
/*                                                             */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Dateien                                           */
/*-------------------------------------------------------------*/

#include "arithmetic.h"
#include "../rsa/rsa.h"
#include "../rsa/rsa_debug.h"

extern  L_NUMBER lz_eins[];

/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC start                          VERSION 1.0     +-----*/
/*                                          DATE 10.09.87      */
/*                                            BY Bott W.       */
/*                                                             */
/*                                                             */
/*   DESCRIPTION  Erzeugt einen Startwert fuer den Zufalls-    */
/*                zahlengenerator.                             */
/*                Der Startwert mua eine maximale Periode      */
/*                haben, und darf auaerdem kein vielfaches     */
/*                von p oder q sein.                           */
/*                                                             */
/*   IN              DESCRIPTION                               */
/*      per             Periodenlaenge, die aufgrund der       */
/*                      Kostruktion des Moduls auftreten kann. */
/*                      Wenn diese ueberschritten wird, so ist */
/*                      eine max. Periode sichergestellt.      */
/*      mod             Modul, bez. dem der Zufallszahlen-     */
/*                      generator arbeitet.                    */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*      wert            Startwert fuer den Zufallszahlen-      */
/*                      generator.                             */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus random.c                                       */
/*     rndm             Erzeugt eine Zufallszahl gewuenschter  */
/*                      Laenge.                                */
/*                                                             */
/*   Module aus lnumber.c                                      */
/*     comp             Vergleich zweier 'Langer Zahlen'       */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     mexp             Modulo - Exponentiation                */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     div              Division                               */
/*     trans            Uebertragen                            */
/*                                                             */
/*-------------------------------------------------------------*/

start (wert,per,mod)
L_NUMBER wert[];
L_NUMBER per[];
L_NUMBER mod[];
{
    L_NUMBER op1[MAXGENL];
    L_NUMBER op2[MAXGENL];
    L_NUMBER op3[MAXGENL];
    int ende = 0;

    for( ; !ende; )
        {
       ende = 1;/* TRUE */
       rndm( mod[0] << SWBITS, wert);

       /*--- Ueberpruefe, ob die Periode lang genug ist. --------*/
       mexp(wert,per,op1,mod);

       if (comp(op1,lz_eins) == 0)      ende = 0;/* FALSE */

       /*------------------------------------------------------*/
       /* Bestimme den GGT won 'mod' und 'wert'                */
       /*------------------------------------------------------*/

       trans(mod,op2);
       trans(wert,op3);
       if (comp(op2,op3) < 0)
          {
          trans (op2,op1);
          trans (op3,op2);
          trans (op1,op3);
          };

       do {
          trans (op2,op1);
          trans (op3,op2);
          div (op1,op2,op3,op3);
          }
          while (op3[0] != 0);

       /*-- Wenn der GGT != 1 ist, dann ist wert ein    -------*/
       /*-- Vielfaches von p oder von q.                -------*/

       if (comp(op2,lz_eins))   ende = 0; /* FALSE */
       }

	return(0);
   }

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E   START                     */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC rndm                           VERSION 1.0     +-----*/
/*                                          DATE 13.10.87      */
/*                                            BY Wolfgang Bott */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Erzeugt eine ungerade Zufallszahl mit einer  */
/*                mindestlaenge von 'lgth' Bit. 'lgth' muss    */
/*                kleiner als PINMOD, wie in include/defrsa.h  */
/*                definiert, sein.                             */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     lgth               Mindestlaenge der zu erzeugenden     */
/*                        Zufallszahl.                         */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*                                                             */
/*                                                             */
/*   OUT                                                       */
/*     zahl               Die erzeugte Zufallszahl als         */
/*                        lange Zahl                           */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus lnumber.c                                      */
/*     lngtouse           Laenge einer Zahl in BIT             */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     mexp             Modulo - Exponentiation                */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     sub              Subtraktion                            */
/*     shift            Shiften einer Zahl um n Bit            */
/*                                                             */
/*-------------------------------------------------------------*/

#ifdef WLNG32
L_NUMBER seed[MAXLGTH] = {0x10,0x12345678,0x9abcdef0,  /*seed */
                          0x56789abc,0xdef01234,  /* Vor */
                          0x9abcdef0,0x12345678,  /* bele*/
                          0xdef01234,0x56789abc,  /* gen */
                          0x12345678,0x9abcdef0,
                          0x56789abc,0xdef01234,
                          0x9abcdef0,0x12345678,
                          0xdef01234,0x56789abc};
#else
L_NUMBER seed[MAXLGTH] = {0x20,0x1234,0x5678,0x9abc,0xdef0,  /*seed */
                          0x5678,0x9abc,0xdef0,0x1234,  /* Vor */
                          0x9abc,0xdef0,0x1234,0x5678,  /* bele*/
                          0xdef0,0x1234,0x5678,0x9abc,  /* gen */
                          0x1234,0x5678,0x9abc,0xdef0,
                          0x5678,0x9abc,0xdef0,0x1234,
                          0x9abc,0xdef0,0x1234,0x5678,
                          0xdef0,0x1234,0x5678,0x9abc};

#endif


rndm(lgth,zahl)

 int lgth;
 L_NUMBER zahl[];

{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   L_NUMBER mersenne[MAXLGTH];
               /*  Der Modul bezueglich der 'seed' potenziert  */
               /*  wird; stets eine Mersennesche Primzahl,     */
               /*  deren groesse in ?defrsa.h festgelegt ist   */
   extern L_NUMBER lz_eins[];
   static L_NUMBER exp[2] = { 1, 11};
   L_NUMBER zeit[4];
   int i;
   char c;
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   Shift(lz_eins,MAXRNDM,mersenne);
   sub(mersenne,lz_eins,mersenne);
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*  Zeit abfragen und in eine lange Zahl verwandeln         */
   /*----------------------------------------------------------*/
   time(zeit+1);
   zeit[0] = 1;
   zeit[1] = zeit[1] | HSBIT;
   /*----------------------------------------------------------*/
   /*  Einen Startwert erzeugen, auf die gewuenschte Laenge    */
   /*  bringen und ungerade machen.                            */
   /*----------------------------------------------------------*/
   mexp(seed,zeit,seed,mersenne);
   while(lngtouse(seed) <= MAXRNDM - 4)
        {
        mexp(seed,exp,seed,mersenne);
        }

   ShiftSeed(seed,lgth - lngtouse(seed),zahl);
   zahl[1] = zahl[1] | 0x1;

   return(0);
 }
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E   rndm                      */
/*-------------------------------------------------------------*/
