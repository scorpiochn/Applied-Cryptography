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
/*   PACKAGE genprime                    VERSION 1.0           */
/*                                          DATE 09.03.88      */
/*                                            BY Wolfgang Bott */
/*                                                             */
/*                                                             */
/*   DESCRIPTION Generate prime numbers                        */
/*               bestimmten Eigenschaften                      */
/*                                                             */
/*   EXPORT          DESCRIPTION                               */
/*      genrsa()        Erzeugen von zwei Primzahlen p u. q    */
/*                      wie sie fuer den RSA benoetigt werden  */
/*      primzahl()      Suche Primzahl. Die 2 hat modulo dieser*/
/*                      Zahl eine maximale Periode             */
/*      nextprime()     Sucht die naechste Primzahl ab einem   */
/*                      vorgegebenen Startwert                 */
/*      optimize()      Wird zur optimierung von nextprime     */
/*                      verwendet                              */
/*      rabinstest()    Rabinsher Primalitaetstest             */
/*                                                             */
/*   USES                                                      */
/*      comp()          Vergleicht zwei lange Zahlen.          */
/*                                                             */
/*   INTERNAL                                                  */
/*      mexp2()         Moduloexponentiation (2 ** zahl)       */
/*                                                             */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-files                                             */
/*-------------------------------------------------------------*/

#include <math.h>

#ifndef MAC
#include <sys/types.h>
#endif /* MAC */

#include "arithmetic.h"

#include "../rsa/rsa.h"
#include "../rsa/rsa_debug.h"

static  double betrag();       		/* Betragsfunktion                   */
int     RSAgenCountDown;              /* counter for prime gen */

/*-------------------------------------------------------------*/
/*   extern-Deklarationen                                      */
/*-------------------------------------------------------------*/
extern int primes[];    /* Die ersten 1000 Primzahlen          */
extern L_NUMBER lz_eins[];
extern L_NUMBER lz_zwei[];
extern L_NUMBER lz_fermat5[];

/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC genrsa                         VERSION 1.0     +-----*/
/*                                          DATE 14.10.87      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION Erzeugt zwei Primzahlen p und q, deren        */
/*               Produkt groesser als 2 ** 'laenge-1' ist und  */
/*               kleiner 2 ** 'laenge'.                        */
/*                                                             */
/*   IN              DESCRIPTION                               */
/*      laenge          Geforderte Mindestlaenge fuer p * q    */
/*      zufall          Zeiger auf die Werte des Zufalls-      */
/*                      zahlengenerators                       */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     schlusr            Zeiger auf die Schluesselinfor-      */
/*                        mationen.                            */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus genprime.c                                     */
/*     nextprime        Sucht die naechste Primzahl ab einem    */
/*                      vorgegebenen Startwert                 */
/*                                                             */
/*   Module aus monitor.c                                      */
/*     message          Ausgeben einer Nachricht               */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     msub             Modulo - Subtraktion                   */
/*     mmult            Modulo - Multiplikation                */
/*     mdiv             Modulo - Division                      */
/*     mexp             Modulo - Exponentiation (x^y)          */
/*     mexp2            Modulo - Exponentiation (x^2^y)        */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     add              Addition                               */
/*     div              Division                               */
/*     mult             Multiplikation                         */
/*     sub              Subtraktion                            */
/*     trans            Uebertragen                            */
/*     shift            Shiften einer Zahl um n Bit            */
/*                                                             */
/*   RETURN                                                    */
/*      != 0 --> Generierung war nicht erfolgreich und mua     */
/*               deshalb wiederholt werden.                    */
/*      == 0 --> Generierung erfolgreich, Schluessel stehen     */
/*               bereit.                                       */
/*                                                             */
/*-------------------------------------------------------------*/
#ifdef WLNG32
int  test[4] = {0x02,0x12345678,0x00009abc};
#else
int  test[4] = {0x06,0x1234,0x5678,0x9abc};
#endif


genrsa(schlusr,laenge,zufall)
Skeys     *schlusr;
int       laenge;
rndmstart *zufall;
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*   Variablen - Definitionen                               */
   /*----------------------------------------------------------*/
   L_NUMBER  modul     [MAXGENL];       /* Modul als 'LZ'           */
   L_NUMBER  pstrich   [MAXGENL];       /* Teiler von p - 1         */
   L_NUMBER  qstrich   [MAXGENL];       /* Teiler von q - 1         */
   L_NUMBER  acc1      [MAXGENL];       /* 1. Arbeitsfeld           */
   L_NUMBER  acc2      [MAXGENL];       /* 2. Arbeitsfeld           */
   int  flag,diff,j;
   int  cnt;

   if (laenge<MINKEYL)      return -1;
   diff = laenge/2 - 2*intlog2(laenge) + 1;
   /*----------------------------------------------------------*/
   /*  Nach q'' suchen                                         */
   /*----------------------------------------------------------*/
   PrintSTART("\n    Generating Q ...    ",3);
   PrintGenRSA("GENERATE RSA: (q'')\n");
   Shift(zufall->q,diff - lngtouse(zufall->q),qstrich);
   qstrich[1] |= 0x01;
   nextprime(qstrich,0,0);
   /*-----------------------------------------------------*/
   /*  Nach q' suchen                                     */
   /*-----------------------------------------------------*/
   PrintGenRSA("GENERATE RSA: (q')\n");
   trans(lz_zwei,acc2);
   nextprime(qstrich,acc2,1);
   mult(acc2,qstrich,qstrich);
   add(qstrich,lz_eins,qstrich);
   /*-----------------------------------------------------*/
   /*  Nach q  suchen                                     */
   /*-----------------------------------------------------*/
   PrintGenRSA("GENERATE RSA: (q)\n");
   trans(lz_zwei,acc2);
   nextprime(qstrich,acc2,1);
   mult(acc2,qstrich,acc2);
   add(acc2,lz_eins,schlusr->q);
        PrintL_NUMBER(acc2,"Q");
   /*-----------------------------------------------------*/
   /*  Nach p'' suchen                                    */
   /*-----------------------------------------------------*/
   PrintSTART("\n    Generating P ...    ",3);
   PrintGenRSA("GENERATE RSA: (p'')\n");
   Shift(zufall->p,diff - lngtouse(zufall->p),pstrich);
   pstrich[1] |= 0x01;
        PrintL_NUMBER(pstrich,"P' vor nextprime()");
   nextprime(pstrich,0,0);
   /*-----------------------------------------------------*/
   /*  Nach p' suchen                                     */
   /*-----------------------------------------------------*/
   PrintGenRSA("GENERATE RSA: (p')\n");
   trans(lz_zwei,acc2);
        PrintL_NUMBER(pstrich,"P' vor nextprime()");
   nextprime(pstrich,acc2,1);
   mult(acc2,pstrich,acc2);
   add(acc2,lz_eins,pstrich);
   /*-----------------------------------------------------*/
   /*  Nach Primzahl p suchen                             */
   /*-----------------------------------------------------*/
   PrintGenRSA("GENERATE RSA: (p)\n");
   mult(pstrich,schlusr->q,acc1);
   Shift(lz_eins,laenge-1,acc2);
   div(acc2,acc1,acc2,acc1);
   add(acc2,lz_zwei,acc2);
   acc2[1] &= ~1L;
   flag = 0;

   while (flag == 0)
           {
        PrintL_NUMBER(acc2,"Faktor vor nextprime()");
           nextprime(pstrich,acc2,1);
           div(acc2,lz_fermat5,acc1,acc1);
           if (acc1[0] != 0) flag = 1;
           }

        PrintL_NUMBER(acc2,"Faktor fuer P");
   PrintNote("\n    Testing P * Q ... ");
   mult(pstrich,acc2,schlusr->p);
   add(schlusr->p,lz_eins,schlusr->p);
   mult(schlusr->p,schlusr->q,modul);
   if(lngtouse(modul) >= laenge) {  /* sorry, some weakness */
        PrintNote(" Sorry: again.\n");
        return -1;
   }

   flag = 1;    /* NOTE: this should be inited to NOT EQUAL ! (s.b.) */
   sub(schlusr->p,lz_eins,pstrich);
   sub(schlusr->q,lz_eins,qstrich);
   /*-----------------------------------------------------*/
   /* Kontrolliere ob das Schluesselpaar korrekt ist       */
   /*-----------------------------------------------------*/
   if ((mdiv(lz_eins,lz_fermat5,schlusr->sp,pstrich) == 0) &&
       (mdiv(lz_eins,lz_fermat5,schlusr->sq,qstrich) == 0) &&
       (mdiv(lz_eins,schlusr->q,schlusr->u,schlusr->p) == 0))
           {
           /*---------------------------------------------*/
           /* Verschluesseln des Teststrings. Anschliesend */
           /* wieder entschluesseln. Vergleichen ob der    */
           /* Originaltext wieder erscheint.              */
           /*---------------------------------------------*/
           mult (schlusr->p,schlusr->q,modul);
           mmult (test,test,acc2,modul);
           for (j=2; j <= 16; j++)
               {
               mmult (acc2,acc2,acc2,modul);
               }
           mmult (acc2,test,acc2,modul);
           div   (acc2,schlusr->q,qstrich,qstrich);
           div   (acc2,schlusr->p,pstrich,pstrich);
           mexp  (qstrich,schlusr->sq,qstrich,schlusr->q);
           mexp  (pstrich,schlusr->sp,pstrich,schlusr->p);
           /*--------------------------------------------*/
           /* Berechnen des Textes mit hilfe des         */
           /* chin. Restesatzes.                         */
           /*--------------------------------------------*/
           msub  (pstrich,qstrich,pstrich,schlusr->p);
           mmult (pstrich,schlusr->u,pstrich,schlusr->p);
           mult  (pstrich,schlusr->q,pstrich);
           add   (pstrich,qstrich,pstrich);
           flag = comp (pstrich,test);
           }
   if(flag) {  /* encrypt/decrypt error */
        PrintNote(" Sorry: again.\n");
   }else PrintNote("O.K.\n");
 return (flag);
 } /* end genrsa     */
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E   genrsa                    */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC  primzahl                      VERSION 1.0     +-----*/
/*                                          DATE 04.09.87      */
/*                                            BY Bott W.       */
/*                                                             */
/*                                                             */
/*   DESCRIPTION  Sucht eine Primzahl mit einer Mindestlaenge   */
/*                von 'length' bit und der Zusatzbedingung,    */
/*                daa die 2 eine maximale Periode hat.         */
/*                Auaerdem erfaellt diese Primzahl alle an-     */
/*                forderungen an eine RSA-Primzahl.            */
/*                                                             */
/*   IN              DESCRIPTION                               */
/*      length          Mindestlaenge der gesuchten Primzahl    */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*      primzahl        gesuchte Primzahl als `LZ'             */
/*      fakt            Faktor fuer Periodentest als 'LZ'       */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus genprime.c                                     */
/*     nextprime        Sucht die naechste Primzahl ab einem    */
/*                      vorgegebenen Startwert                 */
/*                                                             */
/*   Module aus monitor.c                                      */
/*     message          Ausgeben einer Nachricht               */
/*                                                             */
/*   Module aus random.c                                       */
/*     rndm             Erzeugt eine Zufallszahl gewuenschter   */
/*                      Laenge.                                 */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     mexp             Modulo - Exponentiation                */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     add              Addition                               */
/*     mult             Multiplikation                         */
/*     trans            Uebertragen                            */
/*                                                             */
/*-------------------------------------------------------------*/
primzahl (primzahl,fakt,length)
L_NUMBER primzahl [];
L_NUMBER fakt     [];
int length;
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*   Variablen-definitionen                                 */
   /*----------------------------------------------------------*/
   L_NUMBER pstrich [MAXGENL];           /* zwischenergebnis      */
   L_NUMBER test    [MAXGENL];           /* zwischenspeicher fuer */
                                      /* Testgroesse           */
   int i;                             /* Schleifenzhler       */
   /*----------------------------------------------------------*/
   /*   Vorbelegen der Variablen                               */
   /*----------------------------------------------------------*/

          /*---------------------------------------------------*/
          /* Suche pstrich mit folgenden Bedingungen:          */
          /* pstrich ist mindestens 240 Bit lang               */
          /* Die zwei hat mod pstrich eine Maximale Periode    */
          /*---------------------------------------------------*/
   do     {
          Random(length -16,pstrich);
          pstrich[1] |= 1;
          nextprime(pstrich,fakt,0);
          trans(lz_zwei,fakt);
          nextprime(pstrich,fakt,1);
          mult(pstrich,fakt,pstrich);
          add(pstrich,lz_eins,pstrich);
          mexp(lz_zwei,fakt,test,pstrich);
          }
   while ( !comp(test,lz_eins) );
          /*---------------------------------------------------*/
          /* Suche mit folgenden Bedingungen:                  */
          /* primzahl = fakt * pstrich.                        */
          /* Ausserdem ist 'primzahl' eine Primzahl.           */
          /*---------------------------------------------------*/
   trans(lz_zwei,fakt);
   nextprime(pstrich,fakt,1);
   mult(pstrich,fakt,pstrich);
   add(pstrich,lz_eins,primzahl);

   return(0);
}
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      primzahl               */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC nextprime                      VERSION 1.0     +-----*/
/*                                          DATE 14.10.87      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Primalitaetstest.                            */
/*                Es gibt zwei Versionen:                      */
/*                                                             */
/*  'version' = 0 : 'start' ist ungerade und die naechste      */
/*                  Primzahl nach 'start' wird gesucht.        */
/*                  Die Primzahl wird in Feld 'start'          */
/*                  zurueckgegeben.                            */
/*  'version' = 1 : 'start' ist ungerade, 'factor' ist gerade. */
/*                  Es wird die kleinste Primzahl der Form     */
/*                  '(factor + sum) * start + 1' gesucht. Der  */
/*                  Wert 'factor + sum' wird in Feld 'factor'  */
/*                  zurueckgegeben. 'start' wird nicht         */
/*                  veraendert.                                */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     factor             Siehe Procedurbeschreibung           */
/*     version            Siehe Procedurbeschreibung           */
/*                                                             */
/*   INOUT                                                     */
/*     start              Siehe Procedurbeschreibung           */
/*                                                             */
/*   OUT                                                       */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus genprime.c                                     */
/*     optimize         Wird zur optimierung von nextprime     */
/*                      verwendet                              */
/*     rabinstest       Rabinsher Primalitaetstest              */
/*                                                             */
/*   Module aus monitor.c                                      */
/*     message          Ausgeben einer Nachricht               */
/*                                                             */
/*   Module aus lnumber.c                                      */
/*     comp             Vergleich zweier 'Langer Zahlen'       */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     add              Addition                               */
/*     div              Division                               */
/*     mult             Multiplikation                         */
/*                                                             */
/*-------------------------------------------------------------*/
nextprime(start,factor,version)
L_NUMBER start[];             /* Muss eine ungerade Zahl sein       */
L_NUMBER factor[];            /* Muss eine gerade Zahl sein         */
int version;             /* Gibt die Arbeitsweise vor          */
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
 static L_NUMBER rem[1001];          /* Enthaelt die Reste von      */
                                /* 'start' mod p(i)            */
 static L_NUMBER remfac[1001];       /* Enthaelt die Reste von      */
                                /* 'factor' mod p(i)           */
        L_NUMBER dummy[MAXGENL];     /* Ein Arbeitsfeld             */
        L_NUMBER divisor[2];         /* Eine kleine Primzahl als LZ */
        L_NUMBER rest[2];            /* Der Rest der Division durch */
                                /* eine kleine Primzahl        */
        L_NUMBER sum;                /* Differenz zwischen 'start'  */
                                /* und der gefundenen Primzahl */
        int i,j;                /* Schleifenvariablen          */
        int m;                  /* Zahl der verwendeten        */
                                /* kleinen Primzahlen          */
        int dt,rt;              /* Zahl der Primzahltests:     */
                                /* dt <-> Divisionstests       */
                                /* rt <-> Rabinstests          */
        int schalter;
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/

   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   if ((version == 0) && (comp(lz_zwei,start) > 0))
        {
        inttoln(2,start);
        return(0);
        }
   m = optimize(start,version);
   /*----------------------------------------------------------*/
   /*  Reste von 'start' berechnen                             */
   /*----------------------------------------------------------*/
   if (version == 0)
        {
        divisor[0] = 1;
        for (i=0; i<=m; i++)
                {
                divisor[1] = primes[i];
                div(start,divisor,dummy,rest);
                if (rest[0] == 0)
                        {
                        rem[i] = 0;
                        }
                     else
                        {
                        rem[i] = primes[i] - rest[1];
                        }
                }
   /*----------------------------------------------------------*/
   /*  Eine Zahl finden, die durch die ersten m Primzahlen     */
   /*  nicht dividierbar ist                                   */
   /*----------------------------------------------------------*/
        dt = rt = 0;
        rt = -1;
        schalter = -1;
        sum = -2;
        PrintRabinstest;
        while (schalter == -1)
                {
                rt++;
                sum = sum + 2;
                i = 0;
                while (i <= m)
                        {
                        if (sum % primes[i] == rem[i])
                                {
                                i = 0;
                                sum = sum + 2;
                                dt++;
                                }
                             else
                                i++;
                         }
               /*----------------------------------------------*/
               /*  Jetzt Rabins Test anwenden                  */
               /*----------------------------------------------*/

                RabinsParm(rt,dt);

                inttoln(sum,divisor);
                add(start,divisor,dummy);
                schalter = rabinstest(dummy);
                }
        PrintRabinsCount(rt);
        add(divisor,start,start);
        }  /* Ende Version = 0   */
   /*----------------------------------------------------------*/
   /*  Version = 1 : Naechstes primes Vielfaches suchen        */
   /*----------------------------------------------------------*/
   else
        {
        if (factor[0] == 0)
                inttoln(2,factor);
        /*-----------------------------------------------------*/
        /*  Reste von 'start' und 'factor' berechnen           */
        /*-----------------------------------------------------*/
        divisor[0] = 1;
        for (i=0; i<=m; i++)
                {
                divisor[1] = primes[i];
                div(start,divisor,dummy,rest);
                if (rest[0] == 0)
                        rem[i] = 0;
                     else
                        rem[i] = rest[1];
                div(factor,divisor,dummy,rest);
                if (rest[0] == 0)
                        remfac[i] = 0;
                     else
                        remfac[i] = rest[1];
                 }
        /*-----------------------------------------------------*/
        /* Eine Zahl finden, die durch die ersten m Primzahlen */
        /* nicht dividierbar ist                               */
        /*-----------------------------------------------------*/
        dt = rt = 0;
        rt = -1;
        schalter = -1;
        sum = -2;
        PrintRabinstest;
        while (schalter == -1)
                {
                rt++;
                sum = sum + 2;
                i = 0;
                while (i <= m)
                        {
                    if ((((sum+remfac[i])*rem[i])+1) % primes[i] == 0)
                                {
                                i = 0;
                                sum = sum + 2;
                                dt++;
                                }
                             else
                                i++;
                        }
                /*---------------------------------------------*/
                /*  Jetzt Rabins Test anwenden                 */
                /*---------------------------------------------*/

                RabinsParm(rt,dt);

                inttoln(sum,divisor);
                add(factor,divisor,dummy);
                mult(dummy,start,dummy);
                add(dummy,lz_eins,dummy);
                schalter = rabinstest(dummy);
                }
        PrintRabinsCount(rt);
        add(divisor,factor,factor);
        }  /* Ende Version = 1    */

  	return(0);
}
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  nextprime                  */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC optimize                       VERSION 1.0     +-----*/
/*                                          DATE 14.10.87      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Optimiert die Zahl der kleinen Primzahlen,   */
/*                durch die im Primzahlsuchprogramm eine Zahl  */
/*                dividiert wird, bevor Rabins's Test ange-    */
/*                wandt wird.   'version' gibt an, in welcher  */
/*                Version 'nextprime' arbeiten wird.           */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     zahl               Startzahl fuer das Primzahlsuch-     */
/*                        programm                             */
/*     version            versions-nummer                      */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*     return - code liefert die Anzahl der zu verwendenden    */
/*     kleinen Primzahlen.                                     */
/*                                                             */
/*-------------------------------------------------------------*/
optimize(zahl,version)
L_NUMBER zahl[];
int version;
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   double ln2 = log(2.0); /* Der natuerliche Logarithmus von 2 */
   double euler = 4.0 / exp(-.577215);
                          /* Die Eulersche Konstante etwas     */
                          /* geaendert                         */
   double lnx;            /* Logarithmus von 'zahl'            */
   double rx;             /* Aufwand eines Rabinschen Testes   */
   double dx;             /* Aufwand einer Division durch eine */
                          /* kleine Primzahl                   */
   double t;              /* Aufwand eines Testes auf          */
                          /* Dividierbarkeit                   */
   double a,b;            /* Hilfsvariablen                    */
   double p_alt,p_neu;    /* Variable, die optimiert wird,     */
                          /* in doppelter Ausfuehrung          */
   double phi_p;          /* Wert der Funktion an der Stelle p */
   double phi_str_p;      /* Wert der Ableitung an der Stelle p*/
   int lead1,lead2;       /* Die zwei fuehrenden Ziffern von   */
                          /* 'zahl'                            */
   int i;                 /* Eine Schleifenvariable            */
   int korr;              /* Benoetigt zur Berechnung          */
                          /* von Log(x)                        */
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/
   /*  Fuer kleine Zahlen kommt ein zu grosser Wert bei der    */
   /*  Optimierung heraus. Er wird daher konstant              */
   /*  auf -1 gesetzt.                                         */
   /*----------------------------------------------------------*/
   if ((zahl[0] == 1) && (zahl[1] <= 100))
        return(-1);
   /*----------------------------------------------------------*/
   /*  Aufwand der einzelnen Programmschritte in Abhaengigkeit */
   /*  von der Laenge von 'zahl' bestimmen. Komplexitaetsmass  */
   /*  ist die Zahl der Multiplikationen + Zahl der Divisionen.*/
   /*  Aufwand eines Rabinschen Testes: 1 x mexp2              */
   /*  Aufwand von mexp2    : 16 * dx  x mmult  + 2 * dx x div */
   /*  Aufwand von mmult    : dx * dx + dx * (dx + 3)          */
   /*  Aufwand von div (Divident im Schnitt 2**128 mal         */
   /*  groesser als Divisor): 8 * (dx + 3)                     */
   /*                                                          */
   /*  Summa summarum: 32*dx*dx*dx + 64*dx*dx + 6*dx           */
   /*                                                          */
   /*----------------------------------------------------------*/
   if (version == 0)
        t = 1.0;
     else
        t = 2.0;
   dx = lngofln(zahl);
   rx = (((dx * 32.0) + 64.0) * dx + 6.0) * dx;
   /*----------------------------------------------------------*/
   /*  Natuerlicher Logarithmus von x berechnen. Dazu wird nur */
   /*  die hoechstwertigste Ziffer von x benutzt.              */
   /*----------------------------------------------------------*/
   i = lngofln(zahl);
   if (i == 1)
        {
        lead1 = zahl[i];
        if (lead1 < 0)
                {
                lead1 = (lead1 >> 1) & ~HSBIT;
                korr = 1;
                }
             else
                korr = 0;
        }
     else
        {
        korr = (lngofln(zahl) - 1) << SWBITS;
        lead1 = zahl[i];
        lead2 = zahl[i - 1];
        while (lead1 > 0)
                {
                lead1 <<= 1;
                if (lead2 < 0)
                        lead1++;
                lead2 <<= 1;
                korr--;
                }
        lead1 = (lead1 >> 1) & ~HSBIT;
        korr++;
        }
   a = lead1;
   lnx = log(a) + korr * ln2;
   /*----------------------------------------------------------*/
   /*  Newtonsches Iterationsverfahren zur Berechnung          */
   /*  der Nullstelle von phi(p).                              */
   /*----------------------------------------------------------*/
   p_alt = 100.0;
   p_neu = 200.0;
   while (betrag(p_alt - p_neu) > .01)
        {
        a = euler * dx / lnx;
        b = a * log(p_alt) + t;
        phi_p = p_alt - rx / b;
        phi_str_p = 1.0 + (a * rx) / (b * b * p_alt);
        a = p_neu;                  /*  Zwischenspeichern      */
        p_neu = p_alt - phi_p / phi_str_p;
        p_alt = a;
        }
   /*----------------------------------------------------------*/
   /*  Die zum optimalen p naechste Primzahl suchen.           */
   /*----------------------------------------------------------*/
   i = p_neu / log(p_neu);
   if (i > 1000)
        return(1000);
   korr = 1024;
   while (korr > 1)
        {
        if (p_neu - primes[i] > korr)
                i  += korr;
        if (i > 1000)
                i  -= korr;
             else
                {
                if (primes[i] - p_neu > korr)
                        i  -= korr;
                }
        korr >>= 1;
        }
   while ((primes[i] < p_neu) && (i < 1000))     i++;
   while (primes[i] > p_neu)                     i--;
   return(i);
 }
   /*----------------------------------------------------------*/
   /*  Betragsfunktion.                                        */
   /*  Liefert im Return-Code den Betrag von x                 */
   /*----------------------------------------------------------*/
static double betrag(x)
double x;
 {
   if (x<0)
        return(-x);
     else
        return(x);
 }
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  optimize                   */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------+-----*/
/*                                                       | gmd */
/*   PROC rabinstest                     VERSION 1.0     +-----*/
/*                                          DATE 14.10.87      */
/*                                            BY Bott Wolfgang */
/*                                                             */
/*                                                             */
/*   DESCRIPTION: Rabin's Primalitaetstest.                    */
/*                                                             */
/*   IN                 DESCRIPTION                            */
/*     zahl               Auf Primzahl zu testende Zahl        */
/*                                                             */
/*   INOUT                                                     */
/*                                                             */
/*   OUT                                                       */
/*                                                             */
/*   USES                                                      */
/*                                                             */
/*   Module aus lnumber.c                                      */
/*     comp             Vergleich zweier 'Langer Zahlen'       */
/*                                                             */
/*   Module aus modarit.c                                      */
/*     mmult            Modulo - Multiplikation                */
/*     mexp             Modulo - Exponentiation                */
/*                                                             */
/*   Assembler - Routinen:                                     */
/*     sub              Subtraktion                            */
/*     shift            Shiften einer Zahl um n Bit            */
/*                                                             */
/*   RETURNCODE:                                               */
/*       -1       'zahl' nicht prim                            */
/*       +1       'zahl' prim.                                 */
/*                                                             */
/*-------------------------------------------------------------*/
rabinstest(zahl)
L_NUMBER zahl[];
{
   /*----------------------------------------------------------*/
   /*   Deklarationen                                          */
   /*----------------------------------------------------------*/
   static L_NUMBER acc[MAXGENL];             /* Akkumulator         */
   static L_NUMBER exp[MAXGENL];             /* Exponent            */
   int i;                               /* Schleifenvariable   */
   /*----------------------------------------------------------*/
   /*   Definitionen                                           */
   /*----------------------------------------------------------*/

   /*----------------------------------------------------------*/
   /*   Statements                                             */
   /*----------------------------------------------------------*/
   /*  Groesste Zweierpotenz aus 'zahl - 1' herausziehen       */
   /*----------------------------------------------------------*/
   if (comp(zahl,lz_eins) <= 0)        return(-1);
   i = 1;
   Shift(zahl,-1,exp);
   while((exp[1] & 0x1) == 0)
        {
        Shift(exp,-1,exp);
        i++;
        }
   /*----------------------------------------------------------*/
   /*  Grundexponentiation                                     */
   /*----------------------------------------------------------*/
   mexp2(exp,acc,zahl);
   if (comp(acc,lz_eins) == 0)            return(1);
   /*----------------------------------------------------------*/
   /*  Restliche Multiplikationen                              */
   /*----------------------------------------------------------*/
   sub(zahl,lz_eins,exp);
   while (comp(acc,exp) != 0)
        {
        i--;
        if (i == 0)       return (-1);
        mmult(acc,acc,acc,zahl);
        }
   return(1);
 }
/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E  rabinstest                 */
/*-------------------------------------------------------------*/
