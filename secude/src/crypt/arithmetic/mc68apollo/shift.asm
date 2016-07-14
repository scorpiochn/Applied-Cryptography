********************************************************************
* Copyright (C) 1991, GMD. All rights reserved.                    *
*                                                                  *
*                                                                  *
*                         NOTICE                                   *
*                                                                  *
*    Acquisition, use, and distribution of this module             *
*    and related materials are subject to restrictions             *
*    mentioned in each volume of the documentation.                *
*                                                                  *
********************************************************************

* Datei : shift.s
* Datum : 25.5.1988
* Inhalt: Links- bzw. Rechtsshift einer langen Zahl
*
* a1 : Adresse des Operanden (OP)
* a2 : Shiftfaktor
* a3 : Adresse des Ergebnisses
* d1 : Laenge des Operanden (OP), Schleifenzaehler 
* d2 : Anzahl der zu schiebenden Langworte
* d3 : Anzahl der zu schiebenden Bits
* d4 : 32 Minus Anzahl der zu schiebenden Bits
* d5 : Hilfsregister
* d6 : Hilfsregister
* d7 : Hilfsregister
*

*        .text

	  MODULE   _shift
	  cpu      68020
	  entry.p  _shift

null:     dc.l    0,0,0,0,0,0,0,0,0,0,0,0,0 * 13 Langworte 0 zum Loeschen

	  PROC

_shift:     movem.l   a1/a2/a3/d1/d2/d3/d4/d5/d6/d7,-(sp)  * Reg. retten
           movem.l  null,a1/a2/a3/d1/d2/d3/d4/d5/d6/d7   * loeschen
*
* Adressen in Register laden
*
          movem.l  44(sp),a1/a2/a3    * a1 = Adresse von OP1
*                                     * a2 = Adresse Schiebefaktor
*                                     * a3 = Adresse des Ergebnisses
*
* Sonderfaelle : Operand = 0 oder Schiebefaktor = 0
*
          move.l    0(a1),d1           * d1 = L(OP)
          cmp.l    #0,d1               * OP = 0 ?
          beq     zero                * ja => Sprung zu zero
          move.l    a2,d2               * d2 = Schiebefaktor
          cmp.l    #0,d2               * Schiebefaktor <0,>0,=0 ?
          bgt     leftshift           * > 0 => Sprung zu leftshift
          blt     rightshift          * < 0 => Sprung zu rightshift
*
* Schiebefaktor = 0, d.h. kein Schift, d.h. Operand = Ergebnis
*
loop:     move.l    (a1)+,(a3)+           * uebertragen, a1,a3 eine Ziffer
*                                     * weiter
          dbra    d1,loop             * fertig ? nein => Schleife
          bra     return              * ja => Ruecksprung
*
* Fall, dass Operand = 0
*
zero:     move.l    #0,0(a3)           * Laenge des Ergebnisses = 0
          bra     return              * Ruecksprung
*
* negativer Schiebefaktor, d.h. Rechtsshift
*
rightshift:
          neg.l    d2                  * d2 = *d2|
          move.l    d2,d3               * Schiebefaktor merken
          lsr.l    #5,d2               * d2=Faktor:32=Anzahl der zu
*                                     * schiebenden Langworte
          cmp.l    d1,d2               * wird um mehr als Operanden-
*                                     * laenge geschoben ?
          bhi     zero                * ja => Ergebnis = 0
          move.l    d2,d5               * a1 auf erste zu bearbeitende
          mulu.l   #4,d5               * Ziffer ausrichten
          add.l    d5,a1               
          sub.l    d2,d1               * d1 = Zahl der zu bearbeitenden
*                                     * Ziffern
          move.l    d1,(a3)+             * Laenge vor.laeufig eintragen,
*                                     * a3 -> 1. Ziffer
          and.l    #31,d3              * d3 = Anzahl der zu schieben-
*                                     * den Bits = Shiftfaktor mod 32
          cmp.l    #0,d3               * Shift nur in Langworten ?
          bne     bitshift1           * nein => Sprung zu bitshift1
*
* Shiftfaktor ein Vielfaches von 32, Verschieben nur der Langworte
*
          addq.l   #4,a1               * a1 -> 1. Ziffer des Operanden
          subq.l   #1,d1               * Schleifenende bei -1
loop_sh1: move.l    (a1)+,(a3)+           * Uebertragen, a1,a3 eine Ziffer
*                                     * weiter
          dbra    d1,loop_sh1         * fertig ? nein => Schleife
          bra     return              * Ruecksprung
*
* Richtiger Rechtsshift ueber Langwortgrenzen
* d1 = Schleifenzaehler, d3 = Anzahl der zu schiebenden Bits
*
bitshift1:move.l    #32,d4              * d4 = 32 - Anzahld der zu
          sub.l    d3,d4               * schiebenden Bits
          addq.l   #4,a1               * a1-> 1. zu bearbeitende Zi
          subq.l   #1,d1               * Schleifenende bei -1
loop_shr: cmp.l    #0,d1               * hoechstwertige Zi. erreicht ?
          beq     chk_lead            * ja => Sonderbehand.lung 
          move.l    4(a1),d7           * d7 = hoeherwertige Ziffer
          move.l    (a1)+,d6             * d6 = niederwertige Ziffer
          lsr.l    d3,d6               * Rechtsshift der niederwertigen
          lsl.l    d4,d7               * Linksshift der hoeherwertigen
          or.l     d6,d7               * zusammenbasteln
          move.l    d7,(a3)+             * uebertragen, a3 -> naechste Zi
          dbra    d1,loop_shr         * d1=d1-1, Schleife
*
chk_lead: move.l    0(a1),d6           * d0 = fuehrende Ziffer
          lsr.l    d3,d6               * Rechtsshift
          move.l    d6,0(a3)           * neue fuehrende Ziffer eintra-
*                                     * gen
*
          cmp.l    #0,d6               * Shiftergebnis = 0 ?
          beq     no_lead             * ja => weiter bei no_lead
          bra     return              * Ruecksprung
*
no_lead:  move.l    52(sp),a3          * Anfangsadresse Ergebnis zu-
*                                     * rueckholen
          subq.l   #1,0(a3)           * Laenge Ergebnis um 1 vermin-
*                                     * dern
          bra     return              * Ruecksprung
*
*
* Positiver Schiebefaktor, Leftshift
*
leftshift:
          move.l     d2,d3              * Schiebefaktor merken
          lsr.l     #5,d2              * d2 = Anzahl der zu schieben-
*                                     * den Langworte
          move.l     d2,-(sp)            * auf Stack merken
          move.l     #4,d5             
          mulu.l    d1,d5              * d5=Laenge(Operand) in Byte
          add.l     d5,a1
          addq.l    #4,a1              * a1->vor fuehrende Zi Operand
          add.l     d1,d2              * d2 = vor.laeufige Laenge Ergb.
          move.l     d2,(a3)+            * vor.laeufige Laenge eintragen,
*                                     * a3->1. Zi Ergebnis
          move.l     #4,d5              * d5=Laenge(Ergebnis) in Byte
          mulu.l    d2,d5              * d5=vor.laeufige Laenge Ergebnis
          add.l     d5,a3              *a3->vor fuehrende Zi Ergebnis       
*
          and.l     #31,d3             * d3=Anzahl der zu schieb. Bits
          cmp.l     #0,d3              * nur Langworte schieben ?
          bne      bitshift2          * nein => weiter bei bitshift2
*
* Shiftfaktor Vielfaches von 32, d.h. nur Langworte schieben
*
	  subq.l    #1,d1              * d1 Schleifenzaehler
loopsh2:  move.l     -(a1),-(a3)          * schieben
          dbra     d1,loopsh2         * fertig ? nein => Schleife
	  bra      zerofll2           * jetzt noch nullen eintragen
*
bitshift2:move.l     #32,d4
          sub.l     d3,d4              * d4 = 32-Anzahl der Schiebebits
          move.l     -(a1),d6            * d6=fuehrende Zi Operand
          lsr.l     d4,d6              * schieben
          cmp.l     #0,d6              * alles weggeschoben ?
          beq      comp
          move.l     d6,0(a3)          * nein => eintragen und Laenge
          neg.l     d5                 * fuer Pointer auf L-Feld Ergeb.
	  addq.l    #1,-4(a3,d5.l)     * L-Ergebnis eins hoeher
comp:     cmp.l     #1,d1              * schon fertig?
          beq      zerofill           
          subq.l    #2,d1              * es werden L(OP)-2 Stellen
*                                     * in der Schleife bearbeitet.
loop_shl: move.l     0(a1),d6          * d6 hoeherwertige Ziffer
          move.l     -(a1),d7            * d7 niederwertige Ziffer
          lsl.l     d3,d6
          lsr.l     d4,d7
          or.l      d6,d7
          move.l     d7,-(a3)
          dbra     d1,loop_shl
zerofill: move.l     0(a1),d6          * d6 = niederwertigste Ziffer
          lsl.l     d3,d6              * schieben
          move.l     d6,-(a3)            * eintragen
zerofll2: move.l     (sp)+,d7            * d7 = Anzahl zu schiebender
*                                      * Langworte
          cmp.l     #0,d7              * = 0?
          beq      return
          subq.l    #1,d7
loop_zero:move.l     #0,-(a3)
          dbra     d7,loop_zero


return:   movem.l   (sp)+,a1/a2/a3/d1/d2/d3/d4/d5/d6/d7 * Reg. zurueck
        
	  rts                         * Ruecksprung
	  END














