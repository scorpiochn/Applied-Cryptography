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

* Datei : sub.s
* Datum : 9.5.1988
* Inhalt: Subtrahieren zweier langer Zahlen
*
* a1 : Aktuelle Ziffer des ersten Operanden (OP1)
* a2 : Aktuelle Ziffer des zweiten Operanden (OP2)
* a3 : Aktuelle Ziffer ders Ergebnisses
* a4 : Adresse von OP1
* a5 : Adresse von OP2
* a6 : Adresse vom Ergebnis
* d0 : Returncode
* d1 : Differenz von Laenge des 1. Operanden (OP1)  und Laenge des 
*      zweiten Operanden (OP2) ,Schleifenzaehler fuer die Uebertra-
*      gungsschleife
* d2 : Laenge des kuerzeren Operanden, Schleifenzaehler fuer die
*      Subtraktionsschleife
* d3 : Hilfsregister zur Subtraktion
* d4 : Hilfsregister zur Subtraktion
*
*         .text

	  MODULE   _sub
	  cpu      68020
	  entry.p  _sub


null:     dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0
          dc.l    0


	  PROC

_sub:       movem.l  a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7,-(sp) * Register retten
	   movem.l  null,a1/a2/a3/a4/d0/d1/d2/d3/d4/d5/d6/d7 * Register loeschen
*
* Adressen in Register laden
*
	   movem.l  56(sp),a1/a2/a3     * Adressen laden
*
* Laenge von OP1 >= Laenge von OP2 ? ja => weiter 
*                                  nein => weiter bei 'negativ',
*                                          Fehlermeldung
*
           move.l    0(a2),d2           * d2 = L(OP2)
           cmp.l    0(a1),d2           * Vergleiche d2 mit L(OP1), dh.
*                                      * subtrahiere L(OP1) und setze
*                                      * CCR-Bits entsprechend
           bhi.l    negativ             * Falls Borrowbit, dann Carry=1,
*                                      * daher Sprung zu 'netativ',
*                                      * Fehlermeldung, dh. Fehlermel-
*                                      * dung bei L(OP2)>L(OP1)
*
* Bereitstellen der Adressen und Laengen, vor.laeufige Laenge vom Ergeb-
* nis eintragen
*
	   movea.l   a3,a4
*                                      * a4 = Adresse von OP1
*                                      * a5 = Adresse von OP2
*                                      * a6 = Adresse vom Ergebnis
           move.l    (a1)+,d1             * a1 = erste Ziffer von OP1
           move.l    d1,d6               * d6=L(OP1), merken
           sub.l    (a2)+,d1             * d1 = L(OP1)-L(OP2); a2 = erste
*                                      *      Ziffer von OP2
*
* Subtraktionsschleife organisieren
*
	   and.b    #$ce,ccr           * CCR loeschen
           cmp.l    #0,d2               * OP2 = 0 ?
           beq     noborrow1           * ja => Sprung zu 'noborrow', OP1
*                                      * in Ergebnis uebertragen
           sub.l    #1,d2               * d2 = Schleifenzaehler, Schlei-
*                                      * fenende bei -1
*
* Subtraktionsschleife
*
loop_1:    move.l    d4,(a3)+             * Ergebnis d. Subtr. Uebertragen
           move.l    (a1)+,d4             * d4=akt.Zi OP1; (a1)=naechste Zi
           move.l    (a2)+,d3             * d3=akt.Zi OP2; (a2)=naechste Zi
           subx.l   d3,d4               * d1=OP1-(OP2+Borrow)
           dbra    d2,loop_1           * letzte Zi OP2? Nein => Schleife
*
* Die letzte Ziffer von OP2 ist erreicht. a1 deutet auf die naechste
* Ziffer von OP1, a3 auf die naechste vom Ergebnis.
* Uebertrag = Borrow vorhanden ? 
* 
           bcc     noborrow1           * Nein => weiter bei 'noborrow',
*                                      * Rest von OP1 uebertragen
*
* Verfolge den Uebertrag durch den Rest von OP1
* Carry = 1, Extend = 1, a1 deutet auf naechste Ziffer von OP1, a3 auf
* die naechste vom Ergebnis
* Gibt es noch etwas von OP1 zu uebertragen ? 
*
           move.l    d4,(a3)+
           cmp.l    #0,d1               * d1=L(OP1)-L(OP2)=0 ?
           beq     negativ             * ja => Sprung zu 'negativ', denn
*                                      * L(OP1)=L(OP2), dh. vorhandenes
*                                      * Borrowbit kann nicht mehr sub-
*                                      * trahiert werden, dh. OP1 < OP2
*
* Es sind noch Ziffern von OP1 zu uebertragen, Borrow vorhanden
* Uebertragungsschleife vor.bereiten
*
           sub.l    #1,d1               * d3 = Schleifenzaehler, Schlei-
*                                      * fenende bei -1
loop_2:    move.l    (a1)+,0(a3)         * akt.Erg.Zi=akt.Zi OP1; 
*                                      * a1 = naechste Zi OP1
           sub.l    #1,(a3)+             * Subtrahiere Borrowbit; 
*                                      * a3 = naechste Erg.Ziffer
           bcc     noborrow2           * Carry=0 => Rest OP1 uebertragen
           dbra    d1,loop_2           * Ende OP1 ? Nein => Borrow von
*                                      * naechster Zi OP1 abziehen
*
* Falls dieser Punkt erreicht ist, sind beide Operanden voneinander 
* subtrahiert, aber immer noch ein Borrow vorhanden, dh. das Ergebnis
* ist negativ. Daher : Fehlermeldung
* 
negativ:
           move.l    #-1,d0 
           bra     return
*
* Kein Borrow (mehr), Uebertragen der restlichen Ziffern von OP1 ins
* Ergebnisfeld.
* Gibt es noch zu uebertragende Ziffern von OP1 ? 
*
noborrow1: move.l    d4,(a3)+               * Ergebnisfeld uebertragen
noborrow2: move.l    d6,0(a4)             * Laengenfeld eintragen
           dbra    d1,loop_4          * OP1 ist uebertragen; ueber-
*                                        * pruefe, ob L(erg)<L(OP1)
*
* Laenge ueberpruefen
*
chk_lngth: move.l    d6,d1                 * d1 = L(OP1)
           cmp.l    #0,d1                 * d1=L(OP1)=0 ?
           beq     found                 * ja => hoechstwertige Zi vom 
*                                        * Erg gefunden, denn Erg=0
loop_3:    move.l    -(a3),d5               * d5 = letzte Zi v. Erg
           cmp.l    #0,d5                 * letzte Zi Erg = 0 ?
           bne     found                 * nein => hoechstwertige Zi
*                                        * gefunden
           dbra    d1,loop_3             * L(Erg)=vor.laeuf.Laenge-1
found:     move.l    d1,0(a4)             * Laengenfeld eintragen
           eor.l    d0,d0                 * pos. RC
           bra     return  
*
* Kein Borrow, L(OP1)>=L(OP2)+2, dh. L(Erg)+L(OP1); nur noch Rest
* von OP1 uebertragen
*
loop_4:    move.l    (a1)+,(a3)+             * akt.Zi Erg=akt.Zi OP1, beide
*                                        * Register eins weiter
           dbra    d1,loop_4             * letzte Zi OP1 uebertragen ?
*                                        * Nein => naechste Ziffer
           move.l    #0,d0                 * ja => pos. RC
return:    movem.l  (sp)+,a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7 * Registerinhalte
*                                                        * zurueckschreiben
           rts
	   END

