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

* Datei : mult.s
* Datum : 11.5.1988
* Inhalt: Multiplizieren zweier langer Zahlen
*
* a0 : Adresse des Akkumulators acc
* a1 : Adresse des ersten Operanden (OP1)
* a2 : Adresse des zweiten Operanden (OP2)
* a3 : Adresse des Produkts
* a4 : Hilfsregister (Adresse von OP1)
* a5 : Hilfsregister (Adresse von OP2)
* a6 : Hilfsregister (Adresse des Produkts)
* d0 : Returncode (Standard)
* d1 : Laenge des ersten Operanden (OP1), Schleifenzaehler fuer die 
*      aeussere Schleife
* d2 : Laenge des yweiten Operanden (OP2), Schleifenzaehler fuer die
*      innere Schleife
* d3 : Hilfsregister zur Multiplikation, niederwertiger Teil des
*      Produkts
* d4 : Hilfsregister zur Multiplikation, hoeherwertiger Teil des
*      Produkts
* d5 : Uebertrag  aus der inneren Schleife
*

*        .lcomm acc,2*(4*20)

*        .text

	  MODULE   _mult
	  cpu      68020
	  entry.p  _mult

	  DATA
dada      equ      *

_mult      lea      dada,a0
	  jmp.l    mult$proc

	  extern.p printf
a$printf  ac       printf

acc:      ds.l    2*(4*20)


	  PROC


mult$proc movem.l a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7,-(sp)  * retten
	  move.l  a0,db

	  movem.l  null,a0/a1/a2/a3/a4/d0/d1/d2/d3/d4/d5/d6/d7 * loeschen
*
* Adressen in Register laden
*
	  movem.l  60(sp),a1/a2/a3    * a1 = Adresse von OP1
*                                     * a2 = Adresse von OP2
*                                     * a3 = Adresse von OP3
	  movea.l  a1,d6
	  movea.l  a2,d7
	  lea      acc,a0         * a0 = Adresse des Akkumulator

* Ein Operand = 0 ?
*
          cmp.l    #0,0(a1) 
          beq     zero
          cmp.l    #0,0(a2)
	  bne    multi
zero:     move.l    #0,0(a3)           * Ergebnis = 0
          bra     return
*
* Erste Schleife : Inhalt des vorlaeufigen Ergebnisfeldes muss noch
* nicht beruecksichtigt werden.
*
multi:    move.l    #0,d5               * Uebertrag loeschen
	  move.l    (a1)+,d1             * d1=L(OP1), a1 = 1. Zi OP1
          move.l    (a2)+,d2             * d2=L(OP2), a2 = 1. Zi OP2
          subq.l   #1,d2               * Schleifenende bei -1
loop_1:   move.l    0(a1),d3           * d3 = 1. Zi OP1
	  mulu.l   (a2)+,d4:d3          * multipl. 1.Zi OP1 mit akt.Zi
*                                     * OP2, d4=hoeherwertiger,d3=
*                                     * niederwertiger Teil d. Prod.
          add.l     d5,d3              * Addiere Uebertrag auf nie-
*                                     * derwertigen Teil
          bcc     no_carry1           * Uebertrag ?
          addq.l   #1,d4               * ja => addiere 1 auf hoeher-
*                                     * wertigen Teil
no_carry1:move.l    d3,(a0)+             * niederwertigen Teil in Akkumu-
*                                     * lator, a3 eine Zi weiter
          move.l    d4,d5               * Uebertrag merken
          dbra    d2,loop_1           * OP2 fertig ? nein => Schleife
          move.l    d5,0(a0)           * ja => letzten Uebertrag in
*                                     * vorlaeuf. Erg. eintragen
*
* Eigentliche Multiplikation mit Beruecksichtigung des vorlaeufigen
* Inhalts des Ergebnisfelds
*  
          subq.l   #1,d1               
          cmp.l    #0,d1               * schon Ende OP1 erreicht ?
          beq     weiter              * ja => Ende Multiplikation
          subq.l   #1,d1               * Schleifenende bei -1
*
* Aeussere Schleife ( laeuft ueber die Ziffern von OP1)
*
	  lea     acc,a4              * a6 = Adresse des Akkumulators
out_loop: addq.l   #4,a4               * a6 = niederwertigste relevan-
*                                     * te (dh. als Uebertrag aufzu-
*                                     * addierende) Ergebnisstelle
	  move.l    a4,a0               * Uebertragsregister laden
	  movea.l    d7,a2               * OP2 wieder von Ende an be-
          move.l    (a2)+,d2             * arbeiten
          subq.l   #1,d2
          addq.l   #4,a1               * a1 = naechste Zi OP1
          move.l    #0,d5               * Uebertrag loeschen
*
* Innere Schleife (laeuft ueber die Ziffern von OP2)
*
in_loop:  move.l    0(a1),d3           * d3 = akt. Zi OP1
	  mulu.l   (a2)+,d4:d3            * multiplizieren (wie oben)
          add.l    d5,d3               * Uebertrag auf niederwertigen
*                                     * Teil addieren
          bcc     no_carry2           * Uebertrag ? 
          addq.l   #1,d4               * ja => 1 auf hoeherwertigen 
*                                     * Teil addieren
no_carry2:move.l    d4,d5               * Uebertrag merken
          add.l    d3,(a0)+             * niederwertigen Teil auf ent-
*                                     * spr. Akkumulatorziffer addieren
          bcc     no_carry3           * Uebertrag ? 
          addq.l   #1,d5               * ja => 1 auf Uebertrag addiern
no_carry3:dbra    d2,in_loop          * Ende OP2 ? nein => Schleife
          move.l    d5,0(a0)           * ja => letzten Uebertrag in
*                                     * Akkumulatorfeld eintragen
ende_krit:dbra    d1,out_loop         * Ende OP1 ? nein => Schleife

*
* Multiplikation beendet; letzten Uebertrag zwischenspeichern, Laen-
* genfeld eintragen und Ergebnis in das eigentliche Ergebnisfeld
* uebertragen
*
weiter:   move.l    d5,0(a0)           * letzten Uebertrag zwischen-
*                                     * speichern
	  move.l   d6,a4              * a4 restaurieren
          move.l    0(a4),d1           * d1 = L(OP1)
	  move.l   d7,a4              * 'a5' in a4 laden
	  add.l    0(a4),d1           * d1 = L(OP1) + L(OP2)
          cmp.l    #0,0(a0)           * nur die kann = 0 sein
          bne     l_field             * wenn nein, dann Laenge eintr.
          subq.l   #1,d1               * wenn ja, Ergebnis um 1 kuerzer
l_field:  move.l    68(sp),a3          * a3 = Adresse vom Ergebnis
          move.l    d1,(a3)+             * Laenge eintragen
          lea     acc,a0              * Anfangsadresse Akkumulator laden  
          sub.l    #1,d1               * d1 = Schleifenzaehler fuer die
*                                     * Uebertragungsschleife, Ende bei -1
loop_2:   move.l    (a0)+,(a3)+           * Ergebnis uebertragen
          dbra    d1,loop_2           * Ende des Akkumulators erreicht ?
return:   movem.l  (sp)+,a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7
*                                     * Registerinhalte zurueckschreiben
          rts

aui:      movem.l  a0/a1,-(sp)
	  pea      text42
	  move.l   a$printf,a0
	  jsr      (a0)
	  movem.l  d3/d2/d1/d0,-(sp)  * retten
	  pea      text2
	  move.l   a$printf,a0
	  jsr      (a0)
	  movem.l  d7/d6/d5/d4,-(sp)  * retten
	  pea      text3
	  move.l   a$printf,a0
	  jsr      (a0)
	  movem.l  a3/a2/a1/a0,-(sp)  * retten
	  pea      text4
	  move.l   a$printf,a0
	  jsr      (a0)
	  movem.l  a7/a6/a5/a4,-(sp)  * retten
	  pea      text5
	  move.l   a$printf,a0
	  jsr      (a0)
	  move.l   (a3),-(sp)
	  move.l   (a2),-(sp)
	  move.l   (a1),-(sp)
	  pea      text
	  move.l   a$printf,a0
	  jsr      (a0)
	  addq.l   #4,a1
	  addq.l   #4,a2
	  addq.l   #4,a3
	  move.l   #$4242,(a3)
	  move.l   (a3),-(sp)
	  move.l   (a2),-(sp)
	  move.l   (a1),-(sp)
	  pea      text6
	  move.l   a$printf,a0
	  jsr      (a0)
	  subq.l   #4,a1
	  subq.l   #4,a2
	  subq.l   #4,a3
	  move.l   (a3),-(sp)
	  move.l   (a2),-(sp)
	  move.l   (a1),-(sp)
	  pea      text
	  move.l   a$printf,a0
	  jsr      (a0)
	  add.l    #132,sp
	  movem.l  (sp)+,a0/a1
	  rts








text:     da.b     ' Inhalt a1 : %08lx a2 : %08lx a3 : %08lx '
	  dc.b    13,10,0,0
text6:    da.b     ' Inhalt a1+: %08lx a2+: %08lx a3+: %08lx '
	  dc.b    13,10,0,0
text2:    da.b     'd0:  %08lx d1:  %08lx d2:  %08lx d3:  %08lx '
	  dc.b    13,10,0,0
text3:    da.b     'd4:  %08lx d5:  %08lx d6:  %08lx d7:  %08lx '
	  dc.b    13,10,0,0
text4:    da.b     'a0:  %08lx a1:  %08lx a2:  %08lx a3:  %08lx '
	  dc.b    13,10,0,0
text5:    da.b     'a4:  %08lx a5:  %08lx a6:  %08lx a7:  %08lx '
	  dc.b    13,10,0,0
text42:   da.b     'a0:  %08lx a1:  %08lx '
	  dc.b    13,10,0,0


null:     dc.l    0,0,0,0,0,0,0,0,0,0,0,0,0 * 13 Langworte 0 zum Loeschen

	  END

