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

* Datei : div.s
* Datum : 6.6.1988
* Inhalt: Dividieren zweier langer Zahlen
*
* a0 : Adresse des Dividenten(Dt) und Adresse des divident-Felds (dtF)
* a1 : Adresse des Divisors (Dr)
* a2 : Adresse des divident-Felds
* a3 : Adresse des quotient-Felds (qF)
* a4 : Adresse des Testfelds (tF)
* a5 : Adresse des Quotienten (Quot)
* a6 : Adresse des Rests (R)
* d0 : Returncode (Standard) und Laenge Divident und Schleifenzaehler
*      fuer die Hauptschleife (Anzahl Divisionsschritte)
* d1 : Laenge des Divisors (OP1)
* d2 : Hilfsregister
* d3 : Naeherungswert fuer q (q^)
* d4 : Hilfsregister
* d5 : Hilfsregister
* d6 : niederwertiger Teil des Dividenten, Quotient des Ergebnisses
* d7 : hoeherwertiger Teil des Dividenten, Rest des Ergebnisses
*
* 4(sp)  : Divident
* 8(sp)  : Divisor
* 12(sp) : Quotient
* 16(sp) : Rest
*

*        .lcomm     quotient,4*20 * Quotientfeld-Laenge: 4*Feldlaenge
*        .lcomm     divident,2*(4*20)+4
*        .lcomm     testfeld,2*(4*20)

*        .text

	  MODULE   _div
	  cpu      68020
	  entry.p  _div

	  DATA
dada      equ      *

_div       lea      dada,a0
	  jmp.l    div$proc

	  extern.p printf
a$printf  ac       printf

	  extern.f _shift
a$shift   ac       _shift

quotient: ds.l 4*20
divident: ds.l 2*(4*20)+4
testfeld: ds.l 2*(4*20)

	  PROC

div$proc:
	  movem.l a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7,-(sp)
	  move.l  a0,db

	  movem.l  null,a0/a1/a2/a3/a4/d0/d1/d2/d3/d4/d5/d6/d7
*
* Adressen in Register laden
*
	  move.l    64(sp),a1         * a1->Adresse Divisor
	  move.l    0(a1),d1          * d1 = L(Divisor),a1->1.Zi Div.or
	  cmp.l    #0,d1               * Divisor = 0 ?
	  bne     noerror             * nein => weiter bei noerror
*
* Sonderfall : Division durch Null
*
	  move.l    #-1,d0              * RC = -1
	  bra     return              * Ruecksprung
*
* Sonderfall: Divident < Divisor
*
noerror:  move.l    60(sp),a0         * a0->Adresse Divident
	  move.l    0(a0),d0           * d0 = L(Divident)
	  cmp.l    d0,d1               * Divident laenger Divisor ?
	  bls     nottrivial          * ja => "echte" Division

	  move.l    68(sp),a3          * a5->Laengenfeld Quotient
	  move.l    #0,0(a3)           * Quotient = 0
	  move.l    72(sp),a4          * a6->Laengenfeld Rest

	  cmp.l    #0,d0               * Divident = 0 ?
	  bne     nodiv               * nein -> Divident=Rest,Quot=0
	  move.l    #0,0(a4)           * Rest = 0
          bra     return

nodiv:    move.l    d0,(a4)+             * Laenge eintr., a6->1.Zi Quot
	  addq.l   #4,a0               * a0->1.Zi Divident
	  subq.l   #1,d0               * d0 Schleifenzaehler, Schlei-
*                                     * fenende bei -1
looprestonly:
	  move.l    (a0)+,(a4)+           * uebertragen
          dbra    d0,looprestonly
	  eor.l    d0,d0               * RC = 0
          bra     return    
*
* Sonderfall : Divisor hat nur eine Ziffer
*
nottrivial:
	  cmp.l    #1,d1               * L(Divisor) = 1 ?
	  bne     notshort            * nein => echte Division
	  move.l    4(a1),d5           * d5=die einzige Ziffer von Dr
	  move.l    68(sp),a3          * a5->Laengenfeld Quotient
	  move.l    72(sp),a4          * a6->Laengenfeld Rest
	  move.l    d0,(a3)+             * Laenge vor.laeufig eintragen,
*                                     * a5->1.Zi Quotient
          move.l    #4,d4
	  mulu.l   d0,d4               * d4=vor.laeufig L(Quotient)
	  add.l    d4,a3               * a5->vor fuehrende Zi Quotient
          add.l    d4,a0                
	  addq.l   #4,a0               * a0->vor fuehrende Zi Divident
	  subq.l   #1,d0               * d0 Schleifenzaehler, Schlei-
*                                     * fenende bei -1
	  eor.l    d7,d7               * loeschen

loop_sdiv:move.l    -(a0),d6             * d6 = hoechste Zi Divident
	  divu.l   d5,d7:d6            * d6d7,d5,d6=Quotient,d7=Rest
	  move.l    d6,-(a3)             * Quotient eintragen
	  dbra    d0,loop_sdiv        * Divident fertig?nein=>Schleife
	  move.l    -(a3),d4             * d4=vor.laeufige Laenge Quotient
	  cmp.l    #0,0(a3,d4.l*4)    * fuehrende Zi Quotient = 0 ?
	  bne     nocorr1             * nein => Laenge Quotient okay
	  subq.l   #1,0(a3)           * ja=>Laenge Quotient 1 kuerzer

nocorr1:  cmp.l    #0,d7               * Gibt es einen Rest ?
	  bne     notzero             * ja => eintragen
	  move.l    #0,0(a4)           * nein => Rest = 0 eintragen
	  eor.l    d0,d0               * RC = 0
          bra     return

notzero:  move.l    #1,(a4)+             * Laenge Rest = 1
	  move.l    d7,0(a4)           * Rest eintragen
	  eor.l    d0,d0               * RC = 0
          bra     return
*
* Echte Division; Zunaechst uebertragen des Dividenten in das
* Arbeitsfeld
*
notshort: lea     divident,a2         * a2->L-Feld div-Feld
	  move.l    d0,d2               * d2 Schleifenzaehler
loop_trfield:
	  move.l    (a0)+,(a2)+           * uebertragen
	  dbra    d2,loop_trfield     * fertig ? nein => Schleife

*
* Erweitern von divident-Feld und Divisor
* zuerst : v1 > b/2 ?
*
	  move.l    0(a1,d1.l*4),d5   * d5 = fuehrende Zi Divisor=v1
	  cmp.l    #0,d5               * v1>b/2 ?(hoechstwertiges Bit
*                                     * muss 1 sein!)
	  bpl     shift1              * nein => shiften
*
* kein Shift = Erweitern noetig, daher Shiftfaktor = 0 und die beiden
* ersten Ziffern vom Divisor merken
*
	  move.l    #0,-(sp)             * Shiftfaktor auf Stack merken
	  move.l    d5,-(sp)             * v1 auf Stack merken
	  move.l    -4(a1,d1.l*4),-(sp) * v2 auf Stack merken
	  bra     startdiv            * jetzt dividieren

shift1:   eor.l    d4,d4               * d4 loeschen
loopshift:addq.l   #1,d4               * d4 Shiftfaktor
	  lsl.l    #1,d5               * um 1 nach links shiften
	  cmp.l    #0,d5               * v1 jetzt okay ?
	  bpl     loopshift           * nein => weiter shiften

	  move.l    d4,-(sp)             * ja => Shiftfaktor auf Stack
*                                     * merken
	  pea       divident            * Adresse div-Feld und Shiftfak-
	  move.l    d4,-(sp)             * tor fuer den Aufruf des Shift-
	  pea       divident            * programms uebergeben
	  move.l    a$shift,a0
	  jsr       (a0)                 * Programm aufrufen
	  move.l    a1,0(sp)           * Dasselbe fuer den Divisor
          move.l    a1,8(sp)
	  move.l    a$shift,a0
	  jsr       (a0)                 * Programm aufrufen
	  add.l    #$0c,a7             * SP zuruecksetzen: sp=sp+12

	  move.l    0(a1),d1           * d1 = neue Laenge Divisor, a1->
*                                     * 1. Zi Divisor
	  move.l    0(a1,d1.l*4),-(sp)  * fuehrende und naechste Zi Di-
	  move.l    -4(a1,d1.l*4),-(sp) * visor auf Stack merken
	  move.l    0(a1,d1.l*4),d5    * d5 = neue fuehrende Zi Divisor
*
*
*
startdiv: lea     divident,a0         * a0->Laengenfeld div-Feld
	  addq.l   #4,a1               * a1->fuehrende Zi Divisor
	  move.l    (a0)+,d0             * d0=neue Laenge div-Feld
	  sub.l    d1,-4(a0)          * Anzahl der Divisionsschritte
	  addq.l   #1,-4(a0)          * = L(Dt)-L(dr), evtl. +1
	  move.l    -4(a0),-(sp)         * auf Stack merken
	  move.l    #4,d4               * fuer Pointer = Anzahl der
	  mulu.l   d0,d4               * Ziffern * 4
	  add.l    d4,a0               * a0->fuehrende Zi div-Feld
	  move.l    #0,(a0)+             * vor fuehrende Zi div-Feld wird
*                                     * eine 0 eingetragen, a0->davor!
	  move.l    0(sp),d0           * d0=Anzahl Divisionsschritte
*                                     * = L(Dt) - L(Dr), evtl. +1
	  lea     quotient,a3         * a3->Laengenfeld quot-Feld
	  move.l    #4,d4               * d4 fuer Pointerausrichtung
          mulu.l   d0,d4
          add.l    d4,a3
	  add.l    #4,a3               * a3->vor fuehrende Zi quot-Feld
	  subq.l   #1,d0               * d0 Schleifenzaehler, Schlei-
*                                     * fenende bei -1

mainloop: move.l    -(a0),d7             * d7=fuehrende Zi div-Feld
	  move.l    a0,a2               * a2->fuehrende Zi div-Feld
	  move.l    d1,d2               * d2 = Laenge Quotient * 4
	  mulu.l   #4,d2               *      (wg. 4 Byte/Ziffer)
	  sub.l    d2,a2               * a2->niedrigste Zi div-Feld,
*                                     * die bei mult und subtr ange-
*                                     * sprochen wird
	  cmp.l    d7,d5               * hoechste Zi div-Feld = v1 ?
	  bne     dodivide            * nein => q^ durch Division er-
*                                     * mitteln
	  move.l  #-1,d3               * ja => d3=q^=b-1=2**32-1=1...1
	  bra     dotest              * q^ testen

dodivide: move.l    -4(a0),d6          * d6d7 = u1u0
	  divu.l   d5,d7:d6            * u0u1 : v1, d6=Quotient,d7=Rest
	  move.l    d6,d3               * d3 = q^

dotest:   lea     testfeld,a4         * a4->testfeld
	  move.l    4(sp),d4           * d4d5 = v2v1
	  mulu.l   d3,d2:d4            * d4d2 = q^*v2, d2 hoeherwertig
	  move.l    d4,0(a4)           * niederwertiges Testergebnis
	  move.l    d2,4(a4)           * ablegen, hoeherwertiges merken
	  mulu.l   d3,d2:d5            * d5d2 = q^*v1, d2 hoeherwertig
	  add.l    d5,4(a4)           * auf 2. Testfeld addieren
	  bcc     nocarry1            * Uebertrag ? nein => weiter
	  addq.l   #1,d2               * ja => addiere 1 auf hoeherw.

nocarry1: cmp.l    0(a0),d2           * vergleiche hoechstwertiges
*                                     * Testergebnis mit u0
	  bcs     okay                * u0 groesser: okay
	  bhi     docorrect           * u0 kleiner: q^ korrigieren
          move.l    4(a4),d2
	  cmp.l    -4(a0),d2          * gleich: weiter vergleichen
          bcs     okay
          bhi     docorrect
          move.l    0(a4),d2
	  cmp.l    -8(a0),d2          * beim letzten Vergleich okay
	  bls     okay                * bei -8(a0)>=d2 !
*
* q^ ist um eins zu gross: korrigieren
*
docorrect:subq.l   #1,d3
*
* Jetzt ist q^ okay, die Division kann beginnen, d.h. q^ * v wird
* von den entsprechenden u-Stellen abgezogen
*

okay:     eor.l    d5,d5               * Uebertragsregister loeschen
	  move.l    d1,d2               * d2 Schleifenzaehler, Schlei-
	  subq.l   #1,d2               * fenende bei -1
loopsub:  move.l    (a1)+,d6             * d6=niederwertigste Zi Divisor
	  mulu.l   d3,d7:d6            * vn*q^=d6d7,d7 hoeherwert. Teil
	  add.l    d5,d6               * addiere Uebertrag
	  bcc     nocarry2            * Carry ? nein=> weiter
	  addq.l   #1,d7               * ja => add. 1 auf hoeherw. Teil
nocarry2: sub.l    d6,(a2)+             * subtrahieren von niederwert.
*                                     * Zi vom div-Feld
	  bcc     nocarry3            * Borrow ? nein => weiter
	  addq.l   #1,d7               * ja => beim naechsten Schritt
*                                     * eins mehr abziehen
nocarry3: move.l    d7,d5               * Uebertrag merken
	  dbra    d2,loopsub          * Quot.fertig? Nein => Schleife
	  sub.l    d5,0(a2)           * ja => subtrahiere letztes
*                                     * Multiplikationsergebnis
	  bcc     noreadd             * Borrow ? nein => weiter
*
* q^ * v > u , daher muss 1*v wieder auf u aufaddiert und q^ um
* eins vermindert werden
*
	  subq.l   #1,d3               * q^ = q^ - 1
	  move.l    #4,d4               * d4 wird wieder Offset
          mulu.l   d1,d4 
	  sub.l    d4,a2               * a2->niedrigste Zi von u zum
	  sub.l    d4,a1               * Addieren, a1->niedr.Zi von v
	  move.l    d1,d2               * d2 Schleifenzaehler, Schlei-
	  subq.l   #1,d2               * fenende bei -1
	  and.b    #$ce,ccr           * CCR zuruecksetzen
loopreadd:move.l    (a1)+,d5             * d5 = aktuelle Zi Quotient
	  move.l    0(a2),d6           * d6 = aktuelle Zi Div-Feld
	  addx.l   d5,d6               * addiere auf div-Feld mit Carry
	  move.l    d6,(a2)+             * Summe in div-Feld eintragen
	  dbra    d2,loopreadd        * Quot. fertig? nein=>Schleife
	  move.l    #0,(a2)+             * jetzt ist die hoechstwertige
*                                     * Zi vom div-Feld = 0
*
* Die Division ist beendet. a1->vor fuehrende Zi Divisor
*                           a2->vor fuehrende Zi div-Feld
*
noreadd:  move.l    d3,-(a3)             * Quotient eintragen, a3->
*                                     * naechstgroesste Ziffer
	  move.l     #4,d4              * fuer Pointer-Zuruecksetzung
          mulu.l    d1,d4
	  sub.l     d4,a1              * a1->1. Zi Divisor
	  move.l     8(sp),d5          * d5=fuehrende Zi Divisor = v1
	  dbra     d0,mainloop        * Div. fertig? nein => Schleife
*
* Laenge von Quotient und Rest (=div-Feld) bestimmen
*
	  move.l     0(sp),d0          * d0=Anzahl Div.Schritte

	  cmp.l     #0,-4(a3,d0.l*4)  * fuehrende Quot.Ziffer = 0 ?
	  bne      nocorr2            * nein => L(Quot)=L(Div)-L(Divi-
*                                     * sor) = Anzahl Div.Schritte
	  subq.l    #1,d0              * ja => L(Quot) eins groesser
nocorr2:  move.l     d0,-4(a3)         * Laenge Quotient eintragen
	  lea      divident,a2        * a2->Laengenfeld Rest
 
* Die Laenge vom Rest kann hoechst gleich der Laenge vom Divisor
* sein.
*
loopchklngth:
	  cmp.l     #0,0(a2,d1.l*4)   * Ist diese = 0?
	  bne      found              * nein => Laenge klar
	  subq.l    #1,d1              * nein => L. mind. 1 kuerzer
	  bra      loopchklngth       * weiter suchen
found:    move.l     d1,0(a2)          * Laenge Rest eintragen
*
* Erweiterung vom Rest (frueher div-Feld) und Quotient rueckgaengig
* machen
*
	  move.l      12(sp),d4        * d4 = Erweiterungsfaktor
	  cmp.l      #0,d4             * wurde ueberhaupt erweitert ?
	  beq       noreshift         * nein => weiter
	  neg.l      d4             * andersrum shiften
	  subq.l     #4,a1             * a1->L-Feld Divisor
*                                     * a2->L-Feld Rest
	  move.l      a1,-(sp)           * Adresse Divisor und Shift-
	  move.l      d4,-(sp)           * faktor auf Stack schreiben
          move.l      a1,-(sp)           
	  move.l    a$shift,a0
	  jsr       (a0)                 * Programm aufrufen
	  move.l      a2,0(sp)         * dasselbe fuer Rest
          move.l      a2,8(sp) 
	  move.l    a$shift,a0
	  jsr       (a0)                 * Programm aufrufen
	  add.l     #12,sp             * Stackpointer zurueckschalten

noreshift:add.l     #16,sp             * Shiftfaktor etc. wird nicht
*                                     * mehr gebraucht
*
* Ergebnisse uebertragen: Quotient kommt zuerst dran und wird dabei
* evtl. ueberschrieben
*
	  subq.l     #4,a3             * a3->L-Feld Quotient
	  move.l      0(a3),d2         * d2 Schleifenzaehler, Schlei-
	  move.l      68(sp),a4        * a4->L-Feld Quotient
loopquot: move.l      (a3)+,(a4)+         * uebertragen
	  dbra      d2,loopquot       * fertig ? nein => Schleife
	  move.l      0(a2),d2         * d2 wieder Schleifenzaehler
	  move.l      72(sp),a4        * a4->L-Feld Rest
looprest: move.l      (a2)+,(a4)+         * uebertragen
	  dbra      d2,looprest       * fertig ? nein => Schleife
	  eor.l      d0,d0             * alles fertig, RC = 0
  
return:   movem.l  (sp)+,a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7 
          rts


null:     dc.l    0,0,0,0,0,0,0,0,0,0,0,0,0 * 13 Langworte 0 zum Loeschen

	  END




