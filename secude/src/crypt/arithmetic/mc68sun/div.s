|********************************************************************
|* Copyright (C) 1991, GMD. All rights reserved.                    *
|*                                                                  *
|*                                                                  *
|*                         NOTICE                                   *
|*                                                                  *
|*    Acquisition, use, and distribution of this module             *
|*    and related materials are subject to restrictions             *
|*    mentioned in each volume of the documentation.                *
|*                                                                  *
|********************************************************************

| Datei : div.s
| Datum : 6.6.1988
| Inhalt: Dividieren zweier langer Zahlen
|
| a0 : Adresse des Dividenten(Dt) und Adresse des divident-Felds (dtF)
| a1 : Adresse des Divisors (Dr)
| a2 : Adresse des divident-Felds
| a3 : Adresse des quotient-Felds (qF)
| a4 : Adresse des Testfelds (tF)
| a5 : Adresse des Quotienten (Quot)
| a6 : Adresse des Rests (R)
| d0 : Returncode (Standard) und Laenge Divident und Schleifenzaehler
|      fuer die Hauptschleife (Anzahl Divisionsschritte)
| d1 : Laenge des Divisors (OP1)
| d2 : Hilfsregister
| d3 : Naeherungswert fuer q (q^)
| d4 : Hilfsregister 
| d5 : Hilfsregister
| d6 : niederwertiger Teil des Dividenten, Quotient des Ergebnisses
| d7 : hoeherwertiger Teil des Dividenten, Rest des Ergebnisses
|
| sp@(4)  : Divident
| sp@(8)  : Divisor
| sp@(12) : Quotient
| sp@(16) : Rest
| 

         .lcomm     quotient,4*60 | Quotientfeld-Laenge: 4*Feldlaenge
         .lcomm     divident,2*(4*60)+4
         .lcomm     testfeld,2*(4*60)

         .text

          .globl   __div

__div:     moveml a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7,sp@-  

          moveml  null,a0/a1/a2/a3/a4/a5/a6/d0/d1/d2/d3/d4/d5/d6/d7
|
| Adressen in Register laden
|
          movl    sp@(64),a1         | a1->Adresse Divisor
          movl    a1@(0),d1          | d1 = L(Divisor),a1->1.Zi Div.or
          cmpl    #0,d1               | Divisor = 0 ?
          bne     noerror             | nein => weiter bei noerror
|
| Sonderfall : Division durch Null 
|                                
          movl    #fehler,sp@-        | Fehlermeldung
          jsr     _printf       
          addql   #4,sp              | Stack zuruecksetzen
          movl    #-1,d0              | RC = -1
          bra     return              | Ruecksprung
|
| Sonderfall: Divident < Divisor
|
noerror:  movl    sp@(60),a0         | a0->Adresse Divident
          movl    a0@(0),d0           | d0 = L(Divident)
          cmpl    d0,d1               | Divident laenger Divisor ?
          bls     nottrivial          | ja => "echte" Division

          movl    sp@(68),a5          | a5->Laengenfeld Quotient
          movl    #0,a5@(0)           | Quotient = 0
          movl    sp@(72),a6          | a6->Laengenfeld Rest

          cmpl    #0,d0               | Divident = 0 ?
          bne     nodiv               | nein -> Divident=Rest,Quot=0
          movl    #0,a6@(0)           | Rest = 0
          bra     return

nodiv:    movl    d0,a6@+             | Laenge eintr., a6->1.Zi Quot
          addql   #4,a0               | a0->1.Zi Divident
          subql   #1,d0               | d0 Schleifenzaehler, Schlei-
                                      | fenende bei -1
looprestonly:
          movl    a0@+,a6@+           | uebertragen
          dbra    d0,looprestonly
          eorl    d0,d0               | RC = 0
          bra     return    
|
| Sonderfall : Divisor hat nur eine Ziffer
|
nottrivial:
          cmpl    #1,d1               | L(Divisor) = 1 ?
          bne     notshort            | nein => echte Division
          movl    a1@(4),d5           | d5=die einzige Ziffer von Dr
          movl    sp@(68),a5          | a5->Laengenfeld Quotient
          movl    sp@(72),a6          | a6->Laengenfeld Rest
          movl    d0,a5@+             | Laenge vorlaeufig eintragen,
                                      | a5->1.Zi Quotient
          movl    #4,d4
          mulul   d0,d4               | d4=vorlaeufig L(Quotient)
          addl    d4,a5               | a5->vor fuehrende Zi Quotient
          addl    d4,a0                
          addql   #4,a0               | a0->vor fuehrende Zi Divident
          subql   #1,d0               | d0 Schleifenzaehler, Schlei- 
                                      | fenende bei -1
          eorl    d7,d7               | loeschen

loop_sdiv:movl    a0@-,d6             | d6 = hoechste Zi Divident
          divul   d5,d7:d6            | d6d7:d5,d6=Quotient,d7=Rest
          movl    d6,a5@-             | Quotient eintragen
          dbra    d0,loop_sdiv        | Divident fertig?nein=>Schleife
          movl    a5@-,d4             | d4=vorlaeufige Laenge Quotient
          cmpl    #0,a5@(0,d4:l:4)    | fuehrende Zi Quotient = 0 ?
          bne     nocorr1             | nein => Laenge Quotient okay
          subql   #1,a5@(0)           | ja=>Laenge Quotient 1 kuerzer

nocorr1:  cmpl    #0,d7               | Gibt es einen Rest ?
          bne     notzero             | ja => eintragen
          movl    #0,a6@(0)           | nein => Rest = 0 eintragen
          eorl    d0,d0               | RC = 0
          bra     return

notzero:  movl    #1,a6@+             | Laenge Rest = 1
          movl    d7,a6@(0)           | Rest eintragen
          eorl    d0,d0               | RC = 0
          bra     return
|
| Echte Division; Zunaechst uebertragen des Dividenten in das
| Arbeitsfeld
|
notshort: lea     divident,a2         | a2->L-Feld div-Feld
          movl    d0,d2               | d2 Schleifenzaehler
loop_trfield:
          movl    a0@+,a2@+           | uebertragen
          dbra    d2,loop_trfield     | fertig ? nein => Schleife

|
| Erweitern von divident-Feld und Divisor
| zuerst : v1 > b/2 ?
|
          movl    a1@(0,d1:l:4),d5   | d5 = fuehrende Zi Divisor=v1
          cmpl    #0,d5               | v1>b/2 ?(hoechstwertiges Bit
                                      | muss 1 sein!)
          bpl     shift               | nein => shiften
|
| kein Shift = Erweitern noetig, daher Shiftfaktor = 0 und die beiden
| ersten Ziffern vom Divisor merken
| 
          movl    #0,sp@-             | Shiftfaktor auf Stack merken
          movl    d5,sp@-             | v1 auf Stack merken
          movl    a1@(-4,d1:l:4),sp@- | v2 auf Stack merken
          bra     startdiv            | jetzt dividieren

shift:    eorl    d4,d4               | d4 loeschen
loopshift:addql   #1,d4               | d4 Shiftfaktor
          lsll    #1,d5               | um 1 nach links shiften
          cmpl    #0,d5               | v1 jetzt okay ?
          bpl     loopshift           | nein => weiter shiften

          movl    d4,sp@-             | ja => Shiftfaktor auf Stack
                                      | merken
          movl    #divident,sp@-      | Adresse div-Feld und Shiftfak-
          movl    d4,sp@-             | tor fuer den Aufruf des Shift-
          movl    #divident,sp@-      | programms uebergeben
          bsr     __shift             | Programm aufrufen
          movl    a1,sp@(0)           | Dasselbe fuer den Divisor
          movl    a1,sp@(8)
	  bsr     __shift
          addl    #0xc,a7             | SP zuruecksetzen: sp=sp+12

          movl    a1@(0),d1           | d1 = neue Laenge Divisor, a1->
                                      | 1. Zi Divisor
          movl    a1@(0,d1:l:4),sp@-  | fuehrende und naechste Zi Di-
          movl    a1@(-4,d1:l:4),sp@- | visor auf Stack merken
          movl    a1@(0,d1:l:4),d5    | d5 = neue fuehrende Zi Divisor
|
|
|
startdiv: lea     divident,a0         | a0->Laengenfeld div-Feld
          addql   #4,a1               | a1->fuehrende Zi Divisor
          movl    a0@+,d0             | d0=neue Laenge div-Feld
          subl    d1,a0@(-4)          | Anzahl der Divisionsschritte
          addql   #1,a0@(-4)          | = L(Dt)-L(dr), evtl. +1
          movl    a0@(-4),sp@-         | auf Stack merken
          movl    #4,d4               | fuer Pointer = Anzahl der
          mulul   d0,d4               | Ziffern * 4
          addl    d4,a0               | a0->fuehrende Zi div-Feld
          movl    #0,a0@+             | vor fuehrende Zi div-Feld wird
                                      | eine 0 eingetragen, a0->davor!
          movl    sp@(0),d0           | d0=Anzahl Divisionsschritte 
                                      | = L(Dt) - L(Dr), evtl. +1
          lea     quotient,a3         | a3->Laengenfeld quot-Feld
          movl    #4,d4               | d4 fuer Pointerausrichtung
          mulul   d0,d4
          addl    d4,a3
          addl    #4,a3               | a3->vor fuehrende Zi quot-Feld
          subql   #1,d0               | d0 Schleifenzaehler, Schlei-
                                      | fenende bei -1

mainloop: movl    a0@-,d7             | d7=fuehrende Zi div-Feld
          movl    a0,a2               | a2->fuehrende Zi div-Feld
          movl    d1,d2               | d2 = Laenge Quotient * 4
          mulul   #4,d2               |      (wg. 4 Byte/Ziffer)
          subl    d2,a2               | a2->niedrigste Zi div-Feld,
                                      | die bei mult und subtr ange-
                                      | sprochen wird
          cmpl    d7,d5               | hoechste Zi div-Feld = v1 ?
          bne     dodivide            | nein => q^ durch Division er-
                                      | mitteln
          movl    #-1,d3              | ja => d3=q^=b-1=2**32-1=1...1
          bra     dotest              | q^ testen

dodivide: movl    a0@(-4),d6          | d6d7 = u1u0 
          divul   d5,d7:d6            | u0u1 : v1, d6=Quotient,d7=Rest
          movl    d6,d3               | d3 = q^

dotest:   lea     testfeld,a4         | a4->testfeld
          movl    sp@(4),d4           | d4d5 = v2v1
          mulul   d3,d2:d4            | d4d2 = q^*v2, d2 hoeherwertig
          movl    d4,a4@(0)           | niederwertiges Testergebnis
          movl    d2,a4@(4)           | ablegen, hoeherwertiges merken
          mulul   d3,d2:d5            | d5d2 = q^*v1, d2 hoeherwertig
          addl    d5,a4@(4)           | auf 2. Testfeld addieren
          bcc     nocarry1            | Uebertrag ? nein => weiter
          addql   #1,d2               | ja => addiere 1 auf hoeherw.

nocarry1: cmpl    a0@(0),d2           | vergleiche hoechstwertiges
                                      | Testergebnis mit u0
          bcs     okay                | u0 groesser: okay
          bhi     docorrect           | u0 kleiner: q^ korrigieren
          movl    a4@(4),d2
          cmpl    a0@(-4),d2          | gleich: weiter vergleichen
          bcs     okay
          bhi     docorrect
          movl    a4@(0),d2
          cmpl    a0@(-8),d2          | beim letzten Vergleich okay
          bls     okay                | bei a0@(-8)>=d2 !
|
| q^ ist um eins zu gross: korrigieren
|
docorrect:subql   #1,d3
|
| Jetzt ist q^ okay, die Division kann beginnen, d.h. q^ * v wird
| von den entsprechenden u-Stellen abgezogen
|

okay:     eorl    d5,d5               | Uebertragsregister loeschen
          movl    d1,d2               | d2 Schleifenzaehler, Schlei-
          subql   #1,d2               | fenende bei -1
loopsub:  movl    a1@+,d6             | d6=niederwertigste Zi Divisor
          mulul   d3,d7:d6            | vn*q^=d6d7,d7 hoeherwert. Teil
          addl    d5,d6               | addiere Uebertrag
          bcc     nocarry2            | Carry ? nein=> weiter
          addql   #1,d7               | ja => add. 1 auf hoeherw. Teil
nocarry2: subl    d6,a2@+             | subtrahieren von niederwert.
                                      | Zi vom div-Feld
          bcc     nocarry3            | Borrow ? nein => weiter
          addql   #1,d7               | ja => beim naechsten Schritt
                                      | eins mehr abziehen
nocarry3: movl    d7,d5               | Uebertrag merken
          dbra    d2,loopsub          | Quot.fertig? Nein => Schleife
          subl    d5,a2@(0)           | ja => subtrahiere letztes 
                                      | Multiplikationsergebnis
          bcc     noreadd             | Borrow ? nein => weiter
|
| q^ * v > u , daher muss 1*v wieder auf u aufaddiert und q^ um
| eins vermindert werden 
|
          subql   #1,d3               | q^ = q^ - 1
          movl    #4,d4               | d4 wird wieder Offset
          mulul   d1,d4 
          subl    d4,a2               | a2->niedrigste Zi von u zum
          subl    d4,a1               | Addieren, a1->niedr.Zi von v
          movl    d1,d2               | d2 Schleifenzaehler, Schlei-
          subql   #1,d2               | fenende bei -1
          andb    #0xce,cc            | CCR zuruecksetzen
loopreadd:movl    a1@+,d5             | d5 = aktuelle Zi Quotient
          movl    a2@(0),d6           | d6 = aktuelle Zi Div-Feld
          addxl   d5,d6               | addiere auf div-Feld mit Carry
          movl    d6,a2@+             | Summe in div-Feld eintragen  
          dbra    d2,loopreadd        | Quot. fertig? nein=>Schleife
          movl    #0,a2@+             | jetzt ist die hoechstwertige
                                      | Zi vom div-Feld = 0
|
| Die Division ist beendet. a1->vor fuehrende Zi Divisor
|                           a2->vor fuehrende Zi div-Feld
|
noreadd:  movl    d3,a3@-             | Quotient eintragen, a3->
                                      | naechstgroesste Ziffer
          movl     #4,d4              | fuer Pointer-Zuruecksetzung
          mulul    d1,d4
          subl     d4,a1              | a1->1. Zi Divisor
          movl     sp@(8),d5          | d5=fuehrende Zi Divisor = v1
          dbra     d0,mainloop        | Div. fertig? nein => Schleife
|
| Laenge von Quotient und Rest (=div-Feld) bestimmen
|
          movl     sp@(0),d0          | d0=Anzahl Div.Schritte

          cmpl     #0,a3@(-4,d0:l:4)  | fuehrende Quot.Ziffer = 0 ?
          bne      nocorr2            | nein => L(Quot)=L(Div)-L(Divi-
                                      | sor) = Anzahl Div.Schritte
          subql    #1,d0              | ja => L(Quot) eins groesser
nocorr2:  movl     d0,a3@(-4)         | Laenge Quotient eintragen
          lea      divident,a2        | a2->Laengenfeld Rest
 
| Die Laenge vom Rest kann hoechst gleich der Laenge vom Divisor
| sein.
|
loopchklngth:
          cmpl     #0,a2@(0,d1:l:4)   | Ist diese = 0?
          bne      found              | nein => Laenge klar
          subql    #1,d1              | nein => L. mind. 1 kuerzer
          bra      loopchklngth       | weiter suchen
found:    movl     d1,a2@(0)          | Laenge Rest eintragen
|
| Erweiterung vom Rest (frueher div-Feld) und Quotient rueckgaengig
| machen
|
          movl      sp@(12),d4        | d4 = Erweiterungsfaktor
          cmpl      #0,d4             | wurde ueberhaupt erweitert ?
          beq       noreshift         | nein => weiter
          negl      d4             | andersrum shiften
          subql     #4,a1             | a1->L-Feld Divisor
                                      | a2->L-Feld Rest
          movl      a1,sp@-           | Adresse Divisor und Shift-
          movl      d4,sp@-           | faktor auf Stack schreiben
          movl      a1,sp@-           
	  bsr       __shift            | Shiftprogramm aufrufen
          movl      a2,sp@(0)         | dasselbe fuer Rest
          movl      a2,sp@(8) 
	  bsr       __shift
          addl     #12,sp             | Stackpointer zurueckschalten

noreshift:addl     #16,sp             | Shiftfaktor etc. wird nicht
                                      | mehr gebraucht
|
| Ergebnisse uebertragen: Quotient kommt zuerst dran und wird dabei 
| evtl. ueberschrieben
|
          subql     #4,a3             | a3->L-Feld Quotient
          movl      a3@(0),d2         | d2 Schleifenzaehler, Schlei-
          movl      sp@(68),a4        | a4->L-Feld Quotient
loopquot: movl      a3@+,a4@+         | uebertragen
          dbra      d2,loopquot       | fertig ? nein => Schleife
          movl      a2@(0),d2         | d2 wieder Schleifenzaehler
          movl      sp@(72),a4        | a4->L-Feld Rest
looprest: movl      a2@+,a4@+         | uebertragen
          dbra      d2,looprest       | fertig ? nein => Schleife
          eorl      d0,d0             | alles fertig, RC = 0
  
return:   moveml  sp@+,a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5/d6/d7 
          rts

          .data
fehler:   .ascii   "Division durch Null"
          .even
null:     .long    0,0,0,0,0,0,0,0,0,0,0,0,0 | 13 Langworte 0 zum Loeschen

