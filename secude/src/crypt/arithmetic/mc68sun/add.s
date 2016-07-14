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

| Datei : add.s
| Datum : 13.7.1988
| Inhalt: Addieren zweier langer Zahlen
|
| a1 : Adresse des ersten Operanden (OP1)
| a2 : Adresse des zweiten Operanden (OP2)
| a3 : Adresse der Summe
| a4 : Hilfsregister (Adresse Ergebnis)
| d0 : Returncode (Standard) - wird hier nicht benutzt
| d1 : Laenge des laengeren Operanden (OP1), Schleifenzaehler fuer
|      die Uebertragungsschleife
| d2 : Laenge des kuerzeren Operanden (OP2), Schleifenzaehler fuer
|      die Additionsschleife
| d3 : Hilfsregister 
| d4 : Hilfsregister 
| d5 : Hilfsregister 
|
         .text

          .globl   __add

__add:      moveml  a1/a2/a3/a4/d1/d2/d3/d4/d5,sp@-   | Register retten
           moveml  null,a1/a2/a3/a4/d1/d2/d3/d4/d5 | zu ben. Reg. loeschen
|
| Adressen in Register laden
|
           moveml  sp@(40),a1/a2/a3     | a1 = Adresse von OP1
                                       | a2 = Adresse von OP2
                                       | a3 = Adresse von OP3
           movl    a3,a4               | Hilfsregister laden

|
| Laenge von OP1 > Laenge von OP2 ? ja => weiter bei no_ex
|                                 nein => austauschen
|
           movl    a2@(0),d2           | d2 = L(OP2), gleichzeitig
|                                         wird d2 Schleifenzaehler
           cmpl     a1@(0),d2           | L(OP2)-L(OP1)<0 => N = 1
           bls     no_ex               | L(OP1)>L(OP2) => weiter no_ex
           exg     a1,a2               | L(OP1)<L(OP2) => austauschen
           movl    a2@(0),d2           | d2 = L(OP2) = L(kuerzerer OP)
|
| Additionsschleife organisieren
|
no_ex:     movl    a1@(0),d1           | d1 = Laenge von OP1, Schleifen-
                                       | zaehler Uebertragungsschleife
           movl    d1,d5               | L(OP1) merken
           subl    d2,d1               | Laenge Uebertragungsschleife
                                       | = L(OP1) - L(OP2)
           andb    #0xce,cc            | CCR zuruecksetzen (insb.Carry)
           cmpl    #0,d2               | d2 = 0 (dh. kuerzerer OP = 0?)
           beq     transfer3           | ja => nur OP1 uebertragen
|
| Additionsschleife vorbereiten

           subl    #1,d2               | d2 = L(OP2) - 1, weil Schlei-
|                                         fenende bei -1
           addql   #4,a1               | a1 = 1. Ziffer von OP1
           addql   #4,a2               | a2 = 1. Ziffer von OP2
loop_1:    movl    d4,a3@+             | Uebertragen Summe in akt.Erg.
                                       | Zi, naechste Erg.Zi. 
           movl    a1@+,d3             | d1=akt.Zi OP1, a1 naechste Zi
           movl    a2@+,d4             | d2=akt.Zi OP2, a2 naechste Zi
           addxl   d3,d4               | d2 = Summe + Extend

           dbra     d2,loop_1           | letzte Zi OP2? nein=>Schleife
|
| Die letzte Ziffer von OP2 ist erreicht. a1 deutet auf die naechste
| Ziffern von OP1. Uebertrag vorhanden ?
|
           bcc     transfer1           | kein Uebertrag => restliche
|                                       | Ziffern von OP1 uebertragen
|
| Verfolge den Uebertrag durch den Rest von OP1.
| Carry = 1, Extend = 1 
| Gibt es noch was von OP1 zu uebertragen ?
|
          movl    d4,a3@+             | Uebertragen Summe in akt.Erg.
                                       | Zi, naechste Erg.Zi. 
          cmpl    #0,d1              | L(OP1) = L(OP2) ?
          beq     end_lp_2            | ja => nur noch Carry addieren 
|                                       | und Laenge eintragen
|
| Es sind noch Ziffern von OP1 zu uebertragen, Carry = 1
| Zweite Schleife vorbereiten
|
          subl     #1,d1            | Schleifenende bei -1
loop_2:   movl     a1@+,a3@(0)      | akt. Ergeb.Zi = akt. Zi OP1
|                                         a1 = naechste Ziffer von OP1
          addql    #1,a3@+          | Add.Carry,a3 naechste Erg.Zi.
          bcc      transfer2           | Carry=0 => Rest OP1 uebertragen
          dbra     d1,loop_2           | Ende OP1? nein=> naechste Zi.
|
| Falls dieser Punkt erreicht wird, sind beide Operanden komplett auf-
| addiert und noch ein Carrybit vorhanden.
| 
end_lp_2: movl     #1,a3@(0)           | hoechste Ergebnisziffer = 1
          movl     d5,a4@(0)           | L(Ergebnis)=L(OP1)
          addql    #1,a4@(0)           | L(Ergebnis)=L(OP1)+1
          bra      return              | Ruecksprung
|
| Kein Uebertrag mehr, L(Ergebnis) = L(OP1), einfaches Uebertragen
| der restlichen Ziffern von OP1 ins Ergebnisfeld
|
transfer1: movl    d4,a3@+             | letzte Summe OP1+OP2 eintragen
transfer2: subl    #1,d1               | Schleifenende bei -1
transfer3: movl    d5,a4@(0)           | Laengenfeld eintragen
           cmpl     #-1,d1             | ist noch was von OP1 zu ueber-
                                       | tragen ?
          beq      return              | nein => Ruecksprung
loop_3:   movl     a1@+,a3@+           | naechste Zi uebertragen, bei-
|                                          de eine Ziffer weiter
          dbra     d1,loop_3         | Ende OP1? nein => Schleife
return:   moveml   sp@+,a1/a2/a3/a4/d1/d2/d3/d4/d5 | Register zurueck-
                                       | schreiben
          rts                          | Ruecksprung  

         .data
null:    .long    0,0,0,0,0,0,0,0,0
