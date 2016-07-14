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

| Datei : mult.s
| Datum : 11.5.1988
| Inhalt: Multiplizieren zweier langer Zahlen
|
| a0 : Adresse des Akkumulators acc
| a1 : Adresse des ersten Operanden (OP1)
| a2 : Adresse des zweiten Operanden (OP2)
| a3 : Adresse des Produkts
| a4 : Hilfsregister (Adresse von OP1)
| a5 : Hilfsregister (Adresse von OP2)
| a6 : Hilfsregister (Adresse des Produkts)
| d0 : Returncode (Standard)
| d1 : Laenge des ersten Operanden (OP1), Schleifenzaehler fuer die 
|      aeussere Schleife
| d2 : Laenge des yweiten Operanden (OP2), Schleifenzaehler fuer die
|      innere Schleife
| d3 : Hilfsregister zur Multiplikation, niederwertiger Teil des
|      Produkts
| d4 : Hilfsregister zur Multiplikation, hoeherwertiger Teil des
|      Produkts
| d5 : Uebertrag  aus der inneren Schleife
|

         .lcomm acc,2*(4*60)

         .text

          .globl   __mult

__mult:    moveml a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5,sp@-  | retten

          moveml  null,a0/a1/a2/a3/a4/a5/a6/d0/d1/d2/d3/d4/d5 | loeschen
|
| Adressen in Register laden
|
          moveml  sp@(52),a1/a2/a3    | a1 = Adresse von OP1
                                      | a2 = Adresse von OP2
                                      | a3 = Adresse von OP3
          lea     acc,a0         | a0 = Adresse des Akkumulator
|
| Ein Operand = 0 ?
|
          cmpl    #0,a1@(0) 
          beq     zero
          cmpl    #0,a2@(0)
          bne    mult
zero:     movl    #0,a3@(0)           | Ergebnis = 0
          bra     return
|
| Erste Schleife : Inhalt des vorlaeufigen Ergebnisfeldes muss noch
| nicht beruecksichtigt werden.
|
mult:     movl    #0,d5               | Uebertrag loeschen
          moveml  sp@(52),a4/a5       | Adressen retten 
          movl    a1@+,d1             | d1=L(OP1), a1 = 1. Zi OP1
          movl    a2@+,d2             | d2=L(OP2), a2 = 1. Zi OP2
          subql   #1,d2               | Schleifenende bei -1
loop_1:   movl    a1@(0),d3           | d3 = 1. Zi OP1
          mulul   a2@+,d4:d3          | multipl. 1.Zi OP1 mit akt.Zi
                                      | OP2, d4=hoeherwertiger,d3=
                                      | niederwertiger Teil d. Prod.
          addl     d5,d3              | Addiere Uebertrag auf nie-
                                      | derwertigen Teil
          bcc     no_carry1           | Uebertrag ?
          addql   #1,d4               | ja => addiere 1 auf hoeher-
                                      | wertigen Teil
no_carry1:movl    d3,a0@+             | niederwertigen Teil in Akkumu-
                                      | lator, a3 eine Zi weiter
          movl    d4,d5               | Uebertrag merken
          dbra    d2,loop_1           | OP2 fertig ? nein => Schleife
          movl    d5,a0@(0)           | ja => letzten Uebertrag in
                                      | vorlaeuf. Erg. eintragen
|
| Eigentliche Multiplikation mit Beruecksichtigung des vorlaeufigen
| Inhalts des Ergebnisfelds
|  
          subql   #1,d1               
          cmpl    #0,d1               | schon Ende OP1 erreicht ?
          beq     weiter              | ja => Ende Multiplikation
          subql   #1,d1               | Schleifenende bei -1
|
| Aeussere Schleife ( laeuft ueber die Ziffern von OP1)
|
          lea     acc,a6              | a6 = Adresse des Akkumulators
out_loop: addql   #4,a6               | a6 = niederwertigste relevan-
                                      | te (dh. als Uebertrag aufzu-
                                      | addierende) Ergebnisstelle
          movl    a6,a0               | Uebertragsregister laden
          movl    a5,a2               | OP2 wieder von Ende an be-
          movl    a2@+,d2             | arbeiten
          subql   #1,d2
          addql   #4,a1               | a1 = naechste Zi OP1
          movl    #0,d5               | Uebertrag loeschen
|
| Innere Schleife (laeuft ueber die Ziffern von OP2)
|
in_loop:  movl    a1@(0),d3           | d3 = akt. Zi OP1
          mulul   a2@+,d4:d3          | multiplizieren (wie oben)
          addl    d5,d3               | Uebertrag auf niederwertigen
                                      | Teil addieren
          bcc     no_carry2           | Uebertrag ? 
          addql   #1,d4               | ja => 1 auf hoeherwertigen 
                                      | Teil addieren
no_carry2:movl    d4,d5               | Uebertrag merken
          addl    d3,a0@+             | niederwertigen Teil auf ent-
                                      | spr. Akkumulatorziffer addieren
          bcc     no_carry3           | Uebertrag ? 
          addql   #1,d5               | ja => 1 auf Uebertrag addiern
no_carry3:dbra    d2,in_loop          | Ende OP2 ? nein => Schleife
          movl    d5,a0@(0)           | ja => letzten Uebertrag in
                                      | Akkumulatorfeld eintragen
ende_krit:dbra    d1,out_loop         | Ende OP1 ? nein => Schleife
|
| Multiplikation beendet; letzten Uebertrag zwischenspeichern, Laen-
| genfeld eintragen und Ergebnis in das eigentliche Ergebnisfeld
| uebertragen
|
weiter:   movl    d5,a0@(0)           | letzten Uebertrag zwischen-
                                      | speichern
          movl    a4@(0),d1           | d1 = L(OP1)
          addl    a5@(0),d1           | d1 = L(OP1) + L(OP2)
          cmpl    #0,a0@(0)           | nur die kann = 0 sein
          bne     l_field             | wenn nein, dann Laenge eintr.
          subql   #1,d1               | wenn ja, Ergebnis um 1 kuerzer
l_field:  movl    sp@(60),a3          | a3 = Adresse vom Ergebnis
          movl    d1,a3@+             | Laenge eintragen
          lea     acc,a0              | Anfangsadresse Akkumulator laden  
          subl    #1,d1               | d1 = Schleifenzaehler fuer die
                                      | Uebertragungsschleife, Ende bei -1
 loop_2:  movl    a0@+,a3@+           | Ergebnis uebertragen
          dbra    d1,loop_2           | Ende des Akkumulators erreicht ?
                                      | ja => Ende    
return:   moveml  sp@+,a0/a1/a2/a3/a4/a5/a6/d1/d2/d3/d4/d5 
                                      | Registerinhalte zurueckschreiben 
          rts

          .data
null:     .long    0,0,0,0,0,0,0,0,0,0,0,0,0 | 13 Langworte 0 zum Loeschen

