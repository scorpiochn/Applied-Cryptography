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

| Datei : shift.s
| Datum : 25.5.1988
| Inhalt: Links- bzw. Rechtsshift einer langen Zahl
|
| a1 : Adresse des Operanden (OP)
| a2 : Shiftfaktor
| a3 : Adresse des Ergebnisses
| d1 : Laenge des Operanden (OP), Schleifenzaehler 
| d2 : Anzahl der zu schiebenden Langworte
| d3 : Anzahl der zu schiebenden Bits
| d4 : 32 Minus Anzahl der zu schiebenden Bits
| d5 : Hilfsregister
| d6 : Hilfsregister
| d7 : Hilfsregister
|

         .text

          .globl   __shift

__shift:    moveml   a1/a2/a3/d1/d2/d3/d4/d5/d6/d7,sp@-  | Reg. retten
           moveml  null,a1/a2/a3/d1/d2/d3/d4/d5/d6/d7   | loeschen
|
| Adressen in Register laden
|
          moveml  sp@(44),a1/a2/a3    | a1 = Adresse von OP1
                                      | a2 = Adresse Schiebefaktor
                                      | a3 = Adresse des Ergebnisses
|
| Sonderfaelle : Operand = 0 oder Schiebefaktor = 0
|
          movl    a1@(0),d1           | d1 = L(OP)
          cmpl    #0,d1               | OP = 0 ?
          beq     zero                | ja => Sprung zu zero
          movl    a2,d2               | d2 = Schiebefaktor
          cmpl    #0,d2               | Schiebefaktor <0,>0,=0 ?
          bgt     leftshift           | > 0 => Sprung zu leftshift
          blt     rightshift          | < 0 => Sprung zu rightshift
|
| Schiebefaktor = 0, d.h. kein Schift, d.h. Operand = Ergebnis
|
loop:     movl    a1@+,a3@+           | uebertragen, a1,a3 eine Ziffer
                                      | weiter
          dbra    d1,loop             | fertig ? nein => Schleife
          bra     return              | ja => Ruecksprung
|
| Fall, dass Operand = 0
|
zero:     movl    #0,a3@(0)           | Laenge des Ergebnisses = 0
          bra     return              | Ruecksprung
|
| negativer Schiebefaktor, d.h. Rechtsshift
|
rightshift:
          negl    d2                  | d2 = |d2|
          movl    d2,d3               | Schiebefaktor merken
          lsrl    #5,d2               | d2=Faktor:32=Anzahl der zu
                                      | schiebenden Langworte
          cmpl    d1,d2               | wird um mehr als Operanden-
                                      | laenge geschoben ?
          bhi     zero                | ja => Ergebnis = 0
          movl    d2,d5               | a1 auf erste zu bearbeitende
          mulul   #4,d5               | Ziffer ausrichten
          addl    d5,a1               
          subl    d2,d1               | d1 = Zahl der zu bearbeitenden
                                      | Ziffern
          movl    d1,a3@+             | Laenge vorlaeufig eintragen,
                                      | a3 -> 1. Ziffer
          andl    #31,d3              | d3 = Anzahl der zu schieben-
                                      | den Bits = Shiftfaktor mod 32
          cmpl    #0,d3               | Shift nur in Langworten ?
          bne     bitshift1           | nein => Sprung zu bitshift1
|
| Shiftfaktor ein Vielfaches von 32, Verschieben nur der Langworte
|
          addql   #4,a1               | a1 -> 1. Ziffer des Operanden
          subql   #1,d1               | Schleifenende bei -1
loop_sh1: movl    a1@+,a3@+           | Uebertragen, a1,a3 eine Ziffer
                                      | weiter
          dbra    d1,loop_sh1         | fertig ? nein => Schleife
          bra     return              | Ruecksprung
|
| Richtiger Rechtsshift ueber Langwortgrenzen
| d1 = Schleifenzaehler, d3 = Anzahl der zu schiebenden Bits
|
bitshift1:movl    #32,d4              | d4 = 32 - Anzahld der zu
          subl    d3,d4               | schiebenden Bits
          addql   #4,a1               | a1-> 1. zu bearbeitende Zi
          subql   #1,d1               | Schleifenende bei -1
loop_shr: cmpl    #0,d1               | hoechstwertige Zi. erreicht ?
          beq     chk_lead            | ja => Sonderbehandlung 
          movl    a1@(4),d7           | d7 = hoeherwertige Ziffer
          movl    a1@+,d6             | d6 = niederwertige Ziffer
          lsrl    d3,d6               | Rechtsshift der niederwertigen
          lsll    d4,d7               | Linksshift der hoeherwertigen
          orl     d6,d7               | zusammenbasteln
          movl    d7,a3@+             | uebertragen, a3 -> naechste Zi
          dbra    d1,loop_shr         | d1=d1-1, Schleife

chk_lead: movl    a1@(0),d6           | d0 = fuehrende Ziffer
          lsrl    d3,d6               | Rechtsshift
          movl    d6,a3@(0)           | neue fuehrende Ziffer eintra-
                                      | gen

          cmpl    #0,d6               | Shiftergebnis = 0 ?
          beq     no_lead             | ja => weiter bei no_lead
          bra     return              | Ruecksprung

no_lead:  movl    sp@(52),a3          | Anfangsadresse Ergebnis zu-
                                      | rueckholen
          subql   #1,a3@(0)           | Laenge Ergebnis um 1 vermin-
                                      | dern
          bra     return              | Ruecksprung

|
| Positiver Schiebefaktor, Leftshift
|
leftshift:
          movl     d2,d3              | Schiebefaktor merken
          lsrl     #5,d2              | d2 = Anzahl der zu schieben-
                                      | den Langworte
          movl     d2,sp@-            | auf Stack merken
          movl     #4,d5             
          mulul    d1,d5              | d5=Laenge(Operand) in Byte
          addl     d5,a1
          addql    #4,a1              | a1->vor fuehrende Zi Operand
          addl     d1,d2              | d2 = vorlaeufige Laenge Ergb.
          movl     d2,a3@+            | vorlaeufige Laenge eintragen,
                                      | a3->1. Zi Ergebnis
          movl     #4,d5              | d5=Laenge(Ergebnis) in Byte
          mulul    d2,d5              | d5=vorlaeufige Laenge Ergebnis
          addl     d5,a3              |a3->vor fuehrende Zi Ergebnis       

          andl     #31,d3             | d3=Anzahl der zu schieb. Bits
          cmpl     #0,d3              | nur Langworte schieben ?
          bne      bitshift2          | nein => weiter bei bitshift2
|
| Shiftfaktor Vielfaches von 32, d.h. nur Langworte schieben
|
          subql    #1,d1              | d1 Schleifenzaehler
loopsh2:  movl     a1@-,a3@-          | schieben
          dbra     d1,loopsh2         | fertig ? nein => Schleife
          bra      zerofll2           | jetzt noch nullen eintragen

bitshift2:movl     #32,d4
          subl     d3,d4              | d4 = 32-Anzahl der Schiebebits
          movl     a1@-,d6            | d6=fuehrende Zi Operand
          lsrl     d4,d6              | schieben
          cmpl     #0,d6              | alles weggeschoben ?
          beq      comp
          movl     d6,a3@(0)          | nein => eintragen und Laenge
          negl     d5                 | fuer Pointer auf L-Feld Ergeb.
          addql    #1,a3@(-4,d5:l)     | L-Ergebnis eins hoeher
comp:     cmpl     #1,d1              | schon fertig?
          beq      zerofill           
          subql    #2,d1              | es werden L(OP)-2 Stellen
                                      | in der Schleife bearbeitet.
loop_shl: movl     a1@(0),d6          | d6 hoeherwertige Ziffer
          movl     a1@-,d7            | d7 niederwertige Ziffer
          lsll     d3,d6
          lsrl     d4,d7
          orl      d6,d7
          movl     d7,a3@-
          dbra     d1,loop_shl
zerofill: movl     a1@(0),d6          | d6 = niederwertigste Ziffer
          lsll     d3,d6              | schieben
          movl     d6,a3@-            | eintragen
zerofll2: movl     sp@+,d7            | d7 = Anzahl zu schiebender 
                                       | Langworte
          cmpl     #0,d7              | = 0?
          beq      return
          subql    #1,d7
loop_zero:movl     #0,a3@-
          dbra     d7,loop_zero


return:   moveml   sp@+,a1/a2/a3/d1/d2/d3/d4/d5/d6/d7 | Reg. zurueck
        
  rts                         | Ruecksprung

          .data
null:     .long    0,0,0,0,0,0,0,0,0,0,0,0,0 | 13 Langworte 0 zum Loeschen

