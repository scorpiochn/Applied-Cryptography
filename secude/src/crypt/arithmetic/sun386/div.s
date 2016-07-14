;
;-------------------------------------------------------+-----;
;                                                       | GMD ;
;   PROC DIV                            VERSION 1.0     +-----;
;                                          DATE 15.10.87      ;
;                                            BY BOTT WOLFGANG ;
;                                                             ;
;                                                             ;
;   DESCRIPTION GANZZAHLIGE DIVISION VON ZWEI LANGEN ZAHLEN   ;
;               OPERANDEN UND ERGEBNISFELDER DUERFEN GLEICH   ;
;               SEIN. DABEI UEBERSCHREIBT GEGEBENENFALLS      ;
;               DER REST DEN QUOTIENTEN                       ;
;               POINTER AUF DIE OPERANDEN SIND 4 BYTE LANG.   ;
;                                                             ;
;   IN             DESCRIPTION                 ADR:           ;
;     DIVIDENT       ALS LANGE ZAHL            [BP] + 6       ;
;     DIVISOR        ALS LANGE ZAHL            [BP] + 10      ;
;                                                             ;
;   INOUT                                                     ;
;                                                             ;
;   OUT                                                       ;
;     QUOTIENT       ALS LANGE ZAHL            [BP] + 14      ;
;     REST           ALS LANGE ZAHL            [BP] + 18      ;
;                                                             ;
;-------------------------------------------------------------;
;
include asmtoken.h
;
   EXTRN   _SSHIFT:NEAR
;
;--------------------------------------;
;                                      ;
; BLOCKSTRUKTUR DEFINIEREN.            ;
;                                      ;
;--------------------------------------;
;
_TEXT      SEGMENT BYTE PUBLIC 'CODE'
_TEXT      ENDS
_DATA      SEGMENT WORD PUBLIC 'DATA'
_DATA      ENDS
CONST      SEGMENT WORD PUBLIC 'CONST'
CONST      ENDS
_BSS       SEGMENT WORD PUBLIC 'BSS'
_BSS       ENDS
;
DGROUP     GROUP _DATA,_BSS,CONST
ASSUME CS:_TEXT,DS:DGROUP,SS:DGROUP,ES:DGROUP

;
;--------------------------------------;
;                                      ;
; PROGRAMMTEXT:                        ;
;                                      ;
; ZUERST REGISTER RETTEN.              ;
;                                      ;
;--------------------------------------;
;
_TEXT      SEGMENT
PUBLIC     _DIV

_DIV       PROC   FAR
   PUSH    BP
   MOV     BP,SP
   PUSH    ES
   PUSH    DI
   PUSH    SI
   PUSH    DS
   PUSH    DS
   PUSH    DS

;
; OPERAND1 VON FAR IN NEAR UMSPEICHERN
;
   POP     ES         ; REP MOVS BEFEHL
   MOV     DS,[BP+8]  ; VORBEREITEN.
   MOV     SI,[BP+6]  ; SOURCE = DS:SI
   LEA     DI,OPER1   ; DEST   = ES:DI
   MOV     CX,DS:[SI] ; COUNT  = CX
   SAR     CX,1
   ADD     CX,1
   REP     MOVSW

;
; OPERAND2 VON FAR IN NEAR UMSPEICHERN
;
   MOV     DS,[BP+12]
   MOV     SI,[BP+10]
   LEA     DI,OPER2
   MOV     CX,DS:[SI]
   SAR     CX,1
   ADD     CX,1
   REP     MOVSW

;
; EIGNETLICHE DIVISION AUFRUFEN
;
   POP     DS
   POP     ES
   LEA     BX,[OPER4]
   PUSH    BX
   LEA     BX,[OPER3]
   PUSH    BX
   LEA     BX,[OPER2]
   PUSH    BX
   LEA     BX,[OPER1]
   PUSH    BX

   CALL _SDIV
;
; ERGEBNIS VON NEAR IN FAR UMSPEICHERN
;
   MOV     ES,[BP+16]
   MOV     DI,[BP+14]
   MOV     CX,OPER3
   SAR     CX,1
   ADD     CX,1
   LEA     SI,OPER3
   REP     MOVSW
;
; REST VON NEAR IN FAR UMSPEICHERN
;
   MOV     ES,[BP+20]
   MOV     DI,[BP+18]
   MOV     CX,OPER4
   SAR     CX,1
   ADD     CX,1
   LEA     SI,OPER4
   REP     MOVSW

   ADD     SP,8
   POP     SI
   POP     DI
   POP     ES
   MOV     SP,BP
   POP     BP
   RET

_DIV       ENDP

_SDIV      PROC    NEAR
;
;--------------------------------------;
; EIGENTLICHES SUBTRAKTIONSPROGRAMM.   ;
; DIE POINTER AUF DIE OPERANDEN SIND   ;
; JETZT ALLE 'NEAR'.                   ;
;                                      ;
; ADRESSEN DER PARAMETER:              ;
;                                      ;
; DIVIDENT: 4 + (BP)                   ;
; DIVISOR:  6 + (BP)                   ;
; QUOTIENT: 8 + (BP)                   ;
; REST:    10 + (BP)                   ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; LOKALE VARIABLEN:                    ;
;                                      ;
; DIVIDENT : EIN FELD, IN DEM DER      ;
;            REST BERECHNET WIRD       ;
; SFAKTOR  : ERWEITERUNGSFAKTOR        ;
; TEST     : EINE ZIFFER DES TESTFELDES;
; ZQUOT    : AKTUELLE ZIFFER DES       ;
;            QUOTIENTEN, DER IM FELD   ;
; QUOTIENT : BERECHNET WIRD            ;
; FIRSTDIGIT : ERSTE ZIFFER DES        ;
;              DIVISORS                ;
;                                      ;
;  **** VORSICHT ****                  ;
;                                      ;
;  DIE ARBEITSFELDER 'DIVIDENT' UND    ;
;  'QUOTIENT' MUESSEN LANG GENUG SEIN, ;
;  UM DIE OPERANDEN AUFNEHMEN ZU       ;
;  KOENNEN.                            ;
;  DIESE LAENGE IST IN DER DATEI       ;
;  RSANUMBER.H DEFINIERT.              ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; ZUERST REGISTER RETTEN.              ;
;                                      ;
;--------------------------------------;
;
   PUSH    BP
   MOV     BP,SP
   PUSH    DI
   PUSH    SI
;
;--------------------------------------;
;                                      ;
; SONDERFAELLE BEARBEITEN:             ;
;                                      ;
; DIVISION DURCH NULL?                 ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[6+BP]   ; ADRESSE DES
                       ; DIVISORS
   CMP     WORD PTR [BX],0
   JNE     NOERROR     ; DIVISOR <> 0 ?
   MOV     AX,-1       ; C-RETURNCODE
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; DIVIDENT KLEINER ALS DIVISOR?        ;
;                                      ;
;--------------------------------------;
;
NOERROR:
   MOV     SI,[4+BP]   ; ADRESSE DIVIDENT
   MOV     CX,[SI]     ; LAENGE DIVIDENT
   CMP     CX,[BX]     ; LAENGENVERGLEICH
   JGE     NOTTRIVIAL
   MOV     BX,[8+BP]   ; QUOTIENT = 0
   MOV     WORD PTR [BX],0
   MOV     DI,[10+BP]  ; REST = DIVIDENT
   MOV     [DI],CX     ; LAENGENFELD DES
                       ; DIVIDENTEN
                       ; KOENNTE UEBER-
                       ; SCHRIEBEN WORDEN
                       ; SEIN
   ADD     DI,2        ; 'REP MOVS'-BEFEHL
   ADD     SI,2        ; VORBEREITEN
   SHR     CX,1
   REP     MOVSW
   XOR     AX,AX       ; RETURNCODE = 0
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; HAT DER DIVISOR NUR EINE ZIFFER?     ;
;                                      ;
;--------------------------------------;
;
NOTTRIVIAL:
   CMP    WORD PTR [BX],2
   JNE    NOTSHORT
;
;--------------------------------------;
;                                      ;
; DIVISION DURCH EINE EINSTELLIGE      ;
; ZAHL IST LEICHT:                     ;
;                                      ;
;--------------------------------------;
;
   MOV     CX,[2+BX]   ; ZIFFER DES
                       ; DIVISORS LADEN
   MOV     DI,[SI]     ; LAENGE DES DIVI-
                       ; DENTEN LADEN
   MOV     BX,SI       ; ADRESSE DIVIDENT
   PUSH    BP          ; 'BP' RETTEN
   MOV     BP,[8+BP]   ; ADRESSE QUOTIENT
   XOR     DX,DX       ; HOCHWERTIGER
                       ; TEIL DES
                       ; DOPPELREGISTERS
                       ; LOESCHEN
LOOPSDIV:
   MOV     AX,[BX+DI]  ; ZIFFER DES DIVI-
                       ; DENTEN LADEN
   DIV     CX          ; DIVIDIEREN
   MOV     [BP+DI],AX  ; ZIFFER DES QUO-
                       ; TIENTEN SPEICHERN
   SUB     DI,2        ; INDEX FORTSCHALTEN
   JNZ     LOOPSDIV
   MOV     DI,[SI]     ; LAENGE DES QUO-
                       ; TIENTEN BESTIMMEN
   CMP     WORD PTR [BP+DI],0
   JNE     NOCORRQ1
   SUB     DI,2
NOCORRQ1:
   MOV     [BP],DI     ; LAENGE EINTRAGEN
   POP     BP          ; 'BP' VOM STACK
                       ; HOLEN
   MOV     BX,[10+BP]  ; REST BESTEHT AUS
   CMP     DX,0        ; EINER ZIFFER
   JNE     NOTZERO     ; DIESE KANN ABER
                       ; NULL SEIN
   MOV     WORD PTR [BX],0
   XOR     AX,AX       ; RETURNCODE = 0
   JMP     RETURN
NOTZERO:
   MOV     [2+BX],DX
   MOV     WORD PTR [BX],2
   XOR     AX,AX       ; RETURNCODE = 0
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; ECHTE DIVISION MUSS DURCHGEFUEHRT    ;
; WERDEN.                              ;
; ERSTER SCHRITT: UEBERTRAGEN DES      ;
; DIVIDENTEN IN EIN ARBEITSFELD        ;
;                                      ;
;--------------------------------------;
;
NOTSHORT:
   LEA     DI,DIVIDENT
   SHR     CX,1
   INC     CX
   REP     MOVSW
;
;--------------------------------------;
;                                      ;
; ZWEITER SCHRITT: ERWEITERN VON       ;
; DIVISOR UND DIVIDENT                 ;
;                                      ;
;--------------------------------------;
;
   MOV     SI,[BX]     ; HOECHSTWERTIGSTE
   MOV     AX,[BX+SI]  ; ZIFFER DES
                       ; DIVISORS LADEN
   AND     AX,AX       ; HOECHSTWERTIGSTES
   JNS     SHIFT       ; BIT BELEGT ?
   MOV     SFAKTOR,0   ; DANN KEIN SHIFTEN
   JMP     STARTDIV
SHIFT:
   XOR     CX,CX       ; SHIFTFAKTOR BESTIM-
LOOPSHIFT:             ; MEN DURCH SHIFTEN
   INC     CX          ; NACH LINKS
   SHL     AX,1        ; NACH LINKS
   JNS     LOOPSHIFT
   MOV     SFAKTOR,CX  ; SHIFTFAKTOR
                       ; SPEICHERN
   LEA     DX,DIVIDENT ; UNTERPROGRAMM
   PUSH    DX          ; 'SHIFT' FUER DEN
   PUSH    CX          ; DIVIDENTEN AUF-
   PUSH    DX          ; RUFEN
   CALL    _SSHIFT
   ADD     SP,6
   MOV     BX,[6+BP]   ; DAS GLEICHE FUER
   PUSH    BX          ; DEN DIVISOR
   MOV     CX,SFAKTOR
   PUSH    CX
   PUSH    BX
   CALL    _SSHIFT
   ADD     SP,6
;
;--------------------------------------;
;                                      ;
; DRITTER SCHRITT: DIVISION            ;
;                                      ;
;--------------------------------------;
;
STARTDIV:
   MOV     BX,[6+BP]   ; ADRESSE DIVISOR
   MOV     SI,[BX]     ; INDEXREGISTER
                       ; FUER SCHLEIFEN
                       ; UEBER DEN DIVISOR
   MOV     AX,[BX+SI]  ; HOECHSTWERTIGSTE
   MOV     FIRSTDIGIT,AX
                       ; ZIFFER DES
                       ; DIVISORS WIRD
                       ; DAUERND GEBRAUCHT
   MOV     DI,DIVIDENT ; ZAHL DER DIVISIONS-
   SUB     DI,SI       ; SCHRITTE BESTIMMEN
                       ; 'DI' IST INDEX-
                       ; REGISTER FUER
                       ; 'QUOTIENT'
   PUSH    BP          ; 'BP' RETTEN
   LEA     BP,[DIVIDENT+DI]
                       ; 'BP' IST BASIS-
                       ; REGISTER FUER
                       ; 'DIVIDENT'
   MOV     WORD PTR [2+BP+SI],0
                       ; DIESE ZIFFER WIRD
                       ; IN DER ERSTEN DIVI-
                       ; SION GEBRAUCHT
;
;--------------------------------------;
;                                      ;
; SCHLEIFE ZUR DIVISION:               ;
;                                      ;
;--------------------------------------;
;
MAINLOOP:
   MOV     DX,[2+BP+SI];HOECHSTWERTIGSTE
                       ; ZIFFER DES DIVI-
                       ; DENTEN LADEN
   CMP     DX,FIRSTDIGIT
                       ; FALLS GLEICH,
   JNE     DODIVIDE    ; DIVISION NICHT
                       ; MOEGLICH
   MOV     ZQUOT,-1    ; DAS IST DANN DIE
                       ; AKTUELLE ZIFFER
                       ; DES QUOTIENTEN
   JMP     DOTEST
DODIVIDE:
   MOV     AX,[BP+SI]  ; ZWEITHOECHSTE
                       ; ZIFFER DES DIVI-
                       ; DENTEN LADEN
   DIV     FIRSTDIGIT  ; UND DIVIDIEREN
   MOV     ZQUOT,AX    ; ERGIBT AKTUELLE
                       ; ZIFFER DES
                       ; QUOTIENTEN
;
;--------------------------------------;
;                                      ;
; NAEHERUNG FUER DEN QUOTIENTEN WIRD   ;
; AN ZWEI ZIFFERN GETESTET             ;
;                                      ;
;--------------------------------------;
;
DOTEST:
   MOV     AX,[-2+BX+SI]
                       ; ZWEITHOECHSTE
                       ; ZIFFER DES
                       ; DIVISORS
   MUL     ZQUOT       ; MULTIPLIZIEREN
                       ; MIT DER
                       ; GEFUNDENEN
                       ; ZIFFER DES
                       ; QUOTIENTEN
   MOV     CX,DX       ; UEBERTRAG MERKEN
   MOV     TEST,AX
   MOV     AX,FIRSTDIGIT
                       ; HOECHSTWERTIGSTE
                       ; ZIFFER DES
                       ; DIVISORS
   MUL     ZQUOT
   ADD     AX,CX       ; UEBERTRAG ADDIEREN
   JNC     NOCARRY1    ; DABEI KOENNTE ES
   INC     DX          ; EINEN NEUEN UEBER-
                       ; TRAG GEBEN
NOCARRY1:
   MOV     TEST+2,AX   ; ERGEBNIS SPEICHERN
   MOV     TEST+4,DX   ; IM TESTFELD
;
;--------------------------------------;
;                                      ;
; DER VERGLEICH DER DES TESTFELDES     ;
; MIT DEN ZIFFERN DES DIVIDENTEN MUSS  ;
; BYTEWEISE ERFOLGEN, DA DER 'CMP'-    ;
; BEFEHL DAS VORZEICHEN BERUECKSICHTIGT;
;                                      ;
;--------------------------------------;
;
   XOR     AX,AX       ; LOESCHEN FUER
   XOR     DX,DX       ; DEN BYTEWEISEN
                       ; VERGLEICH
   PUSH    DI          ; 'DI' WIRD
                       ; BENOETIGT
   LEA     DI,[3+SI]   ; SCHLEIFE ZUM
   MOV     SI,5        ; VERGLEICH
   MOV     CX,6        ; VORBEREITEN
LOOPCMP:
   MOV     AL,BYTE PTR [TEST+SI]
                       ; EIN BYTE DES TEST-
                       ; FELDES LADEN
   MOV     DL,[BP+DI]  ; EIN BYTE DES DIVI-
                       ; DENTEN LADEN
   CMP     AX,DX       ; VERGLEICHEN
   JL      OKAY
   JG      DOCORRECT
   DEC     SI          ; ZEIGER
   DEC     DI          ; FORTSCHALTEN
   LOOP    LOOPCMP
   JMP     OKAY
DOCORRECT:
   DEC     ZQUOT       ; PROBEQUOTIENT
                       ; MUSS VERKLEINERT
                       ; WERDEN
;
;--------------------------------------;
;                                      ;
; DIVISOR * QUOTIENT WIRD NUN VOM      ;
; DIVIDENTEN ABGEZOGEN                 ;
;                                      ;
;--------------------------------------;
;
OKAY:
   POP     DI          ; 'DI' ZURUECKHOLEN
   MOV     SI,2        ; ZEIGER SETZEN
   XOR     CX,CX       ; UEBERTRAG LOESCHEN
LOOPSUB:
   MOV     AX,[BX+SI]  ; ZIFFER DES
                       ; DIVISORS LADEN
   MUL     ZQUOT       ; MULTIPLIZIEREN
   ADD     AX,CX       ; UEBERTRAG ADDIEREN
   JNC     NOCARRY2    ; DABEI KANN EIN
   INC     DX          ; NEUER UEBERTRAG
                       ; AUFTRETEN
NOCARRY2:
   SUB     [BP+SI],AX  ; VON DER ENTSPRECH-
                       ; ENDEN ZIFFER DES
                       ; DIVIDENTEN ABZIEHEN
   JNC     NOCARRY3    ; WIEDER KANN EIN
   INC     DX          ; UEBERTRAG ENT-
                       ; STANDEN SEIN
NOCARRY3:
   MOV     CX,DX       ; UEBERTRAG MERKEN
   ADD     SI,2        ; ZEIGER FORTSCHALTEN
   CMP     SI,[BX]     ; ALLE ZIFFERN DES
                       ; QUOTIENTEN BEAR-
   JNG     LOOPSUB     ; BEITET ?
;
;--------------------------------------;
;                                      ;
; NUN ENTSCHEIDET SICH, OB DER         ;
; QUOTIENT ZU GROSS WAR:               ;
;                                      ;
;--------------------------------------;
;
   SUB     [BP+SI],CX  ; LETZTEN UEBERTRAG
                       ; SUBTRAHIEREN
   JNC     NOREADD
;
;--------------------------------------;
;                                      ;
; DIVISOR MUSS EINMAL AUF DEN DIVI-    ;
; DENTEN AUFADDIERT WERDEN             ;
;                                      ;
;--------------------------------------;
;
   DEC     ZQUOT       ; ZIFFER DES QUO-
                       ; TIENTEN VERMINDERN
   MOV     SI,2        ; NEUE SCHLEIFE
   MOV     CX,[BX]     ; INITIALISIEREN
   SHR     CX,1
   CLC                 ; UEBERTRAG LOESCHEN
LOOPREADD:
   MOV     AX,[BX+SI]  ; ZIFFER DES QUO-
                       ; TIENTEN LADEN
   ADC     [BP+SI],AX  ; AUF ENTSPRECHENDE
                       ; ZIFFER DES DIVI-
                       ; DENTEN ADDIEREN
   INC     SI          ; ZEIGER WEITER-
   INC     SI          ; SCHALTEN, OHNE
                       ; CARRYBIT ZU AENDERN
   LOOP    LOOPREADD
   MOV     WORD PTR [BP+SI],0
                       ; HIER MUSS NUN 0 HIN
;
;--------------------------------------;
;                                      ;
; HAUPTSCHLEIFE FAST BEENDET: ZEIGER   ;
; WIRD NOCH WEITERGESCHALTET UND DIE   ;
; ZIFFER DES QUOTIENTEN EINGETRAGEN    ;
;                                      ;
;--------------------------------------;
;
NOREADD:
   MOV     AX,ZQUOT
   MOV     [QUOTIENT+2+DI],AX
   SUB     BP,2
   MOV     SI,[BX]
   SUB     DI,2
   JS      ENDDIV
   JMP     MAINLOOP
;
;--------------------------------------;
;                                      ;
; ENDE DER DIVISION: LAENGE DES        ;
; QUOTIENTEN UND DES RESTES - ER       ;
; STEHT IM FELD 'DIVIDENT' - BESTIMMEN ;
;                                      ;
;--------------------------------------;
;
ENDDIV:
   MOV     SI,[BX]     ; DIE LAENGE DES
   MOV     DI,[2+BP]   ; QUOTIENTEN IST BIS
   SUB     DI,SI       ; AUF EINE STELLE
                       ; FESTGELEGT
   CMP     WORD PTR [QUOTIENT+2+DI],0
   JE      NOCORRQ2
   ADD     DI,2
NOCORRQ2:
   MOV     QUOTIENT,DI
LOOPCHKLGTH:           ; LAENGE DER RESTES
                       ; KANN NICHT VORHER-
                       ; GESAGT WERDEN UND
                       ; MUSS IN EINER
                       ; SCHLEIFE BESTIMMT
                       ; WERDEN.
   CMP     WORD PTR [DIVIDENT+SI],0
   JNE     FOUND
   SUB     SI,2
   JNZ     LOOPCHKLGTH
FOUND:
   MOV     DIVIDENT,SI
;
;--------------------------------------;
;                                      ;
; ERWEITERUNG RUECKGAENGIG MACHEN      ;
;                                      ;
;--------------------------------------;
;
   POP     BP
   CMP     SFAKTOR,0
   JE      NORESHIFT
   MOV     SI,SFAKTOR
   NEG     SI
   PUSH    BX          ; ERSTER AUFRUF
   PUSH    SI          ; VON 'SHIFT' FUER
   PUSH    BX          ; DEN DIVISOR
   CALL    _SSHIFT
   ADD     SP,6
   LEA     BX,DIVIDENT
   PUSH    BX          ; ZWEITER AUFRUF VON
   MOV     SI,SFAKTOR  ; 'SHIFT' FUER DEN
   NEG     SI          ; REST DER DIVISION
   PUSH    SI
   PUSH    BX
   CALL    _SSHIFT
   ADD     SP,6
;
;--------------------------------------;
;                                      ;
; ERGEBNISSE UEBERTRAGEN; QUOTIENT     ;
; KOMMT ZUERST DRAN UND WIRD DABEI     ;
; EVENTUELL UEBERSCHRIEBEN VOM REST.   ;
;                                      ;
;--------------------------------------;
;
NORESHIFT:
   MOV     CX,QUOTIENT
   SHR     CX,1
   INC     CX
   MOV     DI,[8+BP]
   LEA     SI,QUOTIENT
   REP     MOVSW
   MOV     CX,DIVIDENT
   SHR     CX,1
   INC     CX
   MOV     DI,[10+BP]
   LEA     SI,DIVIDENT
   REP     MOVSW
   XOR     AX,AX

RETURN:
   POP     SI
   POP     DI
   MOV     SP,BP
   POP     BP
   RET

_SDIV      ENDP
_TEXT      ENDS

_DATA      SEGMENT
   PUBLIC  TEST,SFAKTOR,ZQUOT
   PUBLIC  QUOTIENT,FIRSTDIGIT,DIVIDENT

TEST       DW      3 DUP(?)
SFAKTOR    DW      0
ZQUOT      DW      0
QUOTIENT   DW      RSAINT  DUP(?)
OPER1      DW      RSAINT  DUP(?)
           DW      RSAINT  DUP(?)
OPER2      DW      RSAINT  DUP(?)
OPER3      DW      RSAINT  DUP(?)
OPER4      DW      RSAINT  DUP(?)
FIRSTDIGIT DW      0
DIVIDENT   DW      RSAINT  DUP(?)
           DW      RSAINT  DUP(?)
_DATA      ENDS
           END

;-------------------------------------------------------------;
; E N D   O F   P R O C E D U R E   DIV                       ;
;-------------------------------------------------------------;
