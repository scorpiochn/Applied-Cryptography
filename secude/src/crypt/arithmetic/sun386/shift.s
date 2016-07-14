;
;-------------------------------------------------------+-----;
;                                                       | GMD ;
;   PROC 'SHIFT'                        VERSION 1.0     +-----;
;                                          DATE 09.10.87      ;
;                                            BY BOTT WOLFGANG ;
;                                                             ;
;                                                             ;
;   DESCRIPTION PROGRAMM ZUM SHIFTEN EINER LANGEN ZAHL.       ;
;               EIN POSITIVER FAKTOR BEDEUTET LINKSSHIFT      ;
;               EIN NEGATIVER FAKTOR BEDEUTET (LOGISCHEN)     ;
;               RECHTSSCHIFT.                                 ;
;               POINTER AUF DIE OPERANDEN SIND 4 BYTE LANG.   ;
;                                                             ;
;   IN           DESCRIPTION                 ADR:             ;
;     OP1          ZU VERSCHIEBENDE ZAHL       [BP] + 6       ;
;     FAKTOR       VERSCHIEBUNGSFAKTOR         [BP] + 10      ;
;                                                             ;
;   INOUT                                                     ;
;                                                             ;
;   OUT                                                       ;
;     ERGEBNIS     ERGEBNISFELD                [BP] + 14      ;
;                                                             ;
;-------------------------------------------------------------;
;
include asmtoken.h
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
           PUBLIC  _SHIFT
           PUBLIC  _SSHIFT

_SHIFT     PROC   FAR
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

   POP     DS
   POP     ES
   LEA     BX,[OPER2]
   PUSH    BX
   MOV     BX,[BP+10]
   PUSH    BX
   LEA     BX,[OPER1]
   PUSH    BX
CALL _SSHIFT

;
; ERGEBNIS VON NEAR IN FAR UMSPEICHERN
;
   MOV     ES,[BP+14]
   MOV     DI,[BP+12]
   MOV     CX,OPER2
   SAR     CX,1
   ADD     CX,1
   LEA     SI,OPER2
   REP     MOVSW

   ADD     SP,6
   POP     SI
   POP     DI
   POP     ES
   MOV     SP,BP
   POP     BP
   RET

_SHIFT     ENDP

_SSHIFT    PROC    NEAR

;--------------------------------------;
; EIGENTLICHE SHIFT-OPERATION.         ;
; DIE POINTER AUF DIE OPERANDEN SIND   ;
; JETZT ALLE 'NEAR'.                   ;
;--------------------------------------;
   PUSH    BP
   MOV     BP,SP
   PUSH    DI
   PUSH    SI
;
;--------------------------------------;
;                                      ;
; ADRESSEN DER PARAMETER:              ;
;                                      ;
; OP1 : 4 + (BP)                       ;
; FAKTOR : 6 + (BP)                    ;
; ERGEBNIS : 8 + (BP)                  ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; LOKALE VARIABLEN WERDEN KEINE        ;
;                                      ;
;   KEINE BENOETIGT.                   ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; SONDERFAELLE BEARBEITEN: OP1 = 0     ;
; UND 'FAKTOR' = 0                     ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[4+BP]  ; ADRESSE DER AUS-
                      ; GANGSZAHL
   MOV     SI,[BX]    ; LAENGE DERSELBEN
   CMP     SI,0
   JE      ZERO
   MOV     DX,[6+BP]  ; SHIFTFAKTOR LADEN
   CMP     DX,0
   JNE     TRUESHIFT
;
;--------------------------------------;
;                                      ;
; ERGEBNIS = OP1 FALLS 'FAKTOR' = 0    ;
;                                      ;
;--------------------------------------;
;
   MOV     SI,BX      ; 'REP MOVS'-BEFEHL
   MOV     DI,[8+BP]  ; VORBEREITEN
   MOV     CX,[BX]
   SAR     CX,1
   INC     CX
   REP     MOVSW
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; FALL, DASS OP1 = 0                   ;
;                                      ;
;--------------------------------------;
;
ZEROS:                ; BP wurde auf dem Stack
   POP     BP         ; abgelegt und muá zurck-
                      ; geholt werden.
ZERO:
   MOV     BX,[8+BP]
   MOV     WORD PTR [BX],0
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; NORMALFALL: ES WIRD EIN RICHTIGER    ;
; SHIFT DURCHGEFUEHRT                  ;
;                                      ;
;--------------------------------------;
;
TRUESHIFT:
   PUSH    BP         ; 'BP' WIRD
   MOV     BP,[8+BP]  ; ALS ZEIGER
                      ; AUFS ERGEBNIS
                      ; BENOETIGT.
   CMP     DX,0       ; ART DES SHIFTS
   JNG     RIGHTSHIFT ; ENTSCHEIDEN
   JMP     LEFTSHIFT
;
;--------------------------------------;
;                                      ;
; PROGRAMM ZUM DURCHFUEHREN EINES      ;
; RECHTSSHIFTS.                        ;
;                                      ;
;--------------------------------------;
;
RIGHTSHIFT:
   NEG     DX         ; SHIFTFAKTOR
                      ; POSITIV MACHEN
   MOV     AX,DX      ; ZAHL DER GANZEN
   MOV     CX,3       ; BYTE BESTIMMEN,
   SHR     DX,CL      ; UM DIE
                      ; VERSCHOBEN WIRD
   CMP     DX,SI      ; WIRD ALLES 'WEG-
   JGE     ZEROS      ; GESCHOBEN' ?
   MOV     CX,AX      ; ZAHL DER BIT-
   AND     CX,7       ; STELLEN UM DIE
                      ; VERSCHOBEN
                      ; WERDEN SOLL
   JNZ     BITSHR
;
;--------------------------------------;
;                                      ;
; FALLS UM EIN VIELFACHES VON 8 VER-   ;
; SCHOBEN WERDEN SOLL, KANN DER        ;
; 'REP MOVS' BEFEHL ANGEWANDT WERDEN   ;
;                                      ;
;--------------------------------------;
;
   MOV     CX,SI
   SUB     CX,DX
   LEA     DI,[2+BP]
   LEA     SI,[2+BX]
   ADD     SI,DX
   REP     MOVSB
   MOV     BYTE PTR [DI],0
                      ; DA BYTEWEISE
                      ; VERSCHOBEN WIRD,
                      ; MUSS ZU EINEM
                      ; WORT VERVOLL-
                      ; STAENDIGT WERDEN
   MOV     DI,[BX]    ; LAENGE DES ERGEB-
   SUB     DI,DX      ; NISSES BESTIMMEN
   JMP     DETLGTH
;
;--------------------------------------;
;                                      ;
; FALL, DASS 'FAKTOR' >< 0 MOD 8       ;
;                                      ;
;--------------------------------------;
;
BITSHR:
   SUB     SI,DX      ; POSITION DES
   ADD     BX,DX      ; ERSTEN BENOETIG-
                      ; TEN BYTES
                      ; BESTIMMEN
   MOV     BYTE PTR [2+BX+SI],0
                      ; DIESES BYTE WIRD
                      ; IM LETZTEN DURCH-
                      ; GANG BENOETIGT
   XOR     DI,DI      ; SCHLEIFE
                      ; INITIALISIEREN
LOOPSHR:
   MOV     AX,[2+BX+DI] ; EIN WORT LADEN
   SHR     AX,CL      ; UND SHIFTEN
   MOV     BYTE PTR [2+BP+DI],AL
                      ; EIN BYTE INS ER-
                      ; GEBNIS SPEICHERN
   INC     DI         ; WEITERSCHALTEN
   CMP     DI,SI
   JL      LOOPSHR
   MOV     BYTE PTR [2+BP+DI],0
                     ; ZUM WORT ERGAENZEN
;
;--------------------------------------;
;                                      ;
; BESTIMME LAENGE DES ERGEBNISSES      ;
;                                      ;
;--------------------------------------;
;
DETLGTH:
   RCR     DI,1         ; 'DI' UNGERADE ?
   JNC     NOCORR1
   INC     DI
NOCORR1:
   SHL     DI,1
   CMP     WORD PTR [BP+DI],0
                      ; NUR HIER KOENNTE
                      ; EINE FUEHRENDE
                      ; NULL SEIN
   JNE     NOCORR2
   SUB     DI,2
NOCORR2:
   MOV     [BP],DI
   POP     BP
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; LINKSSHIFT:                          ;
;                                      ;
;--------------------------------------;
;
LEFTSHIFT:
   MOV     AX,DX
   MOV     CX,3       ; ZAHL DER ZU
   SHR     DX,CL      ; VERSCHIEBENDEN
                      ; GANZEN BYTE
                      ; BESTIMMEN
   MOV     CX,AX
   AND     CX,7       ; ZAHL DER ZU
                      ; VERSCHIEBENDEN
                      ; BITSTELLEN
                      ; BESTIMMEN
   ADD     BP,DX      ; LINKSSHIFT
                      ; BEGINNT MIT DER
                      ; HOECHSTWERTIGSTEN
                      ; ZIFFER
   MOV     SI,[BX]
   MOV     DI,SI
   MOV     AH,0       ; DIE OBERSTEN BEIDEN
                      ; BYTE WERDEN GESONDERT
                      ; BEHANDELT, UM NICHT
                      ; AUS DEM UEBERGEBENEN
                      ; BEREICH ZU KOMMEN.
   MOV     AL,[1+BX+SI]
   SHL     AX,CL
   INC     SI
   CMP     AH,0
   JNE     M1
   DEC     DI
   DEC     SI
   MOV     AX,[1+BX+DI]
   SHL     AX,CL
   CMP     AH,0
   JNE     M1
   DEC     SI
   DEC     DI
   JE      MARKE2
LOOPSHL:              ; ABARBEITEN DER REST-
                      ; LICHEN STELLEN.
   MOV     AX,[1+BX+DI]  ; EIN WORT LADEN
   SHL     AX,CL      ; SHIFTEN

M1:

   MOV     BYTE PTR [2+BP+DI],AH
                      ; EIN BYTE IM ERGEB-
                      ; NIS SPEICHERN
   DEC     DI
   JNZ     LOOPSHL

MARKE2:

   MOV     BYTE PTR [2+BP],AL
                      ; DIESES BYTE MUSS
                      ; NOCH EINGETRAGEN
                      ; WERDEN
;
;--------------------------------------;
;                                      ;
; LAENGE DES ERGEBNISSES BESTIMMEN     ;
;                                      ;
;--------------------------------------;
;
   SUB     BP,DX      ; ZEIGER ZURUECK-
                      ; SETZEN
   ADD     SI,DX      ; ZAHL DER
                      ; BELEGTEN BYTE


   MOV     DI,SI      ;LAENGE KANN UNGE-
   AND     DI,01H     ;RADE SEIN
   JZ      PARITY
   ADD     SI,1
   MOV     BYTE PTR [SI+BP+1],0
PARITY:

   MOV     [BP],SI    ;LAENGE EINTRAGEN
;
;--------------------------------------;
;                                      ;
; NACHGEZOGENE NULLEN EINTRAGEN:       ;
;                                      ;
;--------------------------------------;
;
   CMP     DX,0       ; UEBERHAUPT WAS
   JE      RETURN1    ; ZU TUN ?
   MOV     CX,DX      ; SCHLEIFE
   MOV     SI,DX      ; VORBEREITEN
   ADD     SI,1
LOOPINS0:
   MOV     BYTE PTR [BP+SI],0
   DEC     SI         ; NULLEN BYTEWEISE
   LOOP    LOOPINS0   ; EINTRAGEN
RETURN1:
   POP     BP
RETURN:
   POP     SI
   POP     DI
   MOV     SP,BP
   POP     BP
   RET

_SSHIFT    ENDP
_TEXT      ENDS

_DATA      SEGMENT
OPER1      DW      RSAINT  DUP(?)
OPER2      DW      RSAINT  DUP(?)

_DATA      ENDS
           END
