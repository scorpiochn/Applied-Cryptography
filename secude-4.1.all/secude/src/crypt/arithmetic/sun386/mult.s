;
;-------------------------------------------------------+-----;
;                                                       | GMD ;
;   PROC MULT                           VERSION 1.0     +-----;
;                                          DATE 10.12.87      ;
;                                            BY BOTT WOLFGANG ;
;                                                             ;
;                                                             ;
;   DESCRIPTION MULTIPLIZIERT ZWEI LANGE ZAHLEN               ;
;               OPERANDEN UND ERGEBNISFELDER KOENNEN GLEICH   ;
;               SEIN.                                         ;
;               POINTER AUF DIE OPERANDEN SIND 4 BYTE LANG.   ;
;                                                             ;
;   IN             DESCRIPTION                 ADR:           ;
;     OP1            1. FAKTOR                   [BP] + 6     ;
;     OP2            2. FAKTOR                   [BP] + 10    ;
;                                                             ;
;   INOUT                                                     ;
;                                                             ;
;   OUT                                                       ;
;     ERGEBNIS       1. FAKTOR * 2. FAKTOR       [BP] + 14    ;
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
;--------------------------------------;
;
_TEXT      SEGMENT
           PUBLIC  _MULT
_MULT      PROC   FAR
;
;--------------------------------------;
;                                      ;
; ZUERST REGISTER RETTEN.              ;
;                                      ;
;--------------------------------------;
;
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
; EIGNETLICHE MULTIPLIKATIION AUFRUFEN
;
   POP     DS
   POP     ES
   LEA     BX,[OPER3]
   PUSH    BX
   LEA     BX,[OPER2]
   PUSH    BX
   LEA     BX,[OPER1]
   PUSH    BX

   CALL _SMULT

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

   ADD     SP,6
   POP     SI
   POP     DI
   POP     ES
   MOV     SP,BP
   POP     BP
   RET

_MULT      ENDP

;--------------------------------------;
; EIGENTLICHES MULTIPLIKATIONSPROGRAMM.;
; DIE POINTER AUF DIE OPERANDEN SIND   ;
; JETZT ALLE 'NEAR'.                   ;
;--------------------------------------;
_SMULT     PROC    NEAR
;
;--------------------------------------;
;                                      ;
; ADRESSEN DER PARAMETER:              ;
;                                      ;
; OP1 :      4 + [BP]                  ;
; OP2 :      6 + [BP]                  ;
; ERGEBNIS : 8 + [BP]                  ;
;                                      ;
;--------------------------------------;
;
OP1      EQU  4 + [BP]
OP2      EQU  6 + [BP]
ERG      EQU  8 + [BP]
;
;--------------------------------------;
;                                      ;
; LOKALE VARIABLEN:                    ;
;                                      ;
; 'DIOP1'   : EINE ZIFFER DES ERSTEN   ;
;             OPERANDEN                ;
; 'LGTHOP2' : LAENGE DES ZWEITEN       ;
;             OPERANDEN                ;
; 'MACC'     : EIN AKKUMULATORFELD, IN ;
;             DEM DAS ERGEBNIS AUFGE-  ;
;             BAUT WIRD                ;
;                                      ;
;  **** VORSICHT ****                  ;
;                                      ;
;  DAS ARBEITSFELD 'MACC' MUSS LANG    ;
;  GENUG SEIN, UM DAS ERGEBNIS DER     ;
;  MULTIPLIKATION AUFNEHMEN ZU KOENNEN.;
;  DIE LAENGE IST IN DER DATEI         ;
;  RSANUMBER.H DEFINIERT.              ;
;                                      ;
;--------------------------------------;
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
; UEBERPRUEFE ZUERST, OB EIN OPERAND   ;
; GLEICH NULL IST. DANN IST AUCH DAS   ;
; ERGEBNIS GLEICH NULL.                ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[OP1]    ; ADRESSE VON OP1
   CMP     WORD PTR [BX],0
   JE      ZERO        ; LAENGE = 0 ?
   MOV     AX,[2+BX]   ; NIEDERWERTIGSTE
   MOV     DIOP1,AX    ; ZIFFER VON OP1
                       ; VORMERKEN
   MOV     BX,[OP2]    ; ADRESSE VON OP2
   CMP     WORD PTR [BX],0
   JE      ZERO        ; LAENGE = 0 ?
   MOV     AX,[BX]     ; LAENGE VON OP2
   MOV     LGTHOP2,AX  ; VORMERKEN
   JMP     MULT
ZERO:
   MOV     BX,[ERG]
   MOV     WORD PTR [BX],0
   JMP     RETURN
;
;--------------------------------------;
;                                      ;
; ERSTE SCHLEIFE. DER INHALT DES       ;
; AKKUMULATORS MUSS NOCH NICHT BE-     ;
; RUECKSICHTIGT WERDEN.                ;
;                                      ;
;--------------------------------------;
;
MULT:
   MOV     DI,2
   XOR     CX,CX       ; UEBERTRAG
                       ; LOESCHEN
LOOP1:
   MOV     AX,[BX+DI]  ; ZIFFER VON OP2
   MUL     DIOP1       ; MIT AKTUELLER
                       ; ZIFFER VON OP1
                       ; MULTIPLIZIEREN
   ADD     AX,CX       ; UEBERTRAG
                       ; ADDIEREN.
   JNC     NOINC1      ; HIERBEI KANN
   INC     DX          ; ERNEUT EIN
                       ; UEBERTRAG
                       ; AUFTRETEN.
NOINC1:
   MOV     [MACC+DI],AX ; ERG. SPEICHERN
   MOV     CX,DX       ; UEBERTRAG MERKEN
   ADD     DI,2        ; INC INDEX
   CMP     DI,LGTHOP2  ; ENDE VON OP2
   JNG     LOOP1       ; ERREICHT ?
   MOV     [MACC+DI],CX ; LETZTEN UEBERTRAG
                       ; NOCH EINTRAGEN
;
;--------------------------------------;
;                                      ;
; EIGENTLICHE MULTIPLIKATION MIT       ;
; BERUECKSICHTIGUNG DES AKKUMULATOR-   ;
; INHALTES.                            ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; AEUSSERE SCHLEIFE UEBER DIE ZIFFERN  ;
; DES ERSTEN OPERANDEN.                ;
;                                      ;
;--------------------------------------;
;
   MOV     SI,4
LOOPO:
   MOV     BX,[OP1]    ; ALLE ZIFFERN VON
   CMP     SI,[BX]     ; OP1 ABGEARBEITET ?
   JG      ENDMUL      ; MULTIPLIKATION
                       ; BEENDET
   MOV     AX,[BX+SI]  ; AKTUELLE ZIFFER
   MOV     DIOP1,AX    ; VON OP1 LADEN
   MOV     DI,2        ; INDEX UEBER OP2
                       ; INITIALISIEREN
   XOR     CX,CX       ; UEBERTRAG
                       ; LOESCHEN
;
;--------------------------------------;
;                                      ;
; INNERE SCHLEIFE:                     ;
; MULTIPLIKATION VON OP1[SI] MIT OP2.  ;
;                                      ;
;--------------------------------------;
;
LOOPI:
   MOV     BX,[OP2]    ; ZIFFER VON OP2
   MOV     AX,[BX+DI]  ; LADEN UND MIT
   MUL     DIOP1       ; AKTUELLER ZIFFER
                       ; VON OP1
                       ; MULTIPLIZIEREN
   ADD     AX,CX       ; UEBERTRAG ADDIEREN
   JNC     NOINC2      ; DABEI KANN EIN
   INC     DX          ; NEUER UEBERTRAG
                       ; AUFTRETEN
NOINC2:
   LEA     BX,[MACC-2+SI]
   ADD     AX,[BX+DI]  ; BISTHERIGEN AKKU-
                       ; MULATORINHALT
                       ; ADDIEREN
   JNC     NOINC3      ; DABEI KANN ERNEUT
   INC     DX          ; EIN UEBERTRAG
                       ; ENTSTEHEN
NOINC3:
   MOV     [BX+DI],AX  ; ERGEBNIS IM AKKU-
                       ; MULATOR SPEICHERN
   MOV     CX,DX       ; UEBERTRAG MERKEN
   ADD     DI,2        ; INDEX FORTSCHALTEN
   CMP     DI,LGTHOP2  ; ALLE ZIFFERN VON
                       ; OP2 BEARBEITET ?
   JNG     LOOPI
;
;--------------------------------------;
;                                      ;
; ENDE DER INNEREN SCHLEIFE.           ;
; ES KANN NOCH EIN UEBERTRAG VORHAN-   ;
; DEN SEIN:                            ;
;                                      ;
;--------------------------------------;
;
   MOV     [BX+DI],CX  ; UEBERTRAG
                       ; SPEICHERN.
                       ; AN DIESER
                       ; STELLE STEHT
                       ; NOCH NICHTS
                       ; IM AKKUMULATOR
   ADD     SI,2        ; INDEX FUER OP1
                       ; WEITERSCHALTEN
   JMP     LOOPO
;
;--------------------------------------;
;                                      ;
; ENDE DER AEUSSEREN SCHLEIFE.         ;
; ES MUSS NUN NOCH DIE LAENGE DES      ;
; ERGEBNISSES BESTIMMT WERDEN UND      ;
; DAS ERGEBNIS INS ZIELFELD UEBER-     ;
; TRAGEN WERDEN.                       ;
;                                      ;
;--------------------------------------;
;
ENDMUL:
   LEA     BX,[MACC-4+DI]
   CMP     WORD PTR [BX+SI],0
                       ; NUR DIESE
                       ; ZIFFER KOENNTE
                       ; NULL SEIN
   JNE     NOCORR
   SUB     SI,2
NOCORR:
   ADD     SI,DI
   MOV     CX,SI
   SUB     SI,4
   MOV     MACC,SI
   SAR     CX,1        ; 'REP MOVS'-BEFEHL
   DEC     CX          ; VORBEREITEN
   MOV     DI,[ERG]
   LEA     SI,MACC
   REP     MOVSW

RETURN:
   POP     SI
   POP     DI
   MOV     SP,BP
   POP     BP
   RET

_SMULT     ENDP
_TEXT      ENDS

;
;--------------------------------------;
;                                      ;
; VARIABLENFELDER                      ;
;                                      ;
;--------------------------------------;
;
_DATA      SEGMENT
           PUBLIC  LGTHOP2,DIOP1,MACC
LGTHOP2    DW      0
DIOP1      DW      0
MACC       DW      RSAINT DUP(?)
           DW      RSAINT DUP(?)
OPER1      DW      RSAINT DUP(?)
OPER2      DW      RSAINT DUP(?)
OPER3      DW      RSAINT DUP(?)
           DW      RSAINT DUP(?)
_DATA      ENDS
           END


