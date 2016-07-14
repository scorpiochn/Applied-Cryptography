;
;-------------------------------------------------------+-----;
;                                                       | GMD ;
;   PROC ADD                            VERSION 1.0     +-----;
;                                          DATE 10.12.87      ;
;                                            BY BOTT WOLFGANG ;
;                                                             ;
;                                                             ;
;   DESCRIPTION ADDIERT ZWEI LANGE ZAHLEN                     ;
;               OPERANDEN UND ERGEBNISFELDER KOENNEN          ;
;               GLEICH SEIN.                                  ;
;               POINTER AUF DIE OPERANDEN SIND 4 BYTE LANG.   ;
;                                                             ;
;   IN             DESCRIPTION               ADR:             ;
;     OP1          1. SUMMAND                  [BP] + 6       ;
;     OP2          2. SUMMAND                  [BP] + 10      ;
;                                                             ;
;   INOUT                                                     ;
;                                                             ;
;   OUT                                                       ;
;     ERGEBNIS     1. SUMMAND + 2. SUMMAND     [BP] + 14      ;
;                                                             ;
;-------------------------------------------------------------;
;
INCLUDE ASMTOKEN.H
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
           PUBLIC _ADD

_ADD       PROC   FAR
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
; EIGNETLICHE ADDITION AUFRUFEN
;
   POP     DS
   POP     ES
   LEA     BX,[OPER3]
   PUSH    BX
   LEA     BX,[OPER2]
   PUSH    BX
   LEA     BX,[OPER1]
   PUSH    BX

   CALL _SADD

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

_ADD   ENDP

;--------------------------------------;
; EIGENTLICHES ADDITIONSPROGRAMM.      ;
; DIE POINTER AUF DIE OPERANDEN SIND   ;
; JETZT ALLE 'NEAR'.                   ;
;--------------------------------------;

_SADD      PROC NEAR
           PUSH    BP
           MOV     BP,SP
           PUSH    DI
           PUSH    SI

;--------------------------------------;
; ADRESSEN DER PARAMETER:              ;
;                                      ;
; OP1 :  4 + [BP]                      ;
; OP2 :  6 + [BP]                      ;
; ERGEBNIS : 8 + [BP]                  ;
;--------------------------------------;
;
OP1    EQU   4 + [BP]
OP2    EQU   6 + [BP]
ERG    EQU   8 + [BP]
;
;--------------------------------------;
;                                      ;
; ES WERDEN KEINE LOKALEN VARIABLEN    ;
; BEN™TIGT.                            ;
;                                      ;
;--------------------------------------;
;
;--------------------------------------;
;                                      ;
; UEBERPRUEFE ZUERST, OB OP1 GROESSER  ;
; IST, ALS OP2. FALLS NICHT, VERTAU-   ;
; SCHE DIE ADRESSEN AUF DEM STACK.     ;
;                                      ;
;--------------------------------------;
;

   MOV     BX,[OP2]   ; ADRESSE VON OP2
   MOV     CX,[BX]    ; LAENGE VON OP2
   MOV     BX,[OP1]   ; ADRESSE VON OP1
   CMP     CX,[BX]    ; VERGLEICH DER
                      ; LAENGEN
   JNG     OKAY

;
;--------------------------------------;
;                                      ;
; VERTAUSCHE DIE ADRESSEN AUF DEM      ;
; STACK.                               ;
;                                      ;
;--------------------------------------;
;
   MOV     AX,[OP2]
   MOV     [OP1],AX
   MOV     [OP2],BX
   MOV     CX,[BX]

;
;--------------------------------------;
;                                      ;
; OP2 = 0 ?                            ;
;                                      ;
;--------------------------------------;
;

OKAY:
   MOV     SI,2
   JCXZ    NOCARRY    ;AN DAS ENDE DER
                      ;ADDITION SPRINGEN

;
;--------------------------------------;
;                                      ;
; ORGANISIERE LOOP1                    ;
;                                      ;
;--------------------------------------;
;

   SAR     CX,1       ;SCHLEIFENZAEHLER
   CLC

;
;--------------------------------------;
;                                      ;
; IN DER ERSTEN SCHLEIFE WERDEN ZIF-   ;
; FERN VON OP2 UND ZIFFERN VON OP1     ;
; ADDIERT.                             ;
;                                      ;
;--------------------------------------;
;

LOOP1:
   MOV     BX,[OP1]   ;ZIFFER VON OP1
   MOV     AX,[BX+SI] ;LADEN
   MOV     BX,[OP2]   ;ZIFFER VON OP2
   ADC     AX,[BX+SI] ;AUFADDIEREN
   MOV     BX,[ERG]   ;ERGEBNIS
   MOV     [BX+SI],AX ;ABSPEICHERN
   INC     SI         ;AENDERT CARRY-BIT
   INC     SI         ;NICHT
   LOOP    LOOP1      ;ERNIEDRIGT CX

;
;--------------------------------------;
;                                      ;
; ES KANN NOCH EIN UEBERTRAG VORHAN-   ;
; DEN SEIN                             ;
;                                      ;
;--------------------------------------;
;

   JNC NOCARRY        ; AN DAS ENDE DER
                      ; ADDITION SPRINGEN

;
;--------------------------------------;
;                                      ;
; VERFOLGE DEN UEBERTRAG DURCH DEN     ;
; REST VON OP1:                        ;
;                                      ;
;--------------------------------------;
;

   MOV     BX,[OP1]
   MOV     CX,[BX]    ; ZAEHLREGISTER NEU
   PUSHF              ; INITIALISIEREN
   SUB     CX,SI      ; DABEI CARRY-BIT
   POPF               ; IM STACK SICHERN
   SAR     CX,1
   INC     CX
   JCXZ    SKIP2      ; IST OP1 SO LANG
                      ; WIE OP2, DANN
                      ; DIESE SCHLEIFE
                      ; UEBERSPRINGEN

;
;--------------------------------------;
;                                      ;
; ZWEITE SCHLEIFE                      ;
;                                      ;
;--------------------------------------;
;

LOOP2:
   MOV     BX,[OP1]
   MOV     AX,[BX+SI] ; UEBERTRAG AUF-
   ADD     AX,1       ; ADDIEREN UND DAS
   MOV     BX,[ERG]   ; ERGEBNIS
   MOV     [BX+SI],AX ; ABSPEICHERN
   INC     SI
   INC     SI
   JNC     NOCARRY    ; KEIN UEBERTRAG?
   LOOP    LOOP2

;
;--------------------------------------;
;                                      ;
; FALLS DIESER PUNKT ERREICHT WIRD,    ;
; IST IMMER NOCH EIN UEBERTRAG         ;
; VORHANDEN                            ;
;                                      ;
;--------------------------------------;
;

SKIP2:
   MOV     BX,[ERG]   ; FUEHRENDE EINS
                      ; IM ERGEBNIS
   MOV     WORD PTR [BX+SI],1 ; EINTRAGEN
   MOV     [BX],SI
   JMP     RETURN

;
;--------------------------------------;
;                                      ;
; UEBERTRAG ERSCHOEPFT. DAS ERGEBNIS   ;
; IST SO LANG WIE OP1.                 ;
;                                      ;
;--------------------------------------;
;

NOCARRY:
   MOV     BX,[OP1]
   MOV     CX,[BX]
   MOV     BX,[ERG]
   MOV     [BX],CX    ;LAENGE EINTRAGEN

;
;--------------------------------------;
;                                      ;
; REST VON OP1 IN DAS ERGEBNIS         ;
; UEBERTRAGEN                          ;
;                                      ;
;--------------------------------------;
;

   MOV     DI,[ERG]   ; 'REP MOVS'BEFEHL
   ADD     DI,SI      ; VORBEREITEN
   SUB     CX,SI      ; ZAHL DER REST-
   SAR     CX,1       ; LICHEN ZIFFERN
   INC     CX         ; LADEN
   MOV     AX,[OP1]
   ADD     SI,AX
   REP     MOVSW

RETURN:
   POP     SI
   POP     DI
   MOV     SP,BP
   POP     BP
   RET

_SADD      ENDP
_TEXT      ENDS

_DATA      SEGMENT
OPER1      DW      RSAINT   DUP(?)
OPER2      DW      RSAINT   DUP(?)
OPER3      DW      RSAINT   DUP(?)

_DATA      ENDS
           END

;-------------------------------------------------------------;
; E N D   O F   P R O C E D U R E   ADD                       ;
;-------------------------------------------------------------;

