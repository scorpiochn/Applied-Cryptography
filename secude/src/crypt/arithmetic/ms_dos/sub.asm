
;
;-------------------------------------------------------+-----;
;                                                       | GMD ;
;   PROC SUB                            VERSION 1.0     +-----;
;                                          DATE 10.12.87      ;
;                                            BY BOTT WOLFGANG ;
;                                                             ;
;                                                             ;
;   DESCRIPTION SUBTRAHIERT ZWEI LANGE ZAHLEN.                ;
;               OPERANDEN UND ERGEBNISFELDER KOENNEN          ;
;               GLEICH SEIN.                                  ;
;               POINTER AUF DIE OPERANDEN SIND 4 BYTE LANG.   ;
;                                                             ;
;                                                             ;
;   IN           DESCRIPTION                 ADR:             ;
;     OP1          SUBTRAHEND                  [BP] + 6       ;
;     OP2          MINUEND                     [BP] + 10      ;
;                                                             ;
;   INOUT                                                     ;
;                                                             ;
;   OUT                                                       ;
;     ERGEBNIS     SUBTRAHEND - MINUEND        [BP] + 14      ;
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
DGROUP   GROUP _DATA,_BSS,CONST
ASSUME   CS:_TEXT,DS:DGROUP,SS:DGROUP,ES:DGROUP
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
   PUBLIC  _SUB

_SUB       PROC   FAR
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
; EIGNETLICHE SUBTRAKTION AUFRUFEN
;
   POP     DS
   POP     ES
   LEA     BX,[OPER3]
   PUSH    BX
   LEA     BX,[OPER2]
   PUSH    BX
   LEA     BX,[OPER1]
   PUSH    BX

   CALL _SSUB

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

_SUB       ENDP

;--------------------------------------;
; EIGENTLICHES SUBTRAKTIONSPROGRAMM.   ;
; DIE POINTER AUF DIE OPERANDEN SIND   ;
; JETZT ALLE 'NEAR'.                   ;
;--------------------------------------;

_SSUB      PROC    NEAR
   PUSH    BP
   MOV     BP,SP
   PUSH    DI
   PUSH    SI
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
OP1     EQU  4 + [BP]
OP2     EQU  6 + [BP]
ERG     EQU  8 + [BP]
;
;--------------------------------------;
;                                      ;
; ES WERDEN KEINE LOKALEN VARIABLEN    ;
; BENOETIGT.                           ;
;                                      ;
;--------------------------------------;
;
;
;--------------------------------------;
;                                      ;
; UEBERPRUEFE ZUERST, OB OP1 GROESSER  ;
; IST, ALS OP2. FALLS NICHT, IST DAS   ;
; ERGEBNIS NEGATIV.                    ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[OP2]    ; ADRESSE VON OP2
   MOV     CX,[BX]     ; LAENGE VON OP2
   MOV     BX,[OP1]    ; ADRESSE VON OP1
   CMP     CX,[BX]     ; LAENGENVERGLEICH
   JG      NEGATIVE
;
;--------------------------------------;
;                                      ;
; OP2 = 0 ?                            ;
;                                      ;
;--------------------------------------;
;
   MOV     SI,2
   JCXZ    NOBORROW
;
;--------------------------------------;
;                                      ;
; ORGANISIERE LOOP1                    ;
;                                      ;
;--------------------------------------;
;
   CLC
   SAR     CX,1        ; SCHLEIFENREG.
                       ; INITIALISIEREN
;
;--------------------------------------;
;                                      ;
; IN DER ERSTEN SCHLEIFE WERDEN ZIF-   ;
; FERN VON OP2 VON ZIFFERN VON OP1     ;
; ABGEZOGEN.                           ;
;                                      ;
;--------------------------------------;
;
LOOP1:
   MOV     BX,[OP1]    ; ZIFFER VON OP1
   MOV     AX,[BX+SI]  ; LADEN
   MOV     BX,[OP2]    ; ZIFFER VO OP2
   SBB     AX,[BX+SI]  ; ABZIEHEN
   MOV     BX,[ERG]    ; ERGEBNIS
   MOV     [BX+SI],AX  ; ABSPEICHERN
   INC     SI          ; AENDERT BORROW-
   INC     SI          ; BIT NICHT
   LOOP    LOOP1
;
;--------------------------------------;
;                                      ;
; ES KANN NOCH EIN UEBERTRAG VORHAN-   ;
; DEN SEIN:                            ;
;                                      ;
;--------------------------------------;
;
   JNC     NOBORROW
;
;--------------------------------------;
;                                      ;
; VERFOLGE DEN UEBERTRAG DURCH DEN     ;
; REST VON OP1:                        ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[OP1]    ; ZAHL NOCH ZU
   MOV     CX,[BX]     ; VERARBEITENDER
   PUSHF               ; ZIFFERN BERECH-
   SUB     CX,SI       ; NEN, OHNE
   POPF                ; BORROW-BIT ZU
                       ; ZERSTOEREN
   SAR     CX,1
   INC     CX
;
;--------------------------------------;
;                                      ;
; FALLS ALLE ZIFFERN VON OP1 BENUTZT   ;
; WURDEN, ABER IMMER NOCH EIN UEBER-   ;
; TRAG VORHANDEN IST, SO IST DAS ER-   ;
; GEBNIS NEGATIV.                      ;
;                                      ;
;--------------------------------------;
;
   JCXZ    NEGATIVE
;
;--------------------------------------;
;                                      ;
; ZWEITE SCHLEIFE                      ;
;                                      ;
;--------------------------------------;
;
LOOP2:
   MOV     BX,[OP1]    ; BORROW VON
   MOV     AX,[BX+SI]  ; ZIFFER VON OP1
   SUB     AX,1        ; ABZIEHEN.
   MOV     BX,[ERG]    ; ERGEBNIS
   MOV     [BX+SI],AX  ; ABSPEICHERN
   INC     SI
   INC     SI
   JNC     NOBORROW    ; FALLS KEIN
                       ; NEUER BORROW
                       ; EINTRITT,
                       ; SCHLEIFE
                       ; VERLASSEN
   LOOP    LOOP2
;
;--------------------------------------;
;                                      ;
; FALLS DIESER PUNKT ERREICHT WIRD,    ;
; IST DAS ERGEBNIS NEGATIV.            ;
;                                      ;
;--------------------------------------;
;
NEGATIVE:
   MOV     AX,-1       ; WERT DES FUNK-
   JMP     RETURN      ; TIONSAUFRUFS
                       ; = -1
;
;--------------------------------------;
;                                      ;
; FALL, DASS DAS ERGEBNIS POSITIV IST: ;
;                                      ;
;--------------------------------------;
;
NOBORROW:
   MOV     BX,[OP1]
   MOV     CX,[BX]
;
;--------------------------------------;
;                                      ;
; WURDEN ALLE ZIFFERN VON OP1 BE-      ;
; NOETIGT ?                            ;
;                                      ;
;--------------------------------------;
;
   CMP     SI,CX
;
;--------------------------------------;
;                                      ;
; FALLS JA, DANN KOENNTE DAS ERGEBNIS  ;
; FUEHRENDE NULLEN ENTHALTEN.          ;
;                                      ;
;--------------------------------------;
;
   JG      CHKLGTH
;
;--------------------------------------;
;                                      ;
; FALLS NICHT, IST DAS ERGEBNIS SO     ;
; LANG WIE OP1.                        ;
;                                      ;
;--------------------------------------;
;
   MOV     BX,[ERG]
   MOV     [BX],CX
;
;--------------------------------------;
;                                      ;
; UEBERTRAGE DEN REST VON OP1 IN DAS   ;
; ERGEBNISFELD:                        ;
;                                      ;
;--------------------------------------;
;
   MOV     DI,[ERG]      ; 'REP MOVS'-
   ADD     DI,SI         ; BEFEHL
   SUB     CX,SI         ; VORBEREITEN
   SAR     CX,1
   INC     CX
   MOV     AX,[OP1]
   ADD     SI,AX
   REP     MOVSW
   XOR     AX,AX         ; RETURNCODE IM
   JMP     RETURN        ; POSITIVEN FALL
                         ; = 0
;
;--------------------------------------;
;                                      ;
; IN DER DRITTEN SCHLEIFE WIRD AUF     ;
; FUEHRENDE NULLEN GETESTET.           ;
;                                      ;
;--------------------------------------;
;
CHKLGTH:
   MOV     BX,[ERG]
LOOP3:
   DEC     SI
   DEC     SI
   JZ      INSLGTH       ; ALLE ZIFFERN
                         ; GETESTET ?
   CMP     WORD PTR [BX+SI],0
                         ; ZIFFER <> 0
                         ; GEFUNDEN ?
   JNE     INSLGTH
   JMP     LOOP3
;
;--------------------------------------;
;                                      ;
; DIE LAENGE DES ERGEBNISSES IST NUN   ;
; IN 'SI' ENTHALTEN UND KANN NACH      ;
; ERGEBNIS[0] UEBERTRAGEN WERDEN.      ;
;                                      ;
;--------------------------------------;
;
INSLGTH:
   MOV     [BX],SI
   XOR     AX,AX         ; POSITIVER
                         ; RETURN-CODE


RETURN:
   POP     SI
   POP     DI
   MOV     SP,BP
   POP     BP
   RET

_SSUB      ENDP
_TEXT      ENDS

_DATA      SEGMENT
OPER1      DW    RSAINT   DUP(?)
OPER2      DW    RSAINT   DUP(?)
OPER3      DW    RSAINT   DUP(?)

_DATA      ENDS

           END

;-------------------------------------------------------------;
; E N D   O F   P R O C E D U R E                             ;
;-------------------------------------------------------------;
