_DATA   SEGMENT AT 0

        ORG     1CH*4

TICK_INT        LABEL WORD

        ORG     1000H

TICKS   DB      1 DUP(?)

T_O_FLAG        DB      1 DUP(?)

T_CNT   DB      1 DUP(?)

ERR_STATE  DB   1 DUP(?)

Serial  DW      1 DUP(?)

SAVE_MASK DB    1 DUP(?)

SAVE_INT DW     1 DUP(?)

         DW     1 DUP(?)

_DATA   ENDS



STACK   SEGMENT STACK

        DW      50 DUP(?)

STACK   ENDS

COM1    EQU     03f8h

COM2    EQU     02f8h

        _TEXT   SEGMENT

        ASSUME  CS:_TEXT

                PUBLIC     _RS232_INIT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;   To initiat RS232 inteface with baudrate        ;;

;;   and data format. On ok 0 is returned, non zero ;;

;;   if error occured.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_RS232_INIT     PROC  FAR

        PUSH    BP

        MOV     BP,SP

        PUSH    DS

        MOV     BX,[BP+6]

        CMP     BX,1

        JNZ     COM_2?

        MOV     DX,COM1

        MOV     BX,DX

        JMP     SHORT BEGIN

COM_2?:

        CMP     BX,2

        JNZ     I_ERR

        MOV     DX,COM2

        MOV     BX,DX

BEGIN:

        ADD     DX,3            ;line control register

        MOV     AL,80h          ;for baudrate set

        OUT     DX,AL

;

        MOV     DX,BX

        MOV     AX,[BP+8]       ;get divisor

        OUT     DX,AL

        INC     DX

        MOV     AL,AH

        OUT     DX,AL

;

        ADD     DX,2

        MOV     AL,[BP+10]      ;get data format

        OUT     DX,AL


        MOV     DX,BX

        INC     DX

        MOV     AL,0FH

        OUT     DX,AL


        JMP     SHORT I_OK

I_ERR:

        MOV     AX,00ffh        ;if error, non zero return

        JMP     SHORT RS_END

I_OK:

        MOV     AX,0

RS_END:

        POP     DS

        MOV     SP,BP

        POP     BP

        RET

           _RS232_INIT   ENDP

;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;   To send string via serisl port. 0 is returned, ;;

;;   non zero if error                              ;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

                PUBLIC  _SENDSTR

_SENDSTR  PROC  FAR

        PUSH    ES

        PUSH    BP

        MOV     BP,SP

        PUSH    DS

        PUSH    SI

        MOV     BX,[BP+8]       ;get fd

        MOV     SI,[BP+10]      ;get address of string

        MOV     ES,[BP+12]

        MOV     CX,[BP+14]      ;get length to send

        CMP     BX,1

        JNZ     COM2?

        MOV     DX,COM1

        MOV     BX,DX

        JMP     SHORT LOOP1

COM2?:

        CMP     BX,2

        JNZ     S_ERR

        MOV     DX,COM2

        MOV     BX,DX

LOOP1:

        ADD     DX,5

SEND:

        IN      AL,DX

        TEST    AL,20h

        JZ      SEND

        MOV     AL,ES:[SI]

        MOV     DX,BX

        OUT     DX,AL

        INC     SI

        DEC     CX

        JNZ     LOOP1

        JMP     SHORT S_OK

S_ERR:

        MOV     AX,00ffh

        JMP     SHORT S_END

S_OK:

        MOV     AX,0

S_END:

        POP     SI

        POP     DS

        MOV     SP,BP

        POP     BP

        POP     ES

        RET

_SENDSTR        ENDP

;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;   To receive string within waiting time.         ;;

;;   0 is returned on ok, error number if error     ;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        PUBLIC  _RECESTR

_RECESTR    PROC  FAR

        PUSH    ES

        PUSH    BP

        MOV     BP,SP

        PUSH    DS

        PUSH    SI

        ASSUME  DS:_DATA

        SUB     AX,AX

        MOV     DS,AX

        MOV     DX,[BP+8]       ;get fd

        MOV     SI,[BP+10]      ;get address of string

        MOV     ES,[BP+12]

        MOV     CX,[BP+14]      ;get length to receive

        MOV     BX,[BP+16]      ;get timeout value

        CMP     DX,1

        JNZ     R_COM2

        MOV     AX,COM1

        MOV     SERIAL,AX

        JMP     SHORT T2

R_COM2:

        CMP     DX,2

        MOV     ERR_STATE,30h

        JNZ     R_ERR

        MOV     AX,COM2

        MOV     SERIAL,AX

T2:

        MOV     T_CNT,BL

        CMP     BL,12h          ;  timeval > 1 sec

        JG      T3

        MOV     ERR_STATE,27h   ;error number is CHAR_TIMEOUT

        JMP     SHORT STATIME

T3:

        MOV     ERR_STATE,26h   ;error number is BLK_TIMEOUT

STATIME:

        CALL    SETUP_TIME_TICK



LOOP2:

        MOV     DX,SERIAL

        ADD     DX,5

R_CHK:

        IN      AL,DX

        TEST    AL,1

        JNZ     RECE

        CMP     T_O_FLAG,80h

        JZ      R_ERR

        JMP     R_CHK

;

RECE:

        CALL    RESTORE_INT

        MOV     DX,SERIAL

        IN      AL,DX

        MOV     ES:[SI],AL

        INC     SI

        DEC     CX

        JNZ     LOOP2

        JMP     SHORT R_OK

R_ERR:

        CALL    RESTORE_INT

        MOV     AH,00h

        MOV     AL,ERR_STATE    ;return error number

        JMP     SHORT R_END

R_OK:

        MOV     AX,0

R_END:

        POP     SI

        POP     DS

        MOV     SP,BP

        POP     BP

        POP     ES

        RET

_RECESTR        ENDP

;

SETUP_TIME_TICK PROC NEAR

        XOR     AX,AX

        MOV     TICKS,AL

        MOV     T_O_FLAG,AL

        IN      AL,21h

        MOV     SAVE_MASK,AL

        CLI

        MOV     AX,DS:TICK_INT

        MOV     SAVE_INT,AX

        MOV     AX,DS:TICK_INT+2

        MOV     SAVE_INT+2,AX

        MOV     TICK_INT,OFFSET TIMER_INT

        MOV     TICK_INT+2,CS

        JMP     SHORT $+2

        JMP     SHORT $+2

        IN      AL,21h

        AND     AL,0FEh

        OUT     21h,AL

        JMP     SHORT $+2

        JMP     SHORT $+2

        STI

        RET

SETUP_TIME_TICK ENDP

RESTORE_INT     PROC NEAR

        CLI

        MOV     AL,SAVE_MASK

        OUT     21h,AL

        MOV     AX,SAVE_INT

        MOV     TICK_INT,AX

        MOV     AX,SAVE_INT+2

        MOV     TICK_INT+2,AX

        RET

RESTORE_INT     ENDP

TIMER_INT       PROC FAR

        PUSH    AX

        PUSH    DS

        PUSH    DX

        SUB     AX,AX

        MOV     DS,AX

        INC     TICKS

        MOV     AL,TICKS

        CMP     AL,T_CNT

        JNZ     ITRET

        MOV     T_O_FLAG,80h

        MOV     TICKS,0

ITRET:

        JMP     SHORT $+2

        JMP     SHORT $+2

        MOV     AL,20h

        OUT     20h,AL

        POP     DX

        POP     DS

        POP     AX

        IRET

TIMER_INT       ENDP

        _TEXT   ENDS

                END

