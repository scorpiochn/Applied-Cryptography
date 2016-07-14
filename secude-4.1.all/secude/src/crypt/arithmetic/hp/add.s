# 1 "add.m"



























# 1 "/usr/include/hard_reg.h"
; Standard Hardware Register Definitions for Use with Assembler
; version 7.00
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Hardware General Registers
r0	.equ	0
r1	.equ	1
r2	.equ	2
r3	.equ	3
r4	.equ	4
r5	.equ	5
r6	.equ	6
r7	.equ	7
r8	.equ	8
r9	.equ	9
r10	.equ	10
r11	.equ	11
r12	.equ	12
r13	.equ	13
r14	.equ	14
r15	.equ	15
r16	.equ	16
r17	.equ	17
r18	.equ	18
r19	.equ	19
r20	.equ	20
r21	.equ	21
r22	.equ	22
r23	.equ	23
r24	.equ	24
r25	.equ	25
r26	.equ	26
r27	.equ	27
r28	.equ	28
r29	.equ	29
r30	.equ	30
r31	.equ	31
; Hardware Space Registers
sr0	.equ	0
sr1	.equ	1
sr2	.equ	2
sr3	.equ	3
sr4	.equ	4
sr5	.equ	5
sr6	.equ	6
sr7	.equ	7
; Hardware Floating Point Registers
fr0	.equ	0
fr1	.equ	1
fr2	.equ	2
fr3	.equ	3
fr4	.equ	4
fr5	.equ	5
fr6	.equ	6
fr7	.equ	7
fr8	.equ	8
fr9	.equ	9
fr10	.equ	10
fr11	.equ	11
fr12	.equ	12
fr13	.equ	13
fr14	.equ	14
fr15	.equ	15
; Hardware Control Registers
cr0	.equ	0
rctr	.equ	0			; Recovery Counter Register

cr8	.equ	8			; Protection ID 1
pidr1	.equ	8

cr9	.equ	9			; Protection ID 2
pidr2	.equ	9

cr10	.equ	10
ccr	.equ	10			; Coprocessor Confiquration Register

cr11	.equ	11
sar	.equ	11			; Shift Amount Register

cr12	.equ	12
pidr3	.equ	12			; Protection ID 3

cr13	.equ	13
pidr4	.equ	13			; Protection ID 4

cr14	.equ	14
iva	.equ	14			; Interrupt Vector Address

cr15	.equ	15
eiem	.equ	15			; External Interrupt Enable Mask

cr16	.equ	16
itmr	.equ	16			; Interval Timer

cr17	.equ	17
pcsq	.equ	17			; Program Counter Space queue

cr18	.equ	18
pcoq	.equ	18			; Program Counter Offset queue

cr19	.equ	19
iir	.equ	19			; Interruption Instruction Register

cr20	.equ	20
isr	.equ	20			; Interruption Space Register

cr21	.equ	21
ior	.equ	21			; Interruption Offset Register

cr22	.equ	22
ipsw	.equ	22			; Interrpution Processor Status Word

cr23	.equ	23
eirr	.equ	23			; External Interrupt Request

cr24	.equ	24
ppda	.equ	24			; Physcial Page Directory Address
tr0	.equ	24			; Temporary register 0

cr25	.equ	25
hta	.equ	25			; Hash Table Address
tr1	.equ	25			; Temporary register 1

cr26	.equ	26
tr2	.equ	26			; Temporary register 2

cr27	.equ	27
tr3	.equ	27			; Temporary register 3

cr28	.equ	28
tr4	.equ	28			; Temporary register 4

cr29	.equ	29
tr5	.equ	29			; Temporary register 5

cr30	.equ	30
tr6	.equ	30			; Temporary register 6

cr31	.equ	31
tr7	.equ	31			; Temporary register 7
# 28 "add.m"


# 1 "/usr/include/soft_reg.h"
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Procedure Call Convention                                                  ~
; Register Definitions for Use with Assembler                                ~
; version 7.00                                                               ~
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Software Architecture General Registers
rp	.equ    r2	; return pointer
mrp	.equ	r31	; millicode return pointer
ret0	.equ    r28	; return value
ret1	.equ    r29	; return value (high part of double)
sl	.equ    r29	; static link
sp	.equ 	r30	; stack pointer
dp	.equ	r27	; data pointer
arg0	.equ	r26	; argument
arg1	.equ	r25	; argument or high part of double argument
arg2	.equ	r24	; argument
arg3	.equ	r23	; argument or high part of double argument
;_____________________________________________________________________________
; Software Architecture Space Registers
;		sr0	; return link form BLE
sret	.equ	sr1	; return value
sarg	.equ	sr1	; argument
;		sr4	; PC SPACE tracker
;		sr5	; process private data
;_____________________________________________________________________________
; Software Architecture Pseudo Registers
previous_sp	.equ	64	; old stack pointer (locates previous frame)
# 30 "add.m"



























        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_add
        .PROC
        .CALLINFO CALLER,FRAME=16,ENTRY_SR=3
        .ENTRY
        LDO     64(%r30),%r30   ;offset 0x48
        STW     %r3,-64(0,%r30)        ;offset 0x5c
        STW     %r4,-60(0,%r30)        ;offset 0x5c
        STW     %r5,-56(0,%r30)        ;offset 0x5c
        STW     %r6,-52(0,%r30)        ;offset 0x5c
        STW     %r7,-48(0,%r30)        ;offset 0x5c
        STW     %r8,-44(0,%r30)        ;offset 0x5c
        STW     %r9,-40(0,%r30)        ;offset 0x5c





	LDW	0(0, arg0),r3
	LDW	0(0, arg1),r4
	COMB,>=,n  r3, r4,   L$I_swap
	NOP 
	COPY arg0, r6
	COPY arg1, arg0
	COPY r6, arg1
L$I_swap


	LDW	0(0, arg1),r8
	LDW	0(0, arg0),r3
	SUB r3, r8, r9
	COPY arg2, r6
	STW	r3, 0(0, arg2)

	COPY %r0, r7



	COMB, =,n   %r0, r8, L$B_loop1
	NOP
L$C_loop1 

	ADDI 4, arg0, arg0
	ADDI 4, arg1, arg1
	ADDI 4, r6, r6

	LDW	0(0, arg0),r3
	LDW	0(0, arg1),r4

	ADD,UV	r4, r7, r5
	COPY %r0, r7
	ADD,NUV	r3, r5, r5
	ADDI 	1,%r0, r7

	STW	r5, 0(0, r6)
	ADDIB, <>,n	-1, r8,  L$C_loop1
	NOP
L$B_loop1 



	COMB, =,n   %r0, r7, L$B_loop2
	NOP
	COMB, =,n   %r0, r9, L$B_loop2
	NOP
L$C_loop2 

	ADDI 4, arg0, arg0
	ADDI 4, r6, r6

	LDW	0(0, arg0),r3

	ADD,UV r3, r7, r5
	COPY %r0, r7

	STW	r5, 0(0, r6)


	
	COMB,=,n	%r0, r7, L$B_loop2
	NOP
	ADDIB, <>	-1, r9, 	L$C_loop2
	NOP
L$B_loop2 



	COMB, =,n 	arg0, r6,  L$I_equallength
	NOP 

	COMB, =,n   %r0, r9, L$B_loop3
	NOP
L$C_loop3 

	ADDI 4, arg0, arg0
	ADDI 4, r6, r6

	LDW	0(0, arg0),r3
	STW	r3, 0(0, r6)
	ADDIB, <>	-1, r9, 	L$C_loop3
	NOP
L$B_loop3 

L$I_equallength 


	COMB, =,n   %r0, r7,   L$I_longer
	NOP 
	ADDI 4, r6, r6
	STW	r7, 0(0, r6)
	LDW	0(0, arg2),r5
	ADDI 1, r5, r5
	STW	r5, 0(0, arg2)
L$I_longer 
L$B_longer 

        LDW     -64(0,%r30), %r3       ;offset 0x4
        LDW     -60(0,%r30), %r4       ;offset 0x4
        LDW     -56(0,%r30), %r5       ;offset 0x4
        LDW     -52(0,%r30), %r6       ;offset 0x4
        LDW     -48(0,%r30), %r7       ;offset 0x4
        LDW     -44(0,%r30), %r8       ;offset 0x4
        LDW     -40(0,%r30), %r9       ;offset 0x4
        BV      %r0(%r2)        ;offset 0x64
        .EXIT
        LDO     -64(%r30),%r30  ;offset 0x68
        .PROCEND ;in=24,25,26;out=28;









;        .SPACE  $TEXT$,SORT=8
;        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_sub
        .PROC
        .CALLINFO CALLER,FRAME=24,ENTRY_SR=3
        .ENTRY
        LDO     128(%r30),%r30  ;offset 0x6c
        STW     %r3,-72(0,%r30)        ;offset 0x80
        STW     %r4,-68(0,%r30)        ;offset 0x80
        STW     %r5,-64(0,%r30)        ;offset 0x80
        STW     %r6,-60(0,%r30)        ;offset 0x80
        STW     %r7,-56(0,%r30)        ;offset 0x80
        STW     %r8,-52(0,%r30)        ;offset 0x80
        STW     %r9,-48(0,%r30)        ;offset 0x80
        STW     %r10,-44(0,%r30)        ;offset 0x80
        STW     %r11,-40(0,%r30)        ;offset 0x80
        STW     %r12,-36(0,%r30)        ;offset 0x80

	COPY arg0, r10
	COPY arg2, r12
	COPY %r0, r7


	LDW	0(0, arg0),r3
	LDW	0(0, arg1),r4

	LDW	0(0, arg1),r8
	SUB r3, r8, r9

	COMB, =,n   %r0, r8 L$B_loops1
	NOP
L$C_loops1 

	ADDI 4, arg0, arg0
	ADDI 4, arg1, arg1
	ADDI 4, arg2, arg2

	LDW	0(0, arg0),r3
	LDW	0(0, arg1),r4


	ADD,UV	r4, r7, r11
	COPY %r0, r7
	SUB,>>=	r3, r11, r11
	ADDI 	1,%r0, r7

	STW	r11, 0(0, arg2)

	ADDIB, <>,n	-1, r8,  L$C_loops1
	NOP
L$B_loops1 

	COMB, =,n   %r0, r7 L$B_loops2
	NOP
	COMB, =,n   %r0, r9 L$B_loops2
	NOP
L$C_loops2 
	ADDI 4, arg0, arg0
	ADDI 4, arg2, arg2
	LDW	0(0, arg0),r3

	SUB,<< r3, r7, r11
	COPY %r0, r7

	STW	r11, 0(0, arg2)
	
	COMB,=,n	%r0, r7, L$B_loops2
	NOP
	ADDIB, <>	-1, r9, 	L$C_loops2
	NOP
L$B_loops2 






	COMB, =,n 	arg0, arg2,  L$I_equallengths
	NOP 

	COMB, =,n   %r0, r9 L$B_loops3
	NOP
L$C_loops3 

	ADDI 4, arg0, arg0
	ADDI 4, arg2, arg2

	LDW	0(0, arg0),r3
	STW	r3, 0(0, arg2)

	ADDIB, <>	-1, r9, 	L$C_loops3
	NOP
L$B_loops3 

L$I_equallengths 
L$B_equallengths 



	LDW	0(0, r10),r8
	SH2ADD r8, %r0, r10
	ADD r12, r10, arg2


L$C_loops4 
	COMB,=,n	arg2, r12, L$B_loops4
	NOP
	LDW	0(0, arg2),r11
	COMB, <>,n   %r0, r11 L$B_loops4
	NOP
	ADDI -1, r8, r8
	
	ADDIB,TR,n  -4, arg2, L$C_loops4
	NOP
L$B_loops4 

	STW	r8, 0(0, r12)

        LDW     -72(0,%r30), %r3       ;offset 0x4
        LDW     -68(0,%r30), %r4       ;offset 0x4
        LDW     -64(0,%r30), %r5       ;offset 0x4
        LDW     -60(0,%r30), %r6       ;offset 0x4
        LDW     -56(0,%r30), %r7       ;offset 0x4
        LDW     -52(0,%r30), %r8       ;offset 0x4
        LDW     -48(0,%r30), %r9       ;offset 0x4
        LDW     -44(0,%r30), %r10       ;offset 0x4
        LDW     -40(0,%r30), %r11       ;offset 0x4
        LDW     -36(0,%r30), %r12       ;offset 0x4
        BV      %r0(%r2)        ;offset 0x88
        .EXIT
        LDO     -128(%r30),%r30 ;offset 0x8c
        .PROCEND ;in=24,25,26;out=28;


        .EXPORT _sub,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR


        .EXPORT _add,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR
	.END





