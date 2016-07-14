# 1 "shift.m"














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
# 15 "shift.m"


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
# 17 "shift.m"




























        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_shift
        .PROC
        .CALLINFO CALLER,FRAME=392,ENTRY_SR=3
        .ENTRY
        LDO     448(%r30),%r30  ;offset 0x90
        STW     %r3,-64(0,%r30)        ;offset 0xa4
        STW     %r4,-60(0,%r30)        ;offset 0xa4
        STW     %r5,-56(0,%r30)        ;offset 0xa4
        STW     %r6,-52(0,%r30)        ;offset 0xa4
        STW     %r7,-48(0,%r30)        ;offset 0xa4
        STW     %r8,-44(0,%r30)        ;offset 0xa4
        STW     %r9,-40(0,%r30)        ;offset 0xa4
        STW     %r11,-36(0,%r30)        ;offset 0xa4


	LDW	0(0, arg0),r4
	COPY arg2,r3




	COMB,<>,n  r4, %r0, L$I_zero
	NOP 
	STW	r4, 0(0, arg2)
	MOVB,TR,n %r0, %r0, L$B_end
	NOP
L$I_zero 






	COMB,<>,n  arg0,arg2, L$I_samemem
	NOP 
	ADDI -440, %r30, r7
	STW	r4, 0(0, r7)
L$C_copy 
	ADDI 4,r7,r7
	ADDI 4,arg0,arg0
	LDW	0(0, arg0),r8
	STW	r8, 0(0, r7)
	ADDIB,<>,n -1, r4, L$C_copy
	NOP
L$B_copy 
	ADDI -440, %r30, arg0
	LDW	0(0, arg0),r4
L$I_samemem 






	COMB,<,n  arg1, %r0, L$I_sign
	NOP 

	ADDI 31, %r0, r11
	AND r11, arg1, r11
	COMB,=,n  %r0,r11 L$I_mod32l
	NOP 





	SUBI 32,r11,r11
	MTSAR r11

	SHD %r0,arg1,5,arg1
	ADD r4,arg1 ,r6
	STW	r6, 0(0, arg2)

	COMB,=,n %r0, arg1, L$B_fillzero2 
	NOP
L$C_fillzero2 
	ADDI 4,arg2,arg2
	STW	%r0, 0(0, arg2)
	ADDIB,<>,n -1, arg1, L$C_fillzero2
	NOP
L$B_fillzero2 

	COPY %r0, r8
L$C_shl 
	ADDI 4,arg0,arg0
	ADDI 4,arg2,arg2
	LDW	0(0, arg0),r7
	VSHD r7, r8, r8
	STW	r8, 0(0, arg2)
	COPY r7,r8
	ADDIB,<>,n -1, r4, L$C_shl
	NOP
L$B_shl 


	VSHD %r0, r8,r8
	COMB,=,n %r0, r8,   L$I_more
	NOP 
	ADDI 4,arg2,arg2
	STW	r8, 0(0, arg2)
	ADDI 1, r6, r6
	STW	r6, 0(0, r3)
L$I_more 


	
	MOVB,TR,n %r0,%r0, L$B_end
	NOP 







L$I_sign 

	SUB %r0,arg1,arg1
	ADDI 31, %r0, r11
	AND r11, arg1, r11
	MTSAR r11
	COMB,=,n  %r0,r11 L$I_mod32r
	NOP 




	SHD %r0, arg1,5,arg1



	SUB,<= r4,arg1 ,r6
	MOVB,TR,n  %r0,%r0 L$I_toshort
	NOP 
	STW	%r0, 0(0, arg2)
	MOVB,TR,n  %r0,%r0 L$B_end
	NOP
L$I_toshort 


	SH2ADD arg1,arg0,arg0
	ADDI 4,arg0,arg0

	LDW	0(0, arg0),r8
	ADDIB,=,n -1, r6,L$B_shr
	NOP

L$C_shr 
	ADDI 4,arg0,arg0
	ADDI 4,arg2,arg2
	LDW	0(0, arg0),r7
	VSHD r7,r8,r8
	STW	r8, 0(0, arg2)
	COPY r7,r8
	ADDIB,<>,n -1, r6, L$C_shr
	NOP
L$B_shr 


	SUB r4,arg1 ,r6
	VSHD,<> %r0, r8,r8
	MOVB,TR,n  %r0,%r0 L$B_less
	NOP


	ADDI 4,arg2,arg2
	STW	r8, 0(0, arg2)
	STW	r6, 0(0, r3)

	MOVB,TR,n %r0,%r0, L$B_end
	NOP 
L$B_less 
	ADDI -1 ,r6,r6
	STW	r6, 0(0, r3)

	MOVB,TR,n %r0,%r0, L$B_end
	NOP 







L$I_mod32r
	SHD	%r0, arg1, 5, arg1
	SUB,>	r4, arg1, r6
	COPY %r0, r6
	COMB,=,n %r0,r6, L$B_end
	STW	r6, 0(0, arg2)
	SH2ADD arg1, arg0, arg0
L$C_copyr
	ADDI 4,arg2,arg2
	ADDI 4,arg0,arg0
	LDW	0(0, arg0),r8
	STW	r8, 0(0, arg2)
	ADDIB,<>,n -1, r6, L$C_copyr
	NOP
	MOVB,TR,n %r0,%r0, L$B_end
	NOP









L$I_mod32l
	SHD,<>	%r0, arg1, 5, arg1
	MOVB,TR,n %r0,%r0, L$I_mod320
	NOP
	ADD	r4, arg1, r6
	STW	r6, 0(0, arg2)
L$C_filll
	ADDI 4,arg2,arg2
	STW	%r0, 0(0, arg2)
	ADDIB,<>,n -1, arg1, L$C_filll
	NOP
L$C_copyl
	ADDI 4,arg2,arg2
	ADDI 4,arg0,arg0
	LDW	0(0, arg0),r8
	STW	r8, 0(0, arg2)
	ADDIB,<>,n -1, r4, L$C_copyl
	NOP

	MOVB,TR,n %r0,%r0, L$B_end
	NOP







L$I_mod320
	STW	r4, 0(0, arg2)
L$C_copy0 
	ADDI 4,arg2,arg2
	ADDI 4,arg0,arg0
	LDW	0(0, arg0),r8
	STW	r8, 0(0, arg2)
	ADDIB,<>,n -1, r4, L$C_copy0
	NOP


L$B_end

        LDW     -64(0,%r30), %r3       ;offset 0x4
        LDW     -60(0,%r30), %r4       ;offset 0x4
        LDW     -56(0,%r30), %r5       ;offset 0x4
        LDW     -52(0,%r30), %r6       ;offset 0x4
        LDW     -48(0,%r30), %r7       ;offset 0x4
        LDW     -44(0,%r30), %r8       ;offset 0x4
        LDW     -40(0,%r30), %r9       ;offset 0x4
        LDW     -36(0,%r30), %r11       ;offset 0x4

        BV      %r0(%r2)        ;offset 0xb0
        .EXIT
        LDO     -448(%r30),%r30 ;offset 0xb4
        .PROCEND ;in=24,25,26;out=28;

        .EXPORT _shift,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

	.END
