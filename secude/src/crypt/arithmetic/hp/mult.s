# 1 "mult.m"













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
# 14 "mult.m"

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
# 15 "mult.m"



























































        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_mult
        .PROC
        .CALLINFO CALLER,FRAME=824,ENTRY_SR=3,SAVE_RP
        .ENTRY
        STW     %r2,-20(0,%r30) ;offset 0xb8
        LDO     896(%r30),%r30  ;offset 0xbc
        STW     %r19,-32(0,%r30)        ;offset 0xc0

        STW     %r3,-120(0,%r30)        ;offset 0x80
        STW     %r4,-116(0,%r30)        ;offset 0x80
        STW     %r5,-112(0,%r30)        ;offset 0x80
        STW     %r6,-108(0,%r30)        ;offset 0x80
        STW     %r7,-104(0,%r30)        ;offset 0x80
        STW     %r8,-100(0,%r30)        ;offset 0x80
        STW     %r9,-96(0,%r30)        ;offset 0x80
        STW     %r10,-92(0,%r30)        ;offset 0x80
        STW     %r11,-88(0,%r30)        ;offset 0x80
        STW     %r12,-84(0,%r30)        ;offset 0x80
        STW     %r13,-80(0,%r30)        ;offset 0x80
        STW     %r14,-76(0,%r30)        ;offset 0x80
        STW     %r15,-72(0,%r30)        ;offset 0x80
        STW     %r16,-68(0,%r30)        ;offset 0x80
        STW     %r17,-60(0,%r30)        ;offset 0x80
        STW     %r18,-56(0,%r30)        ;offset 0x80
        STW     %r21,-52(0,%r30)        ;offset 0x80
        STW     %r22,-48(0,%r30)        ;offset 0x80





	COPY %r0, %r5

	COPY arg0, %r3
	COPY arg1, %r4
	COPY arg2, %r18


	COPY %r18, %r13
	ADDI -872,%r30, %r18
	LDW	0(0, %r3), %r14
	LDW	0(0, %r4), %r15


	COMB,=,n  %r0, %r14, L$I_zero
	NOP 
	COMB,=,n  %r0, %r15, L$I_zero
	NOP 


	SH2ADD %r14, %r0, %r14
	SH2ADD %r15, %r0, %r15


	ADD %r14, %r15, %r5


	COMB,<<=,n  %r14, %r15, L$I_mi
	NOP 
	MOVB,TR %r15, %r17, L$B_mi
	NOP 
L$I_mi 
	COPY %r14,%r17
L$B_mi 


	COPY %r3, %r11
	ADDI 4, %r3, %r3
	ADDI 4, %r4, %r4
	COPY %r4, %r12



	COPY %r0, %r6
	COPY %r0, %r7
	COPY %r0, %r8

	COPY %r0, %r16
	ADDI -4, %r5, %r9


L$C_diags 


	COMB,<<,n  %r17, %r9, L$I_le
	NOP 
	MOVB,TR %r9, %r16, L$B_le
	NOP 
L$I_le 
	COMB,=,n  %r17, %r16, L$B_le
	NOP
	ADDI 4, %r16, %r16
L$B_le 

	SUB %r5, %r9, %r20



	SUB,>> %r20, %r14, %r21
	B,n   L$I_atoshort
	NOP 
	ADD %r11, %r14, %r3
	ADD %r21, %r12, %r4
	
	B,n L$B_atoshort
	NOP 
L$I_atoshort 
	COPY %r12, %r4
	ADD %r11, %r20, %r3
L$B_atoshort 

	COPY %r16, %r10



L$C_elem 


	LDW	0(0, %r3), arg0
	LDW	0(0, %r4), arg1
	COPY	%r6, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   ;in=23,24,25,26;out=28;
        BL      _dmult,%r2   
        NOP            


	COPY	ret0, %r6
	ADD,NUV %r7, ret1, %r7
	ADDI 1, %r8, %r8

	ADDI -4, %r3, %r3
	ADDI 4, %r4, %r4

	ADDIB,<>,n -4, %r10, L$C_elem
	NOP
L$B_elem 




	ADDI 4,%r18,%r18
	STW	%r6, 0(0, %r18)
	COPY %r7, %r6
	COPY %r8, %r7
	COPY %r0, %r8

	ADDIB,<>,n -4, %r9, L$C_diags
	NOP
L$B_diags 


	COMB,=,n %r0, %r6, L$I_lastword
	NOP 
	ADDI 4, %r18, %r18
	STW	%r6, 0(0, %r18)
	
	B L$B_lastword
	NOP 
L$I_lastword 
	ADDI -4, %r5, %r5
L$B_lastword 
	SHD %r0, %r5, 2, %r5

L$I_zero 
L$B_zero 


	STW	%r5, 0(0, %r13)
	ADDI -872,%r30, %r18
	COMB,=,n %r0, %r5, L$B_copy
	NOP
L$C_copy 
	ADDI 4, %r18, %r18
	ADDI 4, %r13, %r13
	LDW	0(0, %r18),%r21
	STW	%r21, 0(0, %r13)
	ADDIB,<>,n -1, %r5, L$C_copy
	NOP
L$B_copy 



        LDW     -120(0,%r30), %r3       ;offset 0x4
        LDW     -116(0,%r30), %r4       ;offset 0x4
        LDW     -112(0,%r30), %r5       ;offset 0x4
        LDW     -108(0,%r30), %r6       ;offset 0x4
        LDW     -104(0,%r30), %r7       ;offset 0x4
        LDW     -100(0,%r30), %r8       ;offset 0x4
        LDW     -96(0,%r30), %r9       ;offset 0x4
        LDW     -92(0,%r30), %r10       ;offset 0x4
        LDW     -88(0,%r30), %r11       ;offset 0x4
        LDW     -84(0,%r30), %r12       ;offset 0x4
        LDW     -80(0,%r30), %r13       ;offset 0x4
        LDW     -76(0,%r30), %r14       ;offset 0x4
        LDW     -72(0,%r30), %r15       ;offset 0x4
        LDW     -68(0,%r30), %r16       ;offset 0x4
        LDW     -60(0,%r30), %r17       ;offset 0x4
        LDW     -56(0,%r30), %r18       ;offset 0x4
        LDW     -52(0,%r30), %r21       ;offset 0x4
        LDW     -48(0,%r30), %r22       ;offset 0x4

        LDW     -32(0,%r30),%r19        ;offset 0xf4
        LDW     -916(0,%r30),%r2        ;offset 0xf8
        BV      %r0(%r2)        ;offset 0xfc
        .EXIT
        LDO     -896(%r30),%r30 ;offset 0x100
        .PROCEND ;in=24,25,26;out=28;






        .SPACE  $TEXT$
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24

_dmult
        .PROC
        .CALLINFO CALLER,FRAME=0,ENTRY_SR=3
        .ENTRY
        LDO     64(%r30),%r30   ;offset 0x24
        STW     %r3,-40(0,%r30)       ;offset 0x4
        STW     %r4,-36(0,%r30)       ;offset 0x8





	COPY %r0, ret1
	COPY arg2, ret0

	ADDI 31, %r0, %r4
	MTSAR %r4

	COPY %r0, %r4
	MOVB,=,n arg1, %r3, L$I_end
	NOP

	AND,< arg0, arg0, %r0
	B L$I_noadd
	SHD %r3, %r4, 1, %r4
L$I_add
	SHD %r0, %r3, 1, %r3

	ADD %r3,ret1,ret1
	ADD,NUV %r4,ret0,ret0
	ADDI 1,ret1,ret1

	
	VSHD,>= arg0,%r0,arg0
	B L$I_add
	SHD %r3, %r4, 1, %r4
	AND,<> arg0, arg0, %r0
	B L$I_end

L$I_noadd
	SHD %r0, %r3, 1, %r3
L$I_noadd2
	
	VSHD,>= arg0,%r0,arg0
	B L$I_add
	SHD %r3, %r4, 1, %r4

	AND,= arg0, arg0, %r0
	B L$I_noadd2
	SHD %r0, %r3, 1, %r3

L$I_end

        LDW     -40(0,%r30), %r3       ;offset 0x4
        LDW     -36(0,%r30), %r4       ;offset 0x4
        BV      %r0(%r2)        ;offset 0x40
        .EXIT
        LDO     -64(%r30),%r30  ;offset 0x44
        .PROCEND ;in=24,25,26;out=28;



        .EXPORT _dmult,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

        .EXPORT _mult,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

	.END
