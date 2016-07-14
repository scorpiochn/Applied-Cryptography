# 1 "div.m"















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
# 16 "div.m"

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
# 17 "div.m"












































        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_div
        .PROC
        .CALLINFO CALLER,FRAME=1200,ENTRY_SR=3,SAVE_RP
        .ENTRY
        STW     %r2,-20(0,%r30) ;offset 0x104
        LDO     1280(%r30),%r30 ;offset 0x108
        STW     %r19,-32(0,%r30)        ;offset 0x10c

        STW     %r4,-120(0,%r30)        ;offset 0x80
        STW     %r5,-116(0,%r30)        ;offset 0x80
        STW     %r6,-112(0,%r30)        ;offset 0x80
        STW     %r7,-108(0,%r30)        ;offset 0x80
        STW     %r8,-104(0,%r30)        ;offset 0x80
        STW     %r9,-100(0,%r30)        ;offset 0x80
        STW     %r10,-96(0,%r30)        ;offset 0x80
        STW     %r11,-92(0,%r30)        ;offset 0x80
        STW     %r12,-88(0,%r30)        ;offset 0x80
        STW     %r13,-84(0,%r30)        ;offset 0x80
        STW     %r14,-80(0,%r30)        ;offset 0x80
        STW     %r15,-76(0,%r30)        ;offset 0x80
        STW     %r16,-72(0,%r30)        ;offset 0x80
        STW     %r17,-68(0,%r30)        ;offset 0x80
        STW     %r18,-64(0,%r30)        ;offset 0x80
        STW     arg2,-60(0,%r30)        ;offset 0x80
        STW     arg3,-56(0,%r30)        ;offset 0x80
        STW     arg0,-52(0,%r30)        ;offset 0x80




	COPY arg0, %r22
	COPY arg1, %r5
	COPY arg2, %r20
	COPY arg3, %r21

	LDW	0(0, %r5), %r10
	LDW	0(0, %r22), %r13
	SH2ADD %r10, %r0, %r10
	SH2ADD %r13, %r0, %r13
	SUB %r13, %r10, %r11





	COMB,<>,n %r0,%r10,L$I_null
	NOP
	ADDI -1, %r0,ret0
	B,n endofdiv
	NOP
L$I_null 





	COMB,<=,n %r10, %r13, L$I_trivial
	NOP 


	STW	%r0, 0(0, %r20)


	SHD %r0, %r13, 2, %r18
	STW	%r18, 0(0, %r21)
	COMB,=,n %r0, %r13, ok
	NOP

	ADD %r22, %r13, %r22
	ADD %r21, %r13, %r21
L$C_cp1 
	LDW	0(0, %r22), %r18
	STW	%r18, 0(0, %r21)
	ADDI -4, %r22, %r22
	ADDI -4, %r21, %r21
	ADDIB,>,n -4, %r13, L$C_cp1
	NOP
L$B_cp1 
	
	B,n ok
	NOP
L$I_trivial 
L$B_trivial 






	ADDI -496,%r30, %r8
	ADDI -872,%r30, %r9


	COPY %r13, %r4

	LDW	0(0, %r22), %r18
	STW	%r18, 0(0, %r9)

	ADD %r22, %r4, %r22
	ADD %r9, %r4, %r9
L$C_cp2 
	LDW	0(0, %r22), %r18
	STW	%r18, 0(0, %r9)
	ADDI -4, %r22, %r22
	ADDI -4, %r9, %r9
	ADDIB,>,n -4, %r4, L$C_cp2
	NOP
 




	COMIB,<>,n 4, %r10, L$I_one
	NOP

	
	COPY %r13, %r18


	LDW	4(0, %r5), arg2

	COPY %r0, arg0


	ADD %r9, %r18, %r9
	ADD %r8, %r18, %r8
L$C_div1 

	LDW	0(0, %r9), arg1

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      __divlu, %r2   
	NOP
	STW	arg3, 0(0, %r8)
	ADDI -4, %r9, %r9
	ADDI -4, %r8, %r8
	ADDIB,<>,n -4, %r18, L$C_div1
	NOP
L$B_div1 
	ADD %r8, %r13, %r18
	LDW	0(0, %r18), %r18


	COMB,<>,n %r0,%r18,L$I_kuerzen
	NOP
	ADDI -4, %r13, %r13
L$I_kuerzen 

	SHD %r0, %r13, 2, %r18
	STW	%r18, 0(0, %r8)

        LDW     -60(0,%r30), %r20       ;offset 0x4
	STW	%r18, 0(0, %r20)

	ADD %r8, %r13, %r8
	ADD %r20, %r13, %r20

L$C_cp3 
	LDW	0(0, %r8), %r18
	STW	%r18, 0(0, %r20)
	ADDI -4, %r20, %r20
	ADDI -4, %r8, %r8
	ADDIB,>,n -4, %r13, L$C_cp3
	NOP



        LDW     -56(0,%r30), %r21       ;offset 0x4

	COMB,<>,n %r0,arg0,L$I_rest0
	NOP
	STW	%r0, 0(0, %r21)
	
	B,n L$B_rest0
	NOP 
L$I_rest0 
	ADDI 1, %r0, %r18
	STW	%r18, 0(0, %r21)
	STW	arg0, 4(0, %r21)
L$B_rest0 


	B,n ok
	NOP

L$I_one 
L$B_one 









 


	ADD %r5, %r10, %r18
	LDW	0(0, %r18), %r18
	ADDI -1,%r0, %r17


shftlen
	ADDB,NUV %r18, %r18, shftlen
	ADDI 1, %r17, %r17

	COMB,=,n %r0, %r17, noshft1
	NOP

	COPY %r5, arg0
	COPY %r17, arg1
	ADDI -872, %r30, %r5
	ADDI -376, %r5, %r5
	COPY %r5, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP

	COPY %r9, arg0
	COPY %r17, arg1
	COPY %r9, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP
noshft1

	LDW	0(0, %r9), %r18
	SH2ADD %r18, %r9, %r18
	ADDI 4, %r18, %r18
	STW	%r0, 0(0, %r18)







	
	ADDI 4, %r11, %r14
	ADD %r8, %r14, %r8
mloop





	ADD %r9, %r10, %r15
	ADD %r15, %r14, %r15

	ADD %r5, %r10, %r16


	LDW	0(0, %r15), arg0
	LDW	0(0, %r16), arg2
	COMB,= arg0, arg2, equal
	ADDI -1, %r0, %r12

	LDW	-4(0, %r15), arg1

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      __divlu, %r2   
	NOP
	COPY arg3, %r12

equal
test




	LDW	-4(0, %r16), arg0
	COPY %r12, arg1
	COPY %r0, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP
	COPY ret0, %r18
	COPY ret1, %r4


	LDW	0(0, %r16), arg0
	COPY %r12, arg1
	COPY %r4, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP
	COPY ret0, %r4
	COPY ret1, %r6




	ADDI -1, %r12, %r12

	LDW	0(0, %r15), %r7
	COMB,>>,n %r6 , %r7, test
	NOP
	COMB,<<,n %r6 , %r7, norep
	NOP

	LDW	-4(0, %r15), %r7
	COMB,>>,n %r4 , %r7, test
	NOP
	COMB,<<,n %r4 , %r7, norep
	NOP

	LDW	-8(0, %r15), %r7
	COMB,>>,n %r18 , %r7, test
	NOP

norep
	ADDI 1, %r12, %r12




	COPY %r10, %r18
	ADDI 4, %r5, %r16
	SUB %r15, %r10, %r15
	LDW	0(0, %r15), %r4
	COPY %r0 %r7
subloop
	LDW	4(0, %r15), %r6
	LDW	0(0, %r16), arg0
	COPY %r12, arg1
	COPY %r0, arg2
	
        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP

	
	SUB,>>= %r4, ret0, %r4
	ADDI 1, %r7, %r7
	ADDB,UV %r7, ret1, subnull
	ADDI 1, %r0, %r7

	SUB,<< %r6, ret1, %r6	
	COPY %r0, %r7
	
subnull
	STW	%r4, 0(0, %r15)
	COPY %r6, %r4

	ADDI 4, %r16, %r16

	ADDIB,<> -4, %r18, subloop
	ADDI 4, %r15, %r15

	STW	%r6, 0(0, %r15)




	COMB,=,n %r0,%r7,pos
	NOP




	ADDI -1, %r12, %r12
	
	COPY %r10, %r18
	ADDI 4, %r5, %r16
	SUB %r15, %r10, %r15
	COPY %r0, %r7
addback
	LDW	0(0, %r15), %r4
	LDW	0(0, %r16), %r6

	ADD,UV	%r4, %r7, %r4
	COPY %r0, %r7
	ADD,NUV	%r4, %r6, %r4
	ADDI 	1,%r0, %r7

	
	STW	%r4, 0(0, %r15)

	ADDI 4, %r16, %r16

	ADDIB,<> -4, %r18, addback
	ADDI 4, %r15, %r15

	LDW	0(0, %r15), %r4
	ADD %r4, %r7, %r4
	STW	%r4, 0(0, %r15)



pos	


	STW	%r12, 0(0, %r8)




	ADDI -4, %r8, %r8

	ADDIB,<>,n -4,  %r14, mloop
	NOP





	ADDI 4, %r11, %r11
next1
	ADD %r8, %r11, %r18
	LDW	0(0, %r18), %r18
	COMB,<>,n %r0,%r18,ex1
	NOP
	ADDIB,<>,n -4, %r11, next1
	NOP
ex1
	SHD %r0, %r11, 2, %r11
	STW	%r11, 0(0, %r8)





next2
	ADD %r9, %r10, %r18
	LDW	0(0, %r18), %r18
	COMB,<>,n %r0,%r18,ex2
	NOP
	ADDIB,<>,n -4, %r10, next2
	NOP
ex2

	SHD %r0, %r10, 2, %r10
	STW	%r10, 0(0, %r9)




	COMB,=,n %r0,%r17,noshft2
	COPY %r9, arg0
	SUB %r0, %r17, arg1
	COPY %r9, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP


noshft2







        LDW     -60(0,%r30), %r20       ;offset 0x4
	LDW	0(0, %r8), %r4
	STW	%r4, 0(0, %r20)
	SH2ADD %r4, %r0, %r4

	ADD %r8, %r4, %r8
	ADD %r20, %r4, %r20
L$C_cp4 
	LDW	0(0, %r8), %r18
	STW	%r18, 0(0, %r20)
	ADDI -4, %r20, %r20
	ADDI -4, %r8, %r8
	ADDIB,>,n -4, %r4, L$C_cp4
	NOP




        LDW     -56(0,%r30), %r21       ;offset 0x4

	LDW	0(0, %r9), %r4
	STW	%r4, 0(0, %r21)
	SH2ADD %r4, %r0, %r4

	ADD %r9, %r4, %r9
	ADD %r21, %r4, %r21
L$C_cp5 
	LDW	0(0, %r9), %r18
	STW	%r18, 0(0, %r21)
	ADDI -4, %r9, %r9
	ADDI -4, %r21, %r21
	ADDIB,>,n -4, %r4, L$C_cp5
	NOP









ok
	COPY %r0, ret0
endofdiv

        LDW     -120(0,%r30), %r4       ;offset 0x4
        LDW     -116(0,%r30), %r5       ;offset 0x4
        LDW     -112(0,%r30), %r6       ;offset 0x4
        LDW     -108(0,%r30), %r7       ;offset 0x4
        LDW     -104(0,%r30), %r8       ;offset 0x4
        LDW     -100(0,%r30), %r9       ;offset 0x4
        LDW     -96(0,%r30), %r10       ;offset 0x4
        LDW     -92(0,%r30), %r11       ;offset 0x4
        LDW     -88(0,%r30), %r12       ;offset 0x4
        LDW     -84(0,%r30), %r13       ;offset 0x4
        LDW     -80(0,%r30), %r14       ;offset 0x4
        LDW     -76(0,%r30), %r15       ;offset 0x4
        LDW     -72(0,%r30), %r16       ;offset 0x4
        LDW     -68(0,%r30), %r17       ;offset 0x4
        LDW     -60(0,%r30), %r18       ;offset 0x4
        LDW     -56(0,%r30), %r20       ;offset 0x4
        LDW     -52(0,%r30), %r21       ;offset 0x4
        LDW     -48(0,%r30), %r22       ;offset 0x4



        LDW     -1300(0,%r30),%r2       ;offset 0x194
        BV      %r0(%r2)        ;offset 0x198
        .EXIT
        LDO     -1280(%r30),%r30        ;offset 0x19c
        .PROCEND ;in=23,24,25,26;out=28;




























__divlu
        .PROC
        .CALLINFO CALLER,FRAME=0,ENTRY_SR=3
        .ENTRY
        LDO     64(%r30),%r30   ;offset 0x0
        STW     %r3,-40(0,%r30)       ;offset 0x4
        STW     %r4,-36(0,%r30)       ;offset 0x8






	ADDI 31, %r0, %r3
	MTSAR %r3
	ADDI 1, %r0, %r4
	ADDI -32, %r0, %r3

	COPY %r0, arg3

next
	COMB,<,n arg0,%r0 subshl
	NOP
	VSHD arg0,arg1,arg0
	VSHD arg1,%r0,arg1
	COMB,>>=,n arg0,arg2,sub
	NOP

	ADDB,<> %r4,%r3, next
	SH1ADD arg3, %r0, arg3
	B,n ready
	NOP

subshl
	VSHD arg0,arg1,arg0
	VSHD arg1,%r0,arg1
sub
	SUB arg0, arg2, arg0
	ADDB,<> %r4,%r3, next
	SH1ADD arg3, %r4, arg3
ready


        LDW     -40(0,%r30), %r3       ;offset 0x4
        LDW     -36(0,%r30), %r4       ;offset 0x4
        BV      %r0(%r2)        ;offset 0x1c
        .EXIT
        LDO     -64(%r30),%r30  ;offset 0x20
        .PROCEND ;in=24,25,26;out=28;



        .EXPORT __divlu,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

        .EXPORT _div,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR
        .IMPORT _shift,CODE
        .IMPORT _dmult,CODE
	.END
