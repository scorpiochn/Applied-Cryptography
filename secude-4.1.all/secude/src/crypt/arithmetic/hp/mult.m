/********************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

#include <hard_reg.h>
#include <soft_reg.h>




#define parm_a %r3
#define parm_b %r4
#define parm_p %r18
#define len_a %r14
#define len_b %r15
#define len_p %r5
#define sum_l %r6
#define sum_m %r7
#define sum_h %r8
#define diagnr %r9
#define diagpos %r10
#define save_a %r11
#define save_b %r12
#define save_p %r13
#define tmp1 %r21
#define tmp2 %r20
#define lendiag %r16
#define min %r17

#define M1 arg0
#define M2 arg1
#define RH ret1
#define RL ret0
#define TH %r3
#define TL %r4

/*      _mult()

	using _dmult() for two-word-multiplication

	assembler for HP 9000 Series 700

	Thomas Surkau 24.6.93  */



/*
	  a[4]            a[3]            a[2]            a[1]
	-----------------------------------------------------------
	a[4]*b[1]       a[3]*b[1]       a[2]*b[1]       a[1]*b[1]  |   b[1]
		 \               \               \                 |
		   \               \               \               |
		     \               \               \             |
		       \               \               \           |
	a[4]*b[2]       a[3]*b[2]       a[2]*b[2]       a[1]*b[2]  |   b[2]
		 \               \               \                 |
		   \               \               \               |
		     \               \               \             |
		       \               \               \           |
	a[4]*b[3]       a[3]*b[3]       a[2]*b[3]       a[1]*b[3]  |   b[3]



		    */

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





	COPY %r0, len_p

	COPY arg0, parm_a
	COPY arg1, parm_b
	COPY arg2, parm_p

/* first, the result is stored on the stack */
	COPY parm_p, save_p
	ADDI -872,%r30, parm_p
	LDW	0(0, parm_a), len_a
	LDW	0(0, parm_b), len_b

/* not much to do, if one number equal zero   */
	COMB,=,n  %r0, len_a, L$I_zero
	NOP 
	COMB,=,n  %r0, len_b, L$I_zero
	NOP 


	SH2ADD len_a, %r0, len_a
	SH2ADD len_b, %r0, len_b

/* calc length of a*b */
	ADD len_a, len_b, len_p

/* calc min() of lengths */
	COMB,<<=,n  len_a, len_b, L$I_mi
	NOP 
	MOVB,TR len_b, min, L$B_mi
	NOP 
L$I_mi 
	COPY len_a,min
L$B_mi 

/* save pointer to a and b */
	COPY parm_a, save_a
	ADDI 4, parm_a, parm_a
	ADDI 4, parm_b, parm_b
	COPY parm_b, save_b

/* the result of each word*word-operation will be added to these regs
   (low, middle and high word) */
	COPY %r0, sum_l
	COPY %r0, sum_m
	COPY %r0, sum_h

	COPY %r0, lendiag
	ADDI -4, len_p, diagnr

/* loop for all diagonals */
L$C_diags 

/* calc number of elements in this diagonal */
	COMB,<<,n  min, diagnr, L$I_le
	NOP 
	MOVB,TR diagnr, lendiag, L$B_le
	NOP 
L$I_le 
	COMB,=,n  min, lendiag, L$B_le
	NOP
	ADDI 4, lendiag, lendiag
L$B_le 

	SUB len_p, diagnr, tmp2

/* set pointer to a and b */
/* two cases if the diagonal starts in row b[1] or not */
	SUB,>> tmp2, len_a, tmp1
	B,n   L$I_atoshort
	NOP 
	ADD save_a, len_a, parm_a
	ADD tmp1, save_b, parm_b
	
	B,n L$B_atoshort
	NOP 
L$I_atoshort 
	COPY save_b, parm_b
	ADD save_a, tmp2, parm_a
L$B_atoshort 

	COPY lendiag, diagpos


/* loop for all elements in one diagonal */
L$C_elem 

/* unsigned multiply */
	LDW	0(0, parm_a), arg0
	LDW	0(0, parm_b), arg1
	COPY	sum_l, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   ;in=23,24,25,26;out=28;
        BL      _dmult,%r2   
        NOP            

/* add the result to the diagonal sum */
	COPY	ret0, sum_l
	ADD,NUV sum_m, ret1, sum_m
	ADDI 1, sum_h, sum_h

	ADDI -4, parm_a, parm_a
	ADDI 4, parm_b, parm_b

	ADDIB,<>,n -4, diagpos, L$C_elem
	NOP
L$B_elem 

/* store the lowest word of the sum
   shft down the two highest word to add them to the sum of the
   next diagonal */
	ADDI 4,parm_p,parm_p
	STW	sum_l, 0(0, parm_p)
	COPY sum_m, sum_l
	COPY sum_h, sum_m
	COPY %r0, sum_h

	ADDIB,<>,n -4, diagnr, L$C_diags
	NOP
L$B_diags 

/* ADDI -the length, if necessary  */
	COMB,=,n %r0, sum_l, L$I_lastword
	NOP 
	ADDI 4, parm_p, parm_p
	STW	sum_l, 0(0, parm_p)
	
	B L$B_lastword
	NOP 
L$I_lastword 
	ADDI -4, len_p, len_p
L$B_lastword 
	SHD %r0, len_p, 2, len_p

L$I_zero 
L$B_zero 

/* copy p back from stack */
	STW	len_p, 0(0, save_p)
	ADDI -872,%r30, parm_p
	COMB,=,n %r0, len_p, L$B_copy
	NOP
L$C_copy 
	ADDI 4, parm_p, parm_p
	ADDI 4, save_p, save_p
	LDW	0(0, parm_p),tmp1
	STW	tmp1, 0(0, save_p)
	ADDIB,<>,n -1, len_p, L$C_copy
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

/* Mult 32 Bit * 32 Bit */
/* %r28, %r29 = %r26 * %r25 + %r24
/* RL,RH = M1*M2 */

	COPY %r0, RH
	COPY arg2, RL

	ADDI 31, %r0, TL
	MTSAR TL

	COPY %r0, TL
	MOVB,=,n M2, TH, L$I_end
	NOP

	AND,< M1, M1, %r0
	B L$I_noadd
	SHD TH, TL, 1, TL
L$I_add
	SHD %r0, TH, 1, TH

	ADD TH,RH,RH
	ADD,NUV TL,RL,RL
	ADDI 1,RH,RH

	
	VSHD,>= M1,%r0,M1
	B L$I_add
	SHD TH, TL, 1, TL
	AND,<> M1, M1, %r0
	B L$I_end

L$I_noadd
	SHD %r0, TH, 1, TH
L$I_noadd2
	
	VSHD,>= M1,%r0,M1
	B L$I_add
	SHD TH, TL, 1, TL

	AND,= M1, M1, %r0
	B L$I_noadd2
	SHD %r0, TH, 1, TH

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
