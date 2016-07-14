/********************************************************************
 * Copyright (C) 1993, GMD. All rights reserved.                    *
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



#define parm_a arg0
#define parm_b arg1
#define cont_a r3
#define cont_b r4

#define parm_s arg2
#define cont_s r5
#define sum r6
#define carry r7
#define cnt r8
#define res r9

#define parm_d arg2
#define opa r10
#define cont_d r11
#define dp r12

/*      _add()     translated version of _add() in add.c

	assembler for HP 9000 Series 700

	Thomas Surkau 24.6.93           */


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




/* if lngofln(ax)... */
	LDW	0(0, parm_a),cont_a
	LDW	0(0, parm_b),cont_b
	COMB,>=,n  cont_a, cont_b,   L$I_swap
	NOP 
	COPY parm_a, sum
	COPY parm_b, parm_a
	COPY sum, parm_b
L$I_swap

/* cnt=...*/
	LDW	0(0, parm_b),cnt
	LDW	0(0, parm_a),cont_a
	SUB cont_a, cnt, res
	COPY parm_s, sum
	STW	cont_a, 0(0, parm_s)

	COPY %r0, carry

/* loop cnt>0...*/

	COMB, =,n   %r0, cnt, L$B_loop1
	NOP
L$C_loop1 
/* ++ */
	ADDI 4, parm_a, parm_a
	ADDI 4, parm_b, parm_b
	ADDI 4, sum, sum
/* *Ap */
	LDW	0(0, parm_a),cont_a
	LDW	0(0, parm_b),cont_b
/* cadd  */
	ADD,UV	cont_b, carry, cont_s
	COPY %r0, carry
	ADD,NUV	cont_a, cont_s, cont_s
	ADDI 	1,%r0, carry

	STW	cont_s, 0(0, sum)
	ADDIB, <>,n	-1, cnt,  L$C_loop1
	NOP
L$B_loop1 


/* loop carry &&... */
	COMB, =,n   %r0, carry, L$B_loop2
	NOP
	COMB, =,n   %r0, res, L$B_loop2
	NOP
L$C_loop2 
/* ++ */
	ADDI 4, parm_a, parm_a
	ADDI 4, sum, sum
/* *Ap  */
	LDW	0(0, parm_a),cont_a
/* cadd  */
	ADD,UV cont_a, carry, cont_s
	COPY %r0, carry

	STW	cont_s, 0(0, sum)


	
	COMB,=,n	%r0, carry, L$B_loop2
	NOP
	ADDIB, <>	-1, res, 	L$C_loop2
	NOP
L$B_loop2 


/* if Sp != Ap */
	COMB, =,n 	parm_a, sum,  L$I_equallength
	NOP 

	COMB, =,n   %r0, res, L$B_loop3
	NOP
L$C_loop3 
/* ++ */
	ADDI 4, parm_a, parm_a
	ADDI 4, sum, sum
/* copy */
	LDW	0(0, parm_a),cont_a
	STW	cont_a, 0(0, sum)
	ADDIB, <>	-1, res, 	L$C_loop3
	NOP
L$B_loop3 

L$I_equallength 

/* sum longer than a */
	COMB, =,n   %r0, carry,   L$I_longer
	NOP 
	ADDI 4, sum, sum
	STW	carry, 0(0, sum)
	LDW	0(0, parm_s),cont_s
	ADDI 1, cont_s, cont_s
	STW	cont_s, 0(0, parm_s)
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


/*      _sub()     translated version of _sub() in add.c

	assembler for HP 9000 Series 700

	Thomas Surkau 24.6.93           */


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

	COPY parm_a, opa
	COPY parm_d, dp
	COPY %r0, carry


	LDW	0(0, parm_a),cont_a
	LDW	0(0, parm_b),cont_b

	LDW	0(0, parm_b),cnt
	SUB cont_a, cnt, res

	COMB, =,n   %r0, cnt L$B_loops1
	NOP
L$C_loops1 
/* ++ */
	ADDI 4, parm_a, parm_a
	ADDI 4, parm_b, parm_b
	ADDI 4, parm_d, parm_d
/*  *Ap  */
	LDW	0(0, parm_a),cont_a
	LDW	0(0, parm_b),cont_b

/* cadd  */
	ADD,UV	cont_b, carry, cont_d
	COPY %r0, carry
	SUB,>>=	cont_a, cont_d, cont_d
	ADDI 	1,%r0, carry

	STW	cont_d, 0(0, parm_d)

	ADDIB, <>,n	-1, cnt,  L$C_loops1
	NOP
L$B_loops1 

	COMB, =,n   %r0, carry L$B_loops2
	NOP
	COMB, =,n   %r0, res L$B_loops2
	NOP
L$C_loops2 
	ADDI 4, parm_a, parm_a
	ADDI 4, parm_d, parm_d
	LDW	0(0, parm_a),cont_a

	SUB,<< cont_a, carry, cont_d
	COPY %r0, carry

	STW	cont_d, 0(0, parm_d)
	
	COMB,=,n	%r0, carry, L$B_loops2
	NOP
	ADDIB, <>	-1, res, 	L$C_loops2
	NOP
L$B_loops2 





/* if Sp != Ap */
	COMB, =,n 	parm_a, parm_d,  L$I_equallengths
	NOP 

	COMB, =,n   %r0, res L$B_loops3
	NOP
L$C_loops3 
/* ++ */
	ADDI 4, parm_a, parm_a
	ADDI 4, parm_d, parm_d
/* copy */
	LDW	0(0, parm_a),cont_a
	STW	cont_a, 0(0, parm_d)

	ADDIB, <>	-1, res, 	L$C_loops3
	NOP
L$B_loops3 

L$I_equallengths 
L$B_equallengths 



	LDW	0(0, opa),cnt
	SH2ADD cnt, %r0, opa
	ADD dp, opa, parm_d


L$C_loops4 
	COMB,=,n	parm_d, dp, L$B_loops4
	NOP
	LDW	0(0, parm_d),cont_d
	COMB, <>,n   %r0, cont_d L$B_loops4
	NOP
	ADDI -1, cnt, cnt
	
	ADDIB,TR,n  -4, parm_d, L$C_loops4
	NOP
L$B_loops4 

	STW	cnt, 0(0, dp)

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





