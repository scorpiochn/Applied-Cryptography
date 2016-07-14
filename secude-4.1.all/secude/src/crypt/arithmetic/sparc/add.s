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
























































/*      _add()     translated version of _add() in add.c

	sparc-assembler

	Thomas Surkau 24.5.91           */


	.global __add;
	__add:     ! C function definition
	save %sp, -(((((16*4)+(6*4)+4)+0)+(8-1)) & ~(8-1)), %sp     ! save regs, no additional stack




/* if lngofln(ax)... */
	ld [%i0], %l0
	ld [%i1], %l1
	cmp %l0, %l1
	bge   L$I_swap
	nop 
	mov %i0, %l3
	mov %i1, %i0
	mov %l3, %i1
	L$I_swap :
	L$B_swap :

/* %l4=...*/
	ld [%i1], %l4
	ld [%i0], %l0
	sub %l0, %l4, %l5
	mov %i2, %l3
	st %l0, [%i2]

	clr %l6

/* loop %l4>0...*/

	tst %l4
	be L$B_loop1
	nop
	L$C_loop1 :
/* ++ */
	inc 4, %i0
	inc 4, %i1
	inc 4, %l3
/* *Ap */
	ld [%i0], %l0
	ld [%i1], %l1
/* get CF  */
	cmp %g0, %l6
/* cadd  */
	addxcc %l0, %l1, %l2
	st %l2, [%l3]
/* save CF */
	addx %g0, %g0, %l6
	deccc %l4
	bne  L$C_loop1
	nop
	L$B_loop1 :


/* loop %l6 &&... */
	tst %l6
	be L$B_loop2
	nop
	tst %l5
	be L$B_loop2
	nop
	L$C_loop2 :
/* ++ */
	inc 4, %i0
	inc 4, %l3
/* *Ap  */
	ld [%i0], %l0
/* cadd  */
	addcc %l0, %l6, %l2
	st %l2, [%l3]
/* save CF  */
	addx %g0,%g0,%l6
/* overflow ? */
	
	bcc L$B_loop2
	nop
	deccc %l5
	bne  L$C_loop2
	nop
	L$B_loop2 :


/* if Sp != Ap */
	cmp %i0, %l3
	be   L$I_equallength
	nop 

	tst %l5
	be L$B_loop3
	nop
	L$C_loop3 :
/* ++ */
	inc 4, %i0
	inc 4, %l3
/* copy */
	ld [%i0], %l0
	st %l0, [%l3]
	deccc %l5
	bne  L$C_loop3
	nop
	L$B_loop3 :

	L$I_equallength :
	L$B_equallength :

/* %l3 longer than a */
	tst %l6
	be   L$I_longer
	nop 
	inc 4, %l3
	st %l6, [%l3]
	ld [%i2], %l2
	inc %l2
	st %l2, [%i2]
	L$I_longer :
	L$B_longer :

	ret     ;
	restore ;






/*      _sub()     translated version of _sub() in add.c

	sparc-assembler

	Thomas Surkau 24.5.91           */


	.global __sub;
	__sub:     ! C function definition
	save %sp, -(((((16*4)+(6*4)+4)+0)+(8-1)) & ~(8-1)), %sp     ! save regs, no additional stack

	mov %i0, %l7
	mov %i2, %l3
	clr %l6


	ld [%i0], %l0
	ld [%i1], %l1
/*        cmp %l0, %l1
	bge   L$I_negative1
	nop 
	call ALU_exception
	L$I_negative1 :
	L$B_negative1 :     */

	ld [%i1], %l4
	ld [%i0], %l0
	sub %l0, %l4, %l5

	tst %l4
	be L$B_loops1
	nop
	L$C_loops1 :
/* ++ */
	inc 4, %i0
	inc 4, %i1
	inc 4, %i2
/*  *Ap  */
	ld [%i0], %l0
	ld [%i1], %l1
/* get CF  */
	cmp %g0, %l6
/* cadd  */
	subxcc %l0, %l1, %l2
	st %l2, [%i2]
/* save CF  */
	addx %g0,%g0,%l6
	deccc %l4
	bne  L$C_loops1
	nop
	L$B_loops1 :

	tst %l6
	be L$B_loops2
	nop
	tst %l5
	be L$B_loops2
	nop
	L$C_loops2 :
	inc 4, %i0
	inc 4, %i2
	ld [%i0], %l0
/* cadd  */
	subcc %l0, %l6, %l2
	st %l2, [%i2]
/* save CF */
	addx %g0,%g0,%l6
/* overflow ? */
	
	bcc L$B_loops2
	nop
	deccc %l5
	bne  L$C_loops2
	nop
	L$B_loops2 :





/* if Sp != Ap */
	cmp %i0, %i2
	be   L$I_equallengths
	nop 

	tst %l5
	be L$B_loops3
	nop
	L$C_loops3 :
/* ++ */
	inc 4, %i0
	inc 4, %i2
/* copy */
	ld [%i0], %l0
	st %l0, [%i2]
	deccc %l5
	bne  L$C_loops3
	nop
	L$B_loops3 :

	L$I_equallengths :
	L$B_equallengths :


/*        tst %l6
	bne  L$I_negative2
	nop
	call ALU_exception
	L$I_negative2 :
	L$B_negative2 :      */

	ld [%l7], %l4
	sll %l4, 2, %l7
	add %l3, %l7, %i2


	L$C_loops4 :
	cmp %i2, %l3
	ble L$B_loops4
	nop
	ld [%i2], %l2
	tst %l2
	bne L$B_loops4
	nop
	dec %l4
	dec 4, %i2
	
	ba  L$C_loops4
	nop
	L$B_loops4 :

	st %l4, [%l3]

	ret     ;
	restore ;








