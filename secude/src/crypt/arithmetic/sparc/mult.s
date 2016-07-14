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






























































/*      _mult()

	using .umul() for two-word-multiplication

	sparc-assembler

	Thomas Surkau 24.5.91  */


	.global __mult;
	__mult:    ! C function definition
	save %sp, -(((((16*4)+(6*4)+4)+752)+(8-1)) & ~(8-1)), %sp     ! save regs,   additional stack

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


	clr %l2

/* first, the result is stored on the stack */
	mov %i2, %i5
	sub %fp, 752, %i2
	ld [%i0], %l0
	ld [%i1], %l1

/* not much to do, if one number equal zero   */
	tst %l0
	be   L$I_zero
	nop 
	tst %l1
	be   L$I_zero
	nop 


	sll %l0, 2, %l0
	sll %l1, 2, %l1

/* calc length of a*b */
	add %l0, %l1, %l2

/* calc %g7 of lengths */
	cmp %l0, %l1
	ble   L$I_mi
	nop 
	mov %l1, %g7
	
	ba L$B_mi
	nop ;
	L$I_mi :
	mov %l0,%g7
	L$B_mi :

/* save pointer to a and b */
	mov %i0, %i3
	inc 4, %i0
	inc 4, %i1
	mov %i1, %i4

/* the result of each word*word-operation will be added to these regs
   (low, middle and high word) */
	clr %l3
	clr %l4
	clr %l5

	clr %g6
	subcc %l2, 4, %l6

/* loop for all diagonals */
	L$C_diags :

/* calc number of elements in this diagonal */
	cmp %g7, %l6
	bl   L$I_le
	nop 
	mov %l6, %g6
	
	ba L$B_le
	nop ;
	L$I_le :
	cmp %g7, %g6
	be L$B_le
	nop
	inc 4, %g6
	L$B_le :

	sub %l2, %l6, %g5

/* set pointer to a and b */
/* two cases if the diagonal starts in row b[1] or not */
	subcc %g5, %l0, %g4
	ble   L$I_atoshort
	nop 
	add %i3, %l0, %i0
	add %g4, %i4, %i1
	
	ba L$B_atoshort
	nop ;
	L$I_atoshort :
	mov %i4, %i1
	add %i3, %g5, %i0
	L$B_atoshort :

	mov %g6, %l7


/* loop for all elements in one diagonal */
	L$C_elem :

/* unsigned multiply */
	ld [%i0], %o0
	ld [%i1], %o1
	call .umul, 2
	nop

/* add the result to the diagonal sum */
	addcc %l3, %o0, %l3
	addxcc %l4, %o1, %l4
	addx %l5, %g0, %l5

	dec 4, %i0
	inc 4, %i1

	deccc 4, %l7
	bne  L$C_elem
	nop
	L$B_elem :

/* store the lowest word of the sum
   shft down the two highest word to add them to the sum of the
   next diagonal */
	inc 4,%i2
	st %l3,[%i2]
	mov %l4, %l3
	mov %l5, %l4
	clr %l5

	deccc 4, %l6
	bne  L$C_diags
	nop
	L$B_diags :

/* dec the length, if necessary  */
	tst %l3
	be   L$I_lastword
	nop 
	inc 4, %i2
	st %l3, [%i2]
	
	ba L$B_lastword
	nop ;
	L$I_lastword :
	dec %l2
	L$B_lastword :
	srl %l2, 2, %l2

	L$I_zero :
	L$B_zero :

/* copy p back from stack */
	st %l2, [%i5]
	sub %fp,752,%i2
	tst %l2
	be L$B_copy
	nop
	L$C_copy :
	inc 4, %i2
	inc 4, %i5
	ld [%i2],%g4
	st %g4,[%i5]
	deccc %l2
	bne  L$C_copy
	nop
	L$B_copy :

	ret     ;
	restore ;
