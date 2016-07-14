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

include(asm_ctl.h)
define(parm_a,%i0)
define(parm_b,%i1)
define(parm_p,%i2)
define(len_a,%l0)
define(len_b,%l1)
define(len_p,%l2)
define(sum_l,%l3)
define(sum_m,%l4)
define(sum_h,%l5)
define(diagnr,%l6)
define(diagpos,%l7)
define(save_a,%i3)
define(save_b,%i4)
define(save_p,%i5)
define(tmp1,%g4)
define(tmp2,%g5)
define(lendiag,%g6)
define(min,%g7)

/*      _mult()

	using .umul() for two-word-multiplication

	sparc-assembler

	Thomas Surkau 24.5.91  */


	ENTRY(_mult)   ! C function definition
	PROLOGUE(752)     ! save regs,   additional stack

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


	clr len_p

/* first, the result is stored on the stack */
	mov parm_p, save_p
	sub %fp, 752, parm_p
	ld [parm_a], len_a
	ld [parm_b], len_b

/* not much to do, if one number equal zero   */
	IFNOT(zero,tst len_a,e)
	IFNOT(zero,tst len_b,e)


	sll len_a, 2, len_a
	sll len_b, 2, len_b

/* calc length of a*b */
	add len_a, len_b, len_p

/* calc min() of lengths */
	IFNOT(mi,`cmp len_a, len_b',le)
	mov len_b, min
	ELSE(mi)
	mov len_a,min
	ENDELSE(mi)

/* save pointer to a and b */
	mov parm_a, save_a
	inc 4, parm_a
	inc 4, parm_b
	mov parm_b, save_b

/* the result of each word*word-operation will be added to these regs
   (low, middle and high word) */
	clr sum_l
	clr sum_m
	clr sum_h

	clr lendiag
	subcc len_p, 4, diagnr

/* loop for all diagonals */
	LOOP(diags)

/* calc number of elements in this diagonal */
	IFNOT(le,`cmp min, diagnr',l)
	mov diagnr, lendiag
	ELSE(le)
	BREAK(le,`cmp min, lendiag',e)
	inc 4, lendiag
	ENDELSE(le)

	sub len_p, diagnr, tmp2

/* set pointer to a and b */
/* two cases if the diagonal starts in row b[1] or not */
	IFNOT(atoshort,`subcc tmp2, len_a, tmp1',le)
	add save_a, len_a, parm_a
	add tmp1, save_b, parm_b
	ELSE(atoshort)
	mov save_b, parm_b
	add save_a, tmp2, parm_a
	ENDELSE(atoshort)

	mov lendiag, diagpos


/* loop for all elements in one diagonal */
	LOOP(elem)

/* unsigned multiply */
	ld [parm_a], %o0
	ld [parm_b], %o1
	call .umul, 2
	nop

/* add the result to the diagonal sum */
	addcc sum_l, %o0, sum_l
	addxcc sum_m, %o1, sum_m
	addx sum_h, %g0, sum_h

	dec 4, parm_a
	inc 4, parm_b

	WHILE(elem,`deccc 4, diagpos',ne)

/* store the lowest word of the sum
   shft down the two highest word to add them to the sum of the
   next diagonal */
	inc 4,parm_p
	st sum_l,[parm_p]
	mov sum_m, sum_l
	mov sum_h, sum_m
	clr sum_h

	WHILE(diags,`deccc 4, diagnr',ne)

/* dec the length, if necessary  */
	IFNOT(lastword,tst sum_l,e)
	inc 4, parm_p
	st sum_l, [parm_p]
	ELSE(lastword)
	dec len_p
	ENDELSE(lastword)
	srl len_p, 2, len_p

	ENDIF(zero)

/* copy p back from stack */
	st len_p, [save_p]
	sub %fp,752,parm_p
	BREAK(copy,tst len_p,e)
	LOOP(copy)
	inc 4, parm_p
	inc 4, save_p
	ld [parm_p],tmp1
	st tmp1,[save_p]
	WHILE(copy,deccc len_p,ne)

	EPILOGUE
