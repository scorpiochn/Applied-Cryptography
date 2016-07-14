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
define(cont_a,%l0)
define(cont_b,%l1)

define(parm_s,%i2)
define(cont_s,%l2)
define(sum,%l3)
define(cnt,%l4)
define(res,%l5)
define(carry,%l6)

/*      _add()     translated version of _add() in add.c

	sparc-assembler

	Thomas Surkau 24.5.91           */


	ENTRY(_add)    ! C function definition
	PROLOGUE(0)     ! save regs, no additional stack




/* if lngofln(ax)... */
	ld [parm_a], cont_a
	ld [parm_b], cont_b
	IFNOT(swap,`cmp cont_a, cont_b',ge)
	mov parm_a, sum
	mov parm_b, parm_a
	mov sum, parm_b
	ENDIF(swap)

/* cnt=...*/
	ld [parm_b], cnt
	ld [parm_a], cont_a
	sub cont_a, cnt, res
	mov parm_s, sum
	st cont_a, [parm_s]

	clr carry

/* loop cnt>0...*/

	BREAK(loop1,tst cnt,e)
	LOOP(loop1)
/* ++ */
	inc 4, parm_a
	inc 4, parm_b
	inc 4, sum
/* *Ap */
	ld [parm_a], cont_a
	ld [parm_b], cont_b
/* get CF  */
	cmp %g0, carry
/* cadd  */
	addxcc cont_a, cont_b, cont_s
	st cont_s, [sum]
/* save CF */
	addx %g0, %g0, carry
	WHILE(loop1,deccc cnt,ne)


/* loop carry &&... */
	BREAK(loop2,tst carry,e)
	BREAK(loop2,tst res,e)
	LOOP(loop2)
/* ++ */
	inc 4, parm_a
	inc 4, sum
/* *Ap  */
	ld [parm_a], cont_a
/* cadd  */
	addcc cont_a, carry, cont_s
	st cont_s, [sum]
/* save CF  */
	addx %g0,%g0,carry
/* overflow ? */
	BREAK(loop2,,cc)
	WHILE(loop2,deccc res,ne)


/* if Sp != Ap */
	IFNOT(equallength,`cmp parm_a, sum',e)

	BREAK(loop3,tst res,e)
	LOOP(loop3)
/* ++ */
	inc 4, parm_a
	inc 4, sum
/* copy */
	ld [parm_a], cont_a
	st cont_a, [sum]
	WHILE(loop3,deccc res,ne)

	ENDIF(equallength)

/* sum longer than a */
	IFNOT(longer,tst carry,e)
	inc 4, sum
	st carry, [sum]
	ld [parm_s], cont_s
	inc cont_s
	st cont_s, [parm_s]
	ENDIF(longer)

	EPILOGUE

define(parm_d,%i2)
define(cont_d,%l2)
define(dp,%l3)
define(opa,%l7)

/*      _sub()     translated version of _sub() in add.c

	sparc-assembler

	Thomas Surkau 24.5.91           */


	ENTRY(_sub)    ! C function definition
	PROLOGUE(0)     ! save regs, no additional stack

	mov parm_a, opa
	mov parm_d, dp
	clr carry


	ld [parm_a], cont_a
	ld [parm_b], cont_b
/*        IFNOT(negative1,`cmp cont_a, cont_b',ge)
	call ALU_exception
	ENDIF(negative1)     */

	ld [parm_b], cnt
	ld [parm_a], cont_a
	sub cont_a, cnt, res

	BREAK(loops1,tst cnt,e)
	LOOP(loops1)
/* ++ */
	inc 4, parm_a
	inc 4, parm_b
	inc 4, parm_d
/*  *Ap  */
	ld [parm_a], cont_a
	ld [parm_b], cont_b
/* get CF  */
	cmp %g0, carry
/* cadd  */
	subxcc cont_a, cont_b, cont_d
	st cont_d, [parm_d]
/* save CF  */
	addx %g0,%g0,carry
	WHILE(loops1,deccc cnt,ne)

	BREAK(loops2,tst carry,e)
	BREAK(loops2,tst res,e)
	LOOP(loops2)
	inc 4, parm_a
	inc 4, parm_d
	ld [parm_a], cont_a
/* cadd  */
	subcc cont_a, carry, cont_d
	st cont_d, [parm_d]
/* save CF */
	addx %g0,%g0,carry
/* overflow ? */
	BREAK(loops2,,cc)
	WHILE(loops2,deccc res,ne)





/* if Sp != Ap */
	IFNOT(equallengths,`cmp parm_a, parm_d',e)

	BREAK(loops3,tst res,e)
	LOOP(loops3)
/* ++ */
	inc 4, parm_a
	inc 4, parm_d
/* copy */
	ld [parm_a], cont_a
	st cont_a, [parm_d]
	WHILE(loops3,deccc res,ne)

	ENDIF(equallengths)


/*        IF(negative2,tst carry)
	call ALU_exception
	ENDIF(negative2)      */

	ld [opa], cnt
	sll cnt, 2, opa
	add dp, opa, parm_d


	FOR(loops4,`cmp parm_d, dp',le)
	ld [parm_d], cont_d
	BREAK(loops4,tst cont_d,ne)
	dec cnt
	dec 4, parm_d
	ENDFOR(loops4)

	st cnt, [dp]

	EPILOGUE








