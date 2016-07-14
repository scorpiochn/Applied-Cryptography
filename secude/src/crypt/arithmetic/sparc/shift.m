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
define(parm_c,%i2)
define(save_c,%g1)
define(len_a,%l0)
define(len_c,%l1)
define(lw,%l2)
define(rw,%l3)
define(nw,%l4)
define(left,%l5)
define(right,%l6)
define(tmp1,%g2)
define(tmp2,%g3)
define(tmp3,%g4)





/*      _shift()

	sparc-assembler

	Thomas Surkau 24.5.91
				*/



	ENTRY(_shift)
	PROLOGUE(752)

	ld [parm_a],len_a
	mov parm_c,save_c

/* not much to do if length equal 0 */
	IFNOT(zero,tst len_a,ne)
	st len_a,[parm_c]
	b BRL(end)
	nop
	ENDIF(zero)

/* copy a to stack, if a and c have the same position in memory  */
	IFNOT(samemem,`cmp parm_a,parm_c',ne)
	sub %fp,752,tmp1
	st len_a,[tmp1]
	LOOP(copy)
	inc 4,tmp1
	inc 4,parm_a
	ld [parm_a],tmp2
	st tmp2,[tmp1]
	WHILE(copy,deccc len_a,ne)
	sub %fp,752,parm_a
	ld [parm_a],len_a
	ENDIF(samemem)



/* different procedures for left and right shft
   and for special event b and 31==0 (word shft) */

	IFNOT(sign,tst parm_b,l)

	IFNOT(mod32,`andcc parm_b,31,%g0',ne)

/* shft words left (or only copy if b=0) */

	srl parm_b,5,parm_b
	add len_a,parm_b ,len_c
	st len_c,[parm_c]
	BREAK(fillzero,tst parm_b,e)
	LOOP(fillzero)
	inc 4,parm_c
	st %g0,[parm_c]
	WHILE(fillzero,deccc parm_b,ne)

	BREAK(cp1,tst len_a,e)
	LOOP(cp1)
	inc 4,parm_c
	inc 4,parm_a
	ld [parm_a],tmp1
	st tmp1,[parm_c]
	WHILE(cp1,deccc len_a,ne)







	ELSE(mod32)

/* shft bits left */

	and parm_b,31,left
	set 32,right
	sub right,left,right

	srl parm_b,5,parm_b
	add len_a,parm_b ,len_c
	st len_c,[parm_c]

	BREAK(fillzero2,tst parm_b,e)
	LOOP(fillzero2)
	inc 4,parm_c
	st %g0,[parm_c]
	WHILE(fillzero2,deccc parm_b,ne)

	clr rw
	BREAK(shl,tst len_a,e)
	LOOP(shl)
	inc 4,parm_a
	inc 4,parm_c
	ld [parm_a],lw
	sll lw,left,nw
	srl rw,right,rw
	or nw,rw,nw
	st nw,[parm_c]
	mov lw,rw
	WHILE(shl,deccc len_a,ne)

/* inc length if the highest bit is shfted into the next word */
	srl rw,right,nw
	IFNOT(more,tst nw,e)
	inc 4,parm_c
	st nw,[parm_c]
	inc len_c
	st len_c,[save_c]
	ENDIF(more)






	ENDELSE(mod32)
	ELSE(sign)

	sub %g0,parm_b,parm_b
	IFNOT(mod_32,`andcc parm_b,31,%g0',ne)
/* shft word right */


	srl parm_b,5,parm_b
	sub len_a,parm_b,len_c
	st len_c,[parm_c]
	sll parm_b,2,parm_b
	add parm_a,parm_b,parm_a
	BREAK(cp2,tst len_c,e)
	LOOP(cp2)
	inc 4,parm_c
	inc 4,parm_a
	ld [parm_a],tmp1
	st tmp1,[parm_c]
	WHILE(cp2,deccc len_c,ne)






	ELSE(mod_32)

/* shft bits right */

	and parm_b,31,right
	set 32,left
	sub left,right,left

	srl parm_b,5,parm_b

/* exit if abs(b) is to big */
	IFNOT(toshort,`subcc len_a,parm_b ,len_c',g)
	clr len_c
	st len_c,[parm_c]
	b BRL(end)
	nop
	ENDIF(toshort)

	st len_c,[parm_c]

	sll parm_b,2,tmp1
	add parm_a,tmp1,parm_a
	inc 4,parm_a

	ld [parm_a],rw
	BREAK(shr,`subcc len_c,1,tmp1',e)
	LOOP(shr)
	inc 4,parm_a
	inc 4,parm_c
	ld [parm_a],lw
	sll lw,left,nw
	srl rw,right,rw
	or nw,rw,nw
	st nw,[parm_c]
	mov lw,rw
	WHILE(shr,deccc tmp1,ne)

	srl rw,right,nw

/* dec length if the highest word is equal 0 */
	IFNOT(less,tst nw,e)
	inc 4,parm_c
	st nw,[parm_c]
	ELSE(less)
	dec len_c
	st len_c,[save_c]
	ENDELSE(less)





	ENDELSE(mod_32)

	ENDELSE(sign)
BRL(end):
	EPILOGUE
