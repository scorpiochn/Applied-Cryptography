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






























































/*      _shift()

	sparc-assembler

	Thomas Surkau 24.5.91
				*/



	.global __shift;
	__shift: 
	save %sp, -(((((16*4)+(6*4)+4)+752)+(8-1)) & ~(8-1)), %sp

	ld [%i0],%l0
	mov %i2,%g1

/* not much to do if length equal 0 */
	tst %l0
	bne   L$I_zero
	nop 
	st %l0,[%i2]
	b L$B_end
	nop
	L$I_zero :
	L$B_zero :

/* copy a to stack, if a and c have the same position in memory  */
	cmp %i0,%i2
	bne   L$I_samemem
	nop 
	sub %fp,752,%g2
	st %l0,[%g2]
	L$C_copy :
	inc 4,%g2
	inc 4,%i0
	ld [%i0],%g3
	st %g3,[%g2]
	deccc %l0
	bne  L$C_copy
	nop
	L$B_copy :
	sub %fp,752,%i0
	ld [%i0],%l0
	L$I_samemem :
	L$B_samemem :



/* different procedures for %l5 and %l6 shft
   and for special event b and 31==0 (word shft) */

	tst %i1
	bl   L$I_sign
	nop 

	andcc %i1,31,%g0
	bne   L$I_mod32
	nop 

/* shft words %l5 (or only copy if b=0) */

	srl %i1,5,%i1
	add %l0,%i1 ,%l1
	st %l1,[%i2]
	tst %i1
	be L$B_fillzero
	nop
	L$C_fillzero :
	inc 4,%i2
	st %g0,[%i2]
	deccc %i1
	bne  L$C_fillzero
	nop
	L$B_fillzero :

	tst %l0
	be L$B_cp1
	nop
	L$C_cp1 :
	inc 4,%i2
	inc 4,%i0
	ld [%i0],%g2
	st %g2,[%i2]
	deccc %l0
	bne  L$C_cp1
	nop
	L$B_cp1 :







	
	ba L$B_mod32
	nop ;
	L$I_mod32 :

/* shft bits %l5 */

	and %i1,31,%l5
	set 32,%l6
	sub %l6,%l5,%l6

	srl %i1,5,%i1
	add %l0,%i1 ,%l1
	st %l1,[%i2]

	tst %i1
	be L$B_fillzero2
	nop
	L$C_fillzero2 :
	inc 4,%i2
	st %g0,[%i2]
	deccc %i1
	bne  L$C_fillzero2
	nop
	L$B_fillzero2 :

	clr %l3
	tst %l0
	be L$B_shl
	nop
	L$C_shl :
	inc 4,%i0
	inc 4,%i2
	ld [%i0],%l2
	sll %l2,%l5,%l4
	srl %l3,%l6,%l3
	or %l4,%l3,%l4
	st %l4,[%i2]
	mov %l2,%l3
	deccc %l0
	bne  L$C_shl
	nop
	L$B_shl :

/* inc length if the highest bit is shfted into the next word */
	srl %l3,%l6,%l4
	tst %l4
	be   L$I_more
	nop 
	inc 4,%i2
	st %l4,[%i2]
	inc %l1
	st %l1,[%g1]
	L$I_more :
	L$B_more :






	L$B_mod32 :
	
	ba L$B_sign
	nop ;
	L$I_sign :

	sub %g0,%i1,%i1
	andcc %i1,31,%g0
	bne   L$I_mod_32
	nop 
/* shft word %l6 */


	srl %i1,5,%i1
	sub %l0,%i1,%l1
	st %l1,[%i2]
	sll %i1,2,%i1
	add %i0,%i1,%i0
	tst %l1
	be L$B_cp2
	nop
	L$C_cp2 :
	inc 4,%i2
	inc 4,%i0
	ld [%i0],%g2
	st %g2,[%i2]
	deccc %l1
	bne  L$C_cp2
	nop
	L$B_cp2 :






	
	ba L$B_mod_32
	nop ;
	L$I_mod_32 :

/* shft bits %l6 */

	and %i1,31,%l6
	set 32,%l5
	sub %l5,%l6,%l5

	srl %i1,5,%i1

/* exit if abs(b) is to big */
	subcc %l0,%i1 ,%l1
	bg   L$I_toshort
	nop 
	clr %l1
	st %l1,[%i2]
	b L$B_end
	nop
	L$I_toshort :
	L$B_toshort :

	st %l1,[%i2]

	sll %i1,2,%g2
	add %i0,%g2,%i0
	inc 4,%i0

	ld [%i0],%l3
	subcc %l1,1,%g2
	be L$B_shr
	nop
	L$C_shr :
	inc 4,%i0
	inc 4,%i2
	ld [%i0],%l2
	sll %l2,%l5,%l4
	srl %l3,%l6,%l3
	or %l4,%l3,%l4
	st %l4,[%i2]
	mov %l2,%l3
	deccc %g2
	bne  L$C_shr
	nop
	L$B_shr :

	srl %l3,%l6,%l4

/* dec length if the highest word is equal 0 */
	tst %l4
	be   L$I_less
	nop 
	inc 4,%i2
	st %l4,[%i2]
	
	ba L$B_less
	nop ;
	L$I_less :
	dec %l1
	st %l1,[%g1]
	L$B_less :





	L$B_mod_32 :

	L$B_sign :
L$B_end:
	ret     ;
	restore ;
