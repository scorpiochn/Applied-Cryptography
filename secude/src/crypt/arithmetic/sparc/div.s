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












































/* parameter a,b,c and d */




/* parameter quotient and rest will bee
	copied to c and d after calculation */


/* variables
	n length divisor
	k length divident
	m length rest
	q quotient
			*/


















/*      _div()

	
	sparc-assembler

	Thomas Surkau 24.5.91  */


	.global __div;
	__div: 
	save %sp, -(((((16*4)+(6*4)+4)+1128)+(8-1)) & ~(8-1)), %sp

/***********************************************/

/* set length */
	ld [%i1], %l0
	ld [%i0], %l3
	sll %l0, 2, %l0
	sll %l3, 2, %l3
	sub %l3, %l0, %l1

/***********************************************/


/* division by 0 */
	tst %l0
	bne  L$I_null
	nop
	mov -1, %i0
	ba endofdiv
	nop
	L$I_null :
	L$B_null :

/***********************************************/


/* divident<divisor (length) */
	cmp %l0, %l3
	ble   L$I_trivial
	nop 
/* quotient is 0 */
/* set quotient */
	st %g0, [%i2]

/* copy divident to rest */
	srl %l3, 2, %g4
	st %g4, [%i3]
	tst %l3
	be ok
	nop

	L$C_cp1 :
	ld [%i0+%l3], %g4
	st %g4, [%i3+%l3]
	subcc %l3, 4, %l3
	bne  L$C_cp1
	nop
	L$B_cp1 :
	
	ba ok
	nop
	L$I_trivial :
	L$B_trivial :


/***********************************************/


/* working space for quotient and rest */
	sub %fp, 376, %i4
	sub %fp, 752, %i5

/* copy divident */
	mov %l3, %g5
	L$C_cp2 :
	ld [%i0+%g5], %g4
	st %g4, [%i5+%g5]
	subcc %g5, 4, %g5
	bge  L$C_cp2
	nop
	L$B_cp2 :

/***********************************************/


	subcc %l0, 4, %g0
	bne  L$I_one
	nop
/* divisor hat only one word */
	
	mov %l3, %g4
/* set parameters for division loop */
/* divisor is every time the same and won't be changed */
	ld [%i1+4], %o2

	clr %o0

/* loop for division by one word */
	L$C_div1 :
/* set the lowword (the high word is the rest of the last call) */
	ld [%i5+%g4], %o1

	call __divlu, 3
	nop
	st %o4, [%i4+%g4]
	subcc %g4, 4, %g4
	bne  L$C_div1
	nop
	L$B_div1 :

	ld [%i4+%l3], %g4

/* perhaps high word is 0 */
	tst %g4
	bne  L$I_kuerzen
	nop
	subcc %l3, 4, %l3
	L$I_kuerzen :
	L$B_kuerzen :

	srl %l3, 2, %g4
	st %g4, [%i4]

/* copy quotient */
	L$C_cp3 :
	ld [%i4+%l3], %g4
	st %g4, [%i2+%l3]
	subcc %l3, 4, %l3
	bgeu  L$C_cp3
	nop
	L$B_cp3 :


/* copy rest */
	tst %o0
	bne  L$I_rest0
	nop
	st %g0, [%i3]
	
	ba L$B_rest0
	nop ;
	L$I_rest0 :
	mov 1, %g4
	st %g4, [%i3]
	st %o0, [%i3+4]
	L$B_rest0 :


	ba ok
	nop

	L$I_one :
	L$B_one :

/***********************************************/
/***********************************************/
/***********************************************/

/* begin of algorithm */
/* Knuth Page 237 Algorithm D */

/* D1 normalise:  %l3 divident and divisor  */
/* to the left, until the highest bit of the */ 
/* divisor is on the left side of one word */

	ld [%i1+%l0], %g4
	mov -1, %l3

/* count the bits to %l3 */
shftlen:
	addcc %g4, %g4, %g4
	bcc shftlen
	inccc %l3

	be noshft1

/* %l3 */
	mov %i1, %o0
	mov %l3, %o1
	sub %fp, 1128, %i1
	mov %i1, %o2
	call __shift, 3
	nop

	mov %i5, %o0
	mov %l3, %o1
	mov %i5, %o2
	call __shift, 3
	nop
noshft1:
/* set u_0 to 0 (perhaps u_(-1) but doesn't matter*/
	ld [%i5], %g4
	sll %g4, 2, %g4
	add %g4, 4, %g4
	st %g0, [%i5+%g4]



/***********************************************/
/* D2 begin of main loop (j:=0 to m) */
/* m+1 to 1 because long number is stored in */
/* reverse order */
	
	add %l1, 4, %l4
mloop:
/***********************************************/
/* D3 calculate q */

/* %l5 : ptr to u_j    ;    %l6 : ptr to v_1  */

	add %i5, %l0, %l5
	add %l5, %l4, %l5

	add %i1, %l0, %l6

/* calculate q := (u_j*2^32 + u_(j+1)) div v_1 */
	ld [%l5], %o0
	ld [%l6], %o2
	cmp %o0, %o2
	be equal
	mov -1, %l2

	ld [%l5-4], %o1
	call __divlu, 3
	nop
	mov %o4, %l2

equal:
test:
/* calculate v_1*q*2^32 + v_2*q to %g4-3 */
/* ( 3 words )*/

/* v_2 * q */
	ld [%l6-4], %o0
	mov %l2, %o1
	call .umul, 2
	nop
	mov %o0, %g4
	mov %o1, %g5

/* v_1 * q */
	ld [%l6], %o0
	mov %l2, %o1
	call .umul, 2
	nop
	addcc %g5, %o0, %g5
	addx %g0, %o1, %g6

/* compare %g4-3 with u_j - u_(j+2) ( 3 words ) */
/* and repeat test with q:= q - 1*/

	dec %l2

	ld [%l5], %g7
	cmp %g6 , %g7
	bgu test
	nop
	blu norep
	nop

	ld [%l5-4], %g7
	cmp %g5 , %g7
	bgu test
	nop
	blu norep
	nop

	ld [%l5-8], %g7
	cmp %g4 , %g7
	bgu test
	nop

norep:
	inc %l2

/***********************************************/
/* D4 mult and sub ( u := u-q*v ) */

	mov %l0, %g4
	add %i1, 4, %l6
	sub %l5, %l0, %l5
	ld [%l5], %g5
	clr %g7
subloop:
	ld [%l5+4], %g6
	ld [%l6], %o0
	mov %l2, %o1	
	call .umul, 2	
	nop
	add %o1, %g7, %o1
	subxcc %g5, %o0, %g5
	subxcc %g6, %o1, %g6	
	addx %g0, %g0, %g7
	
	st %g5, [%l5]
	mov %g6, %g5

	add %l6, 4, %l6

	subcc %g4, 4, %g4
	bne subloop
	add %l5, 4, %l5

	st %g6, [%l5]

/***********************************************/
/* D5 test, if u positiv */

	tst %g7
	be pos
	nop
/***********************************************/
/* D6 addback, because q was one to big */
/*  ( u := u - v ) */

	dec %l2
	
	mov %l0, %g4
	add %i1, 4, %l6
	sub %l5, %l0, %l5
	clr %g7
addback:
	ld [%l5], %g5
	ld [%l6], %g6

	subcc %g0, %g7, %g0
	addxcc %g5, %g6, %g5
	addx %g0, %g0, %g7
	
	st %g5, [%l5]

	add %l6, 4, %l6

	subcc %g4, 4, %g4
	bne addback
	add %l5, 4, %l5

	ld [%l5], %g5
	add %g5, %g7, %g5
	st %g5, [%l5]



pos:	
/* store q in quotient array */

	st %l2, [%i4+%l4]

/***********************************************/
/* D7 end of main loop */

	subcc %l4, 4, %l4
	bne mloop
	nop


/* test length of quotient  */
/* ( high word may be 0 ) */

	add %l1, 4, %l1
next1:
	ld [%i4+%l1], %g4
	tst %g4
	bne ex1
	nop
	subcc %l1, 4, %l1
	bne next1
	nop
ex1:
	srl %l1, 2, %l1
	st %l1, [%i4]


/* test length of rest */
/* ( high word may be 0 ) */

next2:
	ld [%i5+%l0], %g4
	tst %g4
	bne ex2
	nop
	subcc %l0, 4, %l0
	bne next2
	nop
ex2:

	srl %l0, 2, %l0
	st %l0, [%i5]

/***********************************************/
/* D8 %l3 rest back */

	tst %l3
	be noshft2
	mov %i5, %o0
	sub %g0, %l3, %o1
	mov %i5, %o2
	call __shift, 3
	nop


noshft2:

/* end of algorithm D */
/***********************************************/
/***********************************************/
/***********************************************/

/* copy quotient */
	ld [%i4], %g5
	sll %g5, 2, %g5
	L$C_cp4 :
	ld [%i4+%g5], %g4
	st %g4, [%i2+%g5]
	subcc %g5, 4, %g5
	bgeu  L$C_cp4
	nop
	L$B_cp4 :


/* copy rest */
	ld [%i5], %g5
	sll %g5, 2, %g5
	L$C_cp5 :
	ld [%i5+%g5], %g4
	st %g4, [%i3+%g5]
	subcc %g5, 4, %g5
	bgeu  L$C_cp5
	nop
	L$B_cp5 :


/***********************************************/





ok:
	mov 0, %i0
endofdiv:
	ret     ;
	restore ;




/* 
	divlu()

	Input:

	%i0 : Highword Divident
	%i1 : Lowword  Divident
	%i2 : 	       Divisor

	%i0<%i2 expected


	Output:

	%i0 : 	Rest      ( %i0*2^32 + %i1 ) mod %i2
	%i4 : 	Quotient  ( %i0*2^32 + %i1 ) div %i2

				*/		

	.global __divlu;
	__divlu: 
	save %sp, -(((((16*4)+(6*4)+4)+0)+(8-1)) & ~(8-1)), %sp

	clr %i4

	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub0
	subcc %i0, %i2, %l1
	blu nosub0
sub0:
	nop
	or %i4, 1, %i4
	mov %l1, %i0
nosub0:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub1
	subcc %i0, %i2, %l1
	blu nosub1
sub1:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub1:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub2
	subcc %i0, %i2, %l1
	blu nosub2
sub2:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub2:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub3
	subcc %i0, %i2, %l1
	blu nosub3
sub3:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub3:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub4
	subcc %i0, %i2, %l1
	blu nosub4
sub4:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub4:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub5
	subcc %i0, %i2, %l1
	blu nosub5
sub5:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub5:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub6
	subcc %i0, %i2, %l1
	blu nosub6
sub6:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub6:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub7
	subcc %i0, %i2, %l1
	blu nosub7
sub7:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub7:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub8
	subcc %i0, %i2, %l1
	blu nosub8
sub8:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub8:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub9
	subcc %i0, %i2, %l1
	blu nosub9
sub9:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub9:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub10
	subcc %i0, %i2, %l1
	blu nosub10
sub10:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub10:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub11
	subcc %i0, %i2, %l1
	blu nosub11
sub11:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub11:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub12
	subcc %i0, %i2, %l1
	blu nosub12
sub12:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub12:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub13
	subcc %i0, %i2, %l1
	blu nosub13
sub13:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub13:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub14
	subcc %i0, %i2, %l1
	blu nosub14
sub14:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub14:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub15
	subcc %i0, %i2, %l1
	blu nosub15
sub15:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub15:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub16
	subcc %i0, %i2, %l1
	blu nosub16
sub16:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub16:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub17
	subcc %i0, %i2, %l1
	blu nosub17
sub17:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub17:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub18
	subcc %i0, %i2, %l1
	blu nosub18
sub18:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub18:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub19
	subcc %i0, %i2, %l1
	blu nosub19
sub19:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub19:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub20
	subcc %i0, %i2, %l1
	blu nosub20
sub20:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub20:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub21
	subcc %i0, %i2, %l1
	blu nosub21
sub21:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub21:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub22
	subcc %i0, %i2, %l1
	blu nosub22
sub22:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub22:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub23
	subcc %i0, %i2, %l1
	blu nosub23
sub23:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub23:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub24
	subcc %i0, %i2, %l1
	blu nosub24
sub24:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub24:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub25
	subcc %i0, %i2, %l1
	blu nosub25
sub25:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub25:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub26
	subcc %i0, %i2, %l1
	blu nosub26
sub26:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub26:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub27
	subcc %i0, %i2, %l1
	blu nosub27
sub27:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub27:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub28
	subcc %i0, %i2, %l1
	blu nosub28
sub28:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub28:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub29
	subcc %i0, %i2, %l1
	blu nosub29
sub29:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub29:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub30
	subcc %i0, %i2, %l1
	blu nosub30
sub30:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub30:
	addcc %i1, %i1, %i1
	addxcc %i0, %i0, %i0  
	bcs sub31
	subcc %i0, %i2, %l1
	blu nosub31
sub31:
	sll %i4, 1, %i4
	or %i4, 1, %i4
	mov %l1, %i0
nosub31:




	ret     ;
	restore ;







