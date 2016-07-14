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

/* parameter a,b,c and d */
define(paa,%i0)
define(pab,%i1)
define(pac,%i2)
define(pad,%i3)
/* parameter quotient and rest will bee
	copied to c and d after calculation */
define(paq,%i4)
define(par,%i5)
/* variables
	n length divisor
	k length divident
	m length rest
	q quotient
			*/
define(vn,%l0)
define(vm,%l1)
define(vq,%l2)
define(vk,%l3)
define(vj,%l4)
define(vuj,%l5)
define(vv1,%l6)
define(shft,%l3)
define(tmp1,%g4)
define(tmp2,%g5)
define(tmp3,%g6)
define(tmp4,%g7)






/*      _div()

	
	sparc-assembler

	Thomas Surkau 24.5.91  */


	ENTRY(_div)
	PROLOGUE(1128)

/***********************************************/

/* set length */
	ld [pab], vn
	ld [paa], vk
	sll vn, 2, vn
	sll vk, 2, vk
	sub vk, vn, vm

/***********************************************/


/* division by 0 */
	IF(null, tst vn)
	mov -1, %i0
	ba endofdiv
	nop
	ENDIF(null)

/***********************************************/


/* divident<divisor (length) */
	IFNOT(trivial, `cmp vn, vk', le)
/* quotient is 0 */
/* set quotient */
	st %g0, [pac]

/* copy divident to rest */
	srl vk, 2, tmp1
	st tmp1, [pad]
	tst vk
	be ok
	nop

	LOOP(cp1)
	ld [paa+vk], tmp1
	st tmp1, [pad+vk]
	WHILE(cp1, `subcc vk, 4, vk', ne)
	
	ba ok
	nop
	ENDIF(trivial)


/***********************************************/


/* working space for quotient and rest */
	sub %fp, 376, paq
	sub %fp, 752, par

/* copy divident */
	mov vk, tmp2
	LOOP(cp2)
	ld [paa+tmp2], tmp1
	st tmp1, [par+tmp2]
	WHILE(cp2, `subcc tmp2, 4, tmp2', ge)

/***********************************************/


	IF(one, `subcc vn, 4, %g0')
/* divisor hat only one word */
	
	mov vk, tmp1
/* set parameters for division loop */
/* divisor is every time the same and won't be changed */
	ld [pab+4], %o2

	clr %o0

/* loop for division by one word */
	LOOP(div1)
/* set the lowword (the high word is the rest of the last call) */
	ld [par+tmp1], %o1

	call __divlu, 3
	nop
	st %o4, [paq+tmp1]
	WHILE(div1, `subcc tmp1, 4, tmp1', ne)

	ld [paq+vk], tmp1

/* perhaps high word is 0 */
	IF(kuerzen, tst tmp1)
	subcc vk, 4, vk
	ENDIF(kuerzen)

	srl vk, 2, tmp1
	st tmp1, [paq]

/* copy quotient */
	LOOP(cp3)
	ld [paq+vk], tmp1
	st tmp1, [pac+vk]
	WHILE(cp3, `subcc vk, 4, vk', geu)


/* copy rest */
	IF(rest0, tst %o0)
	st %g0, [pad]
	ELSE(rest0)
	mov 1, tmp1
	st tmp1, [pad]
	st %o0, [pad+4]
	ENDELSE(rest0)


	ba ok
	nop

	ENDIF(one)

/***********************************************/
/***********************************************/
/***********************************************/

/* begin of algorithm */
/* Knuth Page 237 Algorithm D */

/* D1 normalise:  shft divident and divisor  */
/* to the left, until the highest bit of the */ 
/* divisor is on the left side of one word */

	ld [pab+vn], tmp1
	mov -1, shft

/* count the bits to shft */
shftlen:
	addcc tmp1, tmp1, tmp1
	bcc shftlen
	inccc shft

	be noshft1

/* shft */
	mov pab, %o0
	mov shft, %o1
	sub %fp, 1128, pab
	mov pab, %o2
	call __shift, 3
	nop

	mov par, %o0
	mov shft, %o1
	mov par, %o2
	call __shift, 3
	nop
noshft1:
/* set u_0 to 0 (perhaps u_(-1) but doesn't matter*/
	ld [par], tmp1
	sll tmp1, 2, tmp1
	add tmp1, 4, tmp1
	st %g0, [par+tmp1]



/***********************************************/
/* D2 begin of main loop (j:=0 to m) */
/* m+1 to 1 because long number is stored in */
/* reverse order */
	
	add vm, 4, vj
mloop:
/***********************************************/
/* D3 calculate q */

/* vuj : ptr to u_j    ;    vv1 : ptr to v_1  */

	add par, vn, vuj
	add vuj, vj, vuj

	add pab, vn, vv1

/* calculate q := (u_j*2^32 + u_(j+1)) div v_1 */
	ld [vuj], %o0
	ld [vv1], %o2
	cmp %o0, %o2
	be equal
	mov -1, vq

	ld [vuj-4], %o1
	call __divlu, 3
	nop
	mov %o4, vq

equal:
test:
/* calculate v_1*q*2^32 + v_2*q to tmp1-3 */
/* ( 3 words )*/

/* v_2 * q */
	ld [vv1-4], %o0
	mov vq, %o1
	call .umul, 2
	nop
	mov %o0, tmp1
	mov %o1, tmp2

/* v_1 * q */
	ld [vv1], %o0
	mov vq, %o1
	call .umul, 2
	nop
	addcc tmp2, %o0, tmp2
	addx %g0, %o1, tmp3

/* compare tmp1-3 with u_j - u_(j+2) ( 3 words ) */
/* and repeat test with q:= q - 1*/

	dec vq

	ld [vuj], tmp4
	cmp tmp3 , tmp4
	bgu test
	nop
	blu norep
	nop

	ld [vuj-4], tmp4
	cmp tmp2 , tmp4
	bgu test
	nop
	blu norep
	nop

	ld [vuj-8], tmp4
	cmp tmp1 , tmp4
	bgu test
	nop

norep:
	inc vq

/***********************************************/
/* D4 mult and sub ( u := u-q*v ) */

	mov vn, tmp1
	add pab, 4, vv1
	sub vuj, vn, vuj
	ld [vuj], tmp2
	clr tmp4
subloop:
	ld [vuj+4], tmp3
	ld [vv1], %o0
	mov vq, %o1	
	call .umul, 2	
	nop
	add %o1, tmp4, %o1
	subxcc tmp2, %o0, tmp2
	subxcc tmp3, %o1, tmp3	
	addx %g0, %g0, tmp4
	
	st tmp2, [vuj]
	mov tmp3, tmp2

	add vv1, 4, vv1

	subcc tmp1, 4, tmp1
	bne subloop
	add vuj, 4, vuj

	st tmp3, [vuj]

/***********************************************/
/* D5 test, if u positiv */

	tst tmp4
	be pos
	nop
/***********************************************/
/* D6 addback, because q was one to big */
/*  ( u := u - v ) */

	dec vq
	
	mov vn, tmp1
	add pab, 4, vv1
	sub vuj, vn, vuj
	clr tmp4
addback:
	ld [vuj], tmp2
	ld [vv1], tmp3

	subcc %g0, tmp4, %g0
	addxcc tmp2, tmp3, tmp2
	addx %g0, %g0, tmp4
	
	st tmp2, [vuj]

	add vv1, 4, vv1

	subcc tmp1, 4, tmp1
	bne addback
	add vuj, 4, vuj

	ld [vuj], tmp2
	add tmp2, tmp4, tmp2
	st tmp2, [vuj]



pos:	
/* store q in quotient array */

	st vq, [paq+vj]

/***********************************************/
/* D7 end of main loop */

	subcc vj, 4, vj
	bne mloop
	nop


/* test length of quotient  */
/* ( high word may be 0 ) */

	add vm, 4, vm
next1:
	ld [paq+vm], tmp1
	tst tmp1
	bne ex1
	nop
	subcc vm, 4, vm
	bne next1
	nop
ex1:
	srl vm, 2, vm
	st vm, [paq]


/* test length of rest */
/* ( high word may be 0 ) */

next2:
	ld [par+vn], tmp1
	tst tmp1
	bne ex2
	nop
	subcc vn, 4, vn
	bne next2
	nop
ex2:

	srl vn, 2, vn
	st vn, [par]

/***********************************************/
/* D8 shft rest back */

	tst shft
	be noshft2
	mov par, %o0
	sub %g0, shft, %o1
	mov par, %o2
	call __shift, 3
	nop


noshft2:

/* end of algorithm D */
/***********************************************/
/***********************************************/
/***********************************************/

/* copy quotient */
	ld [paq], tmp2
	sll tmp2, 2, tmp2
	LOOP(cp4)
	ld [paq+tmp2], tmp1
	st tmp1, [pac+tmp2]
	WHILE(cp4, `subcc tmp2, 4, tmp2', geu)


/* copy rest */
	ld [par], tmp2
	sll tmp2, 2, tmp2
	LOOP(cp5)
	ld [par+tmp2], tmp1
	st tmp1, [pad+tmp2]
	WHILE(cp5, `subcc tmp2, 4, tmp2', geu)


/***********************************************/





ok:
	mov 0, %i0
endofdiv:
	EPILOGUE




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

	ENTRY(_divlu)
	PROLOGUE(0)

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




	EPILOGUE







