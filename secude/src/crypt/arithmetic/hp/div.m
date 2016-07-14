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



/* parameter a,b,c and d */
#define paa %r22
#define pab %r5
#define pac %r20
#define pad %r21
/* parameter quotient and rest will bee
	copied to c and d after calculation */
#define paq %r8
#define par %r9
/* variables
	n length divisor
	k length divident
	m length rest
	q quotient
			*/
#define vn %r10
#define vm %r11
#define vq %r12
#define vk %r13
#define vj %r14
#define vuj %r15
#define vv1 %r16
#define shft %r17
#define tmp1 %r18
#define tmp2 %r4
#define tmp3 %r6
#define tmp4 %r7






/*      _div()

	
	assembler for HP 9000 Series 700

	Thomas Surkau 24.6.96  */


        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_div
        .PROC
        .CALLINFO CALLER,FRAME=1200,ENTRY_SR=3,SAVE_RP
        .ENTRY
        STW     %r2,-20(0,%r30) ;offset 0x104
        LDO     1280(%r30),%r30 ;offset 0x108
        STW     %r19,-32(0,%r30)        ;offset 0x10c

        STW     %r4,-120(0,%r30)        ;offset 0x80
        STW     %r5,-116(0,%r30)        ;offset 0x80
        STW     %r6,-112(0,%r30)        ;offset 0x80
        STW     %r7,-108(0,%r30)        ;offset 0x80
        STW     %r8,-104(0,%r30)        ;offset 0x80
        STW     %r9,-100(0,%r30)        ;offset 0x80
        STW     %r10,-96(0,%r30)        ;offset 0x80
        STW     %r11,-92(0,%r30)        ;offset 0x80
        STW     %r12,-88(0,%r30)        ;offset 0x80
        STW     %r13,-84(0,%r30)        ;offset 0x80
        STW     %r14,-80(0,%r30)        ;offset 0x80
        STW     %r15,-76(0,%r30)        ;offset 0x80
        STW     %r16,-72(0,%r30)        ;offset 0x80
        STW     %r17,-68(0,%r30)        ;offset 0x80
        STW     %r18,-64(0,%r30)        ;offset 0x80
        STW     arg2,-60(0,%r30)        ;offset 0x80
        STW     arg3,-56(0,%r30)        ;offset 0x80
        STW     arg0,-52(0,%r30)        ;offset 0x80



/***********************************************/
	COPY arg0, paa
	COPY arg1, pab
	COPY arg2, pac
	COPY arg3, pad
/* set length */
	LDW	0(0, pab), vn
	LDW	0(0, paa), vk
	SH2ADD vn, %r0, vn
	SH2ADD vk, %r0, vk
	SUB vk, vn, vm

/***********************************************/


/* division by 0 */
	COMB,<>,n %r0,vn,L$I_null
	NOP
	ADDI -1, %r0,ret0
	B,n endofdiv
	NOP
L$I_null 

/***********************************************/


/* divident<divisor (length) */
	COMB,<=,n vn, vk, L$I_trivial
	NOP 
/* quotient is 0 */
/* set quotient */
	STW	%r0, 0(0, pac)

/* copy divident to rest */
	SHD %r0, vk, 2, tmp1
	STW	tmp1, 0(0, pad)
	COMB,=,n %r0, vk, ok
	NOP

	ADD paa, vk, paa
	ADD pad, vk, pad
L$C_cp1 
	LDW	0(0, paa), tmp1
	STW	tmp1, 0(0, pad)
	ADDI -4, paa, paa
	ADDI -4, pad, pad
	ADDIB,>,n -4, vk, L$C_cp1
	NOP
L$B_cp1 
	
	B,n ok
	NOP
L$I_trivial 
L$B_trivial 


/***********************************************/


/* working space for quotient and rest */
	ADDI -496,%r30, paq
	ADDI -872,%r30, par

/* copy divident */
	COPY vk, tmp2

	LDW	0(0, paa), tmp1
	STW	tmp1, 0(0, par)

	ADD paa, tmp2, paa
	ADD par, tmp2, par
L$C_cp2 
	LDW	0(0, paa), tmp1
	STW	tmp1, 0(0, par)
	ADDI -4, paa, paa
	ADDI -4, par, par
	ADDIB,>,n -4, tmp2, L$C_cp2
	NOP
 

/***********************************************/


	COMIB,<>,n 4, vn, L$I_one
	NOP
/* divisor has only one word */
	
	COPY vk, tmp1
/* set parameters for division loop */
/* divisor is every time the same and won't be changed */
	LDW	4(0, pab), arg2

	COPY %r0, arg0

/* loop for division by one word */
	ADD par, tmp1, par
	ADD paq, tmp1, paq
L$C_div1 
/* set the lowword (the high word is the rest of the last call) */
	LDW	0(0, par), arg1

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      __divlu, %r2   
	NOP
	STW	arg3, 0(0, paq)
	ADDI -4, par, par
	ADDI -4, paq, paq
	ADDIB,<>,n -4, tmp1, L$C_div1
	NOP
L$B_div1 
	ADD paq, vk, tmp1
	LDW	0(0, tmp1), tmp1

/* perhaps high word is 0 */
	COMB,<>,n %r0,tmp1,L$I_kuerzen
	NOP
	ADDI -4, vk, vk
L$I_kuerzen 

	SHD %r0, vk, 2, tmp1
	STW	tmp1, 0(0, paq)

        LDW     -60(0,%r30), pac       ;offset 0x4
	STW	tmp1, 0(0, pac)

	ADD paq, vk, paq
	ADD pac, vk, pac
/* copy quotient */
L$C_cp3 
	LDW	0(0, paq), tmp1
	STW	tmp1, 0(0, pac)
	ADDI -4, pac, pac
	ADDI -4, paq, paq
	ADDIB,>,n -4, vk, L$C_cp3
	NOP


/* copy rest */
        LDW     -56(0,%r30), pad       ;offset 0x4

	COMB,<>,n %r0,arg0,L$I_rest0
	NOP
	STW	%r0, 0(0, pad)
	
	B,n L$B_rest0
	NOP 
L$I_rest0 
	ADDI 1, %r0, tmp1
	STW	tmp1, 0(0, pad)
	STW	arg0, 4(0, pad)
L$B_rest0 


	B,n ok
	NOP

L$I_one 
L$B_one 

/***********************************************/
/***********************************************/
/***********************************************/

/* begin of algorithm */
/* Knuth Page 237 Algorithm D */

/* D1 normalise:  shft divident and divisor  */
/* to the left, until the highest bit of the */ 
/* divisor is on the left side of one word */

	ADD pab, vn, tmp1
	LDW	0(0, tmp1), tmp1
	ADDI -1,%r0, shft

/* count the bits to shft */
shftlen
	ADDB,NUV tmp1, tmp1, shftlen
	ADDI 1, shft, shft

	COMB,=,n %r0, shft, noshft1
	NOP
/* shft */
	COPY pab, arg0
	COPY shft, arg1
	ADDI -872, %r30, pab
	ADDI -376, pab, pab
	COPY pab, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP

	COPY par, arg0
	COPY shft, arg1
	COPY par, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP
noshft1
/* set u_0 to 0 (perhaps u_(-1) but doesn't matter*/
	LDW	0(0, par), tmp1
	SH2ADD tmp1, par, tmp1
	ADDI 4, tmp1, tmp1
	STW	%r0, 0(0, tmp1)



/***********************************************/
/* D2 begin of main loop (j:=0 to m) */
/* m+1 to 1 because long number is stored in */
/* reverse order */
	
	ADDI 4, vm, vj
	ADD paq, vj, paq
mloop
/***********************************************/
/* D3 calculate q */

/* vuj : ptr to u_j    ;    vv1 : ptr to v_1  */

	ADD par, vn, vuj
	ADD vuj, vj, vuj

	ADD pab, vn, vv1

/* calculate q := (u_j*2^32 + u_(j+1)) div v_1 */
	LDW	0(0, vuj), arg0
	LDW	0(0, vv1), arg2
	COMB,= arg0, arg2, equal
	ADDI -1, %r0, vq

	LDW	-4(0, vuj), arg1

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      __divlu, %r2   
	NOP
	COPY arg3, vq

equal
test
/* calculate v_1*q*2^32 + v_2*q to tmp1-3 */
/* ( 3 words )*/

/* v_2 * q */
	LDW	-4(0, vv1), arg0
	COPY vq, arg1
	COPY %r0, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP
	COPY ret0, tmp1
	COPY ret1, tmp2

/* v_1 * q */
	LDW	0(0, vv1), arg0
	COPY vq, arg1
	COPY tmp2, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP
	COPY ret0, tmp2
	COPY ret1, tmp3

/* compare tmp1-3 with u_j - u_(j+2) ( 3 words ) */
/* and repeat test with q:= q - 1*/

	ADDI -1, vq, vq

	LDW	0(0, vuj), tmp4
	COMB,>>,n tmp3 , tmp4, test
	NOP
	COMB,<<,n tmp3 , tmp4, norep
	NOP

	LDW	-4(0, vuj), tmp4
	COMB,>>,n tmp2 , tmp4, test
	NOP
	COMB,<<,n tmp2 , tmp4, norep
	NOP

	LDW	-8(0, vuj), tmp4
	COMB,>>,n tmp1 , tmp4, test
	NOP

norep
	ADDI 1, vq, vq

/***********************************************/
/* D4 mult and sub ( u := u-q*v ) */

	COPY vn, tmp1
	ADDI 4, pab, vv1
	SUB vuj, vn, vuj
	LDW	0(0, vuj), tmp2
	COPY %r0 tmp4
subloop
	LDW	4(0, vuj), tmp3
	LDW	0(0, vv1), arg0
	COPY vq, arg1
	COPY %r0, arg2
	
        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _dmult, %r2   
	NOP

	
	SUB,>>= tmp2, ret0, tmp2
	ADDI 1, tmp4, tmp4
	ADDB,UV tmp4, ret1, subnull
	ADDI 1, %r0, tmp4

	SUB,<< tmp3, ret1, tmp3	
	COPY %r0, tmp4
	
subnull
	STW	tmp2, 0(0, vuj)
	COPY tmp3, tmp2

	ADDI 4, vv1, vv1

	ADDIB,<> -4, tmp1, subloop
	ADDI 4, vuj, vuj

	STW	tmp3, 0(0, vuj)

/***********************************************/
/* D5 test, if u positiv */

	COMB,=,n %r0,tmp4,pos
	NOP
/***********************************************/
/* D6 addback, because q was one to big */
/*  ( u := u - v ) */

	ADDI -1, vq, vq
	
	COPY vn, tmp1
	ADDI 4, pab, vv1
	SUB vuj, vn, vuj
	COPY %r0, tmp4
addback
	LDW	0(0, vuj), tmp2
	LDW	0(0, vv1), tmp3

	ADD,UV	tmp2, tmp4, tmp2
	COPY %r0, tmp4
	ADD,NUV	tmp2, tmp3, tmp2
	ADDI 	1,%r0, tmp4

	
	STW	tmp2, 0(0, vuj)

	ADDI 4, vv1, vv1

	ADDIB,<> -4, tmp1, addback
	ADDI 4, vuj, vuj

	LDW	0(0, vuj), tmp2
	ADD tmp2, tmp4, tmp2
	STW	tmp2, 0(0, vuj)



pos	
/* store q in quotient array */

	STW	vq, 0(0, paq)

/***********************************************/
/* D7 end of main loop */

	ADDI -4, paq, paq

	ADDIB,<>,n -4,  vj, mloop
	NOP


/* test length of quotient  */
/* ( high word may be 0 ) */

	ADDI 4, vm, vm
next1
	ADD paq, vm, tmp1
	LDW	0(0, tmp1), tmp1
	COMB,<>,n %r0,tmp1,ex1
	NOP
	ADDIB,<>,n -4, vm, next1
	NOP
ex1
	SHD %r0, vm, 2, vm
	STW	vm, 0(0, paq)


/* test length of rest */
/* ( high word may be 0 ) */

next2
	ADD par, vn, tmp1
	LDW	0(0, tmp1), tmp1
	COMB,<>,n %r0,tmp1,ex2
	NOP
	ADDIB,<>,n -4, vn, next2
	NOP
ex2

	SHD %r0, vn, 2, vn
	STW	vn, 0(0, par)

/***********************************************/
/* D8 shft rest back */

	COMB,=,n %r0,shft,noshft2
	COPY par, arg0
	SUB %r0, shft, arg1
	COPY par, arg2

        .CALL   ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR   
        BL      _shift, %r2   
	NOP


noshft2

/* end of algorithm D */
/***********************************************/
/***********************************************/
/***********************************************/

/* copy quotient */
        LDW     -60(0,%r30), pac       ;offset 0x4
	LDW	0(0, paq), tmp2
	STW	tmp2, 0(0, pac)
	SH2ADD tmp2, %r0, tmp2

	ADD paq, tmp2, paq
	ADD pac, tmp2, pac
L$C_cp4 
	LDW	0(0, paq), tmp1
	STW	tmp1, 0(0, pac)
	ADDI -4, pac, pac
	ADDI -4, paq, paq
	ADDIB,>,n -4, tmp2, L$C_cp4
	NOP



/* copy rest */
        LDW     -56(0,%r30), pad       ;offset 0x4

	LDW	0(0, par), tmp2
	STW	tmp2, 0(0, pad)
	SH2ADD tmp2, %r0, tmp2

	ADD par, tmp2, par
	ADD pad, tmp2, pad
L$C_cp5 
	LDW	0(0, par), tmp1
	STW	tmp1, 0(0, pad)
	ADDI -4, par, par
	ADDI -4, pad, pad
	ADDIB,>,n -4, tmp2, L$C_cp5
	NOP



/***********************************************/





ok
	COPY %r0, ret0
endofdiv

        LDW     -120(0,%r30), %r4       ;offset 0x4
        LDW     -116(0,%r30), %r5       ;offset 0x4
        LDW     -112(0,%r30), %r6       ;offset 0x4
        LDW     -108(0,%r30), %r7       ;offset 0x4
        LDW     -104(0,%r30), %r8       ;offset 0x4
        LDW     -100(0,%r30), %r9       ;offset 0x4
        LDW     -96(0,%r30), %r10       ;offset 0x4
        LDW     -92(0,%r30), %r11       ;offset 0x4
        LDW     -88(0,%r30), %r12       ;offset 0x4
        LDW     -84(0,%r30), %r13       ;offset 0x4
        LDW     -80(0,%r30), %r14       ;offset 0x4
        LDW     -76(0,%r30), %r15       ;offset 0x4
        LDW     -72(0,%r30), %r16       ;offset 0x4
        LDW     -68(0,%r30), %r17       ;offset 0x4
        LDW     -60(0,%r30), %r18       ;offset 0x4
        LDW     -56(0,%r30), %r20       ;offset 0x4
        LDW     -52(0,%r30), %r21       ;offset 0x4
        LDW     -48(0,%r30), %r22       ;offset 0x4



        LDW     -1300(0,%r30),%r2       ;offset 0x194
        BV      %r0(%r2)        ;offset 0x198
        .EXIT
        LDO     -1280(%r30),%r30        ;offset 0x19c
        .PROCEND ;in=23,24,25,26;out=28;



/* 
	divlu()

Input

%i0 
%i1 
%i2 

	%i0<%i2 expected


Output

%i0 
%i3 

				*/
#define CNT %r3		
#define R1 %r4		
#define DH arg0		
#define DL arg1		
#define DW arg2		
#define QW arg3		

__divlu
        .PROC
        .CALLINFO CALLER,FRAME=0,ENTRY_SR=3
        .ENTRY
        LDO     64(%r30),%r30   ;offset 0x0
        STW     %r3,-40(0,%r30)       ;offset 0x4
        STW     %r4,-36(0,%r30)       ;offset 0x8






	ADDI 31, %r0, CNT
	MTSAR CNT
	ADDI 1, %r0, R1
	ADDI -32, %r0, CNT

	COPY %r0, QW

next
	COMB,<,n DH,%r0 subshl
	NOP
	VSHD DH,DL,DH
	VSHD DL,%r0,DL
	COMB,>>=,n DH,DW,sub
	NOP

	ADDB,<> R1,CNT, next
	SH1ADD QW, %r0, QW
	B,n ready
	NOP

subshl
	VSHD DH,DL,DH
	VSHD DL,%r0,DL
sub
	SUB DH, DW, DH
	ADDB,<> R1,CNT, next
	SH1ADD QW, R1, QW
ready


        LDW     -40(0,%r30), %r3       ;offset 0x4
        LDW     -36(0,%r30), %r4       ;offset 0x4
        BV      %r0(%r2)        ;offset 0x1c
        .EXIT
        LDO     -64(%r30),%r30  ;offset 0x20
        .PROCEND ;in=24,25,26;out=28;



        .EXPORT __divlu,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

        .EXPORT _div,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR
        .IMPORT _shift,CODE
        .IMPORT _dmult,CODE
	.END
