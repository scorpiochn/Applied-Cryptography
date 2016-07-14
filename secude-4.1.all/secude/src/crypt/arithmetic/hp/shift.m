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
#define parm_c arg2
#define save_c r3
#define len_a r4
#define right r5
#define len_c r6
#define lw r7
#define rw r8
#define left r9
#define tmp1 r7
#define tmp2 r8
#define sar r11




/*      _shift()

	hp-assembler

	Thomas Surkau 24.6.93
				*/



        .SPACE  $TEXT$,SORT=8
        .SUBSPA $CODE$,QUAD=0,ALIGN=4,ACCESS=44,CODE_ONLY,SORT=24
_shift
        .PROC
        .CALLINFO CALLER,FRAME=392,ENTRY_SR=3
        .ENTRY
        LDO     448(%r30),%r30  ;offset 0x90
        STW     %r3,-64(0,%r30)        ;offset 0xa4
        STW     %r4,-60(0,%r30)        ;offset 0xa4
        STW     %r5,-56(0,%r30)        ;offset 0xa4
        STW     %r6,-52(0,%r30)        ;offset 0xa4
        STW     %r7,-48(0,%r30)        ;offset 0xa4
        STW     %r8,-44(0,%r30)        ;offset 0xa4
        STW     %r9,-40(0,%r30)        ;offset 0xa4
        STW     %r11,-36(0,%r30)        ;offset 0xa4


	LDW	0(0, parm_a),len_a
	COPY parm_c,save_c



/* not much to do if length equal 0 */
	COMB,<>,n  len_a, %r0, L$I_zero
	NOP 
	STW	len_a, 0(0, parm_c)
	MOVB,TR,n %r0, %r0, L$B_end
	NOP
L$I_zero 





/* copy a to stack, if a and c have the same position in memory  */
	COMB,<>,n  parm_a,parm_c, L$I_samemem
	NOP 
	ADDI -440, %r30, tmp1
	STW	len_a, 0(0, tmp1)
L$C_copy 
	ADDI 4,tmp1,tmp1
	ADDI 4,parm_a,parm_a
	LDW	0(0, parm_a),tmp2
	STW	tmp2, 0(0, tmp1)
	ADDIB,<>,n -1, len_a, L$C_copy
	NOP
L$B_copy 
	ADDI -440, %r30, parm_a
	LDW	0(0, parm_a),len_a
L$I_samemem 



/* different procedures for left and right shft
   and for special event b and 31==0 (word shft) */

	COMB,<,n  parm_b, %r0, L$I_sign
	NOP 

	ADDI 31, %r0, sar
	AND sar, parm_b, sar
	COMB,=,n  %r0,sar L$I_mod32l
	NOP 



/* shft bits left */

	SUBI 32,sar,sar
	MTSAR sar

	SHD %r0,parm_b,5,parm_b
	ADD len_a,parm_b ,len_c
	STW	len_c, 0(0, parm_c)

	COMB,=,n %r0, parm_b, L$B_fillzero2 
	NOP
L$C_fillzero2 
	ADDI 4,parm_c,parm_c
	STW	%r0, 0(0, parm_c)
	ADDIB,<>,n -1, parm_b, L$C_fillzero2
	NOP
L$B_fillzero2 

	COPY %r0, rw
L$C_shl 
	ADDI 4,parm_a,parm_a
	ADDI 4,parm_c,parm_c
	LDW	0(0, parm_a),lw
	VSHD lw, rw, rw
	STW	rw, 0(0, parm_c)
	COPY lw,rw
	ADDIB,<>,n -1, len_a, L$C_shl
	NOP
L$B_shl 

/* inc length if the highest bit is shfted into the next word */
	VSHD %r0, rw,rw
	COMB,=,n %r0, rw,   L$I_more
	NOP 
	ADDI 4,parm_c,parm_c
	STW	rw, 0(0, parm_c)
	ADDI 1, len_c, len_c
	STW	len_c, 0(0, save_c)
L$I_more 


	
	MOVB,TR,n %r0,%r0, L$B_end
	NOP 






/* shift right */
L$I_sign 

	SUB %r0,parm_b,parm_b
	ADDI 31, %r0, sar
	AND sar, parm_b, sar
	MTSAR sar
	COMB,=,n  %r0,sar L$I_mod32r
	NOP 

/* shft bits right */


	SHD %r0, parm_b,5,parm_b

/* exit if abs(b) is to big */

	SUB,<= len_a,parm_b ,len_c
	MOVB,TR,n  %r0,%r0 L$I_toshort
	NOP 
	STW	%r0, 0(0, parm_c)
	MOVB,TR,n  %r0,%r0 L$B_end
	NOP
L$I_toshort 


	SH2ADD parm_b,parm_a,parm_a
	ADDI 4,parm_a,parm_a

	LDW	0(0, parm_a),rw
	ADDIB,=,n -1, len_c,L$B_shr
	NOP

L$C_shr 
	ADDI 4,parm_a,parm_a
	ADDI 4,parm_c,parm_c
	LDW	0(0, parm_a),lw
	VSHD lw,rw,rw
	STW	rw, 0(0, parm_c)
	COPY lw,rw
	ADDIB,<>,n -1, len_c, L$C_shr
	NOP
L$B_shr 


	SUB len_a,parm_b ,len_c
	VSHD,<> %r0, rw,rw
	MOVB,TR,n  %r0,%r0 L$B_less
	NOP

/* inc length if the highest word is not equal 0 */
	ADDI 4,parm_c,parm_c
	STW	rw, 0(0, parm_c)
	STW	len_c, 0(0, save_c)

	MOVB,TR,n %r0,%r0, L$B_end
	NOP 
L$B_less 
	ADDI -1 ,len_c,len_c
	STW	len_c, 0(0, save_c)

	MOVB,TR,n %r0,%r0, L$B_end
	NOP 






/* shift right some words */
L$I_mod32r
	SHD	%r0, parm_b, 5, parm_b
	SUB,>	len_a, parm_b, len_c
	COPY %r0, len_c
	COMB,=,n %r0,len_c, L$B_end
	STW	len_c, 0(0, parm_c)
	SH2ADD parm_b, parm_a, parm_a
L$C_copyr
	ADDI 4,parm_c,parm_c
	ADDI 4,parm_a,parm_a
	LDW	0(0, parm_a),tmp2
	STW	tmp2, 0(0, parm_c)
	ADDIB,<>,n -1, len_c, L$C_copyr
	NOP
	MOVB,TR,n %r0,%r0, L$B_end
	NOP








/* shift left some words */
L$I_mod32l
	SHD,<>	%r0, parm_b, 5, parm_b
	MOVB,TR,n %r0,%r0, L$I_mod320
	NOP
	ADD	len_a, parm_b, len_c
	STW	len_c, 0(0, parm_c)
L$C_filll
	ADDI 4,parm_c,parm_c
	STW	%r0, 0(0, parm_c)
	ADDIB,<>,n -1, parm_b, L$C_filll
	NOP
L$C_copyl
	ADDI 4,parm_c,parm_c
	ADDI 4,parm_a,parm_a
	LDW	0(0, parm_a),tmp2
	STW	tmp2, 0(0, parm_c)
	ADDIB,<>,n -1, len_a, L$C_copyl
	NOP

	MOVB,TR,n %r0,%r0, L$B_end
	NOP






/* no shift only copy */
L$I_mod320
	STW	len_a, 0(0, parm_c)
L$C_copy0 
	ADDI 4,parm_c,parm_c
	ADDI 4,parm_a,parm_a
	LDW	0(0, parm_a),tmp2
	STW	tmp2, 0(0, parm_c)
	ADDIB,<>,n -1, len_a, L$C_copy0
	NOP


L$B_end

        LDW     -64(0,%r30), %r3       ;offset 0x4
        LDW     -60(0,%r30), %r4       ;offset 0x4
        LDW     -56(0,%r30), %r5       ;offset 0x4
        LDW     -52(0,%r30), %r6       ;offset 0x4
        LDW     -48(0,%r30), %r7       ;offset 0x4
        LDW     -44(0,%r30), %r8       ;offset 0x4
        LDW     -40(0,%r30), %r9       ;offset 0x4
        LDW     -36(0,%r30), %r11       ;offset 0x4

        BV      %r0(%r2)        ;offset 0xb0
        .EXIT
        LDO     -448(%r30),%r30 ;offset 0xb4
        .PROCEND ;in=24,25,26;out=28;

        .EXPORT _shift,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR,ARGW2=GR,RTNVAL=GR

	.END
