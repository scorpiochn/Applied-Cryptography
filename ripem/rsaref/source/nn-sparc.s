gcc2_compiled.:
.text
	.align 4
	.proc	017
_XXXAdd:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	sub %o1,%o3,%o1
	addcc %o3,-1,%o3
	bneg L1230
	cmp %o4,0
	ld [%o0],%g2
L1231:
	add %o4,%g2,%o4
	cmp %o4,%g2
	bgeu,a L1222
	ld [%o2],%g2
	ld [%o2],%g2
	st %g2,[%o0]
	add %o2,4,%o2
	add %o0,4,%o0
	b L1220
	mov 1,%o4
L1222:
	add %o2,4,%o2
	add %o4,%g2,%o4
	st %o4,[%o0]
	add %o0,4,%o0
	cmp %o4,%g2
	addx %g0,0,%o4
L1220:
	addcc %o3,-1,%o3
	bpos,a L1231
	ld [%o0],%g2
	cmp %o4,0
L1230:
	bne L1226
	cmp %o1,0
	b L1225
	mov 0,%o0
L1226:
	bne L1232
	addcc %o1,-1,%o1
	b L1225
	mov 1,%o0
L1228:
	addcc %o1,-1,%o1
L1232:
	bneg,a L1225
	srl %o1,31,%o0
	ld [%o0],%g2
	add %g2,1,%g2
	st %g2,[%o0]
	cmp %g2,0
	be L1228
	add %o0,4,%o0
	srl %o1,31,%o0
L1225:
	retl
	sub %sp,-0,%sp
	.align 4
.proc	14
_XXXMultiplyDigit:
!#PROLOGUE# 0
!#PROLOGUE# 1
	tst	%o4
	bne	LMDnonzero
	cmp	%o4,1
	retl
	mov	0,%o0
LMDnonzero:
	bne	LMD0
	mov	0,%o5
	b	_XXXAdd		! shortcut to XXXAdd
	mov	0,%o4		! carry in = 0
LMD0:
	save	%sp,-96,%sp
	tst	%i3
	be	L77007
	sub	%i1,%i3,%l1
LMD1:
	ld	[%i0],%l7
	mov	%i4,%y
	ld	[%i2],%l0
	addcc	%g0,%g0,%o0	! initialize
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%l0,%o0;	mulscc	%o0,%l0,%o0;
	mulscc	%o0,%g0,%o0	! align
	tst	%l0
	blt,a	LMDsignfix
	add	%o0,%i4,%o0
LMDsignfix:
	mov	%o0,%o1
	mov	%y,%o0
	addcc	%o0,%i5,%i1
	inc	4,%i2
	addx	%o1,%g0,%i5
	addcc	%l7,%i1,%l7
	addx	%g0,%i5,%i5
	st	%l7,[%i0]
	deccc	%i3
	bgt	LMD1
	inc	4,%i0
L77007:
	tst	%i5
	be	LMDexit
	deccc	%l1
LY3:					! [internal]
	blt	LMDexit
	inc	4,%i0
	ld	[%i0-4],%i1
	addcc	%i1,%i5,%i1
	addxcc	%g0,%g0,%i5
	st	%i1,[%i0-4]
	bne,a	LY3
	deccc	%l1
LMDexit:
	ret
	restore	%g0,%i5,%o0
	.align 4
	.global _NN_Decode
	.proc	020
_NN_Decode:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	addcc %o3,-1,%o3
	bneg L27
	mov 0,%g1
	mov 0,%o5
L33:
	mov 0,%o4
	cmp %o3,0
	bl L30
	mov 0,%g3
	ldub [%o2+%o3],%g2
L38:
	addcc %o3,-1,%o3
	sll %g2,%g3,%g2
	or %o4,%g2,%o4
	bneg L30
	add %g3,8,%g3
	cmp %g3,31
	bleu,a L38
	ldub [%o2+%o3],%g2
L30:
	st %o4,[%o5+%o0]
	add %o5,4,%o5
	cmp %o3,0
	bge L33
	add %g1,1,%g1
L27:
	cmp %g1,%o1
	bgeu L35
	sll %g1,2,%g2
	sll %o1,2,%o1
	st %g0,[%g2+%o0]
L39:
	add %g2,4,%g2
	cmp %g2,%o1
	blu,a L39
	st %g0,[%g2+%o0]
L35:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Encode
	.proc	020
_NN_Encode:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o3,0
	be L42
	add %o1,-1,%o1
	mov 0,%o4
	sll %o3,2,%o3
	ld [%o4+%o2],%o5
L54:
	cmp %o1,0
	bl L43
	mov 0,%g3
	srl %o5,%g3,%g2
L53:
	stb %g2,[%o0+%o1]
	addcc %o1,-1,%o1
	bneg L43
	add %g3,8,%g3
	cmp %g3,31
	bleu L53
	srl %o5,%g3,%g2
L43:
	add %o4,4,%o4
	cmp %o4,%o3
	blu,a L54
	ld [%o4+%o2],%o5
L42:
	cmp %o1,0
	bl L50
	nop
	stb %g0,[%o0+%o1]
L55:
	addcc %o1,-1,%o1
	bpos,a L55
	stb %g0,[%o0+%o1]
L50:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Assign
	.proc	020
_NN_Assign:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o2,0
	be L58
	mov 0,%g3
	sll %o2,2,%o2
	ld [%g3+%o1],%g2
L61:
	st %g2,[%g3+%o0]
	add %g3,4,%g3
	cmp %g3,%o2
	blu,a L61
	ld [%g3+%o1],%g2
L58:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_AssignZero
	.proc	020
_NN_AssignZero:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o1,0
	be L64
	mov 0,%g2
	sll %o1,2,%o1
	st %g0,[%g2+%o0]
L67:
	add %g2,4,%g2
	cmp %g2,%o1
	blu,a L67
	st %g0,[%g2+%o0]
L64:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Assign2Exp
	.proc	020
_NN_Assign2Exp:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%o0
	call _NN_AssignZero,0
	mov %i2,%o1
	sll %i2,5,%i2
	cmp %i1,%i2
	bgeu L68
	srl %i1,5,%o0
	sll %o0,2,%o0
	and %i1,31,%o2
	mov 1,%o1
	sll %o1,%o2,%o1
	st %o1,[%i0+%o0]
L68:
	ret
	restore
	.align 4
	.global _NN_Add
	.proc	017
_NN_Add:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov %o0,%o5
	mov 0,%o0
	cmp %o0,%o3
	bgeu L72
	mov 0,%o4
	sll %o3,2,%o3
	ld [%o4+%o1],%g2
L79:
	add %o0,%g2,%g3
	cmp %g3,%o0
	bgeu,a L74
	ld [%o4+%o2],%g2
	b L75
	ld [%o4+%o2],%g3
L74:
	add %g3,%g2,%g3
	cmp %g3,%g2
	addx %g0,0,%o0
L75:
	st %g3,[%o4+%o5]
	add %o4,4,%o4
	cmp %o4,%o3
	blu,a L79
	ld [%o4+%o1],%g2
L72:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Sub
	.proc	017
_NN_Sub:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov %o0,%g1
	mov 0,%o0
	cmp %o0,%o3
	bgeu L82
	mov -1,%o5
	mov 0,%o4
	sll %o3,2,%o3
	ld [%o4+%o1],%g2
L89:
	sub %g2,%o0,%g3
	sub %o5,%o0,%g2
	cmp %g3,%g2
	bleu,a L84
	ld [%o4+%o2],%g2
	ld [%o4+%o2],%g2
	b L85
	sub %o5,%g2,%g3
L84:
	sub %g3,%g2,%g3
	sub %o5,%g2,%g2
	cmp %g2,%g3
	addx %g0,0,%o0
L85:
	st %g3,[%o4+%g1]
	add %o4,4,%o4
	cmp %o4,%o3
	blu,a L89
	ld [%o4+%o1],%g2
L82:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Mult
	.proc	020
_NN_Mult:
	!#PROLOGUE# 0
	save %sp,-376,%sp
	!#PROLOGUE# 1
	add %fp,-280,%l2
	mov %l2,%o0
	sll %i3,1,%l0
	call _NN_AssignZero,0
	mov %l0,%o1
	mov %i1,%o0
	call _NN_Digits,0
	mov %i3,%o1
	mov %o0,%l4
	mov %i2,%o0
	call _NN_Digits,0
	mov %i3,%o1
	cmp %i1,%i2
	bne L92
	mov %o0,%l3
	cmp %l4,5
	bgu L91
	cmp %l3,0
L92:
	mov 0,%l1
	cmp %l1,%l4
	bgeu L97
	add %fp,-16,%l5
	mov %l2,%l0
	mov 0,%l2
L96:
	mov %l0,%o0
	mov %l0,%o1
	ld [%l2+%i1],%o2
	mov %i2,%o3
	mov %l3,%o4
	add %l0,4,%l0
	call _NN_AddDigitMult,0
	add %l2,4,%l2
	add %l1,%l3,%o1
	add %l1,1,%l1
	sll %o1,2,%o1
	add %o1,%l5,%o1
	ld [%o1-264],%o2
	cmp %l1,%l4
	add %o0,%o2,%o0
	blu L96
	st %o0,[%o1-264]
	b L103
	mov %i0,%o0
L91:
	be L97
	mov 0,%i2
L102:
	mov %l2,%o0
	mov %l0,%o1
	mov %i1,%o2
	ld [%i1],%l1
	mov 1,%o3
	call _XXXMultiplyDigit,0
	mov %l1,%o4
	cmp %i2,0
	be L101
	mov %l2,%o0
	mov %l0,%o1
	mov %i1,%o2
	mov 1,%o3
	call _XXXAdd,0
	mov 0,%o4
L101:
	add %l3,-1,%l3
	add %i1,4,%i1
	add %l2,8,%l2
	add %l0,-2,%l0
	add %l2,-4,%o0
	add %l0,1,%o1
	mov %i1,%o2
	mov %l3,%o3
	add %l1,%l1,%o4
	call _XXXMultiplyDigit,0
	add %o4,%i2,%o4
	cmp %l3,0
	bne L102
	srl %l1,31,%i2
L97:
	mov %i0,%o0
L103:
	add %fp,-280,%l0
	mov %l0,%o1
	call _NN_Assign,0
	sll %i3,1,%o2
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 264,%o2
	ret
	restore
	.align 4
	.proc	017
_XXXAddCarry:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o2,0
	bne L105
	cmp %o1,0
	b L109
	mov 0,%o0
L105:
	bne L110
	addcc %o1,-1,%o1
	b L109
	mov 1,%o0
L107:
	addcc %o1,-1,%o1
L110:
	bneg,a L109
	srl %o1,31,%o0
	ld [%o0],%g2
	add %g2,1,%g2
	st %g2,[%o0]
	cmp %g2,0
	be L107
	add %o0,4,%o0
	srl %o1,31,%o0
L109:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Mod
	.proc	020
_NN_Mod:
	!#PROLOGUE# 0
	save %sp,-376,%sp
	!#PROLOGUE# 1
	add %fp,-280,%l0
	mov %l0,%o0
	mov %i0,%o1
	mov %i1,%o2
	mov %i2,%o3
	mov %i3,%o4
	call _NN_Div,0
	mov %i4,%o5
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 264,%o2
	ret
	restore
	.align 4
	.global _NN_ModMult
	.proc	020
_NN_ModMult:
	!#PROLOGUE# 0
	save %sp,-376,%sp
	!#PROLOGUE# 1
	add %fp,-280,%l0
	mov %l0,%o0
	mov %i1,%o1
	mov %i2,%o2
	call _NN_Mult,0
	mov %i4,%o3
	mov %i0,%o0
	mov %l0,%o1
	sll %i4,1,%o2
	mov %i3,%o3
	call _NN_Mod,0
	mov %i4,%o4
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 264,%o2
	ret
	restore
	.align 4
	.global _NN_ModExp
	.proc	020
_NN_ModExp:
	!#PROLOGUE# 0
	save %sp,-648,%sp
	!#PROLOGUE# 1
	add %fp,-416,%l1
	mov %l1,%o0
	mov %i1,%o1
	call _NN_Assign,0
	mov %i5,%o2
	add %fp,-284,%l0
	mov %l0,%o0
	mov %l1,%o1
	mov %i1,%o2
	mov %i4,%o3
	call _NN_ModMult,0
	mov %i5,%o4
	add %fp,-152,%o0
	mov %l0,%o1
	mov %i1,%o2
	mov %i4,%o3
	call _NN_ModMult,0
	mov %i5,%o4
	add %fp,-552,%l0
	mov %l0,%o0
	call _NN_AssignZero,0
	mov %i5,%o1
	mov 1,%o0
	st %o0,[%fp-552]
	mov %i2,%o0
	call _NN_Digits,0
	mov %i3,%o1
	mov %o0,%i3
	addcc %i3,-1,%l3
	bneg L128
	mov %i0,%o0
	mov %l1,%l5
	sll %l3,2,%l4
L126:
	ld [%l4+%i2],%i1
	add %i3,-1,%o0
	cmp %l3,%o0
	bne L117
	mov 32,%l2
	b L129
	srl %i1,30,%o0
L120:
	add %l2,-2,%l2
	srl %i1,30,%o0
L129:
	cmp %o0,0
	be,a L120
	sll %i1,2,%i1
L117:
	mov 0,%l1
	cmp %l1,%l2
	bgeu,a L130
	addcc %l3,-1,%l3
L125:
	mov %l0,%o0
	mov %l0,%o1
	mov %l0,%o2
	mov %i4,%o3
	call _NN_ModMult,0
	mov %i5,%o4
	mov %l0,%o0
	mov %l0,%o1
	mov %l0,%o2
	mov %i4,%o3
	call _NN_ModMult,0
	mov %i5,%o4
	srl %i1,30,%o0
	cmp %o0,0
	be L123
	sll %o0,5,%o2
	add %o2,%o0,%o2
	sll %o2,2,%o2
	mov %l0,%o0
	mov %l0,%o1
	add %o2,-132,%o2
	add %l5,%o2,%o2
	mov %i4,%o3
	call _NN_ModMult,0
	mov %i5,%o4
L123:
	add %l1,2,%l1
	cmp %l1,%l2
	blu L125
	sll %i1,2,%i1
	addcc %l3,-1,%l3
L130:
	bpos L126
	add %l4,-4,%l4
	mov %i0,%o0
L128:
	add %fp,-552,%l0
	mov %l0,%o1
	call _NN_Assign,0
	mov %i5,%o2
	add %fp,-416,%o0
	mov 0,%o1
	call _R_memset,0
	mov 396,%o2
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	ret
	restore
	.align 4
	.global _NN_2ModExp
	.proc	020
_NN_2ModExp:
	!#PROLOGUE# 0
	save %sp,-512,%sp
	!#PROLOGUE# 1
	add %fp,-152,%l0
	mov %l0,%o0
	call _NN_AssignZero,0
	mov %i4,%o1
	mov 1,%o0
	st %o0,[%fp-152]
	mov %i1,%o0
	call _NN_Digits,0
	mov %i2,%o1
	mov %o0,%i2
	addcc %i2,-1,%l4
	bneg L133
	sll %i4,2,%o1
	mov %l0,%l1
	add %fp,-416,%l6
	add %fp,-16,%o0
	add %o1,%o0,%l7
	sll %l4,2,%l5
L144:
	ld [%l5+%i1],%l0
	add %i2,-1,%o0
	cmp %l4,%o0
	bne L135
	mov 32,%l3
	b L146
	srl %l0,30,%o0
L138:
	add %l3,-2,%l3
	srl %l0,30,%o0
L146:
	cmp %o0,0
	be,a L138
	sll %l0,2,%l0
L135:
	mov 0,%l2
	cmp %l2,%l3
	bgeu,a L147
	addcc %l4,-1,%l4
L143:
	mov %l1,%o0
	mov %l1,%o1
	mov %l1,%o2
	mov %i3,%o3
	call _NN_ModMult,0
	mov %i4,%o4
	mov %l1,%o0
	mov %l1,%o1
	mov %l1,%o2
	mov %i3,%o3
	call _NN_ModMult,0
	mov %i4,%o4
	srl %l0,30,%o2
	cmp %o2,0
	be L141
	mov %l6,%o0
	mov %l1,%o1
	call _NN_LShift,0
	mov %i4,%o3
	st %o0,[%l7-400]
	mov %l1,%o0
	mov %l6,%o1
	add %i4,1,%o2
	mov %i3,%o3
	call _NN_Mod,0
	mov %i4,%o4
L141:
	add %l2,2,%l2
	cmp %l2,%l3
	blu L143
	sll %l0,2,%l0
	addcc %l4,-1,%l4
L147:
	bpos L144
	add %l5,-4,%l5
L133:
	mov %i0,%o0
	add %fp,-152,%l0
	mov %l0,%o1
	call _NN_Assign,0
	mov %i4,%o2
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-416,%o0
	mov 0,%o1
	call _R_memset,0
	mov 8,%o2
	ret
	restore
	.align 4
	.global _NN_ModInv
	.proc	020
_NN_ModInv:
	!#PROLOGUE# 0
	save %sp,-1328,%sp
	!#PROLOGUE# 1
	add %fp,-560,%l4
	mov %l4,%o0
	call _NN_AssignZero,0
	mov %i3,%o1
	mov 1,%l2
	st %l2,[%fp-560]
	add %fp,-832,%l3
	mov %l3,%o0
	call _NN_AssignZero,0
	mov %i3,%o1
	add %fp,-696,%l1
	mov %l1,%o0
	mov %i1,%o1
	call _NN_Assign,0
	mov %i3,%o2
	add %fp,-968,%l0
	mov %l0,%o0
	mov %i2,%o1
	call _NN_Assign,0
	mov %i3,%o2
	add %fp,-152,%l7
	add %fp,-424,%l6
	mov %l1,%l5
	add %fp,-1232,%l1
	add %fp,-288,%i1
L149:
	mov %l0,%o0
	call _NN_Zero,0
	mov %i3,%o1
	cmp %o0,0
	bne L150
	cmp %l2,0
	mov %l7,%o0
	mov %l6,%o1
	mov %l5,%o2
	mov %i3,%o3
	mov %l0,%o4
	call _NN_Div,0
	mov %i3,%o5
	mov %l1,%o0
	mov %l7,%o1
	mov %l3,%o2
	call _NN_Mult,0
	mov %i3,%o3
	mov %i1,%o0
	mov %l4,%o1
	mov %l1,%o2
	call _NN_Add,0
	mov %i3,%o3
	mov %l4,%o0
	mov %l3,%o1
	call _NN_Assign,0
	mov %i3,%o2
	mov %l3,%o0
	mov %i1,%o1
	call _NN_Assign,0
	mov %i3,%o2
	mov %l5,%o0
	mov %l0,%o1
	call _NN_Assign,0
	mov %i3,%o2
	mov %l0,%o0
	mov %l6,%o1
	call _NN_Assign,0
	mov %i3,%o2
	b L149
	sub %g0,%l2,%l2
L150:
	bge L151
	mov %i0,%o0
	mov %i2,%o1
	add %fp,-560,%o2
	call _NN_Sub,0
	mov %i3,%o3
	b L153
	add %fp,-152,%o0
L151:
	add %fp,-560,%o1
	call _NN_Assign,0
	mov %i3,%o2
	add %fp,-152,%o0
L153:
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-288,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-424,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-560,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-696,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-832,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-968,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	add %fp,-1232,%o0
	mov 0,%o1
	call _R_memset,0
	mov 264,%o2
	ret
	restore
	.align 4
	.global _NN_Gcd
	.proc	020
_NN_Gcd:
	!#PROLOGUE# 0
	save %sp,-520,%sp
	!#PROLOGUE# 1
	add %fp,-288,%l1
	mov %l1,%o0
	mov %i1,%o1
	call _NN_Assign,0
	mov %i3,%o2
	add %fp,-424,%l0
	mov %l0,%o0
	mov %i2,%o1
	call _NN_Assign,0
	mov %i3,%o2
	mov %l0,%i1
	add %fp,-152,%l0
	mov %i1,%o0
L157:
	call _NN_Zero,0
	mov %i3,%o1
	cmp %o0,0
	bne L156
	mov %l0,%o0
	mov %l1,%o1
	mov %i3,%o2
	mov %i1,%o3
	call _NN_Mod,0
	mov %i3,%o4
	mov %l1,%o0
	mov %i1,%o1
	call _NN_Assign,0
	mov %i3,%o2
	mov %i1,%o0
	mov %l0,%o1
	call _NN_Assign,0
	mov %i3,%o2
	b L157
	mov %i1,%o0
L156:
	mov %i0,%o0
	add %fp,-288,%l0
	mov %l0,%o1
	call _NN_Assign,0
	mov %i3,%o2
	add %fp,-152,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	mov %i1,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
	ret
	restore
	.align 4
	.global _NN_Cmp
	.proc	04
_NN_Cmp:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	addcc %o2,-1,%o2
	bneg,a L165
	mov 0,%o0
	sll %o2,2,%o2
	ld [%o2+%o0],%g3
L166:
	ld [%o2+%o1],%g2
	cmp %g3,%g2
	bleu L162
	nop
	b L165
	mov 1,%o0
L162:
	bgeu L161
	addcc %o2,-4,%o2
	b L165
	mov -1,%o0
L161:
	bpos,a L166
	ld [%o2+%o0],%g3
	mov 0,%o0
L165:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Zero
	.proc	04
_NN_Zero:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o1,0
	be,a L173
	mov 1,%o0
	mov 0,%g3
	sll %o1,2,%o1
	ld [%g3+%o0],%g2
L174:
	cmp %g2,0
	be L170
	add %g3,4,%g3
	b L173
	mov 0,%o0
L170:
	cmp %g3,%o1
	blu,a L174
	ld [%g3+%o0],%g2
	mov 1,%o0
L173:
	retl
	sub %sp,-0,%sp
	.align 4
	.global _NN_Bits
	.proc	016
_NN_Bits:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%l0
	mov %l0,%o0
	call _NN_Digits,0
	mov %i1,%o1
	orcc %o0,%g0,%i0
	be L176
	sll %i0,2,%o0
	add %o0,%l0,%o0
	call _NN_DigitBits,0
	ld [%o0-4],%o0
	add %i0,-1,%i0
	sll %i0,5,%i0
	b L177
	add %i0,%o0,%i0
L176:
	mov 0,%i0
L177:
	ret
	restore
	.align 4
	.global _NN_Digits
	.proc	016
_NN_Digits:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov %o0,%o2
	addcc %o1,-1,%o0
	bneg L180
	sll %o0,2,%g3
L183:
	ld [%g3+%o2],%g2
	cmp %g2,0
	bne L180
	nop
	addcc %o0,-1,%o0
	bpos L183
	add %g3,-4,%g3
L180:
	retl
	add %o0,1,%o0
	.align 4
	.proc	017
_NN_LShift:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o2,31
	bleu L185
	mov %o0,%g1
	b L192
	mov 0,%o0
L185:
	mov 32,%g2
	mov 0,%o0
	cmp %o0,%o3
	bgeu L192
	sub %g2,%o2,%o5
	mov 0,%g3
	sll %o3,2,%o3
	ld [%g3+%o1],%o4
L193:
	cmp %o2,0
	sll %o4,%o2,%g2
	or %g2,%o0,%g2
	st %g2,[%g3+%g1]
	be L189
	mov 0,%o0
	srl %o4,%o5,%o0
L189:
	add %g3,4,%g3
	cmp %g3,%o3
	blu,a L193
	ld [%g3+%o1],%o4
L192:
	retl
	sub %sp,-0,%sp
	.align 4
	.proc	017
_NN_RShift:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	cmp %o2,31
	bleu L195
	mov %o0,%o5
	b L202
	mov 0,%o0
L195:
	mov 32,%g2
	sub %g2,%o2,%o4
	addcc %o3,-1,%g2
	bneg L202
	mov 0,%o0
	sll %g2,2,%g3
	ld [%g3+%o1],%o3
L203:
	cmp %o2,0
	srl %o3,%o2,%g2
	or %g2,%o0,%g2
	st %g2,[%g3+%o5]
	be L199
	mov 0,%o0
	sll %o3,%o4,%o0
L199:
	addcc %g3,-4,%g3
	bpos,a L203
	ld [%g3+%o1],%o3
L202:
	retl
	sub %sp,-0,%sp
	.align 4
	.proc	020
_NN_Div:
	!#PROLOGUE# 0
	save %sp,-536,%sp
	!#PROLOGUE# 1
	st %i0,[%fp-436]
	mov %i4,%o0
	call _NN_Digits,0
	mov %i5,%o1
	orcc %o0,%g0,%l1
	be L204
	sll %l1,2,%l0
	add %l0,%i4,%o0
	call _NN_DigitBits,0
	ld [%o0-4],%o0
	mov 32,%o1
	sub %o1,%o0,%i0
	add %fp,-288,%l4
	mov %l4,%o0
	call _NN_AssignZero,0
	mov %l1,%o1
	mov %l4,%o0
	mov %i2,%o1
	mov %i0,%o2
	call _NN_LShift,0
	mov %i3,%o3
	sll %i3,2,%o1
	add %fp,-16,%l2
	add %o1,%l2,%o1
	st %o0,[%o1-272]
	add %fp,-424,%o0
	mov %i4,%o1
	mov %i0,%o2
	call _NN_LShift,0
	mov %l1,%o3
	ld [%fp-436],%o0
	add %l2,%l0,%l0
	ld [%l0-412],%l7
	call _NN_AssignZero,0
	mov %i3,%o1
	subcc %i3,%l1,%i4
	bneg L207
	add %i4,%l1,%l0
	mov %l2,%l6
	sll %i4,2,%l3
	mov %l4,%l5
	add %l3,%l4,%l2
L214:
	cmp %l7,-1
	bne L209
	add %fp,-428,%o0
	add %i4,%i5,%o0
	sll %o0,2,%o0
	add %o0,%l6,%o0
	ld [%o0-272],%o0
	b L210
	st %o0,[%fp-428]
L209:
	sll %l0,2,%o1
	add %o1,-4,%o1
	add %l5,%o1,%o1
	call _NN_DigitDiv,0
	add %l7,1,%o2
L210:
	mov %l2,%o0
	mov %l2,%o1
	ld [%fp-428],%o2
	add %fp,-424,%o3
	mov %l1,%o4
	mov %l3,%l4
	call _NN_SubDigitMult,0
	mov %l2,%i3
	sll %l0,2,%o3
	add %o3,%l6,%o3
	ld [%o3-272],%o2
	sll %l0,2,%o1
	add %o1,%l6,%i2
	sub %o2,%o0,%o2
	st %o2,[%o3-272]
L211:
	ld [%i2-272],%o0
	cmp %o0,0
	bne L213
	add %l5,%l4,%o0
	add %fp,-424,%o1
	call _NN_Cmp,0
	mov %l1,%o2
	cmp %o0,0
	bl,a L212
	add %l2,-4,%l2
L213:
	mov %i3,%o0
	mov %i3,%o1
	add %fp,-424,%o2
	ld [%fp-428],%o4
	mov %l1,%o3
	add %o4,1,%o4
	call _NN_Sub,0
	st %o4,[%fp-428]
	ld [%i2-272],%o1
	sub %o1,%o0,%o1
	b L211
	st %o1,[%i2-272]
L212:
	add %l0,-1,%l0
	ld [%fp-428],%o0
	ld [%fp-436],%o5
	addcc %i4,-1,%i4
	st %o0,[%l3+%o5]
	bpos L214
	add %l3,-4,%l3
L207:
	mov %i1,%o0
	call _NN_AssignZero,0
	mov %i5,%o1
	mov %i1,%o0
	add %fp,-288,%l0
	mov %l0,%o1
	mov %i0,%o2
	call _NN_RShift,0
	mov %l1,%o3
	mov %l0,%o0
	mov 0,%o1
	call _R_memset,0
	mov 268,%o2
	add %fp,-424,%o0
	mov 0,%o1
	call _R_memset,0
	mov 132,%o2
L204:
	ret
	restore
	.align 4
	.proc	017
_NN_AddDigitMult:
	!#PROLOGUE# 0
	save %sp,-120,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	bne L216
	mov %i0,%o0
	b L224
	mov 0,%i0
L216:
	mov 0,%i0
	cmp %i0,%i4
	bgeu L224
	mov %o0,%l0
	mov 0,%l1
	sll %i4,2,%o0
	add %o0,%l0,%i4
L223:
	add %fp,-24,%o0
	ld [%l1+%i3],%o2
	call _NN_DigitMult,0
	mov %i2,%o1
	ld [%l1+%i1],%o0
	add %i0,%o0,%o0
	st %o0,[%l0]
	ld [%fp-24],%o1
	cmp %o0,%i0
	add %o0,%o1,%o0
	st %o0,[%l0]
	ld [%fp-24],%o1
	addx %g0,0,%i0
	cmp %o0,%o1
	blu,a L222
	add %i0,1,%i0
L222:
	add %l0,4,%l0
	add %l1,4,%l1
	ld [%fp-20],%o0
	cmp %l0,%i4
	blu L223
	add %i0,%o0,%i0
L224:
	ret
	restore
	.align 4
	.proc	017
_NN_SubDigitMult:
	!#PROLOGUE# 0
	save %sp,-120,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	bne L226
	mov %i0,%o0
	b L234
	mov 0,%i0
L226:
	mov 0,%i0
	cmp %i0,%i4
	bgeu L234
	mov -1,%l2
	mov %o0,%l0
	mov 0,%l1
	sll %i4,2,%o0
	add %o0,%l0,%i4
L233:
	add %fp,-24,%o0
	ld [%l1+%i3],%o2
	call _NN_DigitMult,0
	mov %i2,%o1
	ld [%l1+%i1],%o1
	sub %l2,%i0,%o0
	sub %o1,%i0,%o1
	st %o1,[%l0]
	ld [%fp-24],%o2
	cmp %o0,%o1
	sub %o1,%o2,%o1
	st %o1,[%l0]
	ld [%fp-24],%o0
	addx %g0,0,%i0
	sub %l2,%o0,%o0
	cmp %o1,%o0
	bgu,a L232
	add %i0,1,%i0
L232:
	add %l0,4,%l0
	add %l1,4,%l1
	ld [%fp-20],%o0
	cmp %l0,%i4
	blu L233
	add %i0,%o0,%i0
L234:
	ret
	restore
	.align 4
	.proc	016
_NN_DigitBits:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov %o0,%g2
	mov 0,%o0
L240:
	cmp %g2,0
	be L237
	nop
	add %o0,1,%o0
	cmp %o0,31
	bleu L240
	srl %g2,1,%g2
L237:
	retl
	sub %sp,-0,%sp
