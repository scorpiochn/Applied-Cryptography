#NO_APP
.text
	.align 1
.globl _NN_Decode
_NN_Decode:
	link a6,#0
	moveml #0x3e20,sp@-
	movel a6@(8),a2
	movel a6@(12),d5
	movel a6@(16),a1
	subl a0,a0
	movel a6@(20),d1
	subql #1,d1
	jmi L14
L9:
	clrl d4
	clrl d2
	tstl d1
	jlt L6
	clrl d3
L8:
	moveb a1@(d1:l),d3
	movel d3,d0
	lsll d2,d0
	orl d0,d4
	subql #1,d1
	addql #8,d2
	tstl d1
	jlt L6
	moveq #31,d6
	cmpl d2,d6
	jcc L8
L6:
	movel d4,a2@(a0:l:4)
	addqw #1,a0
	tstl d1
	jge L9
	jra L14
L13:
	clrl a2@(a0:l:4)
	addqw #1,a0
L14:
	cmpl a0,d5
	jhi L13
	moveml a6@(-24),#0x47c
	unlk a6
	rts
	.align 1
.globl _NN_Encode
_NN_Encode:
	link a6,#0
	moveml #0x3c20,sp@-
	movel a6@(8),a1
	movel a6@(16),a2
	movel a6@(20),d4
	subl a0,a0
	movel a6@(12),d1
	subql #1,d1
	clrl d5
	cmpl d5,d4
	jls L28
L23:
	movel a2@(a0:l:4),d3
	clrl d2
	tstl d1
	jlt L18
L22:
	movel d3,d0
	lsrl d2,d0
	moveb d0,a1@(d1:l)
	subql #1,d1
	addql #8,d2
	tstl d1
	jlt L18
	moveq #31,d5
	cmpl d2,d5
	jcc L22
L18:
	addqw #1,a0
	cmpl a0,d4
	jhi L23
	jra L28
L27:
	clrb a1@(d1:l)
	subql #1,d1
L28:
	tstl d1
	jge L27
	moveml a6@(-20),#0x43c
	unlk a6
	rts
	.align 1
.globl _NN_Assign
_NN_Assign:
	link a6,#0
	movel d2,sp@-
	movel a6@(8),a1
	movel a6@(12),a0
	movel a6@(16),d1
	clrl d0
	cmpl d0,d1
	jls L31
L33:
	movel a0@(d0:l:4),a1@(d0:l:4)
	addql #1,d0
	cmpl d0,d1
	jhi L33
L31:
	movel a6@(-4),d2
	unlk a6
	rts
	.align 1
.globl _NN_AssignZero
_NN_AssignZero:
	link a6,#0
	movel d2,sp@-
	movel a6@(8),a0
	movel a6@(12),d1
	clrl d0
	cmpl d0,d1
	jls L36
L38:
	clrl a0@(d0:l:4)
	addql #1,d0
	cmpl d0,d1
	jhi L38
L36:
	movel a6@(-4),d2
	unlk a6
	rts
	.align 1
.globl _NN_Assign2Exp
_NN_Assign2Exp:
	link a6,#0
	moveml #0x3020,sp@-
	movel a6@(8),a2
	movel a6@(12),d3
	movel a6@(16),d2
	movel d2,sp@-
	movel a2,sp@-
	jbsr _NN_AssignZero
	asll #5,d2
	cmpl d3,d2
	jls L39
	movel d3,d2
	lsrl #5,d2
	moveq #31,d1
	andl d3,d1
	moveq #1,d0
	lsll d1,d0
	movel d0,a2@(d2:l:4)
L39:
	moveml a6@(-12),#0x40c
	unlk a6
	rts
	.align 1
.globl _NN_Add
_NN_Add:
	link a6,#0
	moveml #0x3030,sp@-
	movel a6@(8),a3
	movel a6@(12),a2
	movel a6@(16),a1
	movel a6@(20),d2
	clrl d0
	clrl d1
	cmpl d1,d2
	jls L43
L49:
	movel d0,a0
	addl a2@(d1:l:4),a0
	cmpl a0,d0
	jls L45
	movel a1@(d1:l:4),a0
	jra L46
L45:
	addl a1@(d1:l:4),a0
	cmpl a1@(d1:l:4),a0
	scs d0
	extbl d0
	negl d0
L46:
	movel a0,a3@(d1:l:4)
	addql #1,d1
	cmpl d1,d2
	jhi L49
L43:
	moveml a6@(-16),#0xc0c
	unlk a6
	rts
	.align 1
.globl _NN_Sub
_NN_Sub:
	link a6,#0
	moveml #0x3830,sp@-
	movel a6@(8),a3
	movel a6@(12),a2
	movel a6@(16),a1
	movel a6@(20),d3
	clrl d2
	clrl d1
	cmpl d1,d3
	jls L52
L58:
	movel a2@(d1:l:4),a0
	subl d2,a0
	moveq #-1,d0
	subl d2,d0
	cmpl a0,d0
	jcc L54
	moveq #-1,d4
	subl a1@(d1:l:4),d4
	movel d4,a0
	jra L55
L54:
	subl a1@(d1:l:4),a0
	moveq #-1,d0
	subl a1@(d1:l:4),d0
	cmpl a0,d0
	scs d0
	moveb d0,d2
	extbl d2
	negl d2
L55:
	movel a0,a3@(d1:l:4)
	addql #1,d1
	cmpl d1,d3
	jhi L58
L52:
	movel d2,d0
	moveml a6@(-20),#0xc1c
	unlk a6
	rts
	.align 1
.globl _NN_Mult
_NN_Mult:
	link a6,#-264
	moveml #0x3e38,sp@-
	movel a6@(12),a4
	movel a6@(16),d6
	movel a6@(20),d5
	movel d5,d0
	addl d0,d0
	movel d0,sp@-
	movel a6,d4
	addl #-264,d4
	movel d4,sp@-
	jbsr _NN_AssignZero
	movel d5,sp@-
	movel a4,sp@-
	lea _NN_Digits,a2
	jbsr a2@
	movel d0,d3
	movel d5,sp@-
	movel d6,sp@-
	jbsr a2@
	movel d0,a2
	clrl d2
	addw #24,sp
	cmpl d2,d3
	jls L61
	movel d4,a3
L63:
	movel a2,sp@-
	movel d6,sp@-
	movel a4@(d2:l:4),sp@-
	lea a3@(d2:l:4),a0
	movel a0,sp@-
	movel a0,sp@-
	jbsr _NN_AddDigitMult
	lea a2@(0,d2:l),a0
	lea a6@(a0:l:4),a0
	addl d0,a0@(-264)
	addw #20,sp
	addql #1,d2
	cmpl d2,d3
	jhi L63
L61:
	movel d5,d0
	addl d0,d0
	movel d0,sp@-
	movel a6,d2
	addl #-264,d2
	movel d2,sp@-
	movel a6@(8),sp@-
	jbsr _NN_Assign
	pea 264:w
	clrl sp@-
	movel d2,sp@-
	jbsr _R_memset
	moveml a6@(-296),#0x1c7c
	unlk a6
	rts
	.align 1
.globl _NN_Mod
_NN_Mod:
	link a6,#-264
	movel d2,sp@-
	movel a6@(24),sp@-
	movel a6@(20),sp@-
	movel a6@(16),sp@-
	movel a6@(12),sp@-
	movel a6@(8),sp@-
	movel a6,d2
	addl #-264,d2
	movel d2,sp@-
	jbsr _NN_Div
	pea 264:w
	clrl sp@-
	movel d2,sp@-
	jbsr _R_memset
	movel a6@(-268),d2
	unlk a6
	rts
	.align 1
.globl _NN_ModMult
_NN_ModMult:
	link a6,#-264
	moveml #0x3c00,sp@-
	movel a6@(8),d5
	movel a6@(20),d4
	movel a6@(24),d2
	movel d2,sp@-
	movel a6@(16),sp@-
	movel a6@(12),sp@-
	movel a6,d3
	addl #-264,d3
	movel d3,sp@-
	jbsr _NN_Mult
	movel d2,sp@-
	movel d4,sp@-
	addl d2,d2
	movel d2,sp@-
	movel d3,sp@-
	movel d5,sp@-
	jbsr _NN_Mod
	addw #36,sp
	pea 264:w
	clrl sp@-
	movel d3,sp@-
	jbsr _R_memset
	moveml a6@(-280),#0x3c
	unlk a6
	rts
	.align 1
.globl _NN_ModExp
_NN_ModExp:
	link a6,#-532
	moveml #0x3f3c,sp@-
	movel a6@(12),d2
	movel a6@(20),a5
	movel a6@(24),d7
	movel a6@(28),d6
	movel d6,sp@-
	movel d2,sp@-
	movel a6,d4
	addl #-396,d4
	movel d4,sp@-
	jbsr _NN_Assign
	movel d6,sp@-
	movel d7,sp@-
	movel d2,sp@-
	movel d4,sp@-
	movel a6,d3
	addl #-264,d3
	movel d3,sp@-
	lea _NN_ModMult,a2
	jbsr a2@
	addw #32,sp
	movel d6,sp@-
	movel d7,sp@-
	movel d2,sp@-
	movel d3,sp@-
	pea a6@(-132)
	jbsr a2@
	movel d6,sp@-
	movel a6,d2
	addl #-528,d2
	movel d2,sp@-
	jbsr _NN_AssignZero
	moveq #1,d5
	movel d5,a6@(-528)
	movel a5,sp@-
	movel a6@(16),sp@-
	jbsr _NN_Digits
	movel d0,a5
	lea a5@(-1),a1
	movel a1,a6@(-532)
	addw #36,sp
	jlt L68
	movel d4,a4
L79:
	movel a6@(16),a1
	movel a6@(-532),d5
	movel a1@(d5:l:4),d3
	moveq #32,d4
	movel a5,d0
	subql #1,d0
	cmpl d5,d0
	jne L70
	movel d3,d0
	moveq #30,d1
	lsrl d1,d0
	tstb d0
	jne L70
L73:
	lsll #2,d3
	subql #2,d4
	movel d3,d0
	moveq #30,d5
	lsrl d5,d0
	tstb d0
	jeq L73
L70:
	subl a2,a2
	clrl d1
	cmpl d1,d4
	jls L69
L78:
	movel d6,sp@-
	movel d7,sp@-
	movel d2,sp@-
	movel d2,sp@-
	movel d2,sp@-
	lea _NN_ModMult,a3
	jbsr a3@
	movel d6,sp@-
	movel d7,sp@-
	movel d2,sp@-
	movel d2,sp@-
	movel d2,sp@-
	jbsr a3@
	movel d3,d5
	moveq #30,d1
	lsrl d1,d5
	movel d5,a0
	addw #40,sp
	tstl a0
	jeq L76
	movel d6,sp@-
	movel d7,sp@-
	movel a0,d0
	asll #5,d0
	addl a0,d0
	movew #-132,a0
	lea a0@(d0:l:4),a0
	pea a0@(a4:l)
	movel d2,sp@-
	movel d2,sp@-
	jbsr a3@
	addw #20,sp
L76:
	addqw #2,a2
	lsll #2,d3
	cmpl a2,d4
	jhi L78
L69:
	subql #1,a6@(-532)
	jpl L79
L68:
	movel d6,sp@-
	movel a6,d2
	addl #-528,d2
	movel d2,sp@-
	movel a6@(8),sp@-
	jbsr _NN_Assign
	pea 396:w
	clrl sp@-
	pea a6@(-396)
	lea _R_memset,a2
	jbsr a2@
	pea 132:w
	clrl sp@-
	movel d2,sp@-
	jbsr a2@
	moveml a6@(-572),#0x3cfc
	unlk a6
	rts
	.align 1
.globl _NN_ModInv
_NN_ModInv:
	link a6,#-1188
	moveml #0x3f3c,sp@-
	movel a6@(12),d2
	movel a6@(20),d5
	movel d5,sp@-
	pea a6@(-528)
	lea _NN_AssignZero,a2
	jbsr a2@
	moveq #1,d1
	movel d1,a6@(-528)
	movel d5,sp@-
	pea a6@(-792)
	jbsr a2@
	movel d5,sp@-
	movel d2,sp@-
	movel a6,d3
	addl #-660,d3
	movel d3,sp@-
	lea _NN_Assign,a2
	jbsr a2@
	movel d5,sp@-
	movel a6@(16),sp@-
	movel a6,d2
	addl #-924,d2
	movel d2,sp@-
	jbsr a2@
	moveq #1,d7
	addw #40,sp
	movel d2,d6
	movel d3,a5
	lea a6@(-396),a4
	lea a6@(-132),a3
L81:
	movel d5,sp@-
	movel d6,sp@-
	jbsr _NN_Zero
	addqw #8,sp
	tstl d0
	jne L82
	movel d5,sp@-
	movel d6,sp@-
	movel d5,sp@-
	movel a5,sp@-
	movel a4,sp@-
	movel a3,sp@-
	jbsr _NN_Div
	movel d5,sp@-
	movel a6,d4
	addl #-792,d4
	movel d4,sp@-
	movel a3,sp@-
	movel a6,d2
	addl #-1188,d2
	movel d2,sp@-
	jbsr _NN_Mult
	addw #40,sp
	movel d5,sp@-
	movel d2,sp@-
	movel a6,d2
	addl #-528,d2
	movel d2,sp@-
	movel a6,d3
	addl #-264,d3
	movel d3,sp@-
	jbsr _NN_Add
	movel d5,sp@-
	movel d4,sp@-
	movel d2,sp@-
	lea _NN_Assign,a2
	jbsr a2@
	movel d5,sp@-
	movel d3,sp@-
	movel d4,sp@-
	jbsr a2@
	addw #40,sp
	movel d5,sp@-
	movel d6,sp@-
	movel a5,sp@-
	jbsr a2@
	movel d5,sp@-
	movel a4,sp@-
	movel d6,sp@-
	jbsr a2@
	negl d7
	addw #24,sp
	jra L81
L82:
	tstl d7
	jge L83
	movel d5,sp@-
	pea a6@(-528)
	movel a6@(16),sp@-
	movel a6@(8),sp@-
	jbsr _NN_Sub
	addw #16,sp
	jra L84
L83:
	movel d5,sp@-
	pea a6@(-528)
	movel a6@(8),sp@-
	jbsr _NN_Assign
	addw #12,sp
L84:
	pea 132:w
	clrl sp@-
	pea a6@(-132)
	lea _R_memset,a2
	jbsr a2@
	pea 132:w
	clrl sp@-
	pea a6@(-264)
	jbsr a2@
	pea 132:w
	clrl sp@-
	pea a6@(-396)
	jbsr a2@
	addw #36,sp
	pea 132:w
	clrl sp@-
	pea a6@(-528)
	jbsr a2@
	pea 132:w
	clrl sp@-
	pea a6@(-660)
	jbsr a2@
	pea 132:w
	clrl sp@-
	pea a6@(-792)
	jbsr a2@
	addw #36,sp
	pea 132:w
	clrl sp@-
	pea a6@(-924)
	jbsr a2@
	pea 264:w
	clrl sp@-
	pea a6@(-1188)
	jbsr a2@
	moveml a6@(-1228),#0x3cfc
	unlk a6
	rts
	.align 1
.globl _NN_Gcd
_NN_Gcd:
	link a6,#-396
	moveml #0x3c20,sp@-
	movel a6@(16),d2
	movel a6@(20),d4
	movel d4,sp@-
	movel a6@(12),sp@-
	movel a6,d3
	addl #-264,d3
	movel d3,sp@-
	lea _NN_Assign,a2
	jbsr a2@
	movel d4,sp@-
	movel d2,sp@-
	movel a6,d2
	addl #-396,d2
	movel d2,sp@-
	jbsr a2@
	addw #24,sp
	movel d3,d5
	movel a6,d3
	addl #-132,d3
L86:
	movel d4,sp@-
	movel d2,sp@-
	jbsr _NN_Zero
	addqw #8,sp
	tstl d0
	jne L87
	movel d4,sp@-
	movel d2,sp@-
	movel d4,sp@-
	movel d5,sp@-
	movel d3,sp@-
	jbsr _NN_Mod
	movel d4,sp@-
	movel d2,sp@-
	movel d5,sp@-
	lea _NN_Assign,a2
	jbsr a2@
	addw #32,sp
	movel d4,sp@-
	movel d3,sp@-
	movel d2,sp@-
	jbsr a2@
	addw #12,sp
	jra L86
L87:
	movel d4,sp@-
	movel a6,d2
	addl #-264,d2
	movel d2,sp@-
	movel a6@(8),sp@-
	jbsr _NN_Assign
	pea 132:w
	clrl sp@-
	pea a6@(-132)
	lea _R_memset,a2
	jbsr a2@
	pea 132:w
	clrl sp@-
	movel d2,sp@-
	jbsr a2@
	addw #36,sp
	pea 132:w
	clrl sp@-
	pea a6@(-396)
	jbsr a2@
	moveml a6@(-416),#0x43c
	unlk a6
	rts
	.align 1
.globl _NN_Cmp
_NN_Cmp:
	link a6,#0
	movel a6@(8),a1
	movel a6@(12),a0
	movel a6@(16),d0
	jra L91
L94:
	movel a1@(d0:l:4),d1
	cmpl a0@(d0:l:4),d1
	jls L92
	moveq #1,d0
	jra L95
L92:
	movel a1@(d0:l:4),d1
	cmpl a0@(d0:l:4),d1
	jcc L91
	moveq #-1,d0
	jra L95
L91:
	subql #1,d0
	jpl L94
	clrl d0
L95:
	unlk a6
	rts
	.align 1
.globl _NN_Zero
_NN_Zero:
	link a6,#0
	movel d2,sp@-
	movel a6@(8),a0
	movel a6@(12),d1
	clrl d0
	cmpl d0,d1
	jls L98
L101:
	tstl a0@(d0:l:4)
	jeq L99
	clrl d0
	jra L102
L99:
	addql #1,d0
	cmpl d0,d1
	jhi L101
L98:
	moveq #1,d0
L102:
	movel a6@(-4),d2
	unlk a6
	rts
	.align 1
.globl _NN_Bits
_NN_Bits:
	link a6,#0
	moveml #0x2020,sp@-
	movel a6@(8),a2
	movel a6@(12),sp@-
	movel a2,sp@-
	jbsr _NN_Digits
	movel d0,d2
	addqw #8,sp
	jeq L104
	movel a2@(-4,d2:l:4),sp@-
	jbsr _NN_DigitBits
	movel d2,d1
	asll #5,d1
	movel d1,a0
	lea a0@(-32,d0:l),a0
	movel a0,d0
	jra L105
L104:
	clrl d0
L105:
	moveml a6@(-8),#0x404
	unlk a6
	rts
	.align 1
.globl _NN_Digits
_NN_Digits:
	link a6,#0
	movel a6@(8),a0
	movel a6@(12),d0
	jra L112
L111:
	tstl a0@(d0:l:4)
	jne L108
L112:
	subql #1,d0
	jpl L111
L108:
	addql #1,d0
	unlk a6
	rts
	.align 1
_NN_LShift:
	link a6,#0
	moveml #0x3e20,sp@-
	movel a6@(8),a2
	movel a6@(12),a1
	movel a6@(16),d4
	movel a6@(20),a0
	moveq #31,d6
	cmpl d4,d6
	jcc L114
	clrl d0
	jra L121
L114:
	moveq #32,d5
	subl d4,d5
	clrl d2
	clrl d1
	cmpl d1,a0
	jls L116
L120:
	movel a1@(d1:l:4),d3
	movel d3,d0
	lsll d4,d0
	orl d2,d0
	movel d0,a2@(d1:l:4)
	clrl d2
	tstl d4
	jeq L118
	movel d3,d2
	lsrl d5,d2
L118:
	addql #1,d1
	cmpl d1,a0
	jhi L120
L116:
	movel d2,d0
L121:
	moveml a6@(-24),#0x47c
	unlk a6
	rts
	.align 1
_NN_RShift:
	link a6,#0
	moveml #0x3e00,sp@-
	movel a6@(8),a1
	movel a6@(12),a0
	movel a6@(16),d4
	moveq #31,d6
	cmpl d4,d6
	jcc L123
	clrl d0
	jra L130
L123:
	moveq #32,d5
	subl d4,d5
	clrl d2
	movel a6@(20),d1
	jra L127
L129:
	movel a0@(d1:l:4),d3
	movel d3,d0
	lsrl d4,d0
	orl d2,d0
	movel d0,a1@(d1:l:4)
	clrl d2
	tstl d4
	jeq L127
	movel d3,d2
	lsll d5,d2
L127:
	subql #1,d1
	jpl L129
	movel d2,d0
L130:
	moveml a6@(-20),#0x7c
	unlk a6
	rts
	.align 1
_NN_Div:
	link a6,#-404
	moveml #0x3f3c,sp@-
	movel a6@(20),d3
	movel a6@(24),a4
	movel a6@(28),d7
	movel d7,sp@-
	movel a4,sp@-
	jbsr _NN_Digits
	movel d0,d4
	addqw #8,sp
	jeq L131
	movel a4@(-4,d4:l:4),sp@-
	jbsr _NN_DigitBits
	moveq #32,d6
	subl d0,d6
	movel d4,sp@-
	movel a6,d2
	addl #-268,d2
	movel d2,sp@-
	lea _NN_AssignZero,a3
	jbsr a3@
	movel d3,sp@-
	movel d6,sp@-
	movel a6@(16),sp@-
	movel d2,sp@-
	lea _NN_LShift,a2
	jbsr a2@
	lea a6@(d3:l:4),a0
	movel d0,a0@(-268)
	movel d4,sp@-
	movel d6,sp@-
	movel a4,sp@-
	movel a6,d5
	addl #-400,d5
	movel d5,sp@-
	jbsr a2@
	lea a6@(d4:l:4),a0
	movel a0@(-404),a5
	addw #44,sp
	movel d3,sp@-
	movel a6@(8),sp@-
	jbsr a3@
	subl d4,d3
	addqw #8,sp
	jmi L134
	movel d2,a4
L141:
	moveq #-1,d1
	cmpl a5,d1
	jne L136
	movel d3,a0
	addl d7,a0
	lea a6@(a0:l:4),a0
	movel a0@(-268),a6@(-404)
	jra L137
L136:
	pea a5@(1)
	movel d3,d0
	addl d4,d0
	pea a4@(-4,d0:l:4)
	pea a6@(-404)
	jbsr _NN_DigitDiv
	addw #12,sp
L137:
	movel d4,sp@-
	movel d5,sp@-
	movel a6@(-404),sp@-
	lea a4@(d3:l:4),a2
	movel a2,sp@-
	movel a2,sp@-
	jbsr _NN_SubDigitMult
	movel d3,a0
	addl d4,a0
	lea a6@(a0:l:4),a0
	subl d0,a0@(-268)
	addw #20,sp
	movel a0,a3
	movel a2,d2
L138:
	tstl a3@(-268)
	jne L140
	movel d4,sp@-
	movel d5,sp@-
	movel d2,sp@-
	jbsr _NN_Cmp
	addw #12,sp
	tstl d0
	jlt L139
L140:
	addql #1,a6@(-404)
	movel d4,sp@-
	movel d5,sp@-
	movel d2,sp@-
	movel d2,sp@-
	jbsr _NN_Sub
	subl d0,a3@(-268)
	addw #16,sp
	jra L138
L139:
	movel a6@(8),a1
	movel a6@(-404),a1@(d3:l:4)
	subql #1,d3
	jpl L141
L134:
	movel d7,sp@-
	movel a6@(12),sp@-
	jbsr _NN_AssignZero
	movel d4,sp@-
	movel d6,sp@-
	movel a6,d2
	addl #-268,d2
	movel d2,sp@-
	movel a6@(12),sp@-
	jbsr _NN_RShift
	pea 268:w
	clrl sp@-
	movel d2,sp@-
	lea _R_memset,a2
	jbsr a2@
	addw #36,sp
	pea 132:w
	clrl sp@-
	pea a6@(-400)
	jbsr a2@
L131:
	moveml a6@(-444),#0x3cfc
	unlk a6
	rts
	.align 1
_NN_AddDigitMult:
	link a6,#-8
	moveml #0x3e38,sp@-
	movel a6@(8),a2
	movel a6@(12),a4
	movel a6@(16),d6
	movel a6@(20),a3
	movel a6@(24),d5
	tstl d6
	jne L143
	clrl d0
	jra L151
L143:
	clrl d3
	clrl d2
	cmpl d2,d5
	jls L145
	movel a6,d4
	subql #8,d4
L150:
	movel	a3@(d2:l:4),d0
	movel d6,d4
	mulul d0,d0:d4
	movel d4,a6@(-8)
	movel d0,a6@(-4)

	movel d3,d0
	addl a4@(d2:l:4),d0
	movel d0,a2@(d2:l:4)
	cmpl d0,d3
	jls L147
	moveq #1,d3
	jra L148
L147:
	clrl d3
L148:
	movel a2@(d2:l:4),d0
	addl a6@(-8),d0
	movel d0,a2@(d2:l:4)
	cmpl a6@(-8),d0
	jcc L149
	addql #1,d3
L149:
	addl a6@(-4),d3
	addql #1,d2
	cmpl d2,d5
	jhi L150
L145:
	movel d3,d0
L151:
	moveml a6@(-40),#0x1c7c
	unlk a6
	rts
	.align 1
_NN_SubDigitMult:
	link a6,#-8
	moveml #0x3f38,sp@-
	movel a6@(8),a2
	movel a6@(12),a4
	movel a6@(16),d6
	movel a6@(20),a3
	movel a6@(24),d4
	tstl d6
	jne L153
	clrl d0
	jra L161
L153:
	clrl d2
	clrl d3
	cmpl d3,d4
	jls L155
	movel a6,d5
	subql #8,d5
L160:
	movel a3@(d3:l:4),d1
	movel	d6,d5
	mulul d1,d1:d5
	movel d5,a6@(-8)
	movel d1,a6@(-4)

	movel a4@(d3:l:4),d1
	subl d2,d1
	movel d1,a2@(d3:l:4)
	moveq #-1,d0
	subl d2,d0
	cmpl d1,d0
	scs d0
	moveb d0,d2
	extbl d2
	negl d2
	movel a2@(d3:l:4),d1
	subl a6@(-8),d1
	movel d1,a2@(d3:l:4)
	moveq #-1,d0
	subl a6@(-8),d0
	cmpl d1,d0
	jcc L159
	addql #1,d2
L159:
	addl a6@(-4),d2
	addql #1,d3
	cmpl d3,d4
	jhi L160
L155:
	movel d2,d0
L161:
	moveml a6@(-44),#0x1cfc
	unlk a6
	rts
	.align 1
_NN_DigitBits:
	link a6,#0
	movel d2,sp@-
	movel a6@(8),d1
	clrl d0
L167:
	tstl d1
	jeq L164
	addql #1,d0
	lsrl #1,d1
	moveq #31,d2
	cmpl d0,d2
	jcc L167
L164:
	movel a6@(-4),d2
	unlk a6
	rts
	.align 1
.globl _NN_2ModExp
_NN_2ModExp:
	link a6,#-396
	moveml #0x3f3c,sp@-
	movel a6@(12),a4
	movel a6@(20),d7
	movel a6@(24),a3
	movel a3,sp@-
	pea a6@(-132)
	jbsr _NN_AssignZero
	addqw #8,sp
	moveq #1,d1
	movel d1,a6@(-132)
	movel a6@(16),sp@-
	movel a4,sp@-
	jbsr _NN_Digits
	addqw #8,sp
	movel d0,a6@(16)
	movel d0,d5
	subql #1,d5
	jmi L2Mod81
	lea a6@(-132),a2
	movel a6,d6
	addl #-396,d6
	lea a4@(d5:l:4),a5
L2Mod92:
	movel a5@,d2
	moveq #32,d4
	movel a6@(16),d0
	subql #1,d0
	cmpl d5,d0
	jne L2Mod83
	jra L2Mod93
L2Mod86:
	lsll #2,d2
	subql #2,d4
L2Mod93:
	movel d2,d0
	moveq #30,d1
	lsrl d1,d0
	tstb d0
	jeq L2Mod86
L2Mod83:
	clrl d3
	cmpl d3,d4
	jls L2Mod82
	lea a6@(a3:l:4),a4
L2Mod91:
	movel a3,sp@-
	movel d7,sp@-
	movel a2,sp@-
	movel a2,sp@-
	movel a2,sp@-
	jbsr _NN_ModMult
	addqw #8,sp
	addqw #8,sp
	movel a3,sp@
	movel d7,sp@-
	movel a2,sp@-
	movel a2,sp@-
	movel a2,sp@-
	jbsr _NN_ModMult
	addw #20,sp
	movel d2,d0
	moveq #30,d1
	lsrl d1,d0
	jeq L2Mod89
	movel a3,sp@-
	movel d0,sp@-
	movel a2,sp@-
	movel d6,sp@-
	jbsr _NN_LShift
	addqw #8,sp
	addqw #8,sp
	movel d0,a4@(-396)
	movel a3,sp@-
	movel d7,sp@-
	pea a3@(1)
	movel d6,sp@-
	movel a2,sp@-
	jbsr _NN_Mod
	addw #20,sp
L2Mod89:
	addql #2,d3
	lsll #2,d2
	cmpl d3,d4
	jhi L2Mod91
L2Mod82:
	subqw #4,a5
	dbra d5,L2Mod92
	clrw d5
	subql #1,d5
	jcc L2Mod92
L2Mod81:
	movel a3,sp@-
	lea a6@(-132),a2
	movel a2,sp@-
	movel a6@(8),sp@-
	jbsr _NN_Assign
	addqw #8,sp
	movel #132,sp@
	clrl sp@-
	movel a2,sp@-
	lea _R_memset,a2
	jbsr a2@
	addqw #8,sp
	movel #8,sp@
	clrl sp@-
	pea a6@(-396)
	jbsr a2@
	moveml a6@(-436),#0x3cfc
	unlk a6
	rts
