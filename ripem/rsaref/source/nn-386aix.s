	.file   "nn.c"
gcc2_compiled.:
.text
	.align 2
.globl NN_Decode
NN_Decode:
	pushl %ebp
	movl %esp,%ebp
	subl $8,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl $0,-8(%ebp)
	movl 20(%ebp),%edx
	decl %edx
	js L3
	movl 8(%ebp),%edi
	movl %edi,-4(%ebp)
	.align 2,0x90
L9:
	xorl %ebx,%ebx
	xorl %ecx,%ecx
	testl %edx,%edx
	jl L6
	.align 2,0x90
L8:
	movl 16(%ebp),%esi
	movzbl (%edx,%esi),%eax
	sall %cl,%eax
	orl %eax,%ebx
	decl %edx
	addl $8,%ecx
	testl %edx,%edx
	jl L6
	cmpl $31,%ecx
	jbe L8
L6:
	movl -4(%ebp),%edi
	movl %ebx,(%edi)
	addl $4,-4(%ebp)
	incl -8(%ebp)
	testl %edx,%edx
	jge L9
L3:
	movl 12(%ebp),%esi
	cmpl %esi,-8(%ebp)
	jae L11
	movl -8(%ebp),%edi
	movl 8(%ebp),%esi
	leal (%esi,%edi,4),%eax
	movl 12(%ebp),%edi
	leal (%esi,%edi,4),%edx
	.align 2,0x90
L13:
	movl $0,(%eax)
	addl $4,%eax
	cmpl %edx,%eax
	jb L13
L11:
	leal -20(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Encode
NN_Encode:
	pushl %ebp
	movl %esp,%ebp
	subl $4,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%edi
	movl 20(%ebp),%eax
	movl 12(%ebp),%edx
	decl %edx
	testl %eax,%eax
	je L27
	movl 16(%ebp),%ebx
	leal (%ebx,%eax,4),%eax
	movl %eax,-4(%ebp)
	.align 2,0x90
L22:
	movl (%ebx),%esi
	xorl %ecx,%ecx
	testl %edx,%edx
	jl L17
	.align 2,0x90
L21:
	movl %esi,%eax
	shrl %cl,%eax
	movb %al,(%edx,%edi)
	decl %edx
	addl $8,%ecx
	testl %edx,%edx
	jl L17
	cmpl $31,%ecx
	jbe L21
L17:
	addl $4,%ebx
	cmpl %ebx,-4(%ebp)
	ja L22
	jmp L27
	.align 2,0x90
	.align 2,0x90
L26:
	movb $0,(%edx,%edi)
	decl %edx
L27:
	testl %edx,%edx
	jge L26
	leal -16(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Assign
NN_Assign:
	pushl %ebp
	movl %esp,%ebp
	pushl %ebx
	movl 16(%ebp),%ecx
	testl %ecx,%ecx
	je L30
	movl 8(%ebp),%eax
	movl 12(%ebp),%edx
	leal (%eax,%ecx,4),%ecx
	.align 2,0x90
L32:
	movl (%edx),%ebx
	movl %ebx,(%eax)
	addl $4,%eax
	addl $4,%edx
	cmpl %ecx,%eax
	jb L32
L30:
	movl -4(%ebp),%ebx
	leave
	ret
	.align 2
.globl NN_AssignZero
NN_AssignZero:
	pushl %ebp
	movl %esp,%ebp
	movl 12(%ebp),%edx
	testl %edx,%edx
	je L35
	movl 8(%ebp),%eax
	leal (%eax,%edx,4),%edx
	.align 2,0x90
L37:
	movl $0,(%eax)
	addl $4,%eax
	cmpl %edx,%eax
	jb L37
L35:
	leave
	ret
	.align 2,0x90
	.align 2
.globl NN_Assign2Exp
NN_Assign2Exp:
	pushl %ebp
	movl %esp,%ebp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%edi
	movl 12(%ebp),%esi
	movl 16(%ebp),%ebx
	pushl %ebx
	pushl %edi
	call NN_AssignZero
	sall $5,%ebx
	cmpl %ebx,%esi
	jae L38
	movl %esi,%eax
	shrl $5,%eax
	movl %esi,%ecx
	andl $31,%ecx
	movl $1,%edx
	sall %cl,%edx
	movl %edx,(%edi,%eax,4)
L38:
	leal -12(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Add
NN_Add:
	pushl %ebp
	movl %esp,%ebp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%edx
	xorl %eax,%eax
	cmpl %edx,%eax
	jae L42
	movl 8(%ebp),%ebx
	movl 16(%ebp),%ecx
	movl 12(%ebp),%esi
	leal (%ebx,%edx,4),%edi
	.align 2,0x90
L48:
	movl %eax,%edx
	addl (%esi),%edx
	cmpl %eax,%edx
	jae L44
	movl (%ecx),%edx
	jmp L45
	.align 2,0x90
L44:
	addl (%ecx),%edx
	cmpl %edx,(%ecx)
	seta %al
	andl $255,%eax
L45:
	movl %edx,(%ebx)
	addl $4,%ebx
	addl $4,%ecx
	addl $4,%esi
	cmpl %edi,%ebx
	jb L48
L42:
	leal -12(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Sub
NN_Sub:
	pushl %ebp
	movl %esp,%ebp
	subl $4,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%eax
	xorl %esi,%esi
	cmpl %eax,%esi
	jae L51
	movl 8(%ebp),%ebx
	movl 16(%ebp),%ecx
	movl 12(%ebp),%edi
	leal (%ebx,%eax,4),%eax
	movl %eax,-4(%ebp)
	.align 2,0x90
L57:
	movl (%edi),%edx
	subl %esi,%edx
	movl $-1,%eax
	subl %esi,%eax
	cmpl %eax,%edx
	jbe L53
	movl $-1,%edx
	subl (%ecx),%edx
	jmp L54
	.align 2,0x90
L53:
	subl (%ecx),%edx
	movl $-1,%eax
	subl (%ecx),%eax
	cmpl %eax,%edx
	seta %al
	movzbl %al,%esi
L54:
	movl %edx,(%ebx)
	addl $4,%ebx
	addl $4,%ecx
	addl $4,%edi
	cmpl %ebx,-4(%ebp)
	ja L57
L51:
	movl %esi,%eax
	leal -16(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Mult
NN_Mult:
	pushl %ebp
	movl %esp,%ebp
	subl $272,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%ecx
	leal 0(,%ecx,2),%eax
	pushl %eax
	leal -264(%ebp),%ebx
	pushl %ebx
	call NN_AssignZero
	addl $8,%esp
	pushl 20(%ebp)
	pushl 12(%ebp)
	call NN_Digits
	addl $8,%esp
	movl %eax,-268(%ebp)
	pushl 20(%ebp)
	pushl 16(%ebp)
	call NN_Digits
	addl $8,%esp
	movl %eax,-272(%ebp)
	xorl %esi,%esi
	cmpl %esi,-268(%ebp)
	jbe L60
	xorl %edi,%edi
	.align 2,0x90
L62:
	pushl -272(%ebp)
	pushl 16(%ebp)
	movl 12(%ebp),%ecx
	pushl (%ecx,%edi)
	pushl %ebx
	pushl %ebx
	call NN_AddDigitMult
	addl $20,%esp
	movl %esi,%edx
	addl -272(%ebp),%edx
	addl %eax,-264(%ebp,%edx,4)
	addl $4,%ebx
	addl $4,%edi
	incl %esi
	cmpl %esi,-268(%ebp)
	ja L62
L60:
	movl 20(%ebp),%ecx
	leal 0(,%ecx,2),%eax
	pushl %eax
	leal -264(%ebp),%ebx
	pushl %ebx
	pushl 8(%ebp)
	call NN_Assign
	addl $12,%esp
	pushl $264
	pushl $0
	pushl %ebx
	call R_memset
	leal -284(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Mod
NN_Mod:
	pushl %ebp
	movl %esp,%ebp
	subl $264,%esp
	pushl %ebx
	pushl 24(%ebp)
	pushl 20(%ebp)
	pushl 16(%ebp)
	pushl 12(%ebp)
	pushl 8(%ebp)
	leal -264(%ebp),%ebx
	pushl %ebx
	call NN_Div
	addl $24,%esp
	pushl $264
	pushl $0
	pushl %ebx
	call R_memset
	movl -268(%ebp),%ebx
	leave
	ret
	.align 2
.globl NN_ModMult
NN_ModMult:
	pushl %ebp
	movl %esp,%ebp
	subl $264,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%edi
	movl 24(%ebp),%ebx
	pushl %ebx
	pushl 16(%ebp)
	pushl 12(%ebp)
	leal -264(%ebp),%esi
	pushl %esi
	call NN_Mult
	addl $16,%esp
	pushl %ebx
	pushl %edi
	addl %ebx,%ebx
	pushl %ebx
	pushl %esi
	pushl 8(%ebp)
	call NN_Mod
	addl $20,%esp
	pushl $264
	pushl $0
	pushl %esi
	call R_memset
	leal -276(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_ModExp
NN_ModExp:
	pushl %ebp
	movl %esp,%ebp
	subl $552,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 12(%ebp),%esi
	pushl 28(%ebp)
	pushl %esi
	leal -396(%ebp),%edx
	movl %edx,-552(%ebp)
	pushl %edx
	call NN_Assign
	addl $12,%esp
	pushl 28(%ebp)
	pushl 24(%ebp)
	pushl %esi
	pushl -552(%ebp)
	leal -264(%ebp),%ebx
	pushl %ebx
	call NN_ModMult
	addl $20,%esp
	pushl 28(%ebp)
	pushl 24(%ebp)
	pushl %esi
	pushl %ebx
	leal -132(%ebp),%eax
	pushl %eax
	call NN_ModMult
	addl $20,%esp
	pushl 28(%ebp)
	leal -528(%ebp),%ebx
	pushl %ebx
	call NN_AssignZero
	addl $8,%esp
	movl $1,-528(%ebp)
	pushl 20(%ebp)
	pushl 16(%ebp)
	call NN_Digits
	addl $8,%esp
	movl %eax,20(%ebp)
	movl %eax,%edi
	decl %edi
	movl %edi,-532(%ebp)
	js L67
	movl -552(%ebp),%ecx
	movl %ecx,-540(%ebp)
	movl 16(%ebp),%edx
	leal (%edx,%edi,4),%ecx
	movl %ecx,-544(%ebp)
	.align 2,0x90
L78:
	movl -544(%ebp),%edx
	movl (%edx),%esi
	movl $32,-536(%ebp)
	movl 20(%ebp),%eax
	decl %eax
	cmpl %eax,-532(%ebp)
	jne L69
	jmp L79
	.align 2,0x90
	.align 2,0x90
L72:
	sall $2,%esi
	addl $-2,-536(%ebp)
L79:
	movl %esi,%eax
	shrl $30,%eax
	testb %al,%al
	je L72
L69:
	movl $0,-552(%ebp)
	jmp L80
	.align 2,0x90
	.align 2,0x90
L77:
	pushl 28(%ebp)
	pushl 24(%ebp)
	pushl %ebx
	pushl %ebx
	pushl %ebx
	call NN_ModMult
	addl $20,%esp
	pushl 28(%ebp)
	pushl 24(%ebp)
	pushl %ebx
	pushl %ebx
	pushl %ebx
	call NN_ModMult
	addl $20,%esp
	movl %esi,%ecx
	shrl $30,%ecx
	movl %ecx,-548(%ebp)
	je L75
	pushl 28(%ebp)
	pushl 24(%ebp)
	movl %ecx,%eax
	sall $5,%eax
	addl %ecx,%eax
	movl -540(%ebp),%edx
	leal -132(%edx,%eax,4),%eax
	pushl %eax
	pushl %ebx
	pushl %ebx
	call NN_ModMult
	addl $20,%esp
L75:
	addl $2,-552(%ebp)
	sall $2,%esi
L80:
	movl -536(%ebp),%edi
	cmpl %edi,-552(%ebp)
	jb L77
	addl $-4,-544(%ebp)
	decl -532(%ebp)
	jns L78
L67:
	pushl 28(%ebp)
	leal -528(%ebp),%ebx
	pushl %ebx
	pushl 8(%ebp)
	call NN_Assign
	addl $12,%esp
	pushl $396
	pushl $0
	leal -396(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	pushl %ebx
	call R_memset
	leal -564(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_ModInv
NN_ModInv:
	pushl %ebp
	movl %esp,%ebp
	subl $1212,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 12(%ebp),%ebx
	movl 20(%ebp),%edi
	pushl %edi
	leal -528(%ebp),%eax
	pushl %eax
	call NN_AssignZero
	addl $8,%esp
	movl $1,-528(%ebp)
	pushl %edi
	leal -792(%ebp),%edx
	movl %edx,-1196(%ebp)
	pushl %edx
	call NN_AssignZero
	addl $8,%esp
	pushl %edi
	pushl %ebx
	leal -660(%ebp),%esi
	pushl %esi
	call NN_Assign
	addl $12,%esp
	pushl %edi
	pushl 16(%ebp)
	leal -924(%ebp),%ebx
	pushl %ebx
	call NN_Assign
	addl $12,%esp
	movl $1,-1192(%ebp)
	movl %ebx,-1200(%ebp)
	movl %esi,-1204(%ebp)
	leal -396(%ebp),%edx
	movl %edx,-1208(%ebp)
	movl -1196(%ebp),%edx
	movl %edx,-1212(%ebp)
	.align 2,0x90
L82:
	pushl %edi
	pushl -1200(%ebp)
	call NN_Zero
	addl $8,%esp
	testl %eax,%eax
	jne L83
	pushl %edi
	pushl -1200(%ebp)
	pushl %edi
	pushl -1204(%ebp)
	pushl -1208(%ebp)
	leal -132(%ebp),%ebx
	pushl %ebx
	call NN_Div
	addl $24,%esp
	pushl %edi
	pushl -1212(%ebp)
	pushl %ebx
	leal -1188(%ebp),%ebx
	pushl %ebx
	call NN_Mult
	addl $16,%esp
	pushl %edi
	pushl %ebx
	leal -528(%ebp),%ebx
	pushl %ebx
	leal -264(%ebp),%esi
	pushl %esi
	call NN_Add
	addl $16,%esp
	pushl %edi
	pushl -1212(%ebp)
	pushl %ebx
	call NN_Assign
	addl $12,%esp
	pushl %edi
	pushl %esi
	pushl -1212(%ebp)
	call NN_Assign
	addl $12,%esp
	pushl %edi
	pushl -1200(%ebp)
	pushl -1204(%ebp)
	call NN_Assign
	addl $12,%esp
	pushl %edi
	pushl -1208(%ebp)
	pushl -1200(%ebp)
	call NN_Assign
	addl $12,%esp
	negl -1192(%ebp)
	jmp L82
	.align 2,0x90
L83:
	cmpl $0,-1192(%ebp)
	jge L84
	pushl %edi
	leal -528(%ebp),%eax
	pushl %eax
	pushl 16(%ebp)
	pushl 8(%ebp)
	call NN_Sub
	addl $16,%esp
	jmp L85
	.align 2,0x90
L84:
	pushl %edi
	leal -528(%ebp),%eax
	pushl %eax
	pushl 8(%ebp)
	call NN_Assign
	addl $12,%esp
L85:
	pushl $132
	pushl $0
	leal -132(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -264(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -396(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -528(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -660(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -792(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -924(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $264
	pushl $0
	leal -1188(%ebp),%eax
	pushl %eax
	call R_memset
	leal -1224(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Gcd
NN_Gcd:
	pushl %ebp
	movl %esp,%ebp
	subl $396,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 16(%ebp),%ebx
	pushl 20(%ebp)
	pushl 12(%ebp)
	leal -264(%ebp),%esi
	pushl %esi
	call NN_Assign
	addl $12,%esp
	pushl 20(%ebp)
	pushl %ebx
	leal -396(%ebp),%ebx
	pushl %ebx
	call NN_Assign
	addl $12,%esp
	movl %ebx,%edi
	leal -132(%ebp),%ebx
	.align 2,0x90
L87:
	pushl 20(%ebp)
	pushl %edi
	call NN_Zero
	addl $8,%esp
	testl %eax,%eax
	jne L88
	pushl 20(%ebp)
	pushl %edi
	pushl 20(%ebp)
	pushl %esi
	pushl %ebx
	call NN_Mod
	addl $20,%esp
	pushl 20(%ebp)
	pushl %edi
	pushl %esi
	call NN_Assign
	addl $12,%esp
	pushl 20(%ebp)
	pushl %ebx
	pushl %edi
	call NN_Assign
	addl $12,%esp
	jmp L87
	.align 2,0x90
L88:
	pushl 20(%ebp)
	leal -264(%ebp),%ebx
	pushl %ebx
	pushl 8(%ebp)
	call NN_Assign
	addl $12,%esp
	pushl $132
	pushl $0
	leal -132(%ebp),%eax
	pushl %eax
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	pushl %ebx
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	pushl %edi
	call R_memset
	leal -408(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl NN_Cmp
NN_Cmp:
	pushl %ebp
	movl %esp,%ebp
	pushl %ebx
	movl 16(%ebp),%ecx
	decl %ecx
	js L91
	leal 0(,%ecx,4),%eax
	movl %eax,%edx
	addl 8(%ebp),%edx
	addl 12(%ebp),%eax
	.align 2,0x90
L95:
	movl (%eax),%ebx
	cmpl %ebx,(%edx)
	jbe L93
	movl $1,%eax
	jmp L96
	.align 2,0x90
L93:
	movl (%eax),%ebx
	cmpl %ebx,(%edx)
	jae L92
	movl $-1,%eax
	jmp L96
	.align 2,0x90
L92:
	addl $-4,%edx
	addl $-4,%eax
	decl %ecx
	jns L95
L91:
	xorl %eax,%eax
L96:
	movl -4(%ebp),%ebx
	leave
	ret
	.align 2
.globl NN_Zero
NN_Zero:
	pushl %ebp
	movl %esp,%ebp
	movl 12(%ebp),%edx
	testl %edx,%edx
	je L99
	movl 8(%ebp),%eax
	leal (%eax,%edx,4),%edx
	.align 2,0x90
L102:
	cmpl $0,(%eax)
	je L100
	xorl %eax,%eax
	leave
	ret
	.align 2,0x90
L100:
	addl $4,%eax
	cmpl %edx,%eax
	jb L102
L99:
	movl $1,%eax
	leave
	ret
	.align 2,0x90
	.align 2
.globl NN_Bits
NN_Bits:
	pushl %ebp
	movl %esp,%ebp
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%esi
	pushl 12(%ebp)
	pushl %esi
	call NN_Digits
	addl $8,%esp
	movl %eax,%ebx
	testl %ebx,%ebx
	je L105
	pushl -4(%esi,%ebx,4)
	call NN_DigitBits
	movl %eax,%edx
	movl %ebx,%eax
	sall $5,%eax
	leal -32(%edx,%eax),%eax
	jmp L106
	.align 2,0x90
L105:
	xorl %eax,%eax
L106:
	leal -8(%ebp),%esp
	popl %ebx
	popl %esi
	leave
	ret
	.align 2
.globl NN_Digits
NN_Digits:
	pushl %ebp
	movl %esp,%ebp
	movl 8(%ebp),%edx
	movl 12(%ebp),%eax
	decl %eax
	js L109
	leal (%edx,%eax,4),%edx
	.align 2,0x90
L112:
	cmpl $0,(%edx)
	jne L109
	addl $-4,%edx
	decl %eax
	jns L112
L109:
	incl %eax
	leave
	ret
	.align 2,0x90
	.align 2
NN_LShift:
	pushl %ebp
	movl %esp,%ebp
	subl $12,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 16(%ebp),%edi
	movl 20(%ebp),%eax
	cmpl $31,%edi
	jbe L114
	xorl %eax,%eax
	jmp L121
	.align 2,0x90
L114:
	movl $32,%ecx
	subl %edi,%ecx
	movl %ecx,-4(%ebp)
	xorl %ebx,%ebx
	cmpl %eax,%ebx
	jae L116
	movl 8(%ebp),%edx
	movl 12(%ebp),%esi
	leal (%edx,%eax,4),%eax
	movl %eax,-8(%ebp)
	.align 2,0x90
L120:
	movl (%esi),%ecx
	movl %ecx,-12(%ebp)
	movl -12(%ebp),%eax
	movl %edi,%ecx
	sall %cl,%eax
	orl %ebx,%eax
	movl %eax,(%edx)
	xorl %ebx,%ebx
	testl %edi,%edi
	je L118
	movl -12(%ebp),%ebx
	movl -4(%ebp),%ecx
	shrl %cl,%ebx
L118:
	addl $4,%edx
	addl $4,%esi
	cmpl %edx,-8(%ebp)
	ja L120
L116:
	movl %ebx,%eax
L121:
	leal -24(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
NN_RShift:
	pushl %ebp
	movl %esp,%ebp
	subl $8,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	cmpl $31,16(%ebp)
	jbe L123
	xorl %eax,%eax
	jmp L130
	.align 2,0x90
L123:
	movl $32,%ecx
	subl 16(%ebp),%ecx
	movl %ecx,-4(%ebp)
	xorl %ebx,%ebx
	movl 20(%ebp),%ecx
	decl %ecx
	movl %ecx,-8(%ebp)
	js L125
	leal 0(,%ecx,4),%eax
	movl %eax,%edi
	addl 8(%ebp),%edi
	movl %eax,%esi
	addl 12(%ebp),%esi
	.align 2,0x90
L129:
	movl (%esi),%edx
	movl %edx,%eax
	movl 16(%ebp),%ecx
	shrl %cl,%eax
	orl %ebx,%eax
	movl %eax,(%edi)
	xorl %ebx,%ebx
	cmpl $0,16(%ebp)
	je L127
	movl %edx,%ebx
	movl -4(%ebp),%ecx
	sall %cl,%ebx
L127:
	addl $-4,%edi
	addl $-4,%esi
	decl -8(%ebp)
	jns L129
L125:
	movl %ebx,%eax
L130:
	leal -20(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
NN_Div:
	pushl %ebp
	movl %esp,%ebp
	subl $440,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%edi
	movl 24(%ebp),%esi
	pushl 28(%ebp)
	pushl %esi
	call NN_Digits
	addl $8,%esp
	movl %eax,-416(%ebp)
	testl %eax,%eax
	je L131
	pushl -4(%esi,%eax,4)
	call NN_DigitBits
	addl $4,%esp
	movl $32,%ecx
	subl %eax,%ecx
	movl %ecx,-420(%ebp)
	pushl -416(%ebp)
	leal -268(%ebp),%ebx
	movl %ebx,-440(%ebp)
	pushl %ebx
	call NN_AssignZero
	addl $8,%esp
	pushl %edi
	pushl -420(%ebp)
	pushl 16(%ebp)
	pushl %ebx
	call NN_LShift
	addl $16,%esp
	movl %eax,-268(%ebp,%edi,4)
	pushl -416(%ebp)
	pushl -420(%ebp)
	pushl %esi
	leal -400(%ebp),%esi
	pushl %esi
	call NN_LShift
	addl $16,%esp
	movl -416(%ebp),%edx
	movl -404(%ebp,%edx,4),%ecx
	movl %ecx,-408(%ebp)
	pushl %edi
	pushl 8(%ebp)
	call NN_AssignZero
	addl $8,%esp
	subl -416(%ebp),%edi
	movl %edi,-412(%ebp)
	js L134
	movl %ebx,-424(%ebp)
	movl %esi,-428(%ebp)
	leal 0(,%edi,4),%eax
	movl %eax,%edx
	addl %ebx,%edx
	movl %edx,-432(%ebp)
	movl %eax,-436(%ebp)
	addl -416(%ebp),%edi
	.align 2,0x90
L141:
	cmpl $-1,-408(%ebp)
	jne L136
	movl -412(%ebp),%eax
	addl 28(%ebp),%eax
	movl -268(%ebp,%eax,4),%eax
	movl %eax,-404(%ebp)
	jmp L137
	.align 2,0x90
L136:
	movl -408(%ebp),%eax
	incl %eax
	pushl %eax
	movl -424(%ebp),%ecx
	leal -4(%ecx,%edi,4),%eax
	pushl %eax
	leal -404(%ebp),%eax
	pushl %eax
	call NN_DigitDiv
	addl $12,%esp
L137:
	pushl -416(%ebp)
	pushl -428(%ebp)
	pushl -404(%ebp)
	pushl -432(%ebp)
	pushl -432(%ebp)
	call NN_SubDigitMult
	addl $20,%esp
	subl %eax,-268(%ebp,%edi,4)
	movl %edi,%esi
	movl -432(%ebp),%ebx
	movl %ebx,-440(%ebp)
	.align 2,0x90
L138:
	cmpl $0,-268(%ebp,%esi,4)
	jne L140
	pushl -416(%ebp)
	pushl -428(%ebp)
	pushl -440(%ebp)
	call NN_Cmp
	addl $12,%esp
	testl %eax,%eax
	jl L139
L140:
	incl -404(%ebp)
	pushl -416(%ebp)
	pushl -428(%ebp)
	pushl -440(%ebp)
	pushl -440(%ebp)
	call NN_Sub
	addl $16,%esp
	subl %eax,-268(%ebp,%esi,4)
	jmp L138
	.align 2,0x90
L139:
	movl -404(%ebp),%ebx
	movl -436(%ebp),%edx
	movl 8(%ebp),%ecx
	movl %ebx,(%ecx,%edx)
	addl $-4,-432(%ebp)
	addl $-4,-436(%ebp)
	decl %edi
	decl -412(%ebp)
	jns L141
L134:
	pushl 28(%ebp)
	pushl 12(%ebp)
	call NN_AssignZero
	addl $8,%esp
	pushl -416(%ebp)
	pushl -420(%ebp)
	leal -268(%ebp),%ebx
	pushl %ebx
	pushl 12(%ebp)
	call NN_RShift
	addl $16,%esp
	pushl $268
	pushl $0
	pushl %ebx
	call R_memset
	addl $12,%esp
	pushl $132
	pushl $0
	leal -400(%ebp),%eax
	pushl %eax
	call R_memset
L131:
	leal -452(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
NN_AddDigitMult:
	pushl %ebp
	movl %esp,%ebp
	subl $16,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	cmpl $0,16(%ebp)
	jne L143
	xorl %eax,%eax
	jmp L151
	.align 2,0x90
L143:
	xorl %ebx,%ebx
	cmpl %ebx,24(%ebp)
	jbe L145
	movl 8(%ebp),%esi
	movl 12(%ebp),%edx
	movl %edx,-16(%ebp)
	movl 20(%ebp),%edi
	.align 2,0x90
L150:
	movl  16(%ebp),%eax
	mull  (%edi)
	movl  %eax,-8(%ebp)
	movl  %edx,-4(%ebp)
	movl %ebx,%eax
	movl -16(%ebp),%ecx
	addl (%ecx),%eax
	movl %eax,(%esi)
	cmpl %ebx,%eax
	jae L147
	movl $1,%ebx
	jmp L148
	.align 2,0x90
L147:
	xorl %ebx,%ebx
L148:
	movl (%esi),%eax
	addl -8(%ebp),%eax
	movl %eax,(%esi)
	cmpl %eax,-8(%ebp)
	jbe L149
	incl %ebx
L149:
	addl -4(%ebp),%ebx
	addl $4,%esi
	addl $4,-16(%ebp)
	addl $4,%edi
	movl 24(%ebp),%edx
	movl 8(%ebp),%ecx
	leal (%ecx,%edx,4),%eax
	cmpl %eax,%esi
	jb L150
L145:
	movl %ebx,%eax
L151:
	leal -28(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
NN_SubDigitMult:
	pushl %ebp
	movl %esp,%ebp
	subl $16,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	cmpl $0,16(%ebp)
	jne L153
	xorl %eax,%eax
	jmp L161
	.align 2,0x90
L153:
	xorl %ebx,%ebx
	cmpl %ebx,24(%ebp)
	jbe L155
	movl 8(%ebp),%esi
	movl 12(%ebp),%edi
	movl %edi,-12(%ebp)
	movl 20(%ebp),%ecx
	movl %ecx,-16(%ebp)
	.align 2,0x90
L160:
	movl -16(%ebp),%edi


	movl  16(%ebp),%eax
	mull  (%edi)
	movl  %eax,-8(%ebp)
	movl  %edx,-4(%ebp)

	movl -12(%ebp),%ecx
	movl (%ecx),%edx
	subl %ebx,%edx
	movl %edx,(%esi)
	movl $-1,%eax
	subl %ebx,%eax
	cmpl %eax,%edx
	seta %al
	movzbl %al,%ebx
	subl -8(%ebp),%edx
	movl %edx,(%esi)
	movl $-1,%eax
	subl -8(%ebp),%eax
	cmpl %eax,%edx
	jbe L159
	incl %ebx
L159:
	addl -4(%ebp),%ebx
	addl $4,%esi
	addl $4,-12(%ebp)
	addl $4,-16(%ebp)
	movl 24(%ebp),%edi
	movl 8(%ebp),%ecx
	leal (%ecx,%edi,4),%eax
	cmpl %eax,%esi
	jb L160
L155:
	movl %ebx,%eax
L161:
	leal -28(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
NN_DigitBits:
	pushl %ebp
	movl %esp,%ebp
	movl 8(%ebp),%edx
	xorl %eax,%eax
	.align 2,0x90
L167:
	testl %edx,%edx
	je L164
	incl %eax
	shrl $1,%edx
	cmpl $31,%eax
	jbe L167
L164:
	leave
	ret
	.align 2,0x90
