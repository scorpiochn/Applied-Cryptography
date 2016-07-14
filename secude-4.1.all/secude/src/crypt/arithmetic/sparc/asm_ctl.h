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

define(WINDOWSIZE,(16*4))
define(ARGPUSHSIZE,(6*4))
define(ARGPUSH,(WINDOWSIZE+4))
define(MINFRAME,(WINDOWSIZE+ARGPUSHSIZE+4))
define(STACK_ALIGN,8)
define(SA,((($1)+(STACK_ALIGN-1)) & ~(STACK_ALIGN-1)))

define(PROLOGUE,
	`save %sp, -SA(MINFRAME+$1), %sp')

define(EPILOGUE,
	ret     ;
	restore ;)

define(NAME,_$1)

define(ENTRY,
	.global NAME($1);
	NAME($1): )



define(COL,L$C_$1)
define(BRL,L$B_$1)
define(BREAK,
	$2
	b$3 BRL($1)
	nop)
define(CONTINUE,
	$2
	b$3  COL($1)
	nop)


define(LOOP,
	COL($1) :)
define(WHILE,
	CONTINUE($1,$2,$3)
	BRL($1) :)


define(IF,
	$2
	bne  L$I_$1
	nop)

define(IFNOT,
	$2
	b$3   L$I_$1
	nop )

define(ELSE,
	BREAK($1,,a) ;
	L$I_$1 :)
define(ENDIF,
	L$I_$1 :
	BRL($1) :)
define(ENDELSE,
	BRL($1) :)


define(FOR,
	COL($1) :
	BREAK($1,$2,$3))

define(ENDFOR,
	CONTINUE($1,,a)
	BRL($1) :)


