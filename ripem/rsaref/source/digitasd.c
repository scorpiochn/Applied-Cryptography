/* DIGITASD.C -- Add and Subtract Digit with Multiply routines.
 * (MS-DOS specific version of DIGITAS.C.)
 * Originally part of RSAREF's NN.C.
 * Moved into a new file by Mark Riordan, April 1993,
 * to isolate frequently-changed code.
 *
 * Modified by Mark Riordan, April 1993:
 *   Enhanced with Intel 386 assembler and GNU CC "long long"
 *   extensions to increase performanace.  Define USE_386_ASM
 *   for Intel inline assembler.  Define GCC and RS6000 for
 *   "long long" extensions.
 * Modified by Mark Henderson, April 1993:
 *   Added GCC-compatible assembler syntax version of above mods.
 *   for unix/linux 386 version with gcc/gas define both GCC and i386
 *   as with intel version, faster with USE_BIGNUM off.
 * Modified by Mark Riordan, June 1993.
 *   Added a test for processor type for the generic MS-DOS version,
 *   and added 386-specific assembly code for use when a 386 or
 *   higher is detected.  This version of the code was moved
 *   to a separate file named DIGITASD.C.
 */
/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
	Security, Inc. All rights reserved.
 */
#include "global.h"
#include "rsaref.h"
#include "nn.h"
#include "digit.h"

extern int Got386;
/* "do32" emits a 386-and-higher opcode prefix that switches
 * the 386 into 32-bit mode for one instruction.
 */
#define do32 __asm _emit 0x66

/* Computes a = b + c*d, where c is a digit. Returns carry.

	Lengths: a[digits], b[digits], d[digits].
 */
NN_DIGIT NN_AddDigitMult (a, b, c, d, digits)
NN_DIGIT *a, *b, c, *d;
unsigned int digits;
{
	NN_DIGIT carry;
	NN_DIGIT t[2];
	unsigned int i;

  if (c == 0)
	 return (0);


 if(Got386) {
	digits *= 4;
	/* Register assignments:
	 *
	 * EAX   
	 * EBX   i
	 * ECX   carry
	 * EDX   
	 * ESI   &a
	 * EDI   scratch register for array base addresses
	 */
  _asm {
		do32
		sub   bx,bx ;i=0
		do32
		sub   cx,cx ;carry=0
		mov   si,word ptr a     ;esi=&a
		cmp   digits,0
		jz    endloop  ;jump if digits=0
	mulloop:;
		mov   di,word ptr b     ;edi=&b
		do32
		add   cx,[di+bx]  ;carry += b[i]
		do32
		mov   [si+bx],cx  ;a[i] = carry+b[i]
		do32
		mov   cx,0     ;carry=0
		__asm _emit 0
		__asm _emit    0
		jnc   nocar_add   ;jump if addition did not carry
		do32
		inc   cx    ;carry=1
	nocar_add:;
		lea   di,c     ;eax=c
		do32
		mov   ax,[di]
		mov   di,word ptr d     ;edi=&d
		do32
		mul   word ptr [di+bx]  ;edx:eax = c*d[i]

		do32
		add   [si+bx],ax  ;a[i] += low order product
		jnc   nocarry
		do32
		inc   cx    ;carry++
	nocarry:;
		do32
		add   cx,dx ;carry += high order product     
		do32
		add   bx,4     ;i++
		cmp   bx,digits
		jb    mulloop  ;jump if i<digits
	endloop:;   
		do32
		mov   word ptr carry,cx
	};
 } else {
  /* The same code as above, in less efficient C. */
  carry = 0;
  for (i = 0; i < digits; i++) {
	 NN_DigitMult (t, c, d[i]);
	 if ((a[i] = b[i] + carry) < carry)
		carry = 1;
	 else
		carry = 0;
	 if ((a[i] += t[0]) < t[0])
		carry++;
	 carry += t[1];

  }
 } 
  return (carry);
}


/* Computes a = b - c*d, where c is a digit. Returns borrow.

	Lengths: a[digits], b[digits], d[digits].
 */
NN_DIGIT NN_SubDigitMult (a, b, c, d, digits)
NN_DIGIT *a, *b, c, *d;
unsigned int digits;
{
  NN_DIGIT borrow;
  NN_DIGIT t[2];
  unsigned int i;

  if (c == 0)
	 return (0);

 if(Got386) {
	digits *= 4;
	/* Register assignments:
	 *
	 * EAX   Scratch reg for multiply
	 * EBX   i
	 * ECX   borrow
	 * EDX   Scratch reg for multiply
	 * ESI   &a
	 * EDI   scratch register for array base addresses
	 */
  _asm {
		do32
		sub   bx,bx ;i=0
		do32
		sub   cx,cx ;borrow=0
		mov   si,word ptr a     ;esi=&a
		cmp   digits,0
		jz    endloop  ;jump if digits=0
	mulloop:;
		mov   di,word ptr b     ;edi=&b
		do32
		mov   ax,[di+bx]  ;eax=b[i]
		do32
		sub   ax,cx ;eax=b[i]-borrow
		do32
		mov   [si+bx],ax  ;a[i] = b[i]-borrow
		do32
		mov   cx,0     ;borrow=0
		__asm _emit 0
		__asm _emit 0
		jnc   noborrow_sub   ;jump if subtract did not borrow
		do32
		inc   cx    ;borrow=1
	noborrow_sub:;
		lea   di,c
		do32
		mov   ax,[di]     ;eax=c
		mov   di,word ptr d     ;edi=&d
		do32
		mul   word ptr [di+bx]  ;edx:eax = c*d[i]

		do32
		sub   [si+bx],ax  ;a[i] -= low order product
		jnc   noborrow
		do32
		inc   cx    ;borrow++
	noborrow:;
		do32
		add   cx,dx ;borrow += high order product    
		do32
		add   bx,4     ;i++
		cmp   bx,digits
		jb    mulloop  ;jump if i<digits
	endloop:;   
		do32
		mov   word ptr borrow,cx
	};

 } else {
  /* Same as above, in generic C. */
  borrow = 0;
  for (i = 0; i < digits; i++) {
	 NN_DigitMult (t, c, d[i]);
	 if ((a[i] = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
		borrow = 1;
	 else
		borrow = 0;
	 if ((a[i] -= t[0]) > (MAX_NN_DIGIT - t[0]))
		borrow++;
	 borrow += t[1];
  }
 }
  return (borrow);
}

