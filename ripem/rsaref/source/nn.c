/* NN.C - natural numbers routines
 * 
 * Modified by Mark C. Henderson, 20 December 1992, to incorporate
 *   multiplication code from BIGNUM for a ~15% performance speedup.
 *   See #ifndef USE_BIGNUM.
 * Modified by Mark C. Henderson, April 1993, to speed up
 *   exponentiation.  Added NN_2ModExp.
 * Modified by Mark Riordan, 15 April 1993, by incorporating
 *   Intel 386 assembly code.  See USE_386_ASM.  Note:
 *   Kaliski's original code is more amenable to asm speedup than
 *   the BIGNUM code, so do not define USE_BIGNUM when using
 *   USE_386_ASM.  Separate 386 assembly code for BIGNUM
 *   is available by defining USE_ASM_386_BIGNUM, but it is slower.
 */

/* The BIGNUM code doesn't seem to work for MS-DOS */

/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
   Security, Inc. All rights reserved.
 */

#include "global.h"
#include "rsaref.h"
#include "nn.h"
#include "digit.h"
#include "digitas.h"


#ifdef DIGIT_IN_NN
/* Computes a = b * c, where b and c are digits.

   Lengths: a[2].
 */
void NN_DigitMult (a, b, c)
NN_DIGIT a[2], b, c;
{
  NN_DIGIT t, u;
  NN_HALF_DIGIT bHigh, bLow, cHigh, cLow;

  bHigh = HIGH_HALF (b);
  bLow = LOW_HALF (b);
  cHigh = HIGH_HALF (c);
  cLow = LOW_HALF (c);

  a[0] = (NN_DIGIT)bLow * (NN_DIGIT)cLow;
  t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh;
  u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow;
  a[1] = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh;
  
  if ((t += u) < u)
    a[1] += TO_HIGH_HALF (1);
  u = TO_HIGH_HALF (t);
  
  if ((a[0] += u) < u)
    a[1]++;
  a[1] += HIGH_HALF (t);
}

/* Sets a = b / c, where a and c are digits.

   Lengths: b[2].
   Assumes b[1] < c and HIGH_HALF (c) > 0. For efficiency, c should be
   normalized.
 */
void NN_DigitDiv (a, b, c)
NN_DIGIT *a, b[2], c;
{
  NN_DIGIT t[2], u, v;
  NN_HALF_DIGIT aHigh, aLow, cHigh, cLow;

  cHigh = HIGH_HALF (c);
  cLow = LOW_HALF (c);

  t[0] = b[0];
  t[1] = b[1];

  /* Underestimate high half of quotient and subtract.
   */
  if (cHigh == MAX_NN_HALF_DIGIT)
    aHigh = HIGH_HALF (t[1]);
  else
    aHigh = (NN_HALF_DIGIT)(t[1] / (cHigh + 1));
  u = (NN_DIGIT)aHigh * (NN_DIGIT)cLow;
  v = (NN_DIGIT)aHigh * (NN_DIGIT)cHigh;
  if ((t[0] -= TO_HIGH_HALF (u)) > (MAX_NN_DIGIT - TO_HIGH_HALF (u)))
    t[1]--;
  t[1] -= HIGH_HALF (u);
  t[1] -= v;

  /* Correct estimate.
   */
  while ((t[1] > cHigh) ||
         ((t[1] == cHigh) && (t[0] >= TO_HIGH_HALF (cLow)))) {
    if ((t[0] -= TO_HIGH_HALF (cLow)) > MAX_NN_DIGIT - TO_HIGH_HALF (cLow))
      t[1]--;
    t[1] -= cHigh;
    aHigh++;
  }

  /* Underestimate low half of quotient and subtract.
   */
  if (cHigh == MAX_NN_HALF_DIGIT)
    aLow = LOW_HALF (t[1]);
  else
    aLow =
      (NN_HALF_DIGIT)
        ((NN_DIGIT)(TO_HIGH_HALF (t[1]) + HIGH_HALF (t[0])) / (cHigh + 1));
  u = (NN_DIGIT)aLow * (NN_DIGIT)cLow;
  v = (NN_DIGIT)aLow * (NN_DIGIT)cHigh;
  if ((t[0] -= u) > (MAX_NN_DIGIT - u))
    t[1]--;
  if ((t[0] -= TO_HIGH_HALF (v)) > (MAX_NN_DIGIT - TO_HIGH_HALF (v)))
    t[1]--;
  t[1] -= HIGH_HALF (v);

  /* Correct estimate.
   */
  while ((t[1] > 0) || ((t[1] == 0) && t[0] >= c)) {
    if ((t[0] -= c) > (MAX_NN_DIGIT - c))
      t[1]--;
    aLow++;
  }
  
  *a = TO_HIGH_HALF (aHigh) + aLow;
}
#endif

static NN_DIGIT NN_LShift PROTO_LIST 
  ((NN_DIGIT *, NN_DIGIT *, unsigned int, unsigned int));
static NN_DIGIT NN_RShift PROTO_LIST
  ((NN_DIGIT *, NN_DIGIT *, unsigned int, unsigned int));
static void NN_Div PROTO_LIST
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT *,
    unsigned int));

static unsigned int NN_DigitBits PROTO_LIST ((NN_DIGIT));

/* Decodes character string b into a, where character string is ordered
   from most to least significant.

   Length: a[digits], b[len].
   Assumes b[i] = 0 for i < len - digits * NN_DIGIT_LEN. (Otherwise most
   significant bytes are truncated.)
 */
void NN_Decode (a, digits, b, len)
NN_DIGIT *a;
unsigned char *b;
unsigned int digits, len;
{
  NN_DIGIT t;
  int j;
  unsigned int i, u;
  
  for (i = 0, j = len - 1; j >= 0; i++) {
    t = 0;
    for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
      t |= ((NN_DIGIT)b[j]) << u;
    a[i] = t;
  }
  
  for (; i < digits; i++)
    a[i] = 0;
}

/* Encodes b into character string a, where character string is ordered
   from most to least significant.

   Lengths: a[len], b[digits].
   Assumes NN_Bits (b, digits) <= 8 * len. (Otherwise most significant
   digits are truncated.)
 */
void NN_Encode (a, len, b, digits)
NN_DIGIT *b;
unsigned char *a;
unsigned int digits, len;
{
  NN_DIGIT t;
  int j;
  unsigned int i, u;

  for (i = 0, j = len - 1; i < digits; i++) {
    t = b[i];
    for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
      a[j] = (unsigned char)(t >> u);
  }

  for (; j >= 0; j--)
    a[j] = 0;
}

/* Assigns a = 0.

   Lengths: a[digits], b[digits].
 */
void NN_Assign (a, b, digits)
NN_DIGIT *a, *b;
unsigned int digits;
{
  unsigned int i;

  for (i = 0; i < digits; i++)
    a[i] = b[i];
}

/* Assigns a = 0.

   Lengths: a[digits].
 */
void NN_AssignZero (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  unsigned int i;

  for (i = 0; i < digits; i++)
    a[i] = 0;
}

/* Assigns a = 2^b.

   Lengths: a[digits].
   Requires b < digits * NN_DIGIT_BITS.
 */
void NN_Assign2Exp (a, b, digits)
NN_DIGIT *a;
unsigned int b, digits;
{
  NN_AssignZero (a, digits);

  if (b >= digits * NN_DIGIT_BITS)
    return;

  a[b / NN_DIGIT_BITS] = (NN_DIGIT)1 << (b % NN_DIGIT_BITS);
}

/* Computes a = b + c. Returns carry.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT NN_Add (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT ai, carry;
  unsigned int i;

  carry = 0;

  for (i = 0; i < digits; i++) {
    if ((ai = b[i] + carry) < carry)
      ai = c[i];
    else if ((ai += c[i]) < c[i])
      carry = 1;
    else
      carry = 0;
    a[i] = ai;
  }

  return (carry);
}

/* Computes a = b - c. Returns borrow.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT NN_Sub (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT ai, borrow;
  unsigned int i;

  borrow = 0;

  for (i = 0; i < digits; i++) {
    if ((ai = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
      ai = MAX_NN_DIGIT - c[i];
    else if ((ai -= c[i]) > (MAX_NN_DIGIT - c[i]))
      borrow = 1;
    else
      borrow = 0;
    a[i] = ai;
  }

  return (borrow);
}

/* Computes a = b * c.

   Lengths: a[2*digits], b[digits], c[digits].
   Assumes digits < MAX_NN_DIGITS.
 */
#ifndef USE_BIGNUM
void NN_Mult (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS];
  unsigned int bDigits, cDigits, i;

  NN_AssignZero (t, 2 * digits);
  
  bDigits = NN_Digits (b, digits);
  cDigits = NN_Digits (c, digits);

  for (i = 0; i < bDigits; i++)
    t[i+cDigits] += NN_AddDigitMult (&t[i], &t[i], b[i], c, cDigits);
  
  NN_Assign (a, t, 2 * digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}
#else
 static NN_DIGIT XXXAddCarry PROTO_LIST 
 ((NN_DIGIT *, int, NN_DIGIT));
 static NN_DIGIT XXXAdd PROTO_LIST 
 ((NN_DIGIT *, int, NN_DIGIT *, int, NN_DIGIT));
 static NN_DIGIT XXXMultiplyDigit PROTO_LIST
 ((NN_DIGIT *, int, NN_DIGIT *, int, NN_DIGIT));

/* Computes a = b * c.

   Lengths: a[2*digits], b[digits], c[digits].
   Assumes digits < MAX_NN_DIGITS.
 */
/* some code here extracted from BIGNUM */
void NN_Mult (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS];
  unsigned int bDigits, cDigits, i, tDigits;
  NN_DIGIT cc;
  NN_DIGIT *nt = &t[0];

  NN_AssignZero (t, 2 * digits);
  
  bDigits = NN_Digits (b, digits);
  cDigits = NN_Digits (c, digits);
  tDigits = 2*digits;

  if ((&b[0]!=&c[0]) || (bDigits < 6)) {
      for (i = 0; i < bDigits; i++)
        t[i+cDigits] += NN_AddDigitMult (&t[i], &t[i], b[i], c, cDigits);
  } 
  else  {
    register n_prev = 0;
    for (cc = 0; cDigits > 0; )
    {
       register NN_DIGIT n = *b;
       cc += XXXMultiplyDigit(nt, tDigits, b, 1, n);
       if (n_prev)
           cc += XXXAdd(nt, tDigits, b, 1, 0);
       cDigits--, b++;
       nt += 2, tDigits -= 2;
       cc += XXXMultiplyDigit(nt-1, tDigits+1, b, cDigits, n+n+n_prev);
       n_prev = ((long) n) < 0;
    }
  }
  
  NN_Assign (a, t, 2 * digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

static NN_DIGIT XXXAddCarry (nn, nl, carryin)
NN_DIGIT *  nn;
int         nl;
NN_DIGIT    carryin;

/*
 * Performs the sum N + CarryIn => N.  
 * Returns the CarryOut.
 */

{
    if (carryin == 0) 
        return (0);

    if (nl == 0) 
        return (1);

    while (--nl >= 0 && !(++(*nn++)))
        ;

    return (nl >= 0 ? 0 : 1);
}

static NN_DIGIT XXXAdd (mm, ml, nn, nl, carryin)
NN_DIGIT *mm, *nn;
int         ml;
int         nl;
NN_DIGIT carryin; 

/* 
 * Performs the sum M + N + CarryIn => M.
 * Returns the CarryOut. 
 * Assumes Size(M) >= Size(N).
 */

{
    register NN_DIGIT c = carryin;
    register NN_DIGIT save;


    ml -= nl;

    while (--nl >= 0)
    {
        save = *mm;
        c += save;
        if (c < save) 
        {
        *(mm++) = *(nn++);
        c = 1;
        }
        else
        {
        save = *(nn++);
        c += save;
        *(mm++) = c;
        c = (c < save) ? 1 : 0;
        }
    }

    return (XXXAddCarry (mm, ml, (NN_DIGIT) c));
}

static NN_DIGIT XXXMultiplyDigit (pp, pl, mm, ml, d)
NN_DIGIT *  pp, *mm;
int         pl, ml; 
NN_DIGIT    d;
{ 
#ifndef USE_ASM_386
   register 
#endif
	NN_DIGIT c = 0;

    if (d == 0) 
        return (0);

    if (d == 1) 
        return (XXXAdd (pp, pl, mm, ml, (NN_DIGIT) 0));

    pl -= ml;
    /* test computed at compile time */
  {
#ifndef USE_ASM_386_BIGNUM
/* help for stupid compilers--may actually be counter
   productive on pipelined machines with decent register allocation!! */
#define m_digit X0
#define X3 Lm
#define X1 Hm
    register NN_DIGIT Lm, Hm, Ld, Hd, X0, X2 /*, X1, X3 */;

    Ld = d & ((1 << (NN_DIGIT_BITS / 2)) -1);
    Hd = d >> (NN_DIGIT_BITS / 2);
    while (ml != 0) 
    {
        ml--;
        m_digit = *mm++;
        Lm = m_digit & ((1 << (NN_DIGIT_BITS / 2)) -1);
        Hm = m_digit >> (NN_DIGIT_BITS / 2);
        X0 = Ld * Lm;
        X2 = Hd * Lm;
        X3 = Hd * Hm;
        X1 = Ld * Hm;

        if ((c += X0) < X0) X3++;
        if ((X1 += X2) < X2) X3 += (1<<(NN_DIGIT_BITS / 2));
        X3 += (X1 >> (NN_DIGIT_BITS / 2));
        X1 <<= (NN_DIGIT_BITS / 2);
        if ((c += X1) < X1) X3++;
        if ((*pp += c) < c) X3++;
        pp++;
        c = X3;
#undef m_digit
#undef X1
#undef X3
    }
#else
		/* Register allocation:
		 *   eax		used for multiplies
		 *   ebx		d (digit)
		 *   ecx		c (carry)
		 *   edx    used for multiplies
		 *   esi		points to current digit in mm
		 *   edi  	points to current digit in pp
		 *   
		 */
		_asm{
			mov	ebx,d		; put d in a register.
			sub	ecx,ecx	; c = 0 
			mov	esi,mm
			mov	edi,pp
			cmp	ml,0
			jz		endloop
		mulloop:;
				mov	eax,[esi]	;eax = *mm
				add	esi,4		; mm++
				mul	ebx		;edx:eax = (*mm) * d
				add	ecx,eax	;c += low-order product
				jnc	no_c_carry	;jump if no overflow
				inc	edx		;If carry overflowed, inc high-order product
		no_c_carry:;
				add	[edi],ecx ;add carry into product
				jnc	no_c_pp
				inc	edx		;if *pp overflowed, inc high-order product
		no_c_pp:;
				add	edi,4		; pp++ 
				mov	ecx,edx	;c = high-order product
			
				dec	ml
				jnz 	mulloop
		endloop:;
				mov	c,ecx		;move c back to variable
				mov	pp,edi	;move pp back to variable
		}
#endif

	{ 
	 NN_DIGIT XX0;

    XX0 = *pp;
    c += XX0;
    *(pp++) = c;

    if (c >= XX0)
        return (0);

    pl--;
    while (pl != 0 && !(++(*pp++))) 
        pl--;
    return (pl != 0 ? 0 : 1);
   }
  }
}
#endif

/* Computes a = b mod c.

   Lengths: a[cDigits], b[bDigits], c[cDigits].
   Assumes c > 0, bDigits < 2 * MAX_NN_DIGITS, cDigits < MAX_NN_DIGITS.
 */
void NN_Mod (a, b, bDigits, c, cDigits)
NN_DIGIT *a, *b, *c;
unsigned int bDigits, cDigits;
{
  NN_DIGIT t[2 * MAX_NN_DIGITS];
  
  NN_Div (t, a, b, bDigits, c, cDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b * c mod d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes d > 0, digits < MAX_NN_DIGITS.
 */
void NN_ModMult (a, b, c, d, digits)
NN_DIGIT *a, *b, *c, *d;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS];

  NN_Mult (t, b, c, digits);
  NN_Mod (a, t, 2 * digits, d, digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes b < d, d > 0, cDigits > 0, dDigits > 0,
           dDigits < MAX_NN_DIGITS.
 */
void NN_ModExp (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT bPower[3][MAX_NN_DIGITS], ci, t[MAX_NN_DIGITS];
  int i;
  unsigned int ciBits, j, s;

  /* Store b, b^2 mod d, and b^3 mod d.
   */
  NN_Assign (bPower[0], b, dDigits);
  NN_ModMult (bPower[1], bPower[0], b, d, dDigits);
  NN_ModMult (bPower[2], bPower[1], b, d, dDigits);
  
  NN_ASSIGN_DIGIT (t, 1, dDigits);

  cDigits = NN_Digits (c, cDigits);
  for (i = cDigits - 1; i >= 0; i--) {
    ci = c[i];
    ciBits = NN_DIGIT_BITS;
    
    /* Scan past leading zero bits of most significant digit.
     */
    if (i == (int)(cDigits - 1)) {
      while (! DIGIT_2MSB (ci)) {
        ci <<= 2;
        ciBits -= 2;
      }
    }

    for (j = 0; j < ciBits; j += 2, ci <<= 2) {
      /* Compute t = t^4 * b^s mod d, where s = two MSB's of d.
       */
      NN_ModMult (t, t, t, d, dDigits);
      NN_ModMult (t, t, t, d, dDigits);
      if (s = DIGIT_2MSB (ci))
        NN_ModMult (t, t, bPower[s-1], d, dDigits);
    }
  }
  
  NN_Assign (a, t, dDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)bPower, 0, sizeof (bPower));
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = 2^c mod d.

   Lengths: a[dDigits], c[cDigits], d[dDigits].
   Assumes 2 < d, d > 0, cDigits > 0, dDigits > 0,
           dDigits < MAX_NN_DIGITS.
 */

void NN_2ModExp (a, c, cDigits, d, dDigits)
NN_DIGIT *a, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT ci, t[MAX_NN_DIGITS], bt[MAX_NN_DIGITS*2];
  int i;
  unsigned int ciBits, j, s;

  NN_ASSIGN_DIGIT (t, 1, dDigits);

  cDigits = NN_Digits (c, cDigits);
  for (i = cDigits - 1; i >= 0; i--) {
    ci = c[i];
    ciBits = NN_DIGIT_BITS;
    
    /* Scan past leading zero bits of most significant digit.
     */
    if (i == (int)(cDigits - 1)) {
      while (! DIGIT_2MSB (ci)) {
        ci <<= 2;
        ciBits -= 2;
      }
    }

    for (j = 0; j < ciBits; j += 2, ci <<= 2) {
      /* Compute t = t^4 * 2^s mod d, where s = two MSB's of d.
       */
      NN_ModMult (t, t, t, d, dDigits);
      NN_ModMult (t, t, t, d, dDigits);
      if (s = DIGIT_2MSB (ci)) {
      bt[dDigits]=NN_LShift(bt,t,s,dDigits);
      NN_Mod(t, bt, dDigits+1, d, dDigits);
    }
    }
  }
  
  NN_Assign (a, t, dDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
  R_memset ((POINTER)bt, 0, sizeof(NN_DIGIT)*2);
}


/* Compute a = 1/b mod c, assuming inverse exists.
   
   Lengths: a[digits], b[digits], c[digits].
   Assumes gcd (b, c) = 1, digits < MAX_NN_DIGITS.
 */
void NN_ModInv (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT q[MAX_NN_DIGITS], t1[MAX_NN_DIGITS], t3[MAX_NN_DIGITS],
    u1[MAX_NN_DIGITS], u3[MAX_NN_DIGITS], v1[MAX_NN_DIGITS],
    v3[MAX_NN_DIGITS], w[2*MAX_NN_DIGITS];
  int u1Sign;

  /* Apply extended Euclidean algorithm, modified to avoid negative
     numbers.
   */
  NN_ASSIGN_DIGIT (u1, 1, digits);
  NN_AssignZero (v1, digits);
  NN_Assign (u3, b, digits);
  NN_Assign (v3, c, digits);
  u1Sign = 1;

  while (! NN_Zero (v3, digits)) {
    NN_Div (q, t3, u3, digits, v3, digits);
    NN_Mult (w, q, v1, digits);
    NN_Add (t1, u1, w, digits);
    NN_Assign (u1, v1, digits);
    NN_Assign (v1, t1, digits);
    NN_Assign (u3, v3, digits);
    NN_Assign (v3, t3, digits);
    u1Sign = -u1Sign;
  }
  
  /* Negate result if sign is negative.
    */
  if (u1Sign < 0)
    NN_Sub (a, c, u1, digits);
  else
    NN_Assign (a, u1, digits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)q, 0, sizeof (q));
  R_memset ((POINTER)t1, 0, sizeof (t1));
  R_memset ((POINTER)t3, 0, sizeof (t3));
  R_memset ((POINTER)u1, 0, sizeof (u1));
  R_memset ((POINTER)u3, 0, sizeof (u3));
  R_memset ((POINTER)v1, 0, sizeof (v1));
  R_memset ((POINTER)v3, 0, sizeof (v3));
  R_memset ((POINTER)w, 0, sizeof (w));
}

/* Computes a = gcd(b, c).

   Lengths: a[digits], b[digits], c[digits].
   Assumes b > c, digits < MAX_NN_DIGITS.
 */
void NN_Gcd (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[MAX_NN_DIGITS], u[MAX_NN_DIGITS], v[MAX_NN_DIGITS];

  NN_Assign (u, b, digits);
  NN_Assign (v, c, digits);

  while (! NN_Zero (v, digits)) {
    NN_Mod (t, u, digits, v, digits);
    NN_Assign (u, v, digits);
    NN_Assign (v, t, digits);
  }

  NN_Assign (a, u, digits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
  R_memset ((POINTER)u, 0, sizeof (u));
  R_memset ((POINTER)v, 0, sizeof (v));
}

/* Returns sign of a - b.

   Lengths: a[digits], b[digits].
 */
int NN_Cmp (a, b, digits)
NN_DIGIT *a, *b;
unsigned int digits;
{
	int retval=0;

#ifdef USE_386_ASM
	/* Register assignments:
  	 *
	 *	EAX	
	 *	EBX	
	 *	ECX	loop counter	
	 * EDX	4
	 * ESI	&a
	 * EDI	&b
	 */
	_asm {
		mov	ecx,digits
		mov	esi,a
		mov	edi,b
		mov	edx,4		;handy constant for loop
		mov	eax,ecx	;eax=digits
		dec	eax		;eax=digits-1
		sal	eax,2		;eax=(digits-1)*4
		add	esi,eax	;esi=&a[digits-1]
		add	edi,eax	;edi=&b[digits-1]
		cmp	ecx,0		;
		jz		digits_zero	;
		;jecxz	digits_zero  ; This gives internal compiler error.
	cmp_loop:;
		mov	eax,[esi]
		cmp	eax,[edi]
		ja		a_greater
		jb		b_greater
		sub	esi,edx	;move back one array element
		sub	edi,edx
		dec	ecx
		jnz	cmp_loop
							;loop	cmp_loop gives internal compiler error
	digits_zero:;
		jmp	end_asm
	a_greater:;
		mov	retval,1    ;return 1
		jmp	end_asm
	b_greater:;
		mov	retval,-1   ;return -1

	end_asm:;
	}


#else
  int i;
  
  for (i = digits - 1; i >= 0; i--) {
    if (a[i] > b[i])
      return (1);
    if (a[i] < b[i])
      return (-1);
  }
#endif

  return (retval);
}

/* Returns nonzero iff a is zero.

   Lengths: a[digits].
 */
int NN_Zero (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  unsigned int i;
  
  for (i = 0; i < digits; i++)
    if (a[i])
      return (0);
    
  return (1);
}

/* Returns the significant length of a in bits.

   Lengths: a[digits].
 */
unsigned int NN_Bits (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  if ((digits = NN_Digits (a, digits)) == 0)
    return (0);

  return ((digits - 1) * NN_DIGIT_BITS + NN_DigitBits (a[digits-1]));
}

/* Returns the significant length of a in digits.

   Lengths: a[digits].
 */
unsigned int NN_Digits (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  int i;
  
  for (i = digits - 1; i >= 0; i--)
    if (a[i])
      break;

  return (i + 1);
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires c < NN_DIGIT_BITS.
 */
static NN_DIGIT NN_LShift (a, b, c, digits)
NN_DIGIT *a, *b;
unsigned int c, digits;
{
  NN_DIGIT bi, carry;
  unsigned int i, t;
  
  if (c >= NN_DIGIT_BITS)
    return (0);
  
  t = NN_DIGIT_BITS - c;

  carry = 0;

  for (i = 0; i < digits; i++) {
    bi = b[i];
    a[i] = (bi << c) | carry;
    carry = c ? (bi >> t) : 0;
  }
  
  return (carry);
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires: c < NN_DIGIT_BITS.
 */
static NN_DIGIT NN_RShift (a, b, c, digits)
NN_DIGIT *a, *b;
unsigned int c, digits;
{
  NN_DIGIT bi, carry;
  int i;
  unsigned int t;
  
  if (c >= NN_DIGIT_BITS)
    return (0);
  
  t = NN_DIGIT_BITS - c;

  carry = 0;

  for (i = digits - 1; i >= 0; i--) {
    bi = b[i];
    a[i] = (bi >> c) | carry;
    carry = c ? (bi << t) : 0;
  }
  
  return (carry);
}

/* Computes a = c div d and b = c mod d.

   Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS,
           dDigits < MAX_NN_DIGITS.
 */
static void NN_Div (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT ai, cc[2*MAX_NN_DIGITS+1], dd[MAX_NN_DIGITS], t;
  int i;
  unsigned int ddDigits, shift;
  
  ddDigits = NN_Digits (d, dDigits);
  if (ddDigits == 0)
    return;
  
  /* Normalize operands.
   */
  shift = NN_DIGIT_BITS - NN_DigitBits (d[ddDigits-1]);
  NN_AssignZero (cc, ddDigits);
  cc[cDigits] = NN_LShift (cc, c, shift, cDigits);
  NN_LShift (dd, d, shift, ddDigits);
  t = dd[ddDigits-1];
  
  NN_AssignZero (a, cDigits);

  for (i = cDigits-ddDigits; i >= 0; i--) {
    /* Underestimate quotient digit and subtract.
     */
    if (t == MAX_NN_DIGIT)
      ai = cc[i+dDigits];
    else
      NN_DigitDiv (&ai, &cc[i+ddDigits-1], t + 1);
    cc[i+ddDigits] -= NN_SubDigitMult (&cc[i], &cc[i], ai, dd, ddDigits);

    /* Correct estimate.
     */
    while (cc[i+ddDigits] || (NN_Cmp (&cc[i], dd, ddDigits) >= 0)) {
      ai++;
      cc[i+ddDigits] -= NN_Sub (&cc[i], &cc[i], dd, ddDigits);
    }
    
    a[i] = ai;
  }
  
  /* Restore result.
   */
  NN_AssignZero (b, dDigits);
  NN_RShift (b, cc, shift, ddDigits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)cc, 0, sizeof (cc));
  R_memset ((POINTER)dd, 0, sizeof (dd));
}

/* Returns the significant length of a in bits, where a is a digit.
 */
static unsigned int NN_DigitBits (a)
NN_DIGIT a;
{
  unsigned int i;
  
  for (i = 0; i < NN_DIGIT_BITS; i++, a >>= 1)
    if (a == 0)
      break;
    
  return (i);
}
