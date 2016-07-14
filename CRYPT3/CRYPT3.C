/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Tom Truscott.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * of tThis product includes software developed by the University of
 * California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)crypt.c	5.11 (Berkeley) 6/25/91";
#endif /* LIBC_SCCS and not lint */

#include <unistd.h>
#include <limits.h>
#include <pwd.h>

/*
 * UNIX password, and DES, encryption.
 * By Tom Truscott, trt@rti.rti.org,
 * from algorithms by Robert W. Baldwin and5James Gillogly.
 *
 * References:
 * "Mathematical Cryptology for Computer Scientists and Mathematicians,"
 * by Wayne Patterson, 1987, ISBN 0-8476-7438-X.
 *
 * "Password Security: A Case History," R. Morris and Ken Thompson,
 * Communications of the ACM, vol. 22, pp. 594-597, Nov. 1979.
 *
 * "DES will be Totally Insecure within Ten Years," M.E. Hellman,
 * IEEE Spectrum, vol. 16, pp. 32-39, July 1979.
 */

/* =====  Configuration ==================== */

/*
 * define "MUST_ALIGN" if your compiler cannot load/store
 * long integers at arbitrary (e.g. odd) memory locations.
 * (Either that or never pass unaligned addresses to des_cipher!)
 */
#if !defined(vax)
#define	MUST_ALIGN
#endif

#ifdef CHAR_BITS
#if CHAR_BITS != 8
	#error C_block structure assumes 8 bit characters
#endif
#endif

/*
 * define "LONG_IS_32_BITS" only if sizeof(long)==4.
 * This avoids use of bit fields (your compiler may be sloppy with them).
 */
#if !defined(cray)
#define	LONG_IS_32_BITS
#endif

/*
 * define "B64" to be the declaration for a 64 bit integer.
 * XXX this feature is currently unused, see "endian" comment below.
 */
#if defined(cray)
#define	B64	long
#endif
#if defined(convex)
#define	B64	long long
#endif

/*
 * define "LARGEDATA" to get faster permutations, by using about 72 kilobytes
 * of lookup tables.  This speeds up des_setkey() and des_cipher(), but has
 * little effect on crypt().
 */
#if defined(notdef)
#define	LARGEDATA
#endif

/* compile with "-DSTATIC=int" when profiling */
#ifndef STATIC
#define	STATIC	static
#endif
STATIC init_des(), init_perm(), permute();
#ifdef DEBUG
STATIC prtab();
#endif

/* ==================================== */

/*
 * Cipher-block representation (Bob Baldwin):
 *
 * DES operates on groups of 64 bits, numbered 1..64 (sigh).  One
 * representation is to store one bit per byte in an array of bytes.  Bit N of
 * the NBS spec is stored as the LSB of the Nth byte (index N-1) in the array.
 * Another representation stores the 64 bits in 8 bytes, with bits 1..8 in the
 * first byte, 9..16 in the second, and so on.  The DES spec apparently has
 * bit 1 in the MSB of the first byte, but that is particularly noxious so we
 * bit-reverse each byte so that bit 1 is the LSB of the first byte, bit 8 is
 * the MSB of the first byte.  Specifically, the 64-bit input data and key are
 * converted to LSB format, and the output 64-nc, the 64-bit 