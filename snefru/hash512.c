/*
**  This is Snefru, derived from the Xerox Secure Hash Function.
**  Snefru is a one-way hash function that provides authentication.
**  It does not provide secrecy.
**
**  Snefru is named after a Pharaoh of ancient Egypt.
**
**  It is based on code that is:
**	Copyright (c) Xerox Corporation 1989.  All rights reserved.
**
**	License to copy and use this software is granted provided that it
**	is identified as the 'Xerox Secure Hash Function' in all material
**	mentioning or referencing this software or this hash function.
**
**	License is also granted to make and use derivative works provided
**	that such works are identified as 'derived from the Xerox Secure
**	Hash Function' in all material mentioning or referencing the
**	derived work.
**
**	Xerox Corporation makes no representations concerning either the
**	merchantability of this software or the suitability of this
**	software for any particular purpose.  It is provided "as is"
**	without express or implied warranty of any kind.
**
**	These notices must be retained in any copies of any part of this
**	software.
**
**  Based on the reference implementation (no algorithm changes) of
**  version 2.0, July 31, 1989.  Implementor:  Ralph C. Merkle.
**  This edition is by Rich $alz, <rsalz@bbn.com>.
*/
#include <stdio.h>
#ifdef	lint
#ifndef	NDEBUG
#define NDEBUG
#endif	/* NDEBUG */
#endif	/* lint */
#include <assert.h>
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: hash512.c,v 1.1 90/03/22 12:58:26 rsalz Exp $";
#endif	/* RCSID */


/* Note that the 32-bit word specified by RotatedSnefruSBoxes[i][j][k]
 * is rotated right by i*8 bits. */
static SBOX	RotatedSnefruSBoxes[4][SBOXCOUNT];


SetupHash512()
{
    register int	index;
    register int	rotation;
    register int	i;

    for (index = 0; index < SBOXCOUNT; index++)
	for (rotation = 0; rotation < 4; rotation++)
	    for (i = 0; i < 256; i++)
		RotatedSnefruSBoxes[rotation][index][i] =
		    (SnefruSBoxes[index][i] >> (rotation * 8)) |
		    (SnefruSBoxes[index][i] << (32 - rotation * 8));
}


/*
**  This routine is a specialized version of HashN.  It is optimized for
**  speed, and assumes that the input is always 16 words long:  it hashes
**  512 bits, hence its name.  You need not try to figure out this routine
**  unless you wish to figure out a fast implementation of Snefru.
*/
Hash512(output, input, level, OutputBlockSize)
    WORD32		output[OUTPUTBLOCKSIZE];
    WORD32		input[];
    int			level;
    int			OutputBlockSize;
{
    register WORD32	block00, block01, block02, block03;
    register WORD32	block04, block05, block06, block07;
    register WORD32	block08, block09, block10, block11;
    register WORD32	block12, block13, block14, block15;
    WORD32		SBoxEntry;
    WORD32		*SBox0;
    WORD32		*SBox1;
    int			index;

    assert(OutputBlockSize == 4 || OutputBlockSize == 8);

    /* Initialize the block to be encrypted from the input.  In theory
     * block<i> should be kept in register.  Not all compilers can do
     * this, even when there are enough registers -- this will degrade
     * performance significantly. */
    block00 = input[0];
    block01 = input[1];
    block02 = input[2];
    block03 = input[3];
    block04 = input[4];
    block05 = input[5];
    block06 = input[6];
    block07 = input[7];
    block08 = input[8];
    block09 = input[9];
    block10 = input[10];
    block11 = input[11];
    block12 = input[12];
    block13 = input[13];
    block14 = input[14];
    block15 = input[15];

    for (index = 0; index < 2 * level; index += 2) {
	/* set up the base address for the two S-box pointers.  */
	SBox0 = RotatedSnefruSBoxes[0][index];
	SBox1 = SBox0 + 256;

	/* In the following unrolled code, the basic 'assembly language'
	 * block that is repeated is:
	 *	1	temp1 = shift(block<i>, shiftConstant)
	 *	2	temp2 = temp1 & 0x3FC
	 *	3	temp3 = S-box<0 or 1> + temp2
	 *	4	temp4 = *temp3
	 *	5	block<i-1> ^= temp4
	 *	6	block<i+1> ^= temp4
	 * STEP 1:  Simply shift the i'th 32-bit block to bring the 8-bit
	 * byte into the right position.  Note that we will also build-in a
	 * left-shift by two bits at this stage, to eliminate the left shift
	 * required later because we are indexing into an array of four-byte
	 * table entries.
	 * 
	 * STEP 1:  Mask off the desired eight bits.  Note that 0x3FC is
	 * simply 0xFF << 2.
	 * 
	 * STEP 1:  Use a normal integer add to compute the actual address
	 * of the S-box entry.  Note that one of two pointers is used, as
	 * appropriate.  Temp3 then holds the actual byte address of the
	 * desired S-box entry.
	 * 
	 * STEP 1:  Load the four-byte S-box entry.
	 * 
	 * STEPS 5 and 6:  XOR the loaded S-box entry with both the
	 * previous and the next 32-bit entries in the 'block' array.
	 * 
	 * Typical optimizing comilers might fail to put all the block<i>
	 * variables into registers. This can result in significant
	 * performance degradation. Also, most compilers will use a separate
	 * left-shift-by-2 after masking off the needed 8 bits, but the
	 * performance degradation caused by this oversight should be modest.
	 */
	SBoxEntry = SBox0[block00 & 0xFF];
	block01 ^= SBoxEntry;
	block15 ^= SBoxEntry;
	SBoxEntry = SBox0[block01 & 0xFF];
	block02 ^= SBoxEntry;
	block00 ^= SBoxEntry;
	SBoxEntry = SBox1[block02 & 0xFF];
	block03 ^= SBoxEntry;
	block01 ^= SBoxEntry;
	SBoxEntry = SBox1[block03 & 0xFF];
	block04 ^= SBoxEntry;
	block02 ^= SBoxEntry;
	SBoxEntry = SBox0[block04 & 0xFF];
	block05 ^= SBoxEntry;
	block03 ^= SBoxEntry;
	SBoxEntry = SBox0[block05 & 0xFF];
	block06 ^= SBoxEntry;
	block04 ^= SBoxEntry;
	SBoxEntry = SBox1[block06 & 0xFF];
	block07 ^= SBoxEntry;
	block05 ^= SBoxEntry;
	SBoxEntry = SBox1[block07 & 0xFF];
	block08 ^= SBoxEntry;
	block06 ^= SBoxEntry;
	SBoxEntry = SBox0[block08 & 0xFF];
	block09 ^= SBoxEntry;
	block07 ^= SBoxEntry;
	SBoxEntry = SBox0[block09 & 0xFF];
	block10 ^= SBoxEntry;
	block08 ^= SBoxEntry;
	SBoxEntry = SBox1[block10 & 0xFF];
	block11 ^= SBoxEntry;
	block09 ^= SBoxEntry;
	SBoxEntry = SBox1[block11 & 0xFF];
	block12 ^= SBoxEntry;
	block10 ^= SBoxEntry;
	SBoxEntry = SBox0[block12 & 0xFF];
	block13 ^= SBoxEntry;
	block11 ^= SBoxEntry;
	SBoxEntry = SBox0[block13 & 0xFF];
	block14 ^= SBoxEntry;
	block12 ^= SBoxEntry;
	SBoxEntry = SBox1[block14 & 0xFF];
	block15 ^= SBoxEntry;
	block13 ^= SBoxEntry;
	SBoxEntry = SBox1[block15 & 0xFF];
	block00 ^= SBoxEntry;
	block14 ^= SBoxEntry;

	/* SBox0 = RotatedSnefruSBoxes[2][index];  */
	SBox0 += 2 * SBOXCOUNT * 256;
	SBox1 = SBox0 + 256;

	SBoxEntry = SBox0[(block00 >> 16) & 0xFF];
	block01 ^= SBoxEntry;
	block15 ^= SBoxEntry;
	SBoxEntry = SBox0[(block01 >> 16) & 0xFF];
	block02 ^= SBoxEntry;
	block00 ^= SBoxEntry;
	SBoxEntry = SBox1[(block02 >> 16) & 0xFF];
	block03 ^= SBoxEntry;
	block01 ^= SBoxEntry;
	SBoxEntry = SBox1[(block03 >> 16) & 0xFF];
	block04 ^= SBoxEntry;
	block02 ^= SBoxEntry;
	SBoxEntry = SBox0[(block04 >> 16) & 0xFF];
	block05 ^= SBoxEntry;
	block03 ^= SBoxEntry;
	SBoxEntry = SBox0[(block05 >> 16) & 0xFF];
	block06 ^= SBoxEntry;
	block04 ^= SBoxEntry;
	SBoxEntry = SBox1[(block06 >> 16) & 0xFF];
	block07 ^= SBoxEntry;
	block05 ^= SBoxEntry;
	SBoxEntry = SBox1[(block07 >> 16) & 0xFF];
	block08 ^= SBoxEntry;
	block06 ^= SBoxEntry;
	SBoxEntry = SBox0[(block08 >> 16) & 0xFF];
	block09 ^= SBoxEntry;
	block07 ^= SBoxEntry;
	SBoxEntry = SBox0[(block09 >> 16) & 0xFF];
	block10 ^= SBoxEntry;
	block08 ^= SBoxEntry;
	SBoxEntry = SBox1[(block10 >> 16) & 0xFF];
	block11 ^= SBoxEntry;
	block09 ^= SBoxEntry;
	SBoxEntry = SBox1[(block11 >> 16) & 0xFF];
	block12 ^= SBoxEntry;
	block10 ^= SBoxEntry;
	SBoxEntry = SBox0[(block12 >> 16) & 0xFF];
	block13 ^= SBoxEntry;
	block11 ^= SBoxEntry;
	SBoxEntry = SBox0[(block13 >> 16) & 0xFF];
	block14 ^= SBoxEntry;
	block12 ^= SBoxEntry;
	SBoxEntry = SBox1[(block14 >> 16) & 0xFF];
	block15 ^= SBoxEntry;
	block13 ^= SBoxEntry;
	SBoxEntry = SBox1[(block15 >> 16) & 0xFF];
	block00 ^= SBoxEntry;
	block14 ^= SBoxEntry;


	/* SBox0 = RotatedSnefruSBoxes[1][index];  */
	SBox0 -= SBOXCOUNT * 256;
	SBox1 = SBox0 + 256;

	SBoxEntry = SBox0[block00 >> 24];
	block01 ^= SBoxEntry;
	block15 ^= SBoxEntry;
	SBoxEntry = SBox0[block01 >> 24];
	block02 ^= SBoxEntry;
	block00 ^= SBoxEntry;
	SBoxEntry = SBox1[block02 >> 24];
	block03 ^= SBoxEntry;
	block01 ^= SBoxEntry;
	SBoxEntry = SBox1[block03 >> 24];
	block04 ^= SBoxEntry;
	block02 ^= SBoxEntry;
	SBoxEntry = SBox0[block04 >> 24];
	block05 ^= SBoxEntry;
	block03 ^= SBoxEntry;
	SBoxEntry = SBox0[block05 >> 24];
	block06 ^= SBoxEntry;
	block04 ^= SBoxEntry;
	SBoxEntry = SBox1[block06 >> 24];
	block07 ^= SBoxEntry;
	block05 ^= SBoxEntry;
	SBoxEntry = SBox1[block07 >> 24];
	block08 ^= SBoxEntry;
	block06 ^= SBoxEntry;
	SBoxEntry = SBox0[block08 >> 24];
	block09 ^= SBoxEntry;
	block07 ^= SBoxEntry;
	SBoxEntry = SBox0[block09 >> 24];
	block10 ^= SBoxEntry;
	block08 ^= SBoxEntry;
	SBoxEntry = SBox1[block10 >> 24];
	block11 ^= SBoxEntry;
	block09 ^= SBoxEntry;
	SBoxEntry = SBox1[block11 >> 24];
	block12 ^= SBoxEntry;
	block10 ^= SBoxEntry;
	SBoxEntry = SBox0[block12 >> 24];
	block13 ^= SBoxEntry;
	block11 ^= SBoxEntry;
	SBoxEntry = SBox0[block13 >> 24];
	block14 ^= SBoxEntry;
	block12 ^= SBoxEntry;
	SBoxEntry = SBox1[block14 >> 24];
	block15 ^= SBoxEntry;
	block13 ^= SBoxEntry;
	SBoxEntry = SBox1[block15 >> 24];
	block00 ^= SBoxEntry;
	block14 ^= SBoxEntry;


	/* SBox0 = RotatedSnefruSBoxes[3][index];  */
	SBox0 += 2 * SBOXCOUNT * 256;
	SBox1 = SBox0 + 256;

	SBoxEntry = SBox0[(block00 >> 8) & 0xFF];
	block01 ^= SBoxEntry;
	block15 ^= SBoxEntry;
	SBoxEntry = SBox0[(block01 >> 8) & 0xFF];
	block02 ^= SBoxEntry;
	block00 ^= SBoxEntry;
	SBoxEntry = SBox1[(block02 >> 8) & 0xFF];
	block03 ^= SBoxEntry;
	block01 ^= SBoxEntry;
	SBoxEntry = SBox1[(block03 >> 8) & 0xFF];
	block04 ^= SBoxEntry;
	block02 ^= SBoxEntry;
	SBoxEntry = SBox0[(block04 >> 8) & 0xFF];
	block05 ^= SBoxEntry;
	block03 ^= SBoxEntry;
	SBoxEntry = SBox0[(block05 >> 8) & 0xFF];
	block06 ^= SBoxEntry;
	block04 ^= SBoxEntry;
	SBoxEntry = SBox1[(block06 >> 8) & 0xFF];
	block07 ^= SBoxEntry;
	block05 ^= SBoxEntry;
	SBoxEntry = SBox1[(block07 >> 8) & 0xFF];
	block08 ^= SBoxEntry;
	block06 ^= SBoxEntry;
	SBoxEntry = SBox0[(block08 >> 8) & 0xFF];
	block09 ^= SBoxEntry;
	block07 ^= SBoxEntry;
	SBoxEntry = SBox0[(block09 >> 8) & 0xFF];
	block10 ^= SBoxEntry;
	block08 ^= SBoxEntry;
	SBoxEntry = SBox1[(block10 >> 8) & 0xFF];
	block11 ^= SBoxEntry;
	block09 ^= SBoxEntry;
	SBoxEntry = SBox1[(block11 >> 8) & 0xFF];
	block12 ^= SBoxEntry;
	block10 ^= SBoxEntry;
	SBoxEntry = SBox0[(block12 >> 8) & 0xFF];
	block13 ^= SBoxEntry;
	block11 ^= SBoxEntry;
	SBoxEntry = SBox0[(block13 >> 8) & 0xFF];
	block14 ^= SBoxEntry;
	block12 ^= SBoxEntry;
	SBoxEntry = SBox1[(block14 >> 8) & 0xFF];
	block15 ^= SBoxEntry;
	block13 ^= SBoxEntry;
	SBoxEntry = SBox1[(block15 >> 8) & 0xFF];
	block00 ^= SBoxEntry;
	block14 ^= SBoxEntry;
    }

    output[0] = input[0] ^ block15;
    output[1] = input[1] ^ block14;
    output[2] = input[2] ^ block13;
    output[3] = input[3] ^ block12;

    /* Generate an extra 128 bits if the output is 256 bits. */
    if (OutputBlockSize == 8) {
	output[4] = input[4] ^ block11;
	output[5] = input[5] ^ block10;
	output[6] = input[6] ^ block09;
	output[7] = input[7] ^ block08;
    }
}
