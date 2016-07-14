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
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: hashn.c,v 1.1 90/03/22 12:58:33 rsalz Exp $";
#endif	/* RCSID */


static int	ShiftTable[4] = { 16, 8, 16, 24 };

/*
**  Compute the hash.
**  Note that we are computing level * wordCount * 4 rounds.
*/
HashN(output, wordCount, input, level, OutputBlockSize)
    WORD32	output[OUTPUTBLOCKSIZE];
    int		wordCount;
    WORD32	input[];
    int		level;
    int		OutputBlockSize;
{
    WORD32	mask;
    WORD32	block[WORDCOUNT];	/* array of data being hashed  */
    WORD32	SBoxEntry;
    int		shift;
    int		i;
    int		index;
    int		next;
    int		last;
    int		ByteInWord;

    /* wordCount is a power of two. */
    mask = wordCount - 1;

#if	0
    /* Test for various error conditions and logic problems.  */
    if (level * 2 > SBOXCOUNT)
	abort("Too few S-boxes");
    if (wordCount > WORDCOUNT)
	abort("Logic error, wordCount > WORDCOUNT");
    if (wordCount != 16)
	abort("Security warning, input size not equal to 512 bits");
    /* Spectacularly insecure for small blocks, so... */
    if (wordCount < 4)
	abort("wordCount too small");
    if ((wordCount & mask) != 0)
	abort("Logic error, wordCount not a power of 2");
    if (OutputBlockSize > wordCount)
	abort("Logic error, OutputBlockSize is too big");
    if (OutputBlockSize != 4 && OutputBlockSize != 8)
	abort("Output size neither 128 nor 256 bits");
#endif	/* 0 */

    /* Initialize the block to be encrypted from the input  */
    for (i = 0; i < wordCount; i++)
	block[i] = input[i];

    for (index = 0; index < level; index++) {
	for (ByteInWord = 0; ByteInWord < 4; ByteInWord++) {
	    for (i = 0; i < wordCount; i++) {
		next = (i + 1) & mask;
		last = (i + mask) & mask; /* last = (i-1) MOD wordCount */
		SBoxEntry =
		    SnefruSBoxes[2 * index + ((i / 2) & 1)][block[i] & 0xFF];
		block[next] ^= SBoxEntry;
		block[last] ^= SBoxEntry;
	    }
	    /* Rotate right all 32-bit words in the entire block at once.  */
	    for (shift = ShiftTable[ByteInWord], i = 0; i < wordCount; i++)
		block[i] = (block[i] >> shift) | (block[i] << (32 - shift));
	}
    }

    for (i = 0; i < OutputBlockSize; i++)
	output[i] = input[i] ^ block[mask - i];
}
