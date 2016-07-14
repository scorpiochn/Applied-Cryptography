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
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: snefru.c,v 1.1 90/03/22 13:00:13 rsalz Exp $";
#endif	/* RCSID */

#define SIZEOF(s)	(sizeof s / sizeof s[0])


/*
**  Get the byte order.  If the four bytes 1 2 3 4 are stored as 1234,
**  then we can do punning on the byte/word buffers, and just quickly
**  copy things.  If not, we have to shuffle between buffers.
*/
#if	defined(sun) && !defined(i386)
    /* All Sun's except the 386i. */
#define BYTESHILO
#endif	/* .. */

#if	defined(mc300) || defined(mc500) || defined(u3b2)
    /* The Masscomp MC5500 and MC5500-PEP and the ATT3b2. */
#define BYTESHILO
#endif	/* .. */

extern char	*optarg;
extern int	optind;


/*
**  Convert a byte array to an array of WORD32.  Primarily intended to
**  eliminate the byte-ordering problem (e.g., a Vax orders the bytes in a
**  character array differently than a Sun does).  Using this will slow the
**  hash function!  This is only needed on Vax-like machines, and can be
**  removed for Sun3-like byteorders.
*/
static void
BytesToWords(Cbuffer, Wbuffer)
    register char	*Cbuffer;
    register WORD32	*Wbuffer;
{
#ifdef	BYTESHILO
    register WORD32	*pun;
    register int	i;

    for (pun = (WORD32 *)Cbuffer, i = BUFFERSIZEINWORDS; --i >= 0; )
	*Wbuffer++ = *pun++;
#else	/* BYTESHILO */
    register int	 i;
    register WORD32	 t0;
    register WORD32	 t1;
    register WORD32	 t2;
    register WORD32	 t3;

    for (i = BUFFERSIZEINWORDS; --i >= 0; Cbuffer += 4) {
	t0 = Cbuffer[0] & 0xFF;
	t1 = Cbuffer[1] & 0xFF;
	t2 = Cbuffer[2] & 0xFF;
	t3 = Cbuffer[3] & 0xFF;
	*Wbuffer++ = (t0 << 24) | (t1 << 16) | (t2 << 8) | t3;
    }
#endif	/* BYTESHILO */
}


static void
Usage()
{
    (void)fprintf(stderr, "Usage: snefru [-l#] [-o#] [inputfile]\n");
    (void)fprintf(stderr, "Where %s and %s.\n",
	     "-l takes 2, 3, or 4", "-o takes 4 or 8");
    exit(1);
}


/*
**  Read the input, hashes it, and prints the result.  Much of the logic
**  in the main program is taken up with the trivia of buffer management,
**  error checking, command-line parameter checking, self-tests, and the
**  like. The actual use of the hash function occupies a modest portion of
**  the overall program.
**
**  The basic idea is simple.  As an example, if H is the hash function
**  that produces either 128-bit (or 256-bit) outputs, and if we pick an
**  input string that is 3 "chunks" long then we are computing:
**
**  output = H( H( H( H(0 || chunk[0]) || chunk[1]) || chunk[2]) || bit-length)
**
**  "||" is the concatenation operator, and is used to concatenate the
**  output field of the preceding computation of H with the next "chunk"
**  of bits from the input.
**
**  "bit-length" is a "chunk" sized field into which has been put the
**  length of the input, in bits, right justified.  Note that the size of
**  a "chunk" is just the input size minus the output size.
**
**  "0" is a vector of 0 bits of the same size (in bits) as the output of
**  H (i.e., either 128 or 256 bits).
**
**  "chunk" is an array which holds the input string.  The final element of
**  the array is left justified and zero-filled on the right.
**
*/
main(ac, av)
    int		ac;
    char	*av[];
{
    WORD32	BitCount[2];
    WORD32	hashArray[INPUTBLOCKSIZE];
    WORD32	hash[OUTPUTBLOCKSIZE];
    WORD32	Wbuffer[BUFFERSIZEINWORDS];
    char	Cbuffer[BUFFERSIZE];
    int		OutputBlockSize;
    int		ChunkSize;
    int		ByteCount;
    int		Index;
    int		GotEOF;
    int		i;
    int		level;

    /* Set up defaults.  Four 32-bit word (128 bits) with two iterations. */
    OutputBlockSize = 4;
    ChunkSize = INPUTBLOCKSIZE - 4;
    level = 2;

    /* Parse JCL. */
    while ((i = getopt(ac, av, "l:o:")) != EOF)
	switch (i) {
	default:
	    Usage();
	    /* NOTREACHED */
	case 'l':
	    level = atoi(optarg);
	    if (level != 2 && level != 3 && level != 4)
		Usage();
	    break;
	case 'o':
	    OutputBlockSize = atoi(optarg);
	    if (OutputBlockSize != 4 && OutputBlockSize != 8)
		Usage();
	    ChunkSize = INPUTBLOCKSIZE - OutputBlockSize;
	    if ((BUFFERSIZEINWORDS % ChunkSize) != 0) {
		(void)fprintf(stderr, "Buffer size is fouled up\n");
		exit(1);
	    }
	    break;
	}

    /* Get input. */
    ac -= optind;
    av += optind;
    switch (ac) {
    default:
	Usage();
	/* NOTREACHED */
    case 0:
	break;
    case 1:
	if (freopen(av[0], "r", stdin) == NULL) {
	    perror("No input");
	    (void)fprintf(stderr, "Can't open \"%s\" for reading.\n", av[0]);
	    Usage();
	}
	break;
    }

    /* Set up for the fast hash routine  */
    SetupHash512();

    BitCount[0] = 0;
    BitCount[1] = 0;

    /* Get some input. */
    ByteCount = fread(Cbuffer, sizeof Cbuffer[0], SIZEOF(Cbuffer), stdin);
    if (ByteCount < 0) {
	perror("First read failed");
	exit(1);
    }
    GotEOF = ByteCount != SIZEOF(Cbuffer);

    /* Increment bit-count; bump upper 32 bits when lower 32 wraps. */
    BitCount[1] += ByteCount * 8;
    if (BitCount[1] < ByteCount * 8)
	BitCount[0]++;

    /* Zero out rest of buffer, convert to words, set readpoint. */
    for (i = ByteCount; i < SIZEOF(Cbuffer); i++)
	Cbuffer[i] = 0;
    BytesToWords(Cbuffer, Wbuffer);

    for (i = 0; i < SIZEOF(hashArray); i++)
	hashArray[i] = 0;

    /* Hash each chunk in the input (either 48 byte chunks or 32 byte chunks)
     * and keep the result in hashArray.  Note that the first 16 (32)
     * bytes of hashArray holds the output of the previous hash computation. */
    Index = 0;
    while (ByteCount > 0) {
	if (Index + ChunkSize > SIZEOF(Cbuffer)) {
	    (void)fprintf(stderr, "Can't happen, buffer overrun.\n");
	    exit(1);
	}

	/* Get next chunk and hash it in. */
	for (i = 0; i < ChunkSize; i++)
	    hashArray[OutputBlockSize + i] = Wbuffer[Index + i];
	Hash512(hashArray, hashArray, level, OutputBlockSize);

	/* Move to next chunk. */
	Index += ChunkSize;
	ByteCount -= ChunkSize * 4;

	/* Out of data -- read some more */
	if (ByteCount <= 0) {
	    if (GotEOF == 1)
		ByteCount = 0;
	    else {
		if (ByteCount != 0) {
		    (void)fprintf(stderr, "Can't happen, error near EOF.\n");
		    exit(1);
		}
		ByteCount = fread(Cbuffer, sizeof Cbuffer[0],
				SIZEOF(Cbuffer), stdin);
		if (ByteCount < 0) {
		    perror("Read failed");
		    exit(1);
		}
		if (ByteCount != SIZEOF(Cbuffer))
		    GotEOF = 1;
	    }

	    /* Increment bit-count; bump upper 32 bits when lower 32 wraps. */
	    BitCount[1] += ByteCount * 8;
	    if (BitCount[1] < ByteCount * 8)
		BitCount[0] += 1;

	    /* Zero out rest of buffer, convert to words, set readpoint. */
	    for (i = ByteCount; i < SIZEOF(Cbuffer); i++)
		Cbuffer[i] = 0;
	    BytesToWords(Cbuffer, Wbuffer);
	    Index = 0;
	}
    }


    /* Zero out the remainder of hashArray.  */
    for (i = 0; i < ChunkSize; i++)
	hashArray[OutputBlockSize + i] = 0;

    /* Put the 64-bit bit-count into the final 64-bits of the block about to
     * be hashed */
    hashArray[INPUTBLOCKSIZE - 2] = BitCount[0];
    hashArray[INPUTBLOCKSIZE - 1] = BitCount[1];

    /* Final hash down. */
    Hash512(hash, hashArray, level, OutputBlockSize);

    /* 'hash' now holds the hashed result, which is printed on stdout. */
    for (i = 0; i < OutputBlockSize; i++)
	(void)printf("%s%08x", i ? " " : "", hash[i]);
    (void)printf("\n");
    exit(0);
}
