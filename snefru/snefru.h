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
**  $Header: snefru.h,v 1.1 90/03/22 13:00:52 rsalz Exp $
*/
#include "patchlevel.h"

#if	!defined(lint) && !defined(SABER)
#define RCSID
#endif	/* .. */

    /* Size in 32-bit words of an input block to the hash routine. */
#define INPUTBLOCKSIZE		  16
    /* Size in 32-bit words of largest output block from the hash routine. */
#define OUTPUTBLOCKSIZE		   8
    /* This MUST be 3 * 2**n, where n > 5.  */
#define BUFFERSIZE		3072
    /* Buffer size is normally in bytes, but sometimes we need it in words. */
#define BUFFERSIZEINWORDS	(BUFFERSIZE / 4)
    /* Number of S boxes. */
#define SBOXCOUNT		   8
    /* Maximum valid value for wordCount. */
#define WORDCOUNT		  16

    /* This MUST be 32 bits. */
typedef unsigned long int	 WORD32;
    /* An S-box. */
typedef WORD32			 SBOX[256];

    /* The standard S boxes are defined in another file. */
extern SBOX	 SnefruSBoxes[SBOXCOUNT];

#define CHECKSUMHDR	"X-Checksum-Snefru"
#define HDRFIRSTCHAR	'X'
#define TRUE		1
#define FALSE		0
#define HDRTEXTSIZE	(8 + 1 + 8 + 1 + 8 + 1 + 8)
