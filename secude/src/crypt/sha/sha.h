/* NIST proposed Secure Hash Standard.
 
   Written 2 September 1992, Peter C. Gutmann.
   This implementation placed in the public domain.
 
   Modified 1 June 1993, Colin Plumb.
   These modifications placed in the public domain.
 
   Comments to pgut1@cs.aukuni.ac.nz */
 
/* Useful defines/typedefs */
 
typedef unsigned char   BYTE;
 
/* Since 64-bit machines are the wave of the future, we may as well
   support them directly. */

#define FORCE32
 
#ifdef FORCE32
 
#undef HAVE64
 
#else   /* !FORCE32 */
 
#if __alpha     /* Or other machines? */
#define HAVE64 1
typedef unsigned long WORD64;
#endif
 
#if __GNUC__
#define HAVE64 1
typedef unsigned long long WORD64;
#endif
 
#endif  /* !FORCE32 */
 
#ifdef HAVE64
typedef unsigned int WORD32;
#else
typedef unsigned long WORD32;
#endif
 
/* The SHS block size and message digest sizes, in bytes */
 
#define SHS_BLOCKSIZE   64
#define SHS_DIGESTSIZE  20
 
/* The structure for storing SHS info
   data[] is placed first in case offsets of 0 are faster
   for some reason; it's the most often accessed field. */
 
typedef struct {
        WORD32 data[ 16 ];              /* SHS data buffer */
        WORD32 digest[ 5 ];             /* Message digest */
#ifdef HAVE64
        WORD64 count;
#else
        WORD32 countHi, countLo;        /* 64-bit bit count */
#endif
} SHS_INFO;
