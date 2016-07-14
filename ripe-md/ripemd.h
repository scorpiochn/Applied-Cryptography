/********************************************************************/
/*  file: ripemd.h                                                  */
/*                                                                  */
/*  description: header file for RIPEMD, a sample C-implementation  */
/*           This function is derived from the MD4 Message Digest   */
/*           Algorithm from RSA Data Security, Inc.                 */
/*           This implementation was developed by RIPE.             */
/*                                                                  */
/*  copyright (C)                                                   */
/*           Centre for Mathematics and Computer Science, Amsterdam */
/*           Siemens AG                                             */
/*           Philips Crypto BV                                      */
/*           PTT Research, the Netherlands                          */
/*           Katholieke Universiteit Leuven                         */
/*           Aarhus University                                      */
/*  1992, All Rights Reserved                                       */
/*                                                                  */
/*  date:    05/06/92                                               */
/*  version: 1.0                                                    */
/*                                                                  */
/********************************************************************/

#ifndef  RIPEMDH           /* make sure this file is read only once */
#define  RIPEMDH

/********************************************************************/

/* typedef 8, 16 and 32 bit types, resp.  */
/* adapt these, if necessary, 
   for your operating system and compiler */
typedef    unsigned long        dword;
typedef    unsigned short       word;
typedef    unsigned char        byte;


/********************************************************************/

/* macro definitions */

/* collect four bytes into one word: */
#define BYTES_TO_WORD(strptr)                    \
            (((dword) *((strptr)+3) << 24) | \
             ((dword) *((strptr)+2) << 16) | \
             ((dword) *((strptr)+1) <<  8) | \
             ((dword) *(strptr)))

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))

/* the three basic functions F(), G() and H() */
#define F(x, y, z)        (((x) & (y)) | ((~x) & (z))) 
#define G(x, y, z)        (((x) & (y)) | ((x) & (z)) | ((y) & (z))) 
#define H(x, y, z)        ((x) ^ (y) ^ (z)) 
  
/* the six basic operations FF() through HHH() */
#define FF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
#define GG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + (dword)0x5a827999UL;\
      (a) = ROL((a), (s));\
   }
#define HH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + (dword)0x6ed9eba1UL;\
      (a) = ROL((a), (s));\
   }
#define FFF(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x) + (dword)0x50a28be6UL;\
      (a) = ROL((a), (s));\
   }
#define GGG(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }
#define HHH(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + (dword)0x5c4dd124UL;\
      (a) = ROL((a), (s));\
   }

/********************************************************************/

/* function prototypes */

void MDinit(dword *MDbuf);
/*
 *  initializes MDbuffer to "magic constants"
 */

void compress(dword *MDbuf, dword *X);
/*
 *  the compression function.
 *  transforms MDbuf using message bytes X[0] through X[15]
 */

void MDfinish(dword *MDbuf, byte *strptr, dword lswlen, dword mswlen);
/*
 *  puts bytes from strptr into X and pad out; appends length 
 *  and finally, compresses the last block(s)
 *  note: length in bits == 8 * (lswlen + 2^32 mswlen).
 *  note: there are (lswlen mod 64) bytes left in strptr.
 */

#endif  /* RIPEMDH */

/*********************** end of file ripemd.h ***********************/

