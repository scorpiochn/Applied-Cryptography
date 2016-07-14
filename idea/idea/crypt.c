/******************************************************************************/
/*                                                                            */
/*               C R Y P T O G R A P H I C - A L G O R I T H M S              */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ethz.ch)                   */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Last Edition: 13 May 1992                                                  */
/* System:       AMIGA, SAS (Lattice) C-Compiler, AmigaDOS 2.0                */
/******************************************************************************/
#include "crypt.h"

#define mulMod        0x10001 /* 2**16 + 1                                    */
#define addMod        0x10000 /* 2**16                                        */
#define ones           0xFFFF /* 2**16 - 1                                    */

#define nofKeyPerRound      6 /* number of used keys per round                */
#define nofRound            8 /* number of rounds                             */

/******************************************************************************/
/*                          A L G O R I T H M                                 */
/******************************************************************************/
/* multiplication                                                             */

u_int32 Mul(u_int32 a, u_int32 b)

{ int32 p;
  u_int32 q;
  
  if (a == 0)
    p = mulMod - b; 
  else if (b == 0) 
    p = mulMod - a;
  else {
     q = a * b;
     p = (q & ones) - (q >> 16);
     if (p <= 0)
       p += mulMod;
  }
  return (u_int32)(p & ones);
} /* Mul */

/******************************************************************************/
/* compute inverse of 'x' by Euclidean gcd algorithm                          */

u_int16 MulInv(u_int16 x)

{ int32 n1, n2, q, r, b1, b2, t;

  if (x == 0)
    return 0;
  n1 = mulMod;
  n2 = (int32)x;
  b2 = 1; b1 = 0;
  do {
    r = (n1 % n2);
    q = (n1 - r) / n2;
    if (r == 0) {
      if (b2 < 0)
        b2 = mulMod + b2;
    }
    else {
      n1 = n2;
      n2 = r;
      t = b2;
      b2 = b1 - q * b2;
      b1 = t;
    }
  } while (r != 0);
  return (u_int16)b2;
} /* MulInv */

/******************************************************************************/
/* encryption and decryption algorithm IDEA                                   */

void  Idea(u_int16 *dataIn, u_int16 *dataOut, u_int16 *key)

{ register u_int32 round, x0, x1, x2, x3, t0, t1;

  x0 = (u_int32)*(dataIn++);
  x1 = (u_int32)*(dataIn++);
  x2 = (u_int32)*(dataIn++);
  x3 = (u_int32)*(dataIn);
  for (round = nofRound; round > 0; round--) {
    x0 = Mul(x0, (u_int32)*(key++));
    x1 = (x1 + (u_int32)*(key++)) & ones;
    x2 = (x2 + (u_int32)*(key++)) & ones;
    x3 = Mul(x3, (u_int32)*(key++));
    t0 = Mul((u_int32)*(key++), x0 ^ x2);
    t1 = Mul((u_int32)*(key++), (t0 + (x1 ^ x3)) & ones);
    t0 = (t0 + t1) & ones;
    x0 ^= t1;
    x3 ^= t0;
    t0 ^= x1;
    x1 = x2 ^ t1;
    x2 = t0;
  }
  *(dataOut++) = (u_int16)(Mul(x0, (u_int32)*(key++)));
  *(dataOut++) = (u_int16)((x2 + (u_int32)*(key++)) & ones);
  *(dataOut++) = (u_int16)((x1 + (u_int32)*(key++)) & ones);
  *(dataOut) = (u_int16)(Mul(x3, (u_int32)*key));
} /* Idea */
 
/******************************************************************************/
/* invert decryption / encrytion key for IDEA                                 */

void InvertIdeaKey(u_int16 *key, u_int16 *invKey)

{ register int  i;
  key_t(dk);

  dk[nofKeyPerRound * nofRound + 0] = MulInv(*(key++));
  dk[nofKeyPerRound * nofRound + 1] = (addMod - *(key++)) & ones;
  dk[nofKeyPerRound * nofRound + 2] = (addMod - *(key++)) & ones;
  dk[nofKeyPerRound * nofRound + 3] = MulInv(*(key++));
  for (i = nofKeyPerRound * (nofRound - 1); i >= 0; i -= nofKeyPerRound) {
    dk[i + 4] = *(key++);
    dk[i + 5] = *(key++);
    dk[i + 0] = MulInv(*(key++));
    if (i > 0) {
      dk[i + 2] = (addMod - *(key++)) & ones;
      dk[i + 1] = (addMod - *(key++)) & ones;
    }
    else {
      dk[i + 1] = (addMod - *(key++)) & ones;
      dk[i + 2] = (addMod - *(key++)) & ones;
    }
    dk[i + 3] = MulInv(*(key++));
  }
  for (i = 0; i < keyLen; i++)
    invKey[i] = dk[i]; 
} /* InvertIdeaKey */


/******************************************************************************/
/* expand user key of 128 bits to full key of 832 bits                        */

void ExpandUserKey(u_int16 *userKey, u_int16 *key)

{ register int i;

  for (i = 0; i < userKeyLen; i++)
    key[i] = userKey[i];
  /* shifts */
  for (i = userKeyLen; i < keyLen; i++) {
    if ((i + 2) % 8 == 0)                    /* for key[14],key[22],..  */
      key[i] = ((key[i - 7] & 127) << 9) ^ (key[i - 14] >> 7); 
    else if ((i + 1) % 8 == 0)               /* for key[15],key[23],..  */
      key[i] = ((key[i - 15] & 127) << 9) ^ (key[i - 14] >> 7); 
    else
      key[i] = ((key[i - 7] & 127) << 9 ) ^ (key[i - 6] >> 7);
   }
} /* ExpandUserKey */
