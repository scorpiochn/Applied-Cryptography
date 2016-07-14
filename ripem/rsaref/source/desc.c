/* DESC.C - Data Encryption Standard routines for RSAREF
 *
 * 920319 rwo : retrofitted with "Karn/Hoey/Outerbridge" DEA (KHODES)
 * 920725 rwo : integrate IP and IP-1 into DesFn()
 */

#include "global.h"
#include "rsaref.h"
#include "des.h"

static void Unpack PROTO_LIST ((unsigned char *, unsigned long *));
static void Pack PROTO_LIST ((unsigned long *, unsigned char *));
static void Cookey PROTO_LIST ((unsigned long *, unsigned long *));
static void Deskey PROTO_LIST ((unsigned long *, unsigned char *));
static void DesFn PROTO_LIST ((unsigned long *, unsigned long *));

static unsigned short bytebit[8] = {
        0200, 0100, 040, 020, 010, 04, 02, 01 };

static unsigned long bigbyte[24] = {
        0x800000L,      0x400000L,      0x200000L,      0x100000L,
        0x80000L,       0x40000L,       0x20000L,       0x10000L,
        0x8000L,        0x4000L,        0x2000L,        0x1000L,
        0x800L,         0x400L,         0x200L,         0x100L,
        0x80L,          0x40L,          0x20L,          0x10L,
        0x8L,           0x4L,           0x2L,           0x1L    };

static unsigned char pc1[56] = {
        56, 48, 40, 32, 24, 16,  8,      0, 57, 49, 41, 33, 25, 17,
         9,  1, 58, 50, 42, 34, 26,     18, 10,  2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,      6, 61, 53, 45, 37, 29, 21,
        13,  5, 60, 52, 44, 36, 28,     20, 12,  4, 27, 19, 11,  3 };

static unsigned char totrot[16] = {
        1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };

static unsigned char pc2[48] = {
        13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };

static void Deskey (cooked, key)
unsigned long cooked[64];
unsigned char key[8];
{
        int i, j, l, m, n;
        unsigned char pc1m[56], pcr[56];
        unsigned long kn[32];

        for ( j = 0; j < 56; j++ ) {
                l = pc1[j];
                m = l & 07;
                pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
                }
        for( i = 0; i < 16; i++ ) {
                m = i << 1;
                n = m + 1;
                kn[m] = kn[n] = 0L;
                for( j = 0; j < 28; j++ ) {
                        l = j + totrot[i];
                        if( l < 28 ) pcr[j] = pc1m[l];
                        else pcr[j] = pc1m[l - 28];
                        }
                for( j = 28; j < 56; j++ ) {
                        l = j + totrot[i];
                        if( l < 56 ) pcr[j] = pc1m[l];
                        else pcr[j] = pc1m[l - 28];
                        }
                for( j = 0; j < 24; j++ ) {
                        if( pcr[pc2[j]] ) kn[m] |= bigbyte[j];
                        if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
                        }
                }
        Cookey(cooked, kn);

        /* Zeroize sensitive information.
         */
        R_memset ((POINTER)pc1m, 0, sizeof (pc1m));
        R_memset ((POINTER)pcr, 0, sizeof (pcr));
        R_memset ((POINTER)kn, 0, sizeof (kn));
        return;
        }

static void Cookey (cook, raw1)
unsigned long *cook, *raw1;
{
        unsigned long *raw0, *deckey;
        int i;

        deckey = &cook[62];

        for( i = 0; i < 16; i++, raw1++ ) {
                raw0 = raw1++;
                *cook    = (*raw0 & 0x00fc0000L) << 6;
                *cook   |= (*raw0 & 0x00000fc0L) << 10;
                *cook   |= (*raw1 & 0x00fc0000L) >> 10;
                *cook   |= (*raw1 & 0x00000fc0L) >> 6;
                *deckey++ = *cook++;
                *cook    = (*raw0 & 0x0003f000L) << 12;
                *cook   |= (*raw0 & 0x0000003fL) << 16;
                *cook   |= (*raw1 & 0x0003f000L) >> 4;
                *cook   |= (*raw1 & 0x0000003fL);
                *deckey = *cook++;
                deckey -= 3;
                }
        return;
        }

/* DES-CBC initialization. Begins a DES-CBC operation, writing a new
   context.
 */

void DES3_CBCInit(context, key, iv, encrypt)
DES_CBC_CTX *context;                                                                   /* DES-CBC context */
unsigned char key[24];                                                                                   /* DES key */
unsigned char iv[8];    /* DES initializing vector */
int encrypt;            /* encrypt flag (1 = encrypt, 0 = decrypt) */
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;
  context->triple = 1;

  /* Pack initializing vector into context.
   */
  Pack (context->ivBlok, iv);

  /* Precompute key schedules
   */
  Deskey (context->subkeyBlok, key);
  Deskey (context->subkeyBlok1, &key[8]);
  Deskey (context->subkeyBlok2, &key[16]);
  return;
  }
void DES_CBCInit (context, key, iv, encrypt)
DES_CBC_CTX *context;                                                                   /* DES-CBC context */
unsigned char key[8];                                                                                   /* DES key */
unsigned char iv[8];    /* DES initializing vector */
int encrypt;            /* encrypt flag (1 = encrypt, 0 = decrypt) */
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;
  context->triple = 0;

  /* Pack initializing vector into context.
   */
  Pack (context->ivBlok, iv);

  /* Precompute key schedule
   */
  Deskey (context->subkeyBlok, key);
  return;
  }

/* DES-CBC block update operation. Continues a DES-CBC encryption
   operation, processing eight-byte message blocks, and updating
   the context.
 */
int DES_CBCUpdate (context, output, input, len)
DES_CBC_CTX *context;                                                                   /* DES-CBC context */
unsigned char *output;                                                                    /* output block */
unsigned char *input;                                                                           /* input block */
unsigned int len;                 /* length of input and output blocks */
{
  unsigned long inputBlok[2], work[2], *keysched;
  unsigned int i;
  
  if (len % 8)
        return (RE_LEN);

  if (context->encrypt != 0)
        keysched = context->subkeyBlok;
  else
        keysched = &context->subkeyBlok[32];
  
  for( i = 0; i < len/8; i++ ) {

        /* Pack input block and set LR = (input ^ iv) (encrypt) or
           LR = (input) (decrypt).
         */
        Pack (inputBlok, &input[8*i]);
        
        if (context->encrypt != 0) {
                work[0] = inputBlok[0] ^ context->ivBlok[0];
                work[1] = inputBlok[1] ^ context->ivBlok[1];
                }
        else {
                work[0] = inputBlok[0];
                work[1] = inputBlok[1];         
                }

        DesFn (work, keysched);

        /* Set iv = output (encrypt) or iv = input (decrypt).
         */

        if (context->encrypt != 0) {
                context->ivBlok[0] = work[0];
                context->ivBlok[1] = work[1];
                }
        else {
                work[0] ^= context->ivBlok[0];
                work[1] ^= context->ivBlok[1];
                context->ivBlok[0] = inputBlok[0];
                context->ivBlok[1] = inputBlok[1];
                }
        Unpack (&output[8*i], work);
        }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlok, 0, sizeof (inputBlok));
  R_memset ((POINTER)work, 0, sizeof (work));
  keysched = ((void *) 0);
  
  return (0);
}

int DES3_CBCUpdate (context, output, input, len)
DES_CBC_CTX *context;                                                                   /* DES-CBC context */
unsigned char *output;                                                                    /* output block */
unsigned char *input;                                                                           /* input block */
unsigned int len;                 /* length of input and output blocks */
{
  unsigned long inputBlok[2], work[2], *keysched[3];
  unsigned int i;
  
  if (len % 8)
        return (RE_LEN);

  if (context->encrypt != 0) {
        keysched[0] = context->subkeyBlok;          /* E */
        keysched[1] = &context->subkeyBlok1[32];    /* D */
        keysched[2] = context->subkeyBlok2;         /* E */
  }
  else {
        keysched[2] = &context->subkeyBlok[32];     /* D */
        keysched[1] = context->subkeyBlok1;         /* E */
        keysched[0] = &context->subkeyBlok2[32];    /* D */
  }
  
  for( i = 0; i < len/8; i++ ) {

        /* Pack input block and set LR = (input ^ iv) (encrypt) or
           LR = (input) (decrypt).
         */
        Pack (inputBlok, &input[8*i]);
        
        if (context->encrypt != 0) {
                work[0] = inputBlok[0] ^ context->ivBlok[0];
                work[1] = inputBlok[1] ^ context->ivBlok[1];
                }
        else {
                work[0] = inputBlok[0];
                work[1] = inputBlok[1];         
                }

        DesFn (work, keysched[0]);
        DesFn (work, keysched[1]);
        DesFn (work, keysched[2]);

        /* Set iv = output (encrypt) or iv = input (decrypt).
         */

        if (context->encrypt != 0) {
                context->ivBlok[0] = work[0];
                context->ivBlok[1] = work[1];
                }
        else {
                work[0] ^= context->ivBlok[0];
                work[1] ^= context->ivBlok[1];
                context->ivBlok[0] = inputBlok[0];
                context->ivBlok[1] = inputBlok[1];
                }
        Unpack (&output[8*i], work);
        }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlok, 0, sizeof (inputBlok));
  R_memset ((POINTER)work, 0, sizeof (work));
  keysched[0] = ((void *) 0);
  keysched[1] = ((void *) 0);
  keysched[2] = ((void *) 0);
  
  return (0);
}

/* DES-CBC finalization operation. Ends a DES-CBC encryption operation,
   zeroizing the context.
 */
void DES_CBCFinal (context)
DES_CBC_CTX *context;
{
  R_memset ((POINTER)context, 0, sizeof (*context));
}

void DES3_CBCFinal (context)
DES_CBC_CTX *context;
{
  R_memset ((POINTER)context, 0, sizeof (*context));
}

static void Pack(into, outof)
unsigned long *into;
unsigned char *outof;
{
        *into    = (*outof++ & 0xffL) << 24;
        *into   |= (*outof++ & 0xffL) << 16;
        *into   |= (*outof++ & 0xffL) << 8;
        *into++ |= (*outof++ & 0xffL);
        *into    = (*outof++ & 0xffL) << 24;
        *into   |= (*outof++ & 0xffL) << 16;
        *into   |= (*outof++ & 0xffL) << 8;
        *into   |= (*outof   & 0xffL);
        return;
        }

static void Unpack(into, outof)
unsigned char *into;
unsigned long *outof;
{
        *into++ = (unsigned char) ((*outof >> 24) & 0xffL);
        *into++ = (unsigned char) ((*outof >> 16) & 0xffL);
        *into++ = (unsigned char) ((*outof >>  8) & 0xffL);
        *into++ = (unsigned char) ( *outof++      & 0xffL);
        *into++ = (unsigned char) ((*outof >> 24) & 0xffL);
        *into++ = (unsigned char) ((*outof >> 16) & 0xffL);
        *into++ = (unsigned char) ((*outof >>  8) & 0xffL);
        *into   = (unsigned char) ( *outof        & 0xffL);
        return;
        }

static unsigned long SP1[64] = {
        0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
        0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
        0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
        0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
        0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
        0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
        0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
        0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
        0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
        0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
        0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
        0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
        0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
        0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
        0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
        0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };

static unsigned long SP2[64] = {
        0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
        0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
        0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
        0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
        0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
        0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
        0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
        0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
        0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
        0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
        0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
        0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
        0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
        0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
        0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
        0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };

static unsigned long SP3[64] = {
        0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
        0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
        0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
        0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
        0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
        0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
        0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
        0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
        0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
        0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
        0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
        0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
        0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
        0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
        0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
        0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };

static unsigned long SP4[64] = {
        0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
        0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
        0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
        0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
        0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
        0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
        0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
        0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
        0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
        0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
        0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
        0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
        0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
        0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
        0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
        0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };

static unsigned long SP5[64] = {
        0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
        0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
        0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
        0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
        0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
        0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
        0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
        0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
        0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
        0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
        0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
        0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
        0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
        0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
        0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
        0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };

static unsigned long SP6[64] = {
        0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
        0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
        0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
        0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
        0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
        0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
        0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
        0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
        0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
        0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
        0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
        0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
        0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
        0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
        0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
        0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };

static unsigned long SP7[64] = {
        0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
        0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
        0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
        0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
        0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
        0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
        0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
        0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
        0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
        0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
        0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
        0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
        0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
        0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
        0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
        0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };

static unsigned long SP8[64] = {
        0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
        0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
        0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
        0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
        0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
        0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
        0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
        0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
        0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
        0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
        0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
        0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
        0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
        0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
        0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
        0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };

static void DesFn(block, keys)
register unsigned long *block, *keys;
{
        register unsigned long fval, work, right, leftt;
        register int round;
        
        leftt = block[0];
        right = block[1];
        work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
        right ^= work;
        leftt ^= (work << 4);
        work = ((leftt >> 16) ^ right) & 0x0000ffffL;
        right ^= work;
        leftt ^= (work << 16);
        work = ((right >> 2) ^ leftt) & 0x33333333L;
        leftt ^= work;
        right ^= (work << 2);
        work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
        leftt ^= work;
        right ^= (work << 8);
        right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
        work = (leftt ^ right) & 0xaaaaaaaaL;
        leftt ^= work;
        right ^= work;
        leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;
        
        for( round = 0; round < 8; round++ ) {
                work  = (right << 28) | (right >> 4);
                work ^= *keys++;
                fval  = SP7[ work        & 0x3fL];
                fval |= SP5[(work >>  8) & 0x3fL];
                fval |= SP3[(work >> 16) & 0x3fL];
                fval |= SP1[(work >> 24) & 0x3fL];
                work  = right ^ *keys++;
                fval |= SP8[ work        & 0x3fL];
                fval |= SP6[(work >>  8) & 0x3fL];
                fval |= SP4[(work >> 16) & 0x3fL];
                fval |= SP2[(work >> 24) & 0x3fL];
                leftt ^= fval;
                work  = (leftt << 28) | (leftt >> 4);
                work ^= *keys++;
                fval  = SP7[ work        & 0x3fL];
                fval |= SP5[(work >>  8) & 0x3fL];
                fval |= SP3[(work >> 16) & 0x3fL];
                fval |= SP1[(work >> 24) & 0x3fL];
                work  = leftt ^ *keys++;
                fval |= SP8[ work        & 0x3fL];
                fval |= SP6[(work >>  8) & 0x3fL];
                fval |= SP4[(work >> 16) & 0x3fL];
                fval |= SP2[(work >> 24) & 0x3fL];
                right ^= fval;
                }
                
        right = (right << 31) | (right >> 1);
        work = (leftt ^ right) & 0xaaaaaaaaL;
        leftt ^= work;
        right ^= work;
        leftt = (leftt << 31) | (leftt >> 1);
        work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
        right ^= work;
        leftt ^= (work << 8);
        work = ((leftt >> 2) ^ right) & 0x33333333L;
        right ^= work;
        leftt ^= (work << 2);
        work = ((right >> 16) ^ leftt) & 0x0000ffffL;
        leftt ^= work;
        right ^= (work << 16);
        work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
        leftt ^= work;
        right ^= (work << 4);
        *block++ = right;
        *block = leftt;
        return;
        }

/******* end ******/
