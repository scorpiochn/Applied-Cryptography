/* R_ENHANC.C - cryptographic enhancements for RSAREF
 */

/* 92.12.30 RL - added code to support INIT,PROCESS,END mode
 *
 * 93.05.25 Mark Henderson--Added a choice of encryption
 *   algorithms to R_SealPEMBlock and R_OpenPEMBlock.
 *   Bits 15-8 of the digest algorithm parameter can be one
 *   of DE_ALG_DES_CBC and DE_ALG_DES_EDE2_CBC.
 *   Changed internal routines R_EncryptPEMBlock and 
 *   R_DecryptPEMBlock to support this. 
 */

/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
   Security, Inc. All rights reserved.
 */

#include "global.h"
#include "rsaref.h"
#include "r_encode.h"
#include "r_random.h"
#include "rsa.h"
#include "md2.h"
#include "md5.h"
#include "des.h"

/* DigestInfo encoding is DIGEST_INFO_A, then 2 or 5 (for MD2/MD5),
   then DIGEST_INFO_B, then 16-byte message digest.
 */

static unsigned char DIGEST_INFO_A[] = {
  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x02
};
#define DIGEST_INFO_A_LEN sizeof (DIGEST_INFO_A)

static char DIGEST_INFO_B[] = { 0x05, 0x00, 0x04, 0x10 };
#define DIGEST_INFO_B_LEN sizeof (DIGEST_INFO_B)

#define DIGEST_INFO_LEN (DIGEST_INFO_A_LEN + 1 + DIGEST_INFO_B_LEN + 16)

static unsigned char *PADDING[] = {
  (unsigned char *)"", (unsigned char *)"\001", (unsigned char *)"\002\002",
  (unsigned char *)"\003\003\003", (unsigned char *)"\004\004\004\004",
  (unsigned char *)"\005\005\005\005\005",
  (unsigned char *)"\006\006\006\006\006\006", 
  (unsigned char *)"\007\007\007\007\007\007\007",
  (unsigned char *)"\010\010\010\010\010\010\010\010"
};

#define MAX_ENCRYPTED_KEY_LEN MAX_RSA_MODULUS_LEN

static int R_SignBlock PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int, int,
    R_RSA_PRIVATE_KEY *, int));
static void R_EncodeDigestInfo PROTO_LIST
  ((unsigned char *, int, unsigned char *));

static void R_EncryptPEMBlock PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    unsigned char *, unsigned char [8], int, int));
static int R_DecryptPEMBlock PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    unsigned char *, unsigned char [8], int,int));

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing.
 *                      (signature not valid)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (signature not valid)
 *  MODE_END            means last block -- do the signing
 *                      (signature valid)
 */
int R_SignPEMBlock 
  (encodedContent, encodedContentLen, encodedSignature, encodedSignatureLen,
   content, contentLen, recode, digestAlgorithm, privateKey, mode)
unsigned char *encodedContent;                           /* encoded content */
unsigned int *encodedContentLen;               /* length of encoded content */
unsigned char *encodedSignature;                       /* encoded signature */
unsigned int *encodedSignatureLen;           /* length of encoded signature */
unsigned char *content;                                          /* content */
unsigned int contentLen;                               /* length of content */
int recode;                                                /* recoding flag */
int digestAlgorithm;                            /* message-digest algorithm */
R_RSA_PRIVATE_KEY *privateKey;                  /* signer's RSA private key */
int mode;
{
  int status;
  unsigned char signature[MAX_SIGNATURE_LEN];
  unsigned int signatureLen;
  
  if (status = R_SignBlock
      (signature, &signatureLen, content, contentLen, digestAlgorithm,
       privateKey, mode))
    return (status);

  if(mode != MODE_INIT && mode != MODE_PROCESS)
          R_EncodePEMBlock 
            (encodedSignature, encodedSignatureLen, signature, signatureLen);

  if (recode)
    R_EncodePEMBlock
    (encodedContent, encodedContentLen, content, contentLen);

  return (0);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing.
 *                      (return result will not indicate bad verification)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (return result will not indicate bad verification)
 *  MODE_END            means last block -- do the signing
 *                      (return result valid)
 * Note -- if using INIT,PROCESS,END requires that encodedContentLen be
 *                              a multiple of 32 bytes except for last.
 */
int R_VerifyPEMSignature 
  (content, contentLen, encodedContent, encodedContentLen, encodedSignature,
   encodedSignatureLen, recode, digestAlgorithm, publicKey, mode)
unsigned char *content;                                          /* content */
unsigned int *contentLen;                              /* length of content */
unsigned char *encodedContent;                /* (possibly) encoded content */
unsigned int encodedContentLen;                /* length of encoded content */
unsigned char *encodedSignature;                       /* encoded signature */
unsigned int encodedSignatureLen;            /* length of encoded signature */
int recode;                                                /* recoding flag */
int digestAlgorithm;                            /* message-digest algorithm */
R_RSA_PUBLIC_KEY *publicKey;                     /* signer's RSA public key */
int mode;
{
  int status;
  unsigned char signature[MAX_SIGNATURE_LEN];
  unsigned int signatureLen;
  
  if (encodedSignatureLen > MAX_PEM_SIGNATURE_LEN)
    return (RE_SIGNATURE_ENCODING);
  
  if (recode) {
    if (status = R_DecodePEMBlock
        (content, contentLen, encodedContent, encodedContentLen))
      return (RE_CONTENT_ENCODING);
  }
  else {
    /* was: content = encodedContent;
     * Changed to make a copy so the caller can always get the output in
     * content regardless of whether it's recode mode.  The other way was
     * probably a bug!!!
     */
        R_memcpy(content,encodedContent,encodedContentLen);
    *contentLen = encodedContentLen;
  }
  
  if(mode != MODE_INIT && mode != MODE_PROCESS) {
          if (status = R_DecodePEMBlock
             (signature, &signatureLen, encodedSignature, encodedSignatureLen))
                return (RE_SIGNATURE_ENCODING);
  }
  
  return (R_VerifyBlockSignature 
          (content, *contentLen, signature, signatureLen, digestAlgorithm,
           publicKey, mode));
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing.
 *                      (return result will not indicate bad verification)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (return result will not indicate bad verification)
 *  MODE_END            means last block -- do the signing
 *                      (return result valid)
 */
int R_VerifyBlockSignature 
  (block, blockLen, signature, signatureLen, digestAlgorithm, publicKey, mode)
unsigned char *block;                                              /* block */
unsigned int blockLen;                                   /* length of block */
unsigned char *signature;                                      /* signature */
unsigned int signatureLen;                           /* length of signature */
int digestAlgorithm;                            /* message-digest algorithm */
R_RSA_PUBLIC_KEY *publicKey;                     /* signer's RSA public key */
int mode;
{
  int status;
  unsigned char digest[MAX_DIGEST_LEN], digestInfo[DIGEST_INFO_LEN],
    originalDigestInfo[MAX_SIGNATURE_LEN];
  unsigned int digestLen, originalDigestInfoLen;
  
  if(mode != MODE_INIT && mode != MODE_PROCESS) {
          if (signatureLen > MAX_SIGNATURE_LEN)
            return (RE_SIGNATURE);
  }
  do {
    if (status = R_DigestBlock 
        (digest, &digestLen, block, blockLen, digestAlgorithm, mode))
      break;
    
    if(mode != MODE_INIT && mode != MODE_PROCESS) {
            R_EncodeDigestInfo (digestInfo, digestAlgorithm, digest);
            
            if (status = RSAPublicDecrypt
                (originalDigestInfo, &originalDigestInfoLen, signature, signatureLen, 
                 publicKey)) {
              status = RE_PUBLIC_KEY;
              break;
            }
            
            if ((originalDigestInfoLen != DIGEST_INFO_LEN) ||
                (R_memcmp 
                 ((POINTER)originalDigestInfo, (POINTER)digestInfo,
                  DIGEST_INFO_LEN))) {
              status = RE_SIGNATURE;
              break;
            }
        }
  } while (0);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)digest, 0, sizeof (digest));
  R_memset ((POINTER)digestInfo, 0, sizeof (digestInfo));
  R_memset ((POINTER)originalDigestInfo, 0, sizeof (originalDigestInfo));

  return (status);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing, generate & return iv/enc key only
 *                      (signature not valid)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (signature not valid)
 *  MODE_END            means last block -- do the signing
 *                      (signature valid and key is encrypted)
 *  Note -- when MODE_PROCESS, assumes contentLen is a multiple of 24.
 */
int R_SealPEMBlock 
  (encryptedContent, encryptedContentLen, encryptedKey, encryptedKeyLen,
   encryptedSignature, encryptedSignatureLen, iv, content, contentLen,
   algorithm, publicKey, privateKey, randomStruct, mode)
unsigned char *encryptedContent;              /* encoded, encrypted content */
unsigned int *encryptedContentLen;                                /* length */
unsigned char *encryptedKey;                      /* encoded, encrypted key */
unsigned int *encryptedKeyLen;                                    /* length */
unsigned char *encryptedSignature;          /* encoded, encrypted signature */
unsigned int *encryptedSignatureLen;                              /* length */
unsigned char iv[8];                             /* DES initializing vector */
unsigned char *content;                                          /* content */
unsigned int contentLen;                               /* length of content */
int algorithm;                         /* message-digest/encryption algorithm */
R_RSA_PUBLIC_KEY *publicKey;                  /* recipient's RSA public key */
R_RSA_PRIVATE_KEY *privateKey;                  /* signer's RSA private key */
R_RANDOM_STRUCT *randomStruct;                          /* random structure */
int mode;
{
  int status;
  int keylen;
  unsigned char encryptedKeyBlock[MAX_ENCRYPTED_KEY_LEN], key[24],
    signature[MAX_SIGNATURE_LEN];
  static unsigned char savekey[24];
  unsigned int encryptedKeyBlockLen, signatureLen;
  int digestAlgorithm = algorithm & 0xff;
  int encryptionAlgorithm = (algorithm & 0xff00) >> 8;
  int triple = (encryptionAlgorithm == EA_DES_EDE2_CBC);

  if (triple)
    keylen = 24;
  else
    keylen = 8;
  
  do {
    if (status = R_SignBlock
        (signature, &signatureLen, content, contentLen, digestAlgorithm,
         privateKey, mode))
      break;
   
    if(mode != MODE_PROCESS && mode != MODE_END) {
            if ((status = R_GenerateBytes (key, keylen, randomStruct)) ||
                (status = R_GenerateBytes (iv, 8, randomStruct)))
              break;
/* if you want three independent keys, define EDE3 */
#ifndef EDE3
        if (keylen > 8)
            R_memcpy((POINTER) (&key[0]+16), (POINTER) &key[0], 8);
#endif
        }
        
    if(mode == MODE_INIT) {
        /* return pt key */
        R_memcpy (savekey, key, keylen);
    } else if(mode == MODE_PROCESS || mode == MODE_END) {
        /* grab key from caller */
        R_memcpy (key, savekey, keylen);
    }

    R_EncryptPEMBlock 
      (encryptedContent, encryptedContentLen, content, contentLen, key, iv, 
mode, triple);
    
    if(mode != MODE_PROCESS && mode != MODE_END) {
            if (status = RSAPublicEncrypt
                (encryptedKeyBlock, &encryptedKeyBlockLen, key, keylen, publicKey,
                 randomStruct)) {
              status = RE_PUBLIC_KEY;
              break;
            }
    
            R_EncodePEMBlock 
              (encryptedKey, encryptedKeyLen, encryptedKeyBlock,
               encryptedKeyBlockLen);
        }
        
        if(mode != MODE_INIT && mode != MODE_PROCESS) {
            R_EncryptPEMBlock
              (encryptedSignature, encryptedSignatureLen, signature, signatureLen,
               key, iv, MODE_STANDARD, triple);
        }

  } while (0);
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)key, 0, sizeof (key));
  R_memset ((POINTER)signature, 0, sizeof (signature));
  
  if(mode == MODE_END)
          R_memset ((POINTER)savekey, 0, keylen);

  return (status);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for opening.
 *                      (return result will not indicate bad verification)
 *  MODE_PROCESS        means process block but don't verify signature
 *                      (return result will not indicate bad verification)
 *  MODE_END            means last block -- do the verfication
 *                      (return result valid)
 * Note -- if using INIT,PROCESS,END requires that encodedContentLen be
 *      a multiple of 32 bytes except for last.  (last must be non-zero).
 */
int R_OpenPEMBlock
  (content, contentLen, encryptedContent, encryptedContentLen, encryptedKey,
   encryptedKeyLen, encryptedSignature, encryptedSignatureLen,
   iv, algorithm, privateKey, publicKey, mode)
unsigned char *content;                                          /* content */
unsigned int *contentLen;                              /* length of content */
unsigned char *encryptedContent;              /* encoded, encrypted content */
unsigned int encryptedContentLen;                                 /* length */
unsigned char *encryptedKey;                      /* encoded, encrypted key */
unsigned int encryptedKeyLen;                                     /* length */
unsigned char *encryptedSignature;          /* encoded, encrypted signature */
unsigned int encryptedSignatureLen;                               /* length */
unsigned char iv[8];                             /* DES initializing vector */
int algorithm;                        /* message-digest/encryption algorithm */
R_RSA_PRIVATE_KEY *privateKey;               /* recipient's RSA private key */
R_RSA_PUBLIC_KEY *publicKey;                     /* signer's RSA public key */
int mode;
{
  int status; int keylen;
  unsigned char encryptedKeyBlock[MAX_ENCRYPTED_KEY_LEN],
   key[MAX_ENCRYPTED_KEY_LEN], signature[MAX_SIGNATURE_LEN];
  unsigned int encryptedKeyBlockLen, keyLen, signatureLen;
  static unsigned char saveKey[24];
  int digestAlgorithm = algorithm & 0xff;
  int encryptionAlgorithm = (algorithm & 0xff00) >> 8;
  int triple = (encryptionAlgorithm == EA_DES_EDE2_CBC);
  
  if (triple)
    keylen = 24;
  else
    keylen = 8;
  
  if (encryptedKeyLen > MAX_PEM_ENCRYPTED_KEY_LEN)
    return (RE_KEY_ENCODING);
  
  if (encryptedSignatureLen > MAX_PEM_ENCRYPTED_SIGNATURE_LEN)
    return (RE_SIGNATURE_ENCODING);
  
  do {
        if(mode != MODE_PROCESS && mode != MODE_END) {
            if (status = R_DecodePEMBlock 
                (encryptedKeyBlock, &encryptedKeyBlockLen, encryptedKey,
                 encryptedKeyLen)) {
              status = RE_KEY_ENCODING;
              break;
            }
        
            if (status = RSAPrivateDecrypt
                (key, &keyLen, encryptedKeyBlock, encryptedKeyBlockLen, privateKey)) {
              status = RE_PRIVATE_KEY;
              break;
            }
    
            if (keyLen != 8 && keyLen != 24) {
              status = RE_PRIVATE_KEY;
              break;
            }
    }
    
    if(mode == MODE_INIT) {
        R_memcpy (saveKey, key, keylen);
    } else if(mode == MODE_PROCESS || mode == MODE_END) {
        R_memcpy (key, saveKey, keylen);
    }
    
    if (status = R_DecryptPEMBlock 
        (content, contentLen, encryptedContent, encryptedContentLen, key,
         iv, mode, triple)) {
      if ((status == RE_LEN || status == RE_ENCODING))
        status = RE_CONTENT_ENCODING;
      else
        status = RE_KEY;
      break;
    }
    
    if(mode != MODE_INIT && mode != MODE_PROCESS) {
            if (status = R_DecryptPEMBlock
                (signature, &signatureLen, encryptedSignature, encryptedSignatureLen,
                 key, iv, MODE_STANDARD,triple)) {
              if ((status == RE_LEN || status == RE_ENCODING))
                status = RE_SIGNATURE_ENCODING;
              else
                status = RE_KEY;
            }
        }

    if (status = R_VerifyBlockSignature
        (content, *contentLen, signature, signatureLen, digestAlgorithm,
         publicKey, mode))
      break;

  } while (0);
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)key, 0, sizeof (key));
  R_memset ((POINTER)signature, 0, sizeof (signature));

  if(mode == MODE_END) {
         R_memset ((POINTER)saveKey, 0, keylen);
  }
  
  return (status);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing.
 *                      (signature not valid)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (signature not valid)
 *  MODE_END            means last block -- do the signing
 *                      (signature valid)
 */
static int R_SignBlock
  (signature, signatureLen, block, blockLen, digestAlgorithm, privateKey, mode)
unsigned char *signature;                                      /* signature */
unsigned int *signatureLen;                          /* length of signature */
unsigned char *block;                                              /* block */
unsigned int blockLen;                                   /* length of block */
int digestAlgorithm;                            /* message-digest algorithm */
R_RSA_PRIVATE_KEY *privateKey;                  /* signer's RSA private key */
int mode;
{
  int status;
  unsigned char digest[MAX_DIGEST_LEN], digestInfo[DIGEST_INFO_LEN];
  unsigned int digestLen;

  do {
    if (status = R_DigestBlock
        (digest, &digestLen, block, blockLen, digestAlgorithm, mode))
      break;
    
    if(mode != MODE_INIT && mode != MODE_PROCESS) {
            R_EncodeDigestInfo (digestInfo, digestAlgorithm, digest);
    
            if (status = RSAPrivateEncrypt
                (signature, signatureLen, digestInfo, DIGEST_INFO_LEN, privateKey)) {
              status = RE_PRIVATE_KEY;
              break;
            }
        }
        
  } while (0);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)digest, 0, sizeof (digest));
  R_memset ((POINTER)digestInfo, 0, sizeof (digestInfo));

  return (status);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action
 *  MODE_INIT           means intialize for signing.
 *                      (digest not valid)
 *  MODE_PROCESS        means process block but don't complete signing
 *                      (digest not valid)
 *  MODE_END            means last block -- do the signing
 *                      (digest valid)
 */
int R_DigestBlock (digest, digestLen, block, blockLen, digestAlgorithm, mode)
unsigned char *digest;                                    /* message digest */
unsigned int *digestLen;                        /* length of message digest */
unsigned char *block;                                              /* block */
unsigned int blockLen;                                   /* length of block */
int digestAlgorithm;                            /* message-digest algorithm */
int mode;
{
  /* made static to save info across invocations in INIT,PROCESS,END mode. */
  static MD2_CTX md2Context;
  static MD5_CTX md5Context;
  int status;
  
  status = 0;
  switch (digestAlgorithm) {
  case DA_MD2:
        if(mode != MODE_PROCESS && mode != MODE_END)
            MD2Init (&md2Context);
    MD2Update (&md2Context, block, blockLen);
    if(mode != MODE_INIT && mode != MODE_PROCESS)
            MD2Final (digest, &md2Context);
    *digestLen = 16;
    break;

  case DA_MD5:
        if(mode != MODE_PROCESS && mode != MODE_END)
            MD5Init (&md5Context);
        MD5Update (&md5Context, block, blockLen);
    if(mode != MODE_INIT && mode != MODE_PROCESS)
            MD5Final (digest, &md5Context);
    *digestLen = 16;
    break;
  
  default:
    status = RE_DIGEST_ALGORITHM;
  }
  
  return (status);
}

/* Assumes digestAlgorithm is DA_MD2 or DA_MD5 and digest length is 16.
 */
static void R_EncodeDigestInfo (digestInfo, digestAlgorithm, digest)
unsigned char *digestInfo;                           /* DigestInfo encoding */
int digestAlgorithm;                            /* message-digest algorithm */
unsigned char *digest;                                    /* message digest */
{
  R_memcpy 
    ((POINTER)digestInfo, (POINTER)DIGEST_INFO_A, DIGEST_INFO_A_LEN);
  
  digestInfo[DIGEST_INFO_A_LEN] =
    (digestAlgorithm == DA_MD2) ? (unsigned char)2 : (unsigned char)5;

  R_memcpy 
    ((POINTER)&digestInfo[DIGEST_INFO_A_LEN + 1], (POINTER)DIGEST_INFO_B,
     DIGEST_INFO_B_LEN);
  
  R_memcpy 
    ((POINTER)&digestInfo[DIGEST_INFO_A_LEN + 1 + DIGEST_INFO_B_LEN],
     (POINTER)digest, 16);
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action.
 *  MODE_INIT           means intialize for encryption.
 *  MODE_PROCESS        means process block.
 *  MODE_END            means last block.
 *  Note -- if using INIT,PROCESS,END blockLen s/b mult. of 24 except on last.
 */
static void R_EncryptPEMBlock
  (encryptedBlock, encryptedBlockLen, block, blockLen, key, iv, mode, triple)
unsigned char *encryptedBlock;                  /* encrypted, encoded block */
unsigned int *encryptedBlockLen;                                  /* length */
unsigned char *block;                                              /* block */
unsigned int blockLen;                                   /* length of block */
unsigned char *key;                                            /* DES key */
unsigned char iv[8];                           /* DES initialization vector */
int mode;
int triple;                                     /* triple encryption ? */
{
  static DES_CBC_CTX context;   /* made static for INIT,PROCESS,END */
  unsigned char encryptedPart[24], lastPart[24];
  unsigned int i, lastPartLen, len, padLen;
  int keylen;

  keylen = 8;
  if (triple) 
    keylen = 24;

  if(mode != MODE_PROCESS && mode != MODE_END)
    if (triple)
          DES3_CBCInit (&context, key, iv, 1);
    else
          DES_CBCInit (&context, key, iv, 1);

  for (i = 0; i < blockLen/24; i++) {
    if (triple)
        DES3_CBCUpdate (&context, encryptedPart, &block[24*i], 24);
    else
        DES_CBCUpdate (&context, encryptedPart, &block[24*i], 24);
    /* len is always 32 */
    R_EncodePEMBlock (&encryptedBlock[32*i], &len, encryptedPart, 24);
  }
  
  if(mode != MODE_INIT && mode != MODE_PROCESS) {
          padLen = 8 - (blockLen % 8);
          lastPartLen = blockLen - 24*i + padLen;
          R_memcpy ((POINTER)lastPart, (POINTER)&block[24*i], lastPartLen - padLen);
          R_memcpy
            ((POINTER)&lastPart[lastPartLen - padLen], PADDING[padLen], padLen);
          if (triple)
            DES3_CBCUpdate (&context, encryptedPart, lastPart, lastPartLen);
          else
            DES_CBCUpdate (&context, encryptedPart, lastPart, lastPartLen);
          R_EncodePEMBlock 
            (&encryptedBlock[32*i], &len, encryptedPart, lastPartLen);
  } else
        len = 0;
  *encryptedBlockLen = 32*i + len;

  if(mode != MODE_INIT && mode != MODE_PROCESS)
        if (triple)
          DES3_CBCFinal (&context);
        else
          DES_CBCFinal (&context);
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)lastPart, 0, sizeof (lastPart));
}

/* special values for mode:
 *  MODE_STANDARD       means do standard action.
 *  MODE_INIT           means intialize for decryption.
 *  MODE_PROCESS        means process block.
 *  MODE_END            means last block.
 *  Note -- if using INIT,PROCESS,END requires that encodedContentLen be
 *     a multiple of 32 bytes except for last.  (last must be non-zero).
 */
static int R_DecryptPEMBlock
  (block, blockLen, encryptedBlock, encryptedBlockLen, key, iv, mode,triple)
unsigned char *block;                                              /* block */
unsigned int *blockLen;                                  /* length of block */
unsigned char *encryptedBlock;                  /* encrypted, encoded block */
unsigned int encryptedBlockLen;                                   /* length */
unsigned char *key;                                            /* DES key */
unsigned char iv[8];                           /* DES initialization vector */
int mode;
int triple;
{
  static DES_CBC_CTX context;
  int status;
  int keylen;
  unsigned char encryptedPart[24], lastPart[24];
  unsigned int i, lastPartLen, len, padLen;
  if (triple)
    keylen = 24;
  else
    keylen = 8;
  
  if (encryptedBlockLen < 1)
    return (RE_LEN);

  if(mode != MODE_PROCESS && mode != MODE_END)
       if (triple)
          DES3_CBCInit (&context, key, iv, 0);
       else
          DES_CBCInit (&context, key, iv, 0);
  
  status = 0;
  
  do {
        unsigned int looplim;
        
        if(mode != MODE_INIT && mode != MODE_PROCESS)
                looplim = (encryptedBlockLen-1)/32;
        else
                /* if not at end, don't handle last special */
                looplim = encryptedBlockLen/32;
                
    for (i = 0; i < looplim; i++) {
      /* len is always 24 */
      if (status = R_DecodePEMBlock
          (encryptedPart, &len, &encryptedBlock[32*i], 32))
        break;
      if (triple)
        DES3_CBCUpdate (&context, &block[24*i], encryptedPart, 24);
      else
        DES_CBCUpdate (&context, &block[24*i], encryptedPart, 24);
    }
    if (status)
      break;
  
        if(mode != MODE_INIT && mode != MODE_PROCESS) {
            len = encryptedBlockLen - 32*i;
            if (status = R_DecodePEMBlock
                (encryptedPart, &lastPartLen, &encryptedBlock[32*i], len))
              break;
        
            if (lastPartLen % 8) {
              status = RE_DATA;
              break;
            }
            
            if (triple) 
            DES3_CBCUpdate (&context, lastPart, encryptedPart, lastPartLen);
            else
            DES_CBCUpdate (&context, lastPart, encryptedPart, lastPartLen);

            padLen = lastPart[lastPartLen - 1];
            if (padLen > 8) {
              status = RE_DATA;
              break;
            }
            if (R_memcmp 
                ((POINTER)&lastPart[lastPartLen - padLen], PADDING[padLen], padLen)) {
              status = RE_DATA;
              break;
            }
    
        R_memcpy ((POINTER)&block[24*i], (POINTER)lastPart, lastPartLen - padLen);
    } else {
        padLen = 0;
        lastPartLen = 0;
    }
    *blockLen = 24*i + lastPartLen - padLen;

  } while (0);

  if(mode != MODE_INIT && mode != MODE_PROCESS)
        if (triple)
          DES3_CBCFinal (&context);
        else
          DES_CBCFinal (&context);

  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)lastPart, 0, sizeof (lastPart));

  return (status);
}

/* EOF */
