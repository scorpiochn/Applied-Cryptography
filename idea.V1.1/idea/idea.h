/******************************************************************************/
/*                                                                            */
/* I N T E R N A T I O N A L  D A T A  E N C R Y P T I O N  A L G O R I T H M */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ee.ethz.ch)                */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Created:      April 23, 1992                                               */
/* Changes:      November 16, 1993 (support of ANSI-C and C++)                */
/* System:       SUN SPARCstation, SUN acc ANSI-C-Compiler, SUN-OS 4.1.3      */
/******************************************************************************/
/* Change this type definitions to the representations in your computer.      */

typedef long                     int32; /* signed 32-bit integer (or larger)  */
typedef unsigned long          u_int32; /* unsigned 32-bit integer (or larger)*/
typedef unsigned short         u_int16; /* unsigned 16-bit integer (or larger)*/
typedef unsigned char           u_int8; /* unsigned 8-bit integer             */

#define ANSI_C                   /* If 'ANSI_C' is defined the preprocessed   */
                                 /* source code is ANSI-C or C++ code, other- */
                                 /* wise it is Kerninghan & Ritchie C code.   */

/******************************************************************************/
/* It is possible to change this values.                                      */

#define Idea_nofRound                 8 /* number of rounds                   */
#define Idea_userKeyLen               8 /* user key length (8 or larger)      */

/******************************************************************************/
/* Do not change the lines below.                                             */

#define Idea_dataLen                       4 /* plain-/ciphertext block length*/
#define Idea_keyLen    (Idea_nofRound * 6 + 4) /* en-/decryption key length   */

#define Idea_dataSize       (Idea_dataLen * 2) /* 8 bytes = 64 bits           */
#define Idea_userKeySize (Idea_userKeyLen * 2) /* 16 bytes = 128 bits         */
#define Idea_keySize         (Idea_keyLen * 2) /* 104 bytes = 832 bits        */

typedef u_int16 Idea_Data[Idea_dataLen];
typedef u_int16 Idea_UserKey[Idea_userKeyLen];
typedef u_int16 Idea_Key[Idea_keyLen];

/******************************************************************************/
/* void Idea_Crypt (Idea_Data dataIn, Idea_Data dataOut, Idea_Key key)        */
/*                                                                            */
/* Encryption and decryption algorithm IDEA. Depending on the value of 'key'  */
/* 'Idea_Crypt' either encrypts or decrypts 'dataIn'. The result is stored    */
/* in 'dataOut'.                                                              */
/* pre:  'dataIn'  contains the plain/cipher-text block.                      */
/*       'key'     contains the encryption/decryption key.                    */
/* post: 'dataOut' contains the cipher/plain-text block.                      */
/*                                                                            */
/******************************************************************************/
/* void Idea_InvertKey (Idea_Key key, Idea_Key invKey)                        */
/*                                                                            */
/* Inverts a decryption/encrytion key to a encrytion/decryption key.          */
/* pre:  'key'    contains the encryption/decryption key.                     */
/* post: 'invKey' contains the decryption/encryption key.                     */
/*                                                                            */
/******************************************************************************/
/* void Idea_ExpandUserKey (Idea_UserKey userKey, Idea_Key key)               */
/*                                                                            */
/* Expands a user key of 128 bits to a full encryption key                    */
/* pre:  'userKey' contains the 128 bit user key                              */
/* post: 'key'     contains the encryption key                                */
/*                                                                            */
/******************************************************************************/

#ifdef ANSI_C
  void Idea_Crypt (Idea_Data dataIn, Idea_Data dataOut, Idea_Key key);
  void Idea_InvertKey (Idea_Key key, Idea_Key invKey);
  void Idea_ExpandUserKey (Idea_UserKey userKey, Idea_Key key);
#else
  Idea_Crypt ();
  Idea_InvertKey ();
  Idea_ExpandUserKey ();
#endif
