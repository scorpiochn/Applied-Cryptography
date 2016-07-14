/******************************************************************************/
/*                                                                            */
/* I N T E R N A T I O N A L  D A T A  E N C R Y P T I O N  A L G O R I T H M */
/*                                                                            */
/*                     A S   A   U S E R   C O M M A N D                      */
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

#ifdef RASTERFILE
#include <rasterfile.h>
#endif

#ifdef TIME
#include <time.h>
#ifndef CLK_TCK
#define CLK_TCK        1000000
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "idea.h"

#define TRUE                 1 /* boolean constant for true                   */
#define FALSE                0 /* boolean constant for false                  */
#define nofTestData     163840 /* number of blocks encrypted in time test     */

#define nomode               0 /* no mode is specified                        */
#define ecb                  1 /* electronic code book mode                   */
#define cbc                  2 /* cipher block chaining mode                  */
#define cfb                  3 /* ciphertext feedback mode                    */
#define ofb                  4 /* output feedback mode                        */
#define tan                  5 /* tandem DM-scheme for hashing                */
#define abr                  6 /* abreast DM-scheme for hashing               */
#define eol              0x100 /* end of line character                       */
#define colon            0x101 /* character ':'                               */
#define error            0x102 /* unknown character                           */
#define maxInterleave     1024 /* maximal interleave factor + 1               */
#define nofChar ('~' - '!' +1) /* number of different printable characters    */
#define maxBufLen (Idea_dataSize * 1024) /* size of input and output buffer   */

Idea_UserKey userKey;          /* user selected 128 bit key                   */
Idea_Key key;                  /* expanded key with 832 bits                  */
Idea_Data state[maxInterleave];/* state informations for interleaving modes   */
Idea_Data hashLow;             /* lower 64 bits of hash value                 */
Idea_Data hashHigh;            /* higher 64 bits of hash value                */

u_int32 inputLen    = 0;       /* current number of bytes read from 'inFile'  */
int interleave      = 0;       /* current interleave factor                   */
int time_0          = 0;       /* time for interleaving modes                 */
int time_N          = 0;       /* time-interleave for interleaving modes      */
int mode            = nomode;  /* current mode                                */

int optEncrypt      = FALSE;   /* encrypt option 'e'                          */
int optDecrypt      = FALSE;   /* decrypt option 'd'                          */
int optHash         = FALSE;   /* hash option 'h'                             */
int optCopyHash     = FALSE;   /* copy and hash option 'H'                    */
int optKeyHexString = FALSE;   /* key as hex-string option 'K'                */
int optKeyString    = FALSE;   /* key as string option 'k'                    */
int optRas          = FALSE;   /* raster file option 'r'                      */
int optTime         = FALSE;   /* measure time option 'T'                     */

int inBufLen        = maxBufLen; /* current length of data in 'inBuf'         */
int inBufPos        = maxBufLen; /* current read position of 'inBuf'          */
int outBufLen       = 0;       /* current write position of 'outBuf'          */
u_int8 inBuf[maxBufLen];       /* buffer for file read                        */
u_int8 outBuf[maxBufLen];      /* buffer for file write                       */

FILE *inFile;                  /* file with input data (plain or ciphertext)  */
FILE *outFile;                 /* file for output data (plain or ciphertext)  */
FILE *hashFile;                /* 128 bit hash value is written to this file  */

/******************************************************************************/
/* initialize global variables                                                */

#ifdef ANSI_C
  void Init(void)
#else
  Init()
#endif

{ int i, pos;

  for (i = Idea_userKeyLen - 1; i >= 0 ; i--) userKey[i] = 0;
  for (pos = maxInterleave - 1; pos >= 0 ; pos--)
    for (i = Idea_dataLen - 1; i >= 0; i--)
      state[pos][i] = 0;
} /* Init */

/******************************************************************************/
/*                          E R R O R - H A N D L I N G                       */
/******************************************************************************/
/* write usage error message and terminate program                            */

#ifdef ANSI_C
  void UsageError(int num)
#else
  UsageError(num)
  int num;
#endif

{
#ifdef RASTERFILE
fprintf(stderr, "(%d)\n\
Usage:   idea [ -e | -d ] [ -r ] [ -ecb | -cbcN | -cfbN | -ofbN ]\n\
              ( -k keyString | -K keyHexString )                 \n\
              [ inputFile [ outputFile ] ]                       \n\
         idea [ -h | -H ] [ -tan | -abr ]                        \n\
              [ -k keyString | -K keyHexString ]                 \n\
              [ inputFile [ [ outputFile ] hashvalFile ] ]       \n\
         idea -T                                                 \n\
\nExample: idea -Hk \"k e y\" infile | idea -cbc8 -K 123:9a::eF - outfile\n\
\n", num);
#else
fprintf(stderr, "(%d)\n\
Usage:   idea [ -e | -d ] [ -ecb | -cbcN | -cfbN | -ofbN ]       \n\
              ( -k keyString | -K keyHexString )                 \n\
              [ inputFile [ outputFile ] ]                       \n\
         idea [ -h | -H ] [ -tan | -abr ]                        \n\
              [ -k keyString | -K keyHexString ]                 \n\
              [ inputFile [ [ outputFile ] hashvalFile ] ]       \n\
\nExample: idea -Hk \"k e y\" infile | idea -cbc8 -K 123:9a::eF - outfile\n\
\n", num);
#endif
  exit(-1);
} /* UsageError */

/******************************************************************************/
/* write error message and terminate program                                  */

#ifdef ANSI_C
  void Error(int num, char *str)
#else
  Error(num, str)
  int num;
  char *str;
#endif

{  fprintf(stderr, "error %d in idea: %s\n", num, str); exit(-1); } /* Error */

/******************************************************************************/
/* write system error message and terminate program                           */

#ifdef ANSI_C
  void PError(char *str)
#else
  PError(str)
  char *str;
#endif

{ perror(str); exit(-1); } /* PError */

/******************************************************************************/
/*                          D E C R Y P T I O N  /  E N C R Y P T I O N       */
/******************************************************************************/
/* read one data-block from 'inFile'                                          */

#ifdef ANSI_C
  int GetData(Idea_Data data)
#else
  int GetData(data)
  Idea_Data data;
#endif

{ register int i, len;
  register u_int16 h;
  register u_int8 *inPtr;

  if (inBufPos >= inBufLen) {
    if (inBufLen != maxBufLen) return 0;
    inBufLen = fread(inBuf, 1, maxBufLen, inFile);
    inBufPos = 0;
    if (inBufLen == 0) return 0;
    if (inBufLen % Idea_dataSize != 0)
      for (i = inBufLen; i % Idea_dataSize != 0; i++) inBuf[i] = 0;
  }
  inPtr = &inBuf[inBufPos];
  for (i = 0; i < Idea_dataLen; i++) {
    h = ((u_int16)*inPtr++ & 0xFF) << 8;
    data[i] = h | (u_int16)*inPtr++ & 0xFF;
  }
  inBufPos += Idea_dataSize;
  if (inBufPos <= inBufLen) len = Idea_dataSize;
  else len = inBufLen + Idea_dataSize - inBufPos;
  inputLen += len;
  return len;
} /* GetData */

/******************************************************************************/
/* write one data-block to 'outFile'                                          */

#ifdef ANSI_C
  void PutData(Idea_Data data, int len)
#else
  PutData(data, len)
  Idea_Data data;
  int len;
#endif

{ register int i;
  register u_int16 h;
  register u_int8 *outPtr;

  outPtr = &outBuf[outBufLen];
  for (i = 0; i < Idea_dataLen; i++) {
    h = data[i];
    *outPtr++ = h >> 8 & 0xFF;
    *outPtr++ = h & 0xFF;
  }
  outBufLen += len;
  if (outBufLen >= maxBufLen) {
    fwrite(outBuf, 1, maxBufLen, outFile);
    outBufLen = 0;
  }
} /* PutData */

/******************************************************************************/
/* write last block to 'outFile' and close 'outFile'                          */

#ifdef ANSI_C
  void CloseOutput(void)
#else
  CloseOutput()
#endif

{ if (outBufLen > 0) {
    fwrite(outBuf, 1, outBufLen, outFile);
    outBufLen = 0;
  }
  fclose(outFile);
} /* CloseOutput */

/******************************************************************************/
/* increment time_0 and time_N                                                */

#ifdef ANSI_C
  void IncTime(void)
#else
  IncTime()
#endif

{ time_0 = (time_0 + 1) % maxInterleave;
  time_N = (time_N + 1) % maxInterleave;
} /* IncTime */

/******************************************************************************/
/* encrypt one data-block                                                     */

#ifdef ANSI_C
  void EncryptData(Idea_Data data)
#else
  EncryptData(data)
  Idea_Data data;
#endif

{ int i;

  switch (mode) {
    case ecb:
      Idea_Crypt(data, data, key);
      break;
    case cbc:
      for (i = Idea_dataLen - 1; i >= 0; i--) data[i] ^= state[time_N][i];
      Idea_Crypt(data, data, key);
      for (i = Idea_dataLen - 1; i >= 0; i--) state[time_0][i] = data[i];
      IncTime();
      break;
    case cfb:
      Idea_Crypt(state[time_N], state[time_0], key);
      for (i = Idea_dataLen - 1; i >= 0; i--)
        data[i] = state[time_0][i] ^= data[i];
      IncTime();
      break;
    case ofb:
      Idea_Crypt(state[time_N], state[time_0], key);
      for (i = Idea_dataLen - 1; i >= 0; i--) data[i] ^= state[time_0][i];
      IncTime();
      break;
    default: break;
  }
} /* EncryptData */

/******************************************************************************/
/* decrypt one data-block                                                     */

#ifdef ANSI_C
  void DecryptData(Idea_Data data)
#else
  DecryptData(data)
  Idea_Data data;
#endif

{ int i;

  switch (mode) {
    case ecb:
      Idea_Crypt(data, data, key);
      break;
    case cbc:
      for (i = Idea_dataLen - 1; i >= 0; i--) state[time_0][i] = data[i];
      Idea_Crypt(data, data, key);
      for (i = Idea_dataLen - 1; i >= 0; i--) data[i] ^= state[time_N][i];
      IncTime();
      break;
    case cfb:
      for (i = Idea_dataLen - 1; i >= 0; i--) state[time_0][i] = data[i];
      Idea_Crypt(state[time_N], data, key);
      for (i = Idea_dataLen - 1; i >= 0; i--) data[i] ^= state[time_0][i];
      IncTime();
      break;
    case ofb:
      Idea_Crypt(state[time_N], state[time_0], key);
      for (i = Idea_dataLen - 1; i >= 0; i--) data[i] ^= state[time_0][i];
      IncTime();
      break;
    default: break;
  }
} /* DecryptData */

/******************************************************************************/
/* hash one data-block                                                        */

#ifdef ANSI_C
  void HashData(Idea_Data data)
#else
  HashData(data)
  Idea_Data data;
#endif

{ int i;
  Idea_UserKey userKey;
  Idea_Key key;
  Idea_Data w;

  for (i = Idea_dataLen - 1; i >= 0; i--) { 
    userKey[i] = hashLow[i];
    userKey[i + Idea_dataLen] = data[i]; 
  }
  Idea_ExpandUserKey(userKey, key);
  Idea_Crypt(hashHigh, w, key);
  if (mode == abr) {
    for (i = Idea_dataLen - 1; i >= 0; i--) { 
      userKey[i] = data[i];
      userKey[i + Idea_dataLen] = hashHigh[i]; 
      hashHigh[i] ^= w[i];
      w[i] = hashLow[i] ^ 0xFFFF;
    }
  }
  else { /* mode == tan */
    for (i = Idea_dataLen - 1; i >= 0; i--) {
      hashHigh[i] ^= w[i];
      userKey[i] = data[i];
      userKey[i + Idea_dataLen] = w[i];
      w[i] = hashLow[i];
    }
  }
  Idea_ExpandUserKey(userKey, key);
  Idea_Crypt(w, w, key);
  for (i = Idea_dataLen - 1; i >= 0; i--) hashLow[i] ^= w[i];
} /* HashData */

/******************************************************************************/
/* write the hash value to 'hashFile'                                         */

#ifdef ANSI_C
  void WriteHashValue(void)
#else
  WriteHashValue()
#endif

{ int i;

  for (i = 0; i < Idea_dataLen; i++) fprintf(hashFile, "%04X", hashHigh[i]);
  for (i = 0; i < Idea_dataLen; i++) fprintf(hashFile, "%04X", hashLow[i]);
} /* WriteHashValue */

/******************************************************************************/
/* store integer 'value' in 'data'                                            */

#ifdef ANSI_C
  void PlainLenToData(u_int32 value, Idea_Data data)
#else
  PlainLenToData(value, data)
  u_int32 value;
  Idea_Data data;
#endif

{ data[3] = (u_int16)(value << 3 & 0xFFFF);
  data[2] = (u_int16)(value >> 13 & 0xFFFF);
  data[1] = (u_int16)(value >> 29 & 0x0007);
  data[0] = 0;
} /* PlainLenToData */

/******************************************************************************/
/* extract integer 'value' from 'data'                                        */

#ifdef ANSI_C
  void DataToPlainLen(Idea_Data data, u_int32 *value)
#else
  DataToPlainLen(data, value)
  Idea_Data data;
  u_int32 *value;
#endif

{ if (data[0] || data[1] > 7 || data[3] & 7)
    Error(0, "input is not a valid cryptogram");
  *value = (u_int32)data[3] >> 3 & 0x1FFF |
           (u_int32)data[2] << 13 |
           (u_int32)data[1] << 29;
} /* DataToPlainLen */

/******************************************************************************/
/* copy head and color-map of rasterfile from 'inFile' to 'outFile'           */

#ifdef ANSI_C
  void CopyHeadOfRasFile(void)
#else
  CopyHeadOfRasFile()
#endif

{
#ifdef RASTERFILE
  struct rasterfile header;
  int mapLen, len;

  if (fread(&header, sizeof header, 1, inFile) != 1)
    PError("read header from rasterfile");
  if (header.ras_magic != RAS_MAGIC)
    Error(1, "input is not a rasterfile");
  if (fwrite(&header, sizeof header, 1, outFile) != 1)
    PError("write header to rasterfile");
  len = maxBufLen;
  for (mapLen = header.ras_maplength; mapLen > 0; mapLen -= len){
    if (mapLen < maxBufLen) len = mapLen;
    if (fread(inBuf, len, 1, inFile) != 1) PError("read map from rasterfile");
    if (fwrite(inBuf, len, 1, outFile) != 1) PError("write map to rasterfile");
  }
#endif
} /* CopyHeadOfRasFile */

/******************************************************************************/
/* encrypt / decrypt complete data-stream or compute hash value of data-stream*/

#ifdef ANSI_C
  void CryptData(void)
#else
  CryptData()
#endif

{ int t, i;
  u_int32 len;
  Idea_Data dat[4];
  Idea_Data data;

  if (optRas) {
    CopyHeadOfRasFile();
    if (optEncrypt) /* encrypt rasterfile */
      while ((len = GetData(data)) == Idea_dataSize) {
        EncryptData(data); 
        PutData(data, Idea_dataSize); 
      } 
    else /* decrypt rasterfile */
      while ((len = GetData(data)) == Idea_dataSize) {
        DecryptData(data); 
        PutData(data, Idea_dataSize); 
      } 
    if (len) PutData(data, len);
    CloseOutput();
  }
  else if (optEncrypt) { /* encrypt data */
    while ((len = GetData(data)) == Idea_dataSize) {
      EncryptData(data); 
      PutData(data, Idea_dataSize); 
    }
    if (len) { EncryptData(data); PutData(data, Idea_dataSize); }
    PlainLenToData(inputLen, data);
    EncryptData(data);
    PutData(data, Idea_dataSize);
    CloseOutput();
  }
  else if (optDecrypt) { /* decrypt data */
    if ((len = GetData(dat[0])) != Idea_dataSize) {
      if (len) Error(2, "input is not a valid cryptogram");
      else Error(3, "there are no data to decrypt");
    }
    DecryptData(dat[0]);
    if ((len = GetData(dat[1])) != Idea_dataSize) {
      if (len) Error(4, "input is not a valid cryptogram");
      DataToPlainLen(dat[0], &len);
      if (len) Error(5, "input is not a valid cryptogram");
    }
    else {
      DecryptData(dat[1]);
      t = 2;
      while ((len = GetData(dat[t])) == Idea_dataSize) {
        DecryptData(dat[t]);
        PutData(dat[(t + 2) & 3], Idea_dataSize);
        t = (t + 1) & 3;
      }
      if (len) Error(6, "input is not a valid cryptogram");
      DataToPlainLen(dat[(t + 3) & 3], &len);
      len += 2 * Idea_dataSize;
      if (inputLen < len && len <= inputLen + Idea_dataSize) {
        len -= inputLen;
        PutData(dat[(t + 2) & 3], len);
      }
      else Error(7, "input is not a valid cryptogram");
    }
    CloseOutput();
  }
  else { /* compute hash value */
    for (i = Idea_dataLen - 1; i >= 0; i--) {
      hashHigh[i] = userKey[i];
      hashLow[i] = userKey[i + Idea_dataLen];
    }
    if (optCopyHash) { 
      while ((len = GetData(data)) == Idea_dataSize) {
        HashData(data); 
        PutData(data, Idea_dataSize); 
      }
      if (len) { HashData(data); PutData(data, len); }
      PlainLenToData(inputLen, data);
      HashData(data);
      CloseOutput();
    }
    else { /* optHash */
      while ((len = GetData(data)) == Idea_dataSize) HashData(data); 
      if (len) HashData(data);
      PlainLenToData(inputLen, data);
      HashData(data);
    }
    WriteHashValue();
  }
} /* CryptData */

/******************************************************************************/
/* measure the time to encrypt 'nofTestData' data-blocks                      */

#ifdef ANSI_C
  void TimeTest(void)
#else
  TimeTest()
#endif

{
#ifdef TIME
  clock_t startTime, endTime;
  float size, duration;
  Idea_Data data;
  Idea_Key key;
  int i;

  for (i = 0; i < Idea_dataLen; i++) data[i] = 7 * Idea_dataLen - i;
  for (i = 0; i < Idea_keyLen; i++) key[i] = 2 * Idea_keyLen - i;
  for (i = Idea_keyLen - Idea_dataLen; i >= 0; i -= Idea_dataLen)
    Idea_Crypt(&key[i], &key[i], key);
  if ((startTime = clock()) == -1) PError("start timer");
  for (i = nofTestData; i != 0; i--) Idea_Crypt(data, data, key);
  if ((endTime = clock()) == -1) PError("stop timer");
  size = (float)nofTestData * (float)Idea_dataSize / 131072.0;
  duration = (float)(endTime - startTime) / (float)CLK_TCK;
  fprintf(stderr, 
    "time needed to encrypt %4.1f MBit of data was %4.1f seconds (%6.3f Mb/s)\n"
    , size, duration, size / duration);
#endif
} /* TimeTest */

/******************************************************************************/
/*                          I N I T I A L I Z A T I O N                       */
/******************************************************************************/
/* set option to TRUE                                                         */

#ifdef ANSI_C
  void SetOption(int *option)
#else
  SetOption(option)
  int *option;
#endif

{ if (*option) UsageError(10);
  *option = TRUE;
} /* SetOption */

/******************************************************************************/
/* set encryption / decryption mode                                           */

#ifdef ANSI_C
  void SetMode(int newMode, char **str)
#else
  SetMode(newMode, str)
  int newMode;
  char **str;
#endif

{ if (mode != nomode) UsageError(11);
  mode = newMode;
  (*str)++; (*str)++;
  if (newMode == cbc || newMode == cfb || newMode == ofb) {
    if ('0' <= **str && **str <= '9') {
      interleave = 0;
      do {
        interleave = 10 * interleave + (**str - '0');
        if (interleave >= maxInterleave)
          Error(12, "interleave factor is too large");
        (*str)++;
      } while ('0' <= **str && **str <= '9');
      if (interleave == 0) Error(13, "interleave factor is zero");
    }
    else interleave = 1;
  }
} /* SetMode */

/******************************************************************************/
/* read options from string 'str'                                             */

#ifdef ANSI_C
  void ReadOptions(char *str, int *readKeyString, int *readKeyHexString)
#else
  ReadOptions(str, readKeyString, readKeyHexString)
  char *str;
  int *readKeyString;
  int *readKeyHexString;
#endif

{ char ch;

  str++;
  *readKeyString = *readKeyHexString = FALSE;
  while((ch = *str++) != '\0') {
    switch (ch) {
      case 'a':
        if (str[0] == 'b' && str[1] == 'r') SetMode(abr, &str);
        else UsageError(14);
        break;
      case 'c':
        if (str[0] == 'b' && str[1] == 'c') SetMode(cbc, &str);
        else if (str[0] == 'f' && str[1] == 'b') SetMode(cfb, &str);
        else UsageError(15);
        break;
      case 'd': SetOption(&optDecrypt); break;
      case 'e': 
        if (str[0] == 'c' && str[1] == 'b') SetMode(ecb, &str);
        else SetOption(&optEncrypt);
        break;
      case 'h': SetOption(&optHash); break;
      case 'H': SetOption(&optCopyHash); break;
      case 'o':
        if (str[0] == 'f' && str[1] == 'b') SetMode(ofb, &str);
        else UsageError(16);
        break;
      case 'k': SetOption(&optKeyString); *readKeyString = TRUE; break;
      case 'K': SetOption(&optKeyHexString); *readKeyHexString = TRUE; break;
      case 't':
        if (str[0] == 'a' && str[1] == 'n') SetMode(tan, &str);
        else UsageError(17);
        break;
#ifdef TIME
      case 'T': SetOption(&optTime); break;
#endif
#ifdef RASTERFILE
      case 'r': SetOption(&optRas); break;
#endif
      default: UsageError(18); break;
    }
  }
} /* ReadOptions */

/******************************************************************************/
/* check if options are unique and set default options                        */

#ifdef ANSI_C
  void AdjustOptions(void)
#else
  AdjustOptions()
#endif

{ if (optTime) {
    if (optDecrypt || optEncrypt || optHash || optCopyHash || optKeyString ||
        optKeyHexString || optRas || mode != nomode) UsageError(20);
  }
  else {
    if (optDecrypt && optEncrypt) UsageError(21);
    if (optHash && optCopyHash) UsageError(22);
    if (optKeyString && optKeyHexString) UsageError(23);
    if (!optDecrypt && !optEncrypt && !optHash && !optCopyHash)
      if (mode == tan || mode == abr) SetOption(&optHash);
      else SetOption(&optEncrypt);
    if (optHash || optCopyHash) {
      if (optDecrypt || optEncrypt) UsageError(24);
      if (optRas) UsageError(25);
      if (mode == nomode) mode = tan;
      else if (mode != tan && mode != abr) UsageError(26);
    }
    else {
      if (mode == nomode) { mode = cbc; interleave = 1; }
      else if (mode != ecb && mode != cbc && mode != cfb && mode != ofb)
        UsageError(27);
      if (!optKeyString && !optKeyHexString) UsageError(28);
    }
    time_0 = interleave;
    time_N = 0;
  }
} /* AdjustOptions */

/******************************************************************************/
/* convert a hex-digit into an integer                                        */

#ifdef ANSI_C
  u_int32 HexToInt(char ch)
#else
  u_int32 HexToInt(ch)
  char ch;
#endif

{ if ('0' <= ch && ch <= '9') return ch - '0';
  else if ('a' <= ch  && ch <= 'f') return 10 + (ch - 'a');
  else if ('A' <= ch && ch <= 'F') return 10 + (ch - 'A');
  else if (ch == ':') return colon;
  else if (ch == '\0') return eol;
  else return error;
} /* HexToInt */

/******************************************************************************/
/* convert a character into an integer                                        */

#ifdef ANSI_C
  u_int32 CharToInt(char ch)
#else
  u_int32 CharToInt(ch)
  char ch;
#endif

{ if ('!' <= ch && ch <= '~') return ch - '!';
  else if (ch == '\0') return eol;
  else return error;
} /* CharToInt */

/******************************************************************************/
/* initializes key and initial values                                         */

#ifdef ANSI_C
  void ReadKeyHexString(char *str)
#else
  ReadKeyHexString(str)
  char *str;
#endif

{ int pos, i;
  u_int32 val;

  while ((val = HexToInt(*str++)) < eol) {
    for (i = Idea_userKeyLen - 1; i >= 0; i--) {
      val |= (u_int32)userKey[i] << 4;
      userKey[i] = (u_int16)(val & 0xFFFF);
      val >>= 16;
    }
    if (val) Error(29, "key value is too large");
  }
  for (pos = 0; val == colon && pos < maxInterleave; pos++) {
    while ((val = HexToInt(*str++)) < eol) {
      for (i = Idea_dataLen - 1; i >= 0; i--) {
        val |= (u_int32)state[pos][i] << 4;
        state[pos][i] = (u_int16)(val & 0xFFFF);
        val >>= 16;
      }
      if (val) Error(30, "initial value is too large");
    }
  }
  if (val == colon) Error(31, "too many initial values specified");
  if (val != eol) Error(32, "wrong character in initialization string");
} /* ReadKeyHexString */

/******************************************************************************/
/* initialize key and initial values                                          */

#ifdef ANSI_C
  void ReadKeyString(char *str)
#else
  ReadKeyString(str)
  char *str;
#endif

{ int i;
  u_int32 val;

  while ((val = CharToInt(*str++)) < eol) {
    for (i = Idea_userKeyLen - 1; i >= 0; i--) {
      val += (u_int32)userKey[i] * nofChar;
      userKey[i] = (u_int16)(val & 0xFFFF);
      val >>= 16;
    }
  }
  if (val != eol) Error(32, "wrong character in key string");
} /* ReadKeyString */

/******************************************************************************/
/* show current state informations                                            */

#ifdef ANSI_C
  void ShowState(void)
#else
  ShowState()
#endif

{ int i, j;

  fprintf(stderr, "Mode = {");
  switch (mode) {
    case ecb: fprintf(stderr, "ecb"); break;
    case cbc: fprintf(stderr, "cbc"); break;
    case cfb: fprintf(stderr, "cfb"); break;
    case ofb: fprintf(stderr, "ofb"); break;
    case tan: fprintf(stderr, "tan"); break;
    case abr: fprintf(stderr, "abr"); break;
    case nomode: fprintf(stderr, "nomode"); break;
    default: fprintf(stderr, "!!!wrong mode!!!"); break;
  }
  if (interleave > 0) fprintf(stderr, "%d", interleave);
  if (optEncrypt) fprintf(stderr, ", encrypt");
  if (optDecrypt) fprintf(stderr, ", decrypt");
  if (optHash) fprintf(stderr, ", hash");
  if (optCopyHash) fprintf(stderr, ", copy and hash");
  if (optKeyString) fprintf(stderr, ", key string");
  if (optKeyHexString) fprintf(stderr, ", key hex string");
  if (optRas) fprintf(stderr, ", raster file");
  if (optTime) fprintf(stderr, ", time test");
  fprintf(stderr, "}\n\nKey:\n");
  for (i = 0; i < Idea_keyLen; i++) {
    fprintf(stderr, "%7u<%4x>", key[i], key[i]);
    if ((i % 6) == 5) fprintf(stderr, "\n");
  }
  fprintf(stderr, "\n\nInitial values:");
  for (i = 0; i < interleave; i++) {
    fprintf(stderr, "\n  x[N -%2d] =", i + 1);
    for (j = 0; j < Idea_dataLen; j++)
      fprintf(stderr, "%7u<%4x>", state[i][j], state[i][j]);
  }
  fprintf(stderr, "\n");
} /* ShowState */

/******************************************************************************/
/*                          M A I N - P R O C E D U R E                       */
/******************************************************************************/
#ifdef ANSI_C
  int main(int argc, char *argv[])
#else
  int main(argc, argv)
  int argc;
  char *argv[];
#endif

{ int readKeyString, readKeyHexString;

  Init();
  argv++; argc--;
  while (argc > 0 && argv[0][0] == '-' && argv[0][1] != '\0') {
    ReadOptions(*argv++, &readKeyString, &readKeyHexString); argc--;
    if (readKeyString || readKeyHexString) {
      if (argc <= 0)  Error(36, "missing key on command line");
      else if (readKeyString) { ReadKeyString(*argv++); argc--; }
      else { ReadKeyHexString(*argv++); argc--; }
    }
  }
  AdjustOptions();
  if (optTime && argc > 0 || optCopyHash && argc > 3 || 
      !optCopyHash && argc > 2) Error(37, "too many parameters");
  if (optTime)
    TimeTest();
  else {
    if (argc > 1 && strcmp(argv[0], argv[1]) == 0)
      Error(38, "source and destination are identical");
    if (argc > 2 && strcmp(argv[0], argv[2]) == 0)
      Error(39, "source and destination are identical");
    if (argc > 2 && strcmp(argv[1], argv[2]) == 0)
      Error(40, "destinations are identical");
    inFile = stdin;
    outFile = hashFile = stdout;
    if (argc > 0) {
      if (strcmp(*argv, "-") == 0) { argv++; argc--; }
      else {
        inFile = fopen(*argv++, "rb"); argc--;
        if (inFile == NULL) PError(*--argv);
      }
    }
    if (optCopyHash) {
      if (argc > 1) {
        outFile = fopen(*argv++, "wb"); argc--;
        if (outFile == NULL) PError(*--argv);
      }
      if (argc > 0) {
        hashFile = fopen(*argv++, "wb"); argc--;
        if (hashFile == NULL) PError(*--argv);
      }
      else hashFile = stderr;
    }
    else if (optHash) {
      if (argc > 0) {
        hashFile = fopen(*argv++, "wb"); argc--;
        if (hashFile == NULL) PError(*--argv);
      }
    }
    else {
      if (argc > 0) {
        outFile = fopen(*argv++, "wb"); argc--;
        if (outFile == NULL) PError(*--argv);
      }
    }
    if (argc > 0) Error(41, "too many parameters");
    Idea_ExpandUserKey(userKey, key);
    if (optDecrypt && (mode == ecb || mode == cbc)) Idea_InvertKey(key, key);
#ifdef DEBUG
    ShowState();
#else
    CryptData();
#endif
  }
  return 0;
}
