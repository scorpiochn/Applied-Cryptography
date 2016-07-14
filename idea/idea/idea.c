#include <stdio.h>
#include <string.h>
#include "crypt.h"

#define TRUE                 1 /* boolean constant for true                   */
#define FALSE                0 /* boolean constant for false                  */

#define nomode               0 /* no mode is specified                        */
#define ecb                  1 /* electronic code book mode                   */
#define cbc                  2 /* cipher block chaining mode                  */
#define cfb                  3 /* ciphertext feedback mode                    */
#define ofb                  4 /* output feedback mode                        */
#define tan                  5 /* tandem DM-scheme for hashing                */
#define abr                  6 /* abreast DM-scheme for hashing               */
#define error               -1 /* error constant                              */
#define eol                 -2 /* end of line                                 */
#define colon               -3 /* character ':'                               */
#define maxInterleave     1024 /* maximal interleave factor + 1               */
#define nofChar ('~' - '!' + 1) /* number of different printable characters   */
#define maxBufLen  (dataSize * 1024) /* size of input and output buffer       */

userkey_t(userKey) ;            /* user selected 128 bit key                   */
key_t(key) ;                    /* expanded key with 832 bits                  */
data_t(state[maxInterleave]) ;  /* state informations for interleaving modes   */
data_t(hashLow) ;               /* lower 64 bits of hash value                 */
data_t(hashHigh) ;              /* higher 64 bits of hash value                */

u_int32 inputLen    = 0;       /* current number of bytes read from 'inFile'  */
int interleave      = 0;       /* current interleave factor                   */
int time            = 0;       /* time for interleaving modes                 */
int time_N          = 0;       /* time-interleave for interleaving modes      */
int mode            = nomode;  /* current mode                                */

int optEncrypt      = FALSE;   /* encrypt option 'e'                          */
int optDecrypt      = FALSE;   /* decrypt option 'd'                          */
int optHash         = FALSE;   /* hash option 'h'                             */
int optCopyHash     = FALSE;   /* copy and hash option 'H'                    */
int optKeyHexString = FALSE;   /* key as hex-string option 'K'                */
int optKeyString    = FALSE;   /* key as string option 'k'                    */

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

void Init()

{	int i, pos;

	for (i = 0; i < userKeyLen; i++)
		userKey[i] = 0;
	for (pos = 0; pos < maxInterleave; pos++) {
		for (i = 0; i < dataLen; i++)
			state[pos][i] = 0;
	}
}	/* Init */

/******************************************************************************/
/*                          E R R O R - H A N D L I N G                       */
/******************************************************************************/
/* write usage error message and terminate program                            */

void UsageError(int num)

{
fprintf(stderr, "Usage Error %d\n\
Usage:   idea [ -e | -d ] [ -ecb | -cbcN | -cfbN | -ofbN ]       \n\
              ( -k keyString | -K keyHexString )                 \n\
              [ inputFile [ outputFile ] ]                       \n\
         idea [ -h | -H ] [ -tan | -abr ]                        \n\
              [ -k keyString | -K keyHexString ]                 \n\
              [ inputFile [ [ outputFile ] hashvalFile ] ]       \n\
\nExample: idea -Hk \"k e y\" infile | idea -cbc8 -K 123:9a::eF - outfile\n\
\n");
exit(5);
} /* UsageError */

/******************************************************************************/
/* write error message and terminate program                                  */

void Error(int num, char *str)

{	fprintf(stderr, "ERROR %d in idea: %s\n", num, str); exit(10); } /* Error */

/******************************************************************************/
/* write system error message and terminate program                           */

void PError(char *str)

{	perror(str); exit(20); } /* PError */

/******************************************************************************/
/*                          D E C R Y P T I O N  /  E N C R Y P T I O N       */
/******************************************************************************/
/* read one data-block from 'inFile'                                          */

int GetData(data_t(data))

{	register int i, len;
	register u_int16 h;
	register u_int8 *inPtr;

	if (inBufPos >= inBufLen) {
		if (inBufLen != maxBufLen) return 0;
		inBufLen = fread(inBuf, 1, maxBufLen, inFile);
		inBufPos = 0;
		if (inBufLen == 0) return 0;
		if (inBufLen % dataSize != 0)
			for (i = inBufLen; i % dataSize != 0; i++)
				inBuf[i] = 0;
	}
	inPtr = &inBuf[inBufPos];
	for (i = 0; i < dataLen; i++) {
		h = ((u_int16)(*inPtr++) & 0xFF) << 8;
		data[i] = h | ((u_int16)(*inPtr++) & 0xFF);
	}
	inBufPos += dataSize;
	if (inBufPos <= inBufLen)
		len = dataSize;
	else
		len = inBufLen + dataSize - inBufPos;
	inputLen += len;
	return len;
} /* GetData */

/******************************************************************************/
/* write one data-block to 'outFile'                                          */

void PutData(data_t(data), int len)

{	register int i;
	register u_int16 h;
	register u_int8 *outPtr;

	outPtr = &outBuf[outBufLen];
	for (i = 0; i < dataLen; i++) {
		h = data[i];
		*(outPtr++) = (h >> 8) & 0xFF;
		*(outPtr++) = h & 0xFF;
	}
	outBufLen += len;
	if (outBufLen >= maxBufLen) {
		fwrite(outBuf, 1, maxBufLen, outFile);
		outBufLen = 0;
	}
} /* PutData */

/******************************************************************************/
/* write last block to 'outFile' and close 'outFile'                          */

void CloseOutput()

{	if (outBufLen > 0) {
		fwrite(outBuf, 1, outBufLen, outFile);
		outBufLen = 0;
	}
	close(outFile);
} /* CloseOutput */

/******************************************************************************/
/* increment time and time_N                                                  */

void IncTime()
{	time = (time + 1) % maxInterleave;
	time_N = (time_N + 1) % maxInterleave;
} /* IncTime */

/******************************************************************************/
/* encrypt one data-block                                                     */

void EncryptData(data_t(data))

{	int i;

	switch (mode) {
		case ecb:
			Idea(data, data, key);
			break;
		case cbc:
			for (i = dataLen - 1; i >= 0; i--)
				data[i] ^= state[time_N][i];
			Idea(data, data, key);
			for (i = dataLen - 1; i >= 0; i--)
				state[time][i] = data[i];
			IncTime();
			break;
		case cfb:
			Idea(state[time_N], state[time], key);
			for (i = dataLen - 1; i >= 0; i--)
				data[i] = state[time][i] ^= data[i];
			IncTime();
			break;
		case ofb:
			Idea(state[time_N], state[time], key);
			for (i = dataLen - 1; i >= 0; i--)
				data[i] ^= state[time][i];
			IncTime();
			break;
		default: break;
	}
} /* EncryptData */

/******************************************************************************/
/* decrypt one data-block                                                     */

void DecryptData(data_t(data))

{	int i;

	switch (mode) {
		case ecb:
			Idea(data, data, key);
			break;
		case cbc:
			for (i = dataLen - 1; i >= 0; i--)
				state[time][i] = data[i];
			Idea(data, data, key);
			for (i = dataLen - 1; i >= 0; i--)
				data[i] ^= state[time_N][i];
			IncTime();
			break;
		case cfb:
			for (i = dataLen - 1; i >= 0; i--)
				state[time][i] = data[i];
			Idea(state[time_N], data, key);
			for (i = dataLen - 1; i >= 0; i--)
				data[i] ^= state[time][i];
			IncTime();
			break;
		case ofb:
			Idea(state[time_N], state[time], key);
			for (i = dataLen - 1; i >= 0; i--)
				data[i] ^= state[time][i];
			IncTime();
			break;
		default: break;
	}
} /* DecryptData */

/******************************************************************************/
/* hash one data-block                                                        */

void HashData(data_t(data))

{	int i;
	userkey_t(userKey);
	key_t(key);
	data_t(w);

	for (i = dataLen - 1; i >= 0; i--) {
		userKey[i] = hashLow[i];
		userKey[i + dataLen] = data[i];
	}
	ExpandUserKey(userKey, key);
	Idea(hashHigh, w, key);
	if (mode == abr) {
		for (i = dataLen - 1; i >= 0; i--) {
			userKey[i] = data[i];
			userKey[i + dataLen] = hashHigh[i];
			hashHigh[i] ^= w[i];
			w[i] = ~ hashLow[i];
		}
	}
	else { /* mode == tan */
		for (i = dataLen - 1; i >= 0; i--) {
			hashHigh[i] ^= w[i];
			userKey[i] = data[i];
			userKey[i + dataLen] = w[i];
			w[i] = hashLow[i];
		}
	}
	ExpandUserKey(userKey, key);
	Idea(w, w, key);
	for (i = dataLen - 1; i >= 0; i--)
		hashLow[i] ^= w[i];
} /* HashData */

/******************************************************************************/
/* write value of a 16-bit unsigned integer in hex format to 'hashFile'       */

void WriteHex(u_int16 val)

{	char str[8];
	int i;

	sprintf(str, "%4X", val);
	for (i = 0; i < 4; i++)
		if (str[i] == ' ')
			str[i] = '0';
	fprintf(hashFile, "%s", str);
} /* WriteHex */

/******************************************************************************/
/* write the hash value to 'hashFile'                                         */

void WriteHashValue()

{	int i;

	for (i = 0; i < dataLen; i++) WriteHex(hashHigh[i]);
	for (i = 0; i < dataLen; i++) WriteHex(hashLow[i]);
} /* WriteHashValue */

/******************************************************************************/
/* store integer 'value' in 'data'                                            */

void PlainLenToData(u_int32 value, data_t(data))

{	data[3] = (u_int16)((value << 3) & 0xFFFF);
	data[2] = (u_int16)((value >> 13) & 0xFFFF);
	data[1] = (u_int16)((value >> 29) & 0x0007);
	data[0] = 0;
} /* PlainLenToData */

/******************************************************************************/
/* extract integer 'value' from 'data'                                        */

void data_toPlainLen(data_t(data), u_int32 *value)

{	if ((data[0] != 0) || (data[1] > 7) || ((data[3] & 7) != 0))
		Error(1, "input is not a valid cryptogram");
	*value = ((u_int32)(data[3]) >> 3) & 0x1FFF |
		((u_int32)(data[2]) << 13) |
		((u_int32)(data[1]) << 29);
} /* data_toPlainLen */

/******************************************************************************/
/* encrypt / decrypt complete data-stream or compute hash value of data-stream*/

void CryptData()

{	int t, i;
	u_int32 len;
	data_t(dat[4]);
	data_t(data);

	if (optEncrypt) { /* encrypt data */
		while ((len = GetData(data)) == dataSize) {
			EncryptData(data);
			PutData(data, dataSize);
		}
		if (len > 0) {
			EncryptData(data);
			PutData(data, dataSize);
		}
		PlainLenToData(inputLen, data);
		EncryptData(data);
		PutData(data, dataSize);
		CloseOutput();
	}
	else if (optDecrypt) { /* decrypt data */
		if ((len = GetData(dat[0])) != dataSize) {
			if (len != 0)
				Error(2, "input is not a valid cryptogram");
			else
				Error(3, "there are no data to decrypt");
		}
		DecryptData(dat[0]);
		if ((len = GetData(dat[1])) != dataSize) {
			if (len != 0)
				Error(4, "input is not a valid cryptogram");
			data_toPlainLen(dat[0], &len);
			if (len != 0)
				Error(5, "input is not a valid cryptogram");
		}
		else {
			DecryptData(dat[1]);
			t = 2;
			while ((len = GetData(dat[t])) == dataSize) {
				DecryptData(dat[t]);
				PutData(dat[(t + 2) & 3], dataSize);
				t = (t + 1) & 3;
			}
			if (len != 0)
				Error(6, "input is not a valid cryptogram");
			data_toPlainLen(dat[(t + 3) & 3], &len);
			len += 2 * dataSize;
			if ((inputLen < len) && (len <= inputLen + dataSize)) {
				len -= inputLen;
				PutData(dat[(t + 2) & 3], len);
			}
			else
				Error(7, "input is not a valid cryptogram");
		}
		CloseOutput();
	}
	else { /* compute hash value */
		for (i = dataLen - 1; i >= 0; i--) {
			hashHigh[i] = userKey[i];
			hashLow[i] = userKey[i + dataLen];
		}
		if (optCopyHash) {
			while ((len = GetData(data)) == dataSize) {
				HashData(data);
				PutData(data, dataSize);
			}
			if (len > 0) {
				HashData(data);
				PutData(data, len);
			}
			PlainLenToData(inputLen, data);
			HashData(data);
			CloseOutput();
		}
		else { /* optHash */
			while ((len = GetData(data)) == dataSize)
				HashData(data); 
			if (len > 0)
				HashData(data);
			PlainLenToData(inputLen, data);
			HashData(data);
		}
		WriteHashValue();
	}
} /* CryptData */


/******************************************************************************/
/*                          I N I T I A L I Z A T I O N                       */
/******************************************************************************/
/* set option to TRUE                                                         */

void SetOption(int *option)

{	if (*option)
		UsageError(8);
	*option = TRUE;
} /* SetOption */

/******************************************************************************/
/* set encryption / decryption mode                                           */

void SetMode(int newMode, char **str)

{	if (mode != nomode)
		UsageError(9);
	mode = newMode;
	(*str)++;
	(*str)++;
	if ((newMode == cbc) || (newMode == cfb) || (newMode == ofb)) {
		if (('0' <= **str) && (**str <= '9')) {
			interleave = 0;
			do {
				interleave = 10 * interleave + (**str - '0');
				if (interleave >= maxInterleave)
					Error(10, "interleave factor is too large");
				(*str)++;
			} while (('0' <= **str) && (**str <= '9'));
			if (interleave == 0)
				Error(11, "interleave factor is zero");
		}
		else interleave = 1;
	}
} /* SetMode */

/******************************************************************************/
/* read options from string 'str'                                             */

void ReadOptions(char *str, int *readKeyString, int *readKeyHexString)

{	char ch;

	str++;
	*readKeyString = *readKeyHexString = FALSE;
	while((ch = *(str++)) != 0) {
		switch (ch) {
			case 'a':
				if ((str[0] == 'b') && (str[1] == 'r'))
					SetMode(abr, &str);
				else
					UsageError(12);
				break;
			case 'c':
				if ((str[0] == 'b') && (str[1] == 'c'))
					SetMode(cbc, &str);
				else if ((str[0] == 'f') && (str[1] == 'b'))
					SetMode(cfb, &str);
				else
					UsageError(13);
				break;
			case 'd':
				SetOption(&optDecrypt);
				break;
			case 'e': 
				if ((str[0] == 'c') && (str[1] == 'b'))
					SetMode(ecb, &str);
				else
					SetOption(&optEncrypt);
				break;
			case 'h':
				SetOption(&optHash);
				break;
			case 'H':
				SetOption(&optCopyHash);
				break;
			case 'o':
				if ((str[0] == 'f') && (str[1] == 'b'))
					SetMode(ofb, &str);
				else
					UsageError(14);
				break;
			case 'k':
				SetOption(&optKeyString);
				*readKeyString = TRUE;
				break;
			case 'K':
				SetOption(&optKeyHexString);
				*readKeyHexString = TRUE;
				break;
			case 't':
				if ((str[0] == 'a') && (str[1] == 'n'))
					SetMode(tan, &str);
				else
					UsageError(15);
				break;
			default:
				UsageError(16);
				break;
		}
	}
	if (*readKeyString && *readKeyHexString)
		UsageError(17);
} /* ReadOptions */

/******************************************************************************/
/* check if options are unique and set default options                        */

void AdjustOptions()

{	if (optDecrypt && optEncrypt)
		UsageError(18);
	if (optHash && optCopyHash)
		UsageError(19);
	if (optKeyString && optKeyHexString)
		UsageError(20);
	if (optDecrypt || optEncrypt) {
		if (optHash || optCopyHash)
			UsageError(21);
		if ((! optKeyString) && (! optKeyHexString))
			UsageError(22);
		if (mode == nomode) {
			mode = cbc;
			interleave = 1;
		}
		else if ((mode == tan) || (mode == abr))
			UsageError(23);
	}
	else {
		if (optHash || optCopyHash) {
			if (mode == nomode)
				mode = tan;
			else if ((mode != tan) && (mode != abr))
				UsageError(24);
		}
		else {
			if (mode == nomode) {
				mode = cbc;
				interleave = 1;
			}
			if ((mode == tan) || (mode == abr))
				SetOption(&optHash);
			else
				SetOption(&optEncrypt);
		}
	}
	time = interleave;
	time_N = 0;
}	/* AdjustOptions */

/******************************************************************************/
/* convert a hex-digit into an integer                                        */

int HexToInt(char ch)

{
	if (('0' <= ch) && (ch <= '9'))
		return ch - '0';
	else if (('a' <= ch)  && (ch <= 'f'))
		return 10 + (ch - 'a');
	else if (('A' <= ch) && (ch <= 'F'))
		return 10 + (ch - 'A');
	else if (ch == ':')
		return colon;
	else if (ch == 0)
		return eol;
	else
		return error;
} /* HexToInt */

/******************************************************************************/
/* convert a character into an integer                                        */

int32 CharToInt(char ch)

{
	if (('!' <= ch) && (ch <= '~'))
		return ch - '!';
	else if (ch == 0)
		return eol;
	else
		return error;
} /* CharToInt */

/******************************************************************************/
/* initializes key and initial values                                         */

void ReadKeyHexString(char *str)

{	int i, pos;
	int32 h, val;

	while ((val = HexToInt(*(str++))) >= 0) {
		for (i = userKeyLen - 1; i >= 0; i--) {
			h = ((int32)(userKey[i]) >> 12) & 0xF;
			userKey[i] = ((int32)(userKey[i]) << 4) | val;
			val = h;
		}
		if (val != 0)
			Error(25, "key value is too large");
	}
	pos = 0;
	while ((val == colon) && (pos < maxInterleave)) {
		val = HexToInt(*(str++));
		while (val >= 0) {
			for (i = dataLen - 1; i >= 0; i--) {
				h = ((int32)(state[pos][i]) >> 12) & 0xF;
				state[pos][i] = ((int32)(state[pos][i]) << 4) | val;
				val = h;
			}
			if (val != 0)
				Error(26, "initial value is too large");
			val = HexToInt(*(str++));
		}
		pos++;
	}
	if (val == colon)
		Error(27, "too many initial values specified");
	if (val != eol)
		Error(28, "wrong character in initialization string");
} /* ReadKeyHexString */

/******************************************************************************/
/* initialize key and initial values                                          */

void ReadKeyString(char *str)

{	int i;
	int32 h, val;

	while ((val = CharToInt(*(str++))) >= 0) {
		for (i = userKeyLen - 1; i >= 0; i--) {
			h = (int32)(userKey[i]) * nofChar + val;
			userKey[i] = h & 0xFFFF;
			val = h >> 16;
		}
	}
} /* ReadKeyString */


/******************************************************************************/
/*                          M A I N - P R O C E D U R E                       */
/******************************************************************************/
main(int argc, char *argv[])

{	int readKeyString, readKeyHexString;

	Init();
	argv++; 
	argc--;
	if ((argc == 0) || (*(argv[0]) == '?'))
		UsageError(0);
	while ((argc > 0) && (*(argv[0]) == '-') && (*(argv[0]+1) != '\0')) {
		ReadOptions(*argv++, &readKeyString, &readKeyHexString);
		argc--;
		if (readKeyString || readKeyHexString) {
			if (argc <= 0)
				Error(29, "missing key on command line");
			else if (readKeyString) {
				ReadKeyString(*(argv++));
				argc--;
			}
			else {
				ReadKeyHexString(*(argv++));
				argc--;
			}
		}
	}
	AdjustOptions();
	if ((optCopyHash && (argc > 3)) || (! optCopyHash && (argc > 2)))
		Error(30, "too many parameters");
	if ((argc > 1) && (strcmp(argv[0], argv[1]) == 0))
		Error(31, "source and destination are identical");
	if ((argc > 2) && (strcmp(argv[0], argv[2]) == 0))
		Error(32, "source and destination are identical");
	if ((argc > 2) && (strcmp(argv[1], argv[2]) == 0))
		Error(33, "destinations are identical");
	inFile = stdin;
	outFile = hashFile = stdout;
	if (argc > 0) {
		if (strcmp(*argv, "-") == 0) {
			argv++;
			argc--;
		}
		else {
			inFile = fopen(*argv++, "r");
			argc--;
			if (inFile == 0)
				PError(*--argv);
		}
	}
	if (optCopyHash) {
		if (argc > 1) {
			outFile = fopen(*argv++, "w");
			argc--;
			if (outFile == 0)
				PError(*--argv);
		}
		if (argc > 0) {
			hashFile = fopen(*argv++, "w");
			argc--;
			if (hashFile == 0)
			PError(*--argv);
		}
		else
			hashFile = stderr;
	}
	else if (optHash) {
		if (argc > 0) {
			hashFile = fopen(*argv++, "w");
			argc--;
			if (hashFile == 0)
				PError(*--argv);
		}
	}
	else {
		if (argc > 0) {
			outFile = fopen(*argv++, "w");
			argc--;
			if (outFile == 0)
				PError(*--argv);
		}
	}
	if (argc > 0)
		Error(34, "too many parameters");
	ExpandUserKey(userKey, key);
	if (optDecrypt && ((mode == ecb) || (mode == cbc)))
		InvertIdeaKey(key, key);
	CryptData();
	exit(0);
}
