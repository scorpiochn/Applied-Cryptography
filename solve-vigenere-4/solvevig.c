/*-- solvevig.c -- Find possible solutions to a Vigenere cipher.
 *
 *  Mark Riordan  11 Jan 91
 */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "rdditbl.h"
#include "p.h"

#define DEBUG 1
char *msg[] = {
"Program to help break Vigenere ciphers.",
"Usage:  solvevig -w wordlist [-c ciphertextfile] [-p maxp] [-P] [-t top#]",
" [-s] [-d digramfile] [-S status_every_#] [-D debug#]",
" where",
"   -w wordlist is a list of words to try for the key,",
"            one word per line, in lower case.",
"   -c ciphertextfile  is the file containing the ciphertext",
"            (defaults to stdin).  Can be mixed case.",
"   -P       means print the potential plaintext and other info",
"            for each word in the wordlist (very long!).",
"   -p maxp  means in the final output, print the first maxp characters",
"            of each potential plaintext.  Default is 45.",
"   -t top#  means we should display the top top# best potential keys.",
"            Default is 20.",
"   -s       means minimize the sum of squares of differences in freq,",
"            rather than just the sum of deviations.",
"   -S everyw specifies that solvevig should print a status message",
"            every 'everyw' words.",
"   -D debug# is the debug print level.  Default is 0 (none).",
"   -d digramfile is a file containing digram counts.  Each line contains:",
"            columns 1-2: the digram, lowercase.",
"            column    3: space",
"            columns 4-n: Absolute digram count",
"            (See the program builddig.)",
"            If not specified, digram frequencies are not used.",
" solvevig tests for valid plaintext by testing potential",
" plaintext from each word in the wordlist against known statistical",
" properties of the English language.  When all potential keys",
" have been tested, the results of the top 20 best candidates",
" are listed",
NULL };

static char *author = "Mark Riordan  1100 Parker  Lansing MI  48912  Jan 91";

#define DIGRAMSPER 100000
#define LARGEVAL   999999999L
#define ALFASIZE 26
#define MAXKEYSIZE 40

char VigTable[ALFASIZE][CHARSETSIZE];

/* Array containing frequencies of digrams in general English text
 * (or whatever), as read in from file.
 */
unsigned long int MasterDigramFreqs[CHARSETSIZE][CHARSETSIZE];

/* Arrays containing plaintext stats for current trial key. */
long int CharCount[CHARSETSIZE];
unsigned long int DigramCount[CHARSETSIZE][CHARSETSIZE];
long int TotalDigrams;

int MaxPlainPrint = 45;
int MaxKeys = 20;
int UseSquares = 0;
int UseDigrams = 0;
int Debug = 0;
FILE *DStream = stderr;

typedef struct struct_key {
	long int           sk_close;
	char               sk_key[MAXKEYSIZE];
	struct struct_key *sk_prev;
	struct struct_key *sk_next;
} typ_key;

typ_key *BegKeyList, *EndKeyList;

/* This array contains character frequencies of English, per 10000
 * characters.  I lifted it from some classical text, perhaps
 * Gaines' Elementary Cryptanalysis.
 */
struct freqstruct {
  char      f_ch;
  int       f_freq;
} freqs[] = {
  'e',1231,
  't', 959,
  'a', 805,
  'o', 794,
  'n', 719,
  'i', 718,
  's', 659,
  'r', 603,
  'h', 514,
  'l', 403,
  'd', 365,
  'c', 320,
  'u', 310,
  'p', 229,
  'f', 228,
  'm', 225,
  'w', 203,
  'y', 188,
  'b', 162,
  'g', 161,
  'v',  93,
  'k',  52,
  'q',  20,
  'x',  20,
  'j',  10,
  'z',   9,
  '\0',  0 };

/* Function prototypes */
long int ComputeCloseness P((int cipchars));
void ClearCount P((void));
void DumpKeyList P((typ_key *keyptr, char *ciphertext));


main(argc,argv)
int argc;
char *argv[];
{
#define LINESIZE 80
#define MSGSIZE  20000

   char curkey[LINESIZE];
	int keyint[40];
   typ_key *keyptr, *lastkeyptr, *insertkeyptr;
	int nkey,jch, ordch, jkey, j;
   int cipchars=0;
	char *cptr, outch1, outch2, *ciphertext;

	int ch;
   extern char *optarg;
   FILE *dictstream, *cipfilestream = stdin;
   char *dictfilename = 0, *cipfilename = 0, *digramfilename = 0;
   int argerror = 0, printplain = 0;
   long int closeness, StatusEvery=0, WordsUntilStatus, Nwords=0;

	/* Crack the command line */
   while(EOF != (ch = getopt(argc,argv,"w:c:p:Pt:sd:S:D:"))) {
      switch(ch) {
         case 'w':
            dictfilename = optarg;
            break;

         case 'c':
            cipfilename = optarg;
            break;
				
			case 'd':
				digramfilename = optarg;
				UseDigrams = 1;
				break;

         case 'P':
            printplain = 1;
            break;

			case 't':
				MaxKeys = atoi(optarg);
				if(MaxKeys <= 0) argerror = 1;
				break;

			case 'p':
				MaxPlainPrint = atoi(optarg);
				if(MaxPlainPrint <= 0) argerror = 1;
				break;
				
			case 's':
				UseSquares = 1;
				break;
				
			case 'S':
				StatusEvery = atoi(optarg);
				Nwords = 0;
				WordsUntilStatus = StatusEvery;
				break;
				
			case 'D':
				Debug = atoi(optarg);
				break;

         default:
				fprintf(stderr,"Bad argument: '%c'\n",ch);
            argerror = 1;
      }
   }

   if(!dictfilename || argerror) {
      usage(NULL,msg);
      exit(1);
   }

   cptr = ciphertext = (char *) malloc(MSGSIZE);
   if(!ciphertext) {
      fputs("Unable to allocate memory.\n",stderr);
      exit(1);
   }
	
	/* If a digram file was specified, read it in. */
	if(digramfilename) {
		if(Debug) {
			fprintf(DStream,"sizeof MasterDigramFreqs = %d\n",
				sizeof(MasterDigramFreqs));
		}
		if(ReadDigramTable(digramfilename, MasterDigramFreqs, &TotalDigrams)) {
			fputs("Can't read digram file.\n",stderr);
			return 1;
		}
		AdjustDigramFreq(MasterDigramFreqs,TotalDigrams,DIGRAMSPER);
	}

	/* Open ciphertext file and read into memory */
   if(cipfilename) {
      cipfilestream = fopen(cipfilename,"r");
      if(!cipfilestream) {
         fprintf(stderr,"Unable to open %s\n",cipfilename);
         exit(2);
      }
   }
   while(EOF != (jch = fgetc(cipfilestream))) {
		if(isalpha(jch)) {
 	    	*(cptr++) = jch;
  	   	cipchars++;
		}
   }
   *cptr = '\0';

   cipchars = strlen(ciphertext);

	/* Initialize the list of current best keyword guesses. */
   keyptr = EndKeyList = (typ_key *) malloc(sizeof(typ_key));
	if(!keyptr) {
		fputs("Can't allocate EndKeyList\n",stderr);
		return 3;
	}
   lastkeyptr = (typ_key *) 0;
   for(j=0; j<MaxKeys; j++) {
      keyptr->sk_close = LARGEVAL;
      keyptr->sk_key[0] = '\0';
      keyptr->sk_next = lastkeyptr;
      lastkeyptr = keyptr;

      keyptr = (typ_key *) malloc(sizeof(typ_key));
		if(!keyptr) {
			fputs("Can't allocate next key struct.\n",stderr);
			return 4;
		}
      lastkeyptr->sk_prev = keyptr;
   }
   BegKeyList = lastkeyptr;
   BegKeyList->sk_prev = (typ_key *) 0;
   free(keyptr);


   dictstream = fopen(dictfilename,"r");
   if(!dictstream) {
      fprintf(stderr,"Unable to open %s\n",dictfilename);
      exit(1);
	}

	/* Build the Vigenere table.  For efficiency, have the ciphertext
	 * dimension of the table indexed directly by ASCII value, rather
	 * than by an ordinal 0-25 (i.e., A-Z).
	 * The table can be indexed by upper or lower case.  The
	 * characters in the table are all lower case.
	 */
	for(jkey=0; jkey<ALFASIZE; jkey++) {
		for(jch=0; jch<CHARSETSIZE; jch++) {
			VigTable[jkey][jch] = 0;
		}
		for(jch='A'; jch<='Z'; jch++) {
			VigTable[jkey][jch] = (jch+jkey > 'Z' ? jch+jkey-ALFASIZE : jch+jkey)
				+ ('a'-'A');
		}
		for(jch='a'; jch<='z'; jch++) {
			VigTable[jkey][jch] = jch+jkey > (int) 'z'
			  ? jch+jkey-ALFASIZE : jch+jkey;
		}
	}

	/* Loop through the words in the dictionary.  */
	while(fgets(curkey,LINESIZE,dictstream)) {
		nkey = strlen(curkey)-1;
		if(nkey == 0) continue;
      curkey[nkey] = '\0';

		if(StatusEvery) {
			Nwords++;
			if(!(--WordsUntilStatus)) {
				fprintf(stderr,"Trying word %5d: %s            \r",Nwords,curkey);
				WordsUntilStatus = StatusEvery;
			}
		}
		
		/* Build an integer form of the possible key. */
	   for(jkey=0; jkey<nkey; jkey++) {
		   keyint[jkey] = (ALFASIZE - (tolower(curkey[jkey])-'a')) % ALFASIZE;
	   }

      ClearCount();
		/* Loop through the ciphertext, deciphering with this key.
		 * Build the character count tables for this decipherment.
		 */
		outch1 = 0;
	   for(jkey=0,cptr=ciphertext; *cptr; cptr++,jkey=(jkey+1)%nkey) {
		   outch2 = VigTable[keyint[jkey]][*cptr];
         CharCount[outch2]++;
			DigramCount[outch1][outch2]++;
			outch1 = outch2;
		   if(printplain) putchar(outch2);
      }
      closeness = ComputeCloseness(cipchars);
      if(printplain) printf("\n%10ld %s  p\n",closeness,curkey);
      if(closeness < EndKeyList->sk_close) {
			/* This potential key is better than the worst on the current
			 * list and hence should be on the list.
			 */
         keyptr = BegKeyList;
         while(closeness > keyptr->sk_close) {
            keyptr = keyptr->sk_next;
         }
         if(keyptr == EndKeyList) {
            strcpy(EndKeyList->sk_key,curkey);
            EndKeyList->sk_close = closeness;
         } else {
            /* Grab the last entry in the list and use it for
             * this key.  Make the next-to-last entry in the list
             * be EndKeyList.
             */
            insertkeyptr = EndKeyList;
            EndKeyList->sk_prev->sk_next = (typ_key *) 0;
            EndKeyList = EndKeyList->sk_prev;

            strncpy(insertkeyptr->sk_key,curkey,MAXKEYSIZE);
            insertkeyptr->sk_close = closeness;

            /* Insert this new node before "keyptr" by making its
             * previous be keyptr's previous and its next be keyptr.
             */
            insertkeyptr->sk_prev = keyptr->sk_prev;
            insertkeyptr->sk_next = keyptr;

            if(keyptr == BegKeyList) {
               BegKeyList = insertkeyptr;
            } else {
               /* The node formerly just previous to keyptr, and whose
                * next field pointed to keyptr, now must point to us.
                */
               keyptr->sk_prev->sk_next = insertkeyptr;
            }

            /* We must change the node we just inserted before so
             * that its previous pointer points to us.
             */
            keyptr->sk_prev = insertkeyptr;
         }
      }
	}

   putchar('\n');
   keyptr = BegKeyList;
	DumpKeyList(keyptr,ciphertext);

	return 0;
}


long int
ComputeCloseness(cipchars)
int cipchars;
{
   int j, curch;
	int ch1, ch2;
   long int OursPer, ExpectPer, diff, sum_diff_single=0, sum_diff_digram=0;
	long int divfact;

	divfact = UseSquares ? 100 : 10;
	
	/* Compute the closeness for single-character frequencies. */
	for (j=0; curch=freqs[j].f_ch; j++) {
      OursPer = CharCount[curch] * 10000 / cipchars;
      ExpectPer = freqs[j].f_freq;
      diff = OursPer - ExpectPer;
		if(UseSquares) {
			diff = diff*diff;
		} else {
      	if(diff<0) diff = -diff;
		}
      sum_diff_single += diff;
   }
	
	/* Compute the closeness for digrams. */
	if(UseDigrams) {
	for(ch1='a'; ch1<='z'; ch1++) {
		for(ch2='a'; ch2<='z'; ch2++) {
			if(DigramCount[ch1][ch2]){
				OursPer = DigramCount[ch1][ch2] * DIGRAMSPER / cipchars;
				diff = MasterDigramFreqs[ch1][ch2] - OursPer;
				if(UseSquares) {
					diff = diff*diff;
				} else {
 	    			if(diff<0) diff = -diff;
				}
				if(Debug) {
					fprintf(DStream,"'%c%c' Master=%ld ours=%ld diff=%ld\n",
					  ch1, ch2, MasterDigramFreqs[ch1][ch2], OursPer, diff);
				}
				sum_diff_digram += diff/divfact;
			}
		}
	}
	}
	
   return(sum_diff_single + sum_diff_digram);
}

void
ClearCount()
{
   int j;

#if 0
   for (j=0; j<CHARSETSIZE; j++) {
      CharCount[j] = 0;
   }
#endif
	memset(CharCount,0,sizeof(CharCount));
	memset(DigramCount,0,sizeof(DigramCount));
}

void
DumpKeyList(keyptr,ciphertext)
typ_key *keyptr;
char *ciphertext;
{
	char *kptr, *cptr, outch;
	int jkey;
	int keyint[MAXKEYSIZE];

   while(keyptr) {
		int nkey = strlen(keyptr->sk_key);

		if(!nkey) break;
		
      printf("%10ld %s ",keyptr->sk_close,keyptr->sk_key);
		for(jkey=nkey; jkey<12; jkey++) putchar(' ');

	   for(jkey=0; (keyptr->sk_key)[jkey]; jkey++) {
		   keyint[jkey] = (ALFASIZE - 
  			 (tolower((keyptr->sk_key)[jkey])-'a')) % ALFASIZE;
#if 0
			printf("Set keyint[%d]=%d  ",jkey,keyint[jkey]);
#endif
	   }

	   for(jkey=0,cptr=ciphertext; *cptr && jkey<MaxPlainPrint; cptr++,jkey++) {
#if 0
			printf(" keyint[%d]=%d; *cptr=%c nkey=%d\n",jkey%nkey, 
			 keyint[jkey%nkey],*cptr,nkey);
#endif
		   outch = VigTable[keyint[jkey%nkey]][*cptr];
			putchar(outch);
		}
		putchar('\n');

      keyptr = keyptr->sk_next;
   }
}

