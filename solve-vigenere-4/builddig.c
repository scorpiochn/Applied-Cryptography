/*--- builddig.c -- Program to build a table of digram frequencies.
 *  To be used for cryptographic purposes.
 *  Input is assumed to be alphabetic, all lower-case.
 *  (Run "alfaonly" on it first)
 *
 * Mark Riordan   2 April 93
 */

#include <stdio.h>
#include <ctype.h>
#include "rdditbl.h"

char *msg[] = {
"Program to build a table of digrams.",
"Usage:  builddig [-i intable] -o outtable <intext ",
" where",
"intable  is the digram table being updated (if any)",
"outtable is the updated digram table",
"intext   is the file containing the plaintext from which digram",
"         frequencies will be tallied.",
NULL };

static char *author = "Mark Riordan  1100 Parker  Lansing MI  48912  Apr 93";

int
main(int argc, char *argv[]) 
{
#define MAXCHAR CHARSETSIZE
	register int ch1, ch2;
	extern char *optarg;
	unsigned long int digtbl[CHARSETSIZE][CHARSETSIZE];
	long int freq, tot_digrams;
	int argerror=0;
	char *infile=NULL, *outfile;
	FILE *intblst, *outtblst=stdout;

   while(EOF != (ch1 = getopt(argc,argv,"i:o:"))) {
      switch(ch1) {
         case 'i':
				infile = optarg;
				break;
			case 'o':
				outfile = optarg;
				outtblst = fopen(outfile,"w");
				break;
			default:
				argerror = 1;
				break;
		}
	}
	if(argerror) {
		usage(NULL,msg);
		return 1;
	}
	
	for(ch1=0; ch1<MAXCHAR; ch1++) {
		for(ch2=0; ch2<MAXCHAR; ch2++) {
			digtbl[ch1][ch2] = 0;
		}
	}
	
	if(infile) {
		if(ReadDigramTable(infile,digtbl,&tot_digrams)) {
			fputs("Error reading digram table.\n",stderr);
			return 2;
		}
	}

	ch1 = getchar();
	while(EOF != (ch2 = getchar())) {
		digtbl[ch1][ch2]++;
		ch1 = ch2;
	}
	
	/* Now write out the digram table, writing only the non-zero
	 * entries.
	 */
	 
	for(ch1=0; ch1<MAXCHAR; ch1++) {
		for(ch2=0; ch2<MAXCHAR; ch2++) {
			if(digtbl[ch1][ch2]) {
				fprintf(outtblst,"%c%c %ld\n",ch1, ch2, digtbl[ch1][ch2]);
			}
		}
	}
 
	return 0;
}

