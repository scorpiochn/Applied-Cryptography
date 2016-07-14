#include <stdio.h>
#include "rdditbl.h"

/*--- function ReadDigramTable ----------------------------------
 *
 *  Read a table of digrams from a file.
 *  Each line looks like:
 *        columns 1-2: the digram, lowercase.",
 *        column    3: space",
 *        columns 4-n: Absolute digram count",
 *
 *  Entry:	digramFile	is the filename.
 *	
 *  Exit:	Table			is the table of digrams, indexed by ASCII
 *								character values.
 *				totDigrams  is the total number of digrams.
 */
int
ReadDigramTable(char *digramFile,
unsigned long int Table[CHARSETSIZE][CHARSETSIZE], long int *totDigrams)
{
	int retcode = 0;
	int mych1, mych2;
	char line[32];
	FILE *intblst;
	long int freq;
		
	*totDigrams=0, 
	intblst = fopen(digramFile, "r");
	if(!intblst) return 1;

	while(fgets(line, 32, intblst)){
		mych1 = line[0];
		mych2 = line[1];
		sscanf(line+2,"%ld",&freq);
		Table[mych1][mych2] = freq;
		*totDigrams += freq;
	}
	fclose(intblst);
	
	return retcode;
}

void
AdjustDigramFreq(unsigned long int Table[CHARSETSIZE][CHARSETSIZE],
 long int totDigrams, long int per)
{
	int mych1, mych2;

	for(mych1=0; mych1<CHARSETSIZE; mych1++) {
		for(mych2=0; mych2<CHARSETSIZE; mych2++) {
			Table[mych1][mych2] = 
			 (Table[mych1][mych2]*per)/totDigrams;
		}
	}	
	
}
