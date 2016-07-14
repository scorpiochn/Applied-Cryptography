#define CHARSETSIZE 128

int ReadDigramTable(char *digramFile,
 unsigned long int Table[CHARSETSIZE][CHARSETSIZE], long int *totDigrams);

void
AdjustDigramFreq(unsigned long int Table[CHARSETSIZE][CHARSETSIZE],
 long int totDigrams, long int per);
