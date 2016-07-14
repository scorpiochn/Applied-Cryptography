
/* ----------------------------- SHS Test code --------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "shs.h"

/* Prototypes of the local functions */
local void shsPrint OF((SHS_INFO *shsInfo));
local void shsTimeTrial OF((void));
local void shsString OF((char *inString));
local void shsFile OF((char *filename));
local void shsFilter OF((void));
local void shsTestSuite OF((void));
      void main OF((int argc, char **argv));

/*
 * Prints message digest buffer in shsInfo as 40 hexadecimal digits. Order is
 * from low-order byte to high-order byte of digest. Each byte is printed
 * with high-order hexadecimal digit first.
 */
local void shsPrint (shsInfo)
	SHS_INFO *shsInfo;
{
	int i;

	for (i = 0; i < 5; i++)
		printf ("%08lx", shsInfo->digest [i]);
}

/* size of test block */
#define TEST_BLOCK_SIZE 1000

/* number of blocks to process */
#define TEST_BLOCKS 10000

/* number of test bytes = TEST_BLOCK_SIZE * TEST_BLOCKS */
local long TEST_BYTES = (long) TEST_BLOCK_SIZE * (long) TEST_BLOCKS;

/*
 * A time trial routine, to measure the speed of SHA.
 *
 * Measures wall time required to digest TEST_BLOCKS * TEST_BLOCK_SIZE
 * characters.
 */
local void shsTimeTrial ()
{
	SHS_INFO shsInfo;
	time_t endTime, startTime;
	local unsigned char data [TEST_BLOCK_SIZE];
	unsigned int i;

	/* initialize test data */
	for (i = 0; i < TEST_BLOCK_SIZE; i++)
		data [i] = (unsigned char) (i & 0xFF);

	/* start timer */
	printf ("SHA time trial. Processing %ld characters...\n", TEST_BYTES);
	time (&startTime);

	/* digest data in TEST_BLOCK_SIZE byte blocks */
	shsInit (&shsInfo);
	for (i = TEST_BLOCKS; i > 0; i--)
		shsUpdate (&shsInfo, data, TEST_BLOCK_SIZE);
	shsFinal (&shsInfo);

	/* stop timer, get time difference */
	time (&endTime);
	shsPrint (&shsInfo);
	printf (" is digest of test input.\nSeconds to process test input: %ld\n",
		(long) (endTime - startTime));
	printf ("Characters processed per second: %ld\n",
		TEST_BYTES / (endTime - startTime));
}

/*
 * Computes the message digest for string inString. Prints out message
 * digest, a space, the string (in quotes) and a carriage return.
 */
local void shsString (inString)
	char *inString;
{
	SHS_INFO shsInfo;
	unsigned int len = strlen (inString);

	shsInit (&shsInfo);
	shsUpdate (&shsInfo, (unsigned char *) inString, len);
	shsFinal (&shsInfo);
	shsPrint (&shsInfo);
	printf (" \"%s\"\n", inString);
}

/*
 * Computes the message digest for a specified file. Prints out message
 * digest, a space, the file name, and a carriage return.
 */
local void shsFile (filename)
	char *filename;
{
	FILE *inFile = fopen (filename, "rb");
	SHS_INFO shsInfo;
	int bytes;
	local unsigned char data [1024];

	if (inFile == NULL) {
		printf ("%s can't be opened.\n", filename);
		return;
	}
	shsInit (&shsInfo);
	while ((bytes = fread (data, 1, 1024, inFile)) != 0)
		shsUpdate (&shsInfo, data, bytes);
	shsFinal (&shsInfo);
	shsPrint (&shsInfo);
	printf (" %s\n", filename);
	fclose (inFile);
}

/*
 * Writes the message digest of the data from stdin onto stdout,
 * followed by a carriage return.
 */
local void shsFilter ()
{
	SHS_INFO shsInfo;
	int bytes;
	local unsigned char data [SHS_BLOCKSIZE];

	shsInit (&shsInfo);
	while ((bytes = fread (data, 1, SHS_BLOCKSIZE, stdin)) != 0)
		shsUpdate (&shsInfo, data, bytes);
	shsFinal (&shsInfo);
	shsPrint (&shsInfo);
	printf ("\n");
}

/*
 * Runs a standard suite of test data.
 */
local void shsTestSuite ()
{
	printf ("SHA test suite results:\n");
	shsString ("");
	shsString ("a");
	shsString ("abc");
	shsString ("message digest");
	shsString ("abcdefghijklmnopqrstuvwxyz");
	shsString ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	shsString ("1234567890123456789012345678901234567890\
1234567890123456789012345678901234567890");
	/* Contents of file foo are "abc" */
	shsFile ("foo");
}

void main (argc, argv)
	int argc;
	char **argv;
{
	int i;

	/* For each command line argument in turn:
	** filename	     -- prints message digest and name of file
	** -sstring	     -- prints message digest and contents of string
	** -t		     -- prints time trial statistics for 10M
	**			characters
	** -x		     -- execute a standard suite of test data
	** (no args)	     -- writes messages digest of stdin onto stdout
	*/
	if (argc == 1)
		shsFilter ();
	else
		for (i = 1; i < argc; i++)
			if (argv [i] [0] == '-' && argv [i] [1] == 's')
				shsString (argv [i] + 2);
			else if (strcmp (argv [i], "-t") == 0)
				shsTimeTrial ();
			else if (strcmp (argv [i], "-x") == 0)
				shsTestSuite ();
			else
				shsFile (argv [i]);
}

/*
***********************************************************************
** End of shsdriver.c						     **
******************************** (cut) ********************************
*/
