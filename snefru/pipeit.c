/*
**  Utility routines to interface to the Snefru program as a filter.
*/
#include <stdio.h>
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: pipeit.c,v 1.1 90/03/22 12:59:01 rsalz Exp $";
#endif	/* RCSID */


#ifdef	USE_STRCHR
#define RDX	strrchr
#else
#define RDX	rindex
#endif	/* USE_STRCHR */

static char	OutputFile[] = "/tmp/hashcodeXXXXXX";
static char	ChecksumBuffer[HDRTEXTSIZE + 2];
static FILE	*Stream;

extern char	*RDX();
extern char	*mktemp();
#ifdef	CHARPSPRINTF
extern char	*sprintf();
#endif	/* CHARPSPRINTF */


/*
**  Spawn a Snefru that has its output redirected.
*/
FILE *
SnefruOpen()
{
    char	buff[sizeof OutputFile + 20];

    /* Open stream to snefru. */
    (void)mktemp(OutputFile);
    (void)sprintf(buff, "snefru >%s", OutputFile);
    if ((Stream = popen(buff, "w")) == NULL)
	(void)unlink(OutputFile);
    return Stream;
}


/*
**  Close the pipe and read in the Snefru's output.
*/
char *
SnefruClose()
{
    FILE	*F;
    char	*p;

    (void)pclose(Stream);

    /* Open the output file, read the one line. */
    if ((F = fopen(OutputFile, "r")) == NULL)
	return NULL;
    p = fgets(ChecksumBuffer, sizeof ChecksumBuffer, F);
    (void)fclose(F);
    (void)unlink(OutputFile);
    if (p == NULL)
	return NULL;

    /* Kill the newline. */
    if ((p = RDX(ChecksumBuffer, '\n')) == NULL)
	return NULL;
    *p = '\0';
    return ChecksumBuffer;
}
