/*
**  Call SNEFRU on something about to be feed into INEWS.  Then, rewrite
**  the file to add the X-Snefru-Checksum header.
*/
#include <stdio.h>
#include <pwd.h>
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: hashnews.c,v 1.1 90/03/22 12:58:44 rsalz Exp $";
#endif	/* RCSID */

#ifdef	USE_STRCHR
#define IDX	strchr
#else
#define IDX	index
#endif	/* USE_STRCHR */

#ifndef	SEEK_ABS
#define SEEK_ABS	0
#endif	/* SEEK_ABS */

extern char	*optarg;
extern int	optind;

extern char		*getenv();
extern char		*IDX();
extern char		*mktemp();
extern char		*SnefruClose();
extern char		*strcpy();
extern FILE		*SnefruOpen();
extern long		ftell();
extern struct passwd	*getpwuid();
#ifdef	CHARPSPRINTF
extern char	*sprintf();
#endif	/* CHARPSPRINTF */

static void
Usage()
{
    (void)fprintf(stderr, "Usage: snefru_news articlename\n");
    exit(1);
}


/*
**  Simulate what B2.11 inews does for appeneding signatures.
*/
static int
AppendSignature(Snefru)
    FILE		*Snefru;
{
    char		*p;
    char		buff[256];
    FILE		*F;
    int			i;
    struct passwd	*pwd;

    if ((p = getenv("HOME")) == NULL
     && (p = getenv("LOGDIR")) == NULL) {
	if ((pwd = getpwuid(getuid())) == NULL)
	    return 0;
	p = pwd->pw_dir;
    }
    (void)sprintf(buff, "%s/.signature", p);
    if ((F = fopen(buff, "r")) == NULL)
	return 0;
    for (i = 0; fgets(buff, sizeof buff, F); i++)
	if (IDX(buff, '\n') == NULL) {
	    i = 0;
	    break;
	}
    if (i > 4 || i == 0) {
	(void)fclose(F);
	return 0;
    }
    (void)fprintf(Snefru, "-- \n");
    rewind(F);
    while (fgets(buff, sizeof buff, F))
	(void)fputs(buff, Snefru);
    (void)fclose(F);
    return i;
}


main(ac, av)
    int		ac;
    char	*av[];
{
    int		i;
    int		CheckSignature;
    FILE	*Input;
    FILE	*Snefru;
    FILE	*Output;
    FILE	*Body;
    char	buff[BUFSIZ];
    char	*p;
    char	tempfile[20];
    char	bodyfile[20];
    long	cookie;

    /* Set defaults. */
    CheckSignature = TRUE;

    /* Parse JCL. */
    while ((i = getopt(ac, av, "n")) != EOF)
	switch (i) {
	default:
	    Usage();
	case 'n':
	    CheckSignature = FALSE;
	    break;
	}

    /* Get input. */
    ac -= optind;
    av += optind;
    switch (ac) {
    default:
	Usage();
	/* NOTREACHED */
    case 0:
	/* We're being piped into.  Create a temp file to hold the
	 * article body. */
	Input = stdin;
	(void)strcpy(bodyfile, "/tmp/hashBXXXXXX");
	(void)mktemp(bodyfile);
	if ((Body = fopen(bodyfile, "w")) == NULL) {
	    perror("No temporary");
	    (void)fprintf(stderr, "Can't open \"%s\" for writing.\n",
		    bodyfile);
	    exit(1);
	}
	break;
    case 1:
	if ((Input = fopen(av[0], "r")) == NULL) {
	    perror("No input");
	    (void)fprintf(stderr, "Can't open \"%s\" for reading.\n", av[0]);
	    exit(1);
	}
	Body = NULL;
	break;
    }

    /* Get output file. */
    (void)strcpy(tempfile, "/tmp/hashHXXXXXX");
    (void)mktemp(tempfile);
    if ((Output = fopen(tempfile, "w")) == NULL) {
	perror("No output");
	(void)fprintf(stderr, "Can't open \"%s\" for writing.\n", tempfile);
	exit(1);
    }

    /* Open stream to snefru. */
    if ((Snefru = SnefruOpen()) == NULL) {
	perror("Can't open pipe to snefru");
	(void)fclose(Output);
	(void)unlink(tempfile);
	exit(1);
    }

    /* Read article, skipping headers. */
    while (fgets(buff, sizeof buff, Input)) {
	if (buff[strlen(buff) - 1] != '\n')
	    (void)fprintf(stderr, "Warning, line truncated:\n%s\n",
		    buff);
	if (buff[0] == '\n')
	    break;
	(void)fputs(buff, Output);
    }

    /* If not from stdin we can seek, so remember where the headers end. */
    if (Body == NULL)
	cookie = ftell(Input);

    /* Send rest of article to snefru. */
    while (fgets(buff, sizeof buff, Input)) {
	if (buff[strlen(buff) - 1] != '\n')
	    (void)fprintf(stderr, "Warning, line truncated:\n%s\n",
		    buff);
	(void)fputs(buff, Snefru);
	if (Body)
	    (void)fputs(buff, Body);
    }

    /* Do the signature? */
    if (CheckSignature) {
	if ((i = AppendSignature(Snefru)) == 0)
	    (void)fprintf(stderr, ".signature unreadable or too long...\n");
    }

    (void)fclose(Input);

    /* Write the checksum. */
    if (p = SnefruClose())
	(void)fprintf(Output, "%s: %s\n", CHECKSUMHDR, p);
    else
	(void)fprintf(stderr, "Snefru checksum lost!?\n");

    /* Send the article body. */
    if (Body) {
	(void)fclose(Body);
	Input = fopen(bodyfile, "r");
    }
    else {
	Input = fopen(av[0], "r");
	(void)fseek(Input, cookie, SEEK_ABS);
    }
    (void)fputs("\n", Output);
    while (fgets(buff, sizeof buff, Input))
	(void)fputs(buff, Output);
    (void)fclose(Output);

    if (Input == stdin)
	/* Input is stdin, so send output to stdout. */
	Output = stdout;
    else if ((Output = fopen(av[0], "w")) == NULL) {
	perror("Can't rewrite file");
	(void)fprintf(stderr,
		"Can't overwrite \"%s\", output is in \"%s\".\n",
		av[0], tempfile);
	exit(1);
    }

    Input = fopen(tempfile, "r");
    while (fgets(buff, sizeof buff, Input))
	(void)fputs(buff, Output);

    if (Output != stdout);
	(void)unlink(tempfile);
    (void)fclose(Output);
    exit(0);
}
