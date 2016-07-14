/*
**  Verify a Usenet article with a Snefru hash header.
*/
#include <stdio.h>
#include <ctype.h>
#include "snefru.h"
#ifdef	RCSID
static char RCS[] =
	"$Header: checkhash.c,v 1.1 90/03/22 12:58:18 rsalz Exp $";
#endif	/* RCSID */

#ifndef	isascii
#define isascii(c)	(1)
#endif	/* isascii */

extern char	*optarg;
extern int	optind;

extern char	*mktemp();
extern char	*SnefruClose();
extern char	*strcpy();
extern FILE	*SnefruOpen();


static void
Usage()
{
    (void)fprintf(stderr, "Usage: checkhash [filename]\n");
    exit(1);
}


main(ac, av)
    int		ac;
    char	*av[];
{
    char	*p;
    char	buff[BUFSIZ];
    char	Checksum[40];
    FILE	*Input;
    FILE	*Snefru;
    int		i;
    int		Silent;

    /* Set defaults. */
    Silent = FALSE;

    /* Parse JCL. */
    while ((i = getopt(ac, av, "s")) != EOF)
	switch (i) {
	default:
	    Usage();
	    /* NOTREACHED */
	case 's':
	    Silent = TRUE;
	    break;
	}

    /* Get input. */
    ac -= optind;
    av += optind;
    switch (ac) {
    default:
	Usage();
    case 0:
	Input = stdin;
	break;
    case 1:
	if ((Input = fopen(av[0], "r")) == NULL) {
	    perror("No input");
	    (void)fprintf(stderr, "Can't open \"%s\" for reading.\n", av[0]);
	    exit(1);
	}
	break;
    }

    /* Read headers, looking for the checksum. */
    Checksum[0] = '\0';
    while (fgets(buff, sizeof buff, Input)) {
	if (buff[0] == '\n')
	    break;
	if (buff[0] == HDRFIRSTCHAR
	 && strncmp(buff, CHECKSUMHDR, sizeof CHECKSUMHDR - 1) == 0) {
	    p = &buff[sizeof CHECKSUMHDR] + 1;
	    /* Right length, allowing for the newline? */
	    if (strlen(p) != HDRTEXTSIZE + 1) {
		if (!Silent)
		    (void)printf("Wrong length:\n\t%s", buff);
		continue;
	    }
	    (void)strcpy(Checksum, p);
	    Checksum[HDRTEXTSIZE] = '\0';
	    for (p = Checksum; *p; p++)
		if (*p != ' ' && !(isascii(*p) && isxdigit(*p)))
		    break;
	    if (*p) {
		if (!Silent)
		    (void)printf("Bad character '%c':\n\t%s", *p, buff);
		/* Broke out before reaching the end, invalid header. */
		Checksum[0] = '\0';
	    }
	}
    }

    if (Checksum[0] == '\0') {
	if (!Silent)
	    (void)printf("No valid checksum header found.\n");
	exit(2);
    }

    /* Call up Snefru. */
    if ((Snefru = SnefruOpen()) == NULL) {
	if (!Silent)
	    perror("Can't open pipe to snefru");
	exit(2);
    }

    /* Send the rest of the article down the pipe. */
    while (fgets(buff, sizeof buff, Input))
	(void)fputs(buff, Snefru);
    (void)fclose(Input);

    if ((p = SnefruClose()) == NULL) {
	if (!Silent)
	    perror("Can't open tempfile");
	exit(2);
    }

    /* Compare them. */
    if (strcmp(p, Checksum) == 0) {
	if (!Silent)
	    (void)printf("Valid.\n");
	exit(0);
    }
    if (!Silent) {
	(void)printf("Invalid!\n");
	(void)printf("Computed: %s\n", p);
	(void)printf("  Posted: %s\n", Checksum);
    }
    exit(1);
}
