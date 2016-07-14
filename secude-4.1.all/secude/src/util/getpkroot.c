/*
 *  SecuDE Release 4.1 (GMD)
 */
/********************************************************************
 * Copyright (C) 1992, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

/*
 *      Program to read PKRoot from CA-PSE
 */

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	int	i;
	OctetString     *out;
	PKRoot          *pkroot;
	char	        *filename = CNULL;
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL, * pin;

	char 		*proc = "main (getpkroot)";

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "c:p:htvVW")) != -1 ) {
		switch (opt) {
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
                case 't':
                        MF_check = TRUE;
                        break;
		case 'v':
			verbose = 1;
			continue;
		case 'V':
			verbose = 2;
			continue;
		case 'W':
			verbose = 2;
			af_verbose = TRUE;
			sec_verbose = TRUE;
			continue;
		case 'h':
			usage(LONG_HELP);
			continue;
		default:
		case '?':
			usage(SHORT_HELP);
		}
	}

	if (optind < cnt) 
		filename = parm[optind++];

	if (optind < cnt) 
		usage(SHORT_HELP);

        if(!psename) psename = getenv("CAPSE");
        if(!cadir) cadir = getenv("CADIR");

        if(!psename) psename = DEF_CAPSE;
        if(!cadir) cadir = DEF_CADIR;

        psepath = (char *)malloc(strlen(cadir)+strlen(psename)+2);
        strcpy(psepath, cadir);
        strcat(psepath, "/");
        strcat(psepath, psename);

        pin = getenv("CAPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (!(pkroot = af_pse_get_PKRoot() ) ) {
		aux_add_error(EINVALID, "Can't read PKRoot from PSE", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: Can't read PKRoot from PSE %s\n", cmd, psepath);
		exit(-1);
	}

	if (!(out = e_PKRoot(pkroot) ) ) {
		aux_add_error(EENCODE, "e_PKRoot failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: Can't decode PKRoot\n", cmd);
		exit(-1);
	}

	if (aux_OctetString2file(out, filename, 2)) {
		aux_add_error(EINVALID, "Can't create or write", filename, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: Can't create or write %s\n", cmd, filename);
		exit(-1);
	}

	if(verbose) fprintf(stderr, "%s: done.\n", cmd);
	exit(0);
}




static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "getpkroot  Extract Public Root Information from CA PSE (CA command)\n\n\n");
	fprintf(stderr, "Description:\n\n");
 	fprintf(stderr, "'getpkroot' extracts the the PSE object PKRoot from the CA's PSE\n");
	fprintf(stderr, "and writes its content to the file <pkroot> or stdout, if <pkroot>\n");
	fprintf(stderr, "is omitted.\n\n\n");

        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "getpkroot [-htvVW] [-p <pse>] [-c <cadir>] [pkroot]\n\n");


        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: environment variable CAPSE or .capse)\n");
        	fprintf(stderr, "-c <cadir>       Name of CA-directory (default: environment variable CADIR or .ca)\n");
		fprintf(stderr, "-t               control malloc/free behaviour\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
		fprintf(stderr, "<pkroot>         File containing public root information (or stdout, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM GETPKROOT */
}
