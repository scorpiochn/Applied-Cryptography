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
 *   	program to install given PKRoot on PSE
 */

#include <stdio.h>
#include "cadb.h"

char *getenv();

int             verbose = 0;
static void     usage();


main(cnt, parm) /* installs PKRoot on PSE */
int     cnt;
char    **parm;
{
        PSESel	        pse;
        PKRoot          *root;
        char            *filename = CNULL;
        int             i;
        OctetString     *ostr;
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt, *pin;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL;

	char 		*proc = "main (instpkroot)";

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

	if (!psename) {
		if(cadir) {
			psename = getenv("CAPSE");
			if(!psename) psename = DEF_CAPSE;
		}
		else {
			psename = getenv("PSE");
			if(!psename) psename = DEF_PSE;
		}
	}

        if(cadir) {
                psepath = (char *)malloc(strlen(cadir)+strlen(psename)+2);
	 	if( !psepath ) {
			fprintf(stderr, "%s: ",cmd);
	                fprintf(stderr, "Can't allocate memory\n");
			aux_add_error(EMALLOC, "psepath", CNULL, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			exit(-1);
		}
                strcpy(psepath, cadir);
                strcat(psepath, "/");
                strcat(psepath, psename);
        }
        else {
                psepath = (char *)malloc(strlen(psename)+2);
 	 	if( !psepath ) {
			fprintf(stderr, "%s: ",cmd);
	                fprintf(stderr, "Can't allocate memory\n");
			aux_add_error(EMALLOC, "psepath", CNULL, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			exit(-1);
		}
                strcpy(psepath, psename);
        }

	if (cadir)
		pin = getenv("CAPIN");
        else
		pin = getenv("USERPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (!(ostr = aux_file2OctetString(filename))) {
		fprintf(stderr,"%s: Can't read %s\n", cmd, filename);
		aux_add_error(EINVALID, "Can't read", filename, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (!(root = d_PKRoot(ostr))) {
		fprintf(stderr,"%s: Can't decode PKRoot\n", cmd);
		aux_add_error(EDECODE, "d_PKRoot failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (! cadir){	/* user PSE */
		/* Remove signature from 'root', as it is not needed by a user */
		if(root->newkey){
			if(root->newkey->sig) {
				aux_free_KeyInfo((KeyInfo ** ) &(root->newkey->sig));
				root->newkey->sig = (Signature * )0;
			}
		}
	}

	if (af_pse_update_PKRoot(root) < 0) {
		fprintf(stderr,"%s: Can't install PKRoot on PSE %s\n", cmd, psepath);
		aux_add_error(EINVALID, "af_pse_update_PKRoot failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if(verbose) fprintf(stderr,"%s: PKRoot installed in PSE %s\n", cmd, psepath);

	return(0);
}




static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "instpkroot: Install Public Root Information on PSE\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'instpkroot' reads file <pkroot> or stdin, if <pkroot> is omitted,\n");
	fprintf(stderr, "and installs its content as PSE object PKRoot on the indicated PSE.\n");
	fprintf(stderr, "A PKRoot information that already exists on the target PSE will be overwritten.\n\n\n");

        fprintf(stderr, "usage:\n\n");
	fprintf(stderr,"instpkroot [-htvVW] [-p <pse>] [-c <cadir>] [pkroot]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: environment variable PSE or .pse)\n");
        	fprintf(stderr, "-c <cadir>       Name of CA-directory (default: environment variable CADIR or .ca)\n");
		fprintf(stderr, "-t               control malloc/free behaviour\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
		fprintf(stderr, "<pkroot>         File containing public root information (or stdin, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM INSTPKROOT */
}
