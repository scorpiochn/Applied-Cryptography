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

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"


int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt, *pin;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL;
	int	        i;
	char	        listtype[7];
	KeyType         type;
	PKList          *list;
	char		*proc = "main (pklist)";

	strcpy(listtype, "PKList");
	type = SIGNATURE;

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "c:p:ehtvVW")) != -1 ) {
		switch (opt) {
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
		case 'e':
			strcpy(listtype, "EKList");
			type = ENCRYPTION;
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

        if (cadir) {
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

	if(cadir)
		pin = getenv("CAPIN");
	else
        	pin = getenv("USERPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if ( (list = af_pse_get_PKList (type)) == (PKList * )0 ) {
		aux_add_error(EINVALID, "af_pse_get_PKList failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "No %s\n", listtype);
		exit(-1);
	}

	fprintf(stderr, " ****************** %s ******************\n", listtype);
	aux_fprint_PKList(stderr, list);
	exit(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "pklist: Print Cache of Trusted Public Keys\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'pklist' prints out the content of the cache of trusted public keys\n");
	fprintf(stderr, "(PKList or EKList) of the indicated PSE.\n\n\n");

        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "pklist [-ehtvVW] [-p <pse>] [-c <cadir>]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: environment variable PSE or .pse)\n");
        	fprintf(stderr, "-c <cadir>       Name of CA-directory (default: environment variable CADIR or .ca)\n");
		fprintf(stderr, "-e               print cache of trusted public ENCRYPTION keys (EKList)\n");
		fprintf(stderr, "                 (default: PKList)\n");
		fprintf(stderr, "-t               control malloc/free behaviour\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM PKLIST */
}
