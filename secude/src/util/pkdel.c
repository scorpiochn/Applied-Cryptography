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

char *getenv();
static 	incorrectName();

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	int 		i, serialnumber;
	char		listtype[7];
	KeyType 	type;
	char		*issuer = CNULL, *subject = CNULL;
	DName 	        *issuer_dn, *subject_dn;
	PKList          *pklist;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL;
	char	        *cmd = *parm, opt, *pin;
	extern char	*optarg;
	extern int	optind, opterr;
	char		*proc = "main (pkdel)";

	strcpy(listtype, "PKList");
	type = SIGNATURE;
	serialnumber = -1;

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "c:p:o:i:n:ehtvVW")) != -1 ) {
		switch (opt) {
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
		case 'o':
			if (subject) usage(SHORT_HELP);
			else subject = optarg;
			break;
		case 'i':
			if (issuer) usage(SHORT_HELP);
			else issuer = optarg;
			break;
		case 'n':
			serialnumber = atoi(optarg);
			if (serialnumber < 0) usage(SHORT_HELP);
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

	if(optind<cnt) usage(SHORT_HELP);


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
			if (verbose) aux_fprint_error(stderr, 0);
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


	if (subject) {
		subject_dn = aux_alias2DName(subject);
		if (!subject_dn) incorrectName(proc, verbose);
	}
	else subject_dn = NULLDNAME;

	if (issuer) {
		issuer_dn = aux_alias2DName(issuer);
		if (!issuer_dn) incorrectName(proc, verbose);
	}
	else issuer_dn = NULLDNAME;

	if ( issuer && (serialnumber < 0) ) {
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Serialnumber missing\n");
		aux_add_error(EINVALID, "serialnumber missing", CNULL, 0, proc);
		if (verbose) aux_fprint_error(stderr, 0);
		usage (SHORT_HELP);
	}


	if ( af_pse_delete_PK(type, subject_dn, issuer_dn, serialnumber) < 0 ) {
		if (err_stack && (err_stack->e_number == EOBJNAME)) {
		        fprintf(stderr, "\nThere is no ToBeSigned with\n");
			if (issuer && serialnumber>=0) {
		        	fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       		fprintf(stderr, " serial number %d\n", serialnumber);
			}
			else
			        fprintf(stderr, " owner \"%s\"\n", subject);

			fprintf(stderr, "stored in your %s. No update done!\n", listtype);
		}
	}
	else {
		fprintf(stderr, "\nToBeSigned with\n");
		if (issuer && serialnumber>=0) {
		        fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       	fprintf(stderr, " serial number %d\n", serialnumber);
		}
		else
			fprintf(stderr, " owner \"%s\"\n", subject);

		fprintf(stderr, "removed from your %s.\n", listtype);

		fprintf(stderr, "\nYour updated %s now looks like this:\n\n", listtype);
		pklist = af_pse_get_PKList(type);
		if ( !pklist )
			fprintf(stderr, "Your %s is EMPTY!\n", listtype);
		else {
			fprintf(stderr, " ****************** %s ******************\n", listtype);
			aux_fprint_PKList (stderr, pklist);
		}
	}


	exit(0);
}


static incorrectName(proc, verbose)
char * proc;
char   verbose;
{
	fprintf(stderr, "Name cannot be transformed into DName-structure.\n");
	aux_add_error(EINVALID, "Name cannot be transformed into DName-structure", CNULL, 0, proc);
	if(verbose) aux_fprint_error(stderr, 0);
	exit(1);
}


static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "pkdel  Remove Public Key from Cache\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'pkdel' deletes entries from the cache of trusted public keys (PKList or\n");
	fprintf(stderr, "EKList). It either deletes all entries of the given <owner>, or the one entry\n");
	fprintf(stderr, "that is uniquely identified by its <issuer> and <serial> combination.\n\n\n");

        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "pkdel [-ehtvVW] [-p <pse>] [-c <cadir>] [-o <owner>] [-i <issuer>] [-n <serial>]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        	fprintf(stderr, "-c <cadir>       Name of CA-directory (default: Environment variable CADIR or .ca)\n");
		fprintf(stderr, "-o <owner>       Owner of public key\n");
		fprintf(stderr, "-i <issuer>      Issuer of public key\n");
		fprintf(stderr, "-n <serial>      Serial number of public key\n");
		fprintf(stderr, "-e               remove public key from cache of public ENCRYPTION keys (EKList)\n");
		fprintf(stderr, "-t               control malloc/free behaviour\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM INSTPKROOT */
}
