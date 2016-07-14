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
 *
 *      getkey
 *
 */

#define SIGNKEY "signature"
#define ENCKEY  "encryption"

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

extern  UTCTime *aux_current_UTCTime(), *aux_delta_UTCTime();

char *getenv();

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
        int             rc, i;
        ObjId           *oid;
	Name            *issuer = CNULL;
	DName 		*issuer_dn = NULLDNAME;
        PSESel          *pse;
	Key             key;
	KeyInfo         keyinfo;
        KeyType         type = SIGNATURE;
	Certificate     *cert;
        char            *filename = CNULL;
	OctetString     *newcert;
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt, *pin;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL;

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "c:p:ehstvVW")) != -1 ) {
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
			type = ENCRYPTION;
			break;
		case 's':
			type = SIGNATURE;
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

	if (optind < cnt) filename = parm[optind++];


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
                strcpy(psepath, cadir);  
                strcat(psepath, "/");
                strcat(psepath, psename);
        }
        else {
                psepath = (char *)malloc(strlen(psename)+2);
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

	if(!(cert = af_pse_get_Certificate(type, NULLDNAME, 0))) {
                fprintf(stderr, "%s: ", cmd);
		if(type == SIGNATURE) fprintf(stderr, "can't read SignCert");
		else fprintf(stderr, "can't read EncCert");
		exit(-1);
	}

	cert->tbs->version = 0;
	cert->tbs->serialnumber = 0;
	cert->tbs->issuer = aux_cpy_DName(cert->tbs->subject);
	cert->tbs->notbefore = aux_current_UTCTime();
	cert->tbs->notafter = aux_delta_UTCTime(cert->tbs->notbefore);
	if ((cert->tbs_DERcode = e_ToBeSigned(cert->tbs)) == NULLOCTETSTRING) {
		if(type == SIGNATURE) fprintf(stderr, "can't encode SignCert");
		else fprintf(stderr, "can't encode EncCert");
		exit(-1);
	}
	if(af_sign(cert->tbs_DERcode, cert->sig, END) < 0) {
		fprintf(stderr, "invalid CA signature");
		exit(-1);
	}

        if(verbose) {
                fprintf(stderr, "%s: The following prototype certificate was created:\n", cmd);
        	aux_fprint_Certificate(stderr, cert);
        }

	/* write it to filename or stdout */

	newcert = e_Certificate(cert);

	if (aux_OctetString2file(newcert, filename, 2)) {
		fprintf(stderr, "%s: Can't create or write %s\n", cmd, filename);
		exit(-1);
	}

	exit(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "getkey: Build Prototype Certificate\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'getkey' creates a prototype certificate from a public key previously\n");
	fprintf(stderr, "stored on the PSE, and writes its content to file <proto> or stdout,\n");
	fprintf(stderr, "if <proto> is omitted.\n\n\n");
	
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "getkey [-ehstvVW] [-p <pse>] [-c <cadir>] [proto]\n\n"); 


        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <pse>           PSE name (default: Environment variable PSE or .pse)\n");
	fprintf(stderr, "-c <cadir>         Name of CA-directory (default: Environment variable CADIR or .ca)\n");
	fprintf(stderr, "-s                 build prototype certificate from public signature key (default)\n");
	fprintf(stderr, "-e                 build prototype certificate from public encryption key\n");
        fprintf(stderr, "-h                 write this help text\n");
	fprintf(stderr, "-t                 control malloc/free behaviour\n");
        fprintf(stderr, "-v                 verbose\n");
        fprintf(stderr, "-V                 Verbose\n");
        fprintf(stderr, "-W                 Grand Verbose (for testing only)\n");
	fprintf(stderr, "<proto>            File containing the resulting prototype certificate (or stdout, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM GETKEY */
}
