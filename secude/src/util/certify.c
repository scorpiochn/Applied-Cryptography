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
 *      Program to certify ones Public Key contained in a Prototype Certificate
 *      to be run by CA, which replaces Certificate file.
 */

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

#define TIMELEN 40

extern char	*strcpy(), *getenv();
extern UTCTime  *aux_current_UTCTime(), *aux_delta_UTCTime();

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	int	        i;
        RC              rc;
	char	        *pf[2];
	int	        pfd[2];
	OctetString     *cin, *newcert;
	AlgId           *algorithm = DEF_ISSUER_ALGID;
	ObjId           *oid;
        Key             key;
	Certificate     *cert;
	Certificates    orig_cert;
	FCPath          fcpath;
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL, *home, * pin;
	char		*cadir_abs, *logpath, *notbefore = CNULL, *notafter = CNULL;
	Name		*printrepr;

	char		*proc = "main (certify)";

        pf[0] = pf[1] = 0;
	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "a:c:p:f:l:htvVW")) != -1 ) {
		switch (opt) {
		case 'a':
                        oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(oid) != SIG) usage(SHORT_HELP);
			algorithm = aux_ObjId2AlgId(oid);
			break;
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
		case 'f':
			if (notbefore) usage(SHORT_HELP);
			else notbefore = optarg;
			break;
		case 'l':
			if (notafter) usage(SHORT_HELP);
			else notafter = optarg;
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

	if ((notbefore && !notafter) || (!notbefore && notafter))
		usage(SHORT_HELP);

	if (notbefore)
		if (aux_interval_UTCTime(CNULL, notbefore, notafter)) {
			fprintf(stderr, "%s: ",cmd);
          	        fprintf(stderr, "Validity interval incorrectly specified\n");
			aux_add_error(EVALIDITY, "aux_interval_UTCTime failed", CNULL, 0, proc);
			exit(-1);
		}

        i = 0;
	while (optind < cnt && i < 2) pf[i++] = parm[optind++];

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


	if (!(cin = aux_file2OctetString(pf[0]))) {
		fprintf(stderr,"%s: Can't read %s\n", cmd, pf[0]);
		aux_add_error(EINVALID, "Can't read file", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	/* O.K. skip to CA dir */

        if(cadir[0] != '/') {
		home = getenv("HOME");
		if (!home) home = "";
		cadir_abs = (char *)malloc(strlen(home)+strlen(cadir)+10);
		strcpy(cadir_abs, home);
		strcat(cadir_abs, "/");
		strcat(cadir_abs, cadir);
	}
	else {
		cadir_abs = (char *)malloc(strlen(cadir)+10);
		strcpy(cadir_abs, cadir);
	}

	logpath = (char *)malloc(strlen(cadir_abs)+10);
	strcpy(logpath, cadir_abs);
	strcat(logpath, "/");
	strcat(logpath, CALOG);

	if ((logfile = fopen(logpath, LOGFLAGS)) == (FILE * ) 0) {
		fprintf(stderr, "%s: Can't open %s\n", cmd, CALOG);
		aux_add_error(EINVALID, "Can't open", CALOG, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	cert = d_Certificate(cin);
	if (!cert) {
		fprintf(stderr, "%s: Can't decode prototype certificate\n", cmd);
		aux_add_error(EINVALID, "Can't decode prototype certificate", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	/* include tests of prototype certificate before signing */

        /* verify signature of prototype certificate with 
           public key to be certified                            */


        key.key = cert->tbs->subjectPK;
        key.keyref = 0;
        key.pse_sel = (PSESel *)0;

/*
 *	Verify prototype certificate
 */

	rc = sec_verify(cert->tbs_DERcode, cert->sig, END, &key, (HashInput * ) 0);
	if(rc) {
		fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "Can't verify prototype certificate\n");
		aux_add_error(EINVALID, "Can't verify prototype certificate", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		LOGAFERR;
		exit(-1);
	}


	printrepr = aux_DName2Name(cert->tbs->subject);
        if(af_cadb_add_user(printrepr, cadir_abs) < 0) {
                LOGERR("can't access user db");
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't access user db\n");
		aux_add_error(EINVALID, "can't access user db", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
                exit(-1);
        }
	free(printrepr);


	/* get issuer as name of PSE */
	cert->tbs->issuer = af_pse_get_Name();

	if (cert->tbs->notbefore) {
		free (cert->tbs->notbefore);
		cert->tbs->notbefore = CNULL;
	}
	if (cert->tbs->notafter) {
		free (cert->tbs->notafter);
		cert->tbs->notafter = CNULL;
	}

	if (!notbefore) {
		cert->tbs->notbefore = aux_current_UTCTime();
		cert->tbs->notafter = aux_delta_UTCTime(cert->tbs->notbefore);
	}
	else {
		cert->tbs->notbefore = (UTCTime *)malloc(TIMELEN);
		strcpy(cert->tbs->notbefore, notbefore);
		free(notbefore);
		cert->tbs->notafter = (UTCTime *)malloc(TIMELEN);
		strcpy(cert->tbs->notafter, notafter);
		free(notafter);
	}

	cert->tbs->serialnumber = af_pse_incr_serial();
	cert->tbs->version = 0;           /* default version */

	aux_free_OctetString(&cert->tbs_DERcode);
	if (cert->sig) aux_free_KeyInfo( &cert->sig );
	cert->sig = (Signature * )malloc(sizeof(Signature));
 	if( !cert->sig ) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "cert->sig", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	cert->sig->signAI = af_pse_get_signAI();
	if ( ! cert->sig->signAI ) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Cannot determine the algorithm associated to your own secret signature key\n");
		aux_add_error(EREADPSE, "af_pse_get_signAI failed", CNULL, 0, proc);
		if (verbose) aux_fprint_error(stderr, 0);
		exit (-1);
	}

	if (aux_ObjId2AlgType(cert->sig->signAI->objid) == ASYM_ENC )
		cert->sig->signAI = aux_cpy_AlgId(algorithm);

	cert->tbs->signatureAI = aux_cpy_AlgId(cert->sig->signAI);
	cert->tbs_DERcode = e_ToBeSigned(cert->tbs);
           
	if (!cert->tbs_DERcode || (af_sign(cert->tbs_DERcode, cert->sig, END) < 0)) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "AF Error with CA Signature\n");
		aux_add_error(EINVALID, "AF Error with CA Signature", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		LOGAFERR;
		exit(-1);
	}

	if (af_cadb_add_Certificate(0, cert, cadir_abs)) {
		LOGERR("Can't access cert db");
		aux_add_error(EINVALID, "can't access user db", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	newcert = e_Certificate(cert);
	if (!newcert) {
		fprintf(stderr, "%s: Can't encode new Certificate.\n", cmd);
		aux_add_error(EENCODE, "can't encode new Certificate", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (aux_OctetString2file(newcert, pf[1], 2)) {
		fprintf(stderr, "%s: Can't create or write %s\n", cmd, pf[1]);
		aux_add_error(EINVALID, "Can't create or write file", pf[1], char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

        if(verbose) {
		printrepr = aux_DName2Name(cert->tbs->issuer);
        	fprintf(stderr, "%s: The following certificate was generated by <%s> using PSE %s:\n", cmd, printrepr, psepath);
        	aux_fprint_Certificate(stderr, cert);
		free(printrepr);
        }
	exit(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "certify: Certify Public Key (CA command)\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'certify' reads a prototype certificate from file <proto> or stdin, if\n");
	fprintf(stderr, "<proto> is omitted, and transforms it into a 'valid' certificate.\n");
	fprintf(stderr, "It replaces the 'issuer' and 'serialnumber' fields of the prototype\n");
	fprintf(stderr, "certificate by its CA values (taken from its CA PSE), and replaces\n");
	fprintf(stderr, "the signature appended to the prototype certificate by its own signature.\n");
	fprintf(stderr, "The resulting certificate is written to file <cert> or stdout, if <cert>\n");
	fprintf(stderr, "is omitted.\n\n\n");

        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "certify [-htvVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-f <notbefore>] [-l <notafter>] [proto [cert]]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-p <psename>       PSE name (default: environment variable CAPSE or .capse)\n");
        	fprintf(stderr, "-c <cadir>         Name of CA-directory (default: environment variable CADIR or .ca)\n");
		fprintf(stderr, "-a <issueralg>     CA's signature algorithm (default: md2WithRsaEncryption)\n");
		fprintf(stderr, "-f <notbefore>     First date on which the certificate is valid\n");
		fprintf(stderr, "-l <notafter>      Last date on which the certificate is valid\n");
		fprintf(stderr, "-t                 control malloc/free behaviour\n");
        	fprintf(stderr, "-h                 write this help text\n");
        	fprintf(stderr, "-v                 verbose\n");
        	fprintf(stderr, "-V                 Verbose\n");
        	fprintf(stderr, "-W                 Grand Verbose (for testing only)\n");
		fprintf(stderr, "<proto>            File containing the prototype certificate (or stdin, if omitted)\n");
		fprintf(stderr, "<cert>             File containing the resulting certificate (or stdout, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM CERTIFY */
}
