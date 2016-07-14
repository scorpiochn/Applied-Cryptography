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
 *      genkey
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

#define SIGNKEY "signature"
#define ENCKEY  "encryption"


int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
        int             rc, i;
	int	        keysize = DEFKEYLEN;
	AlgId         * algorithm = DEF_SUBJECT_SIGNALGID, * sig_alg = DEF_ISSUER_ALGID;
        ObjId         * oid = NULLOBJID, * sig_oid = NULLOBJID;
        PSESel        * pse_sel;
	Key             key;
	KeyInfo         keyinfo;
	Certificate   * cert;
        char          * filename = CNULL;
	OctetString   * newcert;
	extern char	*optarg;
	extern int	optind, opterr;
	KeyType         ktype = SIGNATURE;
	char	        *cmd = *parm, opt, *pin, *keytype = SIGNKEY;
	char	        *psename = CNULL, *psepath = CNULL, *cadir = CNULL;
        char            replace = FALSE;
	Boolean         onekeypaironly = FALSE;

	char 		*proc = "main (genkey)";

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

	while ( (opt = getopt(cnt, parm, "a:s:e:k:c:p:hrtvVW")) != -1 ) {
		switch (opt) {
		case 'a':
			if (sig_oid) usage(SHORT_HELP);
                        sig_oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(sig_oid) != SIG) usage(SHORT_HELP);
			sig_alg = aux_ObjId2AlgId(sig_oid);
			break;
		case 's':
			if (oid) usage(SHORT_HELP);
                        oid = aux_Name2ObjId(optarg);
                        if(aux_ObjId2AlgType(oid) != ASYM_ENC && aux_ObjId2AlgType(oid) != SIG)
				usage(SHORT_HELP);
			algorithm = aux_ObjId2AlgId(oid);
			break;
		case 'e':
			if (oid) usage(SHORT_HELP);
			oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(oid) != ASYM_ENC) usage(SHORT_HELP);
			algorithm = aux_ObjId2AlgId(oid);
			ktype = ENCRYPTION;
			keytype = ENCKEY;
			break;
                case 'k':
			keysize = atoi(optarg);
			if ( (keysize < MINKEYLEN) || (keysize > MAXKEYLEN)) usage(SHORT_HELP);
			break;
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
                case 'r':
                        replace = TRUE;
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

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}
	
	if((aux_ObjId2AlgType(algorithm->objid) != ASYM_ENC) && (onekeypaironly == TRUE)){
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Wrong AlgType for a PSE which shall hold one keypair only");
		aux_add_error(EINVALID, "oid", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	key.keyref = 0;
	key.pse_sel = (PSESel * ) 0;
	key.key = &keyinfo;
	keyinfo.subjectAI = aux_cpy_AlgId(algorithm);
        if(aux_ObjId2ParmType(algorithm->objid) != PARM_NULL)
	             *(int *)(keyinfo.subjectAI->parm) = keysize;

        if(verbose) fprintf(stderr, "%s: Generating %s key pair (Algorithm %s)\n        for <%s> with PSE %s ...\n", cmd, keytype, aux_ObjId2Name(algorithm->objid), aux_DName2Name(af_pse_get_Name()), psepath);

        if(verbose) sec_verbose = TRUE;
        else sec_verbose = FALSE;

	rc = af_gen_key(&key, ktype, replace);

	if (rc < 0)       {            
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Can't generate new keys");
		aux_add_error(EINVALID, "Can't generate new keys", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}
	else if(verbose) fprintf(stderr, "%s: Key generation (%s) O.K.\n", cmd, keytype);

	if(onekeypaironly == TRUE)
		cert = af_create_Certificate(&keyinfo, sig_alg, SKnew_name, (DName *)0);
	else{
		if ( ktype == SIGNATURE )
			cert = af_create_Certificate(&keyinfo, sig_alg, SignSK_name, (DName *)0);
		else
			cert = af_create_Certificate(&keyinfo, sig_alg, DecSKnew_name, (DName *)0);
	}

	if (!cert)       { 
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Can't create prototype certificate");
		aux_add_error(EINVALID, "Can't create prototype certificate", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}

        if(verbose) {
                fprintf(stderr, "%s: The following prototype certificate was created:\n", cmd);
        	aux_fprint_Certificate(stderr, cert);
        }

	if (af_pse_update_Certificate(ktype, cert, TRUE) < 0) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "unable to store prototype certificate on PSE");
		aux_add_error(EINVALID, "unable to store prototype certificate on PSE", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}

	/* write it to filename or stdout */

	newcert = e_Certificate(cert);

	if (aux_OctetString2file(newcert, filename, 2)) {
		aux_add_error(EINVALID, "Can't create or write", filename, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
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

        fprintf(stderr, "genkey: Generate Key and Prototype Certificate\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'genkey' generates an asymmetric keypair and installs the secret component on the PSE.\n");
	fprintf(stderr, "The public component of the keypair is wrapped into a self-signed prototype certificate\n");
	fprintf(stderr, "which is stored on the PSE and written to the file <proto> or stdout, if <proto> is omitted.\n\n\n");

        fprintf(stderr, "usage:\n\n");
        fprintf(stderr, "genkey [-hrtvVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-s <signalg>] [-k <keysize>]\n");
	fprintf(stderr, "       [-e <encalg>] [-k <keysize>] [proto]\n\n"); 


        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <pse>           PSE name (default: environment variable PSE or .pse)\n");
	fprintf(stderr, "-c <cadir>         Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-a <issueralg>     Issuer algorithm associated with the signature of the prototype certificate\n");
	fprintf(stderr, "                   (default: md2WithRsaEncryption)\n");
	fprintf(stderr, "-s <signalg>       Signature algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>       Keysize of RSA signature key\n");
	fprintf(stderr, "-e <encalg>        Encryption algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>       Keysize of RSA encryption key\n");
	fprintf(stderr, "-r                 replace a previously generated secret key\n");
        fprintf(stderr, "-h                 write this help text\n");
	fprintf(stderr, "-t                 control malloc/free behaviour\n");
        fprintf(stderr, "-v                 verbose\n");
        fprintf(stderr, "-V                 Verbose\n");
        fprintf(stderr, "-W                 Grand Verbose (for testing only)\n");
	fprintf(stderr, "<proto>            File containing the resulting prototype certificate (or stdout, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM GENKEY */
}
