/*
 *  SecuDE Release 4.1 (GMD)
 */
/********************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

/*--------------------------sign.c----------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   util            VERSION   1.1                          */
/*                              DATE   22.02.1991                   */
/*                                BY   ws                           */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This is a MAIN program to sign files                           */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  sec_sign(), sec_read(), sec_get_key(),                          */
/*  sec_string_to_key()                                             */
/*                                                                  */
/*                                                                  */
/* USAGE:                                                           */
/* sign [-CvVUth]  [-p <pse>] [-c <cadir>]                          */
/*      [-k <key>] [-a <alg>] [-H <hashinput>]                      */
/*      [<files>]	                                            */
/*------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include "af.h"

#define BUFSIZE 8192

char           *getenv();
char           *PROG;
Key             key;
PSESel          pse_sel;
PSESel          pse_sel_hashinput;
KeyInfo         keyinfo;
KeyInfo         key_hashinput;
int             mode;
Certificates   *certs;
OctetString    *encoded_certs;
HashInput       hashinput;
BitString       in_bits, out_bits;
OctetString     in_octets, out_octets, *ostr, *in_ostr;
AlgId           algid;
ObjId           object_oid;
More            more;
Signature       sign_signature;
long            a_sec, a_usec, a_hash_sec, a_hash_usec;

char            buf[BUFSIZE], outbuf[512];
int             verbose = 0;
static void     usage();

/***************************************************************
 *
 * Procedure main
 *
 ***************************************************************/
#ifdef ANSI

int main(
	int	  cnt,
	char	**parm
)

#else

int main(
	cnt,
	parm
)
int	  cnt;
char	**parm;

#endif

{
	extern char    *optarg;
	extern int      optind, opterr;
	char           *cmd = *parm, opt;
	char           *strmtch();
	char           *buf1, *buf2, *bb, *file = CNULL, *sig = CNULL,
	               *ctf = CNULL, *fcp = CNULL, *pkr = CNULL;
	char           *originator_name, *originator_alias;
	char           *object = CNULL, *app = CNULL, *pin;
	char            certflag = TRUE;
	char           *psename = NULL, *psepath = NULL, *cadir = NULL;
	char            k_option = FALSE, c_option = FALSE;
	char           *certname = NULL, *fcpathname = NULL, *pkrootname = NULL;
	int             i, j, in, fd_in = 0, fd_out = 1, out, rc, alg,
	                rest, nfiles = 0, nf, optfiles = 0;
	int             c, keyref = 0;
	PSESel         *std_pse;
	unsigned int    blocksize;
	char           *proc = "main (sign)";
	int             SCapp_available;

	PROG = cmd;

	sign_signature.signAI = md5WithRsaTimeDate;	/* default signature
						         * algorithm */

	key.keyref = 0;
	key.key = (KeyInfo *) 0;
	key.pse_sel = (PSESel *) 0;
	key.alg = (AlgId *)0;

	af_verbose = FALSE;
	sec_time = FALSE;


/*
 *      get args
 */

	optind = 1;
	opterr = 0;


nextopt:
	while ((opt = getopt(cnt, parm, "a:k:H:c:p:CmvVWtUh")) != -1)
		switch (opt) {
		case 'a':
			sign_signature.signAI = aux_Name2AlgId(optarg);
			continue;
		case 't':
			MF_check = TRUE;
			continue;
		case 'v':
			verbose = 1;
			af_verbose = FALSE;
			continue;
		case 'V':
			verbose = 2;
			af_verbose = TRUE;
			continue;
		case 'W':
			verbose = 2;
			af_verbose = TRUE;
			sec_verbose = TRUE;
			continue;
		case 'h':
			usage(LONG_HELP);
			continue;
		case 'U':
			sec_time = TRUE;
			continue;
		case 'k':
			if(c_option) {
				fprintf(stderr, "Only one of options -k or -C is possible\n");
				exit(-1);
			}
			k_option = TRUE;
			bb = optarg;
			while (*bb) {
				if (*bb < '0' || *bb > '9') {
					key.pse_sel = &pse_sel;
					pse_sel.object.name = optarg;
					break;
				}
				bb++;
			}
			if (!(*bb)) sscanf(optarg, "%d", &key.keyref);
			continue;
		case 'H':
			bb = optarg;
			while (*bb) {
				if (*bb < '0' || *bb > '9') {
					object = optarg;
					break;
				}
				bb++;
			}
			if (!(*bb)) sscanf(optarg, "%d", &keyref);
			build_hashinput(keyref, object);
			continue;
		case 'C':
			if(k_option) {
				fprintf(stderr, "Only one of options -k or -C is possible\n");
				exit(-1);
			}
			c_option = TRUE;
			continue;
		case 'c':
			cadir = optarg;
			continue;
		case 'p':
			psename = optarg;
			continue;
		default:
		case '?':
			usage(SHORT_HELP);
		}


	if (optind < cnt) {
		file = parm[optind];
		if(!optfiles) optfiles = optind;
		if ((fd_in = open(file, O_RDONLY)) <= 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't open %s\n", file);
		}
		else {
			close(fd_in);
			nfiles++;
		}
		optind++;
		goto nextopt;
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
		psepath = (char *) malloc(strlen(cadir) + strlen(psename) + 2);
		if (!psepath) {
			fprintf(stderr, "%s: Can't allocate memory", cmd);
			if (verbose) aux_fprint_error(stderr, 0);
			exit(1);
		}
		strcpy(psepath, cadir);
		if (psepath[strlen(psepath) - 1] != '/')
			strcat(psepath, "/");
		strcat(psepath, psename);
	} else {
		psepath = (char *) malloc(strlen(psename) + 2);
		if (!psepath) {
			fprintf(stderr, "%s: Can't allocate memory", cmd);
			if (verbose) aux_fprint_error(stderr, 0);
			exit(-1);
		}
		strcpy(psepath, psename);
	}

	if (cadir)
		pin = getenv("CAPIN");
        else
		pin = getenv("USERPIN");

	if (aux_create_AFPSESel(psepath, pin) < 0) {
		fprintf(stderr, "%s: ", cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n");
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}
	pse_sel.app_name = AF_pse.app_name;
	pse_sel_hashinput.app_name = AF_pse.app_name;


	if (!(std_pse = af_pse_open((ObjId *)0, FALSE))) {
		if (err_stack) {
			if (verbose) aux_fprint_error(stderr, 0);
			else aux_fprint_error(stderr, TRUE);
		}
		else	fprintf(stderr, "%s: unable to open PSE %s\n", cmd, AF_pse.app_name);
		exit(-1);
	}

	aux_free_PSESel(&std_pse);
	for (i = 0; i < PSE_MAXOBJ; i++) AF_pse.object[i].pin = aux_cpy_String(AF_pse.pin);

	pse_sel.app_name = AF_pse.app_name;
	pse_sel.object.pin = AF_pse.pin;
	pse_sel.pin = AF_pse.pin;
	pse_sel.app_id = AF_pse.app_id;

	pse_sel_hashinput.pin = pse_sel.pin;

	if (!(certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME))) {
		if (verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "Can't read certificate from PSE\n");
		exit(-1);
	}
	if (!(encoded_certs = e_Certificates(certs))) {
		if (verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "Can't encode own certificates\n");
		exit(-1);
	}

	for (nf = 0; nf < nfiles; nf++) {

/*
 *      	prepare signature file, certificate file, fcpath file, pkroot file
 */

		file = parm[optfiles + nf];

	/*
	 *      read input file and sign to output file
	 */
	
	/*
		more = MORE;
		while(more == MORE) {
			in = read(fd_in, buf, BUFSIZE);
			if(in == BUFSIZE) more = MORE;
			else more = END;
			in_octets.octets = buf;
			if(in > 0) in_octets.noctets = in;
			else in_octets.noctets = 0;
	*/
		in_ostr = aux_file2OctetString(file);
		if (!in_ostr) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't read inputfile %s\n", file);
			continue;
		}
		more = END;
		if (key.keyref == 0 && !key.pse_sel) {
			if ((rc = af_sign(in_ostr, &sign_signature, more)) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Signing %s failed", file);
			}
		} 
		else {
			if ((rc = sec_sign(in_ostr, &sign_signature, more, &key, &hashinput)) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Signing %s failed", file);
			}
		}
	/*
		}
	*/
	
		if(sec_time) {
			a_hash_usec = (a_hash_sec + hash_sec) * 1000000 + a_hash_usec + hash_usec;
			a_hash_sec = a_hash_usec/1000000;
			a_hash_usec = a_hash_usec % 1000000;
			if(rsa_sec || rsa_usec) {
				a_usec = (a_sec + rsa_sec) * 1000000 + a_usec + rsa_usec;
				a_sec = a_usec/1000000;
				a_usec = a_usec % 1000000;
			}
			if(dsa_sec || dsa_usec) {
				a_usec = (a_sec + dsa_sec) * 1000000 + a_usec + dsa_usec;
				a_sec = a_usec/1000000;
				a_usec = a_usec % 1000000;
			}
		}
	
		aux_free_OctetString(&in_ostr);
		if (rc < 0) continue;
	
		ostr = e_Signature(&sign_signature);
		if (!ostr) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "BER-Encoding of signature of %s failed\n", file);
			continue;
		}
		sig = (char *) malloc(strlen(file) + 8);
		strcpy(sig, file);
		strcat(sig, ".sig");
		if (aux_OctetString2file(ostr, sig, 2) < 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't create or write signature file %s\n", sig);
			aux_free_OctetString(&ostr);
			free(sig);
			continue;
		}
		aux_free_OctetString(&ostr);
		free(sig);
	
		if (key.keyref == 0 && !key.pse_sel && c_option) {
			ctf = (char *) malloc(strlen(file) + 8);
			strcpy(ctf, file);
			strcat(ctf, ".ctf");
			if (aux_OctetString2file(encoded_certs, ctf, 2) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Can't create or write certificates file %s\n", ctf);
				free(ctf);
				continue;
			}
			free(ctf);
		}
		fprintf(stderr, "File %s signed\n", file);
		if(MF_check) MF_fprint(stderr);
	}
	if(sec_time) {
		a_hash_usec = a_hash_usec/1000;
		a_usec = a_usec/1000;
		fprintf(stderr, "Time used for hash computation: %ld.%03ld sec\n", a_hash_sec, a_hash_usec);
		if(rsa_sec || rsa_usec) fprintf(stderr, "Time used for RSA computation:  %ld.%03ld sec\n", a_sec, a_usec);
		else fprintf(stderr, "Time used for DSA computation:  %ld.%03ld sec\n", a_sec, a_usec);
	}
	exit(0);

}


/***************************************************************
 *
 * Procedure usage
 *
 ***************************************************************/
#ifdef ANSI

static void usage(
	int	  help
)

#else

static void usage(
	help
)
int	  help;

#endif

{
	aux_fprint_version(stderr);

        fprintf(stderr, "sign:  Sign Files\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'sign' signs the given <files>. It uses algorithms and keys according\n");
	fprintf(stderr, "to the parameter -k and -a (default: SKnew/SignSK). For each\n");
	fprintf(stderr, "file in <files> it produces file.sig (containing the signature) and, if\n");
	fprintf(stderr, "-C is given, file.ctf (containing the user certificate and the forward\n");
 	fprintf(stderr, "certification path).\n\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "sign [-CvVWUth] [-p <pse>] [-c <cadir>] [-k <key>] [-a <alg>] [-H <hashinput>] [<files>]\n\n");

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-C               Produce .ctf files containing user certificate and forward certification\n");
        fprintf(stderr, "                 path for each file to be signed. Otherwise, produce only .sig files\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for tests only)\n");
        fprintf(stderr, "-U               Show time used for cryptographic algorithms\n");
        fprintf(stderr, "-t               Control malloc/free behaviour\n");
        fprintf(stderr, "-h               Write this help text\n");
        fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>       name of CA-directory (default: Environment variable CADIR or .ca)\n");
        fprintf(stderr, "-k <key>         PSE-object or key reference of signature key. Default: SKnew/SignSK\n");
        fprintf(stderr, "-a <signalg>     Signature algorithm. Default: md5WithRsaTimedate (RSA) or dsaWithSHA (DSS),\n");
        fprintf(stderr, "                 depending on the signature key\n");
        fprintf(stderr, "-H <hashinput>   PSE-object or key reference of hash input (sqmodn only)\n");
        fprintf(stderr, "<files>          Filenames\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM SIGN */
}

/***************************************************************
 *
 * Procedure strmtch
 *
 ***************************************************************/
#ifdef ANSI

char *strmtch(
	char	 *a,
	char	 *b
)

#else

char *strmtch(
	a,
	b
)
char	 *a;
char	 *b;

#endif

{
	register char  *aa, *bb;

	while (*a) {
		aa = a;
		bb = b;
		while (*aa) {
			if (*aa != *bb)
				break;
			bb++;
			if (*bb == '\0')
				return (aa + 1);
			aa++;
		}
		a++;
	}
	return (CNULL);
}


/***************************************************************
 *
 * Procedure build_hashinput
 *
 ***************************************************************/
#ifdef ANSI

int build_hashinput(
	int	  keyref,
	char	 *object
)

#else

int build_hashinput(
	keyref,
	object
)
int	  keyref;
char	 *object;

#endif

{
	Certificate    *cert;
	char           *proc = "build_hashinput";

	if (keyref) {
		if (sec_get_key(&key_hashinput, keyref, (Key *) 0) < 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't read keyref %d\n", keyref);
			exit(-1);
		}
	} 
	else if (object) {
		pse_sel_hashinput.object.name = object;
		if (sec_read_PSE(&pse_sel_hashinput, &object_oid, &out_octets) < 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't read PSE-object %s\n", object);
			exit(-1);
		}
		if (d2_KeyInfo(&out_octets, &key_hashinput) < 0) {
			cert = d_Certificate(&out_octets);
			if(!cert) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Can't decode PSE-object %s\n", object);
				exit(-1);
			}
			key_hashinput.subjectkey.nbits = cert->tbs->subjectPK->subjectkey.nbits;
			key_hashinput.subjectkey.bits = cert->tbs->subjectPK->subjectkey.bits;
		}
	}
	hashinput.sqmodn_input.nbits = key_hashinput.subjectkey.nbits;
	hashinput.sqmodn_input.bits = key_hashinput.subjectkey.bits;
	pse_sel.pin = pse_sel_hashinput.pin;

	return(0);
}
