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
/*   This is a MAIN program to verify files 	                    */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  sec_verify(), sec_read(), sec_get_key(),     	            */
/*  sec_string_to_key()                                             */
/*                                                                  */
/*                                                                  */
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
KeyInfo         *keyinfo;
KeyInfo         key_hashinput;
int             mode;
Certificate    *cert;
Certificates   *certs;
FCPath         *fcpath;
PKRoot         *pkroot;
HashInput       hashinput;
BitString       in_bits, out_bits;
OctetString     in_octets, out_octets, *ostr, *in_ostr;
AlgId           algid;
ObjId           object_oid;
More            more;
Signature       *verify_signature;
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
	char           *cmd = *parm, opt, x500 = TRUE;
	char           *strmtch();
	char           *buf1, *buf2, *bb, *file, *sig = CNULL,
	               *ctf = CNULL, *fcp = CNULL, *pkr = CNULL;
	char           *originator_name, *originator_alias;
	char           *object = CNULL, *app = CNULL, *pin;
	char            certflag = TRUE, *signatureTimeDate;
	char           *psename = NULL, *psepath = NULL, *cadir = NULL;
	char            k_option = FALSE, c_option = FALSE, f_option = FALSE,
	                t_option = FALSE;
	char           *certname = NULL, *fcpathname = NULL, *pkrootname = NULL,
	               *keyname = NULL;
	int             i, j, in, fd_in = 0, fd_out = 1, out, rc, alg,
	                rest, nfiles = 0, nf, optfiles = 0;
	int             c, keyref = 0;
	PSESel         *std_pse;
	unsigned int    blocksize;
	int             SCapp_available;

	char           *proc = "main (sign)";

#ifdef AFDBFILE
	char		afdb[256];
#endif

#ifdef X500
	int              dsap_index;
	char           * callflag;
	char	       * env_auth_level;
#endif
	af_access_directory = FALSE;

	af_chk_crl = FALSE;
	sec_time = FALSE;
	af_verbose = FALSE;
	PROG = cmd;

	key.keyref = 0;
	key.key = (KeyInfo *) 0;
	key.pse_sel = (PSESel *) 0;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;

#ifdef X500
	af_x500_count  = 1;	/* default, binding to local DSA */
	dsap_index = 4;
	callflag = "-call";
	auth_level = DBA_AUTH_SIMPLE;

	i = cnt+1;
	while (parm[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
#endif

nextopt:


#ifdef X500
	while ((opt = getopt(cnt, parm, "k:f:c:d:p:A:htvFVWTURD")) != -1)
		switch (opt) {
#else
	while ((opt = getopt(cnt, parm, "k:f:c:p:htvFVWTURD")) != -1)
		switch (opt) {
#endif
		case 't':
			MF_check = TRUE;
			continue;
		case 'v':
			verbose = 1;
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
#ifdef SCA
		case 'T':
			SC_verify = TRUE;
			continue;
#endif
                case 'F':
                        af_FCPath_is_trusted = TRUE;
                        continue;
		case 'R':
			af_chk_crl = TRUE;
			continue;
		case 'k':
			k_option = TRUE;
			bb = optarg;
			while (*bb) {
				if (*bb < '0' || *bb > '9') {
					keyname = (char *) malloc(strlen(optarg) + 1);
					strcpy(keyname, optarg);
					break;
				}
				bb++;
			}
			if (!(*bb)) sscanf(optarg, "%d", &keyref);
			continue;
		case 'f':
			f_option = TRUE;
			fcpathname = (char *) malloc(strlen(optarg) + 1);
			strcpy(fcpathname, optarg);
			continue;
		case 'c':
			cadir = optarg;
			continue;
		case 'p':
			psename = optarg;
			continue;
		case 'D':
			af_access_directory = TRUE;
			continue;
#ifdef X500
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *) malloc(strlen(callflag) + 1);
			strcpy(af_x500_vecptr[1], callflag);
			af_x500_vecptr[2] = (char *) malloc(strlen(optarg) + 1);
			strcpy(af_x500_vecptr[2], optarg);
			af_x500_vecptr[3] = (char *) 0;
			i = cnt + 1;
			dsap_index = 4;
			while (parm[i])
				af_x500_vecptr[dsap_index++] = parm[i++];
			continue;
		case 'A':
			if (! strcasecmp(optarg, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(optarg, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
			continue;
#endif
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

	if (!nfiles) usage(SHORT_HELP); /* verify requires a file name */

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
		strcpy(psepath, cadir);
		if (psepath[strlen(psepath) - 1] != '/')
			strcat(psepath, "/");
		strcat(psepath, psename);
	} 
	else {
		psepath = (char *) malloc(strlen(psename) + 2);
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

#ifdef X500
	if (auth_level == DBA_AUTH_NONE) {
		env_auth_level = getenv("AUTHLEVEL");
		if (env_auth_level) {
			if (! strcasecmp(env_auth_level, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(env_auth_level, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
		}
	}
#endif

	if (!(std_pse = af_pse_open(0, FALSE))) {
		if (err_stack) {
			if (verbose) aux_fprint_error(stderr, 0);
			else aux_fprint_error(stderr, TRUE);
		}
		else fprintf(stderr, "%s: unable to open PSE %s\n", cmd, AF_pse.app_name);
		exit(-1);
	}

	aux_free_PSESel(&std_pse);
	for (i = 0; i < PSE_MAXOBJ; i++) 
		AF_pse.object[i].pin = AF_pse.pin;

	pse_sel.app_name = AF_pse.app_name;
	pse_sel.object.name = CNULL;
	pse_sel.object.pin = AF_pse.pin;
	pse_sel.pin = AF_pse.pin;
	pse_sel.app_id = AF_pse.app_id;

	pse_sel_hashinput.app_name = AF_pse.app_name;
	pse_sel_hashinput.pin = pse_sel.pin;

#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

#ifdef X500
	if (x500 && af_access_directory == TRUE) 
		directory_user_dname = af_pse_get_Name();
#endif

	if (k_option) {
		if (keyref) {
			keyinfo = (KeyInfo *)malloc(sizeof(KeyInfo));
			if (sec_get_key(keyinfo, keyref, (Key *) 0) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				p_error(PROG, "Can't read key from keyref", "");
			}
			key.key = keyinfo;
			key.pse_sel = (PSESel *)0;
		}
		else if (keyname) {
			key.pse_sel = &pse_sel;
			pse_sel.object.name = keyname;
			if (sec_read_PSE(&pse_sel, &object_oid, &out_octets) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "%s: Can't read object %s from PSE\n", cmd, pse_sel.object.name);
				exit(-1);
			}
			if (aux_cmp_ObjId(&object_oid, SignCert_OID) && aux_cmp_ObjId(&object_oid, Cert_OID)) {
				if (!(keyinfo = d_KeyInfo(&out_octets))) {
					if (verbose) aux_fprint_error(stderr, 0);
					fprintf(stderr, "%s: Can't decode %s. Expected KeyInfo\n", cmd, pse_sel.object.name);
					exit(-1);
				}
				key.key = keyinfo;
				key.pse_sel = (PSESel *)0;
			}
			else if (!(cert = d_Certificate(&out_octets))) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "%s: Can't decode %s. Expected Certificate.\n", cmd, pse_sel.object.name);
				exit(-1);
			}
		}
	}
	if (t_option) {
		pse_sel.object.name = pkrootname;
		if (sec_read_PSE(&pse_sel, &object_oid, &out_octets) < 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: Can't read object %s from PSE\n", cmd, pse_sel.object.name);
			exit(-1);
		}
		if (aux_cmp_ObjId(&object_oid, PKRoot_OID)) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: %s is not a PKRoot\n", cmd, pse_sel.object.name);
			exit(-1);
		}
		if (!(pkroot = d_PKRoot(&out_octets))) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: Can't decode %s\n", cmd, pse_sel.object.name);
			exit(-1);
		}
	}
	if (f_option) {
		pse_sel.object.name = fcpathname;
		if (sec_read_PSE(&pse_sel, &object_oid, &out_octets) < 0) {
			if (verbose)
				aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: Can't read object %s from PSE\n", cmd, pse_sel.object.name);
			exit(-1);
		}
		if (aux_cmp_ObjId(&object_oid, FCPath_OID)) {
			if (verbose)
				aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: %s is not a FCPath\n", cmd, pse_sel.object.name);
			exit(-1);
		}
		if (!(fcpath = d_FCPath(&out_octets))) {
			if (verbose)
				aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: Can't decode %s\n", cmd, pse_sel.object.name);
			exit(-1);
		}
	}
/*
 *      prepare signature file, certificate file, fcpath file, pkroot file
 */

	for (nf = 0; nf < nfiles; nf++) {
		file = parm[optfiles + nf];
		sig = (char *) malloc(strlen(file) + 8);
		strcpy(sig, file);
		strcat(sig, ".sig");

/*
 *      	read input file, signature etc. and verify
 */

		ostr = aux_file2OctetString(sig);
		if (!ostr) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't read signature file %s\n", sig);
			free(sig);
			continue;
		}
		free(sig);
		verify_signature = d_Signature(ostr);
		aux_free_OctetString(&ostr);
		if (!verify_signature) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't decode signature %s\n", sig);
			continue;
		}
	
		if(!keyinfo) {
			ctf = (char *) malloc(strlen(file) + 8);
			strcpy(ctf, file);
			strcat(ctf, ".ctf");
			if ((ostr = aux_file2OctetString(ctf))) {
				if (!(certs = d_Certificates(ostr))) {
					if (verbose) aux_fprint_error(stderr, 0);
					fprintf(stderr, "Can't decode certificates from %s\n", ctf);
					free(ctf);
					aux_free_OctetString(&ostr);
					aux_free_Signature(&verify_signature);
					continue;
				}
				aux_free_OctetString(&ostr);
			}
			free(ctf);
	
			if(!certs) {
	
				/* no .ctf file, read Certificates from PSE */
	
				certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME);
				aux_free_error();
			}
	
			if(!certs) {
				if(cert) aux_create_Certificates(cert, fcpath);
			}
			else {
				if (cert) {
					if(certs->usercertificate) aux_free_Certificate(&certs->usercertificate);
					certs->usercertificate = cert;
				}
				if (fcpath) {
					if(certs->forwardpath) aux_free_FCPath(&certs->forwardpath);
					certs->forwardpath = fcpath;
				}
			}
		}
	
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
			if(certs) aux_free_Certificates(&certs);
			continue;
		}
	
		more = END;
	
		if (!keyinfo) {
			rc = af_verify(in_ostr, verify_signature, more, certs, (UTCTime *) 0, pkroot);
			if(verbose) aux_fprint_VerificationResult(stderr, verifresult);
			aux_free_VerificationResult(&verifresult);
			aux_free_OctetString(&in_ostr);
			aux_free_Signature(&verify_signature);
			if (rc < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Verification of file %s  f a i l e d\n", file);
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
				aux_free_Certificates(&certs);
				continue;	
			} 
			else {
				originator_name = aux_DName2Name(certs->usercertificate->tbs->subject);
				originator_alias = aux_DName2alias(certs->usercertificate->tbs->subject, LOCALNAME);
				if (originator_alias) fprintf(stderr, "File %s signed by %s", file, originator_alias);
				else fprintf(stderr, "File %s signed by <%s>", file, originator_name);
				if(sec_SignatureTimeDate) {
					signatureTimeDate = aux_readable_UTCTime(sec_SignatureTimeDate);
					fprintf(stderr, " at %s\n", signatureTimeDate);
					free(sec_SignatureTimeDate);
					free(signatureTimeDate);
				}
				else fprintf(stderr, "\n");
				if(originator_name) free(originator_name);
				if(originator_alias) free(originator_alias);	
				aux_free_Certificates(&certs);
			}
		}
		else {
			hashinput.sqmodn_input.nbits = keyinfo->subjectkey.nbits;
			hashinput.sqmodn_input.bits = keyinfo->subjectkey.bits;
			if ((rc = sec_verify(in_ostr, verify_signature, more, &key, &hashinput)) < 0) {
				if (verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "Verification of %s f a i l e d\n", file);
				aux_free_OctetString(&in_ostr);
				aux_free_Signature(&verify_signature);				
			}
			else fprintf(stderr, "Signature of file %s O. K.\n", file);
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
		if(MF_check) MF_fprint(stderr);
	}
	if(sec_time) {
		a_hash_usec = a_hash_usec/1000;
		a_usec = a_usec/1000;
		fprintf(stderr, "Time used for hash computation: %ld.%03ld sec\n", a_hash_sec, a_hash_usec);
		if(rsa_sec || rsa_usec) fprintf(stderr, "Time used for RSA computation:  %ld.%03ld sec\n", a_sec, a_usec);
		else fprintf(stderr, "Time used for DSA computation:  %ld.%03ld sec\n", a_sec, a_usec);
	}
	

	exit(rc);

}


static
void usage(help)
int     help;

{
	aux_fprint_version(stderr);

        fprintf(stderr, "verify: Verify Signatures of Files\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'verify' verifies the given <files>. It uses algorithms and keys according\n");
	fprintf(stderr, "to the parameter -k and -a (default: Cert/SignCert). For each\n");
	fprintf(stderr, "file in <files> it expects file.sig (containing the signature) and\n");
	fprintf(stderr, "optionally file.ctf (containing the user certificate and the forward\n");
 	fprintf(stderr, "certification path). If file.ctf does not exist, the verification will\n");
	fprintf(stderr, "only succeed if the file was signed by oneself.\n\n\n");
        fprintf(stderr, "usage:\n\n");
#ifdef X500
#ifdef SCA
	fprintf(stderr, "verify [-DRvFVWtTUh] [-p <pse>] [-c <cadir>] [-d <dsa>] [-A <authlevel>] [-k <key>] \n");
#else
	fprintf(stderr, "verify [-DRvFVWtUh] [-p <pse>] [-c <cadir>] [-d <dsa>] [-A <authlevel>] [-k <key>] \n");
#endif
	fprintf(stderr, "       [-f <fcpath>] [<files>]\n\n");
#else
#ifdef SCA
	fprintf(stderr, "verify [-DRvFVWtTUh] [-p <pse>] [-c <cadir>] [-k <key>] [-f <fcpath>] [<files>]\n\n");
#else
	fprintf(stderr, "verify [-DRvFVWtUh] [-p <pse>] [-c <cadir>] [-k <key>] [-f <fcpath>] [<files>]\n\n");
#endif
#endif

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-D               Retrieve missing certificates from the Directory (X.500 or .af-db)\n");
	fprintf(stderr, "-F               Consider own FCPath as trusted\n");
        fprintf(stderr, "-R               Consult certificate revocation lists for all cerificates which\n");
        fprintf(stderr, "                 are in the certification path\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for tests only)\n");
        fprintf(stderr, "-t               Control malloc/free behaviour\n");
#ifdef SCA
        fprintf(stderr, "-T               Perform each public key RSA operation in the smartcard  terminal\n");
        fprintf(stderr, "                 instead with the software in the workstation (the latter is default)\n");
#endif
        fprintf(stderr, "-U               Show time used for cryptographic algorithms\n");
        fprintf(stderr, "-h               Write this help text\n");
        fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>       name of CA-directory (default: Environment variable CADIR or .ca)\n");
#ifdef X500
        fprintf(stderr, "-d <dsa>         name of the DSA to be accessed for retrieving certificates\n");
        fprintf(stderr, "                 and certificate revocation lists\n");
        fprintf(stderr, "-A <authlevel>   Level of authentication used for binding to the X.500 Directory\n");
       	fprintf(stderr, "                 It may be SIMPLE or STRONG (default: environment variable AUTHLEVEL, or NONE, if\n");
        fprintf(stderr, "                 this does not exist). STRONG implies the use of signed DAP operations\n");
#endif
        fprintf(stderr, "-k <key>         PSE-object (containing either a certificate or a key) or key reference \n");
        fprintf(stderr, "                 of verification key. Default: Cert/SignCert\n");
        fprintf(stderr, "-f <fcpath>      name of PSE-object which contains the Forward Certification Path\n");
        fprintf(stderr, "<files>          Filenames\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM VERIFY */
}



p_error(t1, t2, t3)
	char           *t1, *t2, *t3;
{
	fprintf(stderr, "%s", t1);
	if (t2 && strlen(t2))
		fprintf(stderr, ": %s", t2);
	if (t3 && strlen(t3))
		fprintf(stderr, " %s", t3);
	fprintf(stderr, "\n");
	exit(-1);
}

char           *
strmtch(a, b)
	char           *a, *b;
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
