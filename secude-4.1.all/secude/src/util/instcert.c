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
 *   	program to install given Certificate on PSE
 */


#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

#define SIGNTYPE "Signature"
#define ENCTYPE  "Encryption"

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	OctetString     * in;
	Certificate     * cert, * protocert;
        RC                rc;
        PSESel          * pse_sel;
        FCPath          * fcpath;
        Certificates    * certs;
	Key	          key;
	KeyType           ktype;
	int	          fd, i;
	Boolean           hierarchy = FALSE, replace = FALSE;
        char            * filename = CNULL;
	extern char	* optarg;
	extern int	  optind, opterr;
	char	        * cmd = * parm, opt, * pin;
	char	        * psename = CNULL, * psepath = CNULL, * cadir = CNULL;
	char 	        * keytype;
        char              x500 = TRUE;
	Boolean 	  onekeypaironly = FALSE;
#ifdef AFDBFILE
	char		  afdb[256];
#endif
#ifdef X500
	CertificateType   certtype;
	int 		  dsap_index = 4;
	char		* callflag;
	char	        * env_auth_level;
#endif
	char		* proc = "main (instcert)";

	optind = 1;
	opterr = 0;

	ktype = SIGNATURE;
	keytype = SIGNTYPE;

	af_access_directory = FALSE;
	MF_check = FALSE;

#ifdef X500
	af_x500_count = 1;	/* default, binding to local DSA */
	callflag = "-call";
	certtype = userCertificate; /* default */

	i = cnt+1;
	while (parm[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
	if(! af_x500_vecptr) {
		aux_add_error(EMALLOC, "af_x500_vecptr", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ", parm[0]);
		fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}
#endif

#ifdef X500
	while ( (opt = getopt(cnt, parm, "c:p:d:A:aehrtvVWHD")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "c:p:ehrtvVWHD")) != -1 ) {
#endif
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
#ifdef X500
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *)malloc(strlen(callflag)+1);
			if(! af_x500_vecptr[1]) {
				fprintf(stderr, "Can't allocate memory");
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1);
			}
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] = (char *)malloc(strlen(optarg) + 1);
			if(! af_x500_vecptr[2]) {
				fprintf(stderr, "Can't allocate memory");
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1);
			}
			strcpy(af_x500_vecptr[2], optarg);
			af_x500_vecptr[3] = (char *)0;
			i = cnt+1;
			dsap_index = 4;
			while (parm[i])
				af_x500_vecptr[dsap_index++] = parm[i++];
			break;
		case 'a':
			certtype = cACertificate;
			break;
		case 'A':
			if (! strcasecmp(optarg, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(optarg, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
			break;
#endif
                case 'H':
                        hierarchy = TRUE;
                        break;
                case 'e':
                        ktype = ENCRYPTION;
			keytype = ENCTYPE;
                        break;
		case 'D':
                        af_access_directory = TRUE;
                        break;
		case 'r':
                        replace = TRUE;
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

	if (!(in = aux_file2OctetString(filename))) {
		fprintf(stderr,"%s: Can't read %s\n", cmd, filename);
		aux_add_error(EINVALID, "Can't read", filename, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	/* now decode Certificate file */
	cert = d_Certificate(in);
	if (!cert) {
		fprintf(stderr,"%s: Can't decode Certificate\n", cmd);
		aux_add_error(EDECODE, "d_Certificate failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

#ifdef X500
	if (x500) directory_user_dname = af_pse_get_Name();
#endif

        if(hierarchy) {
		if(verbose) fprintf(stderr, "%s: Verifying and installing certificate in PSE %s ...\n", cmd, psepath);

		if ( (aux_ObjId2AlgType(cert->tbs->subjectPK->subjectAI->objid) == SIG) && ktype == ENCRYPTION ) {
			fprintf(stderr,"%s: Signature key to be installed as Encryption key\n", cmd);
			aux_add_error(EINVALID, "Signature key to be installed as Encryption key", CNULL, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			exit(-1); 
		}

		protocert = af_pse_get_Certificate(ktype, NULLDNAME, 0);
		if(!protocert){
        		/* check whether PK of cert to be installed fits to SKnew or SignSK or DecSKnew */

			if(onekeypaironly == TRUE)
				pse_sel = af_pse_open(SKnew_OID, FALSE);
			else{
        			if(ktype == SIGNATURE) pse_sel = af_pse_open(SignSK_OID, FALSE);
        			else pse_sel = af_pse_open(DecSKnew_OID, FALSE);
			}
        		if(!pse_sel) {
				if(onekeypaironly == TRUE){
					fprintf(stderr,"%s: Can't open SKnew to check PK\n", cmd);
					aux_add_error(EINVALID, "Can't open SKnew to check PK", CNULL, 0, proc);
				}
				else{
					fprintf(stderr,"%s: Can't open SignSK or DecSKnew to check PK\n", cmd);
					aux_add_error(EINVALID, "Can't open SignSK or DecSKnew to check PK", CNULL, 0, proc);
				}
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1); 
			}
        		key.key = (KeyInfo * ) 0;
        		key.keyref = 0;
        		key.pse_sel = pse_sel;
#ifdef SCA
			if(sec_sctest(psename)) rc = 0;
			else rc = sec_checkSK(&key, cert->tbs->subjectPK);
#else
	        	rc = sec_checkSK(&key, cert->tbs->subjectPK);
#endif
		}
		else {
			rc = aux_cmp_KeyInfo(cert->tbs->subjectPK, protocert->tbs->subjectPK);
			aux_free_Certificate(&protocert);
		}

	        if(rc < 0) {
			if(onekeypaironly == TRUE){
 	                	fprintf(stderr, "%s: PK of certificate to be installed does not fit to SKnew\n", cmd);
				aux_add_error(EINVALID, "PK of certificate to be installed does not fit to SKnew", CNULL, 0, proc);
			}
			else{
 	                	fprintf(stderr, "%s: PK of certificate to be installed does not fit to SignSK or DecSKnew\n", cmd);
				aux_add_error(EINVALID, "PK of certificate to be installed does not fit to SignSK or DecSKnew", CNULL, 0, proc);
			}
  	        	if(verbose) aux_fprint_error(stderr, 0);
			exit(-1); 
		}

                fcpath = af_pse_get_FCPath(NULLDNAME);
                certs = aux_create_Certificates(cert, fcpath);
                rc = af_verify_Certificates(certs, CNULL, (PKRoot * ) 0);
		if(verbose) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);
        	if (rc < 0) { 
                        fprintf(stderr, "%s: Can't verify hierarchy certificate to be installed\n", cmd);
			aux_add_error(EINVALID, "Can't verify hierarchy certificate to be installed", CNULL, 0, proc);
           	        if(verbose) aux_fprint_error(stderr, 0);
        		exit(-1); 
        	}
        	else if(verbose) fprintf(stderr, "%s: Hierarchy Certificate verified\n", cmd);
        }


        rc = af_pse_update_Certificate(ktype, cert, hierarchy);

	if (rc < 0) { 
                fprintf(stderr, "%s: Can't install certificate\n", cmd);
		aux_add_error(EINVALID, "Can't install certificate", CNULL, 0, proc);
       	        if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}
	else if(verbose){
		if (hierarchy){
			if(onekeypaironly == TRUE)
				fprintf(stderr, "%s: Certificate installed as object Cert on PSE %s\n", cmd, psepath);
			else{
				if(ktype == SIGNATURE) fprintf(stderr, "%s: %s Certificate installed as object SignCert on PSE %s\n", cmd, keytype, psepath);
				else fprintf(stderr, "%s: %s Certificate installed as object EncCert on PSE %s\n", cmd, keytype, psepath);
			}
		}
		else{
			if(onekeypaironly == TRUE)
				fprintf(stderr, "%s: Certificate added to object CSet on PSE %s\n", cmd, psepath);
			else{
				if(ktype == SIGNATURE) fprintf(stderr, "%s: %s Certificate added to object SignCSet on PSE %s\n", cmd, keytype, psepath);
				else fprintf(stderr, "%s: %s Certificate added to object EncCSet on PSE %s\n", cmd, keytype, psepath);
			}
		}
	}


	if (hierarchy && af_access_directory == TRUE) {
#ifdef X500
		if ( x500 ) {
			if ( verbose ) {
				fprintf(stderr, "%s: Accessing the X.500 directory entry of ", cmd);
				fprintf(stderr, "owner = \"%s\" ...\n", aux_DName2Name(cert->tbs->subject));
			} 
			rc = af_dir_enter_Certificate(cert, certtype);
			if ( verbose ) {
				if ( rc < 0 )
                        		fprintf(stderr, "%s: Directory entry (X.500) failed.\n", cmd);
        			else fprintf(stderr, "%s: Certificate entered into X.500 Directory.\n", cmd);
              	        }
		}
#endif
#ifdef AFDBFILE
		if ( verbose ) {
			fprintf(stderr, "%s: Accessing the .af-db directory entry of ", cmd);
			fprintf(stderr, "owner = \"%s\" ...\n", aux_DName2Name(cert->tbs->subject));
		}
		rc = af_afdb_enter_Certificate(cert, ktype, replace);
		if ( verbose ) {
			if ( rc < 0 )
                                fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
        		else{
				if(onekeypaironly == TRUE)
					fprintf(stderr, "%s: Certificate entered into .af-db Directory.\n", cmd);
				else
					fprintf(stderr, "%s: %s Certificate entered into .af-db Directory.\n", cmd, keytype);
			}
		}
#endif
	} /* if */


	exit(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "instcert: Install Certificate on PSE\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'instcert' reads file <cert> or stdin, if <cert> is omitted, and installs its\n");
	fprintf(stderr, "content on the PSE.\n\n\n");								

        fprintf(stderr, "usage:\n\n");
#ifdef X500
        fprintf(stderr,"instcert [-aehrtvVWHD] [-p <pse>] [-c <cadir>] [-d <dsa name>] [-A <authlevel>] [cert]\n\n"); 
#else
	fprintf(stderr,"instcert [-ehrtvVWHD] [-p <pse>] [-c <cadir>] [cert]\n\n");
#endif

        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>     PSE name (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>       Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-t               control malloc/free behaviour\n");
	fprintf(stderr, "-e               consider certificate as ENCRYPTION certificate (default: SIGNATURE certificate)\n");
        fprintf(stderr, "-h               write this help text\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
	fprintf(stderr, "-D               store certificate in Directory (X.500 or .af-db)\n");
	fprintf(stderr, "-r               replace existing certificate in .af-db Directory\n");
	fprintf(stderr, "-H               install certificate as hierarchy certificate\n");
	fprintf(stderr, "                 (default: add certificate to set of cross certificates)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>    Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-a               store certificate as cACertificate attribute value (default: userCertificate)\n");
	fprintf(stderr, "-A <authlevel>   Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                 <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                 (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                 STRONG implies the use of signed DAP operations\n");
#endif
	fprintf(stderr, "<cert>           File containing the certificate (or stdin, if omitted)\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM INSTCERT */
}
