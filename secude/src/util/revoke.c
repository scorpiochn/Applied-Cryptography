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
#include "af.h"
#include "cadb.h"

extern CrlPSE * PemCrl2CrlPSE();
char * getenv();
static int    getserial();

int             verbose = 0;
static void     usage();

main(cnt, parm)
int	cnt;
char	**parm;
{
	int			  i;
	int 			  serial, found;
	char			  buf[256];
	char			  alias[161], * name, * issuer;
	char	        	  calogfile[256];
	char		        * nextupdate = CNULL;
	DName 		        * dname;
	Certificate		* cert;
	Certificates            * certs;
	Boolean      	          update;
	AlgId                   * algorithm = (AlgId * )0;
	AlgId                   * keyalgid;
	char	      		* psename = CNULL, * psepath = CNULL, * cadir = CNULL, * xx;
	char	       		* cmd = * parm, opt, * pin;
	extern char		* optarg;
	extern int		  optind, opterr;
	char           		  interactive = FALSE;
	ObjId                   * oid;
	RC                        rc;
	UTCTime 		* lastUpdate, * nextUpdate;
	RevCertPem     		* revcertpem;
	PemCrlWithCerts		* pemcrlwithcerts;
	SEQUENCE_OF_RevCertPem  * revcertpemseq;
	CrlPSE	                * crlpse;
	FILE		        * ff;
	char		          x500 = TRUE;
#ifdef AFDBFILE
	char		          afdb[256];
#endif
#ifdef X500
	int 		          dsap_index = 4;
	char		        * callflag;
	char	                * env_auth_level;
#endif
	char		        * proc = "main (revoke)";

	ff = fopen("/dev/tty", "r");

	optind = 1;
	opterr = 0;

	logfile = (FILE * )0;

	af_access_directory = FALSE;
	MF_check = FALSE;

#ifdef X500
	af_x500_count = 1;	/* default, binding to local DSA */
	callflag = "-call";

	i = cnt+1;
	while (parm[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
	if(! af_x500_vecptr) {
		fprintf(stderr, "%s: ", parm[0]);
		fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}
#endif

#ifdef X500
	while ( (opt = getopt(cnt, parm, "a:c:p:d:A:u:htvVWD")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "a:c:p:u:htvVWD")) != -1 ) {
#endif
		switch (opt) {
		case 'a':
			if (algorithm) 
				usage(SHORT_HELP);
			else {
                        	oid = aux_Name2ObjId(optarg);
                        	if (aux_ObjId2AlgType(oid) != SIG) usage(SHORT_HELP);
				algorithm = aux_ObjId2AlgId(oid);
			}
			break;
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
				exit(-1);
			}
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] = (char *)malloc(strlen(optarg) + 1);
			if(! af_x500_vecptr[2]) {
				fprintf(stderr, "Can't allocate memory");
				exit(-1);
			}
			strcpy(af_x500_vecptr[2], optarg);
			af_x500_vecptr[3] = (char *)0;
			i = cnt+1;
			dsap_index = 4;
			while (parm[i])
				af_x500_vecptr[dsap_index++] = parm[i++];
			break;
		case 'A':
			if (! strcasecmp(optarg, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(optarg, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
			break;
#endif
		case 'D':
                        af_access_directory = TRUE;
                        break;
		case 'u':
			if (nextupdate) usage(SHORT_HELP);
			else nextupdate = optarg;
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
		strcpy(alias, parm[optind++]);

	if (optind < cnt) 
		usage(SHORT_HELP);

        if(!psename) psename = getenv("CAPSE");
        if(!cadir) cadir = getenv("CADIR");

        if(!psename) psename = DEF_CAPSE;
        if(!cadir) cadir = DEF_CADIR;
	
	psepath = (char *)malloc(strlen(cadir)+strlen(psename)+2);
	if( !psepath ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}
	strcpy(psepath, cadir);
	strcat(psepath, "/");
	strcat(psepath, psename);

        pin = getenv("CAPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
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

	dname = af_pse_get_Name();
	name = aux_DName2Name(dname);
	aux_free_DName(&dname);
	pemcrlwithcerts = af_cadb_get_PemCrlWithCerts(name, cadir);
	if(! pemcrlwithcerts || ! pemcrlwithcerts->pemcrl){
		fprintf(stderr, "%s: WARNING: Your own PemCrl is NOT stored in your local database!\n", cmd);
		exit(-1);
	}
	fprintf(stderr, "\nThis is your locally stored revocation list:\n\n");
	aux_fprint_PemCrl(stderr, pemcrlwithcerts->pemcrl);
	fprintf(stderr, "\n\nVerifying your locally stored PemCrl ...\n\n");
	certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME); 
	rc = af_verify(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END, certs, (UTCTime * )0, (PKRoot * )0);
	aux_fprint_VerificationResult(stderr, verifresult);
	aux_free_VerificationResult(&verifresult);
	if (rc == 0)
		fprintf(stderr, "%s: Verification of locally stored PemCrl s u c c e e d e d!\n\n", cmd);
	else {
		fprintf(stderr, "%s: WARNING: Verification of locally stored PemCrl f a i l e d!\n", cmd);
		exit(-1);
	}
	
	xx = "y";
	update = 0;
	while (strcmp(xx, "n")) {
		free (xx);
		xx = CNULL;
		fprintf(stderr, "\nEnter serial number of certificate which is to be revoked:\n");
		serial = getserial();
		i = 0;
		while ((serial < 0) && (i < 3)) {
			fprintf(stderr, "Serial number must be a positive integer!\n");
			serial = getserial();
			i++;
		}
		if (i == 3) exit (-1);
		cert = af_cadb_get_Certificate(serial, cadir);
		if (!cert) {
			fprintf(stderr, "\nNo certificate with serial ");
			fprintf(stderr, "number %d in CA database!\n", serial);
			fprintf(stderr, "\nNew choice? [y/n]: ");
		}
		else {	
			revcertpem = af_create_RevCertPem(serial);
			if (!af_search_RevCertPem(pemcrlwithcerts->pemcrl, revcertpem)) { 
				fprintf(stderr, "\nThe following certificate with serial number ");
				fprintf(stderr, "%d is being revoked:\n\n", serial);
				aux_fprint_Certificate(stderr, cert);
				revcertpemseq = (SEQUENCE_OF_RevCertPem * )malloc(sizeof(SEQUENCE_OF_RevCertPem));
				if (!revcertpemseq) {
					fprintf(stderr, "Can't allocate memory");
					exit (-1);
				}

				revcertpemseq->element = aux_cpy_RevCertPem(revcertpem);
				aux_free_RevCertPem(&revcertpem);

				revcertpemseq->next = pemcrlwithcerts->pemcrl->tbs->revokedCertificates;  
				/* existing or NULL pointer */
				pemcrlwithcerts->pemcrl->tbs->revokedCertificates = revcertpemseq;
				update = 1;
				fprintf(stderr, "\nMore certificates to be revoked? [y/n]: ");
			}
			else {
				fprintf(stderr, "\nCertificate with serial number %d ", serial);
				fprintf(stderr, "already revoked !\n");
				fprintf(stderr, "\nNew choice? [y/n]: ");
			}
		}
		gets(buf);
		xx = buf;
		while ( strcmp(xx, "y") && strcmp(xx, "n") ) {
			fprintf(stderr, "\nAnswer must be 'y' or 'n' !\n\n");
			fprintf(stderr, "\nNew choice? [y/n]: ");
			gets(buf);
			xx = buf;
		}
	}  /*while*/
		
	if (!update) {
		fprintf(stderr, "\nNo update done on revocation list!\n");
		aux_free_PemCrlWithCerts(&pemcrlwithcerts);
		exit (-1);
	}

	pemcrlwithcerts->pemcrl->tbs->lastUpdate = aux_current_UTCTime();
	if(nextupdate){ 
		if (aux_interval_UTCTime(CNULL, pemcrlwithcerts->pemcrl->tbs->lastUpdate, nextupdate)) {
			fprintf(stderr, "%s: ",cmd);
          		fprintf(stderr, "Validity interval of PemCrl incorrectly specified\n");
			exit(-1);
		}
		pemcrlwithcerts->pemcrl->tbs->nextUpdate = aux_cpy_String(nextupdate);
	}
	else
		pemcrlwithcerts->pemcrl->tbs->nextUpdate = get_nextUpdate(pemcrlwithcerts->pemcrl->tbs->lastUpdate);

	pemcrlwithcerts->pemcrl->sig = (Signature * )calloc(1, sizeof(Signature));
	if (! pemcrlwithcerts->pemcrl->sig) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}
	pemcrlwithcerts->pemcrl->sig->signature.nbits = 0;
	pemcrlwithcerts->pemcrl->sig->signature.bits = CNULL;

	keyalgid = af_pse_get_signAI();
	if(keyalgid && algorithm) {
		if(aux_ObjId2AlgEnc(algorithm->objid) != aux_ObjId2AlgEnc(keyalgid->objid)) {
			fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "sig_alg does not fit to key\n");
			exit(-1);
		}
	}
	if(!algorithm) {
		if(keyalgid) switch(aux_ObjId2AlgEnc(keyalgid->objid)) {
			case RSA:
				pemcrlwithcerts->pemcrl->sig->signAI = aux_cpy_AlgId(md2WithRsaEncryption);
				break;
			case DSA:
				pemcrlwithcerts->pemcrl->sig->signAI = aux_cpy_AlgId(dsaWithSHA);
				break;
		}
		else {
			fprintf(stderr, "%s: ",cmd);
 			fprintf(stderr, "can't determine sig alg\n");
			exit(-1);
		}
	}
	else
		pemcrlwithcerts->pemcrl->sig->signAI = aux_cpy_AlgId(algorithm);

	pemcrlwithcerts->pemcrl->tbs->signatureAI = aux_cpy_AlgId(pemcrlwithcerts->pemcrl->sig->signAI);

	if ((pemcrlwithcerts->pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrlwithcerts->pemcrl->tbs)) == NULLOCTETSTRING) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Can't encode pemcrlwithcerts->pemcrl->tbs\n");
		exit (-1);
	}

	fprintf(stderr, "\nThe following PemCrl is to be signed. ");
	fprintf(stderr, "Please check it:\n\n");
	aux_fprint_PemCrlTBS(stderr, pemcrlwithcerts->pemcrl->tbs);
	fprintf(stderr, "\nDo you want to sign the displayed revocation list PemCrl ?\n");
	fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");

	af_pse_close(NULLOBJID);

	if ( af_sign(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Signature of revocation list failed\n");
		exit (-1);
	}


	/* Update on Directory entry, PSE, and CA directory: */

	fprintf(stderr, "\n**********************************************\n");

	/* update directory entry */
#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif
#ifdef X500
	if (x500 && af_access_directory == TRUE) {
		directory_user_dname = af_pse_get_Name();
		if ( verbose )
			fprintf(stderr, "\nTrying to update your X.500 directory entry ...");
		rc = af_dir_enter_PemCrl(pemcrlwithcerts->pemcrl);
		if ( verbose ) {
			if ( rc < 0 ) 
				fprintf(stderr, "\n Directory entry (X.500) f a i l e d !\n");
			else fprintf(stderr, "\n Done!\n");
			fprintf(stderr, "\n**********************************************\n");
		}
	}
#endif
#ifdef AFDBFILE
	if (af_access_directory == TRUE) {
		if ( verbose )
			fprintf(stderr, "\nTrying to update your .af-db directory entry ...");
		rc = af_afdb_enter_PemCrl(pemcrlwithcerts->pemcrl);
		if ( verbose ) {
			if ( rc < 0 ) 
				fprintf(stderr, "\n Directory entry (.af-db) f a i l e d !\n");
			else fprintf(stderr, "\n Done!\n");
			fprintf(stderr, "\n**********************************************\n");
		}
	}
#endif

	/* update PSE object CrlSet, even if the directory entry failed */
	crlpse = PemCrl2CrlPSE (pemcrlwithcerts->pemcrl);
	fprintf(stderr, "\nUpdating PSE object CrlSet ...\n");
	rc = af_pse_add_PemCRL(crlpse);
	if (rc != 0) {
		fprintf(stderr, "\n Cannot update PSE object CrlSet.\n");
		aux_free_CrlPSE (&crlpse);
	}
	else fprintf(stderr, "\n Done!\n");
	aux_free_CrlPSE (&crlpse);
	fprintf(stderr, "\n**********************************************\n");

	/* update pemcrlwithcerts database in CA directory, even if the directory entry failed */
	fprintf(stderr, "\nUpdating 'pemcrlwithcerts' database in CA directory \"%s\" ...\n", cadir);

	if(*cadir != '/') {
		strcpy(calogfile, getenv("HOME"));
		strcat(calogfile, "/");
		strcat(calogfile, cadir);
	}
	else strcpy(calogfile, cadir);
	strcat(calogfile, "/");
	strcat(calogfile, "calog");
	logfile = fopen(calogfile, LOGFLAGS);
	if(logfile == (FILE * ) 0) {
		fprintf(stderr, "%s: Can't open %s\n", cmd, CALOG);
		exit(-1);
	}
	rc = af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir);
	if(rc != 0){
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot store your updated PemCrl in your 'pemcrlwithcerts' database!\n");
		exit(-1);
	}
	fclose(logfile);
	logfile = (FILE * )0;
	fprintf(stderr, "\nMost current version of PemCrl stored in 'pemcrlwithcerts' database in ");
	fprintf(stderr, "CA directory \"%s\".\n\n", cadir);

	exit(0);
}



static
int getserial() {
	char * newstring;
	char * proc = "getserial";

	fprintf(stderr, " Serial number: ");
	newstring = gets((char *)malloc(10));
 	if( !newstring ) {
		aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
		fprintf(stderr, "Can't allocate memory");
		return (- 1);
	}
	if (strlen(newstring) == 0) {
		free(newstring);
		newstring = CNULL;
		return (- 1);
	}
        return(atoi(newstring));
}



static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);
        fprintf(stderr, "revoke: Revoke one or more Certificates (CA command)\n\n\n");
        fprintf(stderr, "usage:\n\n");
#ifdef X500
        fprintf(stderr,"revoke [-htvVWD] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-u <nextupdate>] [-d <dsa name>] [-A <authlevel>]\n\n"); 
#else
	fprintf(stderr,"revoke [-htvVWD] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-u <nextupdate>]\n\n");
#endif

        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>     PSE name (default: .capse)\n");
        fprintf(stderr, "-c <cadir>       name of CA-directory (default: .ca)\n");
	fprintf(stderr, "-a <issueralg>   Issuer algorithm associated with the signature of the PEM Crl\n");
	fprintf(stderr, "-u <nextupdate>    Time and date of next scheduled update of PEM revocation list\n");
	fprintf(stderr, "-t               enable memory checking\n");
        fprintf(stderr, "-h               write this help text\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
	fprintf(stderr, "-D               store updated revocation list in Directory (X.500 or .af-db)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>    name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-A <authlevel>   level of authentication used for binding to the X.500 Directory\n");
#endif
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM REVOKE */
}
