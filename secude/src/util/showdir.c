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

static CERT();

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
	Certificate 	        * cert;
	KeyType 	          keytype = SIGNATURE;
	SET_OF_Certificate      * certset;
	char	       	          alias[161];
	DName		        * owner;
	int		          i;
	char	                * psename = CNULL, * psepath = CNULL, * cadir = CNULL;
	char 		        * attrtype = CNULL, * name = CNULL;
	char	                * cmd = * parm, opt, * pin;
	AlgType		          algtype;
	SET_OF_CertificatePair  * cpairset;
	PemCrl	 	* pemcrl;
	extern char	        * optarg;
	extern int	          optind, opterr;
	char			  x500 = TRUE;
#ifdef AFDBFILE
	char			  afdb[256];
#endif
#ifdef X500
	char	                * env_auth_level;
	CertificateType           certtype;
	int		          dsap_index = 4;
	char	                * callflag;
#endif
	char                    * proc = "main (showdir)";


	MF_check = FALSE;

	optind = 1;
	opterr = 0;


#ifdef X500
	af_x500_count = 1;	/* default, binding to local DSA */
	callflag="-call";
	certtype = userCertificate; /* default */

	i = cnt+1;
	while (parm[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
	if(! af_x500_vecptr) {
		aux_add_error(EMALLOC, "af_x500_vecptr", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Can't allocate memory\n");
		exit(-1);
	}
#endif

#ifdef X500
	while ( (opt = getopt(cnt, parm, "c:p:o:d:A:aehtvVW")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "c:p:o:ehtvVW")) != -1 ) {
#endif
		switch (opt) {
#ifdef X500
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *)malloc(strlen(callflag)+1);
			if( !af_x500_vecptr[1] ) {
				aux_add_error(EMALLOC, "af_x500_vecptr[1]", CNULL, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "%s: ",cmd);
				fprintf(stderr, "Can't allocate memory\n");
				exit(-1);
			}
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] = optarg;
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
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
		case 'o':
			if (attrtype) usage(SHORT_HELP);
			else attrtype = optarg;
			break;
		case 'e':
			keytype = ENCRYPTION;
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
		strcpy(alias, parm[optind++]);

	if (optind < cnt) usage(SHORT_HELP);

	if ( ! attrtype )
		attrtype = "cert";
	else if (strcasecmp(attrtype,"cert") && strcasecmp(attrtype,"cross") && strcasecmp(attrtype,"rev")){
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Objname must be either 'cert' or 'cross' or 'rev'\n");
		usage(SHORT_HELP);
	}

	if (strlen(alias) == 0) usage(SHORT_HELP);


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
			if(verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "Can't allocate memory for psepath\n");
			exit(-1);
		}
		strcpy(psepath, cadir);
		strcat(psepath, "/");
		strcat(psepath, psename);
	}	
	else {
		psepath = (char *)malloc(strlen(psename)+2);
		if( !psepath ) {
			if(verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "Can't allocate memory for psepath\n");
			exit(-1);
		}
		strcpy(psepath, psename);
	}	

	if (cadir)
		pin = getenv("CAPIN");
        else
		pin = getenv("USERPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		exit(-1);
	} 

	name = aux_alias2Name(alias);
	if(name) owner = aux_Name2DName(name);
	else owner = aux_Name2DName(alias); 

	if (!owner) {
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Name cannot be transformed into DName-structure.\n");
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
	if(x500) {
		if (auth_level == DBA_AUTH_NONE) {
			env_auth_level = getenv("AUTHLEVEL");
			if (env_auth_level) {
				if (! strcasecmp(env_auth_level, "STRONG"))
					auth_level = DBA_AUTH_STRONG;
				else if (! strcasecmp(env_auth_level, "SIMPLE"))
					auth_level = DBA_AUTH_SIMPLE;
			}
		}

		directory_user_dname = af_pse_get_Name();

		if (!aux_cmp_Name(name, alias))
			fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" ...\n", name);
		else
			fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" with alias \"%s\" ...\n", name, alias);
	}
#endif
#ifdef AFDBFILE
	if (!x500 || !af_x500){
		if (!aux_cmp_Name(name, alias))
			fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" ...\n", name);
		else
			fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" with alias \"%s\" ...\n", name, alias);
	}
#endif

	if (!strcmp(attrtype,"cert")) {
#ifdef X500
		if ( x500 ){
			certset = af_dir_retrieve_Certificate(owner,certtype);
			if (!certset) { 
				if(verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "\n%s: ",cmd);
				fprintf(stderr, "No certificate with owner \"%s\" in the X.500 Directory.\n", name); 
				exit(-1); 
			}
			for ( ; certset; certset = certset->next) {
				cert = certset->element;
				switch (aux_ObjId2AlgType(cert->tbs->subjectPK->subjectAI->objid)) {
				case ASYM_ENC:
					if ((keytype == ENCRYPTION) || (keytype < 0)) {
						CERT("Encryption", cert);
						break;
					}
					if (keytype == SIGNATURE) {
						CERT("Signature", cert);
						break;
					}
				case SIG:
					if ((keytype == SIGNATURE) || (keytype < 0)) CERT("Signature", cert);
					break;
				}  /* switch */
			}  /* for */
			fprintf(stderr, "\n---- END.\n");
		}
#endif
#ifdef AFDBFILE
		if (!x500 || !af_x500){
			certset = af_afdb_retrieve_Certificate(owner,keytype);
			if (!certset) { 
				if(verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "\n%s: ",cmd);
				if(keytype == SIGNATURE)
					fprintf(stderr, "No SIGNATURE certificate with owner \"%s\" in the .af-db Directory.\n", name);
				else fprintf(stderr, "No ENCRYPTION certificate with owner \"%s\" in the .af-db Directory.\n", name);
				exit(-1); 
			}
			if(keytype == SIGNATURE)
				CERT("Signature", certset->element);
			else  
				CERT("Encryption", certset->element);
			fprintf(stderr, "\n---- END.\n");
		}
#endif


	}
	else if (!strcmp(attrtype,"cross")) {
#ifdef X500
		if ( x500 )
			cpairset = af_dir_retrieve_CertificatePair(owner);
#endif
#ifdef AFDBFILE
		if (!x500 || !af_x500)
			cpairset = af_afdb_retrieve_CertificatePair(owner);
#endif
		if (!cpairset) {
			if(verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "Directory access f a i l e d.\n");
			exit (-1);
                }
		aux_fprint_CertificatePairSet(stderr, cpairset);
	}
	else {
#ifdef X500
		if  ( x500 )
			pemcrl = af_dir_retrieve_PemCrl(owner);
#endif
#ifdef AFDBFILE
		if (!x500 || !af_x500)
			pemcrl = af_afdb_retrieve_PemCrl(owner);
#endif
		if (!pemcrl) {
			if(verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "%s: ",cmd);
			fprintf(stderr, "Directory access f a i l e d.\n");
			exit (-1);
                }
		fprintf(stderr, "\n");
		aux_fprint_PemCrl(stderr, pemcrl);
	}


	exit(0);
}


static CERT(s, c) 
Certificate*c; 
{ 
	fprintf(stderr, "\n---- %s Certificate ----\n\n", s); 
	aux_fprint_Certificate(stderr, c); 

	return(0);
}




static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

	fprintf(stderr, "showdir: Retrieve and Show Security Attributes from Directory\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'showdir' reads a security attribute from the directory entry of 'Name'\n");
	fprintf(stderr, "and prints its contents in an appropriate format.\n\n\n");

        fprintf(stderr, "usage:\n\n");
#ifdef X500
	fprintf(stderr, "showdir [-aehtvVW] [-p <pse>] [-c <cadir>] [-o <attributeType>] [-d <dsa name>] [-A <authlevel>] [Owner's Name].\n\n"); 
#else
	fprintf(stderr, "showdir [-ehtvVW] [-p <pse>] [-c <cadir>] [-o <attributeType>] [Name].\n\n");
#endif

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>        PSE name (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>          Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-e                  consider ENCRYPTION certificates only\n");
	fprintf(stderr, "-o <attributeType>  Attribute whose value is requested (default: certificate)\n");
	fprintf(stderr, "                    supported attribute types:\n"); 
	fprintf(stderr, "                    'cert' (certificate),\n");
	fprintf(stderr, "                    'cross' (cross certificate pair), and\n");
	fprintf(stderr, "                    'rev' (PEM revocation list)\n");
        fprintf(stderr, "-h                  write this help text\n");
	fprintf(stderr, "-t                  control malloc/free behaviour\n");
        fprintf(stderr, "-v                  verbose\n");
        fprintf(stderr, "-V                  Verbose\n");
        fprintf(stderr, "-W                  Grand Verbose (for testing only)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>       Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-a                  read cACertificate attribute (default: userCertificate)\n");
	fprintf(stderr, "-A <authlevel>      Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                    <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                    (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                    STRONG implies the use of signed DAP operations\n");
#endif
	fprintf(stderr, "<Name>              Name of directory entry to be accessed\n");         
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM AFPRINT */
}
