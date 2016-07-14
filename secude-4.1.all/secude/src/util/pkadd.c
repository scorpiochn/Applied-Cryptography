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
	int		     i;
	int 		     serialnumber, found;
	char		     yn[81];
	char		     keytype[13], listtype[7];
	char		     buf[4096];
	KeyType 	     type;
	char	             alias[161], * name, * issuer;
	DName              * dname, * issuer_dn;
	int	             names_from_file = 0;
	ObjId  		   * coid;
	SET_OF_Certificate * soc, * found_soc = (SET_OF_Certificate * ) 0, * tmp_soc;
	Certificate 	   * cert;
	char	           * psename = CNULL, * psepath = CNULL, * cadir = CNULL;
	char	           * cmd = * parm, opt, * pin;
	AlgType		     algtype;
	extern char	   * optarg;
	extern int	     optind, opterr;
	char                 interactive = FALSE;
	FILE 		   * ff;
	PSEToc             * psetoc = (PSEToc * )0;
	PSESel		   * pse = (PSESel * )0;
	Boolean		     onekeypaironly = FALSE;
	char		     x500 = TRUE;
#ifdef AFDBFILE
	char 		     afdb[256];
#endif
#ifdef X500
	CertificateType      certtype;
	int 		     dsap_index = 4;
	char		   * callflag;
	char	           * env_auth_level;
#endif

	char		   * proc = "main (pkadd)";



	ff = fopen("/dev/tty", "r");
	
	MF_check = FALSE;

	strcpy(keytype, "SIGNATURE");
	strcpy(listtype, "PKList");
	type = SIGNATURE;

	optind = 1;
	opterr = 0;

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
	while ( (opt = getopt(cnt, parm, "c:p:d:A:aehitvVW")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "c:p:ehitvVW")) != -1 ) {
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
		case 'e':
			strcpy(keytype, "ENCRYPTION");
			strcpy(listtype, "EKList");
			type = ENCRYPTION;
			break;
		case 'i':
			interactive=TRUE;
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
                psepath = (char *)malloc(strlen(cadir)+strlen(psename) + 2);
	 	if(! psepath) {
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
                psepath = (char *)malloc(strlen(psename) + 2);
	 	if(! psepath) {
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

	if (strlen(alias) == 0) 
		names_from_file = 1;

	while (1) {
		if (names_from_file) 
			if (!gets(alias)) 
				break;

		name = aux_alias2Name(alias);
		if(!name) name = aux_cpy_String(alias);
		dname = aux_Name2DName(name);
		if(!dname) {
			fprintf(stderr, "Don't know \"%s\"\n", name);
			exit(-1);
		}
		if (!aux_cmp_Name(name, alias))
			fprintf(stderr, "Look up directory for %s certificate of owner = \"%s\"\n", keytype, name);
		else
			fprintf(stderr, "Look up directory for %s certificate of owner = \"%s\" with alias \"%s\"\n", keytype, name, alias);


#ifdef AFDBFILE
		/* Determine whether X.500 directory shall be accessed */
		strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
		strcat(afdb, "X500");           /* file = .af-db/'X500' */
		if (open(afdb, O_RDONLY) < 0) 
			x500 = FALSE;
#endif
#ifdef X500
		if (x500) {
			directory_user_dname = af_pse_get_Name();
			fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" ...\n\n", name);
			soc = af_dir_retrieve_Certificate(dname,certtype);
			if (!soc) {
				fprintf(stderr, "\nNo certificate with owner = \"%s\" stored in X.500 directory\n", aux_DName2Name(dname));
				if (names_from_file) 
					continue;
				else 
					exit(-1);
			}

			if(af_check_if_onekeypaironly(&onekeypaironly)){
				aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1);
			}

			/*extract certificates of type 'type' from soc and put them into found_soc*/
			while (soc) {
				coid = soc->element->tbs->subjectPK->subjectAI->objid; 

				/* compare, if ENCRYPTION or SIGNATURE object identifier; if the PSE holds one keypair only, however,  */
			        /* only those certificates whose public keys are of algtype ASYM_ENC will be considered		       */

				algtype = aux_ObjId2AlgType(coid);

				if( (onekeypaironly == TRUE && algtype == ASYM_ENC) || (onekeypaironly == FALSE && ((algtype == SIG && type == SIGNATURE) || (algtype == ASYM_ENC && type == ENCRYPTION) || (algtype == ASYM_ENC && type == SIGNATURE))) ) {
					if( ! found_soc ) {
						found_soc = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
						tmp_soc = found_soc;
					}
					else{
						tmp_soc->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
						tmp_soc = tmp_soc->next;
					}
					tmp_soc->element = soc->element;
					tmp_soc->next = (SET_OF_Certificate *)0;
				}								
				soc = soc->next;
			} /*while*/

			if(!found_soc) {
				if (names_from_file) 
					continue;
				else 
					exit(-1);
			}
		}
#endif

#ifdef AFDBFILE
		if (!x500 || !af_x500) {
			fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" ...\n\n", name);
			found_soc = af_afdb_retrieve_Certificate(dname,type);

			if(!found_soc) {
				fprintf(stderr, "\nNo %s certificate with owner \"%s\"", keytype, aux_DName2Name(dname));
				fprintf(stderr, " stored in directory\n");
				if (names_from_file) 
					continue;
				else 
					exit(-1);
			}

		}
#endif

		/* Certificate found: */
		fprintf(stderr, "\nThe directory entry of owner \"%s\"\n", aux_DName2Name(dname));
		if(onekeypaironly == TRUE)
			fprintf(stderr, "contains the following certificates, each identified\n");
		else
			fprintf(stderr, "contains the following %s certificates, each identified\n", keytype);
		fprintf(stderr, "by its issuer and serialnumber:\n\n");
		for(tmp_soc = found_soc; tmp_soc; tmp_soc = tmp_soc->next) {
			fprintf(stderr, " issuer = \"%s\" and\n", aux_DName2Name(tmp_soc->element->tbs->issuer));
			fprintf(stderr, " serial = %d\n\n",tmp_soc->element->tbs->serialnumber);
		}

		if(interactive && found_soc->next) {  /*more than one certificate found*/
			fprintf(stderr, "\nSpecify one certificate:\n");
			fprintf(stderr, " Give serial number (e.g. 1): ");
			while ( !gets(buf) || !buf[0] ) {
				fprintf(stderr, " serial? ");
			}
			sscanf(buf, "%d", &serialnumber);

			/* examine if there is more than one certificate with 
			   the given serial number: */

			soc = (SET_OF_Certificate *)0;
			while (found_soc) {
				if (found_soc->element->tbs->serialnumber == serialnumber){
					if (!soc) {
						soc = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
						tmp_soc = soc;
					}
					else {
						tmp_soc->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
						tmp_soc = tmp_soc->next;
					}
					tmp_soc->element = found_soc->element;
					tmp_soc->next = (SET_OF_Certificate *)0;	
				}			
				found_soc = found_soc->next;
			}
			
			if (!soc) {
				fprintf(stderr,"%s: Wrong serial number!\n", cmd);
				aux_add_error(EINVALID, "Wrong serial number", CNULL, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1);
			}

			if (soc->next) { /*more than one certificate with given serial number*/
				fprintf(stderr, "\nGive issuer of certificate (e.g. C=de; O=gmd; OU=CA).\n");
				fprintf(stderr, " Enter name: ");

				while ( !gets(buf) || !buf[0] ) {
					fprintf(stderr, " Issuer's name? ");
				}
				issuer = (char *) malloc(strlen(buf) + 1);
				strcpy(issuer, buf);
				issuer_dn = aux_alias2DName(issuer);

				found = 0;
				while ( soc && ! found ) {
					if(!aux_cmp_DName(soc->element->tbs->issuer,issuer_dn)){
						found = 1;
						cert = aux_cpy_Certificate(soc->element);
						break;
					}
					soc = soc->next;
				}

				if ( ! found ) {
					aux_add_error(EINVALID, "certificate does not exist", CNULL, 0, proc);
					if(verbose) aux_fprint_error(stderr, 0);
					fprintf(stderr, "%s: The specified certificate does not exist ", cmd);
					fprintf(stderr, "in the returned SET_OF_Certificate !\n");
					exit(-1);
				}
			}
			else cert = soc->element;	
		}
		else cert = found_soc->element;


/* Verification of found certificate is for further study
        	fprintf(stderr, "\nVerify found certificate...\n");
*/

		if ( af_pse_add_PK(type, cert->tbs) < 0 ) {
			if(onekeypaironly == TRUE)
				fprintf(stderr, "%s: Cannot add public key to smartcard list, because ", cmd);
			else	
		        	fprintf(stderr, "%s: Cannot add public %s key to smartcard list, because ", cmd, keytype);
			if ( err_stack && ((err_stack->e_number == EPK) || (err_stack->e_number==EPKCROSS)) ) {
				if(onekeypaironly == TRUE)
					fprintf(stderr, "it already exists in smartcard PKList");
				else
					fprintf(stderr, "it already exists in smartcard %s", listtype);
				if (err_stack && (err_stack->e_number==EPK)) fprintf(stderr, " certified by exactly the same CA.\n");
				else fprintf(stderr, " certified by another CA.\n");
				if(onekeypaironly == TRUE)
					fprintf(stderr, "\nThe ToBeSigned in the PKList ");
				else
					fprintf(stderr, "\nThe ToBeSigned in the %s ", listtype);
				fprintf(stderr, "is as follows:\n\n");
				if (err_stack && (err_stack->e_addrtype==ToBeSigned_n)) aux_fprint_ToBeSigned(stderr, (ToBeSigned *)err_stack->e_addr);
			}
			else fprintf(stderr, " there has been an internal error.\n");
		}
		else {
			if(onekeypaironly == TRUE){
				fprintf(stderr, "\n\"%s\" with new public key added into smartcard PKList", aux_DName2Name(dname));
				fprintf(stderr, "\nYour updated PKList now looks like this:\n\n");
				fprintf(stderr, " ****************** PKList ******************\n");
			}
			else{
				fprintf(stderr, "\n\"%s\" with new public %s key added into smartcard %s", aux_DName2Name(dname), keytype, listtype);
				fprintf(stderr, "\nYour updated %s now looks like this:\n\n", listtype);
				fprintf(stderr, " ****************** %s ******************\n", listtype);
			}
			aux_fprint_PKList (stderr, af_pse_get_PKList(type));
		}

		if (names_from_file == 0) break;
	}

	exit(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "pkadd: Download Public Key into Cache\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'pkadd' retrieves the certificates of owner 'Name' from the Directory\n");
	fprintf(stderr, "and downloads the requested public key information into the cache of\n");
	fprintf(stderr, "trusted public keys (PKList or EKList) in the indicated PSE.\n\n\n");

        fprintf(stderr, "usage:\n\n");
#ifdef X500
	fprintf(stderr, "pkadd [-aehitvVW] [-p <pse>] [-c <cadir>] [-d <dsa name>] [-A <authlevel>] [Name]\n\n");
#else
	fprintf(stderr, "pkadd [-ehitvVW] [-p <pse>] [-c <cadir>] [Name]\n\n");
#endif


        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>     PSE name (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>       Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-e               consider ENCRYPTION certificates only\n");
	fprintf(stderr, "                 (default: consider SIGNATURE certificates only)\n");
        fprintf(stderr, "-h               write this help text\n");
	fprintf(stderr, "-i               let user specify certificate whose public key is to be downloaded\n");
	fprintf(stderr, "-t               control malloc/free behaviour\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>    Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-a               read cACertificate attribute (default: userCertificate)\n");
	fprintf(stderr, "-A <authlevel>   Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                 <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                 (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                 STRONG implies the use of signed DAP operations\n");
#endif
	fprintf(stderr, "<Name>           Owner of the certificate whose public key is downloaded into the cache\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM PKADD */
}
