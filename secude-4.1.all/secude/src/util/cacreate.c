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
	CA creation


*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#ifdef NDBM
#include <ndbm.h>  
#else
#include <dbm.h>
#endif

#include "cadb.h"

#ifndef S_IRWXU
#define S_IRWXU (S_IREAD|S_IWRITE|S_IEXEC)
#endif

extern int errno;
extern char *sys_errlist[ ];

static int	cainit(), encrinit(), localinit(), pemcrlinit();

Certificate      * af_create_Certificate();
CrlPSE		 * PemCrl2CrlPSE();

char	* getenv();
char    * cmd;
UTCTime * notbefore, * notafter;
Name	* caname;

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	int	        i;
	DName		*ca_dname;
	char	        *psename, *psepath, *cadir, *cadir_abs, * nextupdate = CNULL;
	char	        *home, *pin;
	Boolean	        onekeypaironly = TRUE;
	OctetString	*encname;
	extern char	*optarg;
	extern int	optind, opterr;
	char	        opt, line[256];
	AlgId           *algorithm = DEF_ISSUER_ALGID;
	AlgId           *s_alg = DEF_SUBJECT_SIGNALGID, *e_alg = DEF_SUBJECT_ENCRALGID;
        ObjId           *oid;
	OctetString     *ostr;
        int             keysizes[2];
        int             ka = 0, kk = 0, kx = 0;
	int	        keysize = DEFKEYLEN;
	SerialNumbers   * serialnums;
	int		serialnumber;
	int             rcode;

#ifdef X500
	int 		  dsap_index = 4;
	char		* callflag;
	char	        * env_auth_level;
#endif

	char 		*proc = "main (cacreate)";


        cmd = *parm;
        cadir = CNULL;
	caname	 = CNULL;
	psename	 = CNULL;
	serialnumber = 0;
        sec_verbose = FALSE;

	keysizes[0] = DEFKEYLEN;
	keysizes[1] = DEFKEYLEN;
	ka = 2;

	optind = 1;
	opterr = 0;

	af_access_directory = FALSE;
	MF_check = FALSE;

	notbefore = notafter = (UTCTime * )0;

#ifdef X500
	af_x500_count = 1;	/* default, binding to local DSA */
	callflag = "-call";

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
nextopt:

#ifdef X500
	while ( (opt = getopt(cnt, parm, "a:A:d:c:s:e:k:p:n:l:f:u:hqtvDVW")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "a:c:s:e:k:p:n:l:f:u:hqtvDVW")) != -1 ) {
#endif
		switch (opt) {
		case 'a':
                        oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(oid) != SIG) usage(SHORT_HELP);
			algorithm = aux_ObjId2AlgId(oid);
			break;
		case 'n':
			serialnumber = atoi(optarg);
			if (serialnumber < 0) usage(SHORT_HELP);
			break;
		case 'f':
			if (notbefore) usage(SHORT_HELP);
			else notbefore = optarg;
			break;
		case 'l':
			if (notafter) usage(SHORT_HELP);
			else notafter = optarg;
			break;
		case 'u':
			if (nextupdate) usage(SHORT_HELP);
			else nextupdate = optarg;
			break;
		case 's':
                        oid = aux_Name2ObjId(optarg);
                        if ( (aux_ObjId2AlgType(oid) != SIG) && (aux_ObjId2AlgType(oid) != ASYM_ENC) ) 
				usage(SHORT_HELP);
			s_alg = aux_ObjId2AlgId(oid);
			kk = 0;
			break;
		case 'e':
                        oid = aux_Name2ObjId(optarg);
                        if(aux_ObjId2AlgType(oid) != ASYM_ENC) usage(SHORT_HELP);
			e_alg = aux_ObjId2AlgId(oid);
			kk = 1;
			break;
                case 'k':
			keysize = atoi(optarg);
			if ( (keysize < MINKEYLEN) || (keysize > MAXKEYLEN)) usage(SHORT_HELP);
			keysizes[kk] = keysize;
			break;
		case 'c':
			if (cadir) usage(SHORT_HELP);
			else cadir = optarg;
			break;
		case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
			break;
                case 'q':
                        onekeypaironly = FALSE;
                        break;
#ifdef X500
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *)malloc(strlen(callflag)+1);
			if(! af_x500_vecptr[1]){
				fprintf(stderr, "Can't allocate memory");
				if(verbose) aux_fprint_error(stderr, 0);
				exit(-1);
			}
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] =  (char *)malloc(strlen(optarg) + 1);
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

	if (optind < cnt) {
		caname = parm[optind++];
		goto nextopt;
	}

        if(!psename) psename = DEF_CAPSE;

        if(!cadir) cadir = DEF_CADIR;

	if ((optind < cnt)) usage(SHORT_HELP);

	/* first steps: 
		create PSE
		associate name
		generate sign key
		store this as PKRoot
		and a pseudo certificate
	   gives PSE with signature key
	*/

        if(cadir[0] != '/') {
		home = getenv("HOME");
		if (!home) home = "";
		cadir_abs = (char *)malloc(strlen(home)+strlen(cadir)+10);
		if (!cadir_abs) {
			aux_add_error(EMALLOC, "cadir_abs", cmd, char_n, proc);
			exit(-1);
		}
		strcpy(cadir_abs, home);
		strcat(cadir_abs, "/");
		strcat(cadir_abs, cadir);
	}
	else {
		cadir_abs = (char *)malloc(strlen(cadir)+10);
		if (!cadir_abs) {
			aux_add_error(EMALLOC, "cadir_abs", cmd, char_n, proc);
			exit(-1);
		}
		strcpy(cadir_abs, cadir);
	}
		
	if (mkdir(cadir_abs, S_IRWXU) < 0) {
                fprintf(stderr, "%s: Can't create %s (%d %s)\n", cmd, cadir, errno, sys_errlist[errno]);
		aux_add_error(EINVALID, "Can't create", cmd, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

        psepath = (char *)malloc(strlen(cadir)+strlen(psename)+2);
 	if( !psepath ) {
                rmdir(cadir);
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "psepath", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}
        strcpy(psepath, cadir);
        strcat(psepath, "/");
        strcat(psepath, psename);

        pin = getenv("CAPIN");

	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if(verbose) aux_fprint_error(stderr, 0);
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

	accept_alias_without_verification = TRUE;
        if(!caname) { /* read CA directory name from stdin */
again:
                fprintf(stderr, "%s: Directory name of new CA: ", cmd);
                line[0] = '\0';
                gets(line);
                caname = line;
		if(!(ca_dname = aux_alias2DName(caname))) {
                        fprintf(stderr, "%s: Invalid directory name\n", cmd);
                        goto again;
                }
        }
        else {
		if(!(ca_dname = aux_alias2DName(caname))) {
                        fprintf(stderr, "%s: Invalid directory name\n", cmd);
			aux_add_error(EINVALID, "Invalid directory name", cmd, char_n, proc);
			if(verbose) aux_fprint_error(stderr, 0);
                        exit(-1);
                }
	}

	if (localinit(caname, cadir_abs) != 0) {
                rmdir(cadir);
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't init CA");
		aux_add_error(EINVALID, "localinit failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
                exit(-1);
        }

        serialnums = (SerialNumbers *)malloc(sizeof(SerialNumbers));
 	if( !serialnums ) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "serialnums", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}
	serialnums->initial = serialnumber;
	serialnums->actual = serialnumber;

	if (cainit(ca_dname, s_alg, cadir_abs, serialnums, algorithm, keysizes[0], onekeypaironly) != 0) {
                rmdir(cadir);
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't init CA");
		aux_add_error(EINVALID, "cainit failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
                exit(-1);
        }

	if (onekeypaironly == FALSE) { 
		if(encrinit(ca_dname, e_alg, cadir_abs, algorithm, keysizes[1]) != 0) {
                	rmdir(cadir);
			fprintf(stderr, "%s: ",cmd);
                	fprintf(stderr, "Can't init CA");
			aux_add_error(EINVALID, "encrinit failed", CNULL, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
                	exit(-1);
        	}
	}

	if(pemcrlinit(cadir_abs, algorithm, nextupdate) != 0){
                rmdir(cadir);
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "Can't init CA");
		aux_add_error(EINVALID, "pemcrlinit failed", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
                exit(-1);
	}

        if(verbose) {
        	fprintf(stderr, "%s: CA with issuer name <%s> complete.\n", cmd, caname);
        	fprintf(stderr, "          CA-DB resides in ");
                if(cadir[0] != '/') fprintf(stderr, "%s/", home);
                fprintf(stderr, "%s\n", cadir);
                fprintf(stderr, "          PSE %s contains PSE objects Name, PKRoot, ", psepath);
		if(onekeypaironly == TRUE) fprintf(stderr, "SKnew, Cert");
		else fprintf(stderr, "SignSK, SignCert, DecSKnew, EncCert");
                fprintf(stderr, "\n                                              SerialNumbers, CrlSet\n");
        }

	exit(0);
}


static int	
cainit(ca, s_alg, cadir_abs, serialnums, algorithm, keysize, onepaironly)
DName	      * ca;
AlgId         * s_alg;
char          * cadir_abs;
SerialNumbers * serialnums;
AlgId         * algorithm;
int             keysize;
Boolean         onepaironly;
{
        PSESel      * pse, * pse_sel;
	PSEToc      * psetoc;
	Key	      nkey;
	KeyInfo       nkinfo;
	PKRoot	    * pkroot;
	Certificate * cert;
	OctetString   content;
	ObjId         objid;       
	ObjId       * obj_type;
	int	      fd, rc;
	Boolean       x500 = TRUE;
	int	      i;
	char        * logpath;
#ifdef AFDBFILE
	char	      afdb[256];
#endif
	char        * proc = "cainit";

	/* init ca data files */

	logpath = (char *)malloc(strlen(cadir_abs)+10);
	strcpy(logpath, cadir_abs);
	strcat(logpath, "/");
	strcat(logpath, CALOG);

	if ((logfile = fopen(logpath, LOGFLAGS)) == (FILE * ) 0) return(-1);
	LOGINIT;

	/*
	 *  Create PSE
         *
	 *  Set global flag "sec_onekeypair" used in function "sec_create"
	 */

	sec_onekeypair = onepaironly;

	if(!(pse = af_pse_create(NULLOBJID))) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "PSE creation failed");
		aux_add_error(EINVALID, "PSE creation failed", CNULL, 0, proc);
		LOGSECERR;
		return(-1);
	}
	aux_free_PSESel(&pse);


        /* create PSE object "Name" */


	if (af_pse_update_Name(ca) < 0) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "unable to create Name on PSE");
		aux_add_error(EINVALID, "unable to create Name on PSE", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* create PSE object "SerialNumbers" */

	if(af_pse_update_SerialNumbers(serialnums) < 0){
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "unable to create SerialNumbers on PSE");
		aux_add_error(EINVALID, "unable to create SerialNumbers on PSE", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* now generate a new sign key, with default parm */

	nkey.keyref = 0;
	nkey.pse_sel = (PSESel * ) 0;
	nkey.key = &nkinfo;
	nkinfo.subjectAI = s_alg;
	if(aux_ObjId2ParmType(s_alg->objid) != PARM_NULL)
		*(int *)(nkinfo.subjectAI->parm) = keysize;

	if(verbose) {
		if(onepaironly) fprintf(stderr, "%s: Generating CA key pair (algorithm %s)...\n", cmd, aux_ObjId2Name(s_alg->objid));
		else fprintf(stderr, "%s: Generating CA signature key pair (algorithm %s)...\n", cmd, aux_ObjId2Name(s_alg->objid));
	}

	if(verbose) sec_verbose = TRUE;
	if (af_gen_key(&nkey, SIGNATURE, TRUE) < 0) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "unable to generate sign key");
		aux_add_error(EINVALID, "unable to generate sign key", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* now build a prototype certificate ... */
	if(onepaironly == TRUE)
		cert = af_create_Certificate(&nkinfo, algorithm, SKnew_name, (DName *)0);
	else
		cert = af_create_Certificate(&nkinfo, algorithm, SignSK_name, (DName *)0);
	if (! cert) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "unable to create prototype certificate");
		aux_add_error(EINVALID, "unable to create prototype certificate", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}


	
	cert->tbs->serialnumber = serialnums->actual;

	if(notbefore) cert->tbs->notbefore = notbefore;
	if(notafter) cert->tbs->notafter = notafter;

	/* certificate finished, now sign and enter it to certdb, userdb */

	aux_free_OctetString(&cert->tbs_DERcode);
	cert->tbs_DERcode = e_ToBeSigned(cert->tbs); 
	if (!cert->tbs_DERcode || (af_sign(cert->tbs_DERcode, cert->sig, END) < 0)) {
		fprintf(stderr, "%s: ",cmd);
		       fprintf(stderr, "Can't self-sign signature certificate");
		aux_add_error(EINVALID, "Can't self-sign signature certificate", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* ... and store it on the PSE */
	if (af_pse_update_Certificate(SIGNATURE, cert, TRUE) < 0) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "unable to store self-signed signature certificate on PSE");
		aux_add_error(EINVALID, "unable to store self-signed signature certificate on PSE", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* now build PKRoot with public key */

	if(!(pkroot = aux_create_PKRoot(cert, (Certificate *)0))) {
		fprintf(stderr, "%s: ",cmd);
		  fprintf(stderr, "Can't create PKRoot\n");
		aux_add_error(aux_last_error(), "Can't create PKRoot", CNULL, 0, proc);
		return(-1);
	}

	/* ... and install it so far */
	if (af_pse_update_PKRoot(pkroot) < 0) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "update of PKRoot failed");
		aux_add_error(EINVALID, "update of PKRoot failed", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* Enter SignCert to certdb: */

	if(onepaironly == TRUE)
		af_cadb_add_Certificate(3, cert, cadir_abs);
	else
		af_cadb_add_Certificate(SIGNATURE, cert, cadir_abs);


	/* Enter SignCert into Directory: */	

	if (af_access_directory == TRUE) {
#ifdef AFDBFILE
		/* Determine whether X.500 directory shall be accessed */
		strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
		strcat(afdb, "X500");           /* file = .af-db/'X500' */
		if (open(afdb, O_RDONLY) < 0) 
			x500 = FALSE;
#endif
#ifdef X500
		if ( x500 ) {
			directory_user_dname = aux_cpy_DName(cert->tbs->subject);
			if ( verbose ) {
				fprintf(stderr, "%s: Accessing the X.500 directory entry of ", cmd);
				fprintf(stderr, "owner = \"%s\" ...\n", aux_DName2Name(cert->tbs->subject));
			} 
			rc = af_dir_enter_Certificate(cert, cACertificate);
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
		rc = af_afdb_enter_Certificate(cert, SIGNATURE, TRUE);
		if ( verbose ) {
			if ( rc < 0 )
				fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
			else{
				if(onepaironly == TRUE)
					fprintf(stderr, "%s: Certificate entered into .af-db Directory.\n", cmd);
				else
					fprintf(stderr, "%s: %s Certificate entered into .af-db Directory.\n", cmd, "SIGNATURE");
			}
		}
#endif
	}  /* if(af_access_directory) */

	return(0);
}


static int	
localinit(ca, cadir_abs)
Name	* ca;
char    * cadir_abs;
{
#define	DBMOPENFL	O_RDWR|O_CREAT, S_IREAD|S_IWRITE

#ifdef NDBM
	DBM	* user;
	DBM	* cert;
	DBM     * pemcrl;
#else
	FILE    * fd;
	char	  fn[64];
#endif
	char    * userdbpath, * certdbpath, * pemcrldbpath;

	char    * proc = "localinit";

	userdbpath = (char *)malloc(strlen(cadir_abs) + 10);
	strcpy(userdbpath, cadir_abs);
	strcat(userdbpath, "/");
	strcat(userdbpath, USERDB);

	certdbpath = (char *)malloc(strlen(cadir_abs) + 10);
	strcpy(certdbpath, cadir_abs);
	strcat(certdbpath, "/");
	strcat(certdbpath, CERTDB);

	pemcrldbpath = (char *)malloc(strlen(cadir_abs) + 20);
	strcpy(pemcrldbpath, cadir_abs);
	strcat(pemcrldbpath, "/");
	strcat(pemcrldbpath, PEMCRLDB);

	
	/* user dbm */

#ifdef NDBM
	user = dbm_open(userdbpath, DBMOPENFL);
	if (!user) return(-1);
	dbm_close(user);
#else
	strcpy(fn, userdbpath);
	strcat(fn, ".pag");
	fd = fopen(fn, "r");
	if (fd) fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}	
	strcpy(fn, userdbpath);
	strcat(fn, ".dir");
	fd = fopen(fn, "r");
	if (fd)	fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	if (dbminit(userdbpath) < 0) return(-1);
	else dbmclose();
#endif


	/* cert dbm */

#ifdef NDBM
	cert = dbm_open(certdbpath, DBMOPENFL);
	if (!cert) return(-1);
	dbm_close(cert);
#else
	strcpy(fn, certdbpath);
	strcat(fn, ".pag");
	fd = fopen(fn, "r");
	if (fd) fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	strcpy(fn, certdbpath);
	strcat(fn, ".dir");
	fd = fopen(fn, "r");
	if (fd) fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	if (dbminit(certdbpath) < 0) return(-1);
	else dbmclose();
#endif


	/* pemcrl dbm */

#ifdef NDBM
	pemcrl = dbm_open(pemcrldbpath, DBMOPENFL);
	if (!pemcrl) return(-1);
	dbm_close(pemcrl);
#else
	strcpy(fn, pemcrldbpath);
	strcat(fn, ".pag");
	fd = fopen(fn, "r");
	if (fd) fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	strcpy(fn, pemcrldbpath);
	strcat(fn, ".dir");
	fd = fopen(fn, "r");
	if (fd) fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	if (dbminit(pemcrldbpath) < 0) return(-1);
	else dbmclose();
#endif


	return 0;
}


static int	
encrinit(ca, e_alg, cadir_abs, algorithm, keysize)
DName  *ca;
AlgId  *e_alg;
char   *cadir_abs;
AlgId  *algorithm;
int    keysize;
{
	Key	      nkey;
	KeyInfo	      nkinfo;
	PSESel	      psesk;
	Boolean       x500 = TRUE;
	Certificate * cert;
	int           rc;
#ifdef AFDBFILE
	char          afdb[256];
#endif
	char	    * proc = "encrinit";

	/*	generate encryption key */

	nkey.key = &nkinfo;
	nkey.keyref = 0;
	nkey.pse_sel = (PSESel * ) 0;
	nkinfo.subjectAI = e_alg;
        if(aux_ObjId2ParmType(e_alg->objid) != PARM_NULL)
	        *(int *)(nkinfo.subjectAI->parm) = keysize;

        if(verbose) fprintf(stderr, "%s: Generating CA encryption key pair (algorithm %s)...\n", cmd, aux_ObjId2Name(e_alg->objid));

	if (af_gen_key(&nkey, ENCRYPTION, TRUE) < 0) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "unable to generate encryption key");
		aux_add_error(EINVALID, "unable to generate encryption key", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	psesk.app_name	  = 	AF_pse.app_name;
	psesk.pin	  = 	aux_cpy_String(AF_pse.pin);
	psesk.app_id	  = 	AF_pse.app_id;
	psesk.object.name = 	DecSKnew_name;
	psesk.object.pin  =     aux_cpy_String(AF_pse.pin);

	nkey.pse_sel = &psesk;
	cert = af_create_Certificate(&nkinfo, algorithm, DecSKnew_name, (DName *)0);
	if (!cert) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "unable to create prototype certificate");
		aux_add_error(EINVALID, "unable to create prototype certificate", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}


	if (!(cert->tbs->serialnumber = af_pse_incr_serial())) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "problems with serial number");
		aux_add_error(EINVALID, "problems with serial number", CNULL, 0, proc);
		return(-1);
	}

	if(notbefore) cert->tbs->notbefore = notbefore;
	if(notafter) cert->tbs->notafter = notafter;

	/* certificate finished, now sign again and enter it to certdb, userdb */

	aux_free_OctetString(&cert->tbs_DERcode);
	cert->tbs_DERcode = e_ToBeSigned(cert->tbs);
	   
	if (!cert->tbs_DERcode || (af_sign(cert->tbs_DERcode, cert->sig, END) < 0)) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Can't self-sign encryption certificate");
		aux_add_error(EINVALID, "Can't self-sign encryption certificate", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* ... and store it on the PSE */
	if (af_pse_update_Certificate(ENCRYPTION, cert, TRUE) < 0) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "unable to store self-signed encryption certificate on PSE");
		aux_add_error(EINVALID, "unable to store self-signed encryption certificate on PSE", CNULL, 0, proc);
		LOGAFERR;
		return(-1);
	}

	/* ... and store it on the CA DB */
	af_cadb_add_Certificate(ENCRYPTION, cert , cadir_abs);


	/* Enter EncCert into Directory: */

	if (af_access_directory == TRUE) {
#ifdef AFDBFILE
		/* Determine whether X.500 directory shall be accessed */
		strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
		strcat(afdb, "X500");           /* file = .af-db/'X500' */
		if (open(afdb, O_RDONLY) < 0) 
			x500 = FALSE;
#endif
#ifdef X500
		if ( x500 ) {
			if ( verbose ) {
				fprintf(stderr, "%s: Accessing the X.500 directory entry of ", cmd);
				fprintf(stderr, "owner = \"%s\" ...\n", caname);
			} 
			rc = af_dir_enter_Certificate(cert, cACertificate);
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
			fprintf(stderr, "owner = \"%s\" ...\n", caname);
		} 
		rc = af_afdb_enter_Certificate(cert, ENCRYPTION, TRUE);
		if ( verbose ) {
			if ( rc < 0 )
				fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
			else fprintf(stderr, "%s: %s Certificate entered into .af-db Directory.\n", cmd, "ENCRYPTION");
		}

#endif
	}  /* if (af_access_directory) */



	
	return (0);
}


static int	
pemcrlinit(cadir_abs, algorithm, nextupdate)
char   * cadir_abs;
AlgId  * algorithm;
char   * nextupdate;
{
	PemCrl                  * pemcrl;
	PemCrlWithCerts  	* pemcrlwithcerts;
	Boolean                   x500 = TRUE;
	int			  rc;
	CrlPSE			* crlpse;
#ifdef AFDBFILE
	char                      afdb[256];
#endif

	char	    * proc = "pemcrlinit";


	pemcrl = (PemCrl * )malloc(sizeof(PemCrl));
	if (! pemcrl) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "pemcrl", CNULL, 0, proc);
		return(-1);
	}

	pemcrl->tbs = (PemCrlTBS * )malloc(sizeof(PemCrlTBS));
	if (! pemcrl->tbs) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "pemcrl->tbs", CNULL, 0, proc);
		return(-1);
	}

	if (!(pemcrl->tbs->issuer = af_pse_get_Name())) {
		aux_add_error(EREADPSE, "af_pse_get_Name failed", CNULL, 0, proc);
		return(-1);
	}

	pemcrl->tbs->lastUpdate = aux_current_UTCTime();
	if(nextupdate){ 
		if (aux_interval_UTCTime(CNULL, pemcrl->tbs->lastUpdate, nextupdate)) {
			fprintf(stderr, "%s: ",cmd);
          		fprintf(stderr, "Validity interval of PemCrl incorrectly specified\n");
			aux_add_error(EVALIDITY, "aux_interval_UTCTime failed", CNULL, 0, proc);
			return(-1);
		}
		pemcrl->tbs->nextUpdate = nextupdate;
	}
	else
		pemcrl->tbs->nextUpdate = aux_delta_UTCTime(pemcrl->tbs->lastUpdate);

	pemcrl->tbs->revokedCertificates = (SEQUENCE_OF_RevCertPem * )0;

	pemcrl->sig = (Signature * )malloc(sizeof(Signature));
	if (! pemcrl->sig) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "pemcrl->sig", CNULL, 0, proc);
		return(-1);
	}
	pemcrl->sig->signature.nbits = 0;
	pemcrl->sig->signature.bits = CNULL;

	pemcrl->sig->signAI = af_pse_get_signAI();
	if ( aux_ObjId2AlgType(pemcrl->sig->signAI->objid) == ASYM_ENC )
		pemcrl->sig->signAI = aux_cpy_AlgId(algorithm);

	pemcrl->tbs->signatureAI = aux_cpy_AlgId(pemcrl->sig->signAI);

	if ((pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrl->tbs)) == NULLOCTETSTRING) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "e_PemCrlTBS failed\n");
		aux_add_error(EENCODE, "e_PemCrlTBS failed", CNULL, 0, proc);
		return(-1);
	}

	if (af_sign(pemcrl->tbs_DERcode, pemcrl->sig, END) < 0 ) {
		aux_add_error(ESIGN, "af_sign failed", CNULL, 0, proc);
		return(-1);
	}

	pemcrlwithcerts = (PemCrlWithCerts * )malloc(sizeof(PemCrlWithCerts));
	if (! pemcrlwithcerts) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "pemcrlwithcerts", CNULL, 0, proc);
		return(-1);
	}

	pemcrlwithcerts->pemcrl = pemcrl;
	pemcrlwithcerts->certificates = (Certificates * )0;

	af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir_abs);

	
	/* Store own PemCrl in PSE object CrlSet */

	crlpse = PemCrl2CrlPSE(pemcrl);
	rc = af_pse_add_PemCRL(crlpse);
	if (rc != 0) {
		fprintf(stderr, "%s: ",cmd);
  	        fprintf(stderr, "Cannot update PSE object CrlSet\n");
		aux_add_error(EWRITEPSE, "af_pse_add_PemCRL failed", CNULL, 0, proc);
		aux_free_CrlPSE(&crlpse);
		aux_free_PemCrlWithCerts(&pemcrlwithcerts);
		return(-1);
	}
	aux_free_CrlPSE(&crlpse);

	/* Enter PemCrl into Directory: */

	if (af_access_directory == TRUE) {
#ifdef AFDBFILE
		/* Determine whether X.500 directory shall be accessed */
		strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
		strcat(afdb, "X500");           /* file = .af-db/'X500' */
		if (open(afdb, O_RDONLY) < 0) 
			x500 = FALSE;
#endif
#ifdef X500
		if ( x500 ) {
			if ( verbose ) {
				fprintf(stderr, "%s: Accessing the X.500 directory entry of ", cmd);
				fprintf(stderr, "owner = \"%s\" ...\n", caname);
			} 
			rc = af_dir_enter_PemCrl(pemcrl);
			if ( verbose ) {
				if ( rc < 0 )
					fprintf(stderr, "%s: Directory entry (X.500) failed.\n", cmd);
				else fprintf(stderr, "%s: PemCrl entered into X.500 Directory.\n", cmd);
			}
		}
#endif
#ifdef AFDBFILE
		if ( verbose ) {
			fprintf(stderr, "%s: Accessing the .af-db directory entry of ", cmd);
			fprintf(stderr, "owner = \"%s\" ...\n", caname);
		} 
		rc = af_afdb_enter_PemCrl(pemcrl);
		if ( verbose ) {
			if ( rc < 0 )
				fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
			else fprintf(stderr, "%s: PemCrl entered into .af-db Directory.\n", cmd);
		}
	
#endif
	}  /* if (af_access_directory) */

	aux_free_PemCrlWithCerts(&pemcrlwithcerts);


	return(0);
}




static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "cacreate: Create CA PSE (CA command)\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'cacreate' creates a CA PSE with one or two asymmetric keypairs on it,\n");
	fprintf(stderr, "whose public keys are held within self-signed prototype certificates.\n");
	fprintf(stderr, "In addition, an empty PEM revocation list is created.\n\n\n");

        fprintf(stderr, "usage:\n\n");
#ifdef X500
	fprintf(stderr, "cacreate [-hqtvDVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-s <signalg>] [-k <keysize>]\n");
	fprintf(stderr, "         [-e <encalg>] [-k <keysize>] [-n <serial>] [-u <nextupdate>]\n");
	fprintf(stderr, "         [-f <notbefore>] [-l <notafter>] [-d <dsa name>] [-A <authlevel>] [CA-Name]\n\n");
#else
	fprintf(stderr, "cacreate [-hqtvDVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-s <signalg>] [-k <keysize>]\n");
	fprintf(stderr, "         [-e <encalg>] [-k <keysize>] [-n <serial>] [-u <nextupdate>]\n");
	fprintf(stderr, "         [-f <notbefore>] [-l <notafter>] [CA-Name]\n\n");
#endif


        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>       PSE name (default: environment variable CAPSE or .capse)\n");
        fprintf(stderr, "-c <cadir>         Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-a <issueralg>     Issuer algorithm associated with the signature of the prototype certificate(s)\n");
	fprintf(stderr, "                   (default: md2WithRsaEncryption)\n");
	fprintf(stderr, "-s <signalg>       Signature algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>       Keysize of RSA signature key\n");
	fprintf(stderr, "-e <encalg>        Encryption algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>       Keysize of RSA encryption key\n");
	fprintf(stderr, "-n <serial>        Initial value of the serial number to be used by the CA\n");
	fprintf(stderr, "-D                 store self-signed certificate(s) in Directory (X.500 or .af-db)\n");
	fprintf(stderr, "-u <nextupdate>    Time and date of next scheduled update of PEM revocation list\n");
	fprintf(stderr, "-f <notbefore>     First date on which self-signed certificate is valid\n");
	fprintf(stderr, "                   (is only evaluated if option -r was supplied)\n");
	fprintf(stderr, "-l <notafter>      Last date on which self-signed certificate is valid\n");
	fprintf(stderr, "                   (is only evaluated if option -r was supplied)\n");
	fprintf(stderr, "-q                 create PSE that contains two RSA keypairs (default: one RSA keypair only)\n");
	fprintf(stderr, "-t                 control malloc/free behaviour\n");
        fprintf(stderr, "-h                 write this help text\n");
        fprintf(stderr, "-v                 verbose\n");
        fprintf(stderr, "-V                 Verbose\n");
        fprintf(stderr, "-W                 Grand Verbose (for testing only)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>      Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-A <authlevel>     Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                   <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                   (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                   STRONG implies the use of signed DAP operations\n");
#endif
	fprintf(stderr, "<CA-Name>          Intended owner of the generated CA PSE\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM CACREATE */
}
