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
 *      Program to generate PSEs at CA sites
 */

#define TIMELEN 40

#define SIGNKEY "signature"
#define ENCKEY  "encryption"

#define NEXTC  if ((c = getc(scr)) == EOF) return

#include <fcntl.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/wait.h>

#include "cadb.h"
#include "aux_time.h"

#include <errno.h>
#ifdef NDBM
#include <ndbm.h>
#else
#include <dbm.h>
#endif


#include <sys/types.h>
#include <sys/stat.h>
struct stat     buf;

struct passwd  *pwentry;

static set_AF_pse();
static RC  chk_pse_dir();
static void usage();
static int      localinit();
static RC       cpy_sign2enc();

extern UTCTime *delta_time_rec();
static UTCTime *txt2UTCTime();


/* 			parameter structure for a PSE-creation 		*/

struct parms {
	char           *userpse, *nameprefix, *notbefore, *notafter, *userpin,
	               *capin, *newca, *HOME;
	AlgId          *issuer_alg, *algorithms[2];
	int             oldpkroot, keysizes[2];
	SerialNumbers  *serialnums;
	Boolean         pkroot, oldpkr, newpkr, enter, SC_ignore, replace,
	                create, fcpath, cert[2], newkey[2], onekeypair;
#ifdef X500
	char           *vecptr2;
#endif
};

/*		Commands of script file   */
char           *script_cmds[] = {
	"issuer_alg",
	"subject_encalg",
	"subject_sigalg",
	"subject_pse",
	"notbefore",
	"notafter",
	"validity",
	"enter",
	"notenter",
	"dsa",
	"nameprefix",
	"transportpin",
	"sw_pse",
	"sc_pse",
	"home",
	"user",
	"userhome",
	"ca",
	"replace",
	"notreplace",
	"create",
	"update",
	"onekeypair",
	"twokeypairs",
	CNULL
};

typedef enum {
	ISSUER_ALG, SUBJECT_ENCALG, SUBJECT_SIGALG, SUBJECT_PSE, NOTBEFORE, NOTAFTER, VALIDITY, ENTER, NOTENTER, DIRECTORY, NAMEPREFIX, TRANSPORTPIN, SW_PSE, SC_PSE, HOMEDIRS, USER_PSE, USER_HOME, CA_PSE, REPLACE_KEY, NOT_REPLACE_KEY, CREATE, UPDATE, ONE_KEY_PAIR, TWO_KEY_PAIRS
}               Script_Cmds;


typedef enum {
	UNIXNAME, ADDRESS, SUFFIX, PARMMAX
}               PSE_Items;


/* 		Keywords of an update command */
char           *update_parm[] = {
	"oldpkroot",
	"newpkroot",
	"pkroot",
	"fcpath",
	"signcert",
	"encrcert",
	"newkey",
	CNULL
};
typedef enum {
	OLD_TO_PKLIST, NEW_TO_PKLIST, PKROOT, FCPATH, SIGN_CERT, ENCR_CERT, NEW_KEY
}               Update_Parms;



struct parms    local, global;
struct parms   *actualparms = &global;

int             keysize = DEFKEYLEN, ka = 0, kk = 0, fd;
RC              rc, rc_psecreate;
Boolean         verbose = FALSE;
OctetString    *ostr, *newcert;
PKRoot         *pkroot, *oldpkroot;
PKList         *pklist, *newpklist;
FCPath         *fcpath;
SET_OF_Certificate *soc, *fcpathcerts;
Certificates   *certs;
Name           *subject_Name, *issuer = CNULL, *printrepr, *name;
DName          *subject_DName, *issuer_dn = NULLDNAME, *proto_dn = NULLDNAME;
AlgId          *algorithm;
ObjId          *oid;
PSESel         *pse, psesel;
Key             key;
KeyInfo         keyinfo;
KeyType         ktype;
Certificate    *subject_Certificate;
Boolean         hierarchy = TRUE, x500 = FALSE, af_db = FALSE;
char           *keytype, *home, *useraddress, *namesuffix = "\0", *userunixname = " ",
               *userhomedir;
int             userunixuid, caunixuid;
char           *cadir_abs, *logpath;
char           *keytypes[2], *script, line[256], afdb[256];

extern char    *optarg;
extern int      optind, opterr;


#ifdef X500
char            name_from_pse = TRUE;
CertificateType certtype;
int             dsap_index = 4;
char           *callflag;
#endif

char           *capse = DEF_CAPSE, *capsepath = CNULL, *cadir = CNULL;
char            userhome[256], cahome[256], cahomedir[256], username[16],
                genpsedir[256], userappldir[256], userpsedir[256], userfiledir[256],
                userfilebakdir[256], *userappldir_rel;

typedef enum {
	USER, CA
}               PSEtype;



char            c, syscmd[256];
int             linenr = 1, n, psenumber = 0;
FILE           *scr, *fopen();
char            scrstr[256], scrcmd[256], filename[256], scrword1[256],
                scrword2[256], scrword3[256];
T_REC           trec;

void            readtimeformat(), scancmd(), replacestr(), nextnonblank();
int             readword(), cmdnumber();
RC              psecreate();

int             parmno = UNIXNAME;

/*void system(a)
char *a;
{ printf("%s\n",a);
}*/

main(cnt, parm)
	int             cnt;
	char          **parm;
{
	int             i;
	char           *cmd = *parm, opt, *cc, *dd, *nb, *na, *sma, *repl;
	char           *p1, *p2;
	char            keyno = -1;
	Boolean         sc = FALSE;
	int             SCapp_available;

	char           *proc = "main (ca_gen_pse)";

	optind = 1;
	opterr = 0;

	psesel.app_name = CNULL;
	psesel.pin = CNULL;
	psesel.object.name = CNULL;
	psesel.object.pin = CNULL;
	psesel.app_id = 0;

	actualparms->serialnums = (SerialNumbers *) 0;
	actualparms->newca = CNULL;
	actualparms->enter = FALSE;
	actualparms->replace = FALSE;
	actualparms->SC_ignore = FALSE;
	actualparms->HOME = CNULL;
	actualparms->notbefore = CNULL;
	actualparms->notafter = CNULL;
	actualparms->userpse = ".pse";
	actualparms->nameprefix = "\0";
	actualparms->algorithms[0] = DEF_SUBJECT_SIGNALGID;	/* rsa        */
	actualparms->algorithms[1] = DEF_SUBJECT_ENCRALGID;	/* rsa        */
	actualparms->issuer_alg = DEF_ISSUER_ALGID;	/* md5WithRsa */
	actualparms->create = TRUE;
	actualparms->pkroot = TRUE;
	actualparms->oldpkr = FALSE;
	actualparms->newpkr = FALSE;
	actualparms->fcpath = TRUE;
	actualparms->cert[0] = TRUE;
	actualparms->newkey[0] = TRUE;
	actualparms->cert[1] = TRUE;
	actualparms->newkey[1] = TRUE;
	keytypes[0] = SIGNKEY;
	keytypes[1] = ENCKEY;
	actualparms->keysizes[0] = DEFKEYLEN;
	actualparms->keysizes[1] = DEFKEYLEN;
	actualparms->onekeypair = TRUE;
	ka = 2;
	caunixuid = getuid();

#ifdef X500
	af_x500_count = 1;		/* default, binding to local DSA */
	callflag = "-call";
	certtype = userCertificate;	/* default */
	auth_level = DBA_AUTH_SIMPLE;	/* default */

	i = cnt + 1;
	while (parm[i++])
		dsap_index++;
	af_x500_vecptr = (char **) calloc(dsap_index, sizeof(char *));	/* used for dsap_init()
								 * in af_dir.c */
	if (!af_x500_vecptr) {
		aux_add_error(EMALLOC, "af_x500_vecptr", CNULL, 0, proc);
		if (verbose)
			aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ", parm[0]);
		fprintf(stderr, "Can't allocate memory\n");
		exit(1);
	}
#endif

	MF_check = FALSE;

#ifdef X500
	while ((opt = getopt(cnt, parm, "a:s:e:k:i:c:p:P:f:l:d:u:H:g:x:C:rDtvqnh")) != -1) {
#else
	while ((opt = getopt(cnt, parm, "a:s:e:k:i:c:p:P:f:l:u:H:g:x:C:rDtvqh")) != -1) {
#endif
		switch (opt) {

		case 'g':
			if (!actualparms->serialnums)
				actualparms->serialnums = (SerialNumbers *) malloc(sizeof(SerialNumbers));
			actualparms->serialnums->initial = actualparms->serialnums->actual = atoi(optarg);
			if (actualparms->serialnums->actual < 0)
				usage(SHORT_HELP);
			break;
		case 'q':
			actualparms->onekeypair = FALSE;
			break;
#ifdef X500
		case 'n':
			name_from_pse = TRUE;
			break;
#endif
		case 'C':
			actualparms->newca = optarg;
#ifdef X500
			certtype = cACertificate;
#endif
			break;
		case 't':
			MF_check = TRUE;
			break;
		case 'i':
			script = optarg;
			break;
		case 'a':
			oid = aux_Name2ObjId(optarg);
			if (aux_ObjId2AlgType(oid) != SIG)
				usage(SHORT_HELP);
			actualparms->issuer_alg = aux_ObjId2AlgId(oid);
			break;
		case 's':
			oid = aux_Name2ObjId(optarg);
			if (aux_ObjId2AlgType(oid) != ASYM_ENC && aux_ObjId2AlgType(oid) != SIG)
				usage(SHORT_HELP);
			actualparms->algorithms[0] = aux_ObjId2AlgId(oid);
			kk = 0;
			break;
		case 'k':
			keysize = atoi(optarg);
			if ((keysize < MINKEYLEN) || (keysize > MAXKEYLEN))
				usage(SHORT_HELP);
			actualparms->keysizes[kk] = keysize;
			break;
		case 'c':
			if (cadir)
				usage(SHORT_HELP);
			else
				cadir = optarg;
			break;
		case 'H':
			actualparms->HOME = optarg;
			break;
		case 'p':
			capse = optarg;
			break;
		case 'P':
			actualparms->userpse = optarg;
			break;
		case 'u':
			userunixname = optarg;
			break;
		case 'x':
			actualparms->nameprefix = optarg;
			break;
		case 'f':
			if (actualparms->notbefore)
				usage(SHORT_HELP);
			else
				actualparms->notbefore = txt2UTCTime(optarg, CNULL);
			break;
		case 'l':
			if (actualparms->notafter)
				usage(SHORT_HELP);
			else
				actualparms->notafter = txt2UTCTime(optarg, CNULL);
			break;
		case 'D':
			actualparms->enter = TRUE;
			break;
		case 'r':
			actualparms->replace = TRUE;
			break;
		case 'e':
			oid = aux_Name2ObjId(optarg);
			if (aux_ObjId2AlgType(oid) != ASYM_ENC)
				usage(SHORT_HELP);
			actualparms->algorithms[1] = aux_ObjId2AlgId(oid);
			kk = 1;
			break;
		case 'v':
			verbose = TRUE;
			break;
		case 'h':
			usage(LONG_HELP);
#ifdef X500
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *) malloc(strlen(callflag) + 1);
			if (!af_x500_vecptr[1]) {
				fprintf(stderr, "Can't allocate memory");
				if (verbose)
					aux_fprint_error(stderr, 0);
				exit(1);
			}
			strcpy(af_x500_vecptr[1], callflag);
			actualparms->vecptr2 = (char *) malloc(strlen(optarg) + 1);
			if (!actualparms->vecptr2) {
				fprintf(stderr, "Can't allocate memory");
				if (verbose)
					aux_fprint_error(stderr, 0);
				exit(1);
			}
			strcpy(actualparms->vecptr2, optarg);
			af_x500_vecptr[3] = (char *) 0;
			i = cnt + 1;
			dsap_index = 4;
			while (parm[i])
				af_x500_vecptr[dsap_index++] = parm[i++];
			break;
#endif
		}
	}

	if (!script) {
		if (optind < cnt)
			namesuffix = parm[optind++];

		subject_Name = (char *) malloc(strlen(actualparms->nameprefix) + strlen(namesuffix) + 1);
		strcpy(subject_Name, actualparms->nameprefix);
		strcat(subject_Name, namesuffix);

		if (!strlen(subject_Name)) {	/* read CA directory name
						 * from stdin */
	again:
			fprintf(stderr, "    %s: Directory name of PSE owner: ", cmd);
			line[0] = '\0';
			gets(line);
			subject_Name = line;
			if (!(subject_DName = aux_alias2DName(subject_Name))) {

				subject_DName = aux_Name2DName(subject_Name);
				if (!subject_DName) {
					fprintf(stderr, "    %s: Invalid directory name\n", cmd);
					goto again;
				}
			}
		} 
		else {
			if (!(subject_DName = aux_alias2DName(subject_Name))) {
				subject_DName = aux_Name2DName(subject_Name);
				if (!subject_DName) {
					fprintf(stderr, "    %s: Invalid directory name\n", cmd);
				}
			}
		}

		if ((optind < cnt) || !subject_Name || !subject_DName) usage(SHORT_HELP);

		if (subject_Name) free(subject_Name);

		subject_Name = aux_DName2Name(subject_DName);	/* reconstruct
								 * subject_Name for
								 * uniqueness */

		if ((actualparms->notbefore && !actualparms->notafter) || (!actualparms->notbefore && actualparms->notafter))
			usage(SHORT_HELP);

		if (actualparms->notbefore) {
			if (aux_interval_UTCTime(CNULL, actualparms->notbefore, actualparms->notafter)) {
				fprintf(stderr, "%s: ", cmd);
				fprintf(stderr, "Validity interval incorrectly specified\n");
				aux_add_error(EVALIDITY, "aux_interval_UTCTime failed", CNULL, 0, proc);
				exit(1);
			}
		}
	}
	if (!capse)
		capse = DEF_CAPSE;
	if (!cadir)
		cadir = DEF_CADIR;

#ifdef X500
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);	/* file = .af-db/ */
	strcat(afdb, "X500");	/* file = .af-db/'X500' */
	if ((fd = open(afdb, O_RDONLY)) > 0) {
		x500 = TRUE;
		close(fd);
	}
#endif
#ifdef AFDBFILE
	af_db = TRUE;
#endif

	capsepath = (char *) malloc(strlen(cadir) + strlen(capse) + 2);
	if (!capsepath) {
		fprintf(stderr, "%s: ", cmd);
		fprintf(stderr, "Can't allocate memory\n");
		aux_add_error(EMALLOC, "capsepath", CNULL, 0, proc);
		if (verbose)
			aux_fprint_error(stderr, 0);
		exit(1);
	}
	strcpy(capsepath, cadir);
	strcat(capsepath, "/");
	strcat(capsepath, capse);

	actualparms->userpin = getenv("USERPIN");
	actualparms->capin = getenv("CAPIN");

	if (!actualparms->capin)
		actualparms->capin = sec_read_pin("PIN of CA", "", FALSE);

	strcpy(cahome, "HOME=");
	strcpy(cahomedir, getenv("HOME"));
	strcat(cahome, cahomedir);


/************************************* g e t n a m e *******************************************/

	proto_dn = aux_Name2DName("cn=PROTO");

	set_AF_pse(CA);

	if (!(issuer_dn = af_pse_get_Name())) {
		aux_add_error(EINVALID, "Can't read Name from PSE", CNULL, 0, proc);
		if (verbose)
			aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: Can't read Name from PSE %s\n", cmd, capsepath);
		exit(1);
	}
	issuer = aux_DName2Name(issuer_dn);
#ifdef X500
	directory_user_dname = issuer_dn;
#endif
	fprintf(stderr, "\nIssuing CA is <%s>\n", issuer);

/************************************* scriptfile *********************************************/
	if (script) {
		rc_psecreate = 0;
		scr = fopen(script, "r");
		if (!scr) {
			fprintf(stderr, "Error: Scriptfile '%s' not found\n", script);
			exit(1);
		}
		c = getc(scr);
		while (c != EOF) {
			switch (c) {
			case ' ':
				nextnonblank();
				break;
			case ',':
				NEXTC(-1);
				fprintf(stderr, "*** Warning in line %d: ',' unexpected\n", linenr);
				break;
			case '\t':
				nextnonblank();
				break;
			case '#':
				while ((c = getc(scr)) != EOF && c != '\n');
				break;
			case '$':
				NEXTC(-1);
				scancmd();
				if (verbose && sec_debug > 2) {
					if (actualparms == &local)
						fprintf(stderr, "Local-");
					fprintf(stderr, "Command %s\n", scrword1);

					/*
					 * fprintf(stderr, " %s %s %d\n",
					 * scrword2, scrword3, linenr);
					 */
				}
				switch (cmdnumber(scrword1)) {
				case -1:
					fprintf(stderr, "*** Warning in line %d: Command '%s' not found\n", linenr, scrstr);
					break;
				case -2:
					fprintf(stderr, "*** Warning in line %d: Command '%s' ambiguous\n", linenr, scrstr);
					break;
				case NAMEPREFIX:
					replacestr(&actualparms->nameprefix, scrword2, CNULL);
					break;
				case ISSUER_ALG:
					oid = aux_Name2ObjId(scrword2);
					if (aux_ObjId2AlgType(oid) != SIG) {
						if (oid)
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not allowed for issuer. I take 'md5WithRsa'\n", linenr, scrword2);
						else
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not known. I take 'md5WithRsa'\n", linenr, scrword2);

						oid = aux_Name2ObjId("md5WithRsa");

					}
					actualparms->issuer_alg = aux_ObjId2AlgId(oid);
					break;
				case SUBJECT_PSE:
					replacestr(&actualparms->userpse, scrword2, CNULL);
					break;
				case TRANSPORTPIN:
					replacestr(&actualparms->userpin, scrword2, CNULL);
					break;
				case HOMEDIRS:
					if (!strlen(scrword2))
						actualparms->HOME = CNULL;
					else
						replacestr(&actualparms->HOME, scrword2, CNULL);
					break;
				case USER_PSE:
					actualparms->newca = CNULL;
					break;
				case USER_HOME:
					replacestr(&userhomedir, scrword2, CNULL);
					break;
				case CA_PSE:
					if (strlen(scrword2))
						replacestr(&actualparms->newca, scrword2, CNULL);
					else
						replacestr(&actualparms->newca, DEF_CADIR, CNULL);
					if (!actualparms->serialnums)
						actualparms->serialnums = (SerialNumbers *) malloc(sizeof(SerialNumbers));
					actualparms->serialnums->initial = actualparms->serialnums->actual = strlen(scrword3) ? atoi(scrword3) : 0;
#ifdef X500
					certtype = cACertificate;
#endif
					break;
				case ENTER:
					actualparms->enter = TRUE;
					break;
				case NOTENTER:
					actualparms->enter = FALSE;
					break;
				case ONE_KEY_PAIR:
					actualparms->onekeypair = TRUE;
					break;
				case TWO_KEY_PAIRS:
					actualparms->onekeypair = FALSE;
					break;
				case REPLACE_KEY:
					actualparms->replace = TRUE;
					break;
				case NOT_REPLACE_KEY:
					actualparms->replace = FALSE;
					break;
				case SW_PSE:
#ifdef SCA
					actualparms->SC_ignore = TRUE;
#endif
					break;
				case SC_PSE:
#ifdef SCA
					actualparms->SC_ignore = FALSE;
#endif
					break;
				case SUBJECT_ENCALG:
					oid = aux_Name2ObjId(scrword2);
					if (aux_ObjId2AlgType(oid) != ASYM_ENC) {
						if (oid)
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not allowed for encryption-algorithm of subject. I take 'RSA'\n", linenr, scrword2);
						else
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not known. I take 'RSA'\n", linenr, scrword2);

						oid = aux_Name2ObjId("RSA");

					}
					actualparms->algorithms[1] = aux_ObjId2AlgId(oid);
					if (strlen(scrword3)) {
						keysize = atoi(scrword3);
						if ((keysize < MINKEYLEN) || (keysize > MAXKEYLEN)) {
							fprintf(stderr, "*** Warning in line %d: Keysize '%d' not allowed. I take '%d'\n", linenr, keysize, MAXKEYLEN);
							keysize = MAXKEYLEN;

						}
						actualparms->keysizes[1] = keysize;
					}
					break;
				case SUBJECT_SIGALG:
					oid = aux_Name2ObjId(scrword2);
					if (aux_ObjId2AlgType(oid) != ASYM_ENC && aux_ObjId2AlgType(oid) != SIG) {
						if (oid)
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not allowed for signature-algorithm of subject. I take 'RSA'\n", linenr, scrword2);
						else
							fprintf(stderr, "*** Warning in line %d: Algoritm '%s' not known. I take 'RSA'\n", linenr, scrword2);

						oid = aux_Name2ObjId("RSA");

					}
					actualparms->algorithms[0] = aux_ObjId2AlgId(oid);
					if (strlen(scrword3)) {
						keysize = atoi(scrword3);
						if ((keysize < MINKEYLEN) || (keysize > MAXKEYLEN)) {
							fprintf(stderr, "*** Warning in line %d: Keysize '%d' not allowed. I take '%d'\n", linenr, keysize, MAXKEYLEN);
							keysize = MAXKEYLEN;

						}
						actualparms->keysizes[0] = keysize;
					}
					break;
				case NOTBEFORE:
					actualparms->notbefore = txt2UTCTime(scrword2, CNULL);
					break;
				case NOTAFTER:
					actualparms->notafter = txt2UTCTime(scrword2, CNULL);
					break;
				case VALIDITY:
					actualparms->notafter = txt2UTCTime(scrword2, actualparms->notbefore);
					break;
#ifdef X500
				case DIRECTORY:
					af_x500_count = 3;
					af_x500_vecptr[0] = parm[0];
					af_x500_vecptr[1] = (char *) malloc(strlen(callflag) + 1);
					if (!af_x500_vecptr[1]) {
						fprintf(stderr, "Can't allocate memory");
						if (verbose)
							aux_fprint_error(stderr, 0);
						exit(1);
					}
					strcpy(af_x500_vecptr[1], callflag);
					actualparms->vecptr2 = (char *) malloc(strlen(scrword2) + 1);
					if (!actualparms->vecptr2) {
						fprintf(stderr, "Can't allocate memory");
						if (verbose)
							aux_fprint_error(stderr, 0);
						exit(1);
					}
					strcpy(actualparms->vecptr2, scrword2);
					af_x500_vecptr[3] = (char *) 0;
					i = cnt + 1;
					dsap_index = 4;
					while (parm[i])
						af_x500_vecptr[dsap_index++] = parm[i++];
					break;

#endif
				case CREATE:
					actualparms->create = TRUE;
					actualparms->pkroot = TRUE;
					actualparms->oldpkr = FALSE;
					actualparms->newpkr = FALSE;
					actualparms->fcpath = TRUE;
					actualparms->cert[0] = TRUE;
					actualparms->newkey[0] = TRUE;
					actualparms->cert[1] = TRUE;
					actualparms->newkey[1] = TRUE;
					break;
				case UPDATE:
					actualparms->create = FALSE;
					actualparms->pkroot = FALSE;
					actualparms->oldpkr = FALSE;
					actualparms->newpkr = FALSE;
					actualparms->fcpath = FALSE;
					actualparms->cert[0] = FALSE;
					actualparms->newkey[0] = FALSE;
					actualparms->cert[1] = FALSE;
					actualparms->newkey[1] = FALSE;
					for (p1 = scrword2; *p1 != '\0'; p1 = p2) {
						p2 = p1;
						while (*p2 != ' ' && *p2 != '\0') {
							p2++;
						}
						*(p2++) = '\0';
						while (*p2 == ' ')
							p2++;
						switch (parmnumber(p1)) {
						case -1:
							fprintf(stderr, "*** Warning in line %d: Parameter '%s' not found\n", linenr, p1);
							break;
						case -2:
							fprintf(stderr, "*** Warning in line %d: Parameter '%s' ambiguous\n", linenr, p1);
							break;
						case OLD_TO_PKLIST:
							actualparms->pkroot = TRUE;
							actualparms->oldpkr = TRUE;
							actualparms->fcpath = TRUE;
							break;
						case NEW_TO_PKLIST:
							actualparms->pkroot = TRUE;
							actualparms->newpkr = TRUE;
							actualparms->fcpath = TRUE;
							break;
						case PKROOT:
							actualparms->pkroot = TRUE;
							actualparms->fcpath = TRUE;
							break;
						case FCPATH:
							actualparms->fcpath = TRUE;
							break;
						case SIGN_CERT:
							actualparms->cert[0] = TRUE;
							keyno = 0;
							break;
						case ENCR_CERT:
							actualparms->cert[1] = TRUE;
							if (actualparms->onekeypair)
								actualparms->cert[0] = TRUE;
							keyno = 1;
							break;
						case NEW_KEY:
							if (keyno >= 0) {
								actualparms->newkey[keyno] = TRUE;
								if (actualparms->onekeypair) 
									actualparms->newkey[0] = TRUE;
							} else
								fprintf(stderr, "*** Warning in line %d: Paramter '%s' is only allowed after '%s' or '%s'.\n", linenr, update_parm[NEW_KEY], update_parm[ENCR_CERT], update_parm[SIGN_CERT]);
							break;
						}

					}
					break;
				}
				nextnonblank();
				while (actualparms == &global &&c != '$' && c != '#' && c != '\n' && c != EOF) {
					readword(scrstr);
					fprintf(stderr, "*** Warning in line %d : parameter '%s' ignored.\n", linenr, scrstr);
				}
				break;
			case '\n':

				if (actualparms == &global) {
					linenr++;
					NEXTC(-1);
					break;
				}
				if (parmno != PARMMAX) {
					fprintf(stderr, "*** Error in line %d : %d parameters instead of %d. Cannot create PSE.\n", linenr, parmno, PARMMAX);
					parmno = UNIXNAME;
					actualparms = &global;

					break;
				}
				parmno = UNIXNAME;
				replacestr(&subject_Name, actualparms->nameprefix, namesuffix);
				if (subject_DName)
					aux_free_DName(&subject_DName);
				subject_DName = aux_alias2DName(subject_Name);

				if (!subject_DName) {
					subject_DName = aux_Name2DName(subject_Name);
				}
	
				if (!subject_DName) {
					fprintf(stderr, "*** Error in line %d: Name '%s' is a wrong format. Cannot create PSE.\n", linenr, subject_Name);
					actualparms = &global;

					break;
				}
#ifdef X500
				af_x500_vecptr[2] = actualparms->vecptr2;
#endif

/*
					if(subject_Name) free(subject_Name);
					subject_Name = aux_DName2Name(subject_DName);
*/
				if (!actualparms->notbefore)
					actualparms->notbefore = aux_current_UTCTime();
				if (!actualparms->notafter)
					actualparms->notafter = aux_delta_UTCTime(actualparms->notbefore);


#ifdef SCA
				if (actualparms->SC_ignore)
					SC_ignore = TRUE;
				else
					SC_ignore = FALSE;
#endif
				if (actualparms->create)
					repl = "Creating";
				else
					repl = "Updating";


				strcpy(username, "USER=");
				if (userunixname)
					strcat(username, userunixname);
				else
					strcat(username, getenv("USER"));
				putenv(username);
				pwentry = getpwnam(userunixname);
				if (pwentry)
					userunixuid = pwentry->pw_uid;
				else
					fprintf(stderr, "Warning: user %s does not exist\n", userunixname);

				sma = "";
				sc = FALSE;
#ifdef SCA
				set_AF_pse(USER);

				SCapp_available = sec_sctest(actualparms->userpse);
				if(SCapp_available == -1) {
					if (aux_last_error() == EOPENDEV) 
						fprintf(stderr, "Cannot open device for SCT (No such device or device busy).\n");
					else	fprintf(stderr, "Error during SC configuration.\n");
					if(verbose) aux_fprint_error(stderr, 0);
					exit(-1);
				}

				if (SCapp_available == TRUE) {
					sma = " Smartcard";
					sc = TRUE;
				}
				set_AF_pse(CA);
#endif

				if(!sc)
				if (make_genpsedir() < 0) {
					if (actualparms->create)
						repl = "Created";
					else
						repl = "Updated";
					fprintf(stderr, "    PSE not %s for %s\n", repl, userunixname);
					actualparms = &global;

					userhomedir = CNULL;
					break;
				}

				if (actualparms->newca)
					fprintf(stderr, "\n\n\n%2d. %s CA <%s> (Unix-Uid %s)\n", ++psenumber, repl, subject_Name, userunixname);
				else
					fprintf(stderr, "\n\n\n%2d. %s%s PSE for %s <%s>\n", ++psenumber, repl, sma, userunixname, subject_Name);


				if (!actualparms->create) {
					if (!actualparms->HOME && !sc) {


						strcpy(syscmd, "cd ");
						strcat(syscmd, genpsedir);
						strcat(syscmd, ";");
						strcat(syscmd, "decode -r < ");
						strcat(syscmd, userunixname);
						strcat(syscmd, " | uncompress | tar xf - ");
						system(syscmd);
					}
				}
				if (chk_pse_dir() < 0) {
					if (actualparms->create)
						repl = "Created";
					else
						repl = "Updated";
					fprintf(stderr, "    PSE not %s for %s\n", repl, userunixname);
					actualparms = &global;

					userhomedir = CNULL;
					break;
				}
				if (actualparms->newca)
					fprintf(stderr, "    - CA directory is %s, application name (PSE name) is %s\n", actualparms->newca, actualparms->userpse);
				else
					fprintf(stderr, "    - application name (PSE name) is %s\n", actualparms->userpse);

				nb = aux_readable_UTCTime(actualparms->notbefore);
				na = aux_readable_UTCTime(actualparms->notafter);
				fprintf(stderr, "    - Certificate validity is from %s", nb);
				fprintf(stderr, " to %s\n", na);
				if (nb)
					free(nb);
				if (na)
					free(na);
				fprintf(stderr, "    - Certificates are signed using algorithm %s\n", aux_ObjId2Name(actualparms->issuer_alg->objid));
				fprintf(stderr, "    - Subject's default signature algorithm is %s, keysize %d\n", aux_ObjId2Name(actualparms->algorithms[0]->objid), actualparms->keysizes[0]);
				fprintf(stderr, "    - Subject's default encryption algorithm %s, keysize %d\n", aux_ObjId2Name(actualparms->algorithms[1]->objid), actualparms->keysizes[1]);
				if (actualparms->enter && x500)
					fprintf(stderr, "    - The certificates will be entered into the X.500 directory\n");
				if (actualparms->enter && af_db)
					fprintf(stderr, "    - The certificates will be entered into the .af-db directory\n");

				SCapp_available = sec_sctest(actualparms->userpse);
#ifdef SCA
				if (SCapp_available == -1) {
					if (aux_last_error() == EOPENDEV) 
						fprintf(stderr, "Cannot open device for SCT (No such device or device busy).\n");
					else	fprintf(stderr, "Error during SC configuration.\n");
					if(verbose) aux_fprint_error(stderr, 0);
					exit(-1);
				}
#endif
				if (SCapp_available == FALSE) {
					if (!actualparms->userpin)
						actualparms->userpin = global.userpin = sec_read_pin("Transport PIN for user-PSE's", "", TRUE);
				}
				rc_psecreate = psecreate(cmd);
				if (rc_psecreate == 0) {
					if (!actualparms->HOME && !sc) {

						/*
						 * If HOME is Null and user PSE is not an SC, create a
						 * compressed tar file of the
						 * PSE and store it in
						 * <genpsedir>/<userunixname>,
						 * and remove the temporary
						 * <genpsedir>/<userhomedir>
						 */

						strcpy(syscmd, "cd ");
						strcat(syscmd, genpsedir);
						strcat(syscmd, ";");
						strcat(syscmd, "tar cf - ");
						strcat(syscmd, userappldir_rel);
						strcat(syscmd, " | compress | encode -r >");
						strcat(syscmd, userunixname);
						strcat(syscmd, ";");
						strcat(syscmd, "rm -r -f ");
						strcat(syscmd, userappldir);
						system(syscmd);
					}

					if (userunixname)
						aux_add_alias_name(userunixname, subject_Name, systemalias, TRUE, FALSE);
					if (useraddress)
						aux_add_alias_name(useraddress, subject_Name, systemalias, TRUE, FALSE);
					fprintf(stderr, "    PSE generation finished\n");
					if(sc) 	fprintf(stderr, "    Remove Smardcard from Smardcard-Terminal\n");

					else if (!actualparms->HOME)
						fprintf(stderr, "    Generated PSE is compressed tar file %s/%s\n", genpsedir, userunixname);
					else
						fprintf(stderr, "    Generated PSE is directory %s/%s\n", genpsedir, actualparms->userpse);
					fprintf(stderr, "    Alias names %s and %s with\n    target name <%s> generated\n", userunixname, useraddress, subject_Name);
				} else {
					fprintf(stderr, "\n    PSE generation failed for %s\n", userunixname);
					
					if (!actualparms->HOME && !sc && !actualparms->newca) {
						strcpy(syscmd, "rm -f -r ");
						strcat(syscmd, genpsedir);
						strcat(syscmd, "/");
						strcat(syscmd, actualparms->userpse);
						system(syscmd);
					}
				}
				sec_sc_eject(0);
				userhomedir = CNULL;
				aux_free_error();
				actualparms = &global;

				NEXTC(-1);
				break;
			default:
				if (!parmno) {
					local.userpse = global.userpse;

					if (!local.userpse)
						local.userpse = (actualparms->newca) ? DEF_CAPSE : DEF_PSE;
					if (!local.serialnums)
						local.serialnums = (SerialNumbers *) malloc(sizeof(SerialNumbers));
					if (!global.serialnums) {
						global.         serialnums = (SerialNumbers *) malloc(sizeof(SerialNumbers));
						global.         serialnums->initial = 1;
						global.         serialnums->actual = 1;
					}
					local.serialnums->initial = global.serialnums->initial;
					local.serialnums->actual = global.serialnums->actual;
					local.nameprefix = global.nameprefix;
					local.notbefore = global.notbefore;
					local.notafter = global.notafter;

					if (global.userpin)
						local.userpin = strdup(global.userpin);
					else
						local.userpin = CNULL;
					local.capin = strdup(global.capin);
					local.HOME = global.HOME;
					local.issuer_alg = global.issuer_alg;
					local.algorithms[0] = global.algorithms[0];
					local.algorithms[1] = global.algorithms[1];
					local.keysizes[0] = global.keysizes[0];
					local.keysizes[1] = global.keysizes[1];
					local.enter = global.enter;
					local.SC_ignore = global.SC_ignore;
					local.newca = global.newca;
					local.replace = global.replace;
					local.create = global.create;
					local.pkroot = global.pkroot;
					local.oldpkr = global.oldpkr;
					local.fcpath = global.fcpath;
					local.cert[0] = global.cert[0];
					local.cert[1] = global.cert[1];
					local.newkey[0] = global.newkey[0];
					local.newkey[1] = global.newkey[1];
					local.onekeypair = global.onekeypair;

#ifdef X500
					local.vecptr2 = global.vecptr2;

#endif
					actualparms = &local;
				}
				readword(scrstr);

				switch (parmno++) {
				case UNIXNAME:
					replacestr(&userunixname, scrstr, CNULL);
					break;
				case ADDRESS:
					replacestr(&useraddress, scrstr, CNULL);
					break;
				case SUFFIX:
					replacestr(&namesuffix, scrstr, CNULL);
					break;
				}

				break;
			}

		}
		fclose(scr);
	} 
	else {		/* no script file */

		SCapp_available = sec_sctest(actualparms->userpse);
#ifdef SCA
		if (SCapp_available == -1) {
			if (aux_last_error() == EOPENDEV) 
				fprintf(stderr, "Cannot open device for SCT (No such device or device busy)\n");
			else	fprintf(stderr, "Error during SC configuration.\n");
			if(verbose) aux_fprint_error(stderr, 0);
			exit(-1);
		}
#endif

		if (SCapp_available == FALSE) {
			if (!actualparms->userpin)
				actualparms->userpin = global.userpin = sec_read_pin("PIN for user-PSE's", "", TRUE);
		}
		if (make_genpsedir() == 0) rc_psecreate = psecreate(cmd);
	}

	/* save the system alias file */

	aux_put_AliasList(systemalias);

	exit(rc_psecreate);
}


static UTCTime *
txt2UTCTime(txt, oldtime)
	char           *txt;
	UTCTime        *oldtime;
{
	char           *dd, *cc;
	int             i;
	UTCTime        *newtime;
	T_REC           trec;

	trec.zone = 0;
	trec.year = 0;
	if (!oldtime) {
		trec.mon = 1;
		trec.day = 1;
	} else {
		trec.mon = 0;
		trec.day = 0;
	}
	trec.hour = 0;
	trec.minu = 0;
	trec.sec = 0;

	dd = txt;
	i = 0;
	while ((cc = strchr(dd, ':'))) {
		i++;
		*cc = '\0';
		switch (i) {
		case 1:
			trec.year = atoi(dd);
			break;
		case 2:
			trec.mon = atoi(dd);
			break;
		case 3:
			trec.day = atoi(dd);
			break;
		case 4:
			trec.hour = atoi(dd);
			break;
		case 5:
			trec.minu = atoi(dd);
			break;
		case 6:
			trec.sec = atoi(dd);
			break;
		}
		dd = cc + 1;
	}
	if (!oldtime) {
		trec.year += 1900;
		trec.mon -= 1;
		trec.day -= 1;
	}
	if (i)
		newtime = delta_time_rec(oldtime, &trec);
	else
		replacestr(&newtime, txt, CNULL);
	return (newtime);
}

void 
readtimeformat(s, i)
	char           *s;
	int            *i;
{
	int             n, m = 0;

	for (n = 0; n < strlen(s); n++) {
		if (s[n] <= '9' && s[n] >= '0')
			m = 10 * m + s[n] - '0';
		else if (n && s[n - 1] <= '9' && s[n - 1] >= '0') {
			*(i--) = m;
			m = 0;
		}
	}
	if (n && s[n - 1] <= '9' && s[n - 1] >= '0')
		*i = m;

}

int 
readword(str)
	char           *str;
{
	int             n = 0, text = 0;

	nextnonblank();
	while (c != EOF && n < 255) {
		if (c == '"') {
			NEXTC(-1);
			text = 1 - text;
		} else {
			if (c == '\t')
				c = ' ';
			if (!text && (c == ' ' || c == ',' || c == '$' || c == '#' || c == '\n'))
				break;
			if (c == '\n')
				linenr++;
			else
				str[n++] = c;
			NEXTC(-1);
		}
	}
	str[n] = '\0';
	if (n >= 254) {
		fprintf(stderr, "*** Fatal error: Word to long in line %d ( %s )\n", linenr, str);
		exit(-1);
	}
	for (--n; n >= 0 && str[n] == ' '; n--)
		str[n] = '\0';

	return (strlen(str));
}
void 
scancmd()
{
	int             n = 0, m, l;

	if (!readword(scrword1)) {
		scrword2[0] = '\0';
		return;
	}
	nextnonblank();
	if (c == '=') {
		NEXTC;
		if (!readword(scrword2)) {
			scrword3[0] = '\0';
			return;
		}
		nextnonblank();
		if (c == ',') {
			NEXTC;
			readword(scrword3);
		} else
			scrword3[0] = '\0';
	} else
		scrword2[0] = '\0';
}
void 
nextnonblank()
{
	while (c == ' ' || c == '\t') {
		NEXTC;
	}
}
void 
replacestr(a, b, bb)
	char          **a, *b, *bb;
{
	if (bb && *bb) {
		*a = malloc(strlen(b) + strlen(bb) + 1);
		strcpy(*a, b);
		strcat(*a, bb);
	} else {
		*a = malloc(strlen(b) + 1);
		strcpy(*a, b);
	}

}
int 
cmdnumber(a)
	char           *a;
{
	int             n, cmd, anz = 0, m = strlen(a);

	for (n = 0; script_cmds[n]; n++) {
		if (!strncmp(script_cmds[n], a, m)) {
			if (m == strlen(script_cmds[n]))
				return (n);
			cmd = n;
			anz++;
		}
	}
	if (anz == 1)
		return (cmd);	/* 1 match found */
	if (anz > 1)
		return (-2);	/* cmd not uniquely abbr */
	return (-1);
}
int 
parmnumber(a)
	char           *a;
{
	int             n, cmd, anz = 0, m = strlen(a);

	for (n = 0; update_parm[n]; n++) {
		if (!strncmp(update_parm[n], a, m)) {
			if (m == strlen(update_parm[n]))
				return (n);
			cmd = n;
			anz++;
		}
	}
	if (anz == 1)
		return (cmd);	/* 1 match found */
	if (anz > 1)
		return (-2);	/* cmd not uniquely abbr */
	return (-1);
}

RC
make_genpsedir()
{
	char            userpsepath[256], userpsebak[256];
	int             i;

/*
 *  This routine creates the pathname of the directory where the user PSE
 *  is to be installed. This pathname is stored in genpsedir.
 *  genpsedir is either
 *  - the home directory of the user <userunixname> or <userhomedir>. This
 *    happens to be if HOME (option -h) is set and is the directory where
 *    the home directories are located (e.g. /home). It is assumed that the home
 *    directory of the user is the subdirectory of HOME with the name
 *    <userunixname>. If this is not the case, the name of the home directory
 *    can be set using $userhome in the scriptfile. This parameter sets
 *    usehomedir to the name of the home directory. If userhomedir is nonzero,
 *    it is taken as the name of the home directory instead of userunixname.
 *  - or the directory genpse in the CA directory. This happens to be if
 *    HOME is NULL (i.e. option -h is not used).
 *
 *  make_genpsedir returns 0 if all of the following conditions are true:
 *
 *  - <genpsedir> exists and is a directory if HOME is set, or <genpsedir>
 *    does not exist and HOME is not set (genpsedir is created in this case).
 *  - <genpsedir>/<userhomedir> does not exist and mode is create, or it exists and is a directory
 *    and (replace is TRUE or HOME is Null or mode is update).
 *
 *  In all other cases it returns -1
 */

	strcpy(userhome, "HOME=");
	if (actualparms->HOME) {
		strcpy(genpsedir, actualparms->HOME);
		strcat(genpsedir, "/");
		if (userhomedir)
			if (*userhomedir == '/')
				strcpy(genpsedir, userhomedir);
			else
				strcat(genpsedir, userhomedir);
		else
			strcat(genpsedir, userunixname);
	} else {
		if (*cadir == '/')
			strcpy(genpsedir, cadir);
		else {
			strcpy(genpsedir, cahomedir);
			strcat(genpsedir, "/");
			strcat(genpsedir, cadir);
		}
		strcat(genpsedir, "/genpse");
	}
	strcat(userhome, genpsedir);

	if (stat(genpsedir, &buf) < 0) {
		if (!actualparms->HOME) {
			if (mkdir(genpsedir, 7 * 64) < 0) {
				fprintf(stderr, "    Can't create %s\n", genpsedir);
				return (-1);
			}
		} else {
			fprintf(stderr, "    Can't find the subject's home directory %s\n", genpsedir);
			return (-1);
		}
	} else {
		if (!(buf.st_mode & S_IFDIR)) {
			fprintf(stderr, "    File %s exists\n", genpsedir);
			return (-1);
		}
	}
	strcpy(userfiledir, genpsedir);
	strcat(userfiledir, "/");

	if (actualparms->HOME) {
		if (actualparms->newca)
			strcat(userfiledir, actualparms->newca);
		else
			strcat(userfiledir, actualparms->userpse);
	} else {
		strcat(userfiledir, userunixname);
	}

	strcpy(userpsedir, genpsedir);
	strcat(userpsedir, "/");
	strcpy(userappldir, genpsedir);
	strcat(userappldir, "/");

	if (actualparms->newca) {
		strcat(userhome, "/");
		strcat(userhome, actualparms->newca);

		strcat(userpsedir, actualparms->newca);
		strcat(userpsedir, "/");
		strcat(userappldir, actualparms->newca);
	} else
		strcat(userappldir, actualparms->userpse);

	strcat(userpsedir, actualparms->userpse);

	userappldir_rel = userappldir + strlen(genpsedir) + 1;

	if (stat(userfiledir, &buf) == 0) {
		if (!(buf.st_mode & S_IFDIR) == !actualparms->HOME) {

			/*
			 * remove existing directory if actualparms->replace
			 * == TRUE and mode is create.
			 */
			if (actualparms->create)
				if (actualparms->replace) {
					strcpy(userfilebakdir, userfiledir);
					strcat(userfilebakdir, ".BAK");
					i = rename(userfiledir, userfilebakdir);
					if (i < 0 && errno == ENOTEMPTY) {
						strcpy(syscmd, "rm -r -f ");
						strcat(syscmd, userfilebakdir);
						system(syscmd);
						i = rename(userfiledir, userfilebakdir);
						fprintf(stderr, "    Directory %s deleted\n", userfilebakdir);
					}
					if (i < 0) {
						perror("rename failed");
						fprintf(stderr, "    Directory %s exists already. Move to %s failed\n", userfiledir, userfilebakdir);
						return (-1);
					}
				} else {
					fprintf(stderr, "    Directory or file %s exists already. Use $replace to overwrite.\n", userfiledir);
					return (-1);
				}
		} else {

			/*
			 * file with name userfiledir exists, but is must be
			 * a directory. or directory with name userfiledir
			 * exists, but is must be  a file. This is an error
			 * in any case
			 */
			if (actualparms->HOME)
				fprintf(stderr, "    A file %s exists\n", userfiledir);
			else
				fprintf(stderr, "    A directory %s exists\n", userfiledir);
			return (-1);
		}


	} else if (!actualparms->create) {
		fprintf(stderr, "    Can't find directory %s for updating.\n", userfiledir);
		return (-1);
	}
	if (!actualparms->HOME) {
		if (stat(userappldir, &buf) == 0) {
			if (buf.st_mode & S_IFDIR) {
				strcpy(syscmd, "rm -r -f ");
				strcat(syscmd, userappldir);
				system(syscmd);
			} else {
				fprintf(stderr, "    File %s exists. Can`t create application directory.\n", userappldir);
				return (-1);


			}
		}
	}
	return (0);
}


static
RC 
chk_pse_dir()
{
	char            userpsepath[256];

	if (actualparms->newca)
		if (!actualparms->create) {
			if (stat(userappldir, &buf) == 0) {
				if (!(buf.st_mode & S_IFDIR)) {
					fprintf(stderr, "    %s is no directory.\n", userappldir);
					return (-1);


				}
			} else {
				fprintf(stderr, "    Application %s does not exists. Can`t update.\n", userappldir);
				return (-1);

			}
		}
	if (!actualparms->create) {
		if (stat(userpsedir, &buf) == 0) {
			if (!(buf.st_mode & S_IFDIR)) {
				fprintf(stderr, "    %s is no directory.\n", userpsedir);
				return (-1);


			}
		} else {
			fprintf(stderr, "    Application %s does not exists. Can`t update.\n", userpsedir);
			return (-1);

		}
	}
	return (0);
}

/************************************* p s e c r e a t e ***************************************/
RC 
psecreate(cmd)
	char           *cmd;
{
	char           *proc = "psecreate (ca_gen_pse)";
	int             kx = 0;
	PSEToc         *sctoc = (PSEToc *) 0;
	PSEToc         *psetoc = (PSEToc *) 0;
	Certificate    *protocert;
	RC              ret;
	PSESel         *pse_sel;
	int             SCapp_available;
	Boolean		onekeypaironly;
	char		*app_text;




	set_AF_pse(USER);
	psesel.app_name = actualparms->userpse;
	psesel.pin = aux_cpy_String(actualparms->userpin);
	psesel.object.name = CNULL;
	psesel.object.pin = CNULL;


	if((SCapp_available = sec_sctest(actualparms->userpse)) == -1) {
		if (aux_last_error() == EOPENDEV) 
			fprintf(stderr, "Cannot open device for SCT (No such device or device busy)\n");
		else	fprintf(stderr, "Error during SC configuration.\n");
		if(verbose) aux_fprint_error(stderr, 0);
		return(-1);
	}

	if (SCapp_available == TRUE) {
		name = aux_DName2Attr(subject_DName, "CN");
		fprintf(stderr, "    Please insert smartcard of %s\n", name);
		if (name)
			free(name);
		app_text = "SC application";
	}
	else 
		app_text = "application";


	if (actualparms->create) {

		psetoc = sec_read_toc(&psesel);

		if (psetoc && actualparms->replace == FALSE) {

			/* 
			 *  Application exists already, replace flag not set 
			 */

			if (SCapp_available == TRUE) 
				fprintf(stderr, "\n    %s: Inserted smartcard is not virgin  ... try replace option\n\n", cmd);
			else    fprintf(stderr, "\n    %s: Application exists already ... try replace option\n\n", cmd);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}

		if (!psetoc && (actualparms->replace == TRUE) && (SCapp_available == TRUE)) {

			/* 
			 *  SC-Application doesn't exist, replace flag set 
			 */
			/*
			 *  In case of an SW-PSE:
			 *     If replace flag is set, an existing directory has already been removed.
			 */

			fprintf(stderr, "\n    %s: Inserted smartcard is virgin  ... don't use replace option\n\n", cmd);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}

		if (SCapp_available == TRUE)
			strzfree(&psesel.pin);


		/*
		 *  Set global flag "sec_onekeypair" used in function "sec_create"
		 */

		sec_onekeypair = actualparms->onekeypair;

		ret = sec_create(&psesel);
		if (ret < 0) {
			if ((psetoc) && (aux_last_error() == ECREATEAPP)) {

				aux_free_error();

				/*
				 *  Existing SC-application shall be replaced !
				 *  
				 *    Check whether the new application fits to the old one. 
				 */

				if(psetoc->status & ONEKEYPAIRONLY) 
					onekeypaironly = TRUE;
				else 
					onekeypaironly = FALSE;

				if (actualparms->onekeypair != onekeypaironly) {
					if (actualparms->onekeypair == TRUE) 
						fprintf(stderr,"\n     %s: Existing %s contains two RSA keypairs  ... cannot be replaced by one keypair. \n\n", cmd, app_text);
					else 
						fprintf(stderr,"\n     %s: Existing %s contains one RSA keypair  ... cannot be replaced by two keypairs. \n\n", cmd, app_text);
					if (verbose)
						aux_fprint_error(stderr, 0);
					return (-1);
				}

				/*
				 *  In case of an SC application: 
				 *     => check consistency of configuartion data
				 */

				if (SCapp_available == TRUE) {
#ifdef SCA
					if (check_SCapp_configuration(actualparms->userpse, sec_onekeypair)) {
						if (aux_last_error() == EOBJ) 
							fprintf(stderr, "\n     %s: Configuration data for SC application %s are inconsistent\n\n", cmd, actualparms->userpse);
						else 
							fprintf(stderr, "\n    %s: Error during SC configuration check for application %s\n\n", cmd, actualparms->userpse);
						if (verbose)
							aux_fprint_error(stderr, 0);
						return (-1);
					}
#endif
				}
			}
			else {
				/* 
				 *  Error during creation of application 
				 */

				fprintf(stderr, "\n    %s: ", cmd);
				fprintf(stderr, "Creation of %s failed\n\n", app_text);
				if (verbose)
					aux_fprint_error(stderr, 0);
				return (-1);
			}
		}

		actualparms->userpin = global.userpin = psesel.pin;

		set_AF_pse(USER);

		if (af_pse_update_Name(subject_DName) < 0) {
			fprintf(stderr, "    %s: ", cmd);
			fprintf(stderr, "unable to create Name on PSE\n");
			aux_add_error(EINVALID, "unable to create Name on PSE", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}


		/* create and install PSE object "Serial" */

		if (actualparms->newca) {
			if (af_pse_update_SerialNumbers(actualparms->serialnums) < 0) {
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "unable to create Serial on PSE");
				aux_add_error(EINVALID, "unable to create Serial on PSE", CNULL, 0, proc);
				if (verbose)
					aux_fprint_error(stderr, 0);
				return (-1);
			}
		}
		if (verbose)
			fprintf(stderr, "    %s: PSE created for <%s> and application %s.\n", cmd, subject_Name, actualparms->userpse);
	}
/************************************* g e t p k r o o t ***************************************/
	if (actualparms->pkroot) {
		set_AF_pse(CA);

		if (!(pkroot = af_pse_get_PKRoot())) {
			aux_add_error(EINVALID, "Can't read PKRoot from PSE", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			fprintf(stderr, "    %s: Can't read PKRoot from PSE %s\n", cmd, capsepath);
			return (-1);
		}
		if (verbose)
			fprintf(stderr, "    Get PKRoot from %s: done.\n", capsepath);

/************************************* i n s t p k r o o t *************************************/

		set_AF_pse(USER);

		if (actualparms->newpkr || actualparms->oldpkr)
			if ((oldpkroot = af_pse_get_PKRoot())) {

				pklist = af_pse_get_PKList(SIGNATURE);

				if (actualparms->oldpkr && oldpkroot->oldkey) {
					if (!(newpklist = (PKList *) malloc(sizeof(PKList)))) {
						fprintf(stderr, "    %s: ", cmd);
						fprintf(stderr, "Can't allocate memory\n");
						aux_add_error(EMALLOC, "newpklist", CNULL, 0, proc);
						if (verbose)
							aux_fprint_error(stderr, 0);
						return (-1);
					}
					newpklist->next = pklist;
					if (!(newpklist->element = (ToBeSigned *) malloc(sizeof(ToBeSigned)))) {
						fprintf(stderr, "    %s: ", cmd);
						fprintf(stderr, "Can't allocate memory\n");
						aux_add_error(EMALLOC, "newpklist->element", CNULL, 0, proc);
						if (verbose)
							aux_fprint_error(stderr, 0);
						return (-1);
					}
					newpklist->element->version = 0;
					newpklist->element->serialnumber = oldpkroot->oldkey->serial;
					newpklist->element->signatureAI = DEF_ISSUER_ALGID;
					newpklist->element->issuer = oldpkroot->ca;
					newpklist->element->notbefore = "900101000000+0000";
					newpklist->element->notafter = "990101000000+0000";
					newpklist->element->subject = oldpkroot->ca;
					newpklist->element->subjectPK = oldpkroot->oldkey->key;
#ifdef COSINE
					newpklist->element->authatts = (AuthorisationAttributes *) 0;
#endif

					pklist = newpklist;
				}
				if (actualparms->newpkr && oldpkroot->newkey) {
					if (!(newpklist = (PKList *) malloc(sizeof(PKList)))) {
						fprintf(stderr, "    %s: ", cmd);
						fprintf(stderr, "Can't allocate memory\n");
						aux_add_error(EMALLOC, "newpklist", CNULL, 0, proc);
						if (verbose)
							aux_fprint_error(stderr, 0);
						return (-1);
					}
					newpklist->next = pklist;
					if (!(newpklist->element = (ToBeSigned *) malloc(sizeof(ToBeSigned)))) {
						fprintf(stderr, "    %s: ", cmd);
						fprintf(stderr, "Can't allocate memory\n");
						aux_add_error(EMALLOC, "newpklist->element", CNULL, 0, proc);
						if (verbose)
							aux_fprint_error(stderr, 0);
						return (-1);
					}
					newpklist->element->version = 0;
					newpklist->element->serialnumber = oldpkroot->newkey->serial;
					newpklist->element->signatureAI = DEF_ISSUER_ALGID;
					newpklist->element->issuer = oldpkroot->ca;
					newpklist->element->notbefore = "900101000000+0000";
					newpklist->element->notafter = "990101000000+0000";
					newpklist->element->subject = oldpkroot->ca;
					newpklist->element->subjectPK = oldpkroot->newkey->key;
#ifdef COSINE
					newpklist->element->authatts = (AuthorisationAttributes *) 0;
#endif

					pklist = newpklist;
				}
				if (af_pse_update_PKList(SIGNATURE, pklist) < 0) {
					fprintf(stderr, "    %s: Can't install PKList on PSE %s\n", cmd, actualparms->userpse);
					aux_add_error(EINVALID, "af_pse_update_PKList failed", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					aux_free_PKList(&pklist);
					return (-1);
				}
				if (actualparms->newpkr && oldpkroot->newkey) {
					newpklist = pklist;
					free(pklist->element);
					pklist = pklist->next;
					free(newpklist);
				}
				if (actualparms->oldpkr && oldpkroot->oldkey) {
					newpklist = pklist;
					free(pklist->element);
					pklist = pklist->next;
					free(newpklist);
				}
				aux_free_PKList(&pklist);
				aux_free_PKRoot(&oldpkroot);

			}
		if (af_pse_update_PKRoot(pkroot) < 0) {
			fprintf(stderr, "    %s: Can't install PKRoot on PSE %s\n", cmd, actualparms->userpse);
			aux_add_error(EINVALID, "af_pse_update_PKRoot failed", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			aux_free_PKRoot(&pkroot);
			return (-1);
		}
		if (verbose) {
			fprintf(stderr, "    %s: The following PKRoot was installed on the user PSE:\n", cmd);
			aux_fprint_PKRoot(stderr, pkroot);
		}
	}
/************************************* g e t f c p a t h ***************************************/

	set_AF_pse(CA);
	if (actualparms->fcpath || actualparms->pkroot >= OLD_TO_PKLIST) {
		if (!(soc = (SET_OF_Certificate *) malloc(sizeof(SET_OF_Certificate)))) {
			fprintf(stderr, "    %s: ", cmd);
			fprintf(stderr, "Can't allocate memory\n");
			aux_add_error(EMALLOC, "soc", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}
		soc->element = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0);

		if (aux_cmp_DName(soc->element->tbs->issuer, soc->element->tbs->subject))
			soc->next = af_pse_get_CertificateSet(SIGNATURE);
		else {
			/* get FCPath from root CA */
			soc->next = (SET_OF_Certificate *) 0;
			aux_free_CertificateSet(&soc);
			soc = af_pse_get_CertificateSet(SIGNATURE);
		}
		aux_free_error();

		if (!soc) {
			/* empty FCPath */
			if (verbose)
				fprintf(stderr, "    Empty FCPath from %s: done.\n", capsepath);
			goto genkey;
		}
		if (!(fcpath = (FCPath *) malloc(sizeof(FCPath)))) {
			fprintf(stderr, "    %s: ", cmd);
			fprintf(stderr, "Can't allocate memory\n");
			aux_add_error(EMALLOC, "fcpath", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}
		fcpath->liste = soc;
		fcpath->next_forwardpath = af_pse_get_FCPath(NULLDNAME);
		aux_free_error();

		if (verbose)
			fprintf(stderr, "    Get FCPath from %s: done.\n", capsepath);
	}
/************************************* i n s t f c p a t h *************************************/

	if (actualparms->fcpath) {

		set_AF_pse(USER);

		if (af_pse_update_FCPath(fcpath) < 0) {
			fprintf(stderr, "    %s: Can't install FCPath on PSE %s\n", cmd, actualparms->userpse);
			aux_add_error(EINVALID, "af_pse_update_FCPath failed", CNULL, 0, proc);
			if (verbose)
				aux_fprint_error(stderr, 0);
			return (-1);
		}
		if (verbose) {
			fprintf(stderr, "    %s: The following FCPath was installed on the user PSE:\n", cmd);
			aux_fprint_FCPath(stderr, fcpath);
		}
	}
/***************************************** g e n k e y *****************************************/

genkey:
	if (actualparms->onekeypair)
		ka = 1;
	else
		ka = 2;
	for (kx = 0; kx < ka; kx++)
		if (actualparms->cert[kx]) {
			set_AF_pse(USER);

			if (kx == 0)
				ktype = SIGNATURE;
			else
				ktype = ENCRYPTION;

			if (actualparms->newkey[kx]) {
				algorithm = actualparms->algorithms[kx];
				keytype = keytypes[kx];
				keysize = actualparms->keysizes[kx];

				key.keyref = 0;
				key.pse_sel = (PSESel *) 0;
				key.key = &keyinfo;
				keyinfo.subjectAI = aux_cpy_AlgId(algorithm);
				if (aux_ObjId2ParmType(algorithm->objid) != PARM_NULL)
					*(int *) (keyinfo.subjectAI->parm) = keysize;

				name = aux_ObjId2Name(algorithm->objid);
				if (verbose)
					fprintf(stderr, "    %s: Generating %s key pair (Algorithm %s)\n        for <%s> with PSE %s ...\n", cmd, keytype, name, subject_Name, actualparms->userpse);
				free(name);

				if (verbose)
					sec_verbose = TRUE;
				else
					sec_verbose = FALSE;

				rc = af_gen_key(&key, ktype, actualparms->replace);

				if (rc < 0) {
					fprintf(stderr, "    %s: ", cmd);
					fprintf(stderr, "Can't generate new keys\n");
					aux_add_error(EINVALID, "Can't generate new keys", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					aux_free_FCPath(&fcpath);
					aux_free_PKRoot(&pkroot);
					return (-1);
				} else if (verbose)
					fprintf(stderr, "    %s: Key generation O.K.\n", cmd);


				if (ktype == SIGNATURE) {
					if (actualparms->onekeypair)
						subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, SKnew_name, subject_DName);
					else
						subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, SignSK_name, subject_DName);
				} else
					subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, DecSKnew_name, subject_DName);

				if (!subject_Certificate) {
					fprintf(stderr, "    %s: ", cmd);
					fprintf(stderr, "Can't create prototype certificate\n");
					aux_add_error(EINVALID, "Can't create prototype certificate", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					aux_free_FCPath(&fcpath);
					aux_free_PKRoot(&pkroot);
					return (-1);
				}
				if (af_pse_update_Certificate(ktype, subject_Certificate, TRUE) < 0) {
					fprintf(stderr, "%s: ", cmd);
					fprintf(stderr, "unable to store prototype certificate on PSE");
					aux_add_error(EINVALID, "unable to store prototype certificate on PSE", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					return(-1);
				}
			} else {
				subject_Certificate = af_pse_get_Certificate(ktype, NULLDNAME, 0);
				aux_cpy2_KeyInfo(&keyinfo, subject_Certificate->tbs->subjectPK);
				aux_free_Certificate(&subject_Certificate);

				if (ktype == SIGNATURE) {
					if (actualparms->onekeypair)
						subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, SKnew_name, subject_DName);
					else
						subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, SignSK_name, subject_DName);
				} else
					subject_Certificate = af_create_Certificate(&keyinfo, actualparms->issuer_alg, DecSKnew_name, subject_DName);


			}
/***************************************** c e r t i f y ****************************************/

			set_AF_pse(CA);

			/* O.K. skip to CA dir */

			if (cadir[0] != '/') {
				home = getenv("HOME");
				if (!home)
					home = "";
				cadir_abs = (char *) malloc(strlen(home) + strlen(cadir) + 10);
				if (!cadir_abs) {
					aux_add_error(EMALLOC, "cadir_abs", cmd, char_n, proc);
					return (-1);
				}
				strcpy(cadir_abs, home);
				strcat(cadir_abs, "/");
				strcat(cadir_abs, cadir);
			} else {
				cadir_abs = (char *) malloc(strlen(cadir) + 10);
				if (!cadir_abs) {
					aux_add_error(EMALLOC, "cadir_abs", cmd, char_n, proc);
					return (-1);
				}
				strcpy(cadir_abs, cadir);
			}

			logpath = (char *) malloc(strlen(cadir_abs) + 10);
			strcpy(logpath, cadir_abs);
			strcat(logpath, "/");
			strcat(logpath, CALOG);

			if ((logfile = fopen(logpath, LOGFLAGS)) == (FILE *) 0) {
				fprintf(stderr, "    %s: Can't open %s\n", cmd, CALOG);
				aux_add_error(EINVALID, "Can't open", CALOG, char_n, proc);
				if (verbose)
					aux_fprint_error(stderr, 0);
				free(logpath);
				aux_free_FCPath(&fcpath);
				aux_free_PKRoot(&pkroot);
				aux_free_Certificate(&subject_Certificate);
				return (-1);
			}
			free(logpath);

			/*
			 * include tests of prototype certificate before
			 * signing
			 */

			/*
			 * verify signature of prototype certificate with
			 * public key to be certified
			 */


			key.key = subject_Certificate->tbs->subjectPK;
			key.keyref = 0;
			key.pse_sel = (PSESel *) 0;
			rc = sec_verify(subject_Certificate->tbs_DERcode, subject_Certificate->sig, END, &key, (HashInput *) 0);
			if (rc) {
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "Can't verify prototype certificate\n");
				aux_add_error(EINVALID, "Can't verify prototype certificate", CNULL, 0, proc);
				if (verbose)
					aux_fprint_error(stderr, 0);
				LOGAFERR;
				fclose(logfile);
				aux_free_FCPath(&fcpath);
				aux_free_PKRoot(&pkroot);
				aux_free_Certificate(&subject_Certificate);
				return (-1);
			}
			if (af_cadb_add_user(subject_Name, cadir_abs) < 0) {
				LOGERR("can't access user db");
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "Warning: Can't access user db\n");
			}
			if (subject_Certificate->tbs->notbefore) {
				free(subject_Certificate->tbs->notbefore);
				subject_Certificate->tbs->notbefore = CNULL;
			}
			if (subject_Certificate->tbs->notafter) {
				free(subject_Certificate->tbs->notafter);
				subject_Certificate->tbs->notafter = CNULL;
			}
			if (!actualparms->notbefore) {
				subject_Certificate->tbs->notbefore = aux_current_UTCTime();
				subject_Certificate->tbs->notafter = aux_delta_UTCTime(subject_Certificate->tbs->notbefore);
			} else {
				subject_Certificate->tbs->notbefore = (UTCTime *) malloc(TIMELEN);
				strcpy(subject_Certificate->tbs->notbefore, actualparms->notbefore);
				subject_Certificate->tbs->notafter = (UTCTime *) malloc(TIMELEN);
				strcpy(subject_Certificate->tbs->notafter, actualparms->notafter);
			}

			subject_Certificate->tbs->issuer = aux_cpy_DName(issuer_dn);
			subject_Certificate->tbs->serialnumber = af_pse_incr_serial();
			subject_Certificate->tbs->version = 0;	/* default version */

			aux_free_OctetString(&subject_Certificate->tbs_DERcode);
			if (subject_Certificate->sig)
				aux_free_KeyInfo(&subject_Certificate->sig);
			subject_Certificate->sig = (Signature *) malloc(sizeof(Signature));
			if (!subject_Certificate->sig) {
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "Can't allocate memory\n");
				aux_add_error(EMALLOC, "subject_Certificate->sig", CNULL, 0, proc);
				if (verbose)
					aux_fprint_error(stderr, 0);
				fclose(logfile);
				aux_free_FCPath(&fcpath);
				aux_free_PKRoot(&pkroot);
				aux_free_Certificate(&subject_Certificate);
				return (-1);
			}
			subject_Certificate->sig->signAI = aux_cpy_AlgId(actualparms->issuer_alg);
			subject_Certificate->tbs->signatureAI = aux_cpy_AlgId(subject_Certificate->sig->signAI);
			subject_Certificate->tbs_DERcode = e_ToBeSigned(subject_Certificate->tbs);

			if (!subject_Certificate->tbs_DERcode || (af_sign(subject_Certificate->tbs_DERcode, subject_Certificate->sig, END) < 0)) {
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "AF Error with CA Signature\n");
				aux_add_error(EINVALID, "AF Error with CA Signature", CNULL, 0, proc);
				aux_free_Certificate(&subject_Certificate);
				if (verbose)
					aux_fprint_error(stderr, 0);
				LOGAFERR;
				fclose(logfile);
				aux_free_FCPath(&fcpath);
				aux_free_PKRoot(&pkroot);
				aux_free_Certificate(&subject_Certificate);
				return (-1);
			}
			if (af_cadb_add_Certificate(ktype, subject_Certificate, cadir_abs)) {
				LOGERR("Can't access certificate db");
				fprintf(stderr, "    %s: ", cmd);
				fprintf(stderr, "Warning: Can't access certificate db\n");
			}
			if (verbose) {
				fprintf(stderr, "%s: The following certificate was generated by <%s>\n    using PSE %s:\n", cmd, issuer, capsepath);
				aux_fprint_Certificate(stderr, subject_Certificate);
			}
			fclose(logfile);

/***************************************** i n s t c e r t *****************************************/

			set_AF_pse(USER);

			if (hierarchy) {
				if (verbose)
					fprintf(stderr, "%s: Verifying and installing certificate in PSE %s ...\n", cmd, actualparms->userpse);

				if ((aux_ObjId2AlgType(subject_Certificate->tbs->subjectPK->subjectAI->objid) == SIG) && ktype == ENCRYPTION) {
					fprintf(stderr, "%s: Signature key to be installed as Encryption key\n", cmd);
					aux_add_error(EINVALID, "Signature key to be installed as Encryption key", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					return(-1);
				}
				protocert = af_pse_get_Certificate(ktype, NULLDNAME, 0);
				if (!protocert) {

					/*
					 * check whether PK of cert to be
					 * installed fits to SKnew or SignSK or DecSKnew
					 */

					if(actualparms->onekeypair == TRUE)
						pse_sel = af_pse_open(SKnew_OID, FALSE);
					else{
        					if(ktype == SIGNATURE) pse_sel = af_pse_open(SignSK_OID, FALSE);
        					else pse_sel = af_pse_open(DecSKnew_OID, FALSE);
					}
        				if(!pse_sel) {
						if(actualparms->onekeypair == TRUE){
							fprintf(stderr,"%s: Can't open SKnew to check PK\n", cmd);
							aux_add_error(EINVALID, "Can't open SKnew to check PK", CNULL, 0, proc);
						}
						else{
							fprintf(stderr,"%s: Can't open SignSK or DecSKnew to check PK\n", cmd);
							aux_add_error(EINVALID, "Can't open SignSK or DecSKnew to check PK", CNULL, 0, proc);
						}
						if(verbose) aux_fprint_error(stderr, 0);
						return(-1); 
					}
					key.key = (KeyInfo *) 0;
					key.keyref = 0;
					key.pse_sel = pse_sel;
#ifdef SCA
					if((SCapp_available = sec_sctest(actualparms->userpse)) == -1) {
						if (aux_last_error() == EOPENDEV) 
							fprintf(stderr, "Cannot open device for SCT (No such device or device busy)\n");
						else	fprintf(stderr, "Error during SC configuration.\n");
						if(verbose) aux_fprint_error(stderr, 0);
						return(-1);
					}

					if (SCapp_available == TRUE)
						rc = 0;
					else
						rc = sec_checkSK(&key, subject_Certificate->tbs->subjectPK);
#else
					rc = sec_checkSK(&key, subject_Certificate->tbs->subjectPK);
#endif
				} else {
					rc = aux_cmp_KeyInfo(subject_Certificate->tbs->subjectPK, protocert->tbs->subjectPK);
					aux_free_Certificate(&protocert);
				}

				if (rc < 0) {
					fprintf(stderr, "%s: PK of certificate to be installed does not fit to SignSK or DecSKnew\n", cmd);
					aux_add_error(EINVALID, "PK of certificate to be installed does not fit to SignSK or DecSKnew", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					return(-1);
				}
				fcpath = af_pse_get_FCPath(NULLDNAME);
				certs = aux_create_Certificates(subject_Certificate, fcpath);
				rc = af_verify_Certificates(certs, CNULL, (PKRoot *) 0);
				if (rc < 0) {
					fprintf(stderr, "%s: Can't verify hierarchy certificate to be installed\n", cmd);
					aux_add_error(EINVALID, "Can't verify hierarchy certificate to be installed", CNULL, 0, proc);
					if (verbose)
						aux_fprint_error(stderr, 0);
					return(-1);
				} else if (verbose)
					fprintf(stderr, "%s: Hierarchy Certificate verified\n", cmd);
			}
			rc = af_pse_update_Certificate(ktype, subject_Certificate, hierarchy);

			if (rc < 0) {
				fprintf(stderr, "%s: Can't install certificate\n", cmd);
				aux_add_error(EINVALID, "Can't install certificate", CNULL, 0, proc);
				if (verbose)
					aux_fprint_error(stderr, 0);
				return(-1);
			} else if (verbose) {

				if (hierarchy) {
					if (ktype == SIGNATURE) {
						if (actualparms->onekeypair)
							fprintf(stderr, "%s: %s Certificate installed as object Cert on PSE %s\n", cmd, keytype, actualparms->userpse);
						else
							fprintf(stderr, "%s: %s Certificate installed as object SignCert on PSE %s\n", cmd, keytype, actualparms->userpse);
					}
					else
						fprintf(stderr, "%s: %s Certificate installed as object EncCert on PSE %s\n", cmd, keytype, actualparms->userpse);
				}

				else {
					if (ktype == SIGNATURE) {
						if (actualparms->onekeypair)
							fprintf(stderr, "%s: %s Certificate added to object CSet on PSE %s\n", cmd, keytype, actualparms->userpse);
						else
							fprintf(stderr, "%s: %s Certificate added to object SignCSet on PSE %s\n", cmd, keytype, actualparms->userpse);
					}
					else
						fprintf(stderr, "%s: %s Certificate added to object EncCSet on PSE %s\n", cmd, keytype, actualparms->userpse);
				}
			}

			if (hierarchy && actualparms->enter) {
#ifdef AFDBFILE

				/*
				 * Determine whether X.500 directory shall be
				 * accessed
				 */
				strcpy(afdb, AFDBFILE);	/* file = .af-db/ */
				strcat(afdb, "X500");	/* file = .af-db/'X500' */
				if (open(afdb, O_RDONLY) < 0)
					x500 = FALSE;
#endif
#ifdef X500
				if (name_from_pse && x500)
					directory_user_dname = af_pse_get_Name();
				if (x500) {
					if (verbose) {
						fprintf(stderr, "%s: Accessing the X.500 directory entry of ", cmd);
						fprintf(stderr, "owner = \"%s\" ...\n", subject_Name);
					}
					rc = af_dir_enter_Certificate(subject_Certificate, certtype);
					if (verbose) {
						if (rc < 0)
							fprintf(stderr, "%s: Directory entry (X.500) failed.\n", cmd);
						else
							fprintf(stderr, "%s: Certificate entered into X.500 Directory.\n", cmd);
					}
					if (kx == 0) {	/* SIGNATURE certificate */
						rc = af_dir_delete_Certificate_from_targetObject(subject_Certificate->tbs->subject, 0, proto_dn, certtype);
						if (verbose) {
							if (rc < 0)
								fprintf(stderr, "    %s: Directory operation (X.500) failed.\n", cmd);
							else
								fprintf(stderr, "    %s: Certificate with issuer <%s> removed from X.500 Directory entry of <%s>.\n", cmd, "cn=PROTO\0", subject_Name);
						}
					}
				}
#endif
#ifdef AFDBFILE
				if (verbose) {
					fprintf(stderr, "%s: Accessing the .af-db directory entry of ", cmd);
					fprintf(stderr, "owner = \"%s\" ...\n", userunixname);
				}
				if (actualparms->HOME || actualparms->enter)
					setuid(userunixname);
				rc = af_afdb_enter_Certificate(subject_Certificate, ktype, TRUE);
				if (verbose) {
					if (rc < 0)
						fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
					else
						fprintf(stderr, "%s: %s Certificate entered into .af-db Directory.\n", cmd, keytype);
				}
				if (actualparms->onekeypair) {
					rc = af_afdb_enter_Certificate(subject_Certificate, DecSKnew_name, TRUE);
					if (verbose) {
						if (rc < 0)
							fprintf(stderr, "%s: Directory entry (.af-db) failed.\n", cmd);
						else
							fprintf(stderr, "%s: %s Certificate entered into .af-db Directory.\n", cmd, keytypes[1]);
					}
				}
#endif
			}
			aux_free_Certificate(&subject_Certificate);
			aux_free_FCPath(&fcpath);
			aux_free_PKRoot(&pkroot);
		}
			
        af_pse_close(NULLOBJID);

	return (0);
}
static
set_AF_pse(psetype)
	PSEtype         psetype;
{
	int             i;
	char           *proc = "set_AF_pse";

	if (psetype == CA) {
		if (aux_create_AFPSESel(capsepath, actualparms->capin) < 0) {
			aux_add_error(EINVALID, "Cannot create AFPSESel", CNULL, 0, proc);
			return -1;
		}
		putenv(cahome);
		if (actualparms->HOME || actualparms->enter) {
#ifdef __HP__
			i = setuid(caunixuid);
#else
			i = setruid(caunixuid);
#endif
			if (i < 0)
				fprintf(stderr, "setuid to %d failed\n", caunixuid);
		}
#ifdef SCA
		sc_sel.sct_id = 2;
#endif
	} else {
		if (aux_create_AFPSESel(actualparms->userpse, actualparms->userpin) < 0) {
			aux_add_error(EINVALID, "Cannot create AFPSESel", CNULL, 0, proc);
			return -1;
		}
		putenv(userhome);
		if (actualparms->HOME || actualparms->enter) {
#ifdef __HP__
			i = setuid(userunixuid);
#else
			i = setruid(userunixuid);
#endif
			if (i < 0)
				fprintf(stderr, "setuid to %d failed\n", userunixuid);
		}
#ifdef SCA
		sc_sel.sct_id = 1;
#endif
	}

	return (0);
}

static int
localinit(cadir_abs)
	char           *cadir_abs;
{
#define	DBMOPENFL	O_RDWR|O_CREAT, S_IREAD|S_IWRITE
#ifdef NDBM
	DBM            *user;
	DBM            *cert;

#else
	FILE           *fd;
	char            fn[64];

#endif
	datum           key, data;
	int             i;
	char           *userdbpath, *certdbpath;
	char           *proc = "localinit";



	userdbpath = (char *) malloc(strlen(cadir_abs) + 10);
	strcpy(userdbpath, cadir_abs);
	strcat(userdbpath, "/");
	strcat(userdbpath, USERDB);

	certdbpath = (char *) malloc(strlen(cadir_abs) + 10);
	strcpy(certdbpath, cadir_abs);
	strcat(certdbpath, "/");
	strcat(certdbpath, CERTDB);


	/* user dbm */

#ifdef NDBM
	user = dbm_open(userdbpath, DBMOPENFL);
	if (!user)
		return 1;
	dbm_close(user);
#else
	strcpy(fn, userdbpath);
	strcat(fn, ".pag");
	fd = fopen(fn, "r");
	if (fd)
		fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	strcpy(fn, userdbpath);
	strcat(fn, ".dir");
	fd = fopen(fn, "r");
	if (fd)
		fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	if (dbminit(userdbpath) < 0)
		return 1;
	else
		dbmclose();
#endif

	/* cert dbm */

#ifdef NDBM
	cert = dbm_open(certdbpath, DBMOPENFL);
	if (!cert)
		return 1;
	dbm_close(cert);
#else
	strcpy(fn, certdbpath);
	strcat(fn, ".pag");
	fd = fopen(fn, "r");
	if (fd)
		fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	strcpy(fn, certdbpath);
	strcat(fn, ".dir");
	fd = fopen(fn, "r");
	if (fd)
		fclose(fd);
	else {
		fd = fopen(fn, "w");
		fclose(fd);
	}
	if (dbminit(certdbpath) < 0)
		return 1;
	else
		dbmclose();

#endif

	return 0;
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "gen_pse  Creating and updating of PSE's\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "gen_pse            [-i script][-c cadir][-p capse][-H home][-u userunixname]\n");
	fprintf(stderr, "                   [-a issueralg][-s signalg][-e encalg][-k keysize]\n");
	fprintf(stderr, "                   [-f notbefore][-l notafter][-x nameprefix]\n");
	fprintf(stderr, "                   [-P subjectpse][-C caname][-g serialnumber]\n");
	fprintf(stderr, "                   ");
#ifdef X500
	fprintf(stderr, "[-d dsaname] [-n]");
#endif
	fprintf(stderr, "[-vrDqth][namesuffix]\n");

        if(help == LONG_HELP) {




        fprintf(stderr, "                   \n");
        fprintf(stderr, "-i <script>        Name of a script file where these options can be set for more than one creation\n");
        fprintf(stderr, "-c <cadir>         Name of CA-directory (default: environment variable CADIR or .ca)\n");
        fprintf(stderr, "-p <capse>         CA's PSE name (default: environment variable CAPSE or .capse)\n");
        fprintf(stderr, "-H <home>          Path of all home-directories\n");
        fprintf(stderr, "-u <userunixname>  Unixname of the owner of a PSE to create/update\n");
        fprintf(stderr, "-a <issueralg>     Algorithm to sign certificates with\n");
        fprintf(stderr, "-s <signalg>       Algorithm of signature key to create/update\n");
        fprintf(stderr, "-e <encalg>        Algorithm of encryption key to create/update\n");
        fprintf(stderr, "-k <keysize>       Keysize of key to generate\n");
        fprintf(stderr, "-f <notbefore>     First date on which the certificate is valid\n");
        fprintf(stderr, "-l <notafter>      Last date on which the certificate is valid\n");
        fprintf(stderr, "-x <nameprefix>    First part of the name associated to the PSE\n");
        fprintf(stderr, "-P <subjectpse>    Name of PSE to create/update (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-C <caname>        Create a CA with CA-directory name <caname>\n");
        fprintf(stderr, "-g <serialnumber>  If a CA is created a serialnumber to start with can be specified\n");
#ifdef X500
        fprintf(stderr, "-d <dsaname>       The name of the dsa\n");


        fprintf(stderr, "-n                 Read the name of the dsa from PSE\n");
#endif
        fprintf(stderr, "-v                 Verbose\n");
        fprintf(stderr, "-r                 Replace an existing PSE in case of creation\n");
        fprintf(stderr, "-D                 Store generated certificates in X500 directory\n");
        fprintf(stderr, "-q                 Create two different key pairs for signature and encryption\n");
        fprintf(stderr, "-t                 Check malloc/free behaviour\n");
        fprintf(stderr, "-h                 Write this help text\n");
        fprintf(stderr, "                   \n");

        fprintf(stderr, "<namesuffix>      Second part of the name associated to the PSE\n");


        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM GEN_PSE */
}

