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

/*-----------------------psemaint.c---------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   util            VERSION   3.0                          */
/*                              DATE   20.01.1992                   */
/*                                BY   ws                           */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This is a MAIN program to maintain the PSE                     */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*                                                                  */
/*                                                                  */
/* USAGE:                                                           */
/*     psemaint [-c cadir] [-p psename] [-d dsaname] [-i inputfile] */
/*              [-h] [cmd] 					    */
/*------------------------------------------------------------------*/

#define NL '\012'
#define ALL 6
#define ENC 5
#define TIMELEN 40

#include "af.h"
#include "cadb.h"
#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <unix.h>
#include <console.h>
#include "Mac.h"
#endif
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>


/*
 *    Be careful when changing  enum {...} commands  and struct {...} cmds[]:
 *    They must be in the same order. commands is the index of cmds[].
 */

enum {
       ADDALIAS, ADDEK, ADDPK, ALGS, ALIAS2DNAME,
#ifdef X500
       AUTHNONE, AUTHSIMPLE,
#ifdef STRONG
       AUTHSTRONG,
#endif
#endif
       CACERTIFICATE, CAPEMCRL, CAPRINTLOG, CASERIALNUMBERS, CAUSERS, CERTIFY,
       CERT2KEYINFO, CERT2PKROOT, CHPIN, CHALLPIN, CHECK, CLOSE, CREATE, DELALIAS, DELEK, DELETE,
       DELKEY, DELPEMCRL, DELPK, DNAME2ALIAS,
#ifdef SCA
       EJECT,
#endif
       ENDE, ENTER, ERROR, EXIT, GENKEY, HELPCMD, INITPEMCRL, KEYTOC,
       MFLIST,
       OPEN, PROLONG, PROTOTYPE, QM, QUIT, READ, REMOVE,
       RENAME, RESETERROR, RETRIEVE, REVOKE, SETPARM, SHOW,
       SPLIT, STRING2KEY, TOC,
#ifdef SCA
       TOGGLE,
#endif
       VERIFY, WRITE, XDUMP
} commands;

struct {
        char *cmd;
        char *parms;
        char *text;
        char *longtext;
} cmds[] = {
{ "addalias",
        "<username>",
        "Add alias entry with distinguished name <username> to alias file",
        "" } ,
{ "addek",
        "<certificate>",
        "The ToBeSigned part of <certificate> is added to EKList",
        "" } ,
{ "addpk",
        "<certificate> ",
        "The ToBeSigned part of <certificate> is added to PKList",
        "" } ,
{ "algs",
        "<algname> or <algtype>",
        "Show parameters of given algorithm or algorithm type",
        "" } ,
{ "alias2dname",
        "<pattern>",
        "Search alias containing <pattern> and print corresponding DName",
        "" } ,
#ifdef X500
{ "authnone",
        "", 
        "Bind to X.500 Directory without using any authentication", 
        "" } ,
{ "authsimple",
        "", 
        "Use simple DSA authentication ", 
        "" } ,
#ifdef STRONG
{ "authstrong",
        "", 
        "Use strong DSA authentication ", 
        "" } ,
#endif
#endif
{ "cacertificate",
        "<serial>",
        "CA-cmd: Show issued certificate with serial number <serial>",
        "" } ,
{ "capemcrl",
        "",
        "CA-cmd: List all PemCrls stored in local database",
        "" } ,
{ "calog",
        "",
        "CA-cmd: Show CA log-file",
        "" } ,
{ "caserialnumbers",    
        "<name>", 
        "CA-cmd: Show all serialnumbers and dates of issue of certificates issued for user <name>",
        "" } ,
{ "causers",
        "", 
        "CA-cmd: List all users who have been certified", 
        "" } ,
{ "certify",
        "<certificate>", 
        "CA-cmd: Certify the public key contained in <certificate>", 
        "" } ,
{ "cert2keyinfo",
        "<certificate> <object or keyref>", 
        "Take public key from certificate and store it as KeyInfo in object or under keyref",
        "" } ,
{ "cert2pkroot",
        "<certificate> <object>", 
        "Take public key from certificate and store it as PKRoot in <object>",
        "" } ,
{ "chpin",
        "<object>", 
        "Change PIN for PSE or <object> on PSE",
        "" } ,
{ "challpin",
        "", 
        "Change all PIN's for PSE",
        "" } ,
{ "check",
        "", 
        "Check content of PSE for consistency",
        "" } ,
{ "close",   
        "", 
        "Close PSE",
        "" } ,
{ "create",
        "<object>", 
        "Create <object> on PSE",
        "" } ,
{ "delalias",
        "<alias>", 
        "Remove alias <alias> from alias file",
        "" } ,
{ "delek",
        "<issuer> <serialnumber> or <subject>",
        "The ToBeSigned identified by either <issuer> and <serialnumber> or <subject> is deleted from EKList",
        "" } ,
{ "delete",
        "<object>", 
        "Delete PSE or <object> on PSE",
        "" } ,
{ "delkey",
        "<keyref>", 
        "Remove key with given <keyref>",
        "" } ,
{ "delpemcrl",
        "<issuer>",
        "Remove revoction list of <issuer> from set of locally stored revocation lists (PEM)",
        "" } ,
{ "delpk",
        "<issuer> <serialnumber> or <subject>",
        "The ToBeSigned identified by either <issuer> and <serialnumber> or <subject> is deleted from PKList",
        "" } ,
{ "dname2alias",
        "<pattern>",
        "Search DName containing <pattern> and print corresponding alias names",
        "" } ,
#ifdef SCA
{ "eject",
        "<sct-id>",
        "Eject smartcard <sct-id>. If sct-id is 0 or omitted, eject all smartcards",
        "" } ,
#endif
{ "end",
        "",
        "Exit program",
        "" } ,
{ "enter",
        "attrtype=<attrtype> keytype=<keytype>", 
        "Enter security attribute into Directory",
        "" } ,
{ "error",
        "", 
        "print error stack",
        "" } ,
{ "exit",
        "",
        "Exit program",
        "" } ,
{ "genkey",
        "<algname> <object or keyref>", 
        "Generate key and store in <object> or under <keyref>",
        "" } ,
{ "helpcmd",
        "<cmd>",
        "Show helptext for <cmd>",
        "" } ,
{ "initpemcrl",
        "",
        "CA-cmd: Create an empty PemCrl",
        "" } ,
{ "keytoc",  
        "", 
        "Show table of contents (toc) of all keys (keyref's)",
        "" } ,
{ "mflist",
        "<cmd>",
        "Show list of malloc'd addresses",
        "" } ,
{ "open",    
        "<pse>", 
        "Open PSE",
        "" } ,
{ "prolong",    
        "", 
        "CA-cmd: Prolong the validity of the own PemCrl",
        "" } ,
{ "prototype",    
        "", 
        "Create a self-signed prototype-certificate of the own public signature key",
        "" } ,
{ "?",
        "<cmd>", 
        "show helptext for cmd",
        "" } ,
{ "quit",
        "",
        "Exit program",
        "" } ,
{ "read",
        "<object> <destination>", 
        "Read <object> into file <destination>",
        "" } ,
{ "remove",
        "attrtype=<attrtype> keytype=<keytype> cert=<serial,issuer> for=<serial,issuer> rev=<serial,issuer> replace=<TRUE/FALSE>", 
        "Remove security attribute from own directory entry",
        "" } ,
{ "rename",
        "<object> <newname>", 
        "Rename <object> to <newname>",
        "" } ,
{ "reseterror",
        "", 
        "free error stack",
        "" } ,
{ "retrieve",
        "dirname=<dirname> attrtype=<attrtype> keytype=<keytype> update=<TRUE/FALSE>", 
        "Retrieve security attribute from directory entry identified by <dirname>",
        "" } ,
{ "revoke",
        "",
        "Revoke one or more certificates",
        "" } ,
{ "setparm",
        "<algname>",
        "Set parameters of algorithm <algname>",
        "" } ,
{ "show",
        "<object or keyref>",
        "Show object or keyref in suitable form",
        "" } ,
{ "split",
        "for=<serial,issuer> rev=<serial,issuer>",
        "Split a Cross Certificate Pair into its components",
        "" } ,
{ "string2key", 
        "<string>", 
        "Generate DES key from string and store in object or under keyref",
        "" } ,
{ "toc",
        "", 
        "Show table of contents (toc) of PSE)", 
        "" } ,
#ifdef SCA
{ "toggle",
        "", 
        "Toggle verification/encryption tool from SC to SW and vice versa", 
        "" } ,
#endif
{ "verify",
        "certificate=<cert> fcpath=<fcpath> pkroot=<pkroot>",
        "Verify digital signatures",
        "" } ,
{ "write",
        "<object> <source>", 
        "Write object from file", 
        "" } ,
{ "xdump",
        "<object or keyref>", 
        "xdump object or keyref",
        "" } ,
{ CNULL }
};


int     cmd;
Boolean replace;
char    inp[256];
char    * cmdname, * helpname, * filename, * pin, * newpin, * algname, * objtype, * attrname;
CertificateType certtype;
KeyRef  keyref;
PSESel  std_pse;
Key     *key, *publickey, *secretkey;

extern CrlPSE *PemCrl2CrlPSE();


static ack();
static psesel();
static getsize();
static filen();
static keytype();
static printfile();
static new_pin();
static str2key();
static helpcmd();
static store_objpin();
static Key *build_key();
static char *getalgname();
static DName *getdname();
static Name *getname();
static Name *getalias();
static int getserial();
static char *getattrtype();
static Key *object();
static char *nxtpar();
static char *strmtch();
static int check_if_number();
static off_t fsize();
static CertificatePair * specify_CertificatePair();
static incorrectName();
static CertificatePair *compose_CertificatePair();

int             verbose = 0;
static void     usage();


time_t time();
char *sec_read_pin();
char *gets(), *getenv();
OctetString *aux_file2OctetString();
UTCTime *get_nextUpdate();
Boolean interactive = TRUE;
char *pname, *ppin;
int pkeyref;

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
	char			* proc = "main (psemaint)";
	char			* newstring;
	extern char		* optarg;
	extern int		  optind, opterr;
        int             	  fd1, fd2, fdin;
        int             	  i, anz, n, k, algtype, found;
        time_t          	  atime, etime;
	char	        	  opt, x500 = TRUE;
	char	        	  calogfile[256];
        Boolean         	  update, create, replace_afdb_cert;
        char            	* enc_file, *plain_file, *tbs_file, *sign_file, *hash_file;
        char            	* buf1, *buf2, *ii, *xx;
        char            	* par, *dd, *ptr, *cc, *afname, *newname, *attrtype, *number;
	char	        	* pgm_name = *parm;
	char            	* psename = CNULL, *psepath = CNULL, *cadir = CNULL, *home, * notbefore = CNULL, * notafter = CNULL;
        RC              	  rcode_dir, rcode_afdb, rcode;
        OctetString     	  octetstring, *ostr, *objectvalue, *tmp_ostr;
        ObjId    		  objecttype, object_oid, *oid;
	AlgId           	* algid;
        BitString       	  bitstring, *bstr;
        HashInput       	  hashinput;
        KeyInfo         	  tmpkey, * keyinfo, * signpk, * encpk;
        FCPath          	* fcpath;
        PKList          	* pklist;
        PKRoot          	* pkroot;
        Certificate     	* certificate;
        Certificates    	* certs;
	ToBeSigned 		* tbs;
        SET_OF_Certificate 	* certset, * soc, * tmp_soc;
	RevCertPem     		* revcertpem;
	CertificatePair 	* cpair;
	SET_OF_CertificatePair  * cpairset;
	PemCrlWithCerts         * pemcrlwithcerts;
	SET_OF_PemCrlWithCerts  * setofpemcrlwithcerts;
	SEQUENCE_OF_RevCertPem  * revcertpemseq;
	CrlPSE			* crlpse;
	CrlSet      		* crlset;
	SET_OF_int      	* tmp_intset;
	PemCrl			* pemcrl;
        Name            	* name, * alias, * issuer, * subject;
	DName			* dname, * issuer_dn = NULLDNAME, * subject_dn = NULLDNAME, * own_dname, * signsubject, * encsubject;
        EncryptedKey    	  encryptedkey;
        rsa_parm_type   	* rsaparm;
	KeyType         	  ktype;
        AlgEnc          	  algenc;
        PSESel          	* pse_sel;
	PSEToc          	* psetoc, * sctoc;
	struct PSE_Objects 	* pseobj;
	int 			  serial;
	SET_OF_IssuedCertificate *isscertset;
	SET_OF_Name		* nameset;
	SerialNumbers   	* serialnums;
	UTCTime 		* lastUpdate, * nextUpdate;
	AlgList         	* a;
	AlgId           	* algorithm = DEF_ISSUER_ALGID;
	Name			* printrepr;
	Boolean         	  onekeypaironly = FALSE;
	char			* outtext;
	char			  puff[1024];
	FILE		        * keyboard;
	AliasFile		  aliasfile;
	AliasList               * aliaslist;

#ifdef AFDBFILE
	char		 	  afdb[256];
#endif
#ifdef X500
	int 		  dsap_index;
	char		* callflag;
	char	        * env_auth_level;
#endif
	
	logfile = (FILE * )0;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;

	MF_check = FALSE;
	af_access_directory = FALSE;

#ifdef X500
	af_x500_count  = 1;	/* default, binding to local DSA */
	dsap_index = 4;
	callflag = "-call";
	auth_level = DBA_AUTH_SIMPLE;

	i = cnt+1;
	while (parm[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
	if(! af_x500_vecptr) {
		aux_add_error(EMALLOC, "af_x500_vecptr", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: ", parm[0]);
		fprintf(stderr, "Can't allocate memory\n");
		exit(1);
	}
#endif

#ifdef X500
	while ( (opt = getopt(cnt, parm, "a:i:c:p:y:d:f:l:A:htvCFRDTVW")) != -1 ) {
#else
	while ( (opt = getopt(cnt, parm, "a:i:c:p:y:f:l:htvCFRDTVW")) != -1 ) {
#endif
		switch(opt) {

		case 't':
			MF_check = TRUE;
			break;
		case 'y':
			sec_debug = atoi(optarg);
			break;
                case 'i':
                        if((fdin = open(optarg, O_RDONLY)) < 0) {
                                fprintf(stderr, "Can't open %s \n", optarg);
                                exit(1);
                        }
                        close(0);
                        dup(fdin);
                        close(fdin);
                        continue;
                case 'c':
                        cadir = optarg;
                        continue;
		case 'a':
                        oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(oid) != SIG) usage(SHORT_HELP);
			algorithm = aux_ObjId2AlgId(oid);
			continue;
		case 'f':
			if (notbefore) usage(SHORT_HELP);
			else notbefore = optarg;
			continue;
		case 'l':
			if (notafter) usage(SHORT_HELP);
			else notafter = optarg;
			continue;
                case 'R':
                        af_chk_crl = TRUE;
                        continue;
                case 'p':
                        psename = optarg;
                        continue;
                case 'F':
                        af_FCPath_is_trusted = TRUE;
                        continue;
#ifdef X500
		case 'A':
			if (! strcasecmp(optarg, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(optarg, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
			break;
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = parm[0];
			af_x500_vecptr[1] = (char *)malloc(strlen(callflag) + 1);
			if(! af_x500_vecptr[1]) {
				fprintf(stderr, "Can't allocate memory");
				if(verbose) aux_fprint_error(stderr, 0);
				exit(1);
			}
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] = (char *)malloc(strlen(optarg) + 1);
			if(! af_x500_vecptr[2]) {
				fprintf(stderr, "Can't allocate memory");
				if(verbose) aux_fprint_error(stderr, 0);
				exit(1);
			}
			strcpy(af_x500_vecptr[2], optarg);
			af_x500_vecptr[3] = (char *)0;
			i = cnt+1;
			dsap_index = 4;
			while (parm[i])
				af_x500_vecptr[dsap_index++] = parm[i++];
			continue;
#endif
		case 'D':
			af_access_directory = TRUE;
			continue;
#ifdef SCA
		case 'T':
			SC_verify = TRUE;
			SC_encrypt = TRUE;
			continue;
#endif
                case 'C':
                        strcpy(inp, "helpcmd");
                        continue;
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

	while (optind < cnt) {
                if(strlen(inp)) strcat(inp, " ");
                strcat(inp, parm[optind++]);
                interactive = FALSE;
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

        if(cadir) {
                psepath = (char *)malloc(strlen(cadir)+strlen(psename)+2);
		if( !psepath ) {
			fprintf(stderr, "Can't allocate memory");
			if(verbose) aux_fprint_error(stderr, 0);
			exit(1);
		}
                strcpy(psepath, cadir);
                if(psepath[strlen(psepath) - 1] != '/') strcat(psepath, "/");
                strcat(psepath, psename);
        }
        else {
                psepath = (char *)malloc(strlen(psename)+2);
		if( !psepath ) {
			fprintf(stderr, "Can't allocate memory");
			if(verbose) aux_fprint_error(stderr, 0);
			exit(1);
		}
                strcpy(psepath, psename);
        }

        if(strncmp(inp, "helpcmd", 4) == 0) {
                par = nxtpar(CNULL);
                helpcmd();
                exit(0);
        }

        ii = inp;

	if(cadir)
		ppin = getenv("CAPIN");
	else
		ppin = getenv("USERPIN");

	if ( aux_create_AFPSESel(psepath, ppin) < 0 ) {
		fprintf(stderr, "%s: ",parm[0]);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(1);
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

        if(strncmp(inp, "create", 5)) {
        	if(!(pse_sel = af_pse_open((ObjId *)0, FALSE))) {
			if (err_stack) {
				if (verbose) aux_fprint_error(stderr, 0);
				else aux_fprint_error(stderr, TRUE);
			}
			else	fprintf(stderr, "%s: unable to open PSE %s\n", cmd, AF_pse.app_name);
			exit(-1);
        	}

		if(af_check_if_onekeypaironly(&onekeypaironly)){
			if(verbose) aux_fprint_error(stderr, 0);
                        fprintf(stderr, "%s: unable to determine whether or not PSE shall hold one keypair only\n", parm[0]);
			exit(- 1);
		}

                aux_free_PSESel(&pse_sel);
        }

        std_pse.app_name = aux_cpy_String(AF_pse.app_name);
        std_pse.object.name = CNULL;
        std_pse.object.pin = aux_cpy_String(AF_pse.pin);
        std_pse.pin = aux_cpy_String(AF_pse.pin);
	std_pse.app_id = AF_pse.app_id;

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

        if(strlen(inp)) goto entr;

        while(1) {
                if(interactive == FALSE) {
			exit(rcode);
		}
                fprintf(stderr, "psemaint> ");
                std_pse.object.name = CNULL;
                if(!gets(inp)) exit(0);
entr:
                ii = inp;
                if(!(par = nxtpar(CNULL))) continue;

                anz = 0;
                for(i = 0; cmds[i].cmd; i++) {
                        if(!strncmp(cmds[i].cmd, par, strlen(par))) {
                                cmd = i;
                                cmdname = cmds[i].cmd;
                                anz++;
                        }
                }
		if(par) free(par);
                if(anz > 1) {
                        fprintf(stderr, "Ambiguous cmd\n");
                        rcode = 1;
                        continue;
                }
                if(anz == 0) {
                        fprintf(stderr, "unknown cmd\n");
                        rcode = 1;
                        continue;
                }

                rcode = 0;

                switch(cmd) {
			case ADDALIAS:
				name = getname();

				keyboard = fopen("/dev/tty", "r");
alias_again:			fprintf(stderr, "Enter alias name for <%s>: ", name);
				fgets(puff, sizeof(puff), keyboard);
				puff[strlen(puff) - 1] = '\0';             /* delete the CR which fgets provides */
				if(!strlen(puff)) goto alias_again;
				fclose(keyboard);
				dname = aux_Name2DName(name);

				fprintf(stderr, "USER/SYSTEM Alias Database ? [U/S] [CR for U]:  ");
				gets(inp);
                		if(!inp || strlen(inp) == 0)
                        		aliasfile = useralias;
				else {
					if (! strcasecmp(inp, "U"))
						aliasfile = useralias;
					else if (! strcasecmp(inp, "S"))
						aliasfile = systemalias;
					else {
						fprintf(stderr,"Answer must be either 'U' or 'S'\n");
						break;
					}
				}

				if(aux_add_alias(puff, dname, aliasfile, TRUE, TRUE) < 0) {
					fprintf(stderr, "Couldn't add alias\n");
					break;
				}

				keyboard = fopen("/dev/tty", "r");
				fprintf(stderr, "Enter mail address for <%s>, or CR only: ", name);
				fgets(puff, sizeof(puff), keyboard);
				puff[strlen(puff) - 1] = '\0';             /* delete the CR which fgets provides */
				fclose(keyboard);
				if(strlen(puff)) {
					if(aux_add_alias(puff, dname, aliasfile, TRUE, TRUE) < 0)
						fprintf(stderr, "Couldn't add alias\n");
				}
				break;
                        case ADDEK:
                                if(!(key = build_key("Certificate from object", 0))) {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                ostr = &octetstring;
                                if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
					fprintf(stderr,"Can't read from PSE\n");
					aux_free2_ObjId(&object_oid);
					aux_free_Key(&key);
					break;
				}
				aux_free2_ObjId(&object_oid);
                                if(!(certificate = d_Certificate(ostr))) {
					fprintf(stderr,"Can't decode Certificate\n");
					aux_free_Key(&key);
					free(ostr->octets);
					break;
				}
				free(ostr->octets);
				aux_free_Key(&key);
				rcode = af_pse_add_PK(ENCRYPTION, certificate->tbs);
				if(rcode < 0) fprintf(stderr, "Can't add cert to EKList\n");
				aux_free_Certificate(&certificate);
                                break;
                        case ADDPK:
                                if(!(key = build_key("Certificate from object", 0))) {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                ostr = &octetstring;
                                if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
					fprintf(stderr,"Can't read from PSE\n");
					aux_free2_ObjId(&object_oid);
					aux_free_Key(&key);
					break;
				}
				aux_free2_ObjId(&object_oid);
                                if(!(certificate = d_Certificate(ostr))) {
					fprintf(stderr,"Can't decode Certificate\n");
					aux_free_Key(&key);
					free(ostr->octets);
					break;
				}
				free(ostr->octets);
				aux_free_Key(&key);
				rcode = af_pse_add_PK(SIGNATURE, certificate->tbs);
				if(rcode < 0) fprintf(stderr, "Can't add cert to PKList\n");
				aux_free_Certificate(&certificate);
                                break;
                        case ALGS:
                                strrep(&algname, getalgname());
                                algtype = 0;
                                if(!strcmp(algname, "ASYM_ENC")) algtype = ASYM_ENC;
                                else if(!strcmp(algname, "SYM_ENC")) algtype = SYM_ENC;
                                else if(!strcmp(algname, "HASH")) algtype = HASH;
                                else if(!strcmp(algname, "SIG")) algtype = SIG;
                                else if(!strcmp(algname, "ENC")) algtype = ENC;
                                else if(!strcmp(algname, "ALL")) algtype = ALL;

                                for(i = 0; TRUE; i++) {
                                        if(!alglist[i].name) break;
                                        if(algtype == 0) {
                                                if(!strcmp(alglist[i].name, algname)) {
                                                        aux_fprint_AlgId(stderr, alglist[i].algid);
                                                }
                                        }
                                        else {
                                                if(algtype == ALL || 
                                                   ((algtype == ASYM_ENC || algtype == SYM_ENC || algtype == HASH || algtype == SIG) 
                                                     && algtype == alglist[i].algtype) ||
                                                   ((algtype == ENC) && (alglist[i].algtype == ASYM_ENC || alglist[i].algtype == SYM_ENC))) {
                                                        aux_fprint_AlgId(stderr, alglist[i].algid);
                                                }
                                        }
                                }
                                break;
                        case ALIAS2DNAME:
                                alias = (Name *)nxtpar("pattern");
                                aux_fprint_alias2dname(stderr, (char *)alias);
				if(alias) free(alias);
                                break;
#ifdef X500
			case AUTHNONE:
				auth_level = DBA_AUTH_NONE;
				break;
			case AUTHSIMPLE:
				auth_level = DBA_AUTH_SIMPLE;
				break;
#ifdef STRONG
			case AUTHSTRONG:
				auth_level = DBA_AUTH_STRONG;
				break;
#endif
#endif
			case CACERTIFICATE:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
                                if((dd = nxtpar(""))) {
					serial = atoi(dd);
					free(dd);
				}
                                else if((serial = getserial()) < 0){
					fprintf(stderr, "No serial number specified!\n");
					break;
				}
				certificate = af_cadb_get_Certificate(serial, cadir);
				if(certificate) aux_fprint_Certificate(stderr, certificate);
                                else fprintf(stderr, "No certificate issued with serialno %d\n", serial);
				aux_free_Certificate(&certificate);
				break;
			case CAPEMCRL:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				setofpemcrlwithcerts = af_cadb_list_PemCrlWithCerts(cadir);
                                fprintf(stderr, "The following PEM revocation lists, each accompanied by its issuer's certification path\n");
				fprintf(stderr, "(which is OPTIONAL), have been stored in your CA's local database:\n\n\n\n");
				aux_fprint_SET_OF_PemCrlWithCerts(stderr, setofpemcrlwithcerts);
				aux_free_SET_OF_PemCrlWithCerts(&setofpemcrlwithcerts);
				break;
			case CAPRINTLOG:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				if(*cadir != '/') {
					strcpy(calogfile, getenv("HOME"));
					strcat(calogfile, "/");
					strcat(calogfile, cadir);
				}
				else strcpy(calogfile, cadir);
				strcat(calogfile, "/");
				strcat(calogfile, "calog");
				logfile = fopen(calogfile, "r");
				if(logfile == (FILE * ) 0) {
					fprintf(stderr, "%s: Can't open %s\n", pgm_name, CALOG);
					break;
				}
				while ((n = getc(logfile)) != EOF) putchar(n);
				fclose(logfile);
				logfile = (FILE * )0;
				break;
			case CASERIALNUMBERS:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				name = getname();
                                if(!name) break;
				isscertset = af_cadb_get_user(name, cadir);
				if(isscertset) {
                                        fprintf(stderr, "Certificates issued for <%s>:\n", name);
                                        aux_fprint_SET_OF_IssuedCertificate(stderr, isscertset);
                                }
                                else fprintf(stderr, "No certificates issued for this user\n");
				break;
			case CAUSERS:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				nameset = af_cadb_list_user(cadir);
                                fprintf(stderr, "The following users are registered:\n");
				aux_fprint_SET_OF_Name(stderr, nameset);
				break;

			case CERTIFY:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
                                if(!(key = build_key("Certificate from", 0))) {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                ostr = &octetstring;
                                if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
					fprintf(stderr,"Can't read from PSE\n");
					aux_free_Key(&key);
					break;
				}
                                if(!(certificate = d_Certificate(ostr))) {
					fprintf(stderr,"Can't decode Certificate\n");
					aux_free_Key(&key);
					aux_free2_ObjId(&object_oid);
					free(ostr->octets);
					break;
				}
				aux_free2_ObjId(&object_oid);
				free(ostr->octets);
				aux_free_Key(&key);
                                if(!(key = build_key("Certified public key to", 1)))  {
					fprintf(stderr,"Can't build key\n");
					aux_free_Certificate(&certificate);
					break;
				}
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
					fprintf(stderr, "%s: Can't open %s\n", pgm_name, CALOG);
					break;
				}
				printrepr = aux_DName2Name(certificate->tbs->subject);
        			if(af_cadb_add_user(printrepr, cadir) < 0) {
                			LOGERR("can't access user db");
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "Can't access user db\n");
                			break;
        			}
				free(printrepr);
				if(certificate->tbs->issuer)
					aux_free_DName(&certificate->tbs->issuer);
				certificate->tbs->issuer = af_pse_get_Name();
				if (certificate->tbs->notbefore) {
					free(certificate->tbs->notbefore);
					certificate->tbs->notbefore = CNULL;
				}
				if (certificate->tbs->notafter) {
					free(certificate->tbs->notafter);
					certificate->tbs->notafter = CNULL;
				}
				if (! notbefore) {
					certificate->tbs->notbefore = aux_current_UTCTime();
					certificate->tbs->notafter = aux_delta_UTCTime(certificate->tbs->notbefore);
				}
				else {
					certificate->tbs->notbefore = (UTCTime *)malloc(TIMELEN);
					strcpy(certificate->tbs->notbefore, notbefore);
					free(notbefore);
					certificate->tbs->notafter = (UTCTime *)malloc(TIMELEN);
					strcpy(certificate->tbs->notafter, notafter);
					free(notafter);
				}
				certificate->tbs->serialnumber = af_pse_incr_serial();
				certificate->tbs->version = 0;           /* default version */
				if(certificate->tbs_DERcode)
					aux_free_OctetString(&certificate->tbs_DERcode);
				if (certificate->sig)
					aux_free_Signature(&certificate->sig);
				certificate->sig = (Signature * )malloc(sizeof(Signature));
 				if(! certificate->sig) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "Can't allocate memory\n");
					break;
				}
				certificate->sig->signAI = af_pse_get_signAI();
				if (! certificate->sig->signAI) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "Cannot determine the algorithm associated to your own secret signature key\n");
					break;
				}
				if (aux_ObjId2AlgType(certificate->sig->signAI->objid) == ASYM_ENC )
					certificate->sig->signAI = aux_cpy_AlgId(algorithm);
				certificate->tbs->signatureAI = aux_cpy_AlgId(certificate->sig->signAI);
				certificate->tbs_DERcode = e_ToBeSigned(certificate->tbs);
				if (!certificate->tbs_DERcode || (af_sign(certificate->tbs_DERcode, certificate->sig, END) < 0)) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "AF Error with CA Signature\n");
					LOGAFERR;
					break;
				}
				if (af_cadb_add_Certificate(0, certificate, cadir)) {
					LOGERR("Can't access cert db");
					break;
				}
                                if(key->pse_sel) {
                                        if(!(ostr = e_Certificate(certificate)))  {
						fprintf(stderr,"Can't encode new Certificate\n");
						aux_free_Certificate(&certificate);
						aux_free_Key(&key);
  						break;
					}
					aux_free_Certificate(&certificate);
					if(onekeypaironly == TRUE)
						oid = af_get_objoid(Cert_name);
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
                                        if(sec_write_PSE(key->pse_sel, oid, ostr) < 0)  {
						fprintf(stderr,"Can't write to PSE\n");
						aux_free_OctetString(&ostr);
						aux_free_Key(&key);
 						break;
					}
                                        fprintf(stderr, "New certificate stored in object %s\n", key->pse_sel->object.name);
					aux_free_OctetString(&ostr);
					aux_free_Key(&key);
                                }
				fclose(logfile);
				logfile = (FILE * )0;
				break;
                        case CERT2KEYINFO:
                                if(!(key = build_key("Certificate from ", 0))) {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                ostr = &octetstring;
                                if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
					fprintf(stderr,"Can't read from PSE\n");
					aux_free2_ObjId(&object_oid);
					aux_free_Key(&key);
					break;
				}
				aux_free2_ObjId(&object_oid);
                                if(!(certificate = d_Certificate(ostr))) {
					fprintf(stderr,"Can't decode Certificate\n");
					aux_free_Key(&key);
					free(ostr->octets);
					break;
				}
				free(ostr->octets);
				aux_free_Key(&key);
                                if(!(key = build_key("KeyInfo to ", 1)))  {
					fprintf(stderr,"Can't build key\n");
					aux_free_Certificate(&certificate);
					break;
				}
                                keyinfo = aux_cpy_KeyInfo(certificate->tbs->subjectPK);
				aux_free_Certificate(&certificate);
                                if(key->pse_sel) {
                                        if(!(ostr = e_KeyInfo(keyinfo)))  {
						fprintf(stderr,"Can't encode KeyInfo\n");
						aux_free_KeyInfo(&keyinfo);
						aux_free_Key(&key);
						break;
					}
					aux_free_KeyInfo(&keyinfo);
					if(onekeypaironly == TRUE){
                                        	if(sec_write_PSE(key->pse_sel, SKnew_OID, ostr) < 0)  {
							fprintf(stderr,"Can't write to PSE\n");
							aux_free_OctetString(&ostr);
							aux_free_Key(&key);
							break;
						}
					}
					else{
                                        	if(sec_write_PSE(key->pse_sel, SignSK_OID, ostr) < 0)  {
							fprintf(stderr,"Can't write to PSE\n");
							aux_free_OctetString(&ostr);
							aux_free_Key(&key);
							break;
						}
					}
					aux_free_OctetString(&ostr);
                                        fprintf(stderr, "Public Key stored in object %s\n", key->pse_sel->object.name);
					aux_free_Key(&key);
                                }
                                else {
                                        keyref = sec_put_key(keyinfo, key->keyref);
                                        fprintf(stderr, "Public Key stored under keyref %d\n", keyref);
					aux_free_KeyInfo(&keyinfo);
                                }
                                break;
                        case CERT2PKROOT:
                                if(!(key = build_key("Certificate from", 0))) {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                ostr = &octetstring;
                                if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
					fprintf(stderr,"Can't read from PSE\n");
					aux_free_Key(&key);
					break;
				}
                                if(!(certificate = d_Certificate(ostr))) {
					fprintf(stderr,"Can't decode Certificate\n");
					aux_free_Key(&key);
					aux_free2_ObjId(&object_oid);
					free(ostr->octets);
					break;
				}
				aux_free2_ObjId(&object_oid);
				free(ostr->octets);
				aux_free_Key(&key);
                                if(!(key = build_key("PKRoot to", 1)))  {
					fprintf(stderr,"Can't build key\n");
					aux_free_Certificate(&certificate);
					break;
				}
                                keyinfo = aux_cpy_KeyInfo(certificate->tbs->subjectPK);
                                pkroot = (PKRoot *)calloc(1, sizeof(PKRoot));
				if(!pkroot) {
					fprintf(stderr, "Can't allocate memory");
					aux_free_Key(&key);
					aux_free_KeyInfo(&keyinfo);
					aux_free_Certificate(&certificate);
	                                break;
				}
                                pkroot->ca = aux_cpy_DName(certificate->tbs->subject);
                                pkroot->newkey = (struct Serial *)calloc(1, sizeof(struct Serial));
				if(!pkroot->newkey) {
					fprintf(stderr, "Can't allocate memory");
					aux_free_PKRoot(&pkroot);
	                                break;
				}
                                pkroot->newkey->serial = 0;
				pkroot->newkey->version = certificate->tbs->version;
				pkroot->newkey->notbefore = aux_cpy_Name(certificate->tbs->notbefore);
				pkroot->newkey->notafter = aux_cpy_Name(certificate->tbs->notafter);
                                pkroot->newkey->key = aux_cpy_KeyInfo(keyinfo);

				if (cadir)
					pkroot->newkey->sig = aux_cpy_Signature(certificate->sig);
				else
					pkroot->newkey->sig = (Signature * )0;

				aux_free_KeyInfo(&keyinfo);
				aux_free_Certificate(&certificate);

                                if(key->pse_sel) {
                                        if(!(ostr = e_PKRoot(pkroot)))  {
						fprintf(stderr,"Can't encode PKRoot\n");
						aux_free_PKRoot(&pkroot);
						aux_free_Key(&key);
  						break;
					}
					aux_free_PKRoot(&pkroot);
                                        if(sec_write_PSE(key->pse_sel, PKRoot_OID, ostr) < 0)  {
						fprintf(stderr,"Can't write to PSE\n");
						aux_free_OctetString(&ostr);
						aux_free_Key(&key);
 						break;
					}
                                        fprintf(stderr, "PKRoot stored in object %s\n", key->pse_sel->object.name);
					aux_free_OctetString(&ostr);
					aux_free_Key(&key);
                                }
                                break;
                        case CHPIN:
chpin:
#ifdef SCA
                                if(sec_sctest(std_pse.app_name) == FALSE) {
	                                psesel(1);
		                        new_pin();
				}
				else std_pse.object.name = CNULL;
#else
                                psesel(1);
				new_pin();
#endif
				if(std_pse.object.name) {
					for (i = 0; i < PSE_MAXOBJ; i++) 
					       if (!strcmp(AF_pse.object[i].name, std_pse.object.name)) {
							if(std_pse.object.pin) strzfree(&(std_pse.object.pin));
							std_pse.object.pin = aux_cpy_String(AF_pse.object[i].pin);
							break;
                                               }
                                }
                                rcode = sec_chpin(&std_pse, newpin);
                                if (std_pse.object.name) {
					for (i = 0; i < PSE_MAXOBJ; i++) 
					        if (!strcmp(AF_pse.object[i].name, std_pse.object.name)) {
							if (AF_pse.object[i].pin) strzfree(&(AF_pse.object[i].pin));
							AF_pse.object[i].pin = newpin;
							break;
                                       	       }
				}
                                else {
					if(std_pse.pin) strzfree(&(std_pse.pin));
					std_pse.pin = newpin;
					if(AF_pse.pin) strzfree(&(AF_pse.pin));
					AF_pse.pin = aux_cpy_String(newpin);
				}
				break;
                        case CHALLPIN:
#ifdef SCA
                                if(sec_sctest(std_pse.app_name) == FALSE) new_pin();
				else goto chpin;
#else
				new_pin();
#endif
				psetoc = sec_read_toc(&std_pse);
				pseobj = (struct PSE_Objects *)0;
				while(psetoc || pseobj) {
				    if (pseobj) {
					std_pse.object.name = pseobj->name;
					pseobj = pseobj->next;
				    }
				    else {
					std_pse.object.name = CNULL;
					pseobj = psetoc->obj;
				    }
                                    rcode = sec_chpin(&std_pse, newpin);
                                    if(std_pse.object.name) std_pse.object.pin = newpin;
                                    else std_pse.pin = newpin;
				    if(!pseobj) break;
				}
                                break;
			case CHECK:
				secretkey = (Key *)malloc(sizeof(Key));
				if(!secretkey) {
					fprintf(stderr, "Can't malloc memory for secretkey\n");
					aux_free_KeyInfo(&signpk);
					aux_free_KeyInfo(&encpk);
					break;
				}
				secretkey->key = (KeyInfo *)0;
				secretkey->keyref = 0;
				secretkey->pse_sel = &std_pse;
				signpk = (KeyInfo *)0;
				encpk = (KeyInfo *)0;
				signsubject = NULLDNAME;
				encsubject = NULLDNAME;

				certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME);
				if(!certs) {
					if(onekeypaironly == TRUE){
						fprintf(stderr, "Can't get Certificates from PSE (Cert and/or FCPath missing\n");
						free(secretkey);
						break;
					}
					else{
						fprintf(stderr, "Can't get SIGNATURE Certificates from PSE (SignCert and/or FCPath missing\n");
						goto enccert;
					}
				}
				signpk = aux_cpy_KeyInfo(certs->usercertificate->tbs->subjectPK);
				secretkey->alg = signpk->subjectAI;
				signsubject = aux_cpy_DName(certs->usercertificate->tbs->subject);
				af_verbose = TRUE;
				if(onekeypaironly == TRUE)
					fprintf(stderr, "\nVerifying Cert with FCPath and PKRoot ... ");
				else
					fprintf(stderr, "\nVerifying SignCert with FCPath and PKRoot ... ");
                                rcode = af_verify_Certificates(certs, (UTCTime *)0, (PKRoot *)0);
				aux_free_Certificates(&certs);
				aux_fprint_VerificationResult(stderr, verifresult);
				aux_free_VerificationResult(&verifresult);
				if(rcode == 0) fprintf(stderr, "O.K.\n");
				else fprintf(stderr, "failed\n");
				if(onekeypaironly == TRUE)
					fprintf(stderr, "\nChecking whether the keys in Cert and SKnew are an RSA key pair ... ");
				else
					fprintf(stderr, "\nChecking whether the keys in SignCert and SignSK are an RSA key pair ... ");
				if(onekeypaironly == TRUE)
					std_pse.object.name = SKnew_name;
				else
					std_pse.object.name = SignSK_name;
				rcode = sec_checkSK(secretkey, signpk);
				if(rcode < 0){
					if(onekeypaironly == TRUE)
						fprintf(stderr, "\nRSA keys in SKnew and Cert do not fit\n");
					else
						fprintf(stderr, "\nRSA keys in SignSK and SignCert do not fit\n");
				}
				else fprintf(stderr, "O.K.\n");
				if(onekeypaironly == TRUE)
					break;
enccert:
				certs = af_pse_get_Certificates(ENCRYPTION, NULLDNAME);
				if(!certs) {
					fprintf(stderr, "Can't get ENCRYPTION Certificates from PSE (EncCert and/or FCPath missing)\n");
					if(signpk) aux_free_KeyInfo(&signpk);
					if(signsubject) aux_free_DName(&signsubject);
					free(secretkey);
					break;
				}
				encpk = aux_cpy_KeyInfo(certs->usercertificate->tbs->subjectPK);
				encsubject = aux_cpy_DName(certs->usercertificate->tbs->subject);
				if(signsubject) if(aux_cmp_DName(signsubject, encsubject)) {
					fprintf(stderr, "SignCert and EncCert have different subject names\n");
				}
				own_dname = af_pse_get_Name();
				if(!own_dname) fprintf(stderr, "Can't read Name from PSE\n");
				if(own_dname)  if(aux_cmp_DName(encsubject, own_dname)) {
					fprintf(stderr, "Distinguished name in Name is differnt to that of SignCert/EncCert\n");
				}
				if(own_dname) aux_free_DName(&own_dname);
				if(signsubject) aux_free_DName(&signsubject);
				aux_free_DName(&encsubject);
				fprintf(stderr, "\nVerifying EncCert with FCPath and PKRoot ...\n");
                                rcode = af_verify_Certificates(certs, (UTCTime *)0, (PKRoot *)0);
				aux_free_Certificates(&certs);
				aux_fprint_VerificationResult(stderr, verifresult);
				aux_free_VerificationResult(&verifresult);
				fprintf(stderr, "\nChecking whether the keys in EncCert and DecSKnew are an RSA key pair ... ");
				std_pse.object.name = DecSKnew_name;
				secretkey->alg = encpk->subjectAI;
				rcode = sec_checkSK(secretkey, encpk);
				if(rcode < 0) fprintf(stderr, "\nRSA keys in DecSKnew and EncCert do not fit\n");
				else fprintf(stderr, "O.K.\n");
				aux_free_KeyInfo(&signpk);
				aux_free_KeyInfo(&encpk);
				free(secretkey);
				break;

                        case CLOSE:	/* whole PSE to be closed */

				if(af_pse_close (NULLOBJID) == 0) ack(&std_pse, "closed");
				else fprintf(stderr, "No PSE open\n");
				if(std_pse.app_name) {
					free (std_pse.app_name);
					std_pse.app_name = CNULL;
				}
				if(std_pse.pin) strzfree (&(std_pse.pin));
				std_pse.app_id = 0;
				if ( std_pse.object.name ) {
					free (std_pse.object.name);
					std_pse.object.name = CNULL;
				}
				if(std_pse.object.pin) strzfree (&(std_pse.object.pin));
                                break;
                        case CREATE:
                                if(interactive == TRUE) psesel(1);
                                if(!(rcode = sec_create(&std_pse))) {
                                        ack(&std_pse, "created");
                                        if(!std_pse.object.name) {
                                                std_pse.object.name = aux_cpy_String(Name_name);
                                                std_pse.object.pin = aux_cpy_String(std_pse.pin);
                                                rcode = sec_create(&std_pse);
                                                if(rcode < 0) {
                                                        fprintf(stderr, "Can't create object %s on %s\n", std_pse.object.name, std_pse.app_name);
                                                        break;
                                                }
                                                fprintf(stderr, "Enter Subject Name of %s: ", std_pse.app_name);
						newstring = (char *)malloc(128);
						if( !newstring ) {
							fprintf(stderr, "Can't allocate memory");
                                                        break;
						}
                                                afname = gets(newstring);
						if(!(dname = aux_Name2DName(afname))) {
							free(newstring);
                                                        fprintf(stderr, "Can't build DN from %s\n", afname);
                                                        break;
                                                }
						free(newstring);
                                                if(!(ostr = e_DName(dname))) {
                                                        fprintf(stderr, "Can't encode Name %s\n", afname);
							aux_free_DName(&dname);
                                                        break;
                                                }
						aux_free_DName(&dname);
                                                rcode = sec_write_PSE(&std_pse, Name_OID, ostr);
						aux_free_OctetString(&ostr);
                                                if(rcode < 0) {
                                                        fprintf(stderr, "sec_write failed for %s\n", std_pse.object.name);
                                                        break;
                                                }
                                        }
                                        AF_pse.app_name = std_pse.app_name;
                                        AF_pse.pin = std_pse.pin;
                                        AF_pse.app_id = std_pse.app_id;
                                        if (std_pse.object.name) {
                                                for (i = 0; i < PSE_MAXOBJ; i++) 
							if (strcmp(AF_pse.object[i].name, std_pse.object.name) == 0) {
								if(std_pse.object.pin) {
									AF_pse.object[i].pin = (char *) malloc (strlen(std_pse.object.pin) + 1);
									if ( !AF_pse.object[i].pin ) {
										fprintf(stderr, "Can't allocate memory");
										break;
									}
									strcpy (AF_pse.object[i].pin, std_pse.object.pin);
								}
								else AF_pse.object[i].pin = (char *)0;
                                                        	break;
                                                        }  
                                        }
                                } 
				else {
					fprintf(stderr, "Can't create object\n");
                                        break;
                                }

                                break;
			case DELALIAS:
				alias = getalias();
				if(!alias){
					fprintf(stderr, "No alias name specified!\n");
					break;
				}
				fprintf(stderr, "USER/SYSTEM Alias Database ? [U/S] [CR for U]:  ");
				gets(inp);
                		if(!inp || strlen(inp) == 0)
                        		aliasfile = useralias;
				else {
					if (! strcasecmp(inp, "U"))
						aliasfile = useralias;
					else if (! strcasecmp(inp, "S"))
						aliasfile = systemalias;
					else {
						fprintf(stderr,"Answer must be either 'U' or 'S'\n");
						break;
					}
				}
				if(aux_delete_alias(alias, aliasfile, TRUE) < 0) {
					fprintf(stderr, "Could not remove alias\n");
					break;
				}
				break;
			case DELEK:
				subject_dn = getdname("Owner");
				if(! subject_dn){
					issuer_dn = getdname("Issuer");
					if(! issuer_dn){
						fprintf(stderr, "Neither Owner nor Issuer has been specified!\n");
						break;
					}
					if ((serial = getserial()) < 0) {
						fprintf(stderr, "No serial number specified!\n");
						break;
					}
				}
				if(subject_dn){
					subject = aux_DName2Name(subject_dn);
					if(! subject){
						fprintf(stderr, "Cannot transform DName-structure into Name!\n");
						break;
					}
					rcode = af_pse_delete_PK(ENCRYPTION, subject_dn, NULLDNAME, 0);
				}
				else{
					issuer = aux_DName2Name(issuer_dn);
					if(! issuer){
						fprintf(stderr, "Cannot transform DName-structure into Name!\n");
						break;
					}
					rcode = af_pse_delete_PK(ENCRYPTION, NULLDNAME, issuer_dn, serial);
				}
				if ( rcode < 0 ) {
					if (err_stack && (err_stack->e_number == EOBJNAME)) {
		        			fprintf(stderr, "\nThere is no ToBeSigned with\n");
						if (issuer_dn && serial>=0) {
		        				fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       					fprintf(stderr, " serial number %d\n", serial);
						}
						else
			        			fprintf(stderr, " owner \"%s\"\n", subject);

						fprintf(stderr, "stored in your EKList. No update done!\n");
					}
				}
				else {
					fprintf(stderr, "\nToBeSigned with\n");
					if (issuer_dn && serial>=0) {
		        			fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       				fprintf(stderr, " serial number %d\n", serial);
					}
					else
						fprintf(stderr, " owner \"%s\"\n", subject);

					fprintf(stderr, "removed from your EKList.\n");

					fprintf(stderr, "\nYour updated EKList now looks like this:\n\n");
					pklist = af_pse_get_PKList(ENCRYPTION);
					if ( !pklist )
						fprintf(stderr, "Your EKList is EMPTY!\n");
					else {
						fprintf(stderr, " ****************** EKList ******************\n");
						aux_fprint_PKList (stderr, pklist);
						aux_free_PKList(& pklist);				
					}
				}
				if(subject_dn) aux_free_DName(& subject_dn);
				if(issuer_dn) aux_free_DName(& issuer_dn);
				if(subject) free(subject);
				if(issuer) free(issuer);
				break;
                        case DELETE:
                                psesel(1);
                                if(!std_pse.object.name || !strlen(std_pse.object.name)) {
                                        fprintf(stderr, "Do you really want to delete %s ? [yes/no]: ", std_pse.app_name);
                                        gets(inp);
                                        if(strcmp(inp, "yes")) {
                                                fprintf(stderr, "%s not deleted\n", std_pse.app_name);
                                                break;
                                        }
                                }
                                if(!(rcode = sec_delete(&std_pse))) ack(&std_pse, "deleted");
                                else ack(&std_pse, "does not exist");
                                break;
                        case DELKEY:
                                if(!(key = build_key("", 1)))  {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                if(!(rcode = sec_del_key(key->keyref))) {
					outtext = "";
#ifdef SCA
					if ((key->keyref & SC_KEY) == SC_KEY) {
						key->keyref =  key->keyref & ~SC_KEY;
						outtext = "in the smartcard";
						
					} 
					else if ((key->keyref & SCT_KEY) == SCT_KEY) {
						outtext = "in the SCT";
						key->keyref = key->keyref & ~SCT_KEY;
					}
					
#endif
					fprintf(stderr, "Key %s under keyref %d deleted\n", outtext, key->keyref);
				}
				else {
					if (err_stack) {
						if (!verbose) aux_fprint_error(stderr, TRUE);
					}
					else	fprintf(stderr, "%s: unable to delete key with keyref %d\n", cmd, key->keyref);
				}

				aux_free_Key(&key);
                                break;
 			case DELPEMCRL:
 				issuer_dn = getdname("Issuer");
 				if(! issuer_dn){
 					fprintf(stderr, "No issuer specified!\n");
 					break;
 				}
 				issuer = aux_DName2Name(issuer_dn);
 				if(! issuer){
 					fprintf(stderr, "Cannot transform DName-structure into Name!\n");
 					break;
 				}
 				rcode = af_pse_delete_PemCRL(issuer_dn);
 				if ( rcode < 0 ) {
 					if (err_stack && (err_stack->e_number == EOBJNAME)) {
 		        			fprintf(stderr, "\nThere is no revocation list with ");
 		        			fprintf(stderr, "issuer \"%s\"\n", issuer);
 						fprintf(stderr, "stored in your PSE. No update done!\n");
 					}
 				}
 				else {
 					fprintf(stderr, "\nRevocation list issued by \"%s\" ", issuer);
 					fprintf(stderr, "removed from your PSE.\n\n");
 
 					fprintf(stderr, "Your updated set of locally stored revocation lists "); 
 					fprintf(stderr, "now looks like this:\n\n");
 					crlset = af_pse_get_CrlSet();
 					if (! crlset )
 						fprintf(stderr, "            E  M  P  T  Y  !\n\n");
 					else {
 						fprintf(stderr, " ****************** Set of Locally Stored Revocation Lists ******************\n");
 						aux_fprint_CrlSet (stderr, crlset);
 						aux_free_CrlSet(&crlset);				
 					}
 				}
 				if(issuer_dn) aux_free_DName(& issuer_dn);
 				if(issuer) free(issuer);
 				break;
			case DELPK:
				subject_dn = getdname("Owner");
				if(! subject_dn){
					issuer_dn = getdname("Issuer");
					if(! issuer_dn){
						fprintf(stderr, "Neither Owner nor Issuer has been specified!\n");
						break;
					}
					if ((serial = getserial()) < 0) {
						fprintf(stderr, "No serial number specified!\n");
						break;
					}
				}
				if(subject_dn){
					subject = aux_DName2Name(subject_dn);
					if(! subject){
						fprintf(stderr, "Cannot transform DName-structure into Name!\n");
						break;
					}
					rcode = af_pse_delete_PK(SIGNATURE, subject_dn, NULLDNAME, 0);
				}
				else{
					issuer = aux_DName2Name(issuer_dn);
					if(! issuer){
						fprintf(stderr, "Cannot transform DName-structure into Name!\n");
						break;
					}
					rcode = af_pse_delete_PK(SIGNATURE, NULLDNAME, issuer_dn, serial);
				}
				if ( rcode < 0 ) {
					if (err_stack && (err_stack->e_number == EOBJNAME)) {
		        			fprintf(stderr, "\nThere is no ToBeSigned with\n");
						if (issuer_dn && serial>=0) {
		        				fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       					fprintf(stderr, " serial number %d\n", serial);
						}
						else
			        			fprintf(stderr, " owner \"%s\"\n", subject);

						fprintf(stderr, "stored in your PKList. No update done!\n");
					}
				}
				else {
					fprintf(stderr, "\nToBeSigned with\n");
					if (issuer_dn && serial>=0) {
		        			fprintf(stderr, " issuer \"%s\" and\n", issuer);
		       				fprintf(stderr, " serial number %d\n", serial);
					}
					else
						fprintf(stderr, " owner \"%s\"\n", subject);

					fprintf(stderr, "removed from your PKList.\n");

					fprintf(stderr, "\nYour updated PKList now looks like this:\n\n");
					pklist = af_pse_get_PKList(SIGNATURE);
					if ( !pklist )
						fprintf(stderr, "Your PKList is EMPTY!\n");
					else {
						fprintf(stderr, " ****************** PKList ******************\n");
						aux_fprint_PKList(stderr, pklist);
						aux_free_PKList(& pklist);				
					}
				}
				if(subject_dn) aux_free_DName(&subject_dn);
				if(issuer_dn) aux_free_DName(&issuer_dn);
				if(subject) free(subject);
				if(issuer) free(issuer);
				break;
                        case DNAME2ALIAS:
                                name = (Name *)nxtpar("pattern");
                                aux_fprint_dname2alias(stderr, (char *)name);
				if(name) free(name);
                                break;
#ifdef SCA
                        case EJECT:
                                if(dd = nxtpar("")) {
					n = atoi(dd);
					free(dd);
				}
                                else n = 0;
                                sec_sc_eject(ALL_SCTS);
                                break;
#endif
			case ENTER:
				if (af_access_directory == FALSE) {
					fprintf(stderr, "af_access_directory is set to FALSE!\n");
					fprintf(stderr, "If you want to access the Directory, you should invoke ");
					fprintf(stderr, "the 'psemaint' command with the -D option.\n");
					break;
				}
				if(!af_x500 && !af_afdb){
					fprintf(stderr, "No directory flags (AFDBFILE or X500) have been compiled.\n");
					fprintf(stderr, "Therfore, no directory access is provided.\n");
					break;
				}
				attrtype = getattrtype(x500);
				if (!strncasecmp(attrtype, "Certificate", 2) || !strncasecmp(attrtype, "UserCertificate", 1) || !strncasecmp(attrtype, "CACertificate", 2)){
#ifdef X500
					if (x500) {
						if(!strncasecmp(attrtype, "UserCertificate", 1)) 
							certtype = userCertificate;
                                       	        else certtype = cACertificate;
					}
#endif
#ifdef AFDBFILE
					if(onekeypaironly == TRUE){
						std_pse.object.name = Cert_name;
						ktype = SIGNATURE;  /* ktype is not relevant in this case, but should have an acceptable value */
					}
					else{
                                        	keytype();
                                        	if(*objtype == 'S') {
							std_pse.object.name = SignCert_name;
							ktype = SIGNATURE;
						}
                                        	else if(*objtype == 'E') {
							std_pse.object.name = EncCert_name;
							ktype = ENCRYPTION;
						}
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
#endif
					fprintf(stderr, "\nEnter name of PSE object which contains ");
					fprintf(stderr, "certificate\n");
					fprintf(stderr, " to be entered into the directory:\n");
					i = psesel(2);
                               		if(i < 0)  {
						fprintf(stderr,"psesel failed\n");
						break;
					}
					ostr = &octetstring;
                                	if(sec_read_PSE(&std_pse, &object_oid, ostr) < 0)  {
						fprintf(stderr,"Can't read from PSE\n");
						break;
					}
					store_objpin();
                                	if(! aux_cmp_ObjId(&object_oid, SignCert_OID) || ! aux_cmp_ObjId(&object_oid, EncCert_OID) || ! aux_cmp_ObjId(&object_oid, Cert_OID)) { 
						if(!(certificate = d_Certificate(ostr))) {
                                        		fprintf(stderr, "Can't decode %s\n", std_pse.object.name);
                                        		free(ostr->octets);
 							aux_free2_ObjId(&object_oid);
                                      			break;
					        }
					aux_free2_ObjId(&object_oid);
					free(ostr->octets);	
                                        }
				}
				else if (!strncasecmp(attrtype,"CrossCertificatePair", 2)) {
					if(!cadir) {
						fprintf(stderr, "%s: CrossCertificatePairs are for CAs only\n", pgm_name);
						break;
					}	
					cpair = compose_CertificatePair();
					if (!cpair) {
						fprintf(stderr, "%s: No CrossCertificatePair specified\n", pgm_name);
						break;
					}
				}
				else {
					if(!cadir) {
						fprintf(stderr, "%s: Revocation lists are for CAs only\n", pgm_name);
						break;
					}
					dname = af_pse_get_Name();
					name = aux_DName2Name(dname);
					aux_free_DName(&dname);
					pemcrlwithcerts = af_cadb_get_PemCrlWithCerts(name, cadir);
					if(! pemcrlwithcerts || ! pemcrlwithcerts->pemcrl){
						fprintf(stderr, "WARNING: Your own PemCrl is NOT stored in your local database!\n");
						break;
					}
					fprintf(stderr, "\nThis is your locally stored revocation list:\n\n");
					aux_fprint_PemCrl(stderr, pemcrlwithcerts->pemcrl);
					fprintf(stderr, "\n\nVerifying your locally stored PemCrl ...\n\n");
					certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME); 
					rcode = af_verify(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END, certs, (UTCTime * )0, (PKRoot * )0);
					aux_free_Certificates(&certs);
					aux_fprint_VerificationResult(stderr, verifresult);
					aux_free_VerificationResult(&verifresult);
					if (rcode == 0) {
						fprintf(stderr, "Verification of locally stored ");
						fprintf(stderr, "PemCrl s u c c e e d e d!\n\n");
					}
					else {
						fprintf(stderr, "WARNING: Verification of locally ");
						fprintf(stderr, "stored PemCrl f a i l e d!\n");
						break;
					}
				}
#ifdef AFDBFILE
				if ((dd = nxtpar("replace"))) {
					if (!strcmp(dd,"TRUE")) replace_afdb_cert = TRUE;
					else if (!strcmp(dd,"FALSE")) replace_afdb_cert = FALSE;
					else {
						fprintf(stderr, "Update must be either 'TRUE' or 'FALSE'\n");
						break;
					}
				}
				else replace_afdb_cert = FALSE;
#endif
				if (!strncasecmp(attrtype, "Certificate", 2) || !strncasecmp(attrtype, "UserCertificate", 1) || !strncasecmp(attrtype, "CACertificate", 2)) {
#ifdef X500
					if ( x500 ) {
						fprintf(stderr, "\nAccessing your X.500 directory entry ...\n\n");
						if ( af_dir_enter_Certificate(certificate, certtype) == 0 )
							fprintf(stderr, "Directory entry (X.500) succeeded.\n");
                               			else fprintf(stderr, "Directory entry (X.500) f a i l e d.\n");
					}
#endif
#ifdef AFDBFILE
					fprintf(stderr, "\nAccessing your .af-db directory entry ...\n\n");
					if(replace_afdb_cert == TRUE){
						if(onekeypaironly == TRUE)
							fprintf(stderr, "An existing certificate will be replaced.\n\n");
						else{
							if(ktype == SIGNATURE)
								fprintf(stderr, "An existing SIGNATURE certificate will be replaced.\n\n");
							else 
								fprintf(stderr, "An existing ENCRYPTION certificate will be replaced.\n\n");
						}
					}
					if ( af_afdb_enter_Certificate(certificate, ktype, replace_afdb_cert) == 0 )
						fprintf(stderr, "Directory entry (.af-db) succeeded.\n");
                               		else fprintf(stderr, "Directory entry (.af-db) f a i l e d.\n");
#endif
					aux_free_Certificate(&certificate);
				}
				else if (!strncasecmp(attrtype,"CrossCertificatePair", 2)) {
#ifdef X500
					if ( x500 ) {
						fprintf(stderr, "\nAccessing your X.500 directory entry ...\n\n");
						if ( af_dir_enter_CertificatePair(cpair,directory_user_dname) == 0 )
							fprintf(stderr, "Directory entry (X.500) succeeded.\n");
                               			else fprintf(stderr, "Directory entry (X.500) f a i l e d.\n");
					}
#endif
#ifdef AFDBFILE
					own_dname = af_pse_get_Name();
					fprintf(stderr, "\nAccessing your .af-db directory entry ...\n\n");
					if ( af_afdb_enter_CertificatePair(cpair,own_dname) == 0 )
						fprintf(stderr, "Directory entry (.af-db) succeeded.\n");
                               		else fprintf(stderr, "Directory entry (.af-db) f a i l e d.\n");
#endif
					aux_free_CertificatePair(&cpair);
				}
				else {   /* attrtype = PemCertificateRevocationList */
#ifdef X500
					if ( x500 ) {
						fprintf(stderr, "\nAccessing your X.500 directory entry ...\n\n");
						if ( af_dir_enter_PemCrl(pemcrlwithcerts->pemcrl) == 0 )
							fprintf(stderr, "Directory entry (X.500) succeeded.\n");
                               			else fprintf(stderr, "Directory entry (X.500) f a i l e d.\n");
					}
#endif
#ifdef AFDBFILE
					fprintf(stderr, "\nAccessing your .af-db directory entry ...\n\n");
					if ( af_afdb_enter_PemCrl(pemcrlwithcerts->pemcrl) == 0 )
						fprintf(stderr, "Directory entry (.af-db) succeeded.\n");
                               		else fprintf(stderr, "Directory entry (.af-db) f a i l e d.\n");
#endif
					aux_free_PemCrlWithCerts(&pemcrlwithcerts);
				}
                                break;
                        case EXIT:
                        case ENDE:
                        case QUIT:
                                exit(0);
                        case GENKEY:
                                replace = FALSE;
                                strrep(&algname, getalgname());
                                algenc = aux_Name2AlgEnc(algname);
                                if(algenc == DES || algenc == DES3) {
					if(!(secretkey = build_key("generated DES ", 1))) break;
				}
                                else {
					publickey = (Key *)0;
					secretkey = (Key *)0;
                                        if(!(publickey = build_key("generated public ", 1))) break;
                                        if(!(secretkey = build_key("generated secret ", 1))) break;
                                }
                                time(&atime);

				sec_verbose = TRUE;
                                if((rcode = sec_gen_key(secretkey, replace)) < 0)  {
					fprintf(stderr, err_stack->e_text);
					fprintf(stderr, "\n");
					sec_verbose = FALSE;
					break;
				}

				sec_verbose = FALSE;
                                etime = time((time_t *)0) - atime;
                                if(algenc == RSA || algenc == DSA) fprintf(stderr, "Secret Key stored ");
                                else fprintf(stderr, "DES Key stored ");
                                if (secretkey->pse_sel) 
					fprintf(stderr, " in object %s\n", secretkey->pse_sel->object.name);
                                else {
					outtext = "";

#ifdef SCA
					if ((secretkey->keyref & SC_KEY) == SC_KEY) {
						secretkey->keyref =  secretkey->keyref & ~SC_KEY;
						outtext = "in the smartcard";
						
					} 
					else if ((secretkey->keyref & SCT_KEY) == SCT_KEY) {
						outtext = "in the SCT";
						secretkey->keyref = secretkey->keyref & ~SCT_KEY;
					}
					
#endif
					fprintf(stderr, "%s under keyref %d \n", outtext, secretkey->keyref);

				}
                                if(algenc == RSA || algenc == DSA) {
					if(algenc == RSA) oid = RSA_PK_OID;
					else oid = DSA_PK_OID;
                                        /* store public key */
                                        if(publickey->pse_sel) {
                                                if(!(ostr = e_KeyInfo(secretkey->key)))  {
							fprintf(stderr,"Can't encode KeyInfo\n");
							aux_free_Key(&secretkey);
							aux_free_Key(&publickey);
							break;
						}
						aux_free_Key(&secretkey);
                                                if(sec_write_PSE(publickey->pse_sel, oid, ostr) < 0)  {
                                                        fprintf(stderr, "sec_write failed\n");
							aux_free_OctetString(&ostr);
							aux_free_Key(&publickey);
                                                        break;
                                                }
						aux_free_OctetString(&ostr);
                                                fprintf(stderr, "Public Key stored in object %s\n", publickey->pse_sel->object.name);
                                        }
                                        else {
                                                keyref = sec_put_key(secretkey->key, publickey->keyref);
                                                fprintf(stderr, "Public Key stored under keyref %d\n", keyref);
						aux_free_Key(&secretkey);
                                        }
					aux_free_Key(&publickey);
                                }
                                fprintf(stderr, "Time for key generation: %ld sec\n", etime);
                                break;
                        case HELPCMD:
                        case QM:
                                helpcmd();
                                break;
			case INITPEMCRL:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				pemcrl = (PemCrl * )malloc(sizeof(PemCrl));
				if (! pemcrl) {
					fprintf(stderr, "%s: ", pgm_name);
  	        			fprintf(stderr, "Can't allocate memory\n");
					break;
				}

				pemcrl->tbs = (PemCrlTBS * )malloc(sizeof(PemCrlTBS));
				if (! pemcrl->tbs) {
					fprintf(stderr, "%s: ", pgm_name);
  	        			fprintf(stderr, "Can't allocate memory\n");
					break;
				}

				if (!(pemcrl->tbs->issuer = af_pse_get_Name())) {
					break;
				}

				pemcrl->tbs->lastUpdate = aux_current_UTCTime();
				pemcrl->tbs->nextUpdate = (UTCTime *)0;
				pemcrl->tbs->nextUpdate = get_nextUpdate(pemcrl->tbs->lastUpdate);

				pemcrl->tbs->revokedCertificates = (SEQUENCE_OF_RevCertPem * )0;

				pemcrl->sig = (Signature * )malloc(sizeof(Signature));
				if (! pemcrl->sig) {
					fprintf(stderr, "%s: ", pgm_name);
  	        			fprintf(stderr, "Can't allocate memory\n");
					break;
				}
				pemcrl->sig->signature.nbits = 0;
				pemcrl->sig->signature.bits = CNULL;

				pemcrl->sig->signAI = af_pse_get_signAI();
				if ( aux_ObjId2AlgType(pemcrl->sig->signAI->objid) == ASYM_ENC )
					pemcrl->sig->signAI = aux_cpy_AlgId(algorithm);

				pemcrl->tbs->signatureAI = aux_cpy_AlgId(pemcrl->sig->signAI);

				if ((pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrl->tbs)) == NULLOCTETSTRING) {
					fprintf(stderr, "%s: ", pgm_name);
  	        			fprintf(stderr, "e_PemCrlTBS failed\n");
					break;
				}

				if ((pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrl->tbs)) == NULLOCTETSTRING) {
					fprintf(stderr, "Can't encode pemcrl->tbs\n");
					break;
				}

				fprintf(stderr, "\nThe following Crl is to be signed. ");
				fprintf(stderr, "Please check it:\n\n");
				aux_fprint_PemCrlTBS(stderr, pemcrl->tbs);
				fprintf(stderr, "\nDo you want to sign the displayed ");
				fprintf(stderr, "revocation list (PEM) ?\n");
				fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");
				af_pse_close(NULLOBJID);
				if ( af_sign(pemcrl->tbs_DERcode, pemcrl->sig, END) < 0 ) {
					fprintf(stderr, "Signature of revocation list failed\n");
					break;
				}

				/* Update on Directory entry, PSE, and CA directory: */
#ifdef X500
				if ( x500 ) {
					fprintf(stderr, "\n**********************************************\n");
					/* update X.500 directory entry */
					fprintf(stderr, "\nTrying to update your X.500 directory entry ...");
					if ( af_dir_enter_PemCrl(pemcrl) < 0 ) 
						fprintf(stderr, "\n Directory entry (X.500) f a i l e d !\n");
					else fprintf(stderr, "\n Done!\n");
					fprintf(stderr, "\n**********************************************\n");
				}
#endif
#ifdef AFDBFILE
				fprintf(stderr, "\n**********************************************\n");
				/* update .af-db directory entry */
				fprintf(stderr, "\nTrying to update your .af-db directory entry ...");
				if ( af_afdb_enter_PemCrl(pemcrl) < 0 ) 
					fprintf(stderr, "\n Directory entry (.af-db) f a i l e d !\n");
				else fprintf(stderr, "\n Done!\n");
				fprintf(stderr, "\n**********************************************\n");
#endif

				/* update PSE object CrlSet, even if the directory entry failed */
				crlpse = PemCrl2CrlPSE (pemcrl);
				fprintf(stderr, "\nUpdating PSE object CrlSet ...\n");
				rcode = af_pse_add_PemCRL(crlpse);
				if (rcode != 0) {
					fprintf(stderr, "\n Cannot update PSE object CrlSet.\n");
					aux_free_CrlPSE (&crlpse);
				}
				else fprintf(stderr, "\n Done!\n");
				aux_free_CrlPSE (&crlpse);
				fprintf(stderr, "\n**********************************************\n");

				/* update 'pemcrlwithcerts' database in CA directory, even if the directory entry failed */
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
					fprintf(stderr, "%s: Can't open %s\n", pgm_name, CALOG);
					break;
				}
				pemcrlwithcerts = (PemCrlWithCerts * )malloc(sizeof(PemCrlWithCerts));
				pemcrlwithcerts->pemcrl = pemcrl;
				pemcrlwithcerts->certificates = (Certificates * )0;
				rcode = af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir);
				if(rcode != 0){
					fprintf(stderr, "%s: ",cmd);
					fprintf(stderr, "Cannot store your updated PemCrl in your 'pemcrlwithcerts' database!\n");
					if(verbose) aux_fprint_error(stderr, 0);
					aux_free_PemCrlWithCerts(&pemcrlwithcerts);
					break;
				}
				fprintf(stderr, "\nMost current version of PemCrl stored in 'pemcrlwithcerts' database in ");
				fprintf(stderr, "CA directory \"%s\".\n\n", cadir);
				aux_free_PemCrlWithCerts(&pemcrlwithcerts);
				fclose(logfile);
				logfile = (FILE * )0;
				break;
                        case KEYTOC:
                                rcode = sec_print_toc(stderr, (PSESel *)0);
				if(rcode < 0) fprintf(stderr, "Can't read TOC of key_pool\n");
                                break;
			case MFLIST:
				MF_fprint(stderr);
				break;
                        case OPEN:
                                if (psesel(1) < 0)  {
                                        fprintf(stderr, "psesel failed \n");
                                        break;
                                }

                                AF_pse.app_id = std_pse.app_id;
				strrep(&(AF_pse.app_name), std_pse.app_name);
				if(AF_pse.pin) strzfree(&(AF_pse.pin));
                                if(std_pse.pin) strzfree(&(std_pse.pin));

                                pse_sel = af_pse_open((ObjId *)0, FALSE);
				if ( ! pse_sel ) {
                                	fprintf(stderr, "af_pse_open failed\n");
                                	break;
                                }
				ack(pse_sel, "opened");
				aux_free_PSESel(& pse_sel);
				strrep(&(std_pse.pin), AF_pse.pin);

				if(AF_pse.pin) {
					for(i = 0; i < PSE_MAXOBJ; i++) {
						strrep(&(AF_pse.object[i].pin), AF_pse.pin);
						if(!AF_pse.object[i].pin) {
							fprintf(stderr, "Can't allocate memory\n");
							exit(1);
						}
					}
				}
				else {
					for (i = 0; i < PSE_MAXOBJ; i++) 
						if(AF_pse.object[i].pin) strzfree(&(AF_pse.object[i].pin)); 
				}
                                break;
			case PROLONG:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				dname = af_pse_get_Name();
				name = aux_DName2Name(dname);
				aux_free_DName(&dname);
				pemcrlwithcerts = af_cadb_get_PemCrlWithCerts(name, cadir);
				if(! pemcrlwithcerts || ! pemcrlwithcerts->pemcrl){
					fprintf(stderr, "WARNING: Your own PemCrl is NOT stored in your local database!\n");
					break;
				}
				fprintf(stderr, "\nThis is your locally stored revocation list:\n\n");
				aux_fprint_PemCrl(stderr, pemcrlwithcerts->pemcrl);
				fprintf(stderr, "\n\nVerifying your locally stored PemCrl ...\n\n");
				certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME); 
				rcode = af_verify(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END, certs, (UTCTime * )0, (PKRoot * )0);
				aux_free_Certificates(&certs);
				aux_fprint_VerificationResult(stderr, verifresult);
				aux_free_VerificationResult(&verifresult);
				if (rcode == 0) {
					fprintf(stderr, "Verification of locally stored ");
					fprintf(stderr, "PemCrl s u c c e e d e d!\n\n");
				}
				else {
					fprintf(stderr, "WARNING: Verification of locally ");
					fprintf(stderr, "stored PemCrl f a i l e d!\n");
					break;
				}
				pemcrlwithcerts->pemcrl->tbs->lastUpdate = aux_current_UTCTime();
				pemcrlwithcerts->pemcrl->tbs->nextUpdate = (UTCTime *)0;
				pemcrlwithcerts->pemcrl->tbs->nextUpdate = get_nextUpdate(pemcrlwithcerts->pemcrl->tbs->lastUpdate);
				if ((pemcrlwithcerts->pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrlwithcerts->pemcrl->tbs)) == NULLOCTETSTRING) {
					fprintf(stderr, "Can't encode pemcrlwithcerts->pemcrl->tbs\n");
					break;
				}

				fprintf(stderr, "\nThe following Crl is to be signed. ");
				fprintf(stderr, "Please check it:\n\n");
				aux_fprint_PemCrlTBS(stderr, pemcrlwithcerts->pemcrl->tbs);
				fprintf(stderr, "\nDo you want to sign the displayed ");
				fprintf(stderr, "revocation list (PEM) ?\n");
				fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");
				af_pse_close(NULLOBJID);
				if ( af_sign(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END) < 0 ) {
					fprintf(stderr, "Signature of revocation list failed\n");
					break;
				}

				/* Update on Directory entry, PSE, and CA directory: */
#ifdef X500
				if (x500 && af_access_directory == TRUE) {
					fprintf(stderr, "\n**********************************************\n");
					/* update X.500 directory entry */
					fprintf(stderr, "\nTrying to update your X.500 directory entry ...");
					if ( af_dir_enter_PemCrl(pemcrlwithcerts->pemcrl) < 0 ) 
						fprintf(stderr, "\n Directory entry (X.500) f a i l e d !\n");
					else fprintf(stderr, "\n Done!\n");
					fprintf(stderr, "\n**********************************************\n");
				}
#endif
#ifdef AFDBFILE
				if (af_access_directory == TRUE) {
					fprintf(stderr, "\n**********************************************\n");
					/* update .af-db directory entry */
					fprintf(stderr, "\nTrying to update your .af-db directory entry ...");
					if ( af_afdb_enter_PemCrl(pemcrlwithcerts->pemcrl) < 0 ) 
						fprintf(stderr, "\n Directory entry (.af-db) f a i l e d !\n");
					else fprintf(stderr, "\n Done!\n");
					fprintf(stderr, "\n**********************************************\n");
				}
#endif

				/* update PSE object CrlSet, even if the directory entry failed */
				crlpse = PemCrl2CrlPSE (pemcrlwithcerts->pemcrl);
				fprintf(stderr, "\nUpdating PSE object CrlSet ...\n");
				rcode = af_pse_add_PemCRL(crlpse);
				if (rcode != 0) {
					fprintf(stderr, "\n Cannot update PSE object CrlSet.\n");
					aux_free_CrlPSE (&crlpse);
				}
				else fprintf(stderr, "\n Done!\n");
				aux_free_CrlPSE (&crlpse);
				fprintf(stderr, "\n**********************************************\n");

				/* update 'pemcrlwithcerts' database in CA directory, even if the directory entry failed */
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
					fprintf(stderr, "%s: Can't open %s\n", pgm_name, CALOG);
					break;
				}
				rcode = af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir);
				if(rcode != 0){
					fprintf(stderr, "%s: ",cmd);
					fprintf(stderr, "Cannot store your updated PemCrl in your 'pemcrlwithcerts' database!\n");
					if(verbose) aux_fprint_error(stderr, 0);
					aux_free_PemCrlWithCerts(&pemcrlwithcerts);
					break;
				}
				fprintf(stderr, "\nMost current version of PemCrl stored in 'pemcrlwithcerts' database in ");
				fprintf(stderr, "CA directory \"%s\".\n\n", cadir);
				aux_free_PemCrlWithCerts(&pemcrlwithcerts);
				fclose(logfile);
				logfile = (FILE * )0;
				break;
			case PROTOTYPE:
				certificate = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0);
				if(! certificate){
					fprintf(stderr,"Can't read own certificate from PSE\n");
					break;
				}
                                if(!(key = build_key("Self-signed prototype certificate to", 1)))  {
					fprintf(stderr,"Can't build key\n");
					aux_free_Certificate(&certificate);
					break;
				}
				aux_free_DName(&certificate->tbs->issuer);
				certificate->tbs->issuer = af_pse_get_Name();
				if (certificate->tbs->notbefore) {
					free(certificate->tbs->notbefore);
					certificate->tbs->notbefore = CNULL;
				}
				if (certificate->tbs->notafter) {
					free(certificate->tbs->notafter);
					certificate->tbs->notafter = CNULL;
				}
				if (! notbefore) {
					certificate->tbs->notbefore = aux_current_UTCTime();
					certificate->tbs->notafter = aux_delta_UTCTime(certificate->tbs->notbefore);
				}
				else {
					certificate->tbs->notbefore = (UTCTime *)malloc(TIMELEN);
					strcpy(certificate->tbs->notbefore, notbefore);
					free(notbefore);
					certificate->tbs->notafter = (UTCTime *)malloc(TIMELEN);
					strcpy(certificate->tbs->notafter, notafter);
					free(notafter);
				}
				certificate->tbs->serialnumber = 0;
				certificate->tbs->version = 0;           /* default version */
				aux_free_OctetString(&certificate->tbs_DERcode);
				aux_free_Signature(&certificate->sig);
				certificate->sig = (Signature * )malloc(sizeof(Signature));
 				if(! certificate->sig) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "Can't allocate memory\n");
					break;
				}
				certificate->sig->signAI = af_pse_get_signAI();
				if (! certificate->sig->signAI) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "Cannot determine the algorithm associated to your own secret signature key\n");
					break;
				}
				if (aux_ObjId2AlgType(certificate->sig->signAI->objid) == ASYM_ENC )
					certificate->sig->signAI = aux_cpy_AlgId(algorithm);
				certificate->tbs->signatureAI = aux_cpy_AlgId(certificate->sig->signAI);
				certificate->tbs_DERcode = e_ToBeSigned(certificate->tbs);
				if (! certificate->tbs_DERcode || (af_sign(certificate->tbs_DERcode, certificate->sig, END) < 0)) {
					fprintf(stderr, "%s: ",pgm_name);
                			fprintf(stderr, "AF Error with CA Signature\n");
					LOGAFERR;
					break;
				}
                                if(key->pse_sel) {
                                        if(!(ostr = e_Certificate(certificate)))  {
						fprintf(stderr,"Can't encode new Certificate\n");
						aux_free_Certificate(&certificate);
						aux_free_Key(&key);
  						break;
					}
					aux_free_Certificate(&certificate);
					if(onekeypaironly == TRUE)
						oid = af_get_objoid(Cert_name);
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
                                        if(sec_write_PSE(key->pse_sel, oid, ostr) < 0)  {
						fprintf(stderr,"Can't write to PSE\n");
						aux_free_OctetString(&ostr);
						aux_free_Key(&key);
 						break;
					}
                                        fprintf(stderr, "Self-signed prototype-certificate stored in object %s\n", key->pse_sel->object.name);
					aux_free_OctetString(&ostr);
					aux_free_Key(&key);
                                }
				break;
                        case READ:
                                psesel(2);
                                filen();
                                ostr = &octetstring;
                                if((rcode = sec_read_PSE(&std_pse, &objecttype, ostr)) == 0) {
					store_objpin();
					if (aux_cmp_ObjId(&objecttype, Uid_OID) == 0) {
						tmp_ostr = aux_cpy_OctetString(ostr);
						ostr = d_OctetString(tmp_ostr);
						aux_free_OctetString(&tmp_ostr);
					}
                                        printfile(ostr, filename);
                                        free(ostr->octets);
                                } 
				else   {
					fprintf(stderr,"Can't read from PSE\n");
					break;
				}

                                break;
			case REMOVE:
				if (af_access_directory == FALSE) {
					fprintf(stderr, "af_access_directory is set to FALSE!\n");
					fprintf(stderr, "If you want to access the Directory, you should invoke ");
					fprintf(stderr, "the 'psemaint' command with the -D option.\n");
					break;
				}
				if(!af_x500 && !af_afdb){
					fprintf(stderr, "No directory flags (AFDBFILE or X500) have been compiled.\n");
					fprintf(stderr, "Therfore, no directory access is provided.\n");
					break;
				}
				attrtype = getattrtype(x500);
				if (!strncasecmp(attrtype, "Certificate", 2) || !strncasecmp(attrtype, "UserCertificate", 1) || !strncasecmp(attrtype, "CACertificate", 2)){
#ifdef X500
					if(x500){
						if (!(dd = nxtpar("cert"))) {
							       fprintf(stderr, "Serial number:  ");
							newstring = (char *)malloc(16);
							if( !newstring ) {
								fprintf(stderr, "Can't allocate memory");
								break;
							}
							       number = gets(newstring);
							       if(strlen(number) == 0) {
								fprintf(stderr, "No serial number specified!\n");
								break;
							}
							if(check_if_number(number) < 0) break;
							serial = atoi(number);
							if(serial < 0){
								fprintf(stderr, "Serial number must be equal to or greater than 0!\n");
								break;
							}
							issuer_dn = getdname("Issuer");
							if(!issuer_dn) break;
						}
						else {
							if (!strchr( dd, ',' )) {
								serial = atoi(dd);
								issuer_dn = NULLDNAME;
							}
							else {
								ptr = strchr(dd, ',');
								*ptr = '\0';
								ptr++;
								if(check_if_number(dd) < 0) break;
								serial = atoi(dd);
								if(serial < 0){
									fprintf(stderr, "Serial number must be equal to or greater than 0!\n");
									break;
								}
								dd = ptr;
								issuer_dn = aux_alias2DName(dd);
								if (!issuer_dn) {
									fprintf(stderr, "Cannot transform alias <%s> into a Distinguished Name!\n", dd);
									if(dd){
										free(dd);
										dd = CNULL;
									}
									break;
								}
							}
						}
						if(!strncasecmp(attrtype, "UserCertificate", 1)) 
							certtype = userCertificate;
						else
							certtype = cACertificate;
	
						if ( af_dir_delete_Certificate(serial, issuer_dn, certtype)  == 0 )
							fprintf(stderr, "\nDirectory operation (X.500) succeeded.\n");
						       else {
							fprintf(stderr, "\nDirectory operation (X.500) f a i l e d.\n");
							if (verbose) aux_fprint_error(stderr, 0);
						}
					}
#endif
#ifdef AFDBFILE
					if(onekeypaironly == TRUE)
						ktype = SIGNATURE;  /* ktype is not relevant in this case, but should have an acceptable value */
					else{
                                        	keytype();
                                        	if(*objtype == 'S') 
							ktype = SIGNATURE;
                                        	else if (*objtype == 'E') 
							ktype = ENCRYPTION;
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
					own_dname = af_pse_get_Name();
					if ( af_afdb_delete_Certificate(own_dname, ktype) == 0 )
						fprintf(stderr, "\nDirectory operation (.af-db) succeeded.\n");
                               		else {
						fprintf(stderr, "\nDirectory operation (.af-db) f a i l e d.\n");
						if (verbose) aux_fprint_error(stderr, 0);
					}
#endif
				}
				else {    /* attrtype = CrossCertificatePair */
					cpair = specify_CertificatePair();
					if (! cpair) {
						if(verbose) aux_fprint_error(stderr, 0);
                               			fprintf(stderr, "%s: unable to create Cross Certificate Pair\n", parm[0]);
                 				break;
					}
					if (! cpair->forward && ! cpair->reverse) {
						fprintf(stderr, "At least one component (forward or reverse) must be present.\n");
						aux_free_CertificatePair(&cpair);
						break;
					}
#ifdef X500
					if ( x500 ) {
						if ( af_dir_delete_CertificatePair(cpair) == 0 )
							fprintf(stderr, "\nDirectory operation (X.500) succeeded.\n");
                               			else {
							fprintf(stderr, "\nDirectory operation (X.500) f a i l e d.\n");
							if (verbose) aux_fprint_error(stderr, 0);
						}
					}
#endif
#ifdef AFDBFILE 	
					own_dname = af_pse_get_Name();
					if ( af_afdb_delete_CertificatePair(own_dname, cpair) == 0 )
						fprintf(stderr, "\nDirectory operation (.af-db) succeeded.\n");
                               		else {
						fprintf(stderr, "\nDirectory operation (.af-db) f a i l e d.\n");
						if (verbose) aux_fprint_error(stderr, 0);
					}
#endif
					aux_free_CertificatePair(&cpair);
				}
				break;
                        case RENAME:
                                psesel(2);
                                if(!(newname = nxtpar("newname"))) {
                                        while(!newname) {
                                                fprintf(stderr, "Enter new name of object on %s: ", std_pse.app_name);
                                                newname = gets((char *)malloc(128));
						if( !newname ) {
							fprintf(stderr, "Can't allocate memory");
							break;
						}
                                                if(strlen(newname) == 0) {
                                                        free(newname);
                                                        newname = CNULL;
                                                }
                                        }
                                }
				if(newname) {
                                	if((rcode = sec_rename(&std_pse, newname)) < 0) {
						fprintf(stderr, "Can't rename %s\n", std_pse.object.name);
                                        	break;
                                	}
					free(newname);
				}
                                break;
			case RETRIEVE:
				if (af_access_directory == FALSE) {
					fprintf(stderr, "af_access_directory is set to FALSE!\n");
					fprintf(stderr, "If you want to access the Directory, you should invoke ");
					fprintf(stderr, "the 'psemaint' command with the -D option.\n");
					break;
				}
				if(!af_x500 && !af_afdb){
					fprintf(stderr, "No directory flags (AFDBFILE or X500) have been compiled.\n");
					fprintf(stderr, "Therfore, no directory access is provided.\n");
					break;
				}
				dname = getdname(CNULL);
				if(!dname) break;
				if ((dd = nxtpar("update"))) {
					if (!strcmp(dd,"TRUE")) update = TRUE;
					else if (!strcmp(dd,"FALSE")) update = FALSE;
					else {
						fprintf(stderr, "Update must be either 'TRUE' or 'FALSE'\n");
						break;
					}
				}
				else update = FALSE;
				attrtype = getattrtype(x500);
				if (!strncasecmp(attrtype, "Certificate", 2) || !strncasecmp(attrtype, "UserCertificate", 1) || !strncasecmp(attrtype, "CACertificate", 2)){
#ifdef X500
					if ( x500 ) {
						if(!strncasecmp(attrtype, "UserCertificate", 1)) 
							certtype = userCertificate;
                                        	else
							certtype = cACertificate;

						fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" ...\n", aux_DName2Name(dname));
						certset = af_dir_retrieve_Certificate(dname,certtype);
					}
#endif
#ifdef AFDBFILE	
					if (!x500 || !af_x500) {
						keytype();
						if(*objtype == 'S') ktype = SIGNATURE;
						else if(*objtype == 'E') ktype = ENCRYPTION;
						else {
							fprintf(stderr, "Type must me either 'S' or 'E'\n");
							break;
						}
						fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" ...\n", aux_DName2Name(dname));			
						certset = af_afdb_retrieve_Certificate(dname,ktype);
					}
#endif
					aux_fprint_CertificateSet(stderr, certset);
					if(!certset) {
						fprintf(stderr, "No certificates returned from Directory.\n");
						break;
					}

					if (update == FALSE) break;

					if (certset->next) {
						fprintf(stderr, "\nSpecify the certificate (within the returned");
						fprintf(stderr, " SET_OF_Certificate) whose DER-code is needed:\n");
						if ((serial = getserial()) < 0) {
							fprintf(stderr, "No serial number specified!\n");
							break;
						}

						/* examine if there is more than one certificate with 
					           the specified serial number: */

						soc = (SET_OF_Certificate *)0;
						while (certset) {
							if (certset->element->tbs->serialnumber == serial) {
								if (!soc) {
									soc = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
									tmp_soc = soc;
								}
								else {
									tmp_soc->next = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
									tmp_soc = tmp_soc->next;
								}
								tmp_soc->element = certset->element;
								tmp_soc->next = (SET_OF_Certificate *)0;	
							}			
							certset = certset->next;
						}
			
						if (!soc) {
							fprintf(stderr,"No such serial number!\n");
							break;
						}

						if (soc->next) { /*more than one certificate with 
							                  specified serial number*/
							issuer_dn = getdname("Issuer");
							if(!issuer_dn) break;
							found = 0;
							while ( soc && !found ) {
								if (!aux_cmp_DName(soc->element->tbs->issuer,issuer_dn)) {
									found = 1;
									certificate = aux_cpy_Certificate(soc->element);
									break;
								}
								soc = soc->next;
							}
							if ( !found ) {
								fprintf(stderr, "The specified certificate does not exist ");
								fprintf(stderr, "in the returned SET_OF_Certificate !\n");
								break;
							}
						}
						else certificate = soc->element;	
					}
					else certificate = certset->element;

					fprintf(stderr,"\nWhere shall the specified certificate be stored?\n");
					psesel(2);

					if(onekeypaironly == TRUE){
						oid = af_get_objoid(Cert_name);
					}
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}

					ostr = e_Certificate(certificate);
					if (!ostr) {
						fprintf(stderr,"Can't encode specified certificate\n");
						break;
					}
                               		rcode = 0;
                                	if(sec_open(&std_pse) < 0) rcode = sec_create(&std_pse);
                                	if(!rcode) {
						rcode = sec_write_PSE(&std_pse, oid, ostr);
                       	                	if(rcode) {
							fprintf(stderr,"Can't write to PSE\n");
							break;
						}
					} 
					else {
						fprintf(stderr,"Can't create PSE\n");
						break;
					}
					fprintf(stderr, "Specified certificate stored in object <%s> on PSE.\n", std_pse.object.name);
                                	aux_free_OctetString(&ostr);
				}
				else if (!strncasecmp(attrtype,"CrossCertificatePair", 2)) {
#ifdef X500
					if ( x500 ) {
						fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" ...\n", aux_DName2Name(dname));
						cpairset = af_dir_retrieve_CertificatePair(dname);
					}
#endif
#ifdef AFDBFILE
					if (!x500 || !af_x500) {
						fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" ...\n", aux_DName2Name(dname));
						cpairset = af_afdb_retrieve_CertificatePair(dname);
					}
#endif
					aux_fprint_CertificatePairSet(stderr, cpairset);
					if(! cpairset) {
						fprintf(stderr, "No SET OF Cross Certificate Pairs returned from Directory.\n");
						break;
					}

					if (update == TRUE) {
						rcode = 0;
						rcode = af_pse_add_CertificatePairSet(cpairset);
						if (!rcode)
							fprintf(stderr, "\nUpdate done on object CrossCSet.\n");
						else
							fprintf(stderr, "\nNo update done on object CrossCSet.\n");
					}
				}
				else {
#ifdef X500
					if ( x500 ) {
						fprintf(stderr, "\nAccessing the X.500 directory entry of \"%s\" ...\n", aux_DName2Name(dname));
						pemcrl = af_dir_retrieve_PemCrl(dname);
					}
#endif
#ifdef AFDBFILE
					if (!x500 || !af_x500) {
						fprintf(stderr, "\nAccessing the .af-db directory entry of \"%s\" ...\n", aux_DName2Name(dname));
						pemcrl = af_afdb_retrieve_PemCrl(dname);
					}
#endif
					fprintf(stderr, "\n");
					aux_fprint_PemCrl(stderr, pemcrl);
					if(! pemcrl) {
						fprintf(stderr, "No PEM revocation list returned from Directory.\n");
						break;
					}
				}
				if (strncasecmp(attrtype,"PemCertificateRevocationList", 1)) break;

				/* Verifying the returned revocation list: */

				fprintf(stderr, "\nVerifying the returned revocation list ...\n\n");

				own_dname = af_pse_get_Name();
				if (!aux_cmp_DName(dname, own_dname)) {
					certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME);
					rcode = af_verify(pemcrl->tbs_DERcode, pemcrl->sig, END, certs, (UTCTime * )0, (PKRoot * )0);
					aux_free_Certificates(&certs);
					aux_fprint_VerificationResult(stderr, verifresult);
					aux_free_VerificationResult(&verifresult);
				}
				else {
					if ( !(tbs = af_pse_get_TBS(SIGNATURE, dname, NULLDNAME, 0))) {
#ifdef X500
						if(x500) {
 							if(!(certset = af_dir_retrieve_Certificate(dname, cACertificate)) ) {
								fprintf(stderr, "Verification f a i l e d\n");
                        	                    	        break;
							}
						}
#endif
#ifdef AFDBFILE
						if(!x500 || !af_x500) {
							ktype = SIGNATURE;
	 						if(!(certset = af_afdb_retrieve_Certificate(dname,ktype)) ) {
								fprintf(stderr, "Verification f a i l e d\n");
	                                             	        break;
							}
						}
#endif
					}
  
					pkroot = (PKRoot *)malloc(sizeof(PKRoot));
					if( !pkroot ) {
						fprintf(stderr, "Can't allocate memory");
						break;
					}
					pkroot->oldkey = (struct Serial *)0;
					pkroot->newkey = (struct Serial *)malloc(sizeof(struct Serial));

					if (tbs) {
						pkroot->ca = aux_cpy_DName(tbs->subject);
						pkroot->newkey->key = aux_cpy_KeyInfo(tbs->subjectPK);
						pkroot->newkey->serial = tbs->serialnumber;
						rcode = af_verify(pemcrl->tbs_DERcode, pemcrl->sig, END, (Certificates *)0, (UTCTime * )0, pkroot);
						aux_free_PKRoot(&pkroot);
						aux_fprint_VerificationResult(stderr, verifresult);
						aux_free_VerificationResult(&verifresult);
						if (rcode == 0) fprintf(stderr, "Verification s u c c e e d e d\n");
						else{
							fprintf(stderr, "Verification f a i l e d\n");
							break;
						}
					}
					else {		
						while (certset) {
							/* compare, if ENCRYPTION or SIGNATURE object identifier: */
							algtype = aux_ObjId2AlgType(certset->element->tbs->subjectPK->subjectAI->objid);
							if ((algtype == SIG) || (algtype == ASYM_ENC)){
								pkroot->ca = aux_cpy_DName(certset->element->tbs->subject);
								pkroot->newkey->key = aux_cpy_KeyInfo(certset->element->tbs->subjectPK);
								pkroot->newkey->serial = certset->element->tbs->serialnumber;
								rcode = af_verify(pemcrl->tbs_DERcode, pemcrl->sig, END, (Certificates *)0, (UTCTime * )0, pkroot);
								aux_fprint_VerificationResult(stderr, verifresult);
								aux_free_VerificationResult(&verifresult);
								if (rcode == 0){
									fprintf(stderr, "Verification s u c c e e d e d\n");
									aux_free_PKRoot(&pkroot);
									break;
								}
								aux_free_DName(&pkroot->ca);
								aux_free_KeyInfo(&pkroot->newkey->key);
							};
							certset = certset->next;
						} /*while*/
						if (! certset) {
							fprintf(stderr, "Verification f a i l e d\n");
                                               		break;
						}
					}
				}
				if (update == TRUE) {
					crlpse = PemCrl2CrlPSE(pemcrl);
					rcode = af_pse_add_PemCRL(crlpse);
					if (rcode == 0)
						fprintf(stderr, "\nInstallation of revocation list on PSE s u c c e e d e d\n");
					else {
						fprintf(stderr, "\nInstallation of revocation list on PSE f a i l e d\n");
					}
				}
				break;	
			case REVOKE:
				if(!cadir) {
					fprintf(stderr, "%s: This command is for CAs only\n", pgm_name);
					break;
				}
				dname = af_pse_get_Name();
				name = aux_DName2Name(dname);
				aux_free_DName(&dname);
				pemcrlwithcerts = af_cadb_get_PemCrlWithCerts(name, cadir);
				if(! pemcrlwithcerts || ! pemcrlwithcerts->pemcrl){
					fprintf(stderr, "WARNING: Your own PemCrl is NOT stored in your local database!\n");
					break;
				}
				fprintf(stderr, "\nThis is your locally stored revocation list:\n\n");
				aux_fprint_PemCrl(stderr, pemcrlwithcerts->pemcrl);
				fprintf(stderr, "\n\nVerifying your locally stored PemCrl ...\n\n");
				certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME); 
				rcode = af_verify(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END, certs, (UTCTime * )0, (PKRoot * )0);
				aux_free_Certificates(&certs);
				aux_fprint_VerificationResult(stderr, verifresult);
				aux_free_VerificationResult(&verifresult);
				if (rcode == 0) {
					fprintf(stderr, "Verification of locally stored ");
					fprintf(stderr, "PemCrl s u c c e e d e d!\n\n");
				}
				else {
					fprintf(stderr, "WARNING: Verification of locally ");
					fprintf(stderr, "stored PemCrl f a i l e d!\n");
					break;
				}
				xx = "y";
				update = 0;
				while (strcmp(xx, "n")) {
					free (xx);
					xx = CNULL;
					fprintf(stderr, "\nEnter serial number of certificate which ");
					fprintf(stderr, "is to be revoked:\n");
					serial = getserial();
					i = 0;
					while ((serial < 0) && (i < 3)) {
						fprintf(stderr, "Serial number must be a positive integer!\n");
						serial = getserial();
						i++;
					}
					if (i == 3) break;
					certificate = af_cadb_get_Certificate(serial, cadir);
					if (!certificate) {
						fprintf(stderr, "\nNo certificate with serial ");
						fprintf(stderr, "number %d in CA database!\n", serial);
						fprintf(stderr, "\nNew choice? [y/n]: ");
					}
					else {	
						revcertpem = af_create_RevCertPem(serial);
						if (!af_search_RevCertPem(pemcrlwithcerts->pemcrl, revcertpem)) { 
							fprintf(stderr, "\nThe following certificate with serial number ");
							fprintf(stderr, "%d is being revoked:\n\n", serial);
							aux_fprint_Certificate(stderr, certificate);
							revcertpemseq = (SEQUENCE_OF_RevCertPem * )malloc(sizeof(SEQUENCE_OF_RevCertPem));
							if (!revcertpemseq) {
								fprintf(stderr, "Can't allocate memory");
								aux_free_RevCertPem(&revcertpem);
								aux_free_PemCrlWithCerts(&pemcrlwithcerts);
								break;
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
							fprintf(stderr, "\nCertificate with serial ");
							fprintf(stderr, "number %d ", serial);
							fprintf(stderr, "already revoked !\n");
							fprintf(stderr, "\nNew choice? [y/n]: ");
						}
					}
					gets(inp);
					xx = inp;
					while ( strcmp(xx, "y") && strcmp(xx, "n") ) {
						fprintf(stderr, "\nAnswer must be 'y' or 'n' !\n\n");
						fprintf(stderr, "\nNew choice? [y/n]: ");
						gets(inp);
						xx = inp;
					}
				}  /*while*/
		
				if (!update) {
					fprintf(stderr, "No update done on revocation list!\n");
					aux_free_PemCrlWithCerts(&pemcrlwithcerts);
					break;
				}

				if (create == FALSE) {
					pemcrlwithcerts->pemcrl->tbs->lastUpdate = aux_current_UTCTime();
					pemcrlwithcerts->pemcrl->tbs->nextUpdate = (UTCTime *)0;
					pemcrlwithcerts->pemcrl->tbs->nextUpdate = get_nextUpdate(pemcrlwithcerts->pemcrl->tbs->lastUpdate);
				}

				if ((pemcrlwithcerts->pemcrl->tbs_DERcode = e_PemCrlTBS(pemcrlwithcerts->pemcrl->tbs)) == NULLOCTETSTRING) {
					fprintf(stderr, "Can't encode pemcrlwithcerts->pemcrl->tbs\n");
					break;
				}

				fprintf(stderr, "\nThe following Crl is to be signed. ");
				fprintf(stderr, "Please check it:\n\n");
				aux_fprint_PemCrlTBS(stderr, pemcrlwithcerts->pemcrl->tbs);
				fprintf(stderr, "\nDo you want to sign the displayed ");
				fprintf(stderr, "revocation list (PEM) ?\n");
				fprintf(stderr, "If you want to sign it, (re)enter the PIN of your chipcard:\n\n");
				af_pse_close(NULLOBJID);
				if ( af_sign(pemcrlwithcerts->pemcrl->tbs_DERcode, pemcrlwithcerts->pemcrl->sig, END) < 0 ) {
					fprintf(stderr, "Signature of revocation list failed\n");
					break;
				}

				/* Update on Directory entry, PSE, and CA directory: */
#ifdef X500
				if (x500 && af_access_directory == TRUE) {
					fprintf(stderr, "\n**********************************************\n");
					/* update X.500 directory entry */
					fprintf(stderr, "\nTrying to update your X.500 directory entry ...");
					if ( af_dir_enter_PemCrl(pemcrlwithcerts->pemcrl) < 0 ) 
						fprintf(stderr, "\n Directory entry (X.500) f a i l e d !\n");
					else fprintf(stderr, "\n Done!\n");
					fprintf(stderr, "\n**********************************************\n");
				}
#endif
#ifdef AFDBFILE
				if (af_access_directory == TRUE) {
					fprintf(stderr, "\n**********************************************\n");
					/* update .af-db directory entry */
					fprintf(stderr, "\nTrying to update your .af-db directory entry ...");
					if ( af_afdb_enter_PemCrl(pemcrlwithcerts->pemcrl) < 0 ) 
						fprintf(stderr, "\n Directory entry (.af-db) f a i l e d !\n");
					else fprintf(stderr, "\n Done!\n");
					fprintf(stderr, "\n**********************************************\n");
				}
#endif

				/* update PSE object CrlSet, even if the directory entry failed */
				crlpse = PemCrl2CrlPSE (pemcrlwithcerts->pemcrl);
				fprintf(stderr, "\nUpdating PSE object CrlSet ...\n");
				rcode = af_pse_add_PemCRL(crlpse);
				if (rcode != 0) {
					fprintf(stderr, "\n Cannot update PSE object CrlSet.\n");
					aux_free_CrlPSE (&crlpse);
				}
				else fprintf(stderr, "\n Done!\n");
				aux_free_CrlPSE (&crlpse);
				fprintf(stderr, "\n**********************************************\n");

				/* update 'pemcrlwithcerts' database in CA directory, even if the directory entry failed */
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
					fprintf(stderr, "%s: Can't open %s\n", pgm_name, CALOG);
					break;
				}
				rcode = af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir);
				if(rcode != 0){
					fprintf(stderr, "%s: ",cmd);
					fprintf(stderr, "Cannot store your updated PemCrl in your 'pemcrlwithcerts' database!\n");
					if(verbose) aux_fprint_error(stderr, 0);
					aux_free_PemCrlWithCerts(&pemcrlwithcerts);
					break;
				}
				fprintf(stderr, "\nMost current version of PemCrl stored in 'pemcrlwithcerts' database in ");
				fprintf(stderr, "CA directory \"%s\".\n\n", cadir);
				aux_free_PemCrlWithCerts(&pemcrlwithcerts);
				fclose(logfile);
				logfile = (FILE * )0;
				break;
                        case SETPARM:
				a = alglist;
				algid = (AlgId *)0;
                                strrep(&algname, getalgname());
				while (a->name) {
					if (strcmp(algname, a->name) == 0) {
						algid = a->algid;
						break;
					}
					a++;
				}

                                if(algid) switch(aux_Name2ParmType(algname)) {
                                        case PARM_INTEGER:
                                                rsaparm = (rsa_parm_type *)(algid->parm);
                                                *rsaparm = getsize("keysize");
                                                break;
                                        case PARM_OctetString:
                                                filen();
                                                if(filename) ostr = aux_file2OctetString(filename);
                                                if(ostr) algid->parm = (char *)ostr;
                                                break;
					default:
						if(aux_Name2AlgEnc(algname) == DSA) sec_dsa_keysize = getsize("keysize");
						else fprintf(stderr, "algorithm has no parameter\n");
                                }
                                break;
                        case SHOW:
                                if(!(key = build_key("", 0))) break;
                                print_keyinfo_flag = ALGID;
                                print_cert_flag = TBS | ALG | SIGNAT;
                                opt = 0;
                                while((cc = nxtpar(CNULL))) {
                                        dd = cc;
                                        while(*dd) {
                                                if(*dd >= 'a' && *dd <= 'z') *dd -= 32;
                                                dd++;
                                        }
                                        if(!strcmp(cc, "BSTR")) print_keyinfo_flag |= BSTR;
                                        else if(!strcmp(cc, "TBS")) opt |= TBS;
                                        else if(!strcmp(cc, "HSH")) opt |= HSH;
                                        else if(!strcmp(cc, "ALG")) opt |= ALG;
                                        else if(!strcmp(cc, "VAL")) opt |= VAL;
                                        else if(!strcmp(cc, "DER")) opt |= DER;
                                        else if(!strcmp(cc, "SIGNAT")) opt |= SIGNAT;
                                        else if(!strcmp(cc, "KEYINFO")) opt |= KEYINFO;
                                        else if(!strcmp(cc, "ISSUER")) opt |= ISSUER;
                                        else if(!strcmp(cc, "KEYBITS")) print_keyinfo_flag |= KEYBITS;
                                        else if(!strcmp(cc, "ALL")) print_keyinfo_flag = ALGID | BSTR | KEYBITS;
					free(cc);
                                }
                                if(opt && opt != DER) print_cert_flag = 0;
                                print_cert_flag |= opt;
                                if(key->pse_sel) {
                                        ostr = &octetstring;
                                        if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {
						fprintf(stderr,"Can't read from PSE\n");
						aux_free_Key(&key);
						break;
					}
                                        if(aux_cmp_ObjId(&object_oid, SignSK_OID) == 0
                                           || aux_cmp_ObjId(&object_oid, DecSKnew_OID) == 0 
                                           || aux_cmp_ObjId(&object_oid, DecSKold_OID) == 0
					   || aux_cmp_ObjId(&object_oid, SKnew_OID) == 0 
					   || aux_cmp_ObjId(&object_oid, RSA_SK_OID) == 0 
					   || aux_cmp_ObjId(&object_oid, DSA_SK_OID) == 0 
                                           || aux_cmp_ObjId(&object_oid, SKold_OID) == 0) {
                                                if(!(keyinfo = d_KeyInfo(ostr))) goto decodeerr;
                                                fprintf(stderr, "    Secret Key: ");
                                                print_keyinfo_flag |= SK;
                                                aux_fprint_KeyInfo(stderr, keyinfo);
                                                aux_free_KeyInfo(&keyinfo);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, RSA_PK_OID) == 0
                                           || aux_cmp_ObjId(&object_oid, DSA_PK_OID) == 0) {
                                                if(!(keyinfo = d_KeyInfo(ostr))) goto decodeerr;
                                                fprintf(stderr, "    Public Key: ");
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_KeyInfo(stderr, keyinfo);
                                                aux_free_KeyInfo(&keyinfo);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, Name_OID) == 0) {
                                                if(!(dname = d_DName(ostr))) goto decodeerr;
						if(!(name = aux_DName2Name(dname))) {
                               				fprintf(stderr, "Can't build printable repr. of %s\n", key->pse_sel->object.name);
						}
                                                else fprintf(stderr, "%s\n", name);
						aux_free_DName(&dname);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, SerialNumbers_OID) == 0){
                                                if(! (serialnums = d_SerialNumbers(ostr))) goto decodeerr;
						aux_fprint_SerialNumbers(stderr, serialnums);
						aux_free_SerialNumbers(& serialnums);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, SignCert_OID) == 0
                                           || aux_cmp_ObjId(&object_oid, EncCert_OID) == 0
					   || aux_cmp_ObjId(&object_oid, Cert_OID) == 0) { 
                                                if(!(certificate = d_Certificate(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_Certificate(stderr, certificate);
                                                aux_free_Certificate(&certificate);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, SignCSet_OID) == 0
                                           || aux_cmp_ObjId(&object_oid, EncCSet_OID) == 0
					   || aux_cmp_ObjId(&object_oid, CSet_OID) == 0) { 
                                                if(!(certset = d_CertificateSet(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_CertificateSet(stderr, certset);
                                                aux_free_CertificateSet(&certset);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, FCPath_OID) == 0) {
                                                if(!(fcpath = d_FCPath(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_FCPath(stderr, fcpath);
                                                aux_free_FCPath(&fcpath);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, PKRoot_OID) == 0) {
                                                if(!(pkroot = d_PKRoot(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_PKRoot(stderr, pkroot);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, PKList_OID) == 0
                                           || aux_cmp_ObjId(&object_oid, EKList_OID) == 0) { 
                                                if(!(pklist = d_PKList(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_PKList(stderr, pklist);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, CrossCSet_OID) == 0) {
                                                if(!(cpairset = d_CertificatePairSet(ostr))) goto decodeerr;
                                                print_keyinfo_flag |= PK;
                                                aux_fprint_CertificatePairSet(stderr, cpairset);
						aux_free_CertificatePairSet(&cpairset);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, CrlSet_OID) == 0) {
                                                if(!(crlset = d_CrlSet(ostr))) goto decodeerr;
                                                aux_fprint_CrlSet(stderr, crlset);
                                                aux_free_CrlSet(&crlset);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, AliasList_OID) == 0) {
                                                if(!(aliaslist = d_AliasList(ostr))) goto decodeerr;
                                                aux_fprint_AliasList(stderr, aliaslist);
                                                aux_free_AliasList(&aliaslist);
                                        }
                                        else if(aux_cmp_ObjId(&object_oid, QuipuPWD_OID) == 0) {
                                                if(!(dd = d_GRAPHICString(ostr))) goto decodeerr;
                                                fprintf(stderr, "X.500 Password: %s\n", dd);
                                                if (dd) free(dd);
                                        }
					else {
                                                fprintf(stderr, "Object OID { ");
	                                        for(i = 0; i < object_oid.oid_nelem; i++) fprintf(stderr, "%d ", object_oid.oid_elements[i]);
	                                        fprintf(stderr, " }\n");

		                                if((certificate = d_Certificate(ostr))) {
                                                        print_keyinfo_flag |= PK;
                                                        aux_fprint_Certificate(stderr, certificate);
	                                                aux_free_Certificate(&certificate);
		                                }
						else if((dname = d_DName(ostr))) {
							if(!(name = aux_DName2Name(dname))) {
	                               				fprintf(stderr, "Can't build printable repr. of %s\n", key->pse_sel->object.name);
							}
                                                	else fprintf(stderr, "%s\n", name);
		                                        aux_free_DName(&dname);
		                                }
		                                else if((fcpath = d_FCPath(ostr))) {
	                                                aux_fprint_FCPath(stderr, fcpath);
		                                        aux_free_FCPath(&fcpath);
		                                }
		                                else if((pkroot = d_PKRoot(ostr))) {
	                                                aux_fprint_PKRoot(stderr, pkroot);
		                                        aux_free_PKRoot(&pkroot);
		                                }
		                                else if((certset = d_CertificateSet(ostr))) {
	                                                aux_fprint_CertificateSet(stderr, certset);
		                                        aux_free_CertificateSet(&certset);
		                                }
		                                else if((pklist = d_PKList(ostr))) {
	                                                aux_fprint_PKList(stderr, pklist);
		                                        aux_free_PKList(&pklist);
		                                }
		                                else if((keyinfo = d_KeyInfo(ostr))) {
                                                	fprintf(stderr, "    PublicKeyAid: ");
                                                	print_keyinfo_flag |= PK;
                                                	aux_fprint_KeyInfo(stderr, keyinfo);
		                                        aux_free_KeyInfo(&keyinfo);
		                                }
						else if ((cpairset = d_CertificatePairSet(ostr))) {
                                                	aux_fprint_CertificatePairSet(stderr, cpairset);
							aux_free_CertificatePairSet(&cpairset);
						}
		                                else if((crlset = d_CrlSet(ostr))) {
                                                	aux_fprint_CrlSet(stderr, crlset);
		                                        aux_free_CrlSet(&crlset);
		                                }
		                                else if((aliaslist = d_AliasList(ostr))) {
                                                	aux_fprint_AliasList(stderr, aliaslist);
		                                        aux_free_AliasList(&aliaslist);
		                                }
		                                else if((dd = d_GRAPHICString(ostr))) {
                                                	fprintf(stderr, "X.500 Password: %s\n", dd);
                                                	if (dd) free(dd);
		                                }
						else aux_xdump(ostr->octets, ostr->noctets, 0);
					}
                                        print_keyinfo_flag = ALGID;
                                        print_cert_flag = TBS | ALG | SIGNAT;
					if(ostr->octets) free(ostr->octets);
					aux_free2_ObjId(&object_oid);
					aux_free_Key(&key);
                                        break;
                                }
                                else {
                                        if((rcode = sec_get_key(&tmpkey, key->keyref, (Key *)0)) < 0)  {
						fprintf(stderr,"Can't get key\n");
						aux_free_Key(&key);
						break;
					}
                                        fprintf(stderr, "    KeyAid: ");
                                        aux_fprint_KeyInfo(stderr, &tmpkey);
                                        print_keyinfo_flag = ALGID;
                                        print_cert_flag = TBS | ALG | SIGNAT;
					aux_free2_KeyInfo(&tmpkey);
                                        break;
                                }
decodeerr:
                                fprintf(stderr, "Can't decode %s\n", key->pse_sel->object.name);
				if(ostr->octets) free(ostr->octets);
				aux_free_Key(&key);
                                break;
                        case SPLIT:
				cpairset = af_pse_get_CertificatePairSet();
				if (! cpairset) {
					fprintf(stderr,"No Cross Certificate Pairs stored in PSE\n");
					break;
				}
				cpair = specify_CertificatePair();
				if (! cpair) {
					if (verbose) aux_fprint_error(stderr, 0);
                               		fprintf(stderr, "%s: unable to create Cross Certificate Pair\n", parm[0]);
                 			break;
				}
				if (! cpair->forward && ! cpair->reverse) {
					fprintf(stderr, "At least one component (forward or reverse) must be present.\n");
					aux_free_CertificatePair(&cpair);
					break;
				}
				while (cpairset) {
					if (! aux_cmp_CertificatePair(cpair, cpairset->element))
						break;
					cpairset = cpairset->next;
				}
				if (! cpairset) {
					fprintf(stderr,"Specified Cross Certificate Pair NOT found\n");
					break;
				}
				if (cpairset->element->forward) {
					fprintf(stderr,"\nWhere shall the forward certificate be stored?\n");
					psesel(2);
			
					if(onekeypaironly == TRUE){
						oid = af_get_objoid(Cert_name);
					}
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}

					ostr = e_Certificate(cpairset->element->forward);
					if (!ostr) {
						fprintf(stderr,"Can't encode forward certificate\n");
						break;
					}
                               		rcode = 0;
                                	if(sec_open(&std_pse) < 0) rcode = sec_create(&std_pse);
                                	if(!rcode) {
						rcode = sec_write_PSE(&std_pse, oid, ostr);
                       	                	if(rcode) {
							fprintf(stderr,"Can't write to PSE\n");
							break;
						}
					} 
					else {
						fprintf(stderr,"Can't create PSE\n");
						break;
					}
					fprintf(stderr, "Forward certificate stored in object <%s> on PSE.\n", std_pse.object.name);
                                	aux_free_OctetString(&ostr);
				}
				if (cpairset->element->reverse) {
					fprintf(stderr,"\nWhere shall the reverse certificate be stored?\n");
					psesel(2);

					if(onekeypaironly == TRUE){
						oid = af_get_objoid(Cert_name);
					}
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
					ostr = e_Certificate(cpairset->element->reverse);
					if (!ostr) {
						fprintf(stderr,"Can't encode reverse certificate\n");
						break;
					}
                               		rcode = 0;
                                	if(sec_open(&std_pse) < 0) rcode = sec_create(&std_pse);
                                	if(!rcode) {
						rcode = sec_write_PSE(&std_pse, oid, ostr);
                       	                	if(rcode) {
							fprintf(stderr,"Can't write to PSE\n");
							break;
						}
					} 
					else {
						fprintf(stderr,"Can't create PSE\n");
						break;
					}
					fprintf(stderr, "Reverse certificate stored in object <%s> on PSE.\n", std_pse.object.name);
                                	aux_free_OctetString(&ostr);
				}
                                break;
                        case STRING2KEY:
                                str2key();
                                if(!(key = build_key("", 1)))  {
					fprintf(stderr,"Can't build key\n");
					break;
				}
                                sec_string_to_key(pin, key);
                                fprintf(stderr, "DES key stored ");
                                if(key->pse_sel) fprintf(stderr, " in object %s\n", key->pse_sel->object.name);
                                else fprintf(stderr, "under keyref %d\n", key->keyref);
				aux_free_Key(&key);
                                break;
                        case TOC:
				rcode = sec_print_toc(stderr, &std_pse);
				if(rcode < 0) fprintf(stderr, "Can't read TOC of %s\n", std_pse.app_name);
                                break;
#ifdef SCA
                        case TOGGLE:
				SC_verify = 1 - SC_verify;
				SC_encrypt = 1 - SC_encrypt;
				if(SC_verify) fprintf(stderr, "Verification/Encryption in SCT\n");
				else fprintf(stderr, "Verification/Encryption with SW\n");
                                break;
#endif
                        case VERIFY:
                                ostr = &octetstring;

                                if((dd = nxtpar("certificate"))) {
					strrep(&(std_pse.object.name), dd);
					free(dd);
				}
                                else{
					if(onekeypaironly == TRUE)
						strrep(&(std_pse.object.name), Cert_name);
					else
						strrep(&(std_pse.object.name), SignCert_name);
				}

                                if(sec_read_PSE(&std_pse, &object_oid, ostr) < 0) {
					fprintf(stderr,"Can't read from PSE\n");
					break;
				}
				store_objpin();

                                if(aux_cmp_ObjId(&object_oid, SignCert_OID) && aux_cmp_ObjId(&object_oid, EncCert_OID) && aux_cmp_ObjId(&object_oid, Cert_OID)) { 
                                        fprintf(stderr, "%s is not a certificate\n", std_pse.object.name);
                                        free(ostr->octets);
					free(object_oid.oid_elements);
                                        break;
                                }
				free(object_oid.oid_elements);
                                if(!(certificate = d_Certificate(ostr))) {
                                        fprintf(stderr, "Can't decode %s\n", std_pse.object.name);
                                        free(ostr->octets);
                                        break;
                                }
                                free(ostr->octets);
                                if((dd = nxtpar("fcpath"))) {
					strrep(&(std_pse.object.name), dd);
					free(dd);
				}
                                else strrep(&(std_pse.object.name), FCPath_name);
                                ostr = &octetstring;
                                fcpath = (FCPath *)0;
                                if(sec_read_PSE(&std_pse, &object_oid, ostr) == 0) {
					store_objpin();
                                        if(aux_cmp_ObjId(&object_oid, FCPath_OID)) { 
                                                fprintf(stderr, "%s is not an FCPath\n", std_pse.object.name);
                                                free(ostr->octets);
						free(object_oid.oid_elements);
						aux_free_Certificate(&certificate);
                                                break;
                                        }
					free(object_oid.oid_elements);
                                        if(!(fcpath = d_FCPath(ostr))) {
                                                fprintf(stderr, "Can't decode %s\n", std_pse.object.name);
                                                free(ostr->octets);
						aux_free_Certificate(&certificate);
                                                break;
                                        }
                                        free(ostr->octets);
                                }
                                certs = aux_create_Certificates(certificate, fcpath);
				if(!certs) {
					fprintf(stderr, "Can't allocate memory");
					aux_free_Certificate(&certificate);
					aux_free_FCPath(&fcpath);
					break;
				}
				aux_free_Certificate(&certificate);
				aux_free_FCPath(&fcpath);
                                if((dd = nxtpar("pkroot"))) {
                                        strrep(&(std_pse.object.name), dd);
					free(dd);
                                        ostr = &octetstring;
                                        if(sec_read_PSE(&std_pse, &object_oid, ostr) < 0)  {
        					fprintf(stderr,"Can't read from PSE\n");
        					break;
        				}
					store_objpin();
                                        if(aux_cmp_ObjId(&object_oid, PKRoot_OID)) { 
                                                fprintf(stderr, "%s is not a PKRoot\n", std_pse.object.name);
						free(object_oid.oid_elements);
                                                free(ostr->octets);
						aux_free_Certificates(&certs);
                                                break;
                                        }
					free(object_oid.oid_elements);
                                        if(!(pkroot = d_PKRoot(ostr))) {
                                                fprintf(stderr, "Can't decode %s\n", std_pse.object.name);
                                                free(ostr->octets);
                                                break;
                                        }
                                        free(ostr->octets);
                                }
                                else pkroot = (PKRoot *)0;
                                af_verbose = TRUE;
                                print_keyinfo_flag = ALGID;

                                rcode = af_verify_Certificates(certs, (UTCTime *)0, pkroot);
                                aux_free_Certificates(&certs);
                                if(pkroot) aux_free_PKRoot(&pkroot);
				aux_fprint_VerificationResult(stderr, verifresult);
				aux_free_VerificationResult(&verifresult);
				if(rcode < 0 ) {
					fprintf(stderr, "Verification  f a i l e d: %s\n", err_stack->e_text);
				}
                                break;
                        case WRITE:
                                psesel(2);
                                filen();
                                if(!(ostr = aux_file2OctetString(filename)))  {
					fprintf(stderr,"Can't read file\n");
					break;
				}
                                if((certificate = d_Certificate(ostr))) {
					if(onekeypaironly == TRUE)
						oid = af_get_objoid(Cert_name);
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCert_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCert_name);
                                        	else {
                                                	fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
                                        aux_free_Certificate(&certificate);
                                }
				else if((dname = d_DName(ostr))) {
                                        oid = af_get_objoid(Name_name);
                                        aux_free_DName(&dname);
                                }
                                else if((fcpath = d_FCPath(ostr))) {
                                        oid = af_get_objoid(FCPath_name);
                                        aux_free_FCPath(&fcpath);
                                }
                                else if((pkroot = d_PKRoot(ostr))) {
                                        oid = af_get_objoid(PKRoot_name);
                                        aux_free_PKRoot(&pkroot);
                                }
                                else if((certset = d_CertificateSet(ostr))) {
					if(onekeypaironly == TRUE)
						oid = af_get_objoid(CSet_name);
					else{
                                        	keytype();
                                        	if(*objtype == 'S') oid = af_get_objoid(SignCSet_name);
                                        	else if(*objtype == 'E') oid = af_get_objoid(EncCSet_name);
                                        	else {
                                               		fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                	break;
                                        	}
					}
                                        aux_free_CertificateSet(&certset);
                                }
                                else if((pklist = d_PKList(ostr))) {
                                        keytype();
                                        if(*objtype == 'S') oid = af_get_objoid(PKList_name);
                                        else if(*objtype == 'E') oid = af_get_objoid(EKList_name);
                                        else {
                                                fprintf(stderr, "Type must me either 'S' or 'E'\n");
                                                break;
                                        }
                                        aux_free_PKList(&pklist);
                                }
                                else if((keyinfo = d_KeyInfo(ostr))) {
                                        oid = af_get_objoid(DecSKnew_name);
                                        aux_free_KeyInfo(&keyinfo);
                                }
				else if ((cpairset = d_CertificatePairSet(ostr))) {
					oid = af_get_objoid(CrossCSet_name);
					aux_free_CertificatePairSet(&cpairset);
				}
                                else if((crlset = d_CrlSet(ostr))) {
                                        oid = af_get_objoid(CrlSet_name);
                                        aux_free_CrlSet(&crlset);
                                }
                                else if((aliaslist = d_AliasList(ostr))) {
                                        oid = af_get_objoid(AliasList_name);
                                        aux_free_AliasList(&aliaslist);
                                }
				else {
					tmp_ostr = aux_cpy_OctetString(ostr);
					aux_free_OctetString(&ostr);
					ostr = e_OctetString(tmp_ostr);
	                                oid = aux_cpy_ObjId(Uid_OID);
					aux_free_OctetString(&tmp_ostr);
				}
                                rcode = 0;

                                if(sec_open(&std_pse) < 0) rcode = sec_create(&std_pse);

                                if(!rcode) {
					rcode = sec_write_PSE(&std_pse, oid, ostr);
                       	                if(rcode) fprintf(stderr,"Can't write to PSE\n");
				}
				else fprintf(stderr,"Can't create PSE\n");
 
                                aux_free_OctetString(&ostr);
				aux_free_ObjId(&oid);

                                break;
                        case XDUMP:
                                key = object();
				if(!key) break;
                                if(key->pse_sel) {
                                        ostr = &octetstring;
                                        if(sec_read(key->pse_sel, ostr) < 0)   {
						fprintf(stderr,"Can't read from PSE\n");
						aux_free_Key(&key);
						break;
					}
					aux_free_Key(&key);
                                	if((objectvalue = d_PSEObject(&objecttype, ostr)) == (OctetString *)0 ) {
                                                dd = ostr->octets;          
                                                n = ostr->noctets;
                                	}
                                        else {
						free(ostr->octets);
                                                fprintf(stderr, "Object OID { ");
                                                for(i = 0; i < objecttype.oid_nelem; i++) {
     	                                                fprintf(stderr, "%d ", objecttype.oid_elements[i]);
                                                }
                                                fprintf(stderr, " }\n");
						free(objecttype.oid_elements);
                                                dd = objectvalue->octets; 
                                                n  = objectvalue->noctets;
                                        }
                                }
                                else {
                                        if((rcode = sec_get_key(&tmpkey, key->keyref, (Key *)0)) < 0)  {
						fprintf(stderr,"Can't get key\n");
						aux_free_Key(&key);
						free(dd);
						break;
					}
                                        dd = tmpkey.subjectkey.bits;
                                        n = (tmpkey.subjectkey.nbits + 7)/ 8;
					aux_free_AlgId(&(tmpkey.subjectAI));
                                }
                                aux_xdump(dd, n, 0);
				aux_free_Key(&key);
				free(dd);
                                break;
			case ERROR:
				aux_fprint_error(stderr, 0);
				break;
			case RESETERROR:
				aux_free_error();
				break;
                        default:
                                break;
                }
                if(verbose && rcode < 0) {
			aux_fprint_error(stderr, 0);
			aux_free_error();
		}

        }
}

static
num(par)
register char *par;
{
        while(*par) {
                if(*par < '0' || *par > '9') return(FALSE);
                par++;
        }
        return(TRUE);
}

static
ack(pse_sel, txt)
PSESel *pse_sel;
char *txt;
{
        if(!(pse_sel->object.name) || !strlen(pse_sel->object.name)) fprintf(stderr, "PSE %s %s\n", pse_sel->app_name, txt);
        else fprintf(stderr, "object %s of PSE %s %s\n", pse_sel->object.name, pse_sel->app_name, txt);
        return(0);
}

static
psesel(option) 
int option; 
{             

/*
 * psesel(option) sets std_pse according to values given via command-line.
 * option  1: objectname is optional; 2: objectname must be given
 * psesel returns 0 if object was selected, 1 if PSE was selected
 */
	char *proc = "psesel";
	char *newstring;
        char *dd;

        if(cmd == OPEN || cmd == CLOSE) {
                if(!(dd = nxtpar(""))) {
                        if(cmd == OPEN) {
                                fprintf(stderr, "Enter PSE name: ");
				newstring = (char *)malloc(128);
				if( !newstring ) {
					aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
					fprintf(stderr, "Can't allocate memory");
					return(-1);
				}
                                dd = gets(newstring);
                        }
                        else dd = aux_cpy_String(std_pse.app_name);
                }

                if(cmd == OPEN) {
                        if(std_pse.app_name) {
                                if(strcmp(dd, std_pse.app_name) == 0) {
					free(dd);
                                        fprintf(stderr, "%s already open\n", dd);
                                        return(-1);
                                }
                                if(sec_close(&std_pse) == 0) ack(&std_pse, "closed");
                        }
                        if(std_pse.pin) strzfree(&(std_pse.pin));
                }
                else {
                        if(!std_pse.app_name || strcmp(dd, std_pse.app_name)) {
                                fprintf(stderr, "%s not open\n", dd);
				free(dd);
                                return(-1);
                        }
                }
                strrep(&(std_pse.app_name), dd);
                if(std_pse.object.name) free(std_pse.object.name);
                std_pse.object.name = CNULL;
                if(std_pse.object.pin) strzfree(&(std_pse.object.pin));
                return(1);
        }

        if(std_pse.object.name) free(std_pse.object.name);
        if(!(std_pse.object.name = nxtpar(""))) {
                while(!std_pse.object.name) {
                        fprintf(stderr, "Enter name of object on %s: ", std_pse.app_name);
                        newstring = (char *)malloc(128);
 			if( !newstring ) {
				aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
				fprintf(stderr, "Can't allocate memory");
				return(-1);
			}
                        std_pse.object.name = gets(newstring);
                        if(strlen(std_pse.object.name) == 0) {
                                free(std_pse.object.name);
                                std_pse.object.name = CNULL;
                        }
                        if(option == 1) break;
                }
        }
        return(0);
}

static
getsize(par) 
char *par;
{
        int size = 0;
        char *dd, sz[32];
        if(!(dd = nxtpar(par)))  {
                fprintf(stderr, "%s: ", par);
                dd = aux_cpy_String(gets(sz));
		if(!dd) return(0);
        }
        sscanf(dd, "%d", &size);
	free(dd);
        return(size);
}

static
filen() {

	char *proc = "filen";
	char *newstring;

        if(!(filename = nxtpar("file"))) {
                if(cmd == WRITE || cmd == SETPARM) fprintf(stderr, "File: ");
                else fprintf(stderr, "File [CR for stderr]: ");
		newstring = (char *)malloc(128);
 		if( !newstring ) {
			aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
			fprintf(stderr, "Can't allocate memory");
			return(-1);
		}
                filename = gets(newstring);
                if(!filename || strlen(filename) == 0) {
                        free(newstring);
                        filename = CNULL;
                }
        }

	return(0);
}

static
keytype() {
	char *proc = "keytype";
	char *newstring;

        if(!(objtype = nxtpar("keytype"))) {
                fprintf(stderr, "SIGNATURE or ENCRYPTION type (S/E) [CR for S]: ");
 		newstring = (char *)malloc(16);
 		if( !newstring ) {
			aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
			fprintf(stderr, "Can't allocate memory");
			return(-1);
		}
                objtype = gets(newstring);
                if(!objtype || strlen(objtype) == 0) {
                        free(newstring);
                        objtype = "S";
                }
        }

	return(0);
}

static
printfile(ostring, fname)
OctetString *ostring;
char *fname;
{
        register int i, j;
        register char *dd;
        if(!fname || !strlen(fname)) {
                dd = ostring->octets;
                i = ostring->noctets;
                while(i > 0) {
                	j = (i < 1024) ? i : 1024;
                        write(1, dd, j);
                        i -= j;
                        dd += j;
                }
        }
        else aux_OctetString2file(ostring, fname, 2);

	return(0);
}

static
new_pin() {
        if(!(newpin = nxtpar("newpin"))) newpin = sec_read_pin("New PIN", std_pse.object.name, TRUE);

	return(0);
}        

static
str2key() {
        if(!(pin = nxtpar("pin"))) pin = sec_read_pin("PIN", "", TRUE);

	return(0);
}        

static
helpcmd() {
        int i;

        if((helpname = nxtpar(CNULL))) {
                for(i = 0; cmds[i].cmd; i++) {
                        if(strncmp(cmds[i].cmd, helpname, strlen(helpname)) == 0) {
                                fprintf(stderr, "Command:     %s %s\n", cmds[i].cmd, cmds[i].parms);
                                fprintf(stderr, "Description: %s\n", cmds[i].text);
                                fprintf(stderr, "%s\n", cmds[i].longtext);
                        }
                }
                return(0);
        }

        fprintf(stderr, "Command      Description\n");
        fprintf(stderr, "-------------------------------------------------------------------------\n");
        for(i = 0; cmds[i].cmd; i++) fprintf(stderr, "%-12s %s\n", cmds[i].cmd, cmds[i].text);
        fprintf(stderr, "-------------------------------------------------------------------------\n");
        fprintf(stderr, "Command and parameter names may be abbreviated, parameters may be omitted\n");
	return(0);
}

static
store_objpin()
/* stores object pin returned from "pin_check()" in AF_pse */
{
	int    i;
	char * proc = "store_objpin";

	for (i = 0; i < PSE_MAXOBJ; i++) 
		if (strcmp(AF_pse.object[i].name, std_pse.object.name) == 0) {
			strrep(&(AF_pse.object[i].pin), std_pse.object.pin);
		}

	return(0);
}

static
Key *build_key(s, flag) 
char *s; 
int flag;  /* 0: read,  1: write */
#define OPEN_TO_READ 0
#define OPEN_TO_WRITE 1
{
        char *dd, *cc;
	char answ[8];
	int i;
        KeyInfo zwkey;
        OctetString ostring;
	char *proc = "build_key";
	char newstring[64];
	Key *newkey;
	PSEType pse_type;
	AlgEnc   algenc;
	int	 keyref;


	newkey = (Key *)calloc(1, sizeof(Key));
	if(!newkey) return((Key *)0);

        if(cmd == GENKEY) {
                newkey->key = (KeyInfo *)calloc(1, sizeof(KeyInfo));
 		if(!newkey->key) {
			return((Key *)0);
		}
                newkey->key->subjectAI = aux_Name2AlgId(algname);
                if(!newkey->key->subjectAI) {
			free(newkey->key);
			free(newkey);
                        return((Key *)0);
                }
        }
nk:
        if(!(dd = nxtpar(CNULL))) {
                if(cmd == DELKEY) fprintf(stderr, "Keyref: %s", s);
                else if(cmd == CERT2KEYINFO || cmd == CERTIFY || cmd == CERT2PKROOT || cmd == PROTOTYPE || cmd == ADDEK || cmd == ADDPK) fprintf(stderr, "%s: ", s);
                else fprintf(stderr, "Name or ref of %skey: ", s);
                dd = aux_cpy_String(gets(newstring));
		if(!dd) aux_cpy_String("");
        }
        if(strcmp(dd, "replace") == 0) {
                replace = TRUE;
                goto nk;
        }
        if(num(dd)) {
                if(strlen(dd) == 0) {
			newkey->keyref = -1;
		}
                else sscanf(dd, "%d", &(newkey->keyref));
		free(dd);
		if (newkey->keyref == 0) 
			newkey->keyref = -1;
#ifdef SCA
		else {
			/*
			 * GENKEY: 
			 *   check whether a DES/DES3 key shall be generated in SCT/SC 
			 * DELKEY: 
			 *   check whether a key stored in the SCT shall be deleted
			 */
		
			if (cmd == GENKEY) {
				algenc = aux_ObjId2AlgEnc(newkey->key->subjectAI->objid);
				if ((algenc == DES) || (algenc == DES3)) {
					fprintf	(stderr, "Store key in KeyPool (0), in the SCT (1), in the Smartcard (2):");
					gets(answ);
					if ((answ[0] == '1') || (answ[0] == '2')) {

						/*
						 *  Store key in SCT/SC
						 */

						if (answ[0] == '1') {
							 keyref = newkey->keyref | SCT_KEY;
                               				 newkey->keyref = keyref;
						}
						else {
							/*
							 * Check whether pse = pse on SC
							 */

							if (sec_sctest(std_pse.app_name) == FALSE) {
                       						fprintf(stderr, "\nCannot generate a key on the smartcard:\n");
                       						fprintf(stderr, "Application %s is not an application on the smartcard\n", std_pse.app_name);
								aux_free_Key(&newkey);
								return((Key *)0);
							}
                               				keyref = newkey->keyref | SC_KEY;
                               				newkey->keyref = keyref;
						}
						return (newkey);
					}
				}
			
			}
			if (cmd == DELKEY) {
				fprintf	(stderr, "Delete key in KeyPool (0), in the SCT (1):");
				gets(answ);
				if (answ[0] == '1') {

					/*
					 *  Delete key in SCT
					 */

                               		keyref = newkey->keyref | SCT_KEY;
                               		newkey->keyref = keyref;
					return (newkey);

				}
			}
			
		}
#endif
		if(cmd == GENKEY && publickey && newkey->keyref != -1) if(newkey->keyref == publickey->keyref) {
                       	fprintf(stderr, "Public key and secret key must have different keyrefs\n");
			aux_free_Key(&newkey);
			return((Key *)0);
		}
		if(newkey->keyref > 0 && cmd == GENKEY && replace == FALSE) {
			if(sec_get_key(&zwkey, newkey->keyref, (Key *)0) == 0) {
				aux_free2_KeyInfo(&zwkey);
                               	fprintf(stderr, "Keyref %d exists already. Replace? (y/n): ", newkey->keyref);
                               	gets(answ);
                               	if(answ[0] == 'y') {
					sec_del_key(newkey->keyref);
					if(strcmp(s, "generated secret ") == 0) replace = TRUE;
				}
				else {
					aux_free_Key(&newkey);
					return((Key *)0);
				}
			} 
		}
        }
        else {
                newkey->pse_sel = aux_cpy_PSESel(&std_pse);
		strrep(&(newkey->pse_sel->object.name), dd);
		free(dd);
		for (i = 0; i < PSE_MAXOBJ; i++) 
			if(strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name) == 0) {
				strrep(&(newkey->pse_sel->object.pin), AF_pse.object[i].pin);
				break;
               		}
		if(cmd == GENKEY) {
			if(publickey) if(strcmp(newkey->pse_sel->object.name, publickey->pse_sel->object.name) == 0) {
	                       	fprintf(stderr, "Public key and secret key must be stored in different objects\n");
				aux_free_Key(&newkey);
				return((Key *)0);
			}
#ifdef SCA
			if((sec_sctest(newkey->pse_sel->app_name) == TRUE) && (!sec_open(newkey->pse_sel))) {
				if(strcmp(s, "generated secret ") == 0) {
                                	fprintf(stderr, "Replace existing secret key? (y/n): ");
                                	gets(answ);
                                	if(answ[0] == 'y') replace = TRUE;  /* replace is global */
				}
				if ((pse_type = sec_psetest(newkey->pse_sel)) != NOT_ON_SC) {
					if(strcmp(s, "generated DES ") == 0) {
                                		fprintf(stderr, "Replace existing DES key? (y/n): ");
                                		gets(answ);
                                		if(answ[0] == 'y') replace = TRUE;  /* replace is global */
					}
				}
				return(newkey);
                        }
#endif
		}
                if(sec_open(newkey->pse_sel) < 0) {
                        if(flag == OPEN_TO_READ) {
                                fprintf(stderr, "Can't open Object %s\n", newkey->pse_sel->object.name);
				aux_add_error(EINVALID, "sec_open failed", CNULL, 0, proc);
				aux_free_Key(&newkey);
                                return((Key *)0);
                        }

			/*
			 *  Open (object) failed => object doesn't exist.
			 *    
			 *  If object to be generated is a key on the SC => no creation of object.
			 *      
			 */

			if ((pse_type = sec_psetest(newkey->pse_sel)) != KEY_ON_SC) {

                        	fprintf(stderr, "Create object %s\n", newkey->pse_sel->object.name);
                        	strrep(&(newkey->pse_sel->object.pin), newkey->pse_sel->pin);
                        	if(sec_create(newkey->pse_sel) < 0) {
                                	fprintf(stderr, "Can't create Object %s\n", newkey->pse_sel->object.name);
					aux_add_error(EINVALID, "sec_open failed", CNULL, 0, proc);
					aux_free_Key(&newkey);
                                	return((Key *)0);
                        	}
				if(strcmp(s, "generated public ")) replace = TRUE;
				for (i = 0; i < PSE_MAXOBJ; i++) {
					if (!strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name)) {
						strrep(&(AF_pse.object[i].pin), newkey->pse_sel->object.pin);
						break;
                      	      		}
				}
			}
                        return(newkey);
                }
 
		for (i = 0; i < PSE_MAXOBJ; i++) {
			if (!strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name)) {
				strrep(&(AF_pse.object[i].pin), newkey->pse_sel->object.pin);
				break;
                        }
                        else if(flag == OPEN_TO_WRITE) {
				if(cmd == GENKEY && replace == TRUE) return(newkey);
                                fprintf(stderr, "Object %s already exists. Overwrite (y/n)? ", newkey->pse_sel->object.name);
                        	dd = gets(newstring);
                                if(!dd || *dd != 'y') {
					aux_free_Key(&newkey);
					return((Key *)0);
				}
				if(strcmp(s, "generated public ")) replace = TRUE;
                                return(newkey);
                        }
                }
        }
        return(newkey);
}

static
char *getalgname() {
        char aname[32], answ[8];
        char *dd, *ee;
        if(!(dd = nxtpar("algorithm"))) {
                if(cmd == ALGS) strcpy(aname, "ALL");
                else {
                        if(cmd == SETPARM) fprintf(stderr, "Algorithm name [CR for rsa]: ");
                        else fprintf(stderr, "Algorithm name [CR for desCBC]: ");
                        gets(aname);
                }
       	 	if(strlen(aname) == 0) {
                	if(cmd == SETPARM) strcpy(aname, "rsa");
                	else if(cmd == ALGS) strcpy(aname, "ALL");
                	else strcpy(aname, "desCBC");
        	}
		dd = aux_cpy_String(aname);
	}
	if(aux_Name2AlgEnc(dd) == DSA && cmd == GENKEY) {
		if(!(ee = nxtpar("primes"))) { 
			fprintf(stderr, "Predefined p, q, g? (y/n): ");
			gets(answ);
			if(answ[0] == 'y') sec_dsa_predefined = TRUE;
			else sec_dsa_predefined = FALSE;
		}
	}
        return(dd);
}

static
DName *getdname(s)
char * s;
{
	DName *dname;
	char *dd, name[64];

	if(! s){
        	if(!(dd = nxtpar("dirname"))) {
			fprintf(stderr, "Directory name [CR for your own name]: ");
			dd = aux_cpy_String(gets(name));
        	}
		if(!dd) return(af_pse_get_Name());
        	if (strlen(dd) == 0) {
			free(dd);
			return(af_pse_get_Name());
		}
	}
	else{
		fprintf(stderr, "%s's Distinguished Name [CR for NULLDNAME]: ", s);
		dd = aux_cpy_String(gets(name));
 		if( !dd ) return (NULLDNAME);
		if (strlen(dd) == 0) {
			free(dd);
			return (NULLDNAME);
		}
	}
	dname = aux_alias2DName(dd);
	if (!dname){
		fprintf(stderr, "Cannot transform alias name <%s> into a Distinguished Name!\n", dd);
	}
	free(dd);

        return(dname);
}


static
Name *getname() {
	DName *dname;
        char *dd, name[64];
	char *proc = "getname";


username:
        if(!(dd = nxtpar(CNULL))) {
                fprintf(stderr, "Username: ");
                dd = aux_cpy_String(gets(name));
        }
	if(!dd) return((Name *)0);
	if(strlen(dd) == 0) {
		free(dd);
		return((Name *)0);
	}
	dname = aux_alias2DName(dd);
	free(dd);
	if (!dname) {
                incorrectName();
                goto username;
        }
        dd = aux_DName2Name(dname);
        aux_free_DName(&dname);
        return(dd);
}


static
Name *getalias() {
	DName *dname;
        char *dd, name[64];
	char *proc = "getalias";

        if(!(dd = nxtpar(CNULL))) {
                fprintf(stderr, "Alias name: ");
                dd = aux_cpy_String(gets(name));
        }
	if(!dd) return((Name *)0);
	if(strlen(dd) == 0) {
		free(dd);
		return((Name *)0);
	}
        return(dd);
}


static
int getserial() {
	char *proc = "getserial";
	char *dd, number[10];
	int i;

	fprintf(stderr, " Serial number: ");
	dd = aux_cpy_String(gets(number));
 	if( !dd ) return (- 1);
	if (strlen(dd) == 0) {
		free(dd);
		return (- 1);
	}
	i = atoi(dd);
	free(dd);
        return(i);
}


static
char *getattrtype(x500)
char x500;
{
        char type[32];
        char *dd;


        dd = nxtpar("attrtype");
attrtype:
	if(!dd){
                fprintf(stderr, "Select one of the following attribute types:\n\n");
#ifdef X500
		if(x500){
			fprintf(stderr, "       U[serCertificate]\n");
			fprintf(stderr, "       CA[Certificate]\n");
		}
#endif
#ifdef AFDBFILE
		if(!af_x500 || !x500)
			fprintf(stderr, "       Ce[rtificate]\n");
#endif
		fprintf(stderr, "       Cr[ossCertificatePair]\n");
		if(cmd == ENTER || cmd == RETRIEVE)
			fprintf(stderr, "       P[emCertificateRevocationList]\n");
		fprintf(stderr, "\n");
#ifdef X500
		if(x500)
			fprintf(stderr, "[CR for UserCertificate]:  ");
#endif
#ifdef AFDBFILE
		if(!af_x500 || !x500)
			fprintf(stderr, "[CR for Certificate]:  ");
#endif
                gets(type);
       	 	if(strlen(type) == 0){
#ifdef X500
			if(x500)
                		strcpy(type, "UserCertificate");
#endif
#ifdef AFDBFILE
			if(!af_x500 || !x500)
				strcpy(type, "Certificate");
#endif
		}
		dd = aux_cpy_String(type);
	}

#ifdef X500
	if(x500){
		if((strncasecmp(dd, "UserCertificate", 1) && strncasecmp(dd, "CACertificate", 2) &&
		    strncasecmp(dd, "CrossCertificatePair", 2) && strncasecmp(dd, "PemCertificateRevocationList", 1) &&
		    (cmd == ENTER || cmd == RETRIEVE)) ||
		   (strncasecmp(dd, "UserCertificate", 1) && strncasecmp(dd, "CACertificate", 2) &&
		    strncasecmp(dd, "CrossCertificatePair", 2) && (cmd == REMOVE))) {
			fprintf(stderr, "\n");
			fprintf(stderr, "Wrong Attribute Type!\n");
			if(dd){
				free(dd);
				dd = CNULL;
			}
			goto attrtype;
		}
	}
#endif
#ifdef AFDBFILE
	if(!af_x500 || !x500){
		if((strncasecmp(dd, "Certificate", 2) && strncasecmp(dd, "CrossCertificatePair", 2) && 
		    strncasecmp(dd, "PemCertificateRevocationList", 1) && (cmd == ENTER || cmd == RETRIEVE)) ||
		   (strncasecmp(dd, "Certificate", 2) && strncasecmp(dd, "CrossCertificatePair", 2) && 
		    (cmd == REMOVE))) {
			fprintf(stderr, "\n");
			fprintf(stderr, "Wrong Attribute Type!\n");
			if(dd){
				free(dd);
				dd = CNULL;
			}
			goto attrtype;
		}
	}    
#endif
	fprintf(stderr, "\n");

	return(dd);
}


static
Key *object() {
        char *dd;
	char *proc = "object";
	char name[64];
	char *newstring;
	Key  *newkey;
	KeyRef keyref;


        keyref = 0;
        if(!(dd = nxtpar(CNULL))) {
                fprintf(stderr, "Name or keyref: ");
                dd = aux_cpy_String(gets(name));
        }
        if(!dd || strlen(dd) == 0) keyref = -1;
        else sscanf(dd, "%d", &keyref);

	newkey = (Key *)calloc(1, sizeof(Key));
	if(!newkey) return(newkey);

        if(keyref != 0) {
                newkey->pse_sel = (PSESel *)0;
                newkey->keyref = keyref;
		free(dd);
        }
        else {
                newkey->pse_sel = aux_cpy_PSESel(&std_pse);
		if(newkey->pse_sel->object.name) free(newkey->pse_sel->object.name);
                newkey->pse_sel->object.name = dd;
                newkey->keyref = 0;
        }
	return(newkey);
}

static
char *nxtpar(search) 
char *search; 
{
        char *dd, *cc, *ret, *pp, *prm;
	char *proc = "nxtpar";

        int len_excl, len_incl, gl;
		/* len_incl: Argument-Laenge inklusive moeglicher Blanks */
		/* len_excl: Argument-Laenge ohne Blanks */
	int inword = 0;

        if(search) {
                dd = inp;
                while((dd = strchr(dd, '='))) {
                        cc = dd - 1;
                        *dd = '\0';
                        while(*cc && *cc != ' ') cc--;
                        cc++;
			ret = cc;
                        if(strncmp(search, cc, strlen(cc)) == 0) {
				*dd++ = '=';
                                pp = prm = (char *)malloc(64);
                                while (*dd && ( (*dd != ' ') || ((*dd == ' ') && inword) ) ) { 
					if (*dd == '"') {
						inword = 1 - inword;
						dd++;
					}
					else *pp++ = *dd++;
				} 
                                *pp = '\0';
				/* Remove keyword 'search' and parameter 'prm' from input line */
				while (ret < dd) {
					*ret++ = ' ';
				}
                                return(prm);
                        }
                        *dd++ = '=';
                }
                if(!strcmp(search, "pse") || !strcmp(search, "ppin")) return(CNULL);
        }
        dd = inp;
again:
        while(*dd && *dd == ' ') dd++;
        if(*dd) ret = dd;
        else return(CNULL);
        gl = FALSE;
	while (*dd && ( (*dd != ' ') || ((*dd == ' ') && inword) ) ) {
		if (*dd == '"') inword = 1 - inword;
                if ((*dd == '=') && !inword) gl = TRUE;
                dd++;
        }
        if (gl) goto again;
	len_incl = dd - ret;   
	if (*ret == '"') len_excl = dd - ret - 2;  /* Blanks vorne und hinten */ 
        else len_excl = len_incl;
        cc = (char *)malloc(len_excl+1);
 	if( !cc ) {
		aux_add_error(EMALLOC, "cc", CNULL, 0, proc);
		fprintf(stderr, "Can't allocate memory");
		return(CNULL);
	}
	if (*ret == '"') strncpy(cc, ret+1, len_excl);
        else strncpy(cc, ret, len_excl);
        cc[len_excl] = '\0';
        dd = ret;
        while (len_incl) {
                *dd++ = ' ';
                len_incl--;
        }
        return(cc);
}

static
char *strmtch(a, b)
char *a, *b;
{
	register char *aa, *bb;
	while(*a) {
		aa = a;
		bb = b;
		while(*aa) {
			if(*aa != *bb) break;
                        bb++;
			if(*bb == '\0') return(aa + 1);
                        aa++;
		}
		a++;   
	}
	return(CNULL);
}



static
off_t fsize(fd)
int fd;
{
        struct stat stat;
	char *proc = "fsize";


        if(fstat(fd, &stat) == 0) return(stat.st_size);
	aux_add_error(ESYSTEM, "fstat failed", CNULL, 0, proc);
        return(-1);
}


static 
CertificatePair *compose_CertificatePair()
{
	CertificatePair *cpair;
	OctetString     *ostr, octetstring;
	ObjId    	 object_oid;
	char            *proc = "compose_CertificatePair";

	if ( !(cpair = (CertificatePair *)malloc(sizeof(CertificatePair))) ) {
		aux_add_error(EMALLOC, "cpair", CNULL, 0, proc);
		return ((CertificatePair *)0);
	}
	cpair->forward = (Certificate *)0;
	cpair->reverse = (Certificate *)0;
	fprintf(stderr, "Composing the CrossCertificatePair...\n");

	fprintf(stderr, " PSE object containing forward certificate:\n");
	psesel(1);
	if (std_pse.object.name) {
		ostr = &octetstring;
		if(sec_read_PSE(&std_pse, &object_oid, ostr) < 0) {
			aux_add_error(EINVALID, "sec_read_PSE failed", (char *)&std_pse, PSESel_n, proc);
			return ((CertificatePair *)0);
		}
		if(aux_cmp_ObjId(&object_oid, SignCert_OID) && aux_cmp_ObjId(&object_oid, EncCert_OID) && aux_cmp_ObjId(&object_oid, Cert_OID)) { 
			aux_add_error(EINVALID, "Selected object on PSE is no certificate", (char *)&std_pse, PSESel_n, proc);
			free(ostr->octets);
			aux_free2_ObjId(&object_oid);
			return ((CertificatePair *)0);
                }	
		aux_free2_ObjId(&object_oid);
		if(!(cpair->forward = d_Certificate(ostr))) {
			aux_add_error(EDECODE, "Cannot decode forward certificate", CNULL, 0, proc);
			free(ostr->octets);
			return ((CertificatePair *)0);
                }
		free(std_pse.object.name);	
		free(ostr->octets);
	}

	fprintf(stderr, " PSE object containing reverse certificate:\n");
	psesel(1);
	if (std_pse.object.name) {
		ostr = &octetstring;
		if(sec_read_PSE(&std_pse, &object_oid, ostr) < 0) {
			aux_add_error(EINVALID, "sec_read_PSE failed", (char *)&std_pse, PSESel_n, proc);
			return ((CertificatePair *)0);
		}
		if(aux_cmp_ObjId(&object_oid, SignCert_OID) && aux_cmp_ObjId(&object_oid, EncCert_OID) && aux_cmp_ObjId(&object_oid, Cert_OID)) { 
			aux_add_error(EINVALID, "Selected object on PSE is no certificate", (char *)&std_pse, PSESel_n, proc);
			aux_free2_ObjId(&object_oid);
			free(ostr->octets);
			return ((CertificatePair *)0);
                }
		aux_free2_ObjId(&object_oid);
		if(!(cpair->reverse = d_Certificate(ostr))) {
			aux_add_error(EDECODE, "Cannot decode reverse certificate", CNULL, 0, proc);
			free(ostr->octets);
			return ((CertificatePair *)0);
                } 
		free(std_pse.object.name);   
		free(ostr->octets);
	}

	if (!cpair->forward && !cpair->reverse) {
		aux_add_error(EINVALID, "At least one component (forward or reverse) must be present", CNULL, 0, proc);
		return ((CertificatePair *)0);
	}

	return (cpair);
}



/* specify_CertificatePair() creates a CrossCertificatePair whose components
   (forward and reverse certificate) do only comprise a serial number and
   an issuer's distinguished name; this "incomplete" CrossCertificatePair
   universally identifies one "complete" CrossCertificatePair and is used to
   select that CrossCertificatePair by comparison */

static 
CertificatePair * specify_CertificatePair()
{
	CertificatePair * cpair = (CertificatePair * )0;
	char            * dd, * ptr, * number;
	char		* newstring;
	int		  serial;
	DName	        * issuer_dn;

	char *proc = "specify_CertificatePair";


	cpair = (CertificatePair *)malloc(sizeof(CertificatePair));
	if(! cpair){
		aux_add_error(EMALLOC, "cpair", CNULL, 0, proc);
		return ((CertificatePair *)0);
	}

	if (!(dd = nxtpar("for"))){
		fprintf(stderr, " Identify forward certificate:\n");
		fprintf(stderr, "   Serial number [CR, if forward certificate shall be empty]:  ");
		newstring = (char *)malloc(16);
		if(! newstring ){
			aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
               	number = gets(newstring);
		serial = atoi(number);
		free(newstring);
		newstring = CNULL;
               	if(strlen(number) == 0) 
			cpair->forward = (Certificate *)0;
		else{
			fprintf(stderr, "   ");
			issuer_dn = getdname("Issuer");
			if(! issuer_dn){
				aux_add_error(EINVALID, "Forward certificate insufficiently specified", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->forward = (Certificate *)malloc(sizeof(Certificate));
			if( !cpair->forward ) {
				aux_add_error(EMALLOC, "cpair->forward", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->forward->tbs = (ToBeSigned *)malloc(sizeof(ToBeSigned));
			if( !cpair->forward->tbs ) {
				aux_add_error(EMALLOC, "cpair->forward->tbs", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->forward->tbs->version = 0;
			cpair->forward->tbs->signatureAI = (AlgId *)0;
			cpair->forward->tbs->notbefore = (UTCTime *)0;
			cpair->forward->tbs->notafter = (UTCTime *)0;
			cpair->forward->tbs->subject = NULLDNAME;
			cpair->forward->tbs->subjectPK = (KeyInfo *)0;
			cpair->forward->tbs_DERcode = NULLOCTETSTRING;
			cpair->forward->sig = (Signature *)0;
			cpair->forward->tbs->serialnumber = serial;
			cpair->forward->tbs->issuer = aux_cpy_DName(issuer_dn);
			aux_free_DName(&issuer_dn);
		}
	}
	else {
		if (!strchr( dd, ',' )) {
			aux_add_error(EINVALID, "Forward certificate insufficiently specified", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->forward = (Certificate *)malloc(sizeof(Certificate));
		if(! cpair->forward) {
			aux_add_error(EMALLOC, "cpair->forward", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->forward->tbs = (ToBeSigned *)malloc(sizeof(ToBeSigned));
		if(! cpair->forward->tbs) {
			aux_add_error(EMALLOC, "cpair->forward->tbs", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->forward->tbs->version = 0;
		cpair->forward->tbs->signatureAI = (AlgId *)0;
		cpair->forward->tbs->notbefore = (UTCTime *)0;
		cpair->forward->tbs->notafter = (UTCTime *)0;
		cpair->forward->tbs->subject = NULLDNAME;
		cpair->forward->tbs->subjectPK = (KeyInfo *)0;
		cpair->forward->tbs_DERcode = NULLOCTETSTRING;
		cpair->forward->sig = (Signature *)0;
		ptr = strchr(dd, ',');
		*ptr = '\0';
		ptr++;
		cpair->forward->tbs->serialnumber = atoi(dd);
		dd = ptr;
		cpair->forward->tbs->issuer = aux_alias2DName(dd);
		if (! cpair->forward->tbs->issuer) incorrectName();
	}

	if (!(dd = nxtpar("rev"))){
		fprintf(stderr, " Identify reverse certificate:\n");
		fprintf(stderr, "   Serial number [CR, if reverse certificate shall be empty]:  ");
		newstring = (char *)malloc(16);
		if(! newstring ){
			aux_add_error(EMALLOC, "newstring", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
               	number = gets(newstring);
		serial = atoi(number);
		free(newstring);
		newstring = CNULL;
               	if(strlen(number) == 0) 
			cpair->reverse = (Certificate *)0;
		else{
			fprintf(stderr, "   ");
			issuer_dn = getdname("Issuer");
			if(! issuer_dn){
				aux_add_error(EINVALID, "Reverse certificate insufficiently specified", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->reverse = (Certificate *)malloc(sizeof(Certificate));
			if( !cpair->reverse ) {
				aux_add_error(EMALLOC, "cpair->reverse", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->reverse->tbs = (ToBeSigned *)malloc(sizeof(ToBeSigned));
			if( !cpair->reverse->tbs ) {
				aux_add_error(EMALLOC, "cpair->reverse->tbs", CNULL, 0, proc);
				return ((CertificatePair *)0);
			}
			cpair->reverse->tbs->version = 0;
			cpair->reverse->tbs->signatureAI = (AlgId *)0;
			cpair->reverse->tbs->notbefore = (UTCTime *)0;
			cpair->reverse->tbs->notafter = (UTCTime *)0;
			cpair->reverse->tbs->subject = NULLDNAME;
			cpair->reverse->tbs->subjectPK = (KeyInfo *)0;
			cpair->reverse->tbs_DERcode = NULLOCTETSTRING;
			cpair->reverse->sig = (Signature *)0;
			cpair->reverse->tbs->serialnumber = serial;
			cpair->reverse->tbs->issuer = aux_cpy_DName(issuer_dn);
			aux_free_DName(&issuer_dn);
		}
	}
	else {
		if (!strchr( dd, ',' )) {
			aux_add_error(EINVALID, "Reverse certificate insufficiently specified", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->reverse = (Certificate *)malloc(sizeof(Certificate));
		if(! cpair->reverse) {
			aux_add_error(EMALLOC, "cpair->reverse", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->reverse->tbs = (ToBeSigned *)malloc(sizeof(ToBeSigned));
		if(! cpair->reverse->tbs) {
			aux_add_error(EMALLOC, "cpair->reverse->tbs", CNULL, 0, proc);
			return ((CertificatePair *)0);
		}
		cpair->reverse->tbs->version = 0;
		cpair->reverse->tbs->signatureAI = (AlgId *)0;
		cpair->reverse->tbs->notbefore = (UTCTime *)0;
		cpair->reverse->tbs->notafter = (UTCTime *)0;
		cpair->reverse->tbs->subject = NULLDNAME;
		cpair->reverse->tbs->subjectPK = (KeyInfo *)0;
		cpair->reverse->tbs_DERcode = NULLOCTETSTRING;
		cpair->reverse->sig = (Signature *)0;
		ptr = strchr(dd, ',');
		*ptr = '\0';
		ptr++;
		cpair->reverse->tbs->serialnumber = atoi(dd);
		dd = ptr;
		cpair->reverse->tbs->issuer = aux_alias2DName(dd);
		if (! cpair->reverse->tbs->issuer) incorrectName();
	}

	return (cpair);
}


static incorrectName()
{
	fprintf(stderr, "Unknown user\n");
	return(0);
}



static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

	fprintf(stderr, "psemaint: Maintain PSE\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'psemaint' is a maintenance program which can be used by both\n");
	fprintf(stderr, "certification authority administrators and users for the purpose\n");
	fprintf(stderr, "of maintaining their PSEs. This includes moving information (e.g. keys,\n");
	fprintf(stderr, "certificates, revocation lists etc.) from Unix files or a X.500 Directory\n");
	fprintf(stderr, "into the PSE and vice versa, generating keys, changing PINs and displaying\n"); 
	fprintf(stderr, "the content of the PSE.\n\n\n");

        fprintf(stderr, "usage:\n\n");
#ifdef X500
	fprintf(stderr, "psemaint [-htvACFRDTVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-f <notbefore>] [-l <notafter>]\n");
	fprintf(stderr, "         [-i <inputfile>] [-d <dsa name>] [-A <authlevel>] [cmd]\n");
#else 
	fprintf(stderr, "psemaint [-htvCFRDTVW] [-p <pse>] [-c <cadir>] [-a <issueralg>] [-f <notbefore>] [-l <notafter>]\n");
	fprintf(stderr, "         [-i <inputfile>] [cmd]\n");
#endif   

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>        PSE name (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>          Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-i <inputfile>      Scriptfile containing the commands to be executed by 'psemaint'\n");
	fprintf(stderr, "-a <issueralg>      CA's signature algorithm (default: md2WithRsaEncryption)\n");
	fprintf(stderr, "-f <notbefore>      First date on which the certificate is valid\n");
	fprintf(stderr, "                    (evaluated by 'certify' command within 'psemaint')\n");
	fprintf(stderr, "-l <notafter>       Last date on which the certificate is valid\n");
	fprintf(stderr, "                    (evaluated by 'certify' command within 'psemaint')\n");
	fprintf(stderr, "-F                  consider own FCPath as trusted\n");
	fprintf(stderr, "-R                  consult PEM revocation lists during verification\n");
	fprintf(stderr, "-C                  show list of commands available with 'psemaint'\n");
	fprintf(stderr, "-D                  access Directory (X.500 or .af-db)\n");
#ifdef SCA
        fprintf(stderr, "-T                  perform each public key RSA operation in the smartcard  terminal\n");
        fprintf(stderr, "                    instead of employing the software in the workstation (the latter is the default)\n");
#endif
        fprintf(stderr, "-h                  write this help text\n");
	fprintf(stderr, "-t                  control malloc/free behaviour\n");
        fprintf(stderr, "-v                  verbose\n");
        fprintf(stderr, "-V                  Verbose\n");
        fprintf(stderr, "-W                  Grand Verbose (for testing only)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>       Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-A <authlevel>      Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                    <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                    (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                    STRONG implies the use of signed DAP operations\n");
#endif
	fprintf(stderr, "<cmd>               Single command that shall be executed by 'psemaint'\n");
	fprintf(stderr, "                    (otherwise, commands can be provided interactively\n");
 	fprintf(stderr, "                    or are read from file <inputfile> (see option -i))\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM PSEMAINT */
}    



int
new_SerialNumbers()
{
	SerialNumbers serialnums;

	char * proc = "new_SerialNumbers";


	serialnums.initial = 1;
	serialnums.actual = 194;
	if(af_pse_update_SerialNumbers(&serialnums) < 0){
		aux_add_error(EWRITEPSE, "af_pse_update_SerialNumbers failed", CNULL, 0, proc);
		return(-1);
	}

	return(serialnums.actual);
}


static int
check_if_number(number)
char * number;
{
	int len, i;

	len = strlen(number);
	for(i = 0; i < len; i++){
		if(!isdigit(number[i])){
			fprintf(stderr, "'%c' is not a digit[0-9]!\n", number[i]);
			return(-1);
		}
	}
	return(0);
}
