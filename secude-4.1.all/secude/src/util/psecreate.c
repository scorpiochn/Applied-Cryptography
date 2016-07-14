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
 *      psecreate
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include "cadb.h"

#define SIGNKEY "signature"
#define ENCKEY "encryption"

int             verbose = 0;
static void     usage();


main(cnt, parm)
int	cnt;
char	**parm;
{
	PSESel	        pse;
        int             rc, i;
	int	        keysize[2];
	char	        line[256];
	AlgId           *algorithm = DEF_SUBJECT_SIGNALGID, *sig_alg = DEF_ISSUER_ALGID;
	AlgId           *s_algorithm = DEF_SUBJECT_SIGNALGID, *e_algorithm = DEF_SUBJECT_SIGNALGID;
        ObjId           *oid = NULLOBJID, *sig_oid = NULLOBJID;
        PSESel          *pse_sel;
	Name            *afname;
	DName		*af_dname;
	PSEToc          *psetoc;
	Key             key;
	KeyInfo         keyinfo;
	Certificate     *cert, *signcert;
	OctetString     *newcert, *ostr;
	extern char	*optarg;
	extern int	optind, opterr;
	KeyType         ktype = SIGNATURE;
	char	        *cmd = *parm, opt, *pin, *keytype;
	char	        *psename = CNULL, *psepath = CNULL;
        char            *pkrootfile;
        PKRoot          *pkroot;
	Boolean         onekeypaironly = TRUE;
	int             SCapp_available;


	char 		*proc = "main (psecreate)";

	pse.app_name = CNULL;
	pse.pin	 = CNULL;
	pse.object.name = CNULL;
	pse.object.pin = CNULL;
	pse.app_id = 0;
	psename	 = getenv("PSE");
	afname	 = getenv("MYDNAME");
	keysize[0] = keysize[1] = DEFKEYLEN;

	optind = 1;
	opterr = 0;

	MF_check = FALSE;

nextopt:
	while ( (opt = getopt(cnt, parm, "s:e:k:p:hqtvVW")) != -1 ) {
		switch (opt) {
		case 's':
                        oid = aux_Name2ObjId(optarg);
                        if(aux_ObjId2AlgType(oid) != ASYM_ENC && aux_ObjId2AlgType(oid) != SIG)
				usage(SHORT_HELP);
			s_algorithm = aux_ObjId2AlgId(oid);
			if(aux_Name2AlgEnc(optarg) == RSA) sig_alg = aux_cpy_AlgId(md2WithRsaEncryption);
			if(aux_Name2AlgEnc(optarg) == DSA) sig_alg = aux_cpy_AlgId(dsaWithSHA);
			ktype = SIGNATURE;
			break;
		case 'e':
			oid = aux_Name2ObjId(optarg);
                        if (aux_ObjId2AlgType(oid) != ASYM_ENC) usage(SHORT_HELP);
			e_algorithm = aux_ObjId2AlgId(oid);
			ktype = ENCRYPTION;
			break;
                case 'k':
			keysize[ktype] = atoi(optarg);
			if(ktype == SIGNATURE && aux_ObjId2AlgEnc(s_algorithm->objid) == DSA) sec_dsa_keysize = keysize[ktype];
			if ( (keysize[ktype] < MINKEYLEN) || (keysize[ktype] > MAXKEYLEN)) usage(SHORT_HELP);
			break;
		case 'p':
			psename = optarg;
			break;
                case 'q':
                        onekeypaironly = FALSE;
			keytype = SIGNKEY;
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
		afname = parm[optind++];
		goto nextopt;
	}

        if(!psename) psename = DEF_PSE;

        psepath = (char *)malloc(strlen(psename)+2);
        strcpy(psepath, psename);

	if((aux_ObjId2AlgType(s_algorithm->objid) != ASYM_ENC) && (onekeypaironly == TRUE)){
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Wrong AlgType for a PSE which shall hold one keypair only");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

        pin = getenv("USERPIN");
	if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	accept_alias_without_verification = TRUE;
        if(!afname) { /* read owner's DN from stdin */
again:
                fprintf(stderr, "%s: Distinguished name of PSE owner: ", cmd);
                line[0] = '\0';
                gets(line);
                afname = line;
		if(!(af_dname = aux_alias2DName(afname))) {
                        fprintf(stderr, "%s: Invalid distinguished name\n", cmd);
                        goto again;
                }
                if(!(ostr = e_DName(af_dname))) {
                        fprintf(stderr, "%s: Invalid distinguished name\n", cmd);
                        goto again;
                }
        }
        else {
		af_dname = aux_alias2DName(afname);
		ostr = e_DName(af_dname);
		if(! ostr && verbose == TRUE){
			aux_fprint_error(stderr, 0);
			exit(-1);
		}
	}
	if ((optind < cnt) || !afname || !ostr ) usage(SHORT_HELP);

	af_dname = d_DName(ostr);
	aux_free_OctetString(&ostr);

        pse.app_name = psename;
        pse.pin      = getenv("USERPIN");


	if((SCapp_available = sec_sctest(pse.app_name)) == -1) {
		if (aux_last_error() == EOPENDEV) 
			fprintf(stderr, "Cannot open device for SCT (No such device or device busy)\n");
		else	fprintf(stderr, "Error during SC configuration.\n");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (SCapp_available == TRUE) {
/*		name = aux_DName2Attr(af_dname, "CN");*/
		fprintf(stderr, "    Please insert smartcard of %s\n", afname);
	}

	/*
	 *  Set global flag "sec_onekeypair" used in function "sec_create"
	 */

	sec_onekeypair = onekeypaironly;

	/* create new PSE */

	if ( sec_create(&pse) < 0) {
                fprintf(stderr, "%s: ", cmd);
		if (SCapp_available == TRUE) 
			fprintf(stderr, "Application on smartcard exists already\n");
		else 	fprintf(stderr, " %s\n", err_stack->e_text);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

        /* create and install PSE object Name */

	AF_pse.app_id = pse.app_id;
	if ( aux_create_AFPSESel(pse.app_name, pse.pin) < 0 ) {
		fprintf(stderr, "%s: ",cmd);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	if (af_pse_update_Name(af_dname) < 0) {
                fprintf(stderr, "%s: ", cmd);
		fprintf(stderr, "unable to create Name on PSE\n");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}


	algorithm = s_algorithm;
	keytype = SIGNKEY;

genkey:

	key.keyref = 0;
	key.pse_sel = (PSESel * ) 0;
	key.key = &keyinfo;

	keyinfo.subjectAI = aux_cpy_AlgId(algorithm);
        if(aux_ObjId2ParmType(algorithm->objid) != PARM_NULL)
	             *(int *)(keyinfo.subjectAI->parm) = keysize[ktype];

        if(verbose) fprintf(stderr, "%s: Generating %s key pair (Algorithm %s)\n        for <%s> with PSE %s ...\n", cmd, keytype, aux_ObjId2Name(algorithm->objid), aux_DName2Name(af_pse_get_Name()), psepath);
	
        if(verbose) sec_verbose = TRUE;
        else sec_verbose = FALSE;

	rc = af_gen_key(&key, ktype, FALSE);

	if (rc < 0)       {            
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Can't generate new keys\n");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}
	else if(verbose) fprintf(stderr, "%s: Key generation (%s) O.K.\n", cmd, keytype);

	if(onekeypaironly == TRUE)
		cert = af_create_Certificate(&keyinfo, sig_alg, SKnew_name, (DName *)0);
	else {
		if ( ktype == SIGNATURE )
			cert = af_create_Certificate(&keyinfo, sig_alg, SignSK_name, (DName *)0);
		else
			cert = af_create_Certificate(&keyinfo, sig_alg, DecSKnew_name, (DName *)0);
	}

	if (!cert)       { 
		fprintf(stderr, "%s: ",cmd);
	        fprintf(stderr, "Can't create prototype certificate\n");
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
	        fprintf(stderr, "Can't write prototype certificate to PSE\n");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1); 
	}

	if(onekeypaironly == FALSE && ktype == SIGNATURE) {
		signcert = cert;
		ktype = ENCRYPTION;
		algorithm = e_algorithm;
		keytype = ENCKEY;
		goto genkey;
	}
	if(onekeypaironly) signcert = cert;

	/* Create PKRoot from prototype certificate in Cert  */

	pkroot = (PKRoot *)calloc(1, sizeof(PKRoot));
	if(!pkroot) {
		fprintf(stderr, "Can't allocate memory");
		exit(-1);
	}

	pkroot->ca = aux_cpy_DName(signcert->tbs->subject);
	pkroot->newkey = (struct Serial *)calloc(1, sizeof(struct Serial));
	if(!pkroot->newkey) {
		fprintf(stderr, "Can't allocate memory");
		aux_free_PKRoot(&pkroot);
		exit(-1);
	}
	pkroot->newkey->serial = 0;
	pkroot->newkey->key = aux_cpy_KeyInfo(signcert->tbs->subjectPK);

	if(af_pse_update_PKRoot(pkroot) < 0) {
		fprintf(stderr, "%s: ",cmd);
                fprintf(stderr, "can't write PKRoot to PSE\n");
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}

	exit(0);
}




static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

        fprintf(stderr, "psecreate: Create User PSE\n\n\n");
	fprintf(stderr, "Description:\n\n");
	fprintf(stderr, "'psecreate'  creates a User PSE with one or two asymmetric keypairs on it,\n");
	fprintf(stderr, "whose public keys are held within self-signed prototype certificates.\n\n\n");

        fprintf(stderr, "usage:\n\n");
        fprintf(stderr,"psecreate [-hqtvVW] [-p <pse>] [-s <signalg>] [-k <keysize>] [-e <encalg>] [-k <keysize>] [Name]\n\n"); 


        if(help == LONG_HELP) {
        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <pse>         PSE name (default: Environment variable PSE or .pse)\n");
	fprintf(stderr, "-s <signalg>     Signature algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>     Keysize of RSA signature key\n");
	fprintf(stderr, "-e <encalg>      Encryption algorithm (default: rsa)\n");
	fprintf(stderr, "-k <keysize>     Keysize of RSA encryption key\n");
	fprintf(stderr, "-q               create PSE that contains two RSA keypairs (default: one RSA keypair only)\n");
        fprintf(stderr, "-h               write this help text\n");
	fprintf(stderr, "-t               control malloc/free behaviour\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for testing only)\n");
	fprintf(stderr, "<Name>           Intended owner of the generated User PSE\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM PSECREATE */
}
