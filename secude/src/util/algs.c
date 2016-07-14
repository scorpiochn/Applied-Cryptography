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
extern unsigned mindex, allsize;

#include <stdio.h>
#include "secure.h"

#define DIRMASK 0755
#define OBJMASK 0644

int quantity = 102400;

char            *clearoctets;
char            *encryptedbits;
char            *recoveredoctets;


static char	*strmtch();
static HashInput *build_hashinput();
static KeyInfo	*getkey();
static void	usage(), print_alginfo(), print_headline(), check_testkeys_PSE();
static int	time_signverify(), test_alg(), time_encdec(), time_hash();
static int      time_keygen(), putkeys();

int		keysizes[128] = {512, 640, 768, 1024, 0};
char            RSA_PK_name[16] = "RSA-PK-";
char            RSA_SK_name[16] = "RSA-SK-";
char            DSA_PK_name[16] = "DSA-PK-";
char            DSA_SK_name[16] = "DSA-SK-";
PSESel          psesel;
char		psename[256];
char           *pseobject;

char            verbose = FALSE;
Boolean         use = FALSE;
Boolean         generate = FALSE;

main(cnt, parm)
	int             cnt;
	char          **parm;
{
	extern char    *optarg;
	extern int      optind, opterr;
	char           *cmd = *parm, opt;
	char           *keyword = CNULL, *algname = CNULL, samealg[64];
	int             n, i, j, rc = 0, multiple;
	Boolean         all = FALSE;
	AlgType         type = OTHER_ALG, t;
	AlgList         *a;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;
	n = 0;

nextopt:
	while ((opt = getopt(cnt, parm, "s:a:k:l:vVthUG")) != -1) switch (opt) {
		case 's':
			for(t = SYM_ENC; t <= SIG; t++) if (strcasecmp(optarg, algtype_name[t]) == 0) {
				type = t;
				break;
			}
			if(!type) keyword = optarg;
			continue;
		case 'a':
			algname = optarg;
			continue;
		case 'k':
			optind--;
			while (optind < cnt) {
				if(*parm[optind] == '-') goto nextopt;
				keysizes[n++] = atoi(parm[optind++]);

				multiple = 64;
				if(algname) if(aux_Name2AlgEnc(algname) == RSA) multiple = 8;				
				if(keysizes[n-1] % multiple) {
					fprintf(stderr, "Keysize must be a multiple of %d\n", multiple);
					exit(-1);
				}
				if(keysizes[n-1] < MIN_ASYM_KEYSIZE) {
					fprintf(stderr, "Keysize must be not smaller than %d\n", MIN_ASYM_KEYSIZE);
					exit(-1);
				}
				if(keysizes[n-1] > MAX_ASYM_KEYSIZE) {
					fprintf(stderr, "Keysize must be not greater than %d\n", MAX_ASYM_KEYSIZE);
					exit(-1);
				}
			}
			continue;
		case 'l':
			quantity = atoi(optarg) * 1024;
			continue;
		case 'v':
			verbose = TRUE;
			continue;
		case 'V':
			verbose = TRUE;
			sec_verbose = TRUE;
			continue;
		case 't':
			MF_check = TRUE;
			continue;
		case 'h':
			usage(LONG_HELP);
			continue;
		case 'U':
			sec_time = TRUE;
			use = TRUE;
			continue;
		case 'G':
			generate = TRUE;
			continue;
		default:
			usage(SHORT_HELP);
	}

	if(use) {
		clearoctets = (char *)malloc(quantity);
		encryptedbits = (char *)malloc(quantity + 1024);
		recoveredoctets = (char *)malloc(quantity + 1024);
		for (n = 0; n < quantity; n++) clearoctets[n] = (n % 96) + 32;
	}

/*
 *	Check whether .testkeys can be opened/created and is not a smartcard application
 */

	check_testkeys_PSE();

/*
 *	Main loop. It selects the algorithms according to options -s and -a and calls
 *      -   test_alg if use == TRUE (option -U) or generate == TRUE (option -G)
 *      -   print_alginfo otherwise
 */

	for (t = SYM_ENC; t <= SIG; t++) { /* loop over the alg types */

		if (type && type != t) continue;

		for (i = 0; alglist[i].name; i++) { /* loop over all algs */

			a = &alglist[i];
/* if(a->alghash == SQMODN) continue; */

			/*
 			 *	Select algorithms according to option -a, -s
 			 */

			if (t != a->algtype) continue; /* requested algtype doesn't match */
			if(a->alghash == SQMODN) continue; /* sqmodn has some problem */
			if (algname && strcmp(a->name, algname)) continue; /* requested algorithm doesn't match */
			if (keyword && !strmtch(a->name, keyword)) continue; /* requested keyword doesn't match */
			print_headline(t);
			/* check whether we had this algorithm already (OIDs are distinguished) */
			if(!algname) {
				for (j = 0; j < i ; j++) {
					if(aux_cmp_ObjId(a->algid->objid, alglist[j].algid->objid) == 0) {
						sprintf(samealg, "Same algorithm as %s", alglist[j].name);
						print_alginfo(a, samealg, 0,0,0,0,0,0,0);
						break;
					}
				}
				if(j < i) continue;
			}
			if(use || generate) {
				if(test_alg(a) < 0) rc = -1;
			}
			else print_alginfo(a, "", 0,0,0,0,0,0,0);
			if(MF_check && verbose) fprintf(stderr, "mindex = %d, allsize = %d\n", mindex, allsize);
		}
	}
	exit(rc);
}


static
int test_alg(a)

AlgList *a;

{
	int  n, rc = 0, rc1;
	char *pk, *sk;

/*	test_alg tests a single algorithm. It performs
 *	-   time_signverify for each requested keysize in case of a SIG alg,
 *	-   time_encdec for each requested keysize in case of an ASYM_ENC alg,
 *      -   time_encdec in case of a SYM_ENC alg,
 *	-   time_hash in case of a HASH alg,
 *	-   time_genkey in case of an ASYM_ENC alg, if key generation was requested (opion -G)
 */

	switch (a->algtype) {

	case SIG:
	case ASYM_ENC:

		n = 0;
		while(keysizes[n]) { /* Loop over 512, 640, ... */

			if(use) {
				switch (a->algenc) {
				case RSA:
					sprintf(&RSA_PK_name[7], "%d", keysizes[n]);
					sprintf(&RSA_SK_name[7], "%d", keysizes[n]);
					pk = RSA_PK_name;
					sk = RSA_SK_name;
					break;
				case DSA:
					if(keysizes[n] < 512 || keysizes[n] > 1024) {
						fprintf(stderr, "Can't DSA with keysize %d\n", keysizes[n]);
						continue;
					}
					sprintf(&DSA_PK_name[7], "%d", keysizes[n]);
					sprintf(&DSA_SK_name[7], "%d", keysizes[n]);
					pk = DSA_PK_name;
					sk = DSA_SK_name;
					break;
				}
		
				if(a->algtype == ASYM_ENC) {
					if(a->algenc == DSA) {
						print_alginfo(a, "Irreversible (can't encrypt/decrypt, see SIG for time)",0,0,0,0,0,0,0);
						break;
					}
					else if((rc1 = time_encdec(a, pk, sk, keysizes[n])) < 0) rc = -1;
				}
				if(a->algtype == SIG) 
					if(time_signverify(a, sk, pk, keysizes[n]) < 0) rc = -1;
			}

			/*
 			 *	If algtype == ASYM_ENC and generate == TRUE (key generation requested with option -G) 
 			 *      and keys are not already newly generated (rc1 = 0), generate keys
 			 */

			if(!rc1 && a->algtype == ASYM_ENC && generate) if(time_keygen(a, CNULL, CNULL, keysizes[n]) < 0) rc = -1;
			n++;
		}
		break;
	case SYM_ENC:
		if(!use) break;
		if(time_encdec(a, CNULL, CNULL, 0) < 0) rc = -1;
		break;

	case HASH:
		if(!use) break;
		rc = time_hash(a);
		break;

	}
	return(rc);
}

static
int time_signverify(a, sk, pk, keysize)

AlgList *a;
char *sk, *pk;
int keysize;

{
	Signature sign_signature;
	HashInput *hashinput;
	Key  key_sk, key_pk;
	OctetString ostr;
	struct timeval total_tp1, total_tp2;
	struct timezone total_tzp1, total_tzp2;
	long total_sec, total_usec;
	int rc = 0;

/*	time_signverify reads an asymmetric key pair (sk, pk) of alg a
 *	and performs a signature and verification operation with time measurement.
 *	If the key pair doesn't exist, it is created.
 *      It calls print_alginfo with the measured times.
 */

	ostr.octets    = clearoctets;
	ostr.noctets   = quantity;
	key_sk.keyref = 0;
	key_pk.keyref = 0;
	key_sk.pse_sel = (PSESel *)0;
	key_pk.pse_sel = (PSESel *)0;

/*
 *	Read keys. Generate new keys, if they don't exist
 */

	if(!(key_sk.key = getkey(sk))) {
		if(verbose) fprintf(stderr, "%s and %s don't exist. Generating ...\n", sk, pk);
		if(time_keygen(a, sk, pk, keysize) < 0) return(-1);
		if(!(key_sk.key = getkey(sk))) return(-1);
	}
	if(!(key_pk.key = getkey(pk))) {
		fprintf(stderr, "Can't read %s\n", pk);
		aux_free_KeyInfo(&key_sk.key);
		return(-1);
	}
	if(a->alghash == SQMODN) hashinput = build_hashinput(key_pk.key);
	else hashinput = (HashInput *)0;

	key_sk.alg = a->algid;
	sign_signature.signAI = (AlgId *)0;

/*
 * 	test signature time
 */

	gettimeofday(&total_tp1, &total_tzp1);

	if (sec_sign(&ostr, &sign_signature, END, &key_sk, hashinput) < 0) {
		fprintf(stderr, "Sign with %s failed\n", sk); 
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		aux_free_KeyInfo(&key_sk.key);
		aux_free_KeyInfo(&key_pk.key);
		return(-1);
	}
	gettimeofday(&total_tp2, &total_tzp2);

	total_usec = (total_tp2.tv_sec - total_tp1.tv_sec) * 1000000 + total_tp2.tv_usec - total_tp1.tv_usec;
	total_sec = total_usec/1000000;
	total_usec = total_usec % 1000000;
	aux_free_KeyInfo(&key_sk.key);
	print_alginfo(a, "Sign", keysize, rsa_sec + dsa_sec, rsa_usec + dsa_usec, hash_sec, hash_usec, total_sec, total_usec);

/*
 * 	test verification time
 */

	gettimeofday(&total_tp1, &total_tzp1);

	if (sec_verify(&ostr, &sign_signature, END, &key_pk, hashinput) < 0) {
		fprintf(stderr, "Verify with %s failed\n", pk); 
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		aux_free2_Signature(&sign_signature);
		aux_free_KeyInfo(&key_pk.key);
		return(-1);
	}
	gettimeofday(&total_tp2, &total_tzp2);

	total_usec = (total_tp2.tv_sec - total_tp1.tv_sec) * 1000000 + total_tp2.tv_usec - total_tp1.tv_usec;
	total_sec = total_usec/1000000;
	total_usec = total_usec % 1000000;
	print_alginfo(a, "Veri", keysize, rsa_sec + dsa_sec, rsa_usec + dsa_usec, hash_sec, hash_usec, total_sec, total_usec);
	aux_free2_Signature(&sign_signature);
	aux_free_KeyInfo(&key_pk.key);
	return(0);
}

static
int time_encdec(a, pk, sk, keysize)

AlgList *a;
char *sk, *pk;
int keysize;

{

/*	In case of an ASYM_ENC alg, time_encdec reads an asymmetric key pair (sk, pk) of alg a 
 *	and performs an encryption and decryption operation with time measurement.
 *	If the key pair doesn't exist, it is created.
 *
 *	In case of a SYM_ENC alg, time_encdec creates a symmetric key for alg a 
 *	and performs an encryption and decryption operation with time measurement.
 *
 *      It calls print_alginfo with the measured times.
 *
 *	time_encdec returns 0 if successful and did not generate keys,
 *                          1 if successful and generated keys;
 *                         -1 if not successful
 */

	Key  key;
	OctetString orig, recov;
	KeyInfo keyinfo;
	BitString bstr;
	int rc = 0, i;

	/* keysize 0 indicates symmetric algorithm, keysize > 0 indicates asymmetric algorithm */

	orig.octets    = clearoctets;
	orig.noctets   = (keysize ? keysize/16 : quantity);   /* half keysize fits into a 
                                                                  PKCS#2 block anayway */
	bstr.bits      = encryptedbits;
	bstr.nbits     = 0;

	key.keyref = 0;
	key.pse_sel = (PSESel *)0;

	rsa_sec = des_sec = rsa_usec = des_usec = 0;

	if(a->algtype == ASYM_ENC) {
		/* for encryption read public key from PSE .testkeys */
		if(!(key.key = getkey(pk))) {
			if(verbose) fprintf(stderr, "%s and %s don't exist. Generating ...\n", pk, sk);
			if(time_keygen(a, sk, pk, keysize) < 0) return(-1);
			if(!(key.key = getkey(pk))) return(-1);
			rc = 1; 
		}
		key.alg = a->algid;
	}
	else {
		/* generate symmetric key */
		key.key = &keyinfo;
		key.key->subjectAI = a->algid;
		key.alg = (AlgId *)0;
	
		if(sec_gen_key(&key, FALSE) < 0) {
			fprintf(stderr, "Generation of sym key failed for %s\n", a->name);
			if(verbose) aux_fprint_error(stderr, 0);
			aux_free_error();
			return(-1);
		}
	}


/*
 * 	test encryption time
 */

	if (sec_encrypt(&orig, &bstr, END, &key) < 0) {
		fprintf(stderr, "Encrypt with %s failed\n", sk); 
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		aux_free2_KeyInfo(key.key);
		return(-1);
	}
	print_alginfo(a, "Encr", keysize, rsa_sec + des_sec, rsa_usec + des_usec, 0, 0, 0, 0);

/*
 * 	test decryption time
 */

	if(a->algtype == ASYM_ENC) {
		/* for decryption read secret key from PSE .testkeys */
		aux_free_KeyInfo(&(key.key));
		if(!(key.key = getkey(sk))) return(-1);
		key.alg = a->algid;
	}
	recov.noctets = 0;
	recov.octets  = recoveredoctets;
	if (sec_decrypt(&bstr, &recov, END, &key) < 0) {
		fprintf(stderr, "Decrypt with %s failed\n", a->name); 
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		aux_free2_KeyInfo(key.key);
		return(-1);
	}
	if(a->algtype == ASYM_ENC) aux_free_KeyInfo(&(key.key));
	else aux_free2_KeyInfo(key.key);

	/* whether we can recover the cleartext */
	for (i = 0; i < orig.noctets; i++) if(orig.octets[i] != recov.octets[i]) {
		fprintf(stderr, "encryption/decryption error\n");
		break;
	}
	print_alginfo(a, "Decr", keysize, rsa_sec + des_sec, rsa_usec + des_usec, 0, 0, 0, 0);

	return(0);
}

static
int time_hash(a)

AlgList *a;

{
	OctetString ostr, hash_result;
	KeyInfo *keyinfo;
	HashInput *hashinput;

	ostr.octets    = clearoctets;
	ostr.noctets   = quantity;
	hash_result.octets  = encryptedbits;
	hash_result.noctets = 0;

	if(a->alghash == SQMODN) {
		if(!(keyinfo = getkey("RSA-PK-512"))) {
			fprintf(stderr, "Can't get public key for %s\n", a->name);
			return(-1);
		}
		hashinput = build_hashinput(keyinfo);
	}
	else hashinput = (HashInput *)0;


/*
 * 	test hash time
 */

	if (sec_hash(&ostr, &hash_result, END, a->algid, hashinput) < 0) {
		fprintf(stderr, "Hash with %s failed\n", a->name); 
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		if(a->alghash == SQMODN) aux_free_KeyInfo(&keyinfo);
		return(-1);
	}
	if(a->alghash == SQMODN) aux_free_KeyInfo(&keyinfo);
	print_alginfo(a, "Hash", 0, hash_sec, hash_usec, 0, 0, 0, 0);

	return(0);
}

static
int time_keygen(a, sk, pk, keysize)

AlgList *a;
char *sk, *pk;
int keysize;

{
	BitString *skey, *pkey;
	struct timeval total_tp1, total_tp2;
	struct timezone total_tzp1, total_tzp2;
	long total_sec, total_usec;
	int rc;


/*
 * 	test key generation time
 */

	gettimeofday(&total_tp1, &total_tzp1);

	switch(a->algenc) {
		case RSA: 
			rc = rsa_gen_key(keysize, &skey, &pkey);
			break;
		case DSA:
			rc = dsa_gen_key(keysize, &skey, &pkey);
			break;
	}


	gettimeofday(&total_tp2, &total_tzp2);

	if(rc == 0) {
		if(pk) putkeys(a, sk, pk, skey, pkey, keysize); /* store newly generated keys */ 
		total_usec = (total_tp2.tv_sec - total_tp1.tv_sec) * 1000000 + total_tp2.tv_usec - total_tp1.tv_usec;
		total_sec = total_usec/1000000;
		total_usec = total_usec % 1000000;
		print_alginfo(a, "KGen", keysize, total_sec, total_usec, 0, 0, 0, 0);
	}
	else fprintf(stderr, "Key generation failed for %s (keysize %d)\n", a->name, keysize);

	free(skey->bits);
	free(pkey->bits);

	return(rc);
}



/*
 *      getkey(name)
 *      reads a keyinfo from PSE 
 */

static
KeyInfo  *getkey(name)

char *name;

{
	OctetString     ostr;
	ObjId           obj_id;
	KeyInfo        *keyinfo;

	psesel.object.name = name;

	if (sec_read_PSE(&psesel, &obj_id, &ostr) < 0) {
		aux_free_error();
		return ((KeyInfo *)0);
	}
	if (!(keyinfo = d_KeyInfo(&ostr))) {
		fprintf(stderr, "Can't decode %s\n", name);
		if(verbose) aux_fprint_error(stderr, 0);
		aux_free_error();
		free(ostr.octets);
		aux_free2_ObjId(&obj_id);
		return ((KeyInfo *)0);
	}
	aux_free2_ObjId(&obj_id);
	free(ostr.octets);

	return (keyinfo);
}

static
int putkeys(a, sk, pk, skey, pkey, keysize)

AlgList *a;
char *sk, *pk;
BitString *skey, *pkey;
int keysize;
{

	OctetString    *ostr;
	ObjId          *objid;
	KeyInfo		keyinfo;
	extern	ObjId  *RSA_SK_OID, *RSA_PK_OID, *DSA_SK_OID, *DSA_PK_OID;
	int i;

	for(i = 0; i < 2; i++) {
		if(i == 0) {
			psesel.object.name = sk;
			keyinfo.subjectkey.nbits = skey->nbits;
			keyinfo.subjectkey.bits = skey->bits;
		}
		else {
			psesel.object.name = pk;
			keyinfo.subjectkey.nbits = pkey->nbits;
			keyinfo.subjectkey.bits = pkey->bits;
		}
		switch(a->algenc) {
			case RSA:
				if(i == 0) objid = RSA_SK_OID;
				else objid = RSA_PK_OID;
				keyinfo.subjectAI = rsa;
				*(rsa_parm_type *)keyinfo.subjectAI->parm = keysize;
				break;
			case DSA:
				if(i == 0) objid = DSA_SK_OID;
				else objid = DSA_PK_OID;
				keyinfo.subjectAI = dsa;
				break;
		}
	
		if (!(ostr = e_KeyInfo(&keyinfo))) {
			fprintf(stderr, "Can't encode %s\n", sk);
			if(verbose) aux_fprint_error(stderr, 0);
			aux_free_error();
			return (-1);
		}
	
	
		if (sec_create(&psesel) < 0) {
			if(aux_last_error() != ECREATEOBJ) {
				fprintf(stderr, "Can't create %s\n", sk);
				if(verbose) aux_fprint_error(stderr, 0);
				aux_free_error();
				aux_free_OctetString(&ostr);
				return (-1);
			}
			aux_free_error();
		}
		if (sec_write_PSE(&psesel, objid, ostr) < 0) {
			fprintf(stderr, "Can't write %s\n", sk);
			if(verbose) aux_fprint_error(stderr, 0);
			aux_free_error();
			aux_free_OctetString(&ostr);
			return (-1);
		}
		strcpy(pseobject, psesel.object.name);
		chmod(psename, OBJMASK);
		strcpy(pseobject, "Toc");
		chmod(psename, OBJMASK);
	}
	return(0);
}


/*
 *      print name, action and time for a specified algorithm
 */

static
void print_alginfo(a, string, keysize, sec1, usec1, sec2, usec2, sec3, usec3)

AlgList *a;
char	*string;
int 	keysize;
long	sec1, usec1, sec2, usec2, sec3, usec3;

{
	static char lastname[64];
	static char dashline[128];
	char *aa;
	AlgType t;
	AlgId *aid;
	int paramchoice, n;
	rsa_parm_type  *rsa_parm;
	desCBC_parm_type *des_parm;

	if(!dashline[0]) for(n = 0; n < 85; n++) dashline[n] = '-';
	if(strncmp(string, "KGen", 4)) t = a->algtype;
	else t = ASYM_ENC;
	aid = a->algid;

	if (strcmp(a->name, lastname)) {
		if(use || generate) fprintf(stderr, "%s\n", dashline);
		fprintf(stderr, "%-21s", a->name);
		if(strncmp(string, "Sam", 3)) {
			fprintf(stderr, "OID ");
			aux_fprint_ObjId(stderr, aid->objid);
			if (aid->parm) {
				switch (paramchoice = aux_ObjId2ParmType(a->algid->objid)) {
		
				case PARM_INTEGER:
					rsa_parm = (rsa_parm_type *) (aid->parm);
					fprintf(stderr, "Parameter Keysize (default %d)\n", *rsa_parm);
					break;
		
				case PARM_OctetString:
					des_parm = (desCBC_parm_type *) (aid->parm);
					fprintf(stderr, "Parameter DES-IV (default zeros)\n");
					break;
				default:
					fprintf(stdout, "?? Unidentified parameter:\n");
					break;
				}
			} 
			else {
				switch (paramchoice = aux_ObjId2ParmType(aid->objid)) {
				case PARM_NULL:
					fprintf(stderr, "NULL parameter\n");
					break;
				case PARM_ABSENT:
					fprintf(stderr, "No parameter\n");
					break;
				}
			}
			if(!strlen(string)) return;
		}
		if(!strncmp(string, "Sam", 3)) {
			fprintf(stderr, "%s\n", string);
			return;
		}
		if(!strncmp(string, "Irr", 3)) {
			fprintf(stderr, "%-21s%s\n", "", string);
			return;
		}
		strcpy(lastname, a->name);
	}


	if(sec1 || usec1) {
		fprintf(stderr, "%-21s%s ", "", string);
		switch(t) {
		case SIG:
			fprintf(stderr, "(%4d bits): ", keysize);
			fprintf(stderr, "%3ld.%03ld (total),", sec3, usec3/1000);
			fprintf(stderr, "%3ld.%03ld (%s),", sec1, usec1/1000, algenc_name[a->algenc]);
			fprintf(stderr, "%3ld.%03ld (%s)  \n", sec2, usec2/1000, alghash_name[a->alghash]);
			break;
		case ASYM_ENC:
			fprintf(stderr, "(%4d bits): %3ld.%03ld  \n", keysize, sec1, usec1/1000);
			break;
		case SYM_ENC:
			fprintf(stderr, "(%d Kbytes): %3ld.%03ld  \n", quantity/1024, sec1, usec1/1000);
			break;
		case HASH:
			fprintf(stderr, "(%d Kbytes): %3ld.%03ld  \n", quantity/1024, sec1, usec1/1000);
			break;
		}
	}
}

static
char *strmtch(a, b)
	char           *a, *b;
{
	char           *aa, *bb, cc, dd;

	if(!b || ! *b) return(CNULL);
	while (*a) {
		aa = a;
		bb = b;
		while (*aa) {
			cc = *aa;
			if (cc >= 'A' && cc <= 'Z') cc += 0x20;
			dd = *bb;
			if (dd >= 'A' && dd <= 'Z') dd += 0x20;
			if (cc != dd) break;
			bb++;
			if (*bb == '\0') return (aa + 1);
			aa++;
		}
		a++;
	}
	return (CNULL);
}


static
void print_headline(t)
AlgType t;
{
	char headline[64];
	int n;
	static int old;

	if(t != old) {
		old = t;
		sprintf(headline, "%s Algorithms", algtype_name[t]);
		fprintf(stderr, "\n%s\n", headline);
		for (n = 0; n < strlen(headline); n++) fprintf(stderr, "=");
		fprintf(stderr, "\n");
	}
}


static
HashInput *build_hashinput(keyinfo)
KeyInfo *keyinfo;
{
	static HashInput hashinput;

	hashinput.sqmodn_input.nbits = keyinfo->subjectkey.nbits;
	hashinput.sqmodn_input.bits = keyinfo->subjectkey.bits;
	return(&hashinput);
}

static
void check_testkeys_PSE()
{
	if(sec_sctest(TESTKEYS_PSE)) {
		fprintf(stderr, "%s must not be defined as smartcard application\n", TESTKEYS_PSE);
		exit(-1);
	}
	psesel.app_name = TESTKEYS_PSE;
	psesel.pin = "";
	psesel.object.name = CNULL;
	psesel.object.pin = "";
	if(sec_open(&psesel) < 0) if(sec_create(&psesel) < 0) {
		fprintf(stderr, "Can't create PSE %s\n", TESTKEYS_PSE);
		if(verbose) aux_fprint_error(stderr, 0);
		exit(-1);
	}
	chmod(TESTKEYS_PSE, DIRMASK);
	strcpy(psename, TESTKEYS_PSE);
	strcat(psename, "/");
	pseobject = psename + strlen(psename);
	strcpy(pseobject, "Toc");
	chmod(psename, OBJMASK);
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "algs  Information about algorithms\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "algs [-UGvVth] [-a] [<name>] [-s] [<keyword>] [-k] [<k1> <k2> ... ] [-l] [<quantity>]\n\n");

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-a <name>        Selects a single algorithm with name <name>\n");
        fprintf(stderr, "-s <keyword>     Selects groups of algorithms. Either one of the AlgTypes (SYM_ENC, ASYM_ENC,\n"); 
        fprintf(stderr, "                 HASH, SIG) which selects all algorithms of the given type, or a string\n");
        fprintf(stderr, "                 which is contained in an algorithm name.\n");
        fprintf(stderr, "-U               Show performance times of algorithms for sign, verify, encrypt, decrypt\n");
        fprintf(stderr, "                 and hash, depending on the algorithm type:\n");
        fprintf(stderr, "                 Signature algorithms: Total, asymmetric encryption and hash time for\n");
        fprintf(stderr, "                           signing and verifying a given quantity with different\n");
        fprintf(stderr, "                           keysizes (parameter -k). Asymmetric keys are generated\n");
        fprintf(stderr, "                           and stored in PSE $(TOP)/lib/.testkeys afterwards if not available\n");
        fprintf(stderr, "                 Asymetric Encryption algorithms: Encryption and decryption of a block\n");
        fprintf(stderr, "                           with different keysizes (parameter -k). Asymmetric keys are generated\n");
        fprintf(stderr, "                           and stored in PSE $(TOP)/lib/.testkeys afterwards if not available\n");
        fprintf(stderr, "                 Symmetric Encryption algorithms: Encryption of a 100 K quantity\n");
        fprintf(stderr, "                 Hash algorithms: Hashing of a given quantity\n");
        fprintf(stderr, "-G               Show key generation times of asymmetric algorithms with\n");
        fprintf(stderr, "                 different keysizes (parameter -k). Needs time!\n");
        fprintf(stderr, "-k <k1> <k2> ... Use keysizes k1, k2, ... (default: 512, 640, 756, 1024)\n");
        fprintf(stderr, "-l <quantity>    Quantity to be signed or hashed in K bytes (default: 100)\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-t               Control malloc/free behaviour\n");
        fprintf(stderr, "-h               Write this help text\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM ALGS */
}

