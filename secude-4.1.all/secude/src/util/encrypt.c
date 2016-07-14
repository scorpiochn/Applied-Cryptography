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

/*-----------------------encrypt.c----------------------------------*/
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
/*   This is a MAIN program to encrypt/decrypt files                */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  sec_encrypt(), sec_decrypt(),sec_read(), sec_get_key(),         */
/*  sec_string_to_key()                                             */
/*                                                                  */
/*                                                                  */
/*------------------------------------------------------------------*/

#define DESKEY 1
#define STRING 0
#define ENCRYPT 1
#define DECRYPT 2
#include <stdio.h>
#include <fcntl.h>
#include "af.h"

#define BUFSIZE 8192
char *getpass();

Key key, deskey;
PSESel pse_sel;
KeyInfo keyinfo;
int verbose = 0;
int mode;
static void     usage();
long  a_rsa_sec, a_rsa_usec, a_des_sec, a_des_usec;

char buf[BUFSIZE+128], outbuf[BUFSIZE+128];


main(cnt, parm) 
int cnt;
char **parm; 
{
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
        char *strmtch();
        char *buf1, *buf2, *bb, ckey[16], *inputkey = (char *)0, *pin = CNULL, *file;
        char *object = CNULL, *psename = CNULL, *psepath = NULL, *cadir = NULL, *cert = CNULL;
        char *plainfile = CNULL, *encryptedfile = CNULL, *keyfile = CNULL, *infile = CNULL, *outfile = CNULL, *encfile = CNULL;
        int i, j, in,  type = STRING, hex = FALSE, hybrid = TRUE;
        int fd_in = 0, fd_out = 1, fd_key, out, ret, rest, nfiles = 0, nf, optfiles = 0;
        int c, ct, aind = FALSE, oind = FALSE, keyref = 0, keyopt = FALSE;
	AlgId *desAlgId = desCBC;

#ifdef X500
	int              dsap_index;
	char           * callflag;
	char	       * env_auth_level;
#endif

        char *recipient = CNULL;
        DName *dname;
        AlgEnc alg;
        More more;
        BitString in_bits, out_bits;
        OctetString in_octets, out_octets, *ostr, octetstring;
        EncryptedKey encryptedkey;
        KeyInfo tmpkey, * kinfo;
        ObjId object_oid;
        Certificate *certificate;
        rsa_parm_type *rsaparm;
        unsigned int blocksize;
	int SCapp_available = FALSE;

	Boolean onekeypaironly, access_pse = TRUE;

#ifdef X500
	af_access_directory = FALSE;
#endif

	sec_time = FALSE;

        if(strmtch(parm[0], "encrypt")) mode = ENCRYPT;
        else mode = DECRYPT;

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
	while ( (opt = getopt(cnt, parm, "k:c:w:d:p:r:e:E:A:nxvDVWtTUh")) != -1 ) switch(opt) {
#else
	while ( (opt = getopt(cnt, parm, "k:c:w:p:r:e:E:nxvDVWtTUh")) != -1 ) switch(opt) {
#endif
                case 'E':
                        desAlgId = aux_Name2AlgId(optarg);
			if(!desAlgId) p_error(cmd, "unknown algorithm name in option -e", "");
                        continue;
                case 'x':
                        hex = TRUE;
                        continue;
                case 'n':
                        hybrid = FALSE;
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
                case 'p':
			if (psename) usage(SHORT_HELP);
			else psename = optarg;
                        continue;
                case 'e':
                        if(keyopt) p_error(cmd, "Only one of the options -k, -r, -e, or -w allowed", "");
                        keyopt = TRUE;
                        type = DESKEY;
			access_pse = FALSE;
                        inputkey = optarg;
			hybrid = FALSE;
                        continue;
                case 'w':                                                         
                        if(keyopt) p_error(cmd, "Only one of the options -k, -r, -e, or -w allowed", "");
                        keyopt = TRUE;
                        type = STRING;
			access_pse = FALSE;
                        inputkey = optarg;
			hybrid = FALSE;
                        continue;
                case 'k':
                        if(keyopt) p_error(cmd, "Only one of the options -k, -r, -e, or -w allowed", "");
                        keyopt = TRUE;
                        bb = optarg;
			hybrid = FALSE;
                        while(*bb) {
                                if(*bb < '0' || *bb > '9') {
                                        object = optarg;
                                        break;
                                }
                                bb++;
                        }
                        if(!(*bb)) {
				sscanf(optarg, "%d", &keyref);
				access_pse = FALSE;
			}
                        continue;
		case 'c':
			cadir = optarg;
			continue;
                case 'r':
                        if(mode == DECRYPT) p_error(cmd, "-r not possible for decrypt", "");
                        if(keyopt) p_error(cmd, "Only one of the options -k, -c, -u, -d, or -w allowed", "");
                        keyopt = TRUE;
                        recipient = optarg;
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
#ifdef SCA
		case 'T':
			SC_encrypt = TRUE;
			continue;
#endif
                case 't':
                        MF_check = TRUE;
                        continue;
                case 'U':
                        sec_time = TRUE;
                        continue;
                default:
		case '?':
			if(! strcmp(parm[optind - 1], "-w") && ! inputkey) {
				keyopt = TRUE;
                        	type = STRING;
				access_pse = FALSE;
                        	inputkey = buf;
                        	strcpy(buf, getpass("Password: "));
                        	i = strlen(buf);
                        	for(j = i; j < 16; j++) buf[j] = '\0';
			}
			else usage(SHORT_HELP);
	}

	if (optind < cnt) {
		file = (char *)malloc(strlen(parm[optind]) + 16);
		strcpy(file, parm[optind]);
		if(mode == DECRYPT) {
			if(strcmp(file + strlen(file) - 4, ".enc")) strcat(file, ".enc");
			else parm[optind][strlen(parm[optind]) - 4] = '\0';
		}
		if(!optfiles) optfiles = optind;
		if ((fd_in = open(file, O_RDONLY)) <= 0) {
			if (verbose) aux_fprint_error(stderr, 0);
			fprintf(stderr, "Can't open %s\n", file);
		}
		else {
			close(fd_in);
			nfiles++;
		}
		free(file);
                optind++;
		goto nextopt;
        }
		

/*
 *      input/output files
 */

        if(!nfiles && hybrid) p_error(cmd, "Filename needed in hybrid mode (no filter mode)", "");


	if(access_pse || recipient) {
		/* If recipient is given, PSE is required for alias transformation */
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
	

		if (cadir) {
			pin = getenv("USERPIN");
		}
		else {
			pin = getenv("USERPIN");
		}

		if ( aux_create_AFPSESel(psepath, pin) < 0 ) {
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

		if(af_check_if_onekeypaironly(&onekeypaironly)){
			if(verbose) aux_fprint_error(stderr, 0);
			else aux_fprint_error(stderr, TRUE);
			exit(2);
		}

        	if(! keyopt) {
			if(onekeypaironly) {
                		if(mode == ENCRYPT) cert = Cert_name;
                		else object = SKnew_name;
			}
			else {
                		if(mode == ENCRYPT) cert = EncCert_name;
                		else object = DecSKnew_name;
			}
        	}

		pse_sel.app_name = AF_pse.app_name;
		pse_sel.object.name = CNULL;
		pse_sel.object.pin = AF_pse.pin;
		pse_sel.pin = AF_pse.pin;
		pse_sel.app_id = AF_pse.app_id;
	}



/*
 *      set up key structure
 */

        if(keyref || object) {
                key.keyref = keyref;
                key.key = (KeyInfo *)0;
                if(keyref){
			if(sec_get_key(&tmpkey, key.keyref, (Key *)0) < 0)
				p_error(cmd, "Cannot gey key", "");
			key.key = &tmpkey;
			key.pse_sel = (PSESel *)0;
		}
                else {
                        key.pse_sel = &pse_sel;
                        pse_sel.object.name = aux_cpy_String(object);
			ostr = &octetstring;

			if(key.pse_sel && (strcmp(key.pse_sel->object.name, SKnew_name) == 0 || strcmp(key.pse_sel->object.name, DecSKnew_name) == 0) ) {

				SCapp_available = sec_sctest(key.pse_sel->app_name);
#ifdef SCA
				if  (SCapp_available == -1) {
					if (aux_last_error() == EOPENDEV) 
						fprintf(stderr, "Cannot open device for SCT (No such device or device busy).\n");
					else	fprintf(stderr, "Error during SC configuration.\n");
					if(verbose) aux_fprint_error(stderr, 0);
					exit(-1);
				}
#endif
			}

			if (SCapp_available)
				key.alg = rsa;
			else {
				if(sec_read_PSE(key.pse_sel, &object_oid, ostr) < 0)
					p_error(cmd, "Unknown PSE object", "");
				if(!(kinfo = d_KeyInfo(ostr))) {
					if(!(certificate = d_Certificate(ostr))) p_error(cmd, "Can't decode KeyInfo", "");
					else {
						kinfo = aux_cpy_KeyInfo(certificate->tbs->subjectPK);
						aux_free_Certificate(&certificate);
					}
				}				
				key.key = kinfo;
				key.pse_sel = (PSESel *)0;
			}
                }
        }
        else if(cert) {
                key.keyref = 0;
                key.key = (KeyInfo *)0;
                key.pse_sel = &pse_sel;
                pse_sel.object.name = cert;
                ostr = &in_octets;
                if(sec_read_PSE(key.pse_sel, &object_oid, ostr) < 0) 
			p_error(cmd, "Unknown PSE object", "");
                if(!(certificate = d_Certificate(ostr))) 
			p_error(cmd, "Can't decode certificate", "");
                key.key = certificate->tbs->subjectPK;
                key.pse_sel = (PSESel *)0;
        }
        else if(recipient) {
                key.keyref = 0;
                key.pse_sel = (PSESel *)0;
                bb = aux_alias2Name(recipient);
		if(bb) recipient = bb;
                if(!(dname = aux_Name2DName(recipient))) 
			p_error(cmd, "Can't transform Name to DName: ", recipient);
                if(!(certificate = af_search_Certificate(ENCRYPTION, dname))) 
			p_error(cmd, "Can't find PK of ", recipient);
                key.key = certificate->tbs->subjectPK;
                key.pse_sel = (PSESel *)0;
        }
        else {

                /* this implies DES */
		
		key.pse_sel = (PSESel *)0;

                if(type == STRING) { /* this is option -w */
                        key.key = &keyinfo;
                        if(sec_string_to_key(inputkey, &key) < 0) p_error(cmd, err_stack->e_text, "");
                }
                else {
        
        	        if(hex) {
        		        for(i = 0; i < 16; i++) {
        			        if(htoa(inputkey[i]) == -1) p_error(cmd, "Non-hex character in key", "");
        	        	}
                		gethex(ckey, inputkey, 8);
                	} 
                        else {
        	        	strncpy(ckey, inputkey, 8);
        		        /* Set up key, determine parity bit 
        		        for(ct = 0; ct < 8; ct++) {
        			        c = 0;
        	        		for(i = 0; i < 7; i++) if(ckey[ct] & (1 << i)) c++;
        		        	if((c & 1) == 0) ckey[ct] |= 0x80;
        	        		else ckey[ct] &= ~0x80;
        	        	}                                    */
        	        }
 

                	while(*inputkey) *inputkey++ = '\0';


                        key.key = &keyinfo;
			key.key->subjectAI = desAlgId;
                        key.key->subjectkey.bits = ckey;
                        key.key->subjectkey.nbits = 64;
			key.alg = (AlgId *)0;
     
                }
        }


/*
 *      check algorithm
 */

	if(key.key != (KeyInfo *)0) {
		alg = aux_ObjId2AlgEnc(key.key->subjectAI->objid);

        	switch(alg) {
                	case RSA:
				/* in case of the hybrid method, use always rsaEncryption instead of rsa */
				if(hybrid) {
					key.alg = rsaEncryption;
				}
                        	break;
			case DES:
			case DES3:
				hybrid = FALSE;
				break;
                	default:
                        	p_error(cmd, "Key is not an encryption/decryption key", "");
        	}
	}

	nf = 0;
	if(!nfiles) goto filter; /* encrypt/decrypt used as a filter */

	for (nf = 0; nf < nfiles; nf++) { /* main loop over the input files */

                plainfile = parm[optfiles + nf];
                encryptedfile = (char *)malloc(strlen(plainfile) + 8);
                strcpy(encryptedfile, plainfile);
                strcat(encryptedfile, ".enc");
                if(mode == ENCRYPT) {
                        infile = plainfile;
                        outfile = encryptedfile;
                }
                else {
                        outfile = plainfile;
                        infile = encryptedfile;
                }
                if((fd_in = open(infile, O_RDONLY)) <= 0) {
			fprintf(stderr, "Can't open %s\n", infile);
			free(encryptedfile);
			continue;
		}
                if((fd_out = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0644)) <= 0) {
			fprintf(stderr, "Can't open %s\n", outfile);
			free(encryptedfile);
			close(fd_in);
			continue;
		}
/*
 *      Hybrid mode
 */

		if(hybrid) {
			keyfile = (char *)malloc(strlen(plainfile) + 8);
			strcpy(keyfile, plainfile);
			strcat(keyfile, ".key");
			deskey.keyref = 0;
			deskey.pse_sel = (PSESel *)0;
			deskey.key = (KeyInfo *)malloc(sizeof(KeyInfo));
			if(mode == ENCRYPT) {
	
				/* generate DES key */
	
				deskey.key->subjectAI = aux_cpy_AlgId(desAlgId);
				if(sec_gen_key(&deskey, TRUE) < 0) {
					aux_free_KeyInfo(&deskey.key);
					fprintf(stderr, "Can't generate DES key for %s\n", plainfile);
					if(verbose) aux_fprint_error(stderr, 0);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					close(fd_in);
					close(fd_out);
					continue;
				}
	
				/* encrypt DES key */
	
				key.alg = rsaEncryption;
				if(sec_get_EncryptedKey(&encryptedkey, &deskey, &key) < 0) {
					fprintf(stderr, "Can't encrypt DES key for %s\n", plainfile);
					if(verbose) aux_fprint_error(stderr, 0);
					if(encryptedkey.encryptionAI) aux_free_AlgId(&encryptedkey.encryptionAI);
					if(encryptedkey.subjectAI) aux_free_AlgId(&encryptedkey.subjectAI);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					close(fd_in);
					close(fd_out);
					continue;
				}
	
				/* write encrypted DES key to <plainfile>.key */
	
				if(!(ostr = e_EncryptedKey(&encryptedkey))) {
					fprintf(stderr, "Can't encode encrypted key for %s\n", plainfile);
					if(encryptedkey.encryptionAI) aux_free_AlgId(&encryptedkey.encryptionAI);
					if(encryptedkey.subjectAI) aux_free_AlgId(&encryptedkey.subjectAI);
					if(encryptedkey.subjectkey.bits) free(encryptedkey.subjectkey.bits);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					close(fd_in);
					close(fd_out);
					continue;
				}
				if(encryptedkey.encryptionAI) aux_free_AlgId(&encryptedkey.encryptionAI);
				if(encryptedkey.subjectAI) aux_free_AlgId(&encryptedkey.subjectAI);
				if(encryptedkey.subjectkey.bits) free(encryptedkey.subjectkey.bits);
	
				if(aux_OctetString2file(ostr, keyfile, 2) < 0) {
					fprintf(stderr, "Can't create or write %s\n", keyfile);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					aux_free_OctetString(&ostr);
					close(fd_in);
					close(fd_out);
					continue;
				}
				key.key->subjectkey.bits = deskey.key->subjectkey.bits;
				key.key->subjectkey.nbits = deskey.key->subjectkey.nbits;
				key.key->subjectAI = desAlgId;
				key.alg = desAlgId;
			}
			else {
	
				/* read encrypted DES key from <plainfile>.key */
	
				if(!(ostr = aux_file2OctetString(keyfile))) {
					fprintf(stderr, "Can't read %s\n", keyfile);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					close(fd_in);
					close(fd_out);
					continue;
				}
				if(d2_EncryptedKey(ostr, &encryptedkey) < 0) {
					fprintf(stderr, "Can't BER-decode encrypted key from %s\n", keyfile);
					if(hybrid) free(keyfile);
					free(encryptedfile);
					aux_free_OctetString(&ostr);
					close(fd_in);
					close(fd_out);
					continue;
				}
				aux_free_OctetString(&ostr);
	
				/* decrypt DES key */
	
				key.alg = rsaEncryption;
				if(sec_put_EncryptedKey(&encryptedkey, &deskey, &key, TRUE) < 0) {
					if(hybrid) free(keyfile);
					free(encryptedfile);
					fprintf(stderr, "Can't decrypt encryption key from %s\n", keyfile);
					if(encryptedkey.encryptionAI) aux_free_AlgId(&encryptedkey.encryptionAI);
					if(encryptedkey.subjectAI) aux_free_AlgId(&encryptedkey.subjectAI);
					if(encryptedkey.subjectkey.bits) free(encryptedkey.subjectkey.bits);
					close(fd_in);
					close(fd_out);
					continue;
				}
				if(encryptedkey.encryptionAI) aux_free_AlgId(&encryptedkey.encryptionAI);
				if(encryptedkey.subjectAI) aux_free_AlgId(&encryptedkey.subjectAI);
				if(encryptedkey.subjectkey.bits) free(encryptedkey.subjectkey.bits);
				key.key = &keyinfo;
				key.key->subjectkey.bits = deskey.key->subjectkey.bits;
				key.key->subjectkey.nbits = deskey.key->subjectkey.nbits;
				key.key->subjectAI = deskey.key->subjectAI;
				key.pse_sel = (PSESel *)0;
				key.keyref = 0;
			}
		}
	
	
/*
 *      	set blocksize if alg == RSA
 */

filter:
		key.alg = (AlgId *)0;
		if(SCapp_available && !hybrid) { /* SCapp_available = TRUE implies RSA */
			blocksize = 63;
			alg = RSA;
		}
		else {
			alg = aux_ObjId2AlgEnc(key.key->subjectAI->objid);
			if(alg == RSA) blocksize = (RSA_PARM(key.key->subjectAI->parm) - 1) / 8;
		}
	
	
/*
 *      	read input file and encrypt/decrypt to output file 
 */
	
		switch(mode) {
			case ENCRYPT:
				out_bits.bits = outbuf;
				buf1 = buf;
				buf2 = &buf[BUFSIZE/2];
				rest = 0;
				in = read(fd_in, buf1, BUFSIZE / 2);
				bb = buf2;
				while(in) {
					in_octets.noctets = in;
					if(alg == RSA) rest = (in + rest) % blocksize;
					in = read(fd_in, bb, BUFSIZE / 2);
					if(bb == buf1) in_octets.octets = bb = buf2;
					else in_octets.octets = bb = buf1;
					if(in > 0) more = MORE;
					else {
						if(alg == RSA) {
							if(rest) {
lastrsa:                                        		/* add bytecount as DES does */
								in_octets.octets[in_octets.noctets + blocksize - rest - 1] = rest;
								in_octets.noctets += (blocksize - rest);
								more = END;
							}
							else more = MORE;
						}
						else more = END;
					}
					out_bits.nbits = 0;
					if((out = sec_encrypt(&in_octets, &out_bits, more, &key)) < 0) {
						fprintf(stderr, "encryption of %s failed\n", infile);
						if(verbose) aux_fprint_error(stderr, 0);
						goto endfile;
					}
					if(write(fd_out, out_bits.bits, out / 8) <= 0) {
						fprintf(stderr, "Can't write %s\n", encryptedfile);
						goto endfile;
					}
					if(alg == RSA && rest == 0 && in <= 0 && more == MORE) {
						in_octets.noctets = 0;
						goto lastrsa;
					}
				}
				break;
			case DECRYPT:
				out_octets.octets = outbuf;
				buf1 = buf;
				buf2 = &buf[BUFSIZE/2];
				in = read(fd_in, buf1, BUFSIZE / 2);
				bb = buf2;
				while(in) {
					in_bits.nbits = in * 8;
					in = read(fd_in, bb, BUFSIZE / 2);
					if(bb == buf1) in_bits.bits = bb = buf2;
					else in_bits.bits = bb = buf1;
					if(in > 0) more = MORE;
					else more = END;
					out_octets.noctets = 0;
					if((out = sec_decrypt(&in_bits, &out_octets, more, &key)) < 0) {
						fprintf(stderr, "decryption of %s failed\n", infile);
						if(verbose) aux_fprint_error(stderr, 0);
						goto endfile;
					}
					if(alg == RSA && more == END) {
						/* check bytecount */
						rest = out_octets.octets[out_octets.noctets - 1];
						out -= (blocksize - rest);
					}
	
					write(fd_out, out_octets.octets, out);
				}
				break;
		} 
		if(infile) unlink(infile);
		if(!infile) infile = "stdin";
		if(!outfile) outfile = "stdout";
		if(mode == ENCRYPT) {
			if(!hybrid) fprintf(stderr, "%s encrypted --> %s\n", infile, outfile);
			else fprintf(stderr, "%s encrypted --> %s, %s\n", infile, outfile, keyfile);
		}
		else {
			if(!hybrid) fprintf(stderr, "%s decrypted --> %s\n", infile, outfile);
			else fprintf(stderr, "%s, %s decrypted --> %s\n", keyfile, infile, outfile);
		}
		if(mode == DECRYPT && hybrid) unlink(keyfile);
	
		if(sec_time) {
			a_des_usec = (a_des_sec + hash_sec) * 1000000 + a_des_usec + des_usec;
			a_des_sec = a_des_usec/1000000;
			a_des_usec = a_des_usec % 1000000;
			a_rsa_usec = (a_rsa_sec + rsa_sec) * 1000000 + a_rsa_usec + rsa_usec;
			a_rsa_sec = a_rsa_usec/1000000;
			a_rsa_usec = a_rsa_usec % 1000000;
		}
endfile:
		if(hybrid) free(keyfile);
		free(encryptedfile);
		close(fd_in);
		close(fd_out);
	}
	if(MF_check) MF_fprint(stderr);
	if(sec_time) {
		des_usec = des_usec/1000;
		rsa_usec = rsa_usec/1000;
		fprintf(stderr, "Time used for des computation: %ld.%03ld sec\n", des_sec, des_usec);
		fprintf(stderr, "Time used for rsa computation:  %ld.%03ld sec\n", rsa_sec, rsa_usec);
	}

        exit(0);
}

/* Convert hex/ascii nybble to binary */
int
htoa(c)
char c;
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return 10 + c - 'a';
	if(c >= 'A' && c <= 'F') return 10 + c - 'A';
	return -1;
}
/* Convert bytes from hex/ascii to binary */
gethex(result,cp,ct)
register char *result;
register char *cp;
register int ct;
{
	while(ct-- != 0){
		*result = htoa(*cp++) << 4;
		*result++ |= htoa(*cp++);
	}

	return(0);
}


static
void usage(help)
int     help;

{

	aux_fprint_version(stderr);

	if (mode == ENCRYPT) {

        	fprintf(stderr, "encrypt:  Encrypt Files\n\n\n");
		fprintf(stderr, "Description:\n\n"); 
		fprintf(stderr, "'encrypt' encrypts the given <files>. It uses algorithms and keys according\n");
		fprintf(stderr, "to the parameter -k or -w or -r or -w. Not more than one of these parameters\n");
		fprintf(stderr, "must be given (default: key and alg from PSE-object Cert/EncCert). For each\n");
		fprintf(stderr, "file in <files> it encrypts from file to file.enc and removes file.\n");
		fprintf(stderr, "'encrypt' also works as a filter from stdin to stdout.\n\n\n");

       		fprintf(stderr, "usage:\n\n");
#ifdef X500
#ifdef SCA
		fprintf(stderr, "encrypt [-DnxvVWtTU] [-k <key>] [-r <recipient>] [-w <pw>] [-e <deskey>] \n");
#else
		fprintf(stderr, "encrypt [-DnxvVWtU] [-k <key>] [-r <recipient>] [-w <pw>] [-e <deskey>] \n");
#endif
		fprintf(stderr, "        [-E <encalg>] [-p <pse>] [-c <cadir>] [-d <dsa>] [-A <auth-level>]\n");
		fprintf(stderr, "        [<files>]\n\n");
#else
#ifdef SCA
		fprintf(stderr, "encrypt [-nxvVWtTU] [-k <key>] [-r <recipient>] [-w <pw>] [-e <deskey>] \n");
#else
		fprintf(stderr, "encrypt [-nxvVWtU] [-k <key>] [-r <recipient>] [-w <pw>] [-e <deskey>] \n");
#endif
		fprintf(stderr, "        [-E <encalg>] [-p <pse>] [-c <cadir>] [<files>]\n\n");
#endif

        	if(help == LONG_HELP) {

       		fprintf(stderr, "with:\n\n");
      		fprintf(stderr, "(not more than one of the parameters -k, -e, -w and -r must be given. If none of these four\n");
      		fprintf(stderr, " parameters is given, the file is symmetrically (default: desCBC) encrypted with a newly \n");
      		fprintf(stderr, " generated DES key, and the DES key is asymmetrically encrypted with the own encryption key\n");
      		fprintf(stderr, " (Cert/EncCert). This is called the hybrid method.)\n\n");
        	fprintf(stderr, "-k <object/ref>  PSE-object (containing either a certificate or a key) or key reference \n");
        	fprintf(stderr, "                 of encryption key. Default: Cert/EncCert. If this key is an asymmetric\n");
        	fprintf(stderr, "                 key, the hybrid method is used.\n");
        	fprintf(stderr, "-e <key>         DES key for desCBC encryption.\n");
        	fprintf(stderr, "-x               If given, <key> of parameter -e must be a 16 character string\n");
        	fprintf(stderr, "                 denoting the key in a [0-9, A-F] notation. Otherwise it must be\n");
        	fprintf(stderr, "                 an 8 character string comprising the key itself.\n");
        	fprintf(stderr, "-w               8 character password which is transformed into a DES key with a\n");
        	fprintf(stderr, "                 one-way function, for desCBC encryption.\n");
       		fprintf(stderr, "-r               Intended recipient (alias allowed). Search encryption key of this recipient\n");
                fprintf(stderr, "                 in EKList/PKList. If not given, encrypt with own encryption key. This\n");
                fprintf(stderr, "                 implies the hybrid method\n");
       		fprintf(stderr, "-n               Don't use the hybrid method in case of an asymmetric key. Do asymmetric\n");
                fprintf(stderr, "                 encryption of the whole file (not recommendable for larger files)\n");
#ifdef X500
        	fprintf(stderr, "-D               Search public encryption key in the Directory if it cannot\n");
        	fprintf(stderr, "                 be found in EKList/PKList of the PSE\n");
        	fprintf(stderr, "-d <dsa>         Name of the DSA to be accessed for retrieving the public encryption key\n");
        	fprintf(stderr, "-A <auth_level>  Level of authentication in case of X.500 Directory access. <auth-level>\n");
        	fprintf(stderr, "                 may be SIMPLE or STRONG (default: environment variable AUTHLEVEL, or NONE, if\n");
        	fprintf(stderr, "                 this does not exist). STRONG implies the use of signed DAP operations\n");
#endif
        	fprintf(stderr, "-E <encalg>      Use algorithm encalg instead of desCBC for the file encryption. <encalg>\n");
        	fprintf(stderr, "                 must be a symmetric algorithm\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for tests only)\n");
        	fprintf(stderr, "-t               Control malloc/free behaviour\n");
#ifdef SCA
        	fprintf(stderr, "-T               Perform each public key RSA operation in the smartcard  terminal\n");
        	fprintf(stderr, "                 instead of employing the software in the workstation (the latter is the default)\n");
#endif
       		fprintf(stderr, "-U               Show time used for cryptographic algorithms\n");
        	fprintf(stderr, "-h               Write this help text\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        	fprintf(stderr, "-c <cadir>       name of CA-directory (default: Environment variable CADIR or .ca)\n");
        	fprintf(stderr, "<files>          Filenames\n");
        	}
	}
	else {
        	fprintf(stderr, "decrypt:  Decrypt Files\n\n\n");
		fprintf(stderr, "Description:\n\n"); 
		fprintf(stderr, "'decrypt' decrypts the given <files>. It uses algorithms and keys according\n");
		fprintf(stderr, "to the parameter -k or -w or -r or -w. Not more than one of these parameters\n");
		fprintf(stderr, "must be given (default: key and alg from PSE-object SKnew/DecSKnew). For each\n");
		fprintf(stderr, "file in <files> it decrypts from file.enc to file and removes file.enc.\n");
		fprintf(stderr, "'decrypt' also works as a filter from stdin to stdout.\n\n\n");

       		fprintf(stderr, "usage:\n\n");
		fprintf(stderr, "decrypt [-nxvVWtU] [-k <key>] [-w <pw>] [-e <deskey>] \n");
		fprintf(stderr, "        [-E <encalg>] [-p <pse>] [-c <cadir>] [<files>]\n\n");

        	if(help == LONG_HELP) {

       		fprintf(stderr, "with:\n\n");
      		fprintf(stderr, "(not more than one of the parameters -k, -e and -w must be given. If none of these three\n");
      		fprintf(stderr, " parameters is given, the file is symmetrically (default: desCBC) decrypted with the key from \n");
      		fprintf(stderr, " <file>.sig which will be asymmetrically decrypted before with the own decryption key\n");
      		fprintf(stderr, " (SKnew/DecSKnew). This is called the hybrid method.)\n\n");
        	fprintf(stderr, "-k <object/ref>  PSE-object (containing a KeyInfo) or key reference \n");
        	fprintf(stderr, "                 of decryption key. Default: SKnew/DecSKnew. If this key is an asymmetric\n");
        	fprintf(stderr, "                 key, the hybrid method is used.\n");
        	fprintf(stderr, "-e <key>         DES key for desCBC decryption.\n");
        	fprintf(stderr, "-x               If given, <key> of parameter -e must be a 16 character string\n");
        	fprintf(stderr, "                 denoting the key in a [0-9, A-F] notation. Otherwise it must be\n");
        	fprintf(stderr, "                 an 8 character string comprising the key itself.\n");
        	fprintf(stderr, "-w               8 character password which is transformed into a DES key with a\n");
        	fprintf(stderr, "                 one-way function, for desCBC decryption.\n");
       		fprintf(stderr, "-n               Don't use the hybrid method in case of an asymmetric key. Do asymmetric\n");
                fprintf(stderr, "                 decryption of the whole file\n");
        	fprintf(stderr, "-E <decalg>      Use algorithm decalg instead of desCBC for the file decryption. <decalg>\n");
        	fprintf(stderr, "                 must be a symmetric algorithm\n");
        	fprintf(stderr, "-v               verbose\n");
        	fprintf(stderr, "-V               Verbose\n");
        	fprintf(stderr, "-W               Grand Verbose (for tests only)\n");
        	fprintf(stderr, "-t               Control malloc/free behaviour\n");
       		fprintf(stderr, "-U               Show time used for cryptographic algorithms\n");
        	fprintf(stderr, "-h               Write this help text\n");
        	fprintf(stderr, "-p <psename>     PSE name (default: Environment variable PSE or .pse)\n");
        	fprintf(stderr, "-c <cadir>       name of CA-directory (default: Environment variable CADIR or .ca)\n");
        	fprintf(stderr, "<files>          Filenames\n");
        	}
	}

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM ENCRYPT */
}









p_error(t1, t2, t3)
char *t1, *t2, *t3;
{
        fprintf(stderr, "%s", t1);
        if(t2 && strlen(t2)) fprintf(stderr, ": %s", t2);
        if(t3 && strlen(t3)) fprintf(stderr, " %s", t3);
        fprintf(stderr, "\n");
	if(verbose) aux_fprint_error(stderr, FALSE);
        exit(-1);
}

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

