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

/*--------------------------hsh.c-----------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   util            VERSION   3.0                          */
/*                              DATE   06.02.1992                   */
/*                                BY   ws                           */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This is a MAIN program to hash files                           */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  sec_hash()                                                      */
/*                                                                  */
/*                                                                  */
/* USAGE:                                                           */
/*      hsh alg [-h hashinput] [-c cert] [-a alg] [-p psename]      */
/*              [file] [hash-result]                                */
/*------------------------------------------------------------------*/

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <fcntl.h>
#include "af.h"

PSESel pse_sel_hashinput;
KeyInfo key_hashinput;
HashInput hashinput;
BitString in_bits, out_bits;
OctetString in_octets, out_octets, *ostr, *in_ostr, hash_value;
char verbose = FALSE;

static void     usage();

main(cnt, parm) 
int cnt;
char **parm; 
{
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
        char *buf1, *buf2, *bb, *file = CNULL, *hash = CNULL;
        char *key = CNULL, *app = CNULL, *cert = CNULL;
        int i, j, in, fd_in = 0, fd_out = 1, out, rc, alg, rest;
        int c, keyref = 0;
        rsa_parm_type *rsaparm;
        unsigned int blocksize;
        AlgId *algid;
        ObjId *oid;
        More more;
	char *proc = "main (hsh)";

        pse_sel_hashinput.app_name = DEF_PSE;
        algid = md5;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;
	while ( (opt = getopt(cnt, parm, "a:H:c:p:vh")) != -1 ) switch(opt) {
                case 'H':
                        bb = optarg;
                        while(*bb) {
                                if(*bb < '0' || *bb > '9') {
                                        key = optarg;
                                        break;
                                }
                                bb++;
                        }
                        if(!(*bb)) sscanf(optarg, "%d", &keyref);
                        build_hashinput(keyref, key, cert);
                        continue;
                case 'p':
                        pse_sel_hashinput.app_name = optarg;
                        continue;
                case 'v':
                        verbose = TRUE;
                        continue;
                case 'h':
                        usage(LONG_HELP);
                        continue;
                case 'c':
                        cert = optarg;
                        build_hashinput(keyref, key, cert);
                        continue;
                case 'a':                                                         
                        oid = aux_Name2ObjId(optarg);
                        if(aux_ObjId2AlgType(oid) != HASH) {
				aux_add_error(EINVALID, "Algorithm unknown or not of type HASH", optarg, char_n, proc);
				if(verbose) aux_fprint_error(stderr, 0);
                                fprintf(stderr, "Algorithm %s unknown or not of type HASH\n", optarg);
				exit(-1);
                        }
                        algid = aux_ObjId2AlgId(oid);
                        continue;
                default:
		case '?':	
			usage(SHORT_HELP);
	}

	if (optind < cnt) {
                if(fd_in == 0) {
                        if((fd_in = open(parm[optind], O_RDONLY)) <= 0)  {
				aux_add_error(EINVALID, "Can't open", parm[optind], char_n, proc);
				if(verbose) aux_fprint_error(stderr, 0);
				p_error("Can't open", parm[optind]);
                        }
                        file = parm[optind];
                }
                else if(fd_out == 1) {
                        if((fd_out = open(parm[optind], O_WRONLY|O_CREAT|O_TRUNC, 0644)) <= 0) {
				aux_add_error(EINVALID, "Can't open", parm[optind], char_n, proc);
				if(verbose) aux_fprint_error(stderr, 0);
                                p_error("Can't open", parm[optind]);
                        }
                        hash = parm[optind];
                }
                optind++;
        }

endarg:

/*
 *      prepare hash file
 */

        if(file && !hash) {
                hash = (char *)malloc(strlen(file) + 8);
                if(!hash)  {
			aux_add_error(EMALLOC, "hash", 0, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't malloc", "");
                      }
                strcpy(hash, file);
                strcat(hash, ".hsh");
                if((fd_out = open(hash, O_WRONLY|O_CREAT|O_TRUNC, 0644)) <= 0)  {
			aux_add_error(EINVALID, "Can't open", hash, char_n, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't open", hash);
                }
        }


/*
 *      read input file and hash to output file 
 */

        in_ostr = aux_file2OctetString(file);
        if(!in_ostr) {
		aux_add_error(EINVALID, "Can't read inputfile", file, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		p_error("Can't read inputfile", "");
        }
        more = END;
        if((rc = sec_hash(in_ostr, &hash_value, more, algid, &hashinput)) < 0)  {
		aux_add_error(EINVALID, "Sign failed", 0, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		p_error("Sign failed: ", "");
        }
        write(fd_out, hash_value.octets, hash_value.noctets);
        close(fd_out);
        exit(0);
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "hsh:  Hash Filter\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'hsh' reads <file> and writes its hash value to <hash>. It uses the algorithm\n");
	fprintf(stderr, "given with parameter -a <alg>. <alg> is the name of an algorithm of type HASH.\n\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr, "hsh [-vh] [-a <alg>] [-H <hashinput>] [-p <pse>] [-c <cadir>] [<file> [<hash>] ]\n\n");

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-a <alg>         Name of a hash algorithm (default: md5)\n");
        fprintf(stderr, "-H <hashinput>   PSE-object or key reference of hash input (sqmodn only)\n");
        fprintf(stderr, "-p <psename>     PSE name, if <hashinput> is PSE-object (sqmodn only)\n");
        fprintf(stderr, "-c <cadir>       CA directory, if <hashinput> is PSE-object (sqmodn only)\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-h               Write this help text\n");
        fprintf(stderr, "<file>           Filename of file to be hashed. Stdin, if omitted\n");
        fprintf(stderr, "<hash>           File where hash value shall be written. Stdout, if omitted\n");
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM HSH */
}

p_error(t2, t3)
char *t2, *t3;
{
        fprintf(stderr, "hsh: ");
        if(t2 && strlen(t2)) fprintf(stderr, ": %s", t2);
        if(t3 && strlen(t3)) fprintf(stderr, " %s", t3);
        fprintf(stderr, "\n");
        exit(-1);
}


build_hashinput(keyref, key, cert)
int keyref;
char *key, *cert;
{
        Certificate *certificate;
        ObjId object_oid;
	char *proc = "build_hashinput";

        if(keyref) {
                if(sec_get_key(&key_hashinput, keyref, (Key *)0) < 0)  {
			aux_add_error(EINVALID, "sec_get_key failed for key2", 0, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't read key2", "");
        	}
        }
        else if(key) {
                pse_sel_hashinput.object.name = key;
                if(sec_read_PSE(&pse_sel_hashinput, &object_oid, &out_octets) < 0)  {
			aux_add_error(EINVALID, "sec_read_PSE failed", key, char_n, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't read ", key);
        	}
                if(d2_KeyInfo(&out_octets, &key_hashinput) < 0)  {
			aux_add_error(EDECODE, "d2_KeyInfo failed", 0, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't decode ", key);
        	}
        }
        else if(cert) {
                pse_sel_hashinput.object.name = cert;
                if(sec_read_PSE(&pse_sel_hashinput, &object_oid, &out_octets) < 0) {
			aux_add_error(EINVALID, "sec_read_PSE failed", cert, char_n, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't read ", cert);
        	}
                if(!(certificate = d_Certificate(&out_octets))) {
			aux_add_error(EDECODE, "d_Certificate failed", 0, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			p_error("Can't decode ", cert);
        	}
		key_hashinput.subjectkey.nbits = certificate->tbs->subjectPK->subjectkey.nbits;
		key_hashinput.subjectkey.bits = certificate->tbs->subjectPK->subjectkey.bits;
        }
        hashinput.sqmodn_input.nbits = key_hashinput.subjectkey.nbits;
        hashinput.sqmodn_input.bits = key_hashinput.subjectkey.bits;

	return(0);
}

