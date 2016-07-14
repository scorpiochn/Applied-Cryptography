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

/* #define APCONV */

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <fcntl.h>
#include "secure.h"

#define RFC 0
#define HEX 1
#define AP  2

#define DECSIZE 8000
#define ENCSIZE 6000

char buf[16000];
static void     usage();

main(cnt, parm) 
int cnt;
char **parm; 
{
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
        char *buf1, *buf2, *bb;
        int i, j, type = RFC, insnl = 64, fd_in = 0, fd_out = 1, ret, BUFSIZE, stripped, rest=0;
        OctetString in, *out;
        FILE *instream;
  	char *proc = "main (encode)";
  	char verbose = FALSE;                          
        in.octets = buf;
        in.noctets = 0;

        BUFSIZE = ENCSIZE;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;
	while ( (opt = getopt(cnt, parm, "i:rxavh")) != -1 ) switch(opt) {
                case 'h':
                        usage(LONG_HELP);
                        continue;
                case 'r':
                        type = RFC;
                        continue;
                case 'x':
                        type = HEX;
                        continue;
                case 'v':
                        verbose = TRUE;
                        continue;
#ifdef APCONV
                case 'a':
                        type = AP;
                        continue;
#endif
                case 'i':
                        i++;
                        insnl = atoi(optarg);
                        continue;
                default:
		case '?':	
			usage(SHORT_HELP);
	}

	while (optind < cnt) {
                if(fd_in == 0) {                    
                        if((fd_in = open(parm[optind], O_RDONLY)) <= 0) {
                                aux_add_error(EINVALID, "Can't open", parm[optind], char_n, proc);
				if (verbose) aux_fprint_error(stderr, 0);
				p_error(cmd, "Can't open", parm[optind]);
			}
                }
                else if(fd_out == 1) {
                        if((fd_out = open(parm[optind], O_WRONLY|O_CREAT|O_TRUNC, 0644)) <= 0) {
                                aux_add_error(EINVALID, "Can't open", parm[optind], char_n, proc);
				if (verbose) aux_fprint_error(stderr, 0);
				p_error(cmd, "Can't open", parm[optind]);
			}
                }
                optind++;
        }

        instream = fdopen(fd_in, "r");

        while((in.noctets = fread(buf, 1, BUFSIZE, instream)) > 0) {
                if(type == RFC) out = aux_encrfc(&in);
#ifdef APCONV
                if(type == AP)  out = aux_encap(&in);
#endif
                if(type == HEX) out = aux_enchex(&in);
                if(out) {
                        if(insnl) {
                                /* insert NL's */
                                buf1 = out->octets;
                                buf2 = buf;
                                stripped = 0;
                                j = rest;
                                for (i = 0; i < out->noctets; i++) {
                                        *buf2++ = *buf1++;
                                        stripped++;
                                        j++;
                                        if(j == insnl) {
                                                *buf2++ = '\n';
                                                stripped++;
                                                j = 0;
                                        }
                                }
                                rest = j;
                                buf1 = buf;
                                i = stripped;
                        }
                        else {
                                buf1 = out->octets;
                                i = out->noctets;
                        }

                        write(fd_out, buf1, i);
                        aux_free_OctetString(&out);
                }
                else {
                        aux_add_error(EINVALID, "encoding/decoding failed", &in, OctetString_n, proc);
			if (verbose) aux_fprint_error(stderr, 0);
                        p_error(cmd, "encoding failed", "");
                }
        }
        exit(0);
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "encode  Encode File to RFC 1421 or [0-9,A-F] ASCII Represenation\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr,"encode [-rxhv] [ -i <n> ] [ file [encodedfile] ]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-r               RFC 1421 encoding style (default)\n");
        	fprintf(stderr, "-x               [0-9,A-F] encoding style\n");
        	fprintf(stderr, "-i <n>           insert newlines after n characters (default 64)\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        }


        exit(-1);                                /* IRREGULAR EXIT FROM ENCODE */
}

p_error(t1, t2, t3)
char *t1, *t2, *t3;
{
        fprintf(stderr, "%s", t1);
        if(t2 && strlen(t2)) fprintf(stderr, ": %s", t2);
        if(t3 && strlen(t3)) fprintf(stderr, " %s", t3);
        fprintf(stderr, "\n");
        exit(-1);
}
