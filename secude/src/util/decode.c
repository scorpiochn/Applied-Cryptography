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

char buf[DECSIZE+1000];
static void     usage();

main(cnt, parm) 
int cnt;
char **parm; 
{
	extern char	*optarg;
	extern int	optind, opterr;
	char	        *cmd = *parm, opt;
        char *buf1, *buf2, *bb;
        int i, j, inc, type = RFC, fd_in = 0, fd_out = 1, ret, BUFSIZE, stripped, rest=0;
        int inp = TRUE;
        OctetString in, *out;
        FILE *f_in;
  	char *proc = "main (decode)";
       	char verbose = FALSE;
                   
        in.octets = buf;
        in.noctets = 0;

        BUFSIZE = DECSIZE;

/*
 *      get args
 */

	optind = 1;
	opterr = 0;
	while ( (opt = getopt(cnt, parm, "rxavh")) != -1 ) switch(opt) {
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

        f_in = fdopen(fd_in, "r");

        buf1 = in.octets;
        while(inp) {

                inc = getc(f_in);

                /* eliminate NL's */

                if(inc == '\n' || inc == ' ') continue;

                if(inc != EOF) *buf1++ = inc;
                else inp = FALSE;

                if(buf1 - buf == BUFSIZE || inc == EOF) {
                        in.noctets = buf1 - buf;
                        if(type == RFC) out = aux_decrfc(&in);
#ifdef APCONV
                        if(type == AP)  out = aux_decap(&in);
#endif
                        if(type == HEX) out = aux_dechex(&in);
                        if(out) {
                                write(fd_out, out->octets, out->noctets);
                                aux_free_OctetString(&out);
                        }
                        else {
                                aux_add_error(EINVALID, "encoding/decoding failed", &in, OctetString_n, proc);
				if (verbose) aux_fprint_error(stderr, 0);
                                p_error(cmd, "encoding/decoding failed", "");
                        }
                        buf1 = in.octets;
                }
        }
        exit(0);
}

static
void usage(help)
int     help;
{
	aux_fprint_version(stderr);

        fprintf(stderr, "decode  decode RFC 1421 or [0-9,A-F] encoded ASCII file to file\n\n");
        fprintf(stderr, "usage:\n\n");
	fprintf(stderr,"decode [-rxhv] [ encodedfile [ file ] ]\n\n");
 

        if(help == LONG_HELP) {
        	fprintf(stderr, "with:\n\n");
        	fprintf(stderr, "-r               RFC 1421 encoding style (default)\n");
        	fprintf(stderr, "-x               [0-9,A-F] encoding style\n");
        	fprintf(stderr, "-h               write this help text\n");
        	fprintf(stderr, "-v               verbose\n");
        }


        exit(-1);                                /* IRREGULAR EXIT FROM DECODE */
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
