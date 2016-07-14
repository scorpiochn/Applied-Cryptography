/*
 *  SecuDE Release 4.1 (GMD)
 */

/********************************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                                *
 *                                                                              *
 *                                                                              *
 *                         NOTICE                                               *
 *                                                                              *
 *    Acquisition, use, and distribution of this module                         *
 *    and related materials are subject to restrictions                         *
 *    mentioned in each volume of the documentation.                            *
 *                                                                              *
 *******************************************************************************/


/*-----------------------pem.c-------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)                    */
/* Rheinstr. 75 / Dolivostr. 15                                                */
/* 6100 Darmstadt                                                              */
/* Project ``SecuDE'' 1990 / "SecuDe" 1991,92,93                               */
/*      Grimm/Luehe/Nausester/Schneider/Viebeg/                                */
/*      Surkau/Reichelt/Kolletzki                     et alii                  */
/*-----------------------------------------------------------------------------*/
/*                                                                             */
/* PACKAGE   util            VERSION   4.0                                     */
/*                              DATE   06.02.1992                              */
/*                                BY   Grimm/Luehe/Schneider/Surkau/           */
/*                                     Reichelt/Kolletzki                      */
/*                                                                             */
/*                            REVIEW                                           */
/*                              DATE                                           */
/*                                BY                                           */
/* DESCRIPTION                                                                 */
/*   This is the main program of the RFC 1421 - 1424  PEM filter               */
/*                                                                             */
/* CALLS TO                                                                    */
/*                                                                             */
/*  pem_read() (->pem_scan())                                                  */
/*  pem_write() (->pem_cinfo(), pem_create())                                  */
/*                                                                             */
/*  *** canonicalized input: ***                                               */
/*                                                                             */
/* PEM scanning routines accept canonicalized and local                        */
/* text input.                                                                 */
/*                                                                             */
/* *** multi body PEM: ***                                                     */
/*                                                                             */
/* multi body PEM can only be used for MIC-CLEAR                               */
/* (otherwise PEM body ins encoded).                                           */
/*                                                                             */
/* pem_read(): input depth > 0:                                                */
/*          skip all text before required PEM boundary                         */
/*          begin no. "depth+1". No cut-off at end of                          */
/*          text input.                                                        */
/* pem_scan(): separate text input into "heading"                              */
/*          and "body"; in heading skip anything before                        */
/*          1st boundary begin line found.                                     */
/* pem_sbody(): input text must be "body", i.e. must                           */
/*          point to the 1st octet of signed (encoded,                         */
/*          encrypted, resp.) text;                                            */
/*          ignores any text behind (and including)                            */
/*          corresponding boundary end line, which is                          */
/*          found out here correctly.                                          */
/*-----------------------------------------------------------------------------*/


#include <stdio.h>
#include "pem.h"
#include "cadb.h"
#ifndef OK
#define OK 0
#endif
#ifdef TEST
#define VERBOSE_MAX 3
#else
#define VERBOSE_MAX 1
#endif


char            *psename = CNULL, *psepath = CNULL, *cadir = CNULL, *ppin = CNULL;
static                evaluate_args();
static                errmsg();
static  void          usage();
char puff[1024];
FILE *keyboard;

SET_OF_Name *names = (SET_OF_Name *)0, *names2;
SET_OF_DName *issuer = (SET_OF_DName *)0, *issuer2;
RecpList  *reciplist = (RecpList  *)0, *reciplist2;
DName	*tmp_dname;
Boolean   pem_option_y, encr, writepem, clear, crl, certify, install;
int       depth, crl_instmode;
char	  *crl_inst;
char      *ofname, *ifname;



/***************************************************************
 *
 * Procedure main
 *
 ***************************************************************/
#ifdef ANSI

int main(
	int	  cnt,
	char	 *parms[]
)

#else

int main(
	cnt,
	parms
)
int	  cnt;
char	 *parms[];

#endif

{
        RecpList **rpl, *r;
	PSESel *std_pse;
	int i;
#ifdef X500
	char * env_auth_level;
#endif

        char *proc = "main (pem)";

        af_verbose = FALSE;
	chk_PEM_subordination = TRUE;

        evaluate_args(cnt, parms);

        pem_verbose_0 =                 (pem_verbose_level >= 0);
        pem_verbose_1 = af_verbose =    (pem_verbose_level >= 1);
        pem_verbose_2 = sec_verbose =   (pem_verbose_level >= 2);

	if((certify || crl==CRL_MESSAGE)  && !cadir) {
                fprintf(stderr, "CA-Directory is set to %s\n", DEF_CADIR);
		cadir = DEF_CADIR;
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
                strcpy(psepath, cadir);
                strcat(psepath, "/");
                strcat(psepath, psename);
 	        if(!ppin) ppin = getenv("CAPIN");
        }
        else {
                psepath = (char *)malloc(strlen(psename)+2);
                strcpy(psepath, psename);
 	        if(!ppin) ppin = getenv("USERPIN");
        }

	AF_pse.app_name = psepath;

        if ( aux_create_AFPSESel(psepath, ppin) < 0 ) {
                fprintf(stderr, "Cannot create AFPSESel.\n");
                if (pem_verbose_1) aux_fprint_error(stderr, 0);
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
	if((auth_level == DBA_AUTH_SIMPLE || auth_level == DBA_AUTH_NONE) && af_access_directory) {
		directory_user_dname = af_pse_get_Name();
	}

#endif

	if (!(std_pse = af_pse_open((ObjId *)0, FALSE))) {
		if (err_stack) {
			if (pem_verbose_1) aux_fprint_error(stderr, 0);
			else aux_fprint_error(stderr, TRUE);
		}
		else 	fprintf(stderr, "%s: unable to open PSE %s\n", proc, AF_pse.app_name);
		exit(-1);
	}

	aux_free_PSESel(&std_pse);
	for (i = 0; i < PSE_MAXOBJ; i++) AF_pse.object[i].pin = aux_cpy_String(AF_pse.pin);





/*	evaluate aliases */
	if(pem_option_y) {
		while(names) {
                	if (!(tmp_dname = aux_alias2DName(names->element))) {
                                aux_add_error(EINVALID, "aux_alias2DName failed", names->element, char_n, proc);
                                if(pem_verbose_0) aux_fprint_error(stderr, 0);
                                fprintf(stderr, "%s: ", names->element);
                                errmsg("Name is incorrect.\n");
                        } 
			else {
				issuer2 = (SET_OF_DName *)calloc(1, sizeof(SET_OF_Name));
                                issuer2->next = issuer;
                                issuer2->element = tmp_dname;
                                issuer = issuer2;
			}
			names2 = names->next;
			free(names->element);
			free(names);
			names = names2;
		}
	}
	else
	if(pem_option_r) {
		while(names) {
                	if (!(tmp_dname = aux_alias2DName(names->element))) {
                                aux_add_error(EINVALID, "aux_alias2DName failed", names->element, char_n, proc);
                                if(pem_verbose_0) aux_fprint_error(stderr, 0);
                                fprintf(stderr, "%s: ", names->element);
                                errmsg("Name is incorrect.\n");
                        } 
			else {
				reciplist2 = (RecpList *)calloc(1, sizeof(RecpList));
                                reciplist2->next = reciplist;
                                reciplist2->recpcert = (Certificate *)calloc(1, sizeof(Certificate));
                                reciplist2->recpcert->tbs = (ToBeSigned *)calloc(1, sizeof(ToBeSigned));
                                reciplist2->recpcert->tbs->subject = tmp_dname;
                                reciplist = reciplist2;
			}
			names2 = names->next;
			free(names->element);
			free(names);
			names = names2;
		}
	}

		
	if(crl) { 
		if(pem_option_y && !issuer) {
			issuer = (SET_OF_DName *)calloc(1, sizeof(SET_OF_Name));
			issuer->next = NULL;
			issuer->element = NULL;

		}
                if(pem_write_crl(issuer, ofname, crl, pem_verbose_0, cadir) != OK )  {
                        aux_add_error(EINVALID, "pem_write_crl failed", 0, 0, proc);
                        if (pem_verbose_0) fprintf(stderr, "Can't create PEM message\n");
                        if(MF_check) MF_fprint(stderr);
                        exit(-1);                        /* IRREGULAR EXIT FROM PEM */

                }

	} 
	else if(certify) {
                if (pem_verbose_1) {
                        if(depth != 0) fprintf(stderr, "De-enhance %d-level embedded PEM\n", depth);
                }
                if(pem_certify(ifname, ofname, pem_verbose_0, cadir) != OK)  {
                        aux_add_error(EINVALID, "pem_certify failed", 0, 0, proc);
                        aux_free_RecpList(&reciplist);
                        if(MF_check) MF_fprint(stderr);
                        exit(-1);                        /* IRREGULAR EXIT FROM PEM */

                }

	} else if(writepem) {
/*
 *   read clear msg body, write PEM msg
 */

                if (encr) {
                        if(pem_verbose_1) fprintf(stderr, "write encrypted PEM\n");

                        if(!reciplist && (pem_option_K || pem_option_r)) {              /* no recipients given via -r */
                                reciplist = (RecpList *)calloc(1, sizeof(RecpList));

                                reciplist->next = NULL;
                                rpl = &reciplist->next;
                                keyboard = fopen("/dev/tty", "r");
                                reciplist->recpcert = (Certificate *)calloc(1, sizeof(Certificate));

first_again:                    fprintf(stderr, "Give recipient's name:\n");
                                fgets(puff, sizeof(puff), keyboard);
                                puff[strlen(puff) - 1] = '\0';                          /* delete the CR which fgets provides */
                                if(strlen(puff) == 0) goto first_again;

                                reciplist->recpcert->tbs = (ToBeSigned *)calloc(1, sizeof(ToBeSigned));

                                if( !(reciplist->recpcert->tbs->subject = aux_alias2DName(puff))) {
                                        aux_add_error(EINVALID, "aux_alias2DName or aux_alias2Name failed", puff, char_n, proc);
                                        errmsg("Name is incorrect: %s\n", puff);
                                }

next_recipient:                 fprintf(stderr, "Give another recipient or (CR):\n");
                                if(fgets(puff, sizeof(puff), keyboard)) {
                                        puff[strlen(puff) - 1] = '\0';  /* delete the CR which fgets provides */
                                        if(strlen(puff) == 0) goto end_recipient;

                                        *rpl = (RecpList *)calloc(1, sizeof(RecpList));

                                        (*rpl)->next = (RecpList *)0;
                                        (*rpl)->recpcert = (Certificate *)calloc(1, sizeof(Certificate));

                                        (*rpl)->recpcert->tbs = (ToBeSigned *)calloc(1, sizeof(ToBeSigned));

                                        if( !((*rpl)->recpcert->tbs->subject = aux_alias2DName(puff))) {
                                                aux_add_error(EINVALID, "aux_alias2DName or aux_alias2Name failed", puff, char_n, proc);
                                                errmsg("Name is incorrect: %s\n", puff);
                                        }

                                        rpl = &(*rpl)->next;
                                        goto next_recipient;
                                }
                        }

                } 
		else {
                        if(pem_verbose_1) {
                                if(clear) fprintf(stderr, "write clear PEM with MIC\n");
                                else fprintf(stderr, "write RFC encoded PEM with MIC\n");
                        }
                }
end_recipient:

                if(pem_write(reciplist, ifname, ofname, encr, clear, pem_verbose_0) != OK )  {
                        aux_add_error(EINVALID, "pem_write failed", 0, 0, proc);
                        if (pem_verbose_0) fprintf(stderr, "Can't create PEM message\n");
                        aux_free_RecpList(&reciplist);
                        if(MF_check) MF_fprint(stderr);
			if (pem_verbose_1) aux_fprint_error(stderr, 0);
                        exit(-1);                        /* IRREGULAR EXIT FROM PEM */

                }

        }



/*
 *   read PEM msg, write clear msg body
 */

        else {
                if (pem_verbose_1) {
                        if(depth != 0) fprintf(stderr, "De-enhance %d-level embedded PEM\n", depth);
                }
                if(pem_read(ifname, ofname, depth, pem_verbose_0, cadir) != OK)  {
                        aux_add_error(EINVALID, "pem_read failed", 0, 0, proc);
                        aux_free_RecpList(&reciplist);
                        if(MF_check) MF_fprint(stderr);
			if (pem_verbose_1) aux_fprint_error(stderr, 0);
                        exit(-1);                        /* IRREGULAR EXIT FROM PEM */

                }
        }



/*
 *   write/read OK
 */

        aux_free_RecpList(&reciplist);
        if(MF_check) MF_fprint(stderr);
        exit(pem_content_domain);                                        /* REGULAR EXIT FROM PEM */
}

/***************************************************************
 *
 * Procedure evaluate_args
 *
 ***************************************************************/
#ifdef ANSI

static int evaluate_args(
	int	  cnt,
	char	 *parms[]
)

#else

static int evaluate_args(
	cnt,
	parms
)
int	  cnt;
char	 *parms[];

#endif

{
        char            tmp_c, *proc = "evaluate_args";
        int             nparm, iparm, tmp_i, i;
        Boolean         writeoptions = FALSE;
        RecpList        **rpl = &reciplist;
#ifdef X500
	int 		dsap_index;
	char          * callflag;
#endif


        /* defaults: */


#ifdef X500
	af_x500_count  = 1;	/* default, binding to local DSA */
	dsap_index = 4;
	callflag = "-call";

	i = cnt+1;
	while (parms[i ++]) dsap_index ++;
	af_x500_vecptr = (char**)calloc(dsap_index,sizeof(char*));	/* used for dsap_init() in af_dir.c */
#endif

        clear = TRUE;
        MF_check = FALSE;
        pem_enter_certificate_into_pklist = pem_option_r = pem_option_y = pem_option_K = encr = writepem = pem_insert_cert = certify = install
 = FALSE;
	crl = NO_CRL_MESSAGE;
	
        pem_verbose_level = -1;
        depth = pem_Depth = 0;

	af_chk_crl = FALSE;
	af_access_directory = FALSE;

        for(nparm = 1, iparm = 0; nparm < cnt; nparm++, iparm = 0) switch(parms[nparm][iparm]) {
                case '-':
                        while(parms[nparm][++iparm]) switch(parms[nparm][iparm]) {
                                case 'h':
                                        usage(LONG_HELP);
                                        break;
				case 'D':
					af_access_directory = TRUE;
					break;
#ifdef X500
				case 'd':
					af_x500_count = 3;
					af_x500_vecptr[0] = parms[0];
					af_x500_vecptr[1] = (char *)malloc(strlen(callflag) + 1);
					strcpy(af_x500_vecptr[1],callflag);
					af_x500_vecptr[2] = (char *)malloc(strlen(parms[++nparm]) + 1);
					strcpy(af_x500_vecptr[2], parms[nparm]);
					af_x500_vecptr[3] = (char *)0;
					i = cnt+1;
					dsap_index = 4;
					while (parms[i])
						af_x500_vecptr[dsap_index++] = parms[i++];
					goto next_parm;
				case 'A':
					nparm++;
					if (! strcasecmp(parms[nparm], "STRONG"))
						auth_level = DBA_AUTH_STRONG;
					else if (! strcasecmp(parms[nparm], "SIMPLE"))
						auth_level = DBA_AUTH_SIMPLE;
					break;
#endif
				case 'F':
					af_FCPath_is_trusted = TRUE;
					break;
				case 'R':
					af_chk_crl = TRUE;
					break;
                                case 'v':
                                        pem_verbose_level = 0;
                                        break;
                                case 'V':
                                        pem_verbose_level = 1;
                                        break;
                                case 'W':
                                        pem_verbose_level = 2;
                                        break;
                                case 't':
                                        MF_check = TRUE;
                                        break;
                                case 'm':
                                        if(writepem) errmsg("-m is possible for pem scan only");
                                        if(pem_Depth) errmsg("-m is possible whithout -M, only\n");
                                        if(nparm >= (cnt - 1)) { fprintf(stderr, "WARNING: parameter -m ignored!\n"); break; }
                                        sscanf (parms[++nparm],"%d", &depth);
                                        if(depth <= 0) {
                                                depth = 0;
                                                fprintf(stderr, "WARNING: parameter -d ignored!\n");
                                        } else if(depth > 200) {
                                                fprintf(stderr, "WARNING: depth of %d ignored, set to 200\n", depth);
                                                depth = 200;
                                        }
                                        goto next_parm;
                                case 'M':
                                        if(writepem) errmsg("-M is possible for pem scan only");
                                        if(depth) errmsg("-M is possible whithout -m, only\n");
                                        if(nparm >= (cnt - 1)) { fprintf(stderr, "WARNING: parameter -M ignored!\n"); break; }
                                        sscanf (parms[++nparm],"%d", &pem_Depth);
                                        if(pem_Depth <= 0) {
                                                pem_Depth = 0;
                                                fprintf(stderr, "WARNING: parameter -D ignored!\n");
                                        } else if(pem_Depth > 200) {
                                                fprintf(stderr, "WARNING: depth of %d ignored, set to 200\n", pem_Depth);
                                                pem_Depth = 200;
                                        }
                                        goto next_parm;
                                case 'r':
                                        if(!writepem || !encr) errmsg("-r is possible for pem encrypted only");
                                        pem_option_r = TRUE;
                                        break;
                                case 'y':
                                        if(!crl) errmsg("-y is possible for pem crl or pem crl-retrieval-request");
                                        pem_option_y = TRUE;
                                        break;
#ifdef SCA
                                case 'T':
                                        SC_verify = TRUE;
                                        break;
#endif
                                case 'n':
                                        if(!writepem || !encr) errmsg("-n is possible for pem encrypted only");
                                        pem_option_K = TRUE;
                                        break;
                                case 'i':
                                        if(ifname) usage(SHORT_HELP);
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        ifname = parms[++nparm];
                                        goto next_parm;
                                case 'o':
                                        if(ofname) usage(SHORT_HELP);
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        ofname = parms[++nparm];
                                        goto next_parm;
                                case 'p':
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        psename = parms[++nparm];
                                        goto next_parm;
                                case 'u':
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        crl_inst = parms[++nparm];
					for(crl_instmode = 0; update_modes[crl_instmode].name && strncmp(update_modes[crl_instmode].name, crl_inst, strlen(crl_inst)); crl_instmode++);
					if(update_modes[crl_instmode].name) update_mode = update_modes[crl_instmode].value;
					else usage(SHORT_HELP);
                                        goto next_parm;
                                case 'c':
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        cadir = parms[++nparm];
					isCA = TRUE;
                                        goto next_parm;
                                case 'C':
 					pem_cert_num = -1;
/*                                      if(!writepem) errmsg("-C is not possible when scanning"); */
                                        pem_insert_cert = TRUE;
                                        pem_cert_num = -1;
                                        break;
				case 'N':
					PEM_Conformance_Requested = FALSE;
					break;
				case 'O':
					chk_PEM_subordination = FALSE;
					break;
                                case 'E':
                                        if(!writepem || !encr) errmsg("-E is possible for pem encrypted only");
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        MSG_ENC_ALG = parms[++nparm];
                                        if(aux_Name2AlgType(MSG_ENC_ALG) != SYM_ENC) errmsg("Message encryption algorithm must be symmetric");
					if(PEM_Conformance_Requested) {
						if(aux_Name2AlgEnc(MSG_ENC_ALG) != DES || aux_Name2AlgMode(MSG_ENC_ALG) != CBC) errmsg("RFC 1423 requires desCBC as message encryption algorithm");
					}
                                        goto next_parm;
                                case 'S':
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        MIC_ENC_ALG = parms[++nparm];
                                        if(aux_Name2AlgType(MIC_ENC_ALG) != ASYM_ENC) errmsg("MIC encryption algorithm must be asymmetric");
					if(aux_Name2AlgEnc(MIC_ENC_ALG) == DSA) MIC_ALG = "NIST-SHA";
					if(PEM_Conformance_Requested) {
						if(strcmp(MIC_ENC_ALG, "RSA")) errmsg("RFC 1423 requires RSA as MIC encryption algorithm");
					}
                                        goto next_parm;
                                case 'K':
                                        if(!writepem || !encr) errmsg("-K is possible for pem encrypted only");
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        DEK_ENC_ALG = parms[++nparm];
                                        if(aux_Name2AlgEnc(DEK_ENC_ALG) != RSA || aux_Name2AlgType(DEK_ENC_ALG) != ASYM_ENC) errmsg("DEK encryption algorithm must be RSA");
                                        goto next_parm;
                                case 'H':
                                        if(nparm >= (cnt - 1)) usage(SHORT_HELP);
                                        MIC_ALG = parms[++nparm];
                                        if(aux_Name2AlgType(MIC_ALG) != HASH) errmsg("Message digest algorithm must be a hash algorithm");
					if(aux_Name2AlgHash(MIC_ALG) == SHA) MIC_ENC_ALG = "NIST-DSA";
					if(PEM_Conformance_Requested) {
						if(strcmp(MIC_ALG, "RSA-MD2") && strcmp(MIC_ALG, "RSA-MD5")) errmsg("RFC 1423 requires RSA-MD2 or RSA-MD5 as message digest algorithm");
					}
                                        goto next_parm;
                                default:
                                        usage(SHORT_HELP);
                        }
next_parm:              break;

                default:
                        if(strcmp(parms[nparm], "scan") == 0) {
                                writepem = FALSE;
                                break;
                        }
                        if(strcmp(parms[nparm], "mic-only") == 0) {
                                writepem = TRUE;
                                clear = FALSE;
                                encr = FALSE;
                                writeoptions = TRUE;
                                break;
                        }
                        if(strcmp(parms[nparm], "mic-clear") == 0) {
                                writepem = TRUE;
                                clear = TRUE;
                                encr = FALSE;
                                writeoptions = TRUE;
                                break;
                        }
                        if(strcmp(parms[nparm], "encrypted") == 0) {
                                writepem = TRUE;
                                clear = FALSE;
                                encr = TRUE;
                                writeoptions = TRUE;
                                break;
                        }
                        if(strcmp(parms[nparm], "certify") == 0) {
                                certify = TRUE;
                                break;
                        }
                        if(strcmp(parms[nparm], "crl") == 0) {
                                crl = CRL_MESSAGE;
                                break;
                        }
                        if(strcmp(parms[nparm], "crl-rr") == 0) {
                                crl = CRL_RETRIEVAL_REQUEST_MESSAGE;
                                break;
                        }
                        if(pem_option_r || pem_option_y) {
                                names2 = (SET_OF_Name *)calloc(1, sizeof(SET_OF_Name));
                                names2->next = names;
                                if (!(names2->element = malloc(strlen(parms[nparm]) + 1))) {
                                        aux_add_error(EMALLOC, "names2->element", CNULL, 0, proc);
                                        return(-1);
                                }
				strcpy(names2->element, parms[nparm]);
                                names = names2;

                                break;
                        }
                        usage(SHORT_HELP);
        }


	return(0);
}

/***************************************************************
 *
 * Procedure errmsg
 *
 ***************************************************************/
#ifdef ANSI

static int errmsg(
	char	 *text
)

#else

static int errmsg(
	text
)
char	 *text;

#endif

{
        fprintf(stderr, "%s\n", text);
        if(pem_verbose_0) aux_fprint_error(stderr, 0);

        aux_free_RecpList(&reciplist);
        if(MF_check) MF_fprint(stderr);
        exit(1);                                /* IRREGULAR EXIT FROM PEM */
}

/***************************************************************
 *
 * Procedure usage
 *
 ***************************************************************/
#ifdef ANSI

static void usage(
	int	  help
)

#else

static void usage(
	help
)
int	  help;

#endif

{
	aux_fprint_version(stderr);

        fprintf(stderr, "pem  Privacy Enhancement for Internet Electronic Mail\n\n");
        fprintf(stderr, "usage:\n\n");
        fprintf(stderr, "pem [ scan | mic-clear | mic-only | encrypted | crl | clr-rr | certify ]\n");
        fprintf(stderr, "    [-i <inputfile>] [-o <outputfile>] [-p <psename>] [-c <cadir>] [-m|M 1..200]\n");
#ifdef X500
	fprintf(stderr, "    [-u <update>] [-r <name1 ...> ] [-y <name1 ...> ] [-CnFNOhvVWRDTt] [-d <dsaname>]\n");
#else
	fprintf(stderr, "    [-u <update>] [-r <name1 ...> ] [-y <name1 ...> ] [-CnFNOhvVWRDTt]\n");
#endif
        fprintf(stderr, "    [-H <mic-alg>] [-S <micenc-alg>] [-E <msgenc-alg>] [-K <dekenc-alg>]");
        fprintf(stderr, "\n\n");

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "scan             read PEM any Proc-Type, write clear body and/or update\n");
        fprintf(stderr, "                 PSE and/or CA-database according to -u (default)\n");
        fprintf(stderr, "mic-clear        read text file, write PEM Proc-Type MIC-CLEAR\n");
        fprintf(stderr, "mic-only         read text file, write PEM Proc-Type MIC-ONLY\n");
        fprintf(stderr, "encrypted        read text file, write PEM Proc Type ENCRYPTED according to -r\n");
        fprintf(stderr, "crl              write PEM Proc-Type CRL according to -y\n");
        fprintf(stderr, "crl-rr           write PEM Proc-Type CRL-RETRIEVAL-REQUEST according to -y\n");
        fprintf(stderr, "certify          read PEM Proc-Type MIC-CLEAR or MIC-ONLY, check whether it is certification\n");
        fprintf(stderr, "                 request, sign Prototype-certificate, write certification reply\n");
        fprintf(stderr, "-i <inputfile>   inputfile (default: stdin)\n");
        fprintf(stderr, "-o <outputfile>  outputfile (default: stdout)\n");
        fprintf(stderr, "-p <psename>     PSE name (default: .pse)\n");
        fprintf(stderr, "-c <cadir>       name of CA-directory (default: .ca)\n");
        fprintf(stderr, "-m <level>       depth of multi PEM body, which is to be de-enhanced (only if pem scan)\n");
        fprintf(stderr, "-M <level>       depth of multi PEM body, up to which is to be de-enhanced (only if pem scan)\n");
        fprintf(stderr, "-u <update>      mode for updating the PSE or CA-database after scanning a PEM-msg\n");
        fprintf(stderr, "                 (ask, yes, no, cadb, pse (default: ask))\n");
        fprintf(stderr, "-r <recipients>  DNames or alias-names of recipients (only if pem encrypted)\n");
        fprintf(stderr, "-y <issuers>     DNames or alias-names of issuers of CRLs or CRL-RRs (only if pem crl or pem clr-rr)\n");
        fprintf(stderr, "-C               generate PEM-header with Originator-Certificate and all Issuer-Certificates\n");
        fprintf(stderr, "                 (default: generate PEM-header with Originator-ID-Asymmetric)\n");
        fprintf(stderr, "-n               don't insert Key-Info header field for originator (only if pem encrypted)\n");
        fprintf(stderr, "-N               use of non-PEM conformant algorithms allowed\n");
        fprintf(stderr, "-O               RFC 1422 DName subordination not required\n");
        fprintf(stderr, "-h               write this help text\n");
        fprintf(stderr, "-v               verbose\n");
        fprintf(stderr, "-V               Verbose\n");
        fprintf(stderr, "-W               Grand Verbose (for tests only)\n");
	fprintf(stderr, "-F               consider own FCPath as trusted\n");
        fprintf(stderr, "-R               consult CRLs during validation process\n");
        fprintf(stderr, "-D               retrieve missing certificates or CRLs from the Directory (X.500 or .af-db)\n");
#ifdef X500
	fprintf(stderr, "-d <dsaname>     name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-A <authlevel>   level of authentication used for binding to the X.500 Directory\n");
#endif
        fprintf(stderr, "-H <mic-alg>     MIC algorithm (default: %s)\n", MIC_ALG);
        fprintf(stderr, "-S <micenc-alg>  MIC encryption algorithm (default: %s)\n", MIC_ENC_ALG);
        fprintf(stderr, "-E <msgenc-alg>  Message encryption algorithm (default: %s) (only if pem encrypted)\n", MSG_ENC_ALG);
        fprintf(stderr, "-K <dekenc-alg>  DEK encryption algorithm (default: %s) (only if pem encrypted)\n", DEK_ENC_ALG);
        fprintf(stderr, "-t               enable memory checking\n");
#ifdef SCA
        fprintf(stderr, "-T               verification of signature is to be done by the smartcard terminal\n");
#endif
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM PEM */
}
