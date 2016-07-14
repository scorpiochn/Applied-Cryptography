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

/*-----------------------pem-rw.c-----------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/* 	Grimm/Nausester/Schneider/Viebeg/Vollmer/                   */
/* 	Surkau/Reichelt/Kolletzki                     et alii       */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   pem             VERSION   3.0                          */
/*                              DATE   06.02.1992                   */
/*                                BY   Grimm/Surkau/Schneider/      */
/*                                     Reichelt                     */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This modul presents functions to prepare input                 */
/*   to the pem_create/pem_scan functions from the                  */
/*   user's terminal and give response from the pem-                */
/*   functions to the user's terminal.                              */
/*                                                                  */
/* EXPORT                                                           */
/*                                                                  */
/*  pem_read()                                                      */
/*  pem_write()                                                     */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  pem_scan(), pem_cinfo(), pem_create(),                          */
/*  af_pse_open, af_pse_close(),                                    */
/*  aux_ functions                                                  */
/*                                                                  */
/*------------------------------------------------------------------*/
#include <fcntl.h>
#include "cadb.h"
#include "pem.h"

#define TIMELEN 40

extern char	*strcpy(), *getenv();
extern UTCTime  *aux_current_UTCTime(), *aux_delta_UTCTime();


#ifdef X500
extern DName * directory_user_dname;    /* defined in af_init.c */
extern int     count;			/* defined in af_init.c */
extern char ** vecptr;   		/* defined in af_init.c */
#endif

#define SIGNTYPE "Signature"
#define ENCTYPE  "Encryption"



#include <stdio.h>
#include "pem.h"
#ifndef OK
#define OK 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* defined in pem.h / pem_initialization.c:
 * extern char PEM_Boundary_Begin[];
*/

extern RC	pem_cinfo(), pem_create(), pem_scan();
extern RC	aux_searchitem();

static
UPDATE_Mode get_update_mode(text, std, no, yes, pse, cadb)
char *text;
UPDATE_Mode std;
char no, yes, pse, cadb;
{
	char		puff[128];
	FILE		*keyboard;

	if(update_mode == UPDATE_ASK) {

again1:		keyboard = fopen("/dev/tty", "r");
		fprintf(stderr, text);
		fgets(puff, sizeof(puff), keyboard);
		puff[strlen(puff) - 1] = '\0';                          /* delete the CR which fgets provides */
		fclose(keyboard);
		if(strlen(puff) != 1) return(std);
		str_low(puff);
		if (puff[0] == no) return(UPDATE_NO);
		else if (puff[0] == yes) return(UPDATE_YES);
		else if (puff[0] == pse) return(UPDATE_PSE);
		else if (puff[0] == cadb) return(UPDATE_CADB);
		else goto again1;
		
	} else return(update_mode);

}
RC pem_store_certificate(originator_name, originator_alias, originator_mailadr, owncert, cert, path, pkroot, verbose)
Name  *originator_name;
char *originator_alias, *originator_mailadr;
Certificate *owncert, *cert;
FCPath *path;
PKRoot *pkroot;
Boolean verbose;
{
	char *proc = "pem_store_certificate";
	UPDATE_Mode upd_mode;
	ToBeSigned *tbs;
	RC	rc;
	char		puff[1024];
	FILE		*keyboard;

	if( !owncert ) {

		if(update_mode == UPDATE_ASK || update_mode == UPDATE_YES || update_mode == UPDATE_PSE) {
			tbs = af_pse_get_TBS(SIGNATURE, 0, cert->tbs->issuer, cert->tbs->serialnumber);
			if(tbs) aux_free_ToBeSigned(&tbs); /* already there */
			else {
				upd_mode = get_update_mode("\nAdd Originator-Certificate as trusted key to PSE-object PKList (y/n) ? ", UPDATE_NO, 'n', 'y', 0, 0);

				if(upd_mode == UPDATE_YES || upd_mode == UPDATE_PSE) {
					
		
					/*   Check whether alias exists. Ask for one if not	*/
		
					if(!originator_alias) {
						keyboard = fopen("/dev/tty", "r");
		alias_again:			fprintf(stderr, "Enter alias name for <%s>: ", originator_name);
						fgets(puff, sizeof(puff), keyboard);
						puff[strlen(puff) - 1] = '\0';             /* delete the CR which fgets provides */
						if(!strlen(puff)) goto alias_again;
						fclose(keyboard);
						if(aux_add_alias(puff, cert->tbs->subject, useralias, TRUE, TRUE) < 0) {
							fprintf(stderr, "Couldn't add alias\n");
						}
					}	
					if(!originator_mailadr) {
						keyboard = fopen("/dev/tty", "r");
						fprintf(stderr, "Enter mail address for <%s>, or CR only: ", originator_name);
						fgets(puff, sizeof(puff), keyboard);
						puff[strlen(puff) - 1] = '\0';             /* delete the CR which fgets provides */
						fclose(keyboard);
						if(strlen(puff)) {
							if(aux_add_alias(puff, cert->tbs->subject, useralias, TRUE, TRUE) < 0) {
								fprintf(stderr, "Couldn't add alias\n");
							}
						}
					}
					/*   ... into PKList							*/
					if(!af_pse_add_PK(SIGNATURE, cert->tbs))  { 
						if(pem_verbose_0) fprintf(stderr, "PK of <%s> added to PKList of your PSE\n", 
													aux_DName2Name(cert->tbs->subject));
						return(0); 
					} 
					else {
						fprintf(stderr, "adding of PK of <%s> to PKList of your PSE failed\n",
											aux_DName2Name(cert->tbs->subject));
						return(-1);
					}
					
				}
			}
		}

	} 
	else if( aux_cmp_BitString(&(cert->sig->signature), &(owncert->sig->signature))) {

		upd_mode = get_update_mode("\nStore Originator-Certificate as PSE-object Cert (y/n) ? ", UPDATE_NO, 'n', 'y', 0, 0);

		if(upd_mode == UPDATE_YES || upd_mode == UPDATE_PSE) {
	

			rc = af_pse_update_Certificate(SIGNATURE, cert, TRUE);
		
			if (rc < 0) { 
				fprintf(stderr, "Can't install certificate\n");
				aux_add_error(EINVALID, "Can't install certificate", CNULL, 0, proc);
				if(verbose) aux_fprint_error(stderr, 0);
				return(-1); 
			}
			else if(verbose) fprintf(stderr, "Certificate installed in PSE-object Cert\n");			
		}
		
		if(path) {
			upd_mode = get_update_mode("\nStore the chain of Issuer-certificates as PSE-object FCPath (y/n) ? ", UPDATE_NO, 'n', 'y', 0, 0);
	
			if(upd_mode == UPDATE_YES || upd_mode == UPDATE_PSE) {
		
				rc = af_pse_update_FCPath(path);
				if (rc < 0) { 
					fprintf(stderr, "Can't install FCPath\n");
					aux_add_error(EINVALID, "Can't install FCPath", CNULL, 0, proc);
					if(verbose) aux_fprint_error(stderr, 0);
					return(-1); 
				}
				else if(verbose) fprintf(stderr, "Issuer-Certificates installed as PSE-object FCPath\n");			
			}
		}
		if(pkroot) {

			upd_mode = get_update_mode("\nStore the Root key PSE-object PKRoot (y/n) ? ", UPDATE_NO, 'n', 'y', 0, 0);
	
			if(upd_mode == UPDATE_YES || upd_mode == UPDATE_PSE) {
		
				rc = af_pse_update_PKRoot(pkroot);
				if (rc < 0) { 
					fprintf(stderr, "Can't install PKRoot\n");
					aux_add_error(EINVALID, "Can't install PKRoot", CNULL, 0, proc);
					if(verbose) aux_fprint_error(stderr, 0);
					return(-1); 
				}
				else if(verbose) fprintf(stderr, "Root key installed as PSE-object PKRoot\n");
			}
		}
	}
	return(0);	
}

RC pem_store_crl(set_of_pemcrlwithcerts, cadir)
SET_OF_PemCrlWithCerts *set_of_pemcrlwithcerts;
char *cadir;
{
	char *proc = "pem_store_crl";
	UPDATE_Mode upd_mode;
	CrlPSE	crlpse;
        SEQUENCE_OF_RevCertPem   *revokedCertificates, * revcerts;

	upd_mode = get_update_mode("\nStore Certificate Revocation List in  CA-database ( c ), PSE ( p )  or both ( y ) ? ", UPDATE_NO, 'n', 'y', 'p', 'c');
	if(cadir) 
		if(upd_mode == UPDATE_CADB || upd_mode == UPDATE_YES) 
			af_cadb_add_PemCrlWithCerts(set_of_pemcrlwithcerts->element, cadir);

	crlpse.issuer = set_of_pemcrlwithcerts->element->pemcrl->tbs->issuer;
	crlpse.nextUpdate = set_of_pemcrlwithcerts->element->pemcrl->tbs->nextUpdate;
	revokedCertificates = set_of_pemcrlwithcerts->element->pemcrl->tbs->revokedCertificates;
	crlpse.revcerts = (SEQUENCE_OF_RevCertPem * )0;
	while (revokedCertificates) {
		revcerts = (SEQUENCE_OF_RevCertPem *)calloc(1, sizeof(SEQUENCE_OF_RevCertPem));
		revcerts->next = crlpse.revcerts;
		revcerts->element = aux_cpy_RevCertPem(revokedCertificates->element);
		crlpse.revcerts = revcerts;
		revokedCertificates = revokedCertificates->next;
	}
	if(upd_mode == UPDATE_PSE || upd_mode == UPDATE_YES) 
	af_pse_add_PemCRL(&crlpse);
	while (crlpse.revcerts) {
		revcerts = crlpse.revcerts;
		crlpse.revcerts = crlpse.revcerts->next;
		free(revcerts);
	}

	

	return(0);
}


int	pem_read (ifname, ofname, depth, verbose, cadir)
/* input parameters: */
char	*ifname, *ofname;
int	depth;
Boolean verbose;
char	*cadir;
{
	RC           found, scanrc;
	PemInfo      peminfo;
	SET_OF_DName 	*issuer;
	SET_OF_PemCrlWithCerts *set_of_pemcrlwithcerts, *set_of_pemcrlwithcerts1;
	OctetString *clearmsg, *clearmsg_1, *pemmsg, *pemmsg_1, before;
	char	 *originator_name, *originator_alias, *originator_mailadr, *alias, *logpath, *cadir_abs, *home;
	int	i, pos, form_pos, from, to, cur_depth;
        PSESel *pse_sel;
	char *proc = "pem_read";
	CrlPSE	crlpse;
        SEQUENCE_OF_RevCertPem   *revokedCertificates, * revcerts;
	ToBeSigned *tbs;

	if(pem_verbose_1) {
		if(ifname) fprintf(stderr, "Read PEM message from file \"%s\".\n", ifname);
		else fprintf(stderr, "Read PEM message from stdin\n");
	}
	if( !(pemmsg = aux_file2OctetString( ifname )) ) {
		fprintf(stderr, "Can't read PEM message file %s\n", ifname); 
		aux_add_error(EINVALID, "Can't read PEM message file", ifname, char_n, proc);
		return (-1);
	}

	do {
		pem_Depth--;

		if(pem_verbose_1) fprintf(stderr, "Scan PEM message\n");

		cur_depth = pos = from = to = found = 0;

		peminfo.confidential	= peminfo.clear = FALSE;
		peminfo.encryptKEY	= (Key *)0;
		peminfo.origcert	= (Certificates *)0;
		peminfo.signAI		= (AlgId        *)0;
		peminfo.recplist	= (RecpList     *)0; 

		if(aux_searchitem(pemmsg, PEM_Boundary_Begin, &pos)) {
			if(pem_verbose_0) fprintf(stderr, "WARNING: There is no PEM Begin Boundary line\n"); 
			aux_add_error(EINVALID, "no PEM Begin Boundary line", pemmsg, OctetString_n, proc);
			pos = pemmsg->noctets;
		}

		clearmsg_1 = (OctetString * )calloc(1, sizeof(OctetString));
		clearmsg = (OctetString * )calloc(1, sizeof(OctetString));
		pemmsg_1 = (OctetString *)calloc(1, sizeof(OctetString));

		if(pos < pemmsg->noctets) {
			while(cur_depth < depth) {
				form_pos = pos;
				cur_depth++;
				if(aux_searchitem(pemmsg, PEM_Boundary_Begin, &pos)) {
					fprintf(stderr, "no PEM message at required level\n"); 
					aux_add_error(EINVALID, "no PEM message at required level", pemmsg, OctetString_n, proc);
					aux_free_OctetString(&pemmsg);
					free(pemmsg_1);
					free(clearmsg_1);
					free(clearmsg);
					return(-1);
				}
				while(!aux_searchitem(pemmsg, PEM_Boundary_End, &form_pos) && (pos > form_pos)) cur_depth--;
			}

			/*
			 *  	Open PSE
			 */
	
			if (!(pse_sel = af_pse_open(0, FALSE))) {
				aux_add_error(EINVALID, "Cannot open PSE", 0, 0, proc);
				fprintf(stderr, "can't open your PSE\n");
				aux_free_OctetString(&pemmsg);
				free(pemmsg_1);
				free(clearmsg_1);
				free(clearmsg);
				return (-1);
			}
			aux_free_PSESel(&pse_sel);

			do {
				/* skip PEM headings above required level depth: */
				to = pos - strlen(PEM_Boundary_Begin);

				for(found = TRUE; (cur_depth <= depth) && found; cur_depth++) {
					form_pos = pos;
					found = !aux_searchitem(pemmsg, PEM_Boundary_End, &pos);
					while(found && !aux_searchitem(pemmsg, PEM_Boundary_Begin, &form_pos) && (pos > form_pos)) cur_depth--;
				}

				pemmsg_1->octets = pemmsg->octets + to + strlen(PEM_Boundary_Begin);
				if(found) {
					pemmsg_1->noctets = pos - to - strlen(PEM_Boundary_Begin) - strlen(PEM_Boundary_End);
					cur_depth--;
				}
				else pemmsg_1->noctets = pemmsg->noctets - to - strlen(PEM_Boundary_Begin);

				/*
				 * 	pem_scan provides one of the following values:
				 *
				 * 	1. peminfo, if a MIC-CLEAR, MIC-ONLY or ENCRYPTED Proc-Type was scanned,
				 *	2. set_of_pemcrlwithcerts, if a CRL Proc-Type was scanned,
				 * 	3. issuer, if a CRL-RETRIEVAL-REQUEST Proc-Type was scanned.
				 */

				scanrc = pem_scan(&peminfo, &set_of_pemcrlwithcerts, &issuer, clearmsg_1, pemmsg_1, SCAN);

			 	if(scanrc == -1) {

					/* this may happen only in case 1 (MIC-CLEAR, MIC-ONLY or ENCRYPTED Proc-Type) */

					if(peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0)) sec_del_key (peminfo.encryptKEY->keyref);
					aux_free_OctetString(&pemmsg);
					free(pemmsg_1);
					aux_free_OctetString(&clearmsg_1);
					aux_free_OctetString(&clearmsg);
					return (-1);
				}
				if(set_of_pemcrlwithcerts) {

					/* case 2 (CRL Proc-Type) */

					if(cadir) {
						if(cadir[0] != '/') {
							home = getenv("HOME");
							if (!home) home = "";
							cadir_abs = (char *)malloc(strlen(home)+strlen(cadir)+10);
							if (!cadir_abs) {
								aux_add_error(EMALLOC, "cadir_abs", 0, 0, proc);
								free(mic_for_certification);
								mic_for_certification = 0;
								return(-1);
							}
							strcpy(cadir_abs, home);
							strcat(cadir_abs, "/");
							strcat(cadir_abs, cadir);
						}
						else {
							cadir_abs = (char *)malloc(strlen(cadir)+10);
							if (!cadir_abs) {
								aux_add_error(EMALLOC, "cadir_abs", 0, 0, proc);
								free(mic_for_certification);
								mic_for_certification = 0;
								return(-1);
							}
							strcpy(cadir_abs, cadir);
						}
	
						logpath = (char *) malloc(strlen(cadir_abs) + 10);
						strcpy(logpath, cadir_abs);
						strcat(logpath, "/");
						strcat(logpath, CALOG);
			
						if ((logfile = fopen(logpath, LOGFLAGS)) == (FILE *) 0) {
							fprintf(stderr, "Can't open %s\n", CALOG);
							aux_add_error(EINVALID, "Can't open", CALOG, char_n, proc);
							if (verbose) aux_fprint_error(stderr, 0);
							free(logpath);
							return (-1);
						}
						free(logpath);
					}
					set_of_pemcrlwithcerts1 = set_of_pemcrlwithcerts;
					while(set_of_pemcrlwithcerts) {


						aux_free_OctetString(&set_of_pemcrlwithcerts->element->pemcrl->tbs_DERcode);
						set_of_pemcrlwithcerts->element->pemcrl->tbs_DERcode = e_PemCrlTBS(set_of_pemcrlwithcerts->element->pemcrl->tbs);
				   

					
						if(af_verify(set_of_pemcrlwithcerts->element->pemcrl->tbs_DERcode, set_of_pemcrlwithcerts->element->pemcrl->sig, END, set_of_pemcrlwithcerts->element->certificates, 0, 0)) {
							fprintf(stderr, "Verification of CRL failed\n"); 
							aux_add_error(EMIC, "CRL verification", 0, 0, proc);
							if(pem_verbose_0) aux_fprint_VerificationResult(stderr, verifresult);
							aux_free_VerificationResult(&verifresult);
							return(-1);
						}

						pem_VerifResult = verifresult;
						verifresult = (VerificationResult *)0;
						/* MIC of CRL  O.K. */

/*
 *						save verifresult (otherwise, could be overwritten by alias file verification)
 */
						pem_VerifResult = verifresult;
						verifresult = (VerificationResult *)0;
/*
 * 						look for alias names of originator
 */
						originator_name = aux_DName2Name(set_of_pemcrlwithcerts->element->certificates->usercertificate->tbs->subject);
						originator_alias = aux_DName2alias(set_of_pemcrlwithcerts->element->certificates->usercertificate->tbs->subject, LOCALNAME);
						originator_mailadr = aux_DName2alias(set_of_pemcrlwithcerts->element->certificates->usercertificate->tbs->subject, RFCMAIL);

						if(originator_alias) alias = originator_alias;
						else if(originator_mailadr) alias = originator_mailadr;
						else alias = originator_name;

						fprintf(stderr, "CRL OK. Signed by <%s>\n", alias); 
/*
 *						print verifresult from pem verification
 */ 
						if(pem_verbose_0) aux_fprint_VerificationResult(stderr, pem_VerifResult);
						aux_free_VerificationResult(&pem_VerifResult);
					
						if(pem_verbose_1) fprintf(stderr, "done.\n");
						if(originator_name) free(originator_name);
					
					
						/*
						 *   Enter Originator-Certificate into PKList if not found there
						 */
						if(pem_store_certificate(originator_name, originator_alias, originator_mailadr, (Certificate *)0, set_of_pemcrlwithcerts->element->certificates->usercertificate, (FCPath *)0, (PKRoot *)0, verbose)) {
							return(-1);
						}
						if(pem_store_crl(set_of_pemcrlwithcerts, cadir)) {
							return(-1);
						}
					

						set_of_pemcrlwithcerts = set_of_pemcrlwithcerts->next;
					}
					fclose(logfile);
					aux_free_SET_OF_PemCrlWithCerts(&set_of_pemcrlwithcerts1);
					return(0);
				}

 				if(issuer) {

					/* case 3 (CRL-RETRIEVAL-REQUEST Proc-Type) */

                                        pem_insert_cert = TRUE;
					pem_crl(issuer, clearmsg_1, cadir);
				}


				before.octets  = &pemmsg->octets[from];
				before.noctets = to - from;
				from = pos;

				aux_append_OctetString(clearmsg, &before);
				aux_append_OctetString(clearmsg, clearmsg_1);
				free(clearmsg_1->octets);
				clearmsg_1->octets = NULL;

				while((cur_depth <= depth) && found) {
					form_pos = pos;
					cur_depth++;
					found = !aux_searchitem(pemmsg, PEM_Boundary_Begin, &pos);
					while(found && !aux_searchitem(pemmsg, PEM_Boundary_End, &form_pos) && (pos > form_pos)) cur_depth--;
				}
				cur_depth--;

				if((from < pemmsg->noctets) && ((pemmsg->octets[from] == '\n') || (pemmsg->octets[from] == '\r'))) {
					from++;
					if((from < pemmsg->noctets) && (((pemmsg->octets[from] == '\r') && (pemmsg->octets[from - 1] == '\n'))
						|| ((pemmsg->octets[from] == '\n') && (pemmsg->octets[from - 1] == '\r')))) from++;
				}

			} while(found);
		}

		before.noctets = pemmsg->noctets - from;
		before.octets  = &pemmsg->octets[from];
		aux_append_OctetString(clearmsg, &before);
		aux_free_OctetString(&pemmsg);
		free(pemmsg_1);
		aux_free_OctetString(&clearmsg_1);
		pemmsg = clearmsg;
		cur_depth = pos = from = to = found = 0;

	} while(pem_Depth >= 0);

	if(pem_verbose_1) {
		if(ofname) fprintf(stderr, "Write clearmessage to file \"%s\".\n", ofname);
		else fprintf(stderr, "Write clearmessage to stdout\n");
	}
	if(aux_OctetString2file(clearmsg, ofname, 2)) {
		fprintf(stderr, "Can't write clearmessage file %s\n", ofname); 
		aux_add_error(EINVALID, "Can't write clearmessage file", ofname, char_n, proc);
	}
	if(peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0)) sec_del_key (peminfo.encryptKEY->keyref);

	aux_free_OctetString(&clearmsg);
	aux_free2_PemInfo(peminfo);
	return (found | scanrc);
}


int	pem_certify (ifname, ofname, verbose, cadir)
/* input parameters: */
char	*ifname, *ofname;
Boolean verbose;
char	*cadir;
{
	RC		scanrc;
	PemInfo      peminfo;
	SET_OF_PemCrlWithCerts *set_of_pemcrlwithcerts;
	SET_OF_DName 	*issuer;
	OctetString *clearmsg, *pemmsg, *pemmsg_1, *repl_msg, *newcert;
	char	 *originator_name;
	int	i, pos = 0;
	char *proc = "pem_certify";


        RC              rc;
	AlgId           *algorithm = DEF_ISSUER_ALGID;
        Key             key;
	Certificate     *cert, *protocert;
	Certificates    orig_cert;
	FCPath          fcpath;
	FCPath          *fcp;
	PKRoot          *pkroot;
	Name		*printrepr;
	char	        *psename = CNULL, *psepath = CNULL, *home, * pin;
	char		*cadir_abs, *logpath;
        char            verify = FALSE;
	char		*cert_filename, *curr_time;
	ToBeSigned      *tbs;
	SET_OF_Certificate * soc;


	pem_verbose_1 = verbose;

	/* allocate space for saving MIC-info   this will be done in pem_get_header */

	mic_for_certification = (OctetString **)calloc(1, 3*sizeof(OctetString *));
	pemmsg_1 = (OctetString *)calloc(1, sizeof(OctetString));
	if(pem_verbose_1) {
		if(ifname) fprintf(stderr, "Read PEM message from file \"%s\".\n", ifname);
		else fprintf(stderr, "Read PEM message from stdin\n");
	}
	if( !(pemmsg = aux_file2OctetString( ifname )) ) {
		fprintf(stderr, "Can't read PEM message file %s\n", ifname); 
		aux_add_error(EINVALID, "Can't read PEM message file", ifname, char_n, proc);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	}

	if(pem_verbose_1) fprintf(stderr, "Scan PEM message\n");


	peminfo.confidential	= peminfo.clear = FALSE;
	peminfo.encryptKEY	= (Key *)0;
	peminfo.origcert	= (Certificates *)0;
	peminfo.signAI		= (AlgId        *)0;
	peminfo.recplist	= (RecpList     *)0; 

	if(aux_searchitem(pemmsg, PEM_Boundary_Begin, &pos)) {
		if(pem_verbose_0) fprintf(stderr, "WARNING: There is no PEM Begin Boundary line\n"); 
		aux_add_error(EINVALID, "no PEM Begin Boundary line", pemmsg, OctetString_n, proc);
		free(pemmsg_1);
		free(mic_for_certification);
		mic_for_certification = 0;
		return(-1);
	}
	pemmsg_1->octets = pemmsg->octets+pos;
	pemmsg_1->noctets = pemmsg->noctets-pos;
	pos = 0;

	if(aux_searchitem(pemmsg_1, PEM_Boundary_End, &pos)) {
		if(pem_verbose_0) fprintf(stderr, "WARNING: There is no PEM End Boundary line\n"); 
		aux_add_error(EINVALID, "no PEM End Boundary line", pemmsg, OctetString_n, proc);
		free(pemmsg_1);
		free(mic_for_certification);
		mic_for_certification = 0;
		return(-1);
	}
	pemmsg_1->noctets = pos - strlen(PEM_Boundary_End);

/* pemmsg_1 is pem-message without boundary lines */
	clearmsg = (OctetString * )calloc(1, sizeof(OctetString));

/* scan PEM message */
	scanrc = pem_scan(&peminfo, &set_of_pemcrlwithcerts, &issuer, clearmsg, pemmsg_1, CERTIFY);
	 if(scanrc == -1) {
		if(peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0)) sec_del_key (peminfo.encryptKEY->keyref);
/*		af_pse_close(0); */
		aux_free_OctetString(&pemmsg);
		free(pemmsg_1);
		aux_free_OctetString(&clearmsg);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	} 

        if(!cadir) cadir = DEF_CADIR;


	/* O.K. skip to CA dir */

        if(cadir[0] != '/') {
		home = getenv("HOME");
		if (!home) home = "";
		cadir_abs = (char *)malloc(strlen(home)+strlen(cadir)+10);
		strcpy(cadir_abs, home);
		strcat(cadir_abs, "/");
		strcat(cadir_abs, cadir);
	}
	else {
		cadir_abs = (char *)malloc(strlen(cadir)+10);
		strcpy(cadir_abs, cadir);
	}

	logpath = (char *)malloc(strlen(cadir_abs)+10);
	strcpy(logpath, cadir_abs);
	strcat(logpath, "/");
	strcat(logpath, CALOG);

	if ((logfile = fopen(logpath, LOGFLAGS)) == (FILE * ) 0) {
		fprintf(stderr, "Can't open %s\n", CALOG);
		aux_add_error(EINVALID, "Can't open", CALOG, char_n, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	}

	cert = peminfo.origcert->usercertificate;

	/* include tests of prototype certificate before signing */

        /* verify signature of prototype certificate with 
           public key to be certified                            */


        key.key = cert->tbs->subjectPK;
        key.keyref = 0;
        key.pse_sel = (PSESel *)0;


	if ( verify ) {
        	rc = sec_verify(cert->tbs_DERcode, cert->sig, END, &key, (HashInput * ) 0);
        	if(rc) {
               	 	fprintf(stderr, "Can't verify prototype certificate\n");
			aux_add_error(EINVALID, "Can't verify prototype certificate", CNULL, 0, proc);
			if(verbose) aux_fprint_error(stderr, 0);
			LOGAFERR;
			return (-1);
		}
	}


	printrepr = aux_DName2Name(cert->tbs->subject);
        if(af_cadb_add_user(printrepr, cadir_abs) < 0) {
                LOGERR("can't access user db");
                fprintf(stderr, "Can't access user db\n");
		aux_add_error(EINVALID, "can't access user db", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
        }
	free(printrepr);


	/* get issuer as name of PSE */
	if (cert->tbs->issuer) {
		aux_free_DName (&cert->tbs->issuer);
	}
	cert->tbs->issuer = af_pse_get_Name();

	if (cert->tbs->notbefore) {
		free (cert->tbs->notbefore);
		cert->tbs->notbefore = CNULL;
	}
	if (cert->tbs->notafter) {
		free (cert->tbs->notafter);
		cert->tbs->notafter = CNULL;
	}

	cert->tbs->notbefore = aux_current_UTCTime();
	cert->tbs->notafter = aux_delta_UTCTime(cert->tbs->notbefore);

	cert->tbs->serialnumber = af_pse_incr_serial();
	cert->tbs->version = 0;           /* default version */

	aux_free_OctetString(&cert->tbs_DERcode);
	if (cert->sig) aux_free_KeyInfo( &cert->sig );
	cert->sig = (Signature * )malloc(sizeof(Signature));
	cert->sig->signAI = af_pse_get_signAI();
	if ( ! cert->sig->signAI ) {
                fprintf(stderr, "Cannot determine the algorithm associated to your own secret signature key\n");
		aux_add_error(EREADPSE, "af_pse_get_signAI failed", CNULL, 0, proc);
		if (verbose) aux_fprint_error(stderr, 0);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	}

	if (aux_ObjId2AlgType(cert->sig->signAI->objid) == ASYM_ENC )
		cert->sig->signAI = aux_cpy_AlgId(algorithm);

	cert->tbs->signatureAI = aux_cpy_AlgId(cert->sig->signAI);
	cert->tbs_DERcode = e_ToBeSigned(cert->tbs);
           
	if (!cert->tbs_DERcode || (af_sign(cert->tbs_DERcode, cert->sig, END) < 0)) {
                fprintf(stderr, "AF Error with CA Signature\n");
		aux_add_error(EINVALID, "AF Error with CA Signature", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		LOGAFERR;
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	}

	if (af_cadb_add_Certificate(0, cert, cadir_abs)) {
		LOGERR("Can't access cert db");
		aux_add_error(EINVALID, "can't access user db", CNULL, 0, proc);
		if(verbose) aux_fprint_error(stderr, 0);
		free(mic_for_certification);
		mic_for_certification = 0;
		return (-1);
	}


/* create message to reply */
	repl_msg = (OctetString * )calloc(1, sizeof(OctetString));
	repl_msg->noctets = 0;
	repl_msg->octets = CNULL;

	pem_insert_cert = TRUE;
	aux_free_RecpList(&peminfo.recplist);



	

        soc = (SET_OF_Certificate *)malloc(sizeof(SET_OF_Certificate));
        soc->element = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0);

        if(aux_cmp_DName(soc->element->tbs->issuer, soc->element->tbs->subject))
	    soc->next = af_pse_get_CertificateSet(SIGNATURE);
        else soc = af_pse_get_CertificateSet(SIGNATURE);

	fcp = (FCPath * )malloc(sizeof(FCPath));

	fcp->liste = soc;
	fcp->next_forwardpath = af_pse_get_FCPath(NULLDNAME);
	

	peminfo.origcert->forwardpath = fcp;

	pkroot = af_pse_get_PKRoot();
	protocert = af_PKRoot2Protocert(pkroot);
	if(pkroot) aux_free_PKRoot(&pkroot);
	if(protocert) {
	        soc = (SET_OF_Certificate *)calloc(1, sizeof(SET_OF_Certificate));
        	soc->element = protocert;
		soc->next = (SET_OF_Certificate *)0;
		while(fcp->next_forwardpath) fcp = fcp->next_forwardpath;
		fcp->next_forwardpath = (FCPath * )calloc(1, sizeof(FCPath));
		fcp = fcp->next_forwardpath;
		fcp->liste = soc;
		fcp->next_forwardpath = (FCPath *)0;
	}


	pem_create(&peminfo, clearmsg, repl_msg);
	if(pem_verbose_1) {
		if(ofname) fprintf(stderr, "Write clearmessage to file \"%s\".\n", ofname);
		else fprintf(stderr, "Write clearmessage to stdout\n");
	}
	if(aux_OctetString2file(repl_msg, ofname, 2)) {
		fprintf(stderr, "Can't write reply message file %s\n", ofname); 
		aux_add_error(EINVALID, "Can't write reply message file", ofname, char_n, proc);
	}
	if(peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0)) sec_del_key (peminfo.encryptKEY->keyref);
/*	af_pse_close(0); */

	aux_free_OctetString(&clearmsg);
	free(pemmsg_1);
	aux_free2_PemInfo(peminfo);
	return (scanrc);
}



int	pem_write (recips, ifname, ofname, encr, clear, verbose)
/* input parameters: */
RecpList *recips; /* only recips->recpcert->tbs->subject is filled on input */
char	*ofname, *ifname;
Boolean  encr, clear, verbose;
{
	int	rc;
	PemInfo      peminfo;
	OctetString * clearmsg, *pemmsg;
	RecpList    * rpl;
	KeyInfo     * ki;
	SET_OF(Certificate) * so;
        PSESel *pse_sel;
	char *proc = "pem_write";

	if (pem_verbose_1) {
		if(ifname) fprintf(stderr, "Read clearmessage from file \"%s\".\n", ifname);
		else fprintf(stderr, "Read clearmessage from stdin\n");
	}

	if ( !(clearmsg = aux_file2OctetString( ifname )) ) {
		aux_add_error(EINVALID, "Cannot read file", ifname, char_n, proc);
		fprintf(stderr, "Couldn't read clear-text file \"%s\". Can't create PEM message. Sorry.\n", ifname);
		return (-1);
	}

	pemmsg = (OctetString * )calloc(1, sizeof(OctetString));

	if (pem_verbose_1) fprintf(stderr, "Build up PemInfo\n");

	if (!(pse_sel = af_pse_open(0, FALSE))) {
		aux_add_error(EINVALID, "Cannot open pse", 0, 0, proc);
		return (-1);
	}
        free(pse_sel);

	peminfo.confidential = encr;  /* input param */
	peminfo.clear        = clear; /* input param */
	peminfo.origcert     = (Certificates * )0;
	peminfo.signAI       = (AlgId * )0;

	if (encr) peminfo.recplist = recips;          /* input param: certificate-owner is set*/
	else      peminfo.recplist = (RecpList * )0;  /* mic-only or mic-clear: */		

	if ( (rc = pem_cinfo(&peminfo)) != OK ) {
		aux_add_error(EINVALID, "Couldn't collect sufficient informations for a PEM message", 0, 0, proc);
		if ( peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0) ) {
			if ( sec_del_key (peminfo.encryptKEY->keyref) < 0 )
				aux_add_error(EINVALID, "DES-key reference not deleted", 0, 0, proc);
			else if(pem_verbose_1) fprintf(stderr, "DES-key reference deleted.\n");
		}
/*		af_pse_close(0); */
		return (rc);
	}

	if (pem_verbose_1) fprintf(stderr, "Create pem-message\n");

	if ( (rc = pem_create(&peminfo, clearmsg, pemmsg)) != OK ) {
		aux_add_error(EINVALID, "pem_create failed", &peminfo, PemInfo_n, proc);
		return (-1);
	}

	if (pem_verbose_1) {
		if(ofname) fprintf(stderr, "Write PEM message to file \"%s\".\n", ofname);
		else fprintf(stderr, "Write PEM message to stdout\n");
	}

	if ( (rc = aux_OctetString2file( pemmsg, ofname, 2)) < 0 ) {
		aux_add_error(EINVALID, "Couldn't write file", ofname, char_n, proc);
	}

	if ( peminfo.encryptKEY && (peminfo.encryptKEY->keyref > 0) ) {
		if ( sec_del_key (peminfo.encryptKEY->keyref) < 0 )
			aux_add_error(EINVALID, "error: DES-key reference not deleted.\n", 0, 0, proc);
		else if (pem_verbose_1) fprintf(stderr, "DES-key reference deleted.\n");
	}

/*	af_pse_close(0); */
	return (rc);
}



int	pem_write_crl(issuer, ofname, crl, verbose, cadir)
/* input parameters: */
SET_OF_DName *issuer;
char	*ofname;
PEM_CRL_Mode crl;
Boolean  verbose;
char	*cadir;
{
	int	rc;
	OctetString *pemmsg;
	RecpList    * rpl;
	KeyInfo     * ki;
	SET_OF(Certificate) * so;
        PSESel *pse_sel;
	char *proc = "pem_write_crl";

	pem_insert_cert = TRUE;

	pemmsg = (OctetString * )calloc(1, sizeof(OctetString));

	if (!(pse_sel = af_pse_open(0, FALSE))) {
		aux_add_error(EINVALID, "Cannot open pse", 0, 0, proc);
		return (-1);
	}
        aux_free_PSESel(&pse_sel);

	if (pem_verbose_1) fprintf(stderr, "Create pem-message\n");

	if(crl == CRL_MESSAGE) {
		if ( (rc = pem_crl(issuer, pemmsg, cadir)) != OK ) {
			aux_add_error(EINVALID, "pem_crl failed", 0, 0, proc);
			return (-1);
		}
	} 
	else {


		if ( (rc = pem_crl_retrieval_request(issuer, pemmsg)) != OK ) {
			aux_add_error(EINVALID, "pem_crl_retrieval_request failed", 0, 0, proc);
			return (-1);
		}

	}
	if (pem_verbose_1) {
		if(ofname) fprintf(stderr, "Write PEM message to file \"%s\".\n", ofname);
		else fprintf(stderr, "Write PEM message to stdout\n");
	}

	if ( (rc = aux_OctetString2file( pemmsg, ofname, 2)) < 0 ) {
		aux_add_error(EINVALID, "Couldn't write file", ofname, char_n, proc);
	}

	return (rc);
}

