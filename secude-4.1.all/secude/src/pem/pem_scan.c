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

/*-----------------------pem_scan.c---------------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institut fuer TeleKooperationsTechnik (I2)         */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDe" 1991,92,93                */
/* 	Grimm/Nausester/Schneider/Viebeg/Vollmer/                   */
/* 	Surkau/Reichelt/Kolletzki                     et alii       */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   pem             VERSION   4.0                          */
/*                              DATE   12.02.1993                   */
/*                                BY   Reichelt/Kolletzki           */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/* DESCRIPTION                                                      */
/*   This module presents functions to create and scan              */
/*   a PEM heading 			                            */
/*                                                                  */
/* EXPORT                                                           */
/*                                                                  */
/*  pem_create()          pem_scan()                                */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*  af_ ... and sec_ ...crypt/key functions                         */
/*  aux_ functions                                                  */
/*                                                                  */
/*------------------------------------------------------------------*/

#include "pem.h"
#include <stdio.h>

#define	MAX_INT		32000	/* number to indicate an invalid text length		*/
#define	MAX_PARTS	3	/* maximum of header field parts			*/
#define	EDELIM		400	/* error code for wrong delimiter			*/
#define	TABLE_LEN	64	/* length of character table of valid characters	*/

#define HEADERFIELD(name) strcat(strcpy(headerfield,name),":")

extern OctetString *aux_create_OctetString(), *aux_64(), *aux_encrfc(),	*aux_decrfc(), *aux_ostr_get64(),
		   *aux_enchex(), *aux_dechex(), *aux_canon(), *aux_decanon(), *aux_de64();
extern	char	   *aux_ObjId2Name();
extern	ObjId	   *aux_Name2ObjId();


struct	HD {	
	OctetString *item[MAX_PARTS];	/* value of header field item			*/
	char	     avail;		/* is item valid ?				*/
	int	     num;		/* number of items in the field			*/
};
static 	char 		headerfield[40];


/************************************************************************************************/
/*	pem_find_delim										*/
/* 												*/
/* find '\n\n' or '\n\r\n' in msg as delimiter between header and body; if ok, pos points to 	*/
/* the 1st '\n'											*/
/************************************************************************************************/
RC	pem_find_delim(msg, pos)
OctetString	*msg;
int		*pos;
{
	char	*proc = "pem_find_delim";


	/* check parameters */

	if(!msg || !pos) {
		aux_add_error(EINVALID, "msg or pos is NULL pointer", 0, 0, proc);
		return(-1);
	}

	/* search for delimiter	*/

	(*pos) = 0;
	while((*pos) < msg->noctets) {
		while((*pos < msg->noctets) && (msg->octets[*pos] !='\n')) (*pos)++;
		if(((*pos) + 1) >= msg->noctets) {
			if(pem_verbose_1) fprintf(stderr, "\n--> ERROR in %s: EOF reached, no PEM header delimiter found\n\n", proc);
			return(-1);							/* EOF		*/
		}
		(*pos)++;
		if(msg->octets[*pos] =='\n') {
			(*pos)--;
			return(0);							/* \n\n		*/
		}
		if((msg->octets[*pos] =='\r') && (*pos < (msg->noctets - 1))&& (msg->octets[*pos + 1] =='\n')) {
			(*pos)--;
			return(0);							/* \n\r\n	*/
		}
		(*pos)++;
	}
	return(-1);									/* EOF		*/
}



/************************************************************************************************/
/* 	pem_check										*/
/* 												*/
/* check ostr on valid characters								*/
/************************************************************************************************/

RC pem_check(ostr)
OctetString	*ostr;
{
	int	index_1;
	char	tab[256], *proc = "pem_check";

/* valid characters										*/
	static rfctable[TABLE_LEN] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T','U', 
		'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't','u', 
		'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9','+', '/'
	};


/* check parameter										*/
	if(!ostr) {
		aux_add_error(EINVALID, "ostr invalid", 0, 0, proc);
		return(-1);
	}

/* init table											*/
	for(index_1 = 0; index_1 < 256; index_1++) tab[index_1] = FALSE;

	for(index_1 = 0; index_1 < TABLE_LEN; index_1++) tab[rfctable[index_1]] = TRUE;

/* look up input characters in table								*/

	for(index_1 = 0; index_1 < ostr->noctets; index_1++) if(!tab[ostr->octets[index_1]]) {
		aux_add_error(EMSGBUF, "message contains invalid characters", 0, 0, proc);
		if(pem_verbose_0) fprintf(stderr, "--> in %s: message contains invalid characters! ", proc);
		if(pem_verbose_1) fprintf(stderr, "(\'%c\' = %02xh)\n", ostr->octets[index_1], ostr->octets[index_1]);
		return(-1);
	} 

	return(0);
}



/************************************************************************************************/
/* 	pem_string2string									*/
/* 												*/
/* put valid characters of string_2 into string_1						*/
/* number points to length of string_2 and after processing to length of string_1		*/
/* len points after processing to amount of checked characters					*/
/* char may be pointing to a delimiting character (else pointing to NULL)			*/
/************************************************************************************************/

RC pem_string2string(strng_1, string_2, number, len, ichar)
char	**strng_1, *string_2;
int	*number, *len;
char	*ichar;
{
	int	index_1, index_2, index_3;
	char	*string_1, *proc = "pem_string2string";


/* check parameters										*/
	if(!string_2 || !number || !len) {
		aux_add_error(EINVALID, "string_2, number or len is NULL pointer", 0, 0, proc);
		return(-1);
	}

/* count valid characters									*/
	for(*len = index_1 = 0; ((*len) < (*number)) && (!ichar || (string_2[*len] != *ichar)); (*len)++) 
		if((string_2[*len] != ' ') && (string_2[*len] != '\n') && (string_2[*len] != '=') 
			&& (string_2[*len] != '\r')) index_1++;

	/* memory allocation for destination */

	string_1 = (char *)calloc(1, index_1 + 1);

	/* copy valid source characters to destination	*/

	for(index_1 = index_2 = 0; (index_1 < (*number)) && (!ichar || (string_2[index_1] != *ichar)); index_1++)
		if((string_2[index_1] != ' ') && (string_2[index_1] != '=') && (string_2[index_1] != '\r') 
			&& (string_2[index_1] != '\n')) 
			string_1[index_2++] = string_2[index_1];
	string_1[index_2] = 0;
	(*number) = index_2;
	*strng_1 = string_1;

	return(0);
}


/************************************************************************************************/
/* 	pem_free_HD										*/
/* 												*/
/* free header											*/
/************************************************************************************************/

RC	pem_free_HD(header, only_one)
struct HD	header[];
char		only_one;
{
	int		part, item;
	char		*proc = "pem_free_HD";


/* free header											*/
	if(header) for(item = 0; only_one ? !item : (item < ONCE_MAX); item++) if(header[item].avail || only_one) {
		for(part = 0; part < header[item].num; part++) {
			aux_free_OctetString(&header[item].item[part]);
		}
		header[item].avail = FALSE;
		header[item].num   = 0;
	}

	if(MF_check && pem_verbose_1) MF_fprint(stderr);

	return(0);
}


/************************************************************************************************/
/* 	pem_search_next										*/
/* 												*/
/* evaluate type (next_hfield) and position (beg_next_hfield) of next header field beginning	*/
/* from beg_next_hfield	in buf									*/
/************************************************************************************************/

RC	pem_search_next(buf, next_hfield, beg_next_hfield)
OctetString	*buf;
int		*next_hfield, *beg_next_hfield;
{
	int	i_1, i_2, begin;
	char	*proc = "pem_search_next";

	/* check parameters */

	if(!buf || !next_hfield || !beg_next_hfield) {
		aux_add_error(EINVALID, "buf, next_hfield or beg_next_hfield is NULL pointer", 0, 0, proc);
		return(-1);
	}

	begin = *beg_next_hfield;
	for(i_1 = *next_hfield = 0, i_2 = begin, *beg_next_hfield = buf->noctets; rXH_kwl[i_1].name; i_1++) {
		if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[i_1].name), &i_2) && (i_2 < *beg_next_hfield)) {
			*beg_next_hfield = --i_2;
			*next_hfield = i_1;
		} 
		i_2 = begin;
	}

	return(*next_hfield ? 0 : (buf->noctets == *beg_next_hfield));
}



/************************************************************************************************/
/* 	pem_cpy_next										*/
/* 												*/
/* copy	header field from buf to dest from position begin up to begin+length if number of parts	*/
/* (devided by c if c not NULL) not greater than maxi						*/
/************************************************************************************************/
RC	pem_cpy_next(buf, dest, begin, length, maxi, c)
OctetString	*buf;
struct HD	*dest;
int		*begin;
int		length, maxi;
char		*c;
{
	int	len, diff, n, sum = 0;
	char	*proc = "pem_cpy_next";

/* check parameters										*/
	if(!buf || !dest || !begin) {
		aux_add_error(EINVALID, "buf, dest or begin is NULL pointer", 0, 0, proc);
		return(1);
	}

	dest->num = 0;
	len = diff = length;

/* copy header field										*/
	while((len > 0) && (dest->num < maxi)) { 
		dest->item[dest->num] = (OctetString *)calloc(1, sizeof(OctetString));
		if(pem_string2string(&dest->item[dest->num]->octets, &buf->octets[*begin], &diff, &n, c)) {
			aux_add_error(EMSGBUF, "pem_string2string failed", 0, 0, proc);
			pem_free_HD(&dest, TRUE);
			return(-1);
		}
		n++;
		sum += (dest->item[dest->num++]->noctets = diff);
		*begin	+= n;
		diff	=  (len	-= n);
	}
	dest->avail = (dest->num > 0) && (dest->num <= maxi) && sum;

	return(0);
}


/************************************************************************************************/
/* 	pem_get_header										*/
/* 												*/
/* get info and signature from buf								*/
/************************************************************************************************/

RC	pem_get_header(info, set_of_pemcrlwithcerts, issuer, signature, buf)
PemInfo		*info;
SET_OF_PemCrlWithCerts **set_of_pemcrlwithcerts;
SET_OF_DName 	**issuer;
BitString	*signature;
OctetString	*buf;
{
	int		start[ONCE_MAX], num[ONCE_MAX], index, index_1, index_2, index_3, number;
	int		i_1, i_2, pem_curr_text_idx, pem_next_hdfield_type, diff, n, len, serial;
	char		*string, *s, c, invalid, found, first, *proc = "pem_get_header";
	char		myself, done;
	OctetString	*ostr = NULL, crlstr, *decoded, *printable;
	BitString	sign;
	EncryptedKey	encrypted_key;
	struct HD	field, *recp;
	struct HD	header[ONCE_MAX];
	struct HD	key;			/* Originator's Key-Info */
	Certificate	*cert = (Certificate *)0, *mycert = (Certificate *)0;
	FCPath		*path;
	ToBeSigned	*tbs;
	SET_OF_Certificate	*cross;
	DName		*DN, *subj;
	SET_OF_PemCrlWithCerts       *set_of_pemcrlwithcerts1;
	SET_OF_DName 	*issuer1;
	Boolean PEM_conformant, wrong_hash;


	*set_of_pemcrlwithcerts = 0;
	*issuer = 0;


	/* check parameters */

	if(!buf) {
		aux_add_error(EINVALID, "buf is NULL pointer", 0, 0, proc);
		return(-1);
	}

	myself = FALSE;
	sign.bits = 0;
	sign.nbits = NULL;
	for(index_1 = 0; index_1 < ONCE_MAX; index_1++)	{
		num[index_1]			= MAX_INT;
		start[index_1] 			= 0;
		for(index_2 = 0; index_2 < MAX_PARTS ; index_2++) 
			header[index_1].item[index_2]	= (OctetString *) 0;
		header[index_1].avail		= FALSE;
		header[index_1].num		= 0;
	}


	/* look for header fields and get their position */

	for(index_1 = 0; index_1 < ONCE_MAX; index_1++) 
		header[index_1].avail = !aux_searchitem(buf, rXH_kwl[index_1].name, &start[index_1]);

	/* evaluate length of header field contents */

	for(index_1 = 0; index_1 < ONCE_MAX; index_1++)	if(header[index_1].avail) {
		start[index_1]++;
		for(index_2 = 0; rXH_kwl[index_2].name; index_2++) {
				index_3 = start[index_1];
				if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[index_2].name), &index_3) ) 
					if(index_3 - strlen(headerfield) - start[index_1] < num[index_1])
						num[index_1] = index_3 - strlen(headerfield) - start[index_1];
		}
		if(num[index_1] == MAX_INT) num[index_1] = buf->noctets - start[index_1];
		if(num[index_1] <= 0) header[index_1].avail = FALSE;
	}


	/* copy contents of header fields into 'header'	*/

	key.num = 0;
	key.avail = FALSE;
	c	 = ',';
	for(index_1 = 0; index_1 < ONCE_MAX; index_1++) if(header[index_1].avail)
		if((index_2 = pem_cpy_next(buf, &header[index_1], &start[index_1], num[index_1], MAX_PARTS, &c))) {
			if(index_2 == 1) aux_add_error(EINVALID, "pem_cpy_next", 0, 0, proc);
			pem_free_HD(header, FALSE);
			return(-1);
		}


/*
 *   Proc-Type
 */ 

	if(pem_verbose_1) fprintf(stderr, "  Scanning Proc-Type header field ... ");

	if(!(header[PEM_PROC_TYPE].avail)) {
		aux_add_error(EMSGBUF, "no Proc-Type header field found", 0, 0, proc);
		fprintf(stderr, "Error: Proc-Type header field not found\n");
		pem_free_HD(header, FALSE);
		return(-1);
	}

 	if(header[PEM_PROC_TYPE].num != 2) {
		aux_add_error(EMSGBUF, "Proc-Type header field invalid", 0, 0, proc);
		fprintf(stderr, "found (%s, %s)\n", header[PEM_PROC_TYPE].item[0]->octets, header[PEM_PROC_TYPE].item[1]->octets);
		fprintf(stderr, "Error: Proc-Type header field invalid\n");
		pem_free_HD(header, FALSE);
		return(-1);
	}

	for(index = 0; proc_type_v[index].name 
		&& strcasecmp(header[PEM_PROC_TYPE].item[0]->octets, proc_type_v[index].name); index++);

	if(!proc_type_v[index].name) {
		aux_add_error(EMSGBUF, "unknown PEM format", 0, 0, proc);
		fprintf(stderr, "found (%s, %s)\n", header[PEM_PROC_TYPE].item[0]->octets, header[PEM_PROC_TYPE].item[1]->octets);
		fprintf(stderr, "Error: Proc-Type header field has unknown PEM format\n");
		pem_free_HD(header, FALSE);
		return(-1);
	}

	for(index = 0; proc_type_t[index].name 
		&& strcasecmp(header[PEM_PROC_TYPE].item[1]->octets, proc_type_t[index].name); index++);

	if(!proc_type_t[index].name) {
		aux_add_error(EMSGBUF, "unknown word in Proc_Type-header-field", 0, 0, proc);
		fprintf(stderr, "found (%s, %s)\n", header[PEM_PROC_TYPE].item[0]->octets, header[PEM_PROC_TYPE].item[1]->octets);
		fprintf(stderr, "Error: Proc-Type header field has unknown keyword\n");
		pem_free_HD(header, FALSE);
		return(-1);
	}

	if(pem_verbose_1) fprintf(stderr, "<%s,%s> valid\n", header[PEM_PROC_TYPE].item[0]->octets, header[PEM_PROC_TYPE].item[1]->octets);

	switch(index) {
		case	PEM_ENC :					/* type "ENCRYPTED"	*/
				info->confidential = TRUE;
				info->clear = FALSE;
				if(!(mycert = af_pse_get_Certificate(ENCRYPTION, 0, 0))) {
					aux_add_error(EREADPSE, "af_pse_get_Certificate failed", 0, 0, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Error: can't get own signature certificate from PSE-object Cert\n");
					return(-1);
				}
				break;

		case	PEM_CRL :					/* type "CRL"		*/

				set_of_pemcrlwithcerts1 = *set_of_pemcrlwithcerts;
				index_1 = 0;
				if(aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_CRL].name), &index_1)) {
						if(pem_verbose_1) fprintf(stderr, "    ");
						if(pem_verbose_0) fprintf(stderr, "Warning: Proc-Type CRL, but no CRL found.\n");
						return(0);
				}

				i_2 = 1;
				do {
					i_1 = i_2;
					index_2 = index_1++;
					index_1 = buf->noctets;

					index_3 = index_2;
					if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_CRL].name), &index_3)) {
						if(index_3 < index_1) {
							index_1 = index_3;	
							i_2 = 1;
						}
					}
					index_3 = index_2;
					if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_CERTIFICATE].name), &index_3)) {
						if(index_3 < index_1) {
							index_1 = index_3;	
							i_2 = 2;
						}
					}
					index_3 = index_2;
					if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_ISSUER_CERTIFICATE].name), &index_3)) {
						if(index_3 < index_1) {
							index_1 = index_3;	
							i_2 = 3;
						}
					}
					index_3 = index_2;
					if(!aux_searchitem(buf, ":", &index_3)) {
						if(index_3 < index_1) {
 							aux_add_error(EMSGBUF, "headerfield not allowed in CRL message", buf, OctetString_n, proc);
							if(pem_verbose_1) fprintf(stderr, "    ");
							fprintf(stderr, "Error: Proc-Type CRL, headerfield not allowed in CRL message\n");
							return(-1);
						}
					} else {
							index_1 = buf->noctets;	
							headerfield[0] = '\0';
							i_2 = 4;
					}


					if((i_1 == 1 && i_2 != 2) || (i_1 == 3 && i_2 == 2)) {
 						aux_add_error(EMSGBUF, "Wrong order of header fields", buf, OctetString_n, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL, wrong order of header fields\n");
						return(-1);
					}

					while (index_2<buf->noctets && buf->octets[index_2] != '\n') index_2++;
					crlstr.octets = buf->octets + index_2 + 1;
					crlstr.noctets = index_1 - strlen(headerfield) - index_2 - 1;

					if(!(printable = aux_de64(&crlstr, 1))) {
						aux_add_error(EMSGBUF, "aux_de64 failed", &crlstr, OctetString_n, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL, cannot decode CRL\n");
						return(-1);
					}
					if(!(decoded = aux_decrfc(printable))) {
						aux_add_error(EMSGBUF, "aux_decrfc failed", printable, OctetString_n, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL, cannot decode CRL\n");
						return(-1);
					}
					aux_free_OctetString(&printable);
					if(i_1 == 1) {

						*set_of_pemcrlwithcerts = (SET_OF_PemCrlWithCerts *)calloc(1, sizeof(SET_OF_PemCrlWithCerts));
						(*set_of_pemcrlwithcerts)->next = set_of_pemcrlwithcerts1;
						set_of_pemcrlwithcerts1 = *set_of_pemcrlwithcerts;
	
						set_of_pemcrlwithcerts1->element = (PemCrlWithCerts *)calloc(1, sizeof(PemCrlWithCerts));
	
						if(!(set_of_pemcrlwithcerts1->element->pemcrl = d_PemCrl(decoded))) {
							aux_add_error(EDECODE, "d_PemCrl failed", 0, 0, proc);
							if(pem_verbose_1) fprintf(stderr, "    ");
							fprintf(stderr, "Error: Proc-Type CRL, cannot decode CRL\n");
							return(-1);
						}
						aux_free_OctetString(&decoded);
					} 
					else {

						if(!(cert = d_Certificate(decoded))) {
							aux_add_error(EDECODE, "d_Certificate failed", 0, 0, proc);
							if(pem_verbose_1) fprintf(stderr, "    ");
							fprintf(stderr, "Error: Proc-Type CRL, cannot decode Certificate\n");
							return(-1);
						}
						aux_free_OctetString(&decoded);

						if(i_1 == 2) {
							set_of_pemcrlwithcerts1->element->certificates = (Certificates *)calloc(1, sizeof(Certificates));
							first = TRUE;
							set_of_pemcrlwithcerts1->element->certificates->usercertificate = cert;
							set_of_pemcrlwithcerts1->element->certificates->forwardpath = 0;
						}
						else {
							if(first) {
								first = FALSE;
								path = set_of_pemcrlwithcerts1->element->certificates->forwardpath = (FCPath *)calloc(1, sizeof(FCPath));
							}
			
							if(!subj || aux_cmp_DName(subj, cert->tbs->subject)) {
								if(subj) {
									path->next_forwardpath = (FCPath *)calloc(1, sizeof(FCPath));			
									path = path->next_forwardpath;
								}
			
								cross = path->liste = (SET_OF_Certificate *)calloc(1, sizeof(SET_OF_Certificate));	
								path->liste->element = cert;
								if(!(subj = aux_cpy_DName(cert->tbs->subject)))  {
									aux_add_error(EDECODE, "aux_cpy_DName failed", 0, 0, proc);
									return(-1);
								}
			
							} 
							else {
			
								cross->next = (CrossCertificates *)calloc(1, sizeof(CrossCertificates));		
								cross = cross->next;
								cross->element = cert;
							}
						}
					}

				} while (i_2 != 4);
				return(0);
		case	PEM_CRL_RETRIEVAL_REQUEST :					/* type "CRL"		*/

				issuer1 = *issuer;
				index_1 = 0;
				if(aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_ISSUER].name), &index_1)) {
						if(pem_verbose_1) fprintf(stderr, "    ");
						if(pem_verbose_0) fprintf(stderr, "Proc-Type CRL-RETRIEVAL-REQUEST, Warning: no CRL found. Header field ignored.\n");
						return(0);
				}

				i_2 = 1;
				do {
					i_1 = i_2;
					index_2 = index_1++;
					index_1 = buf->noctets;

					index_3 = index_2;
					if(!aux_searchitem(buf, HEADERFIELD(rXH_kwl[PEM_ISSUER].name), &index_3)) {
						if(index_3 < index_1) {
							index_1 = index_3;	
							i_2 = 1;
						}
					}
					index_3 = index_2;
					if(!aux_searchitem(buf, ":", &index_3)) {
						if(index_3 < index_1) {
 							aux_add_error(EMSGBUF, "headerfield not allowed in CRL message", buf, OctetString_n, proc);
							if(pem_verbose_1) fprintf(stderr, "    ");
							fprintf(stderr, "Error: Proc-Type CRL-RETRIEVAL-REQUEST, headerfield not allowed in CRL message\n");
							return(-1);
						}
					} else {
							index_1 = buf->noctets;	
							headerfield[0] = '\0';
							i_2 = 2;
					}



					while (index_2<buf->noctets && buf->octets[index_2] != '\n') index_2++;
					crlstr.octets = buf->octets + index_2 + 1;
					crlstr.noctets = index_1 - strlen(headerfield) - index_2 - 1;

					if(!(printable = aux_de64(&crlstr, 1))) {
						aux_add_error(EMSGBUF, "aux_de64 failed", &crlstr, OctetString_n, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL-RETRIEVAL-REQUEST, cannot decode CRL\n");
						return(-1);
					}
					if(!(decoded = aux_decrfc(printable))) {
						aux_add_error(EMSGBUF, "aux_decrfc failed", printable, OctetString_n, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL-RETRIEVAL-REQUEST, cannot decode CRL\n");
						return(-1);
					}
					aux_free_OctetString(&printable);

					*issuer = (SET_OF_DName *)calloc(1, sizeof(SET_OF_DName));
					(*issuer)->next = issuer1;
					issuer1 = *issuer;

					if(!(issuer1->element = d_DName(decoded))) {
						aux_add_error(EDECODE, "d_DName failed", 0, 0, proc);
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Error: Proc-Type CRL-RETRIEVAL-REQUEST, cannot decode issuer name\n");
						return(-1);
					}
					aux_free_OctetString(&decoded);


				} while (i_2 != 2);
				return(0);

		case	PEM_MCO :					/* type "MIC-ONLY"	*/
				info->confidential = FALSE;
				info->clear = FALSE;
				break;

		case	PEM_MCC :					/* type "MIC-CLEAR"	*/
				info->confidential = FALSE;
				info->clear = TRUE;
				break;
	}

/*
 *   Content-Domain
 */ 

	if(pem_verbose_1) fprintf(stderr, "  Scanning Content-Domain header field ... ");

	if(!header[PEM_CONTENT_DOMAIN].avail) 
		{ if(pem_verbose_1) fprintf(stderr, "Warning: no Content-Domain header field\n"); }
	else if(header[PEM_CONTENT_DOMAIN].num < 1) 
		{ if(pem_verbose_0) fprintf(stderr, "Warning: empty Content-Domain header field (ignored)\n"); }
	else {
		for(index = 0; content_domain[index].name && 
			strcasecmp(header[PEM_CONTENT_DOMAIN].item[0]->octets, content_domain[index].name); index++);

		if(!content_domain[index].name) {
			aux_add_error(EMSGBUF, "Content-Domain invalid", 0, 0, proc);
			fprintf(stderr, "Content-Domain header field invalid <%s>\n", header[PEM_CONTENT_DOMAIN].item[0]->octets);
			pem_free_HD(header, FALSE);
			return(-1);
		}
		pem_content_domain = content_domain[index].value;

		if(pem_verbose_1) fprintf(stderr, "<%s> valid\n", header[PEM_CONTENT_DOMAIN].item[0]->octets);
	}

/*
 *   DEK-Info
 */ 

	/* search algorithm and append encryptKEY */

	if(info->confidential && header[PEM_DEK_INFO].avail && (header[PEM_DEK_INFO].num > 1)) {

		if(pem_verbose_1) fprintf(stderr, "  Scanning DEK-Info header field ... ");

		info->encryptKEY = (Key *)calloc(1, sizeof(Key));
		info->encryptKEY->key = (KeyInfo *)calloc(1, sizeof(KeyInfo));
		info->encryptKEY->key->subjectAI = (AlgId *)calloc(1, sizeof(AlgId));

		if(!(info->encryptKEY->key->subjectAI->objid = aux_Name2ObjId(header[PEM_DEK_INFO].item[0]->octets))) {
			fprintf(stderr, "DEK-Info header field, invalid DEK algorithm <%s>\n", header[PEM_DEK_INFO].item[0]->octets);
			aux_add_error(EMSGBUF, "aux_Name2ObjId failed", header[PEM_DEK_INFO].item[0]->octets, char_n, proc);
			pem_free_HD(header, FALSE);
			return(-1);
		}

		/* append desECB_parm */

		if(!(info->encryptKEY->key->subjectAI->parm = (char *)aux_dechex(header[PEM_DEK_INFO].item[1]))) {
			fprintf(stderr, "DEK-Info header field, invalid IV <%s>\n", header[PEM_DEK_INFO].item[1]->octets);
			aux_add_error(EMSGBUF, "aux_dechex failed", header[PEM_DEK_INFO].item[1], OctetString_n, proc);
			pem_free_HD(header, FALSE);
			return(-1);
		}

		if(pem_verbose_1) fprintf(stderr, "Alg <%s>, IV <%s>\n", header[PEM_DEK_INFO].item[0]->octets, header[PEM_DEK_INFO].item[1]->octets);
	} 
	else if(info->confidential) {
		if(!header[PEM_DEK_INFO].avail) {
			fprintf(stderr, "Proc-Type ENCRYPTED, but no DEK-Info header field found\n");
			aux_add_error(EMSGBUF, "Proc-Type ENCRYPTED, but no DEK-Info header field found", 0, 0, proc);
			pem_free_HD(header, FALSE);
			return(-1);
		}
		if(header[PEM_DEK_INFO].num <= 1) {
			fprintf(stderr, "Proc-Type ENCRYPTED, DEK-Info header field invalid\n");
			pem_free_HD(header, FALSE);
			return(-1);
		}
	}

	info->origcert = (Certificates *)calloc(1, sizeof(Certificates));


/*
 *  Originator-ID-Asymmetric
 *  Originator-Certificate
 */

	/* get originator certificate or ID, issuer certificates and MIC */

	index_2 = index_1 = 0;
	i_1 = i_2 = TRUE;

	while((!(i_1 = aux_searchitem(buf, rXH_kwl[PEM_SENDER_ID].name, &index_1)) && (index_1 < buf->noctets)) || 
		(!(i_2 = aux_searchitem(buf, rXH_kwl[PEM_CERTIFICATE].name, &index_2)) && (index_2 < buf->noctets))) {
		if(pem_verbose_1) fprintf(stderr, "  Scanning Originator information ... ");
		if(i_1) index_1 = buf->noctets - 1;
		if(i_2) index_2 = buf->noctets - 1;

		/* look for next entry	*/

		pem_curr_text_idx = ((index_1 < index_2) ? index_1 : index_2);
		index_1 = index_2 = pem_curr_text_idx + 1;


		if(!pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx)) len = pem_curr_text_idx - (i_1 ? index_1 : index_2) - strlen(rXH_kwl[pem_next_hdfield_type].name);
		else len = buf->noctets - (i_1 ? index_1 : index_2);


		if(!i_1) {

			/* Originator-ID-Asymmetric header field found  */

			if(pem_verbose_1) fprintf(stderr, "Originator-ID-Asymmetric found\n");

			if((i_2 = pem_cpy_next(buf, &field, &index_1, len, MAX_PARTS, &c))) {
				if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
				return(-1);
			}

			if(!(ostr = aux_decrfc(field.item[0]))) {
				aux_add_error(EDECODE, "aux_decrfc of first Originator-ID-Asymmetric parameter failed", 0, 0, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "Error: Originator-ID-Asymmetric, can't RFC-decode first parameter (%s)\n", field.item[0]->octets);
				return(-1);
			}

			DN = d_DName(ostr);
			aux_free_OctetString(&ostr);
			if(!DN) {
				aux_add_error(EDECODE, "d_DName of first Originator-ID-Asymmetric parameter failed", 0, 0, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "Error: Originator-ID-Asymmetric, can't BER-decode first parameter (%s)\n", field.item[0]->octets);
				return(-1);
			} 
			else {
				serial = (field.num > 1 ? pem_OS2inthex(field.item[1]) : 0);
				if(pem_verbose_1) {
					s = aux_DName2Name(DN);
					fprintf(stderr, "        Issuer <%s>, Serial %d\n", s, serial);
					free(s);
				}
			}

			info->origcert->usercertificate = (Certificate *)calloc(1, sizeof(Certificate));

			if((info->origcert->usercertificate->tbs = af_pse_get_TBS(SIGNATURE, 0, DN, serial))) {

				/* Issuer/Serial not found in PKList */

				if(pem_verbose_1) {
					s = aux_DName2Name(info->origcert->usercertificate->tbs->subject);
					fprintf(stderr, "        Originator of this message is: <%s>\n", s);
					free(s);
				}
				invalid = FALSE;
				info->origcert->usercertificate->tbs_DERcode = NULL;
				info->origcert->usercertificate->sig = NULL;
			} 
			else {

				/* try own certificate from Cert */

				free(info->origcert->usercertificate);

				if(!mycert) if(!(mycert = af_pse_get_Certificate(SIGNATURE, 0, 0))) {
					aux_add_error(EREADPSE, "af_pse_get_Certificate failed", 0, 0, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Error: can't get own signature certificate from PSE-object Cert\n");
					return(-1);
				}

				if(!aux_cmp_DName(mycert->tbs->issuer, DN) && (mycert->tbs->serialnumber == serial)) {
					if(!(info->origcert->usercertificate = aux_cpy_Certificate(mycert))) {
						aux_add_error(EINVALID, "aux_cpy_Certificate failed", 0, 0, proc);
						return(-1);
					}
					if(pem_verbose_1) fprintf(stderr, "        you are the originator of this message\n");
					myself = TRUE;
				}
				else {
					s = aux_DName2Name(DN);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Error: Originator-ID-Asymmetric, no certificate of issuer <%s>, serial %d available\n", s, (field.num > 1 ? pem_OS2inthex(field.item[1]) : 0));
					free(s);
					aux_free_error();
					info->origcert->usercertificate = NULL;
				}

			}
			aux_free_DName(&DN);
			pem_free_HD(&field, TRUE);
		}

		if(!i_1 && !info->origcert->usercertificate) {
			index_1--;
			i_1 = !aux_searchitem(buf, rXH_kwl[PEM_CERTIFICATE].name, &index_1) && (index_1 < buf->noctets);
			index_1++;
			if(i_1) fprintf(stderr, "Originator-ID-Asymmetric header field ignored\n ");
		}
		pem_curr_text_idx = index_1;


		if(i_1 && !(i_2 = pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx))) {

			/* Originator-Certificate header field found */

			len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);

			if(pem_verbose_1) fprintf(stderr, "Originator-Certificate found\n");

			if((i_2 = pem_cpy_next(buf, &field, &index_1, len, MAX_PARTS, &c))) {
				if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
				return(-1);
			}

			if(!(ostr = aux_decrfc(field.item[0]))) {
				aux_add_error(EMSGBUF, "aux_decrfc failed", &field.item[0], OctetString_n, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "Can't RFC-decode Originator-Certificate (%s)\n", field.item[0]->octets);
				pem_free_HD(&field, TRUE);
				return(-1);
			}
			if(!(info->origcert->usercertificate = d_Certificate(ostr))) {
				aux_add_error(EDECODE, "d_Certificate failed", 0, 0, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "Can't BER-decode Originator-Certificate (%s)\n", field.item[0]->octets);
				aux_free_OctetString(&ostr);
				pem_free_HD(&field, TRUE);
				return(-1);
			} 
			else {
				if(pem_verbose_1) {
					fprintf(stderr, "  Originator-Certificate:\n");
					aux_fprint_Certificate(stderr, info->origcert->usercertificate);
				}
				else if(pem_verbose_1) {
					s = aux_DName2Name(info->origcert->usercertificate->tbs->subject);
					fprintf(stderr, "Originator of this message is: <%s>\n", s);
					free(s);
				}
				if(!aux_cmp_DName(info->origcert->usercertificate->tbs->issuer, info->origcert->usercertificate->tbs->subject)) {

					/* This is a prototype certificate which is supposed to be a certification request */

					if(pem_verbose_1) fprintf(stderr, "        This is a prototype certificate (probably certification request)\n"); 
				}

			}
				
			aux_free_OctetString(&ostr);
		}

 		pem_free_HD(&field, TRUE);
		index_1 += strlen(rXH_kwl[pem_next_hdfield_type].name);
		first = TRUE;


/*
 *   Key-Info  of Originator
 */
		

		if(pem_next_hdfield_type == PEM_KEY_INFO) {

			/* Key-Info header field corresponding to Originator-ID-Asymmetric  or Originator-Certificate header field */

			if(pem_verbose_1) fprintf(stderr, "  Originator's Key-Info header field found.\n");

			pem_curr_text_idx = index_1;
			pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx);

			if(!myself) index_1 = pem_curr_text_idx + 1;
			else {
				if(pem_next_hdfield_type) len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);
				else len = buf->noctets - index_1;

				if((i_2 = pem_cpy_next(buf, &key, &index_1, len, MAX_PARTS, &c))) {
					if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
					fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
					return(-1);
				}
				index_1 += strlen(rXH_kwl[pem_next_hdfield_type].name);
			}
		}

		myself = myself && key.avail && (key.num > 1);


/*
 *   Issuer-Certificate
 */
	
		/* Issuer Certificate header fields */

		first = TRUE;
		subj = NULL;
		while(pem_next_hdfield_type == PEM_ISSUER_CERTIFICATE) {

			if(pem_verbose_1) fprintf(stderr, "  Issuer-Certificate header field found.\n");

			pem_curr_text_idx = index_1;
			if(!pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx)) len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);
			else len = buf->noctets - index_1;

			if(myself) {
				if(len == buf->noctets - index_1) index_1 = buf->noctets;
				else index_1 = pem_curr_text_idx + 1;
			} else {
				if((i_2 = pem_cpy_next(buf, &field, &index_1, len, MAX_PARTS, &c))) {
					if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
		 			pem_free_HD(&key, TRUE);
					return(-1);
				}
				index_1 += strlen(rXH_kwl[pem_next_hdfield_type].name);

				if(!(ostr = aux_decrfc(field.item[0]))) {
					aux_add_error(EMSGBUF, "aux_decrfc failed", &field.item[0], OctetString_n, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Can't  RFC-decode issuer certificate(%s)\n", field.item[0]->octets);
					pem_free_HD(&field, TRUE);
			 		pem_free_HD(&key, TRUE);
					return(-1);
				}

				if(!(cert = d_Certificate(ostr))) {
					aux_add_error(EDECODE, "d_Certificate failed", 0, 0, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Can't BER-decode issuer certificate(%s)\n", field.item[0]->octets);
					pem_free_HD(&field, TRUE);
					aux_free_OctetString(&ostr);
			 		pem_free_HD(&key, TRUE);
					return(-1);
				}
				if(pem_verbose_1) {
					fprintf(stderr, "    Issuer-Certificate:\n");
					aux_fprint_Certificate(stderr, cert);
				}
				else if(pem_verbose_1) {
					s = aux_DName2Name(cert->tbs->subject);
					fprintf(stderr, "Subject <%s>\n", s);
					free(s);
					s = aux_DName2Name(cert->tbs->issuer);
					fprintf(stderr, "Issuer <%s>, serial %d\n", s, cert->tbs->serialnumber);
					free(s);
				}
				aux_free_OctetString(&ostr);
				pem_free_HD(&field, TRUE);

				if(!aux_cmp_DName(cert->tbs->issuer, cert->tbs->subject)) {

					/* This is a prototype certificate which is supposed to be the top-level certificate */

					if(pem_verbose_1) fprintf(stderr, "        This is a prototype certificate:\n"); 

					info->rootKEY = aux_create_PKRoot(cert, (Certificate *)0);
					if(!isCA) aux_free_Signature(&(info->rootKEY->newkey->sig));

				} 
				else {
					if(first) {
						first = FALSE;
						path = info->origcert->forwardpath = (FCPath *)calloc(1, sizeof(FCPath));
					}
	
					if(!subj || aux_cmp_DName(subj, cert->tbs->subject)) {
						if(subj) {
							path->next_forwardpath = (FCPath *)calloc(1, sizeof(FCPath));	
							path = path->next_forwardpath;
						}
	
						cross = path->liste = (SET_OF_Certificate *)calloc(1, sizeof(SET_OF_Certificate));	
						path->liste->element = aux_cpy_Certificate(cert);
						if(!(subj = aux_cpy_DName(cert->tbs->subject)))  {
							if(pem_verbose_1) fprintf(stderr, "    ");
							fprintf(stderr, "aux_cpy_DName failed when reading Issuer-Certificates\n");
							return(-1);
						}	
					} 
					else {	
						cross->next = (CrossCertificates *)calloc(1, sizeof(CrossCertificates));	
						cross = cross->next;
						cross->element = aux_cpy_Certificate(cert);
					}

				}
			}
		}


/*
 *  MIC-Info
 */
	
		/* copy header field containing information for verification of MIC */

		if(pem_next_hdfield_type == PEM_MIC_INFO) {
			if(pem_verbose_1) fprintf(stderr, "  Scanning MIC-Info ... ");
			pem_curr_text_idx = index_1;
			if(!pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx)) len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);
			else len = buf->noctets - index_1;
			
			if((i_2 = pem_cpy_next(buf, &field, &index_1, len, MAX_PARTS, &c))) {
				if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
			 	pem_free_HD(&key, TRUE);
				return(-1);
			}
			index_1 += strlen(rXH_kwl[pem_next_hdfield_type].name);

			info->signAI = (AlgId *)0;
			wrong_hash = FALSE;
			PEM_conformant = FALSE;

			switch(aux_Name2AlgHash(field.item[0]->octets)) {

				case MD2:	
					if(aux_Name2AlgEnc(field.item[1]->octets) == RSA) switch(aux_Name2AlgSpecial(field.item[1]->octets)) {

						case NOSPECIAL :
							info->signAI = aux_cpy_AlgId(md2WithRsa);
							break;

						case PKCS_BT_02:
							info->signAI = aux_cpy_AlgId(md2WithRsaEncryption);
							PEM_conformant = TRUE;
							break;
					}
					break;

				case MD4:	
					if(aux_Name2AlgEnc(field.item[1]->octets) == RSA) switch(aux_Name2AlgSpecial(field.item[1]->octets)) {

						case NOSPECIAL:
							info->signAI = aux_cpy_AlgId(md4WithRsa);
							break;

						case PKCS_BT_02:
							info->signAI = aux_cpy_AlgId(md4WithRsaEncryption);
							break;
					}
					break;

				case MD5:	
					if(aux_Name2AlgEnc(field.item[1]->octets) == RSA) switch(aux_Name2AlgSpecial(field.item[1]->octets)) {

						case NOSPECIAL:
							info->signAI = aux_cpy_AlgId(md5WithRsa);
							break;

						case PKCS_BT_02:
							info->signAI = aux_cpy_AlgId(md5WithRsaEncryption);
							PEM_conformant = TRUE;
							break;
					}
					break;
				case SHA:
					if(aux_Name2AlgEnc(field.item[1]->octets) == DSA) info->signAI = aux_cpy_AlgId(dsaWithSHA);
					break;
				default:
					wrong_hash = TRUE;
			}
			if(PEM_conformant && PEM_Conformance_Requested) {
				if(strcmp(field.item[0]->octets, "RSA-MD2") && strcmp(field.item[0]->octets, "RSA-MD5")) PEM_conformant = FALSE;
			}


			if(!info->signAI) {
				if(wrong_hash) {
					aux_add_error(EMSGBUF, "wrong MIC algorithm", field.item[0]->octets, char_n, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "invalid MIC algorithm <%s>\n", field.item[0]->octets);
				}
				else {
					aux_add_error(EMSGBUF, "wrong MIC-ENC algorithm", field.item[1]->octets, char_n, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "invalid MIC-ENC algorithm <%s>\n", field.item[1]->octets);
				}
				pem_free_HD(&key, TRUE);
				pem_free_HD(&field, TRUE);
				return(-1);
			}
			else if(pem_verbose_1) fprintf(stderr, "<%s,%s> found.\n", field.item[0]->octets, field.item[1]->octets);
			if(!PEM_conformant) {
				if(PEM_Conformance_Requested) {
					aux_add_error(EMICINFO, "MIC encryption alg is not PEM conformant", field.item[0]->octets, char_n, proc);
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "MIC encryption alg is not PEM conformant (%s, %s)\n", field.item[0]->octets, field.item[1]->octets);
		 			pem_free_HD(&key, TRUE);
					pem_free_HD(&field, TRUE);
					return(-1);
				}
				else {
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Warning: MIC encryption alg is not PEM conformant (%s, %s)\n", field.item[0]->octets, field.item[1]->octets);
				}
			}
			if(!(ostr = aux_decrfc(field.item[2]))) {
				aux_add_error(EMSGBUF, "aux_decrfc failed", field.item[2]->octets, char_n, proc);
				if(pem_verbose_1) fprintf(stderr, "    ");
				fprintf(stderr, "can't RFC-decode MIC info (%s)\n", field.item[3]->octets);
		 		pem_free_HD(&key, TRUE);
				pem_free_HD(&field, TRUE);
				return(-1);
			}
			if (mic_for_certification) {

				/* save MIC for the certification reply in case that 'pem certify' was called */  

				mic_for_certification[0] = (OctetString *)aux_cpy_OctetString(field.item[0]);
				mic_for_certification[1] = (OctetString *)aux_cpy_OctetString(field.item[1]);
				mic_for_certification[2] = (OctetString *)aux_cpy_OctetString(field.item[2]);
			}
			pem_free_HD(&field, TRUE);
			sign.bits = ostr->octets;
			sign.nbits= ostr->noctets * 8;
		}	

		index_1 -= strlen(rXH_kwl[pem_next_hdfield_type].name) + 1;
		index_2 = index_1;
		i_1 = i_2 = 0;
	}


/*
 *   no Originator Certificate ?
 */

	if(!info->origcert->usercertificate || !info->origcert->usercertificate->tbs) {
		if(info->origcert->usercertificate) info->origcert->usercertificate->tbs_DERcode = NULL;
		aux_free_Certificates(&info->origcert);
	}

	if(!info->origcert) {
		aux_add_error(EMIC, "have no Originator-certificate for MIC validation", 0, 0, proc);
		fprintf(stderr, "WARNING: have no Originator-certificate for MIC validation\n");
	}


/*
 *   create reclist
 */


	/* get my key info (recipient)	*/

	found = FALSE;


/*
 *   pse: get my_EncCert, my_serialnumber, my_issuer
 */


	index_1  = 0;
	if(info->confidential) recp = (struct HD *)calloc(1, sizeof(struct HD));


/*
 *   scan recipients
 */

	if(pem_verbose_1 && info->confidential && !myself) fprintf(stderr, " trying to find you in the recipient's list ... ");


/*
 *   Recipient-ID-Asymmetric
 */


	done = FALSE;

	if(info->confidential) while(!done && (myself || (!aux_searchitem(buf, rXH_kwl[PEM_RECIPIENT_ID].name, &index_1) && index_1++ && !found))) {

		/* search for next entry */

		pem_curr_text_idx = index_1;

		invalid = TRUE;
		
		if(!myself) pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx);


/*
 *   Key-Info  of Recipients
 */

		if(!myself && (pem_next_hdfield_type != PEM_KEY_INFO)) {
			aux_add_error(EMSGBUF, "Recipient-ID without following Key-Info", 0, 0, proc);
			index_1 = pem_curr_text_idx;
		} 
		else {

			/* get recipient id field */

			if(!myself) {
				len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);

				if((i_2 = pem_cpy_next(buf, recp, &index_1, len, MAX_PARTS, &c))) {
					if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
					fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
					aux_free_OctetString(&ostr);
					pem_free_HD(&key, TRUE);
					pem_free_HD(recp, TRUE);
					free(recp);
					free(ostr);
					return(-1);
				}
				index_1 += strlen(rXH_kwl[PEM_KEY_INFO].name);

				if(!info->recplist) {
					info->recplist = (RecpList *)calloc(1, sizeof(RecpList));
				
					if(!(info->recplist->recpcert = aux_cpy_Certificate(mycert))) {
						aux_add_error(EREADPSE, "aux_cpy_Certificate failed", 0, 0, proc);
						aux_free_OctetString(&ostr);
						pem_free_HD(&key, TRUE);
						return(-1);
					}
				}
				if(!(ostr = aux_decrfc(recp->item[0]))) {
					if(pem_verbose_1) fprintf(stderr, "    ");
					fprintf(stderr, "Can't RFC-decode first parameter of Key-Info (%s)\n", recp->item[0]->octets);
					return(-1);
				}
				else { 
					DN = d_DName(ostr);
					aux_free_OctetString(&ostr);
					if(!DN) {
						if(pem_verbose_1) fprintf(stderr, "    ");
						fprintf(stderr, "Can't BER-decode first parameter of Key-Info (%s)\n", recp->item[0]->octets);
						return(-1);
					} 
					else {
						serial = (recp->num > 1 ? pem_OS2inthex(recp->item[1]) : 0);
						if(!aux_cmp_DName(DN, mycert->tbs->issuer) && (mycert->tbs->serialnumber == serial)) invalid = FALSE;
					}
				}

				if(pem_verbose_0) {
					if(pem_verbose_1) fprintf(stderr, "\n");
					fprintf(stderr, "	found recipient with issuer: <%s>, serial number: %d", 
						s = aux_DName2Name(DN), serial);
					if(s) free(s);
				}
			}


/*
 *   Recipient or Originator: it's me !
 */
			if(myself || !invalid) {
				found = TRUE;

/*  myself: get Key-Info from key; else: get Key-Info from header				*/
				if(myself) for(i_1 = recp->num = 0, recp->avail = key.avail; i_1 < key.num; i_1++) 
					recp->item[recp->num++] = key.item[i_1];
				else {
					if(pem_verbose_1) fprintf(stderr, " -> that's you!\n");
					pem_free_HD(recp, TRUE);

/* get keyinfo field										*/
					pem_curr_text_idx = index_1;
					if(!pem_search_next(buf, &pem_next_hdfield_type, &pem_curr_text_idx)) len = pem_curr_text_idx - index_1 - strlen(rXH_kwl[pem_next_hdfield_type].name);
					else len = buf->noctets - index_1;
					pem_free_HD(&key, TRUE);
					aux_free_DName(&DN);

					if((i_2 = pem_cpy_next(buf, recp, &index_1, len, MAX_PARTS, &c))) {
						if(i_2 == 1) aux_add_error(EINVALID, "", 0, 0, proc);
						fprintf(stderr, "call to pem_cpy_next with invalid parameters! --- returning.\n");
						aux_free2_BitString(&sign);
						pem_free_HD(recp, TRUE);
						free(recp);
						free(ostr);
						return(-1);
					}
					index_1--;
				}


/*
 *   get IK-algid, asymenc-DEK
 */
				if(!(encrypted_key.encryptionAI = aux_Name2AlgId(recp->item[0]->octets))) {
					aux_add_error(EMSGBUF, "aux_Name2AlgId failed", 0, 0, proc);
					fprintf(stderr, "unknown algorithm (%s)\n", recp->item[0]->octets);
					aux_free2_BitString(&sign);
					pem_free_HD(recp, TRUE);
					free(recp);
					free(ostr);
					return(-1);
				}

				if(!(encrypted_key.subjectAI = aux_cpy_AlgId(info->encryptKEY->key->subjectAI))) {
					aux_add_error(EMSGBUF, "aux_cpy_AlgId failed", 0, 0, proc);
					fprintf(stderr, "can't copy algorithm identifier: %s\n", recp->item[0]->octets);
					aux_free2_AlgId(encrypted_key.encryptionAI);
					aux_free2_BitString(&sign);
					pem_free_HD(recp, TRUE);
					free(recp);
					free(ostr);
					return(-1);
				}

				if(!(ostr = aux_decrfc(recp->item[1]))) {
					aux_add_error(EMSGBUF, "aux_decrfc failed", 0, 0, proc);
					fprintf(stderr, "can't decode key info: %s\n", recp->item[0]->octets);
					aux_free2_AlgId(encrypted_key.subjectAI);
					aux_free2_AlgId(encrypted_key.encryptionAI);
					aux_free2_BitString(&sign);
					pem_free_HD(recp, TRUE);
					free(recp);
					free(ostr);
					return(-1);
				}

				encrypted_key.subjectkey.nbits = ostr->noctets * 8;
				encrypted_key.subjectkey.bits  = ostr->octets;

				if(af_put_EncryptedKey(&encrypted_key, info->encryptKEY, encrypted_key.encryptionAI)) {
					aux_add_error(EMSGBUF, "af_put_EncryptedKey failed", 0, 0, proc);
					fprintf(stderr, "can't get key from key info\n");
					aux_free2_AlgId(encrypted_key.subjectAI);
					aux_free2_AlgId(encrypted_key.encryptionAI);
					aux_free2_BitString(&sign);
					aux_free_OctetString(&ostr);
					pem_free_HD(recp, TRUE);
					free(recp);
					return(-1);
				}
				done = TRUE;
				aux_free2_AlgId(encrypted_key.subjectAI);
				aux_free2_AlgId(encrypted_key.encryptionAI);

/* 
 *   Recipient is not me
 */

			} 
			else if(pem_verbose_1) fprintf(stderr, " -> that's not you\n");

			for(index_2 = 0; index_2 < recp->num; index_2++) aux_free_OctetString(&recp->item[index_2]);
		}
	}
	if(pem_verbose_1 && info->confidential && !myself) fprintf(stderr, " done.\n");

	if(info->confidential) {
		free(recp);
		pem_free_HD(recp, TRUE);
	}

	signature->nbits = sign.nbits;
	signature->bits  = sign.bits;

	if(info->confidential && !found) {
		fprintf(stderr, "you are not on the recipient's list\n");
		return(-1);
	}
	
	return(0);
}



/************************************************************************/
/*	pem_OS2int							*/
/*									*/
/* convert OctetString to integer, ignore invalid characters		*/
/************************************************************************/
int	pem_OS2int(ostr)
OctetString	*ostr;
{
	int	val, index;
	char	v[256], *proc = "pem_OS2int";
	static	tab[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

	if(!ostr) return(0);

	for(index = 0; index < 256; index++) v[index] = -1;
	for(index = 0; index < 10; index++) v[tab[index]] = index;

	for(val = index = 0; index < ostr->noctets; index++) 
		if(v[ostr->octets[index]] >= 0) { val *= 10; val += v[ostr->octets[index]]; }

	return(val);
}



/************************************************************************/
/*	pem_OS2inthex							*/
/*									*/
/* convert OctetString (hexadecimaL) to integer, ignore invalid chars	*/
/************************************************************************/
int	pem_OS2inthex(ostr)
OctetString	*ostr;
{
	int	val, index;
	char	v[256], *proc = "pem_OS2inthex";
	static	tab[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	static	tabA[6] = { 'A', 'B', 'C', 'D', 'E', 'F' };
	static	taba[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };

	if(!ostr) return(0);

	for(index = 0; index < 256; index++) v[index] = -1;
	for(index = 0; index < 10; index++) v[tab[index]] = index;
	for(index = 0; index < 6; index++) v[tabA[index]] = index + 10;
	for(index = 0; index < 6; index++) v[taba[index]] = index + 10;

	for(val = index = 0; index < ostr->noctets; index++) 
		if(v[ostr->octets[index]] >= 0) { val *= 16; val += v[ostr->octets[index]]; }

	return(val);
}




/************************************************************************/
/*	pem_scan							*/
/*									*/
/*									*/
/************************************************************************/
RC	pem_scan(info, set_of_pemcrlwithcerts, issuer, cbody, pem, certify)
PemInfo		*info;
SET_OF_PemCrlWithCerts **set_of_pemcrlwithcerts;
SET_OF_DName 	**issuer;
OctetString	*pem, *cbody;
Boolean certify;
{
	int		index, count, number;
	char		*searchstr;
	char		*proc = "pem_scan";
	Signature	signat;
	OctetString	*ostr, *body;
	ToBeSigned      *tbs;
	Certificate     *owncert = 0;
	BitString	decr_bstr;
	struct RL	*recps;
	struct OL	*orig;
	Name            *originator_name;
	char            *originator_alias, *originator_mailadr, *alias;
	PKRoot		*pkroot_verify = 0;


	/* check parameters */

	if(!info || !pem || !cbody) {
		aux_add_error(EINVALID, "info or pem = 0", 0, 0, proc);
		return(-1);
	}

	cbody->noctets = 0;
	cbody->octets  = (char *)0;
	info->origcert = (Certificates *)0;

	if(pem_verbose_1) fprintf(stderr, "  Scanning for delimiter (blank line between headerand body) ... ");

	/* find delimiter between header and body (empty line)	*/

	if(pem_find_delim(pem, &count)) {
		if(pem_verbose_1) fprintf(stderr, "Warning: no body found.\n");
	}
	if(pem_verbose_1) fprintf(stderr, "found.\n");

	ostr = (OctetString *)calloc(1, sizeof(OctetString));

	ostr->octets = calloc(1, ostr->noctets = (count));

	for(index = 0; index < count; index++) ostr->octets[index] = pem->octets[index];

	info->encryptKEY = NULL;
	info->origcert   = NULL;
	info->rootKEY    = NULL;
	info->signAI     = NULL;
	info->recplist   = NULL;

	if(pem_get_header(info, set_of_pemcrlwithcerts, issuer, &signat.signature, ostr)) {
		aux_free_OctetString(&ostr);
		aux_add_error(EMSGBUF, "pem_get_header", 0, 0, proc);
		aux_free2_PemInfo(info);
		aux_free2_BitString(&signat.signature);
		return(-1);
	}
	if(*set_of_pemcrlwithcerts || *issuer) return(0);

	signat.signAI = info->signAI;
	aux_free_OctetString(&ostr);

	/* memory allocation for body */

	body = (OctetString *)calloc(1, sizeof(OctetString));

	/* ignore empty line */

	count++;
	while((count < pem->noctets) && (pem->octets[count] != '\n')) count++; count++;
	if((count < pem->noctets) && (pem->octets[count] == '\r')) count++;
	body->noctets = pem->noctets - count;

	/* copy body into parameter */

	if(info->clear) {
		body->octets = calloc(1, body->noctets);
		strncpy(body->octets, &pem->octets[count], body->noctets);
	} 
	else if(pem_string2string(&body->octets, &pem->octets[count], &body->noctets, &index, 0)) {
			aux_add_error(EMSGBUF, "pem_string2string failed", 0, 0, proc);
			fprintf(stderr, "can't get body\n");
			aux_free_OctetString(&body);
			goto error;
	}

	if(!info->clear) {
		if(pem_verbose_1) fprintf(stderr, "Decode MIC-ONLY / ENCRYPTED message\n");
		if(!(ostr = aux_decrfc(body))) {
			aux_add_error(EDECODE, "aux_decrfc failed", 0, 0, proc);
			fprintf(stderr, "can't decode body\n");
			aux_free_OctetString(&body);
			goto error;
		}
		free(body->octets);
		body->octets  = ostr->octets;
		body->noctets = ostr->noctets;
	}

	if(info->confidential) {
		ostr->octets = (char *)calloc(1, (signat.signature.nbits/8) + 8);
		ostr->noctets = 0;

		if(pem_verbose_1) fprintf(stderr, "Decryption of signature ... ");
		if(af_decrypt(&signat.signature, ostr, END, info->encryptKEY) < 0) {
			fprintf(stderr, "Decryption of MIC failed\n");
			aux_free_OctetString(&ostr);
			aux_free_OctetString(&body);
			goto error;
		}
		if(pem_verbose_1) fprintf(stderr, "done.\n");

		free(signat.signature.bits);
		signat.signature.bits = ostr->octets;
		signat.signature.nbits= ostr->noctets * 8;

		if(body->noctets > 0) {
			decr_bstr.nbits= body->noctets * 8;
			decr_bstr.bits = body->octets;
			ostr->octets = (char *)calloc(1, body->noctets + 8);
			ostr->noctets = 0;

			if(pem_verbose_1) fprintf(stderr, "Decryption of text ... ");
			count = af_decrypt(&decr_bstr, ostr, END, info->encryptKEY);
			if(count < 0) {
				fprintf(stderr, "Decryption of text portion failed\n");
				aux_free_OctetString(&ostr);
				aux_free_OctetString(&body);
				aux_add_error(EDECODE, "af_decrypt failed", 0, 0, proc);
				goto error;
			}
			if(pem_verbose_1) fprintf(stderr, "done.\n");

			free(body->octets); 
			body->octets = ostr->octets;
			body->noctets= ostr->noctets;
			free(ostr);
		}
	}
 
	if(pem_verbose_1) fprintf(stderr, "Decanonicalize message ...\n");
	if(!(ostr = aux_decanon(body))) {
		aux_add_error(EDECODE, "aux_decanon failed", 0, 0, proc);
		fprintf(stderr, "decanonization of text failed\n");
		aux_free_OctetString(&body);
		goto error;
	}

	aux_free_OctetString(&body);
	cbody->noctets = ostr->noctets;
	cbody->octets  = ostr->octets;
	free(ostr);

	if(pem_verbose_1) fprintf(stderr, "Canonicalize message ...\n");
	if(!(ostr = aux_canon(cbody))) {
		aux_add_error(ECODE, "aux_canon failed", 0, 0, proc);
		fprintf(stderr, "canonicalization of text failed\n");
		aux_free2_OctetString(cbody);
		goto error;
	}

	if(pem_verbose_1) fprintf(stderr, "Verification of text signature ...\n");

	if(certify && info->origcert) {
		if(!aux_cmp_DName(info->origcert->usercertificate->tbs->issuer, info->origcert->usercertificate->tbs->subject)) {

			/*
			 * 'pem certify' was called and Originator-Certificate appears to be a prototype certificate.
			 * Verify with the PK of that certificate as root key.
			 */

			pkroot_verify = aux_create_PKRoot(info->origcert->usercertificate, (Certificate *)0);
		}
		
	} 
	else {
		if(info->rootKEY) {
			/*
			 * Apparently a prototype certificate was scanned as Issuer-Certificate. Consider it
                         * as a certification reply if the subject DName from the Originator-Certificate is
                         * the own DName.
			 */

			owncert = af_pse_get_Certificate(SIGNATURE, NULLDNAME, 0);
			if(!owncert) {
				fprintf(stderr, "Can't read own Cert from PSE\n"); 
				aux_add_error(EMIC, "no PSE-object Cert", 0, 0, proc);
				aux_free2_BitString(&signat.signature);
				aux_free_OctetString(&ostr);
				return(-1);
			}
			if(aux_cmp_DName(info->origcert->usercertificate->tbs->subject, owncert->tbs->subject)) {
				aux_free_PKRoot(&(info->rootKEY));
				aux_free_Certificate(&owncert);
			}
		}
		pkroot_verify = info->rootKEY;
	}

	if(!info->origcert) {
		fprintf(stderr, "MIC not validated (no certificate available)\n"); 
		aux_add_error(EMIC, "no Certificate", 0, 0, proc);
		aux_free2_BitString(&signat.signature);
		aux_free_OctetString(&ostr);
		return(-1);
	}
	if(af_verify(ostr, &signat, END, info->origcert, 0, pkroot_verify)) {
		fprintf(stderr, "MIC not validated\n"); 
		aux_add_error(EMIC, "text verification", 0, 0, proc);
		aux_free2_BitString(&signat.signature);
		aux_free_OctetString(&ostr);
		if(pem_verbose_0) aux_fprint_VerificationResult(stderr, verifresult);
		aux_free_VerificationResult(&verifresult);
		return(-1);
	}
/*
 *	save verifresult (otherwise, could be overwritten by alias file verification)
 */
	pem_VerifResult = verifresult;
	verifresult = (VerificationResult *)0;
/*
 * 	look for alias names of originator
 */
	originator_name = aux_DName2Name(info->origcert->usercertificate->tbs->subject);
	originator_alias = aux_DName2alias(info->origcert->usercertificate->tbs->subject, LOCALNAME);
	originator_mailadr = aux_DName2alias(info->origcert->usercertificate->tbs->subject, RFCMAIL);
	if(originator_alias) alias = originator_alias;
	else if(originator_mailadr) alias = originator_mailadr;
	else alias = originator_name;

	fprintf(stderr, "MIC OK. Message signed by <%s>\n", alias);
/*
 *	print verifresult from pem verification
 */ 
	if(pem_verbose_0) aux_fprint_VerificationResult(stderr, pem_VerifResult);

	aux_free_VerificationResult(&pem_VerifResult);
	aux_free2_BitString(&signat.signature);
	aux_free_OctetString(&ostr);



/*
 *   Enter Originator-Certificate into PKList if not found there
 */
	if(!certify) {
		if(pem_store_certificate(originator_name, originator_alias, originator_mailadr, owncert, info->origcert->usercertificate, info->origcert->forwardpath, info->rootKEY, pem_verbose_1)) {
			fprintf(stderr, "Storage of certificate failed\n"); 
			aux_add_error(EINVALID, "Storage of certificate failed", 0, 0, proc);
			return(-1);
		}
	}

/*
 *   End of scanning
 */ 

	if(pem_verbose_1) { aux_fprint_error(stderr, 0); aux_fprint_PemInfo(stderr, info); }

	return(0);




error:	
	aux_free_OctetString(&body);
	aux_free2_PemInfo(info);
	aux_free2_BitString(&signat.signature);

	return(-1);
}

