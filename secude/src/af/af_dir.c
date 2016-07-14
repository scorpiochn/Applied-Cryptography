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

#ifdef X500

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <sys/stat.h>

#include "config.h"
#include "isoaddrs.h"
#include "logger.h"
#include "psap.h"
#include "af.h"

#ifdef STRONG
#include "osisec-stub.h"
#include "secude-stub.h"
#endif

#include "quipu/common.h"
#include "quipu/attr.h"
#include "quipu/sequence.h"
#include "tailor.h"
#include "quipu/dua.h"
#include "quipu/name.h"
#include "quipu/config.h"
#include "quipu/nrs_info.h"
#include "quipu/oid.h"
#include "x500as/AF-types.h"
#include "quipu/DAS-types.h"   /*for specifying the S T R O N G argument type*/
#include "x500as/af-cdefs.h"
#include "x500as/if-cdefs.h"
#include "x500as/nrs-cdefs.h"
#include "x500as/qu-cdefs.h"
#include "quipu/syntaxes.h"

#define EUNKNOWN       114
#define BUFLEN 4096

static char	stream_contents[LINESIZE];
static char	home_dir[LINESIZE];
static char	quipurc_file[100];
static char	prompt[64];

extern FILE    *fopen();
extern char	*strstr();
extern char	*getpass();
extern struct passwd *getpwuid();
extern char	*TidyString();

extern AttributeValue 	    AttrV_cpy();
extern Attr_Sequence        as_cpy();
extern AttributeType  	    AttrT_new();
extern Attr_Sequence  	    as_comp_new();
extern AV_Sequence	    avs_comp_new();

/* from /usr/local/secude/src/af/af-add-encdec.c: */
extern PE            certificate_enc();
extern Certificate * certificate_dec();

/* from /usr/local/isode/src/dsap/common/certificate.c: */
extern PE 		    cert_enc();
extern struct certificate * cert_dec();
extern struct certificate * cert_cpy();

/* from /usr/local/isode/src/dsap/common/dn_str.c: */
extern DN dn_dec();
extern DN str2dn();

/* from /usr/local/isode/src/dsap/common/dn_cpy.c: */
extern DN dn_cpy();

/* from /usr/local/isode/src/dsap/common/dn_free.c: */
extern void dn_free ();

/* from /usr/local/isode/src/dsap/common/cpair.c: */
extern struct certificate_list * cpair_cpy();

/* from /usr/local/isode/src/dsap/common/cache.c: */
extern char *new_version();

extern struct Octetstring * aux_PE2OctetString();

static CommonArgs ca = default_common_args;


extern char * myname;  		      /* name of the DSA which is to be accessed */
				      /* "myname" is set in tai_args() in dsap_init() */
static DN directory_user_dn = NULLDN;
static char * directory_user_name = CNULL;

#ifdef STRONG
static struct security_parms * ca_security = (struct security_parms *)0;
static struct SecurityServices * dsap_security = (struct SecurityServices * ) 0;
#endif

/* Arguments used by secure_ds_bind(): */
static struct ds_bind_arg       bindarg;
static struct ds_bind_arg       bindresult;
static struct ds_bind_error     binderr;

static 	DN      real_name;
static 	char	Password[LINESIZE] = {'\0'};

static Boolean  store_password_on_PSE = FALSE;
static DN first_intended_recipient;

int rc;

/************* local functions: ******************************/

int	cmp_quipu_cert(a, b)
struct certificate *a, *b;
{
	int	  rc;
	char	* proc = "cmp_quipu_cert";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!a || !b)
		return(1);

	if (a->serial != b->serial)
		return(1);

	return(dn_cmp(a->issuer, b->issuer));
}



int	cmp_quipu_cpair(a, b)
struct certificate_list *a, *b;
{
	int	  rc;
	char	* proc = "cmp_quipu_cpair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (a->cert == (struct certificate *) 0) {
		if (b->cert == (struct certificate *) 0) 
			rc = 0;
		else 
			rc = 1;
	} else {
		if (b->cert == (struct certificate *) 0) 
			rc = 1;
		else 
			rc = cmp_quipu_cert(a->cert, b->cert);
	}

	if (rc != 0)
		return (rc);

	if (a->reverse == (struct certificate *) 0) {
		if (b->reverse == (struct certificate *) 0) 
			rc = 0;
		else 
			rc = 1;
	} else {
		if (b->reverse == (struct certificate *) 0) 
			rc = 1;
		else 
			rc = cmp_quipu_cert(a->reverse, b->reverse);
	}

	return (rc);
}


struct entrymod *ems_append_local (a, b)
struct entrymod *a;
struct entrymod *b;
{
	struct entrymod * ptr;
	char	        * proc = "ems_append_local";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ((ptr = a) == NULLMOD)
		return b;

	for ( ; ptr->em_next != NULLMOD; ptr = ptr->em_next)
		;

	ptr->em_next = b;
	return a;
}


void ems_part_free_local(emp)
struct entrymod *emp;
{
	char  * proc = "ems_part_free_local";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (emp == NULLMOD)
		return;
	ems_part_free_local(emp->em_next);
	free((char *)emp);
}


static int set_error(error)
struct DSError error;
{

	switch (error.dse_type) {

	case DSE_ATTRIBUTEERROR:
		return (EATTRDIR);

	case DSE_NAMEERROR:
		return (ENAMEDIR);

	case DSE_SERVICEERROR:
		return (ENODIR);

	case DSE_SECURITYERROR:
		return (EACCDIR);

	case DSE_UPDATEERROR:
		return (EUPDATE);

	}  /*switch*/

}


static int set_bind_error(error)
struct ds_bind_error error;
{
	switch (error.dbe_type) {
	case DBE_TYPE_SERVICE:
		return(ENODIR);
	case DBE_TYPE_SECURITY:
		return(EACCDIR);
	default:
		return(EUNKNOWN);
	}
}


/************************************************************************************************************ 
 *  get_credentials() returns:										    *
 *													    *
 *													    *
 * 	directory user's distinguished name and password in case of SIMPLE authentication (DBA_AUTH_SIMPLE);* 
 *													    *
 *	directory user's distinguished name only in case of STRONG authentication (DBA_AUTH_STRONG) or      *
 *		no authentication (DBA_AUTH_NONE);							    *
 ************************************************************************************************************/

static RC get_credentials()
{

	PE 	        pe;
	char	        Dirname[LINESIZE];
	struct passwd * pw_entry;
	int	        uid ;
	FILE          * fp_quipurc;
	char	      * p;
	char          * dd = CNULL;
	int	        ind = 0, rc;
	char	      * proc = "get_credentials";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if(! directory_user_dn && directory_user_dname) { /* "directory_user_dname" may have been provided by a util-routine */
		directory_user_name = aux_DName2Name(directory_user_dname);
		fprintf(stderr, "\nBinding as \"%s\"\n", directory_user_name);

		build_IF_Name(&pe, 1, 0, NULLCP, directory_user_dname);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(NOTOK);
		}

		if ( (directory_user_dn = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(NOTOK);
		}

		pe_free(pe);
		if((auth_level == DBA_AUTH_STRONG) || (auth_level == DBA_AUTH_NONE)) return(OK);
	}

	uid = getuid();

	if ((pw_entry = getpwuid(uid)) == (struct passwd *) 0) {
		aux_add_error(EINVALID, "Who are you? (no name for your uid number)", CNULL, 0, proc);
		return(NOTOK);
	}

#ifndef MAC
	if (getenv("HOME") == CNULL) {
#else
    if (MacGetEnv("HOME") == 0) {
#endif /* MAC */
		fprintf(stderr, "No home directory?!!\n");
		strcpy(home_dir, pw_entry->pw_dir);
	}
	else strcpy(home_dir, getenv("HOME"));

	strcpy(quipurc_file, home_dir);
	strcat(quipurc_file, "/.quipurc");

	/*  If possible, read the Directory-name and -password used for binding from the 
	 *  invoker's .quipurc file; otherwise, Directory-name and -password have to be entered
	 *  interactively.
 	 */

	/* read from .quipurc file */

	if ( (fp_quipurc = fopen(quipurc_file, "r")) != (FILE *) 0 ) {
		while ( fgets(stream_contents, LINESIZE, fp_quipurc) != CNULL ) {

			/* read user's distinguished name */

			if(! directory_user_dn){
				if ( strstr(stream_contents, "username") != CNULL ) {
					p = strchr(strstr(stream_contents, "username"), ':');
					p += 2;
					Dirname[0] = 0;
					while ( (Dirname[ind++] = *p++) != '\n' ) {
					}
					ind--;
					Dirname[ind] = '\0';		/* lexequ?? */
					if ( (directory_user_dn = str2dn(TidyString(Dirname))) == NULLDN ) {
						aux_add_error(EPARSE, "Cannot fill DN structure", CNULL, 0, proc);
						return(NOTOK);
					}
					directory_user_name = strcpy(Dirname);
				}
			}
			if(directory_user_dn && ((auth_level == DBA_AUTH_STRONG) || (auth_level == DBA_AUTH_NONE))){
				fclose(fp_quipurc);
				return(OK);
			}


			/* read user's directory password */

			if(! Password[0]){
				if ( strstr(stream_contents, "password") != CNULL ) {
					p = strchr(strstr(stream_contents, "password"), ':');
					p += 2;
					ind = 0;
					while ( (Password[ind++] = *p++) != '\n' ) {
					}
					ind--;
					Password[ind] = '\0';
					strcpy(bindarg.dba_passwd, Password);
					break;
				}
			}
		} /*while*/

		fclose(fp_quipurc);
		if(Password[0]) return(OK);
	} 


	/* read from stdin */

	if(! directory_user_dn){
		if(ask_for_username() == NOTOK){
			aux_add_error(EINVALID, "ask_for_username failed", CNULL, 0, proc);
			return(NOTOK);
		}
		if((auth_level == DBA_AUTH_STRONG) || (auth_level == DBA_AUTH_NONE)) return(OK);
	}

	if(! Password[0]){
		/* Read user's X.500 password from user's PSE */
		dd = af_pse_get_QuipuPWD();
		if (! dd) {
			store_password_on_PSE = TRUE;
			strcpy(prompt, "\nEnter your directory password: ");
			if (!(dd = getpass(&prompt[1]))) {
				aux_add_error(EINVALID, "getpass failed", CNULL, 0, proc);
				return(NOTOK);
			}
		}
		strcpy(bindarg.dba_passwd, dd);
		strcpy(Password, dd);
		free(dd);
		dd = CNULL;
	}

	return(OK);
}


static int ask_for_username()
{
	char	        buf[BUFLEN];
	Name          * alias;
	PE		pe;
	char	      * proc = "ask_for_username";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	fprintf(stderr, "\nEnter your directory name in printable representation\n");
	fprintf(stderr, "  (e.g. C=de; O=gmd; OU=CA): ");
	while ( !gets(buf) || !buf[0] ) {
		fprintf(stderr, "Directory Name? ");
	}
	alias = malloc(strlen(buf) + 1);
	if (!alias) {
		aux_add_error(EMALLOC, "alias", CNULL, 0, proc);
		return(NOTOK);
	}
	strcpy(alias, buf);
	directory_user_dname = aux_alias2DName(alias);
	free(alias);

	directory_user_name = aux_DName2Name(directory_user_dname);
	fprintf(stderr, "\nBinding as \"%s\"\n", directory_user_name);

	build_IF_Name(&pe, 1, 0, NULLCP, directory_user_dname);
	if ( pe == NULLPE ) {
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(NOTOK);
	}

	if ( (directory_user_dn = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(NOTOK);
	}

	pe_free(pe);
	return(OK);
}


static RC set_bindarg()  /* NO parameters required, as bindarg is globally defined within af_dir.c */
{
	DName	    * dsa_dname;
	PE	      pe;
	char	    * proc = "set_bindarg";


	if (auth_level == DBA_AUTH_SIMPLE){
		if(! directory_user_dn || ! Password[0]) 
			get_credentials();  /* reads distinguished name and password */

		/* "bindarg.dba_dn" is the directory user's distinguished name; */
		/* therefore, copy it from "directory_user_dn"			*/

		bindarg.dba_dn = dn_cpy(directory_user_dn);
		bindarg.dba_auth_type = DBA_AUTH_SIMPLE;
		bindarg.dba_version = DBA_VERSION_V1988;
		bindarg.dba_passwd_len = strlen(bindarg.dba_passwd);
		return(0);
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(! directory_user_dn) get_credentials();  /* reads distinguished name */

		/* "bindarg.dba_dn" is the distinguished name of the first intended recipient, i.e. the DSA's name */

		dsa_dname = aux_alias2DName(myname);
		if(! dsa_dname){
			aux_add_error(EINVALID, "Name cannot be transformed into DName-structure", CNULL, 0, proc);
			return(- 1);
		}
		build_IF_Name(&pe, 1, 0, NULLCP, dsa_dname);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(- 1);
		}
		if ( (bindarg.dba_dn = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(- 1);
		}
		pe_free(pe);

		first_intended_recipient = dn_cpy(bindarg.dba_dn);  /* Security Parameter 'sp_name' */

		if(sign_bindarg() == NOTOK){
			aux_add_error(EINVALID, "Creation of STRONG credentials failed", CNULL, 0, proc);
			return(- 1);
		}
		return(0);
	}
#endif

	if (bindarg.dba_auth_type == DBA_AUTH_NONE){
		if(! directory_user_dn) get_credentials();  /* reads distinguished name */

		/* "bindarg.dba_dn" is the directory user's distinguished name; */
		/* therefore, copy it from "directory_user_dn"			*/

		bindarg.dba_dn = dn_cpy(directory_user_dn);
		bindarg.dba_version = DBA_VERSION_V1988;
		bindarg.dba_passwd[0]  = 0;
		bindarg.dba_passwd_len = 0;
		return(0);
	}

	return(0);
}	


#ifdef STRONG
static RC set_SecurityParameter()
{
	char  * proc = "set_SecurityParameter";

	if(! ca_security){
		ca_security = (struct security_parms *)calloc(1, sizeof(struct security_parms));
		if(! ca_security){
			aux_add_error(EMALLOC, "ca_security", CNULL, 0, proc);
			return(NOTOK);
		}
		/* The following are constant values which need be assigned once only */
		ca_security->sp_name = dn_cpy(first_intended_recipient);
		ca_security->sp_target = 1;  /* Result (if provided) shall be protected by a digital signature */
		ca_security->sp_random = (struct random_number *)0;
		ca_security->sp_time = CNULL;  
		if (dsap_security->serv_mkpath) 
			ca_security->sp_path = (dsap_security->serv_mkpath)();
		else ca_security->sp_path = (struct certificate_list *)0;
	}
	if(ca_security->sp_time) free(ca_security->sp_time);
	ca_security->sp_time = new_version();

	return(OK);
}
#endif


#ifdef STRONG
static RC verify_bindres()  /* NO parameters required, as bindresult and binderr are globally defined within af_dir.c */
{

/* As the data type of the bind argument does not provide a "ProtectionRequest" field,       */
/* PASSWORD DSAs will return a signed bind result to a requestor only if the bind argument   */ 
/* submitted by the requestor was signed, too. (see X.500 Interoperability Profile Document  */

	int 	rc;
	PS      rps;
	char  * proc = "verify_bindres";

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);

	if(bindresult.dba_dn){  /*result is provided and must be evaluated*/

	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			if (af_verbose) {
				fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n *******************************************************************");
				fprintf(stderr, "\n ****************   B I N D   R  E  S  U  L  T   *******************");
				fprintf(stderr, "\n *******************************************************************\n\n\n");
			}
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &bindresult, bindresult.dba_cpath, bindresult.dba_sig, &real_name, _ZTokenToSignDAS);
			if (rc != OK){
				binderr.dbe_version = DBA_VERSION_V1988;
				binderr.dbe_type = DBE_TYPE_SECURITY;
				if ( err_stack->e_number == ESIGNATURE )
					binderr.dbe_value = DSE_SC_INVALIDSIGNATURE;
				else if ( err_stack->e_number == EVERIFICATION )
					binderr.dbe_value = DSE_SC_AUTHENTICATION;
				else  binderr.dbe_value = DSE_SC_NOINFORMATION;
				ds_bind_error(rps, &binderr);
				return (- 1);
			}
		}
		if(dn_cmp(directory_user_dn, bindresult.dba_dn) != OK){
			fprintf(stderr, "User != Authenticated User, ie %s != %s\n", dn2str(bindresult.dba_dn),directory_user_name);
			binderr.dbe_version = DBA_VERSION_V1988;
			binderr.dbe_type = DBE_TYPE_SECURITY;
			binderr.dbe_value = DSE_SC_AUTHENTICATION;
			ds_bind_error(rps, &binderr);
			return (- 1);
	    	}
	}

	return(0);
}
#endif


#ifdef STRONG
static void load_security_functions()
{
	char    * proc = "load_security_functions";

	dsap_security = use_serv_secude();
}
#endif


#ifdef STRONG
static int sign_bindarg()
{
	struct Nonce * nonce;
	char	     * proc = "sign_bindarg";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (dsap_security == (struct SecurityServices *) 0){
		load_security_functions();
		if (dsap_security == (struct SecurityServices *) 0)
			return (NOTOK);
	}
 
	if (! dsap_security->serv_mknonce)
		return (NOTOK);

	nonce = (dsap_security->serv_mknonce)((struct Nonce *) 0);
	if (nonce == (struct Nonce *) 0)
		return (NOTOK);

	bindarg.dba_auth_type = DBA_AUTH_STRONG;
	bindarg.dba_version = DBA_VERSION_V1988;
	bindarg.dba_time1 = nonce->non_time1;
	bindarg.dba_time2 = nonce->non_time2;
	bindarg.dba_r1.n_bits = nonce->non_r1.n_bits;
	bindarg.dba_r1.value = nonce->non_r1.value;
	bindarg.dba_r2.n_bits = nonce->non_r2.n_bits;
	bindarg.dba_alg.algorithm = nonce->non_alg.algorithm;
	bindarg.dba_alg.p_type = nonce->non_alg.p_type;
	bindarg.dba_alg.asn = nonce->non_alg.asn;
	free((char *) nonce);
	if (dsap_security->serv_sign)
		bindarg.dba_sig = (dsap_security->serv_sign)((char*)&bindarg, _ZTokenToSignDAS);
	else
		return (NOTOK);

	if (bindarg.dba_sig == (struct signature *) 0)
		return (NOTOK);

	if (dsap_security->serv_mkpath)
 		bindarg.dba_cpath = (dsap_security->serv_mkpath)();
	else
 		bindarg.dba_cpath = (struct certificate_list *)0;

	return (OK);
}
#endif


security_syntaxes ()
{
	oclist_syntax();
	revoke_syntax();
	pemcrl_syntax();
}


/***************************************************************************************
 *                                     af_dir_enter_Certificate                        *
 ***************************************************************************************/



RC
af_dir_enter_Certificate(cert, type)
Certificate *cert;
CertificateType type;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	struct certificate *quipu_cert;
	struct certificate *quipu_cert_tmp;

	objectclass * obj_class;
	int	      found = 0;

	char	    * proc = "af_dir_enter_Certificate";

	PS rps;


#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !cert || ((type != userCertificate) && (type != cACertificate)) ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	if ( (pe = certificate_enc(cert)) == NULLPE ) {
		aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
		return(- 1);
	}

	if ( (quipu_cert = cert_dec(pe)) == (struct certificate *)0 ) {
		pe_free(pe);
		aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

/*
	printcert(rps, quipu_cert, EDBOUT);
*/

	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}		

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, cert->tbs->subject);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	if ( type == userCertificate )
		at = AttrT_new("userCertificate");
	else
		at = AttrT_new("cACertificate");

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "at==NULLAttrT", CNULL, 0, proc);
		return (- 1);
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);
	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return(- 1);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The cACertificate attribute is MANDATORY within the directory entry of
	 *  a certificationAuthority, and the userCertificate attribute MANDATORY within
	 *  the directory entry of a strongAuthenticationUser; it has multiple value, namely
	 *  one or more EncrCertificates and one or more SignCertificates.
	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return(- 1);
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;
	acl = read_result.rdr_entry.ent_attr->attr_acl;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return(- 1);
	}

	for ( avseq = avst_result ; avseq ; avseq = avseq->avseq_next ) {
		quipu_cert_tmp = (struct certificate *)avseq->avseq_av.av_struct;

		if ( !cert_cmp(quipu_cert_tmp, quipu_cert) ) {    /*equal*/
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(ECREATEOBJ, "Specified certificate already exists in Your directory entry", CNULL, 0, proc);
			return(- 1);
		}
	}  /*for*/

	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	emnew->em_type = EM_ADDVALUES;
	av = AttrV_alloc();
	if (!av) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "av", CNULL, 0, proc);
		return(- 1);
	}
	av->av_struct = (caddr_t) cert_cpy(quipu_cert);
	av->av_syntax = avst_result->avseq_av.av_syntax;
	avst_arg = avs_comp_new(av);
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	mod_arg.mea_changes = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_retrieve_Certificate                     *
 ***************************************************************************************/



SET_OF_Certificate *af_dir_retrieve_Certificate(dname, type)
DName *dname;
CertificateType type;
{
	PE      pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	SET_OF_Certificate * ret;   /* return value */
	SET_OF_Certificate * certset;
	SET_OF_Certificate * save_certset;

	objectclass * obj_class;
	int	found = 0;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct certificate *quipu_cert;

	PS rps;
	char	*proc = "af_dir_retrieve_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname || ((type != userCertificate) && (type != cACertificate)) ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	}

	if ( !(ret = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate))) ) {
		aux_add_error(EMALLOC, "ret", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return((SET_OF_Certificate * )0);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return((SET_OF_Certificate * )0); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	if ( type == userCertificate )
		at = AttrT_new("userCertificate");
	else
		at = AttrT_new("cACertificate");

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "at==NULLAttrT", CNULL, 0, proc);
		return ( (SET_OF_Certificate * )0 );
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);
	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;

#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return((SET_OF_Certificate * )0);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return((SET_OF_Certificate * )0);
			}
		}
	}
#endif


	dn_free (read_arg.rda_object);

	/*  The cACertificate attribute is MANDATORY within the directory entry of
	 *  a certificationAuthority, and the userCertificate attribute MANDATORY within
	 *  the directory entry of a strongAuthenticationUser; it has multiple value, namely
	 *  one or more EncrCertificates and one or more SignCertificates.
	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return ( (SET_OF_Certificate * )0 );
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return ( (SET_OF_Certificate * )0 );
	}

	quipu_cert = (struct certificate *)avst_result->avseq_av.av_struct;

	if ( (pe = cert_enc(quipu_cert)) == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
		return( (SET_OF_Certificate * )0);
	}

	if ( (ret->element = certificate_dec(pe)) == (Certificate * )0 ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
		return( (SET_OF_Certificate * )0);
	}

	pe_free(pe);

	ret->next = (SET_OF_Certificate * )0;
	save_certset = ret;


	/*  The requested attribute has multiple value; the values are stored within a set 
	 *  of certificates:
	 */
	for ( avseq = avst_result->avseq_next; avseq ; avseq = avseq->avseq_next ) {

		if ( !(certset = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate))) ) {
			ds_unbind();
			aux_add_error(EMALLOC, "certset", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}

		save_certset->next = certset;
		quipu_cert = (struct certificate *)avseq->avseq_av.av_struct;

		if ( (pe = cert_enc(quipu_cert)) == NULLPE ) {
			ds_unbind();
			aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}

		if ( (certset->element = certificate_dec(pe)) == (Certificate * )0 ) {
			pe_free(pe);
			ds_unbind();
			aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
			return((SET_OF_Certificate * )0);
		}

		pe_free(pe);
		certset->next = (SET_OF_Certificate * )0;
		save_certset = certset;

	}    /*for*/


	ds_unbind();

	return(ret);
}




/***************************************************************************************
 *                                     af_dir_delete_Certificate                       *
 ***************************************************************************************/




RC
af_dir_delete_Certificate(serial, issuer, type)
int	serial;
DName *issuer;
CertificateType type;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	struct certificate *quipu_cert_tmp, *quipu_cert_found;

	DN quipu_issuer;

	objectclass * obj_class;
	int	found = 0;

	PS rps;
	char	*proc = "af_dir_delete_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif


	if ( serial < 0 || ((type != userCertificate) && (type != cACertificate)) ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if (issuer) {
		build_IF_Name(&pe, 1, 0, NULLCP, issuer);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(- 1);
		}

		if ( (quipu_issuer = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(- 1);
		}

		pe_free(pe);
	}

	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1);
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	read_arg.rda_object = dn_cpy(directory_user_dn);
	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	if ( type == userCertificate )
		at = AttrT_new("userCertificate");
	else
		at = AttrT_new("cACertificate");

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "at==NULLAttrT", CNULL, 0, proc);
		return (- 1);
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);
	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return(- 1);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The cACertificate attribute is MANDATORY within the directory entry of
	 *  a certificationAuthority, and the userCertificate attribute MANDATORY within
	 *  the directory entry of a strongAuthenticationUser; it has multiple value, namely
	 *  one or more EncrCertificates and one or more SignCertificates.
	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return(- 1);
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;
	acl = read_result.rdr_entry.ent_attr->attr_acl;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return(- 1);
	}

	if (issuer) {
		for ( avseq = avst_result, found = 0 ; avseq ; avseq = avseq->avseq_next ) {
			quipu_cert_tmp = (struct certificate *)avseq->avseq_av.av_struct;
			if ( !dn_cmp(quipu_cert_tmp->issuer, quipu_issuer) && 
			    (serial == quipu_cert_tmp->serial) ) {    /*equal*/
				quipu_cert_found = quipu_cert_tmp;
				found = 1;
				break;
			}
		}  /*for*/
	} 
	else {
		for ( avseq = avst_result, found = 0 ; avseq ; avseq = avseq->avseq_next ) {
			quipu_cert_tmp = (struct certificate *)avseq->avseq_av.av_struct;
			if (serial == quipu_cert_tmp->serial) {
				if (!found) {
					quipu_cert_found = quipu_cert_tmp;
					found = 1;
				}
				else {
					ds_unbind();
					dn_free (read_arg.rda_object);
					aux_add_error(EOBJ, "More than one certificate with specified serial number", CNULL,
					    0, proc);
					return(- 1);
				}
			}
		}  /*for*/
	}

	if ( !found ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EOBJNAME, "Specified certificate does not exist in Your directory entry", CNULL, 0, proc);
		return(- 1);
	}

	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	emnew->em_type = EM_REMOVEVALUES;
	av = AttrV_alloc();
	if (!av) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "av", CNULL, 0, proc);
		return(- 1);
	}
	av->av_struct = (caddr_t) cert_cpy(quipu_cert_found);
	av->av_syntax = avst_result->avseq_av.av_syntax;
	avst_arg = avs_comp_new(av);
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	mod_arg.mea_changes = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_enter_Crl                            *
 ***************************************************************************************/




RC
af_dir_enter_Crl(type, rcl_attr, dname)
RevokeType type;
Crl *rcl_attr;
DName *dname;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;


	PS rps;
	char	*proc = "af_dir_enter_Crl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ARL) && (type != CRL)) || !rcl_attr || !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;


	/* Set up the desired attribute type to be read from read.c: */

	switch (type) {
	case ARL:
		at = AttrT_new("revokedAuthorityList");
		break;
	case CRL:
		at = AttrT_new("revokedCertificateList");
		break;
	}   /*switch*/

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		return (- 1);
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return(- 1);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  Both the "revokedCertificateList" attribute and the "revokedAuthorityList" attribute 
	 *  are MANDATORY within the directory entry of a certification authority.
	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return(- 1);
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;
	acl = read_result.rdr_entry.ent_attr->attr_acl;


	if ( avst_result == NULLAV ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return(- 1);
	}

	mod_arg.mea_changes = NULLMOD;

	/* replace old by new value */
	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	emnew->em_type = EM_REMOVEVALUES;
	avst_arg = avs_comp_new(AttrV_cpy(&avst_result->avseq_av));
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	emnew->em_type = EM_ADDVALUES;
	av = AttrV_alloc();
	if (!av) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "av", CNULL, 0, proc);
		return(- 1);
	}
	av->av_struct = (caddr_t) aux_cpy_Crl(rcl_attr);
	av->av_syntax = avst_result->avseq_av.av_syntax;
	avst_arg = avs_comp_new(av);
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);


	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;

#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}


	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_retrieve_Crl                  *
 ***************************************************************************************/




Crl *af_dir_retrieve_Crl(dname, type)
DName *dname;
RevokeType type;
{
	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	PS rps;
	char	*proc = "af_dir_retrieve_Crl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ((type != ARL) && (type != CRL)) || !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return((Crl * )0);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return((Crl * )0);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return((Crl * )0);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return((Crl * )0);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return((Crl * )0); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return((Crl * )0);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return((Crl * )0);
	}

	pe_free(pe);


	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	switch (type) {
	case ARL:
		at = AttrT_new("revokedAuthorityList");
		break;
	case CRL:
		at = AttrT_new("revokedCertificateList");
		break;
	}   /*switch*/

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		return ( (Crl * )0 );
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return((Crl * )0);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return((Crl * )0);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return((Crl * )0);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return((Crl * )0);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return((Crl * )0);
			}
		}
	}
#endif


	dn_free (read_arg.rda_object);

	/*  Both the revokedCertificateList attribute and the revokedAuthorityList attribute 
	 *  are MANDATORY within the directory entry of a certification authority.
 	 *  Both certified lists shall exist, even if empty (see X.509, p.15).
 	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return ( (Crl * )0 );
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return ( (Crl * )0 );
	}

	ds_unbind();

	return( (Crl * )avst_result->avseq_av.av_struct );
}




/***************************************************************************************
 *                                     af_dir_enter_PemCrl                         *
 ***************************************************************************************/




RC
af_dir_enter_PemCrl(pemcrl)
PemCrl *pemcrl;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	PS rps;
	char	*proc = "af_dir_enter_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !pemcrl) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);

	fprintf(stderr, "You are supposed to be the issuer of the revocation list.\n");
	fprintf(stderr, "Your directory name is being derived from the name of the issuer ");
	fprintf(stderr, "of the revocation list.\n");
	fprintf(stderr, "\nBinding as \"%s\"\n", aux_DName2Name(pemcrl->tbs->issuer));

	build_IF_Name(&pe, 1, 0, NULLCP, pemcrl->tbs->issuer);
	if ( pe == NULLPE ) {
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (bindarg.dba_dn = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	read_arg.rda_object = dn_cpy(directory_user_dn);
	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;


	/* Set up the desired attribute type to be read from read.c: */

	if ((at = AttrT_new("pemCRL")) == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		return (- 1);
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		if ( (read_error.dse_type != DSE_ATTRIBUTEERROR) || 
		    (read_error.dse_un.dse_un_attribute.DSE_at_plist.DSE_at_what != DSE_AT_NOSUCHATTRIBUTE) ) {
			fprintf(stderr, "\n");
			ds_error(rps, &read_error);
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
			return(- 1);
		}
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The "pemCRL" attribute is OPTIONAL within the directory entry of a 
	 *  certification authority.
	 */

	mod_arg.mea_changes = NULLMOD;

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		/* create new attribute */
		emnew = em_alloc();
		if (!emnew) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
			return(- 1);
		}
		emnew->em_type = EM_ADDATTRIBUTE;
		av = AttrV_alloc();
		if (!av) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "av", CNULL, 0, proc);
			return(- 1);
		}
		av->av_struct = (caddr_t) aux_cpy_PemCrl(pemcrl);
		av->av_syntax = at->oa_syntax;
		avst_arg = avs_comp_new(av);
		emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, NULLACL_INFO);
		emnew->em_next = NULLMOD;
		if ( emnew != NULLMOD )
			mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
	}    /*if*/ 
	else {
		avst_result = read_result.rdr_entry.ent_attr->attr_value;
		acl = read_result.rdr_entry.ent_attr->attr_acl;

		if ( avst_result == NULLAV ) {
			/* add value */
			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_ADDVALUES;
			av = AttrV_alloc();
			if (!av) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "av", CNULL, 0, proc);
				return(- 1);
			}
			av->av_struct = (caddr_t) aux_cpy_PemCrl(pemcrl);
			av->av_syntax = avst_result->avseq_av.av_syntax;
			avst_arg = avs_comp_new(av);
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
		} 
		else {
			/* replace old by new value */
			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_REMOVEVALUES;
			avst_arg = avs_comp_new(AttrV_cpy(&avst_result->avseq_av));
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_ADDVALUES;
			av = AttrV_alloc();
			if (!av) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "av", CNULL, 0, proc);
				return(- 1);
			}
			av->av_struct = (caddr_t) aux_cpy_PemCrl(pemcrl);
			av->av_syntax = avst_result->avseq_av.av_syntax;
			avst_arg = avs_comp_new(av);
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
		}   /*else*/
	}    /*else*/

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_retrieve_PemCrl                      *
 ***************************************************************************************/




PemCrl *af_dir_retrieve_PemCrl(dname)
DName *dname;
{
	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	PS rps;
	char	*proc = "af_dir_retrieve_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return((PemCrl * )0);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return((PemCrl * )0);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return((PemCrl * )0);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return((PemCrl * )0);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return((PemCrl * )0); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return((PemCrl * )0);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return((PemCrl * )0);
	}

	pe_free(pe);


	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	if ((at = AttrT_new("pemCRL")) == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		return ( (PemCrl * )0 );
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return((PemCrl * )0);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return((PemCrl * )0);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return((PemCrl * )0);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return((PemCrl * )0);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return((PemCrl * )0);
			}
		}
	}
#endif


	dn_free (read_arg.rda_object);

	/*  The "pemCRL" attribute is OPTIONAL within the directory entry of a 
	 *  certification authority.
	 */

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return ( (PemCrl * )0 );
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return ( (PemCrl * )0 );
	}

	ds_unbind();

	return( (PemCrl * )avst_result->avseq_av.av_struct );
}




/***************************************************************************************
 *                                     af_dir_enter_CertificatePair                    *
 ***************************************************************************************/




RC
af_dir_enter_CertificatePair(cpair, dname)
CertificatePair *cpair;
DName *dname;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	struct certificate_list *quipu_cpair;

	PS rps;
	char	*proc = "af_dir_enter_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !cpair || !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	/* at least one (forward or reverse) must be present (X.509, 7.6) */
	if (!cpair->forward && !cpair->reverse) {
		aux_add_error(EINVALID, "Invalid argument: At least one certificate (forward or reverse) must be present",
		     CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	/*Transform SecuDe-type "CertificatePair" into QUIPU-type "certificate_list":*/

	if ( !(quipu_cpair = (struct certificate_list *)malloc(sizeof(struct certificate_list ))) ) {
		aux_add_error(EMALLOC, "quipu_cpair", CNULL, 0, proc);
		return(- 1);
	}

	if (cpair->forward) {
		if ( (pe = certificate_enc(cpair->forward)) == NULLPE ) {
			aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
			return(- 1);
		}

		if ( (quipu_cpair->cert = cert_dec(pe)) == (struct certificate *)0 ) {
			pe_free(pe);
			aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
			return(- 1);
		}

		pe_free(pe);
	} 
	else /* cpair->forward may be the NULL pointer */
		quipu_cpair->cert = (struct certificate *)0;

	if (cpair->reverse) {
		if ( (pe = certificate_enc(cpair->reverse)) == NULLPE ) {
			aux_add_error(EENCODE, "certificate_enc failed", CNULL, 0, proc);
			return(- 1);
		}

		if ( (quipu_cpair->reverse = cert_dec(pe)) == (struct certificate *)0 ) {
			pe_free(pe);
			aux_add_error(EDECODE, "cert_dec failed", CNULL, 0, proc);
			return(- 1);
		}

		pe_free(pe);
	} 
	else /* cpair->reverse may be the NULL pointer */
		quipu_cpair->reverse = (struct certificate *)0;

	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1);  
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	if ( (at = AttrT_new("crossCertificatePair")) == NULLAttrT ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "AttrT_new failed for crossCertificatePair", CNULL, 0, proc);
		return (- 1);
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;

#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif

	/* READ operation in order to find out whether an attribute of type
	   "crossCertificatePair" already exists in the specified entry */

	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		if ( (read_error.dse_type != DSE_ATTRIBUTEERROR) || 
		    (read_error.dse_un.dse_un_attribute.DSE_at_plist.DSE_at_what != DSE_AT_NOSUCHATTRIBUTE) ) {
			fprintf(stderr, "\n");
			ds_error(rps, &read_error);
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
			return(- 1);
		}
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The crossCertificatePair attribute is OPTIONAL within the directory entry of
	 *  a CA; if it is not present, it is to be created as a new attribute in the
	 *  directory entry of the named CA:
	 */

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {     /* create new attribute */
		emnew = em_alloc();
		if (!emnew) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
			return(- 1);
		}
		emnew->em_type = EM_ADDATTRIBUTE;
		av = AttrV_alloc();
		if (!av) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "av", CNULL, 0, proc);
			return(- 1);
		}
		av->av_struct = (caddr_t) cpair_cpy(quipu_cpair);
		av->av_syntax = at->oa_syntax;
		avst_arg = avs_comp_new(av);
		emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, NULLACL_INFO);
		emnew->em_next = NULLMOD;
		mod_arg.mea_changes = NULLMOD;
		if ( emnew != NULLMOD )
			mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
	}    /*if*/ 
	else {	/* add value */
		acl = read_result.rdr_entry.ent_attr->attr_acl;
		emnew = em_alloc();
		if (!emnew) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
			return(- 1);
		}
		emnew->em_type = EM_ADDVALUES;
		av = AttrV_alloc();
		if (!av) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "av", CNULL, 0, proc);
			return(- 1);
		}
		av->av_struct = (caddr_t) cpair_cpy(quipu_cpair);
		av->av_syntax = at->oa_syntax;
		avst_arg = avs_comp_new(av);
		emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
		emnew->em_next = NULLMOD;
		mod_arg.mea_changes = NULLMOD;
		if ( emnew != NULLMOD )
			mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	}    /*else*/

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;

#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_retrieve_CertificatePair                 *
 ***************************************************************************************/




SET_OF_CertificatePair *af_dir_retrieve_CertificatePair(dname)
DName *dname;
{
	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	SET_OF_CertificatePair * ret;   /* return value */
	SET_OF_CertificatePair * cpair_set;
	struct certificate_list *quipu_cpair;

	objectclass * obj_class;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	PS rps;
	char	*proc = "af_dir_retrieve_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return((SET_OF_CertificatePair * )0);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return( (SET_OF_CertificatePair * )0);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return( (SET_OF_CertificatePair * )0);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return((SET_OF_CertificatePair * )0);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return((SET_OF_CertificatePair * )0); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return((SET_OF_CertificatePair * )0);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return((SET_OF_CertificatePair * )0);
	}

	pe_free(pe);


	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	if ( (at = AttrT_new("crossCertificatePair")) == NULLAttrT ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "AttrT_new failed for crossCertificatePair", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return((SET_OF_CertificatePair * )0);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return((SET_OF_CertificatePair * )0);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return((SET_OF_CertificatePair * )0);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return((SET_OF_CertificatePair * )0);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return((SET_OF_CertificatePair * )0);
			}
		}
	}
#endif


	dn_free (read_arg.rda_object);

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	if ((quipu_cpair = (struct certificate_list *)avst_result->avseq_av.av_struct)
	     == (struct certificate_list *)0) {
		ds_unbind();
		aux_add_error(EINVALID, "quipu_cpair == 0", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	if ( !(cpair_set = (SET_OF_CertificatePair * )malloc(sizeof(SET_OF_CertificatePair))) ) {
		ds_unbind();
		aux_add_error(EMALLOC, "cpair_set", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	if ( !(cpair_set->element = (CertificatePair * )malloc(sizeof(CertificatePair))) ) {
		ds_unbind();
		aux_add_error(EMALLOC, "cpair_set->element", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair * )0 );
	}

	/* quipu_cpair->cert may be empty */
	if (!quipu_cpair->cert)
		cpair_set->element->forward = (Certificate * )0;
	else {
		if ( (pe = cert_enc(quipu_cpair->cert)) == NULLPE ) {
			ds_unbind();
			aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}
		if ( (cpair_set->element->forward = certificate_dec(pe)) == (Certificate * )0 ) {
			pe_free(pe);
			ds_unbind();
			aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}
		pe_free(pe);
	}

	/* quipu_cpair->reverse may be empty */
	if (!quipu_cpair->reverse)
		cpair_set->element->reverse = (Certificate * )0;
	else {
		if ( (pe = cert_enc(quipu_cpair->reverse)) == NULLPE ) {
			ds_unbind();
			aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}
		if ( (cpair_set->element->reverse = certificate_dec(pe)) == (Certificate * )0 ) {
			pe_free(pe);
			ds_unbind();
			aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}
		pe_free(pe);
	}

	cpair_set->next = (SET_OF_CertificatePair * )0;
	ret = cpair_set;

	for ( avseq = avst_result->avseq_next; 
	    avseq; 
	    avseq = avseq->avseq_next ) {

		if ((quipu_cpair = (struct certificate_list *)avseq->avseq_av.av_struct)
		     == (struct certificate_list *)0) {
			ds_unbind();
			return ( (SET_OF_CertificatePair * )0 );
		}

		if ( !(cpair_set->next = (SET_OF_CertificatePair * )malloc(sizeof(SET_OF_CertificatePair))) ) {
			ds_unbind();
			aux_add_error(EMALLOC, "cpair_set->next", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}

		cpair_set = cpair_set->next;
		cpair_set->next = (SET_OF_CertificatePair * )0;

		if ( !(cpair_set->element = (CertificatePair * )malloc(sizeof(CertificatePair))) ) {
			ds_unbind();
			aux_add_error(EMALLOC, "cpair_set->element", CNULL, 0, proc);
			return( (SET_OF_CertificatePair * )0);
		}

		/* quipu_cpair->cert may be empty */
		if (!quipu_cpair->cert)
			cpair_set->element->forward = (Certificate * )0;
		else {
			if ( (pe = cert_enc(quipu_cpair->cert)) == NULLPE ) {
				ds_unbind();
				aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
				return( (SET_OF_CertificatePair * )0);
			}
			if ((cpair_set->element->forward = certificate_dec(pe)) == (Certificate * )0) {
				pe_free(pe);
				ds_unbind();
				aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
				return( (SET_OF_CertificatePair * )0);
			}
			pe_free(pe);
		}

		/* quipu_cpair->reverse may be empty */
		if (!quipu_cpair->reverse)
			cpair_set->element->reverse = (Certificate * )0;
		else {
			if ( (pe = cert_enc(quipu_cpair->reverse)) == NULLPE ) {
				ds_unbind();
				aux_add_error(EENCODE, "cert_enc failed", CNULL, 0, proc);
				return( (SET_OF_CertificatePair * )0);
			}
			if ((cpair_set->element->reverse = certificate_dec(pe)) == (Certificate * )0) {
				pe_free(pe);
				ds_unbind();
				aux_add_error(EDECODE, "certificate_dec failed", CNULL, 0, proc);
				return( (SET_OF_CertificatePair * )0);
			}
			pe_free(pe);
		}

	}    /*for*/


	ds_unbind();

	return(ret);
}




/***************************************************************************************
 *                                     af_dir_delete_CertificatePair                   *
 ***************************************************************************************/

RC
af_dir_delete_CertificatePair(cpair)
CertificatePair *cpair;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	struct certificate_list *quipu_cpair, *quipu_cpair_tmp;
	int	found = 0;

	PS rps;
	char	*proc = "af_dir_delete_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!cpair) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	/* at least one (forward or reverse) must be present (X.509, 7.6) */
	if (!cpair->forward && !cpair->reverse) {
		aux_add_error(EINVALID, "Invalid argument: At least one certificate (forward or reverse) must be present",
		     CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);

	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	/*Transform SecuDe-type "CertificatePair" into QUIPU-type "certificate_list":*/

	if ( !(quipu_cpair = (struct certificate_list *)malloc(sizeof(struct certificate_list ))) ) {
		aux_add_error(EMALLOC, "quipu_cpair", CNULL, 0, proc);
		return(- 1);
	}

	if (cpair->forward) {
		if ( !(quipu_cpair->cert = (struct certificate *)malloc(sizeof(struct certificate ))) ) {
			aux_add_error(EMALLOC, "quipu_cpair->cert", CNULL, 0, proc);
			return(- 1);
		}
		quipu_cpair->cert->serial = cpair->forward->tbs->serialnumber;
		build_IF_Name(&pe, 1, 0, NULLCP, cpair->forward->tbs->issuer);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(- 1);
		}
		if ( (quipu_cpair->cert->issuer = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(- 1);
		}
		pe_free(pe);

		quipu_cpair->cert->alg.algorithm = NULLOID;
		quipu_cpair->cert->alg.asn = NULLPE;
		quipu_cpair->cert->alg.p_type = 0;
		quipu_cpair->cert->version = 0;
		quipu_cpair->cert->subject = NULLDN;
		quipu_cpair->cert->valid.not_before = CNULL;
		quipu_cpair->cert->valid.not_after = CNULL;
		quipu_cpair->cert->key.alg.algorithm = NULLOID;
		quipu_cpair->cert->key.alg.asn = NULLPE;
		quipu_cpair->cert->key.alg.p_type = 0;
		quipu_cpair->cert->key.n_bits = 0;
		quipu_cpair->cert->key.value = CNULL;
		quipu_cpair->cert->sig.alg.algorithm = NULLOID;
		quipu_cpair->cert->sig.alg.asn = NULLPE;
		quipu_cpair->cert->sig.alg.p_type = 0;
		quipu_cpair->cert->sig.encoded = NULLPE;
		quipu_cpair->cert->sig.n_bits = 0;
		quipu_cpair->cert->sig.encrypted = CNULL;

	} else /* cpair->forward may be the NULL pointer */
		quipu_cpair->cert = (struct certificate *)0;

	if (cpair->reverse) {
		if ( !(quipu_cpair->reverse = (struct certificate *)malloc(sizeof(struct certificate ))) ) {
			aux_add_error(EMALLOC, "quipu_cpair->reverse", CNULL, 0, proc);
			return(- 1);
		}
		quipu_cpair->reverse->serial = cpair->reverse->tbs->serialnumber;
		build_IF_Name(&pe, 1, 0, NULLCP, cpair->reverse->tbs->issuer);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(- 1);
		}
		if ( (quipu_cpair->reverse->issuer = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(- 1);
		}
		pe_free(pe);

		quipu_cpair->reverse->alg.algorithm = NULLOID;
		quipu_cpair->reverse->alg.asn = NULLPE;
		quipu_cpair->reverse->alg.p_type = 0;
		quipu_cpair->reverse->version = 0;
		quipu_cpair->reverse->subject = NULLDN;
		quipu_cpair->reverse->valid.not_before = CNULL;
		quipu_cpair->reverse->valid.not_after = CNULL;
		quipu_cpair->reverse->key.alg.algorithm = NULLOID;
		quipu_cpair->reverse->key.alg.asn = NULLPE;
		quipu_cpair->reverse->key.alg.p_type = 0;
		quipu_cpair->reverse->key.n_bits = 0;
		quipu_cpair->reverse->key.value = CNULL;
		quipu_cpair->reverse->sig.alg.algorithm = NULLOID;
		quipu_cpair->reverse->sig.alg.asn = NULLPE;
		quipu_cpair->reverse->sig.alg.p_type = 0;
		quipu_cpair->reverse->sig.encoded = NULLPE;
		quipu_cpair->reverse->sig.n_bits = 0;
		quipu_cpair->reverse->sig.encrypted = CNULL;

	} else /* cpair->reverse may be the NULL pointer */
		quipu_cpair->reverse = (struct certificate *)0;

	quipu_cpair->next = (struct certificate_list * )0;
	quipu_cpair->prev = (struct certificate_list * )0;
	quipu_cpair->superior = (struct certificate_list * )0;

	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1);  
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	read_arg.rda_object = dn_cpy(directory_user_dn);
	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	if ( (at = AttrT_new("crossCertificatePair")) == NULLAttrT ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "AttrT_new failed for crossCertificatePair", CNULL, 0, proc);
		return (- 1);
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);
	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return(- 1);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return(- 1);
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;
	acl = read_result.rdr_entry.ent_attr->attr_acl;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return(- 1);
	}

	for ( avseq = avst_result, found = 0 ; avseq ; avseq = avseq->avseq_next ) {
		quipu_cpair_tmp = (struct certificate_list *)avseq->avseq_av.av_struct;
		if ( !cmp_quipu_cpair(quipu_cpair, quipu_cpair_tmp)) {    /*equal*/
			found = 1;
			break;
		}
	}  /*for*/

	if ( !found ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EOBJNAME, "Specified CertificatePair does not exist in your directory entry", CNULL, 0, proc);
		return(- 1);
	}

	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	if (avst_result->avseq_next) 
		emnew->em_type = EM_REMOVEVALUES;
	else 
		emnew->em_type = EM_REMOVEATTRIBUTE;
	av = AttrV_alloc();
	if (!av) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "av", CNULL, 0, proc);
		return(- 1);
	}
	av->av_struct = (caddr_t) cpair_cpy(quipu_cpair_tmp);
	av->av_syntax = avst_result->avseq_av.av_syntax;
	avst_arg = avs_comp_new(av);
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	mod_arg.mea_changes = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;

#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}






/***************************************************************************************
 *                                     af_dir_enter_OCList                             *
 ***************************************************************************************/




RC
af_dir_enter_OCList(ocl_attr, dname)
OCList *ocl_attr;
DName *dname;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	PS rps;
	char	*proc = "af_dir_enter_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !ocl_attr || !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);

	
	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1);  
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	if ( (at = AttrT_new("oldCertificateList")) == NULLAttrT ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "AttrT_new failed for oldCertificateList", CNULL, 0, proc);
		return (- 1);
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		if ( (read_error.dse_type != DSE_ATTRIBUTEERROR) || 
		    (read_error.dse_un.dse_un_attribute.DSE_at_plist.DSE_at_what != DSE_AT_NOSUCHATTRIBUTE) ) {
			fprintf(stderr, "\n");
			ds_error(rps, &read_error);
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
			return(- 1);
		}
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The oldCertificateList attribute is OPTIONAL within the directory entry of
	 *  a CA; if it is not present, it is to be created as a new attribute in the
	 *  directory entry of the named CA:
	 */
	mod_arg.mea_changes = NULLMOD;

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		/* create new attribute */
		emnew = em_alloc();
		if (!emnew) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
			return(- 1);
		}
		emnew->em_type = EM_ADDATTRIBUTE;
		av = AttrV_alloc();
		if (!av) {
			ds_unbind ();
			dn_free (read_arg.rda_object);
			aux_add_error(EMALLOC, "av", CNULL, 0, proc);
			return(- 1);
		}
		av->av_struct = (caddr_t) aux_cpy_OCList(ocl_attr);
		av->av_syntax = at->oa_syntax;
		avst_arg = avs_comp_new(av);
		emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, NULLACL_INFO);
		emnew->em_next = NULLMOD;
		if ( emnew != NULLMOD )
			mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
	}    /*if*/ 
	else {
		avst_result = read_result.rdr_entry.ent_attr->attr_value;
		acl = read_result.rdr_entry.ent_attr->attr_acl;

		if ( avst_result == NULLAV ) {
			/* add value */
			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_ADDVALUES;
			av = AttrV_alloc();
			if (!av) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "av", CNULL, 0, proc);
				return(- 1);
			}
			av->av_struct = (caddr_t) aux_cpy_OCList(ocl_attr);
			av->av_syntax = avst_result->avseq_av.av_syntax;
			avst_arg = avs_comp_new(av);
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
		}
		else {
			/* replace old by new value */
			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_REMOVEVALUES;
			avst_arg = avs_comp_new(AttrV_cpy(&avst_result->avseq_av));
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

			emnew = em_alloc();
			if (!emnew) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
				return(- 1);
			}
			emnew->em_type = EM_ADDVALUES;
			av = AttrV_alloc();
			if (!av) {
				ds_unbind ();
				dn_free (read_arg.rda_object);
				aux_add_error(EMALLOC, "av", CNULL, 0, proc);
				return(- 1);
			}
			av->av_struct = (caddr_t) aux_cpy_OCList(ocl_attr);
			av->av_syntax = avst_result->avseq_av.av_syntax;
			avst_arg = avs_comp_new(av);
			emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
			emnew->em_next = NULLMOD;
			if ( emnew != NULLMOD )
				mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);
		}   /*else*/

	}    /*else*/

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}


	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}




/***************************************************************************************
 *                                     af_dir_retrieve_OCList                          *
 ***************************************************************************************/




OCList *af_dir_retrieve_OCList(dname)
DName *dname;
{
	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	PS rps;
	char	*proc = "af_dir_retrieve_OCList";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return((OCList * )0);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return( (OCList * )0);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return( (OCList * )0);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return((OCList * )0);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return((OCList * )0); 
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, dname);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return((OCList * )0);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return((OCList * )0);
	}

	pe_free(pe);


	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	/* Set up the desired attribute type to be read from read.c: */

	if ( (at = AttrT_new("oldCertificateList")) == NULLAttrT ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "AttrT_new failed for oldCertificateList", CNULL, 0, proc);
		return ( (OCList * )0 );
	}

	/*  Only the attribute types of the Attr_Sequence structure need to be set
	 *  (see Volume5, p.213)
	 */
	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);

	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return((OCList * )0);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return((OCList * )0);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return((OCList * )0);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return((OCList * )0);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return((OCList * )0);
			}
		}
	}
#endif


	dn_free (read_arg.rda_object);

	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return ( (OCList * )0 );
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return ( (OCList * )0 );
	}

	ds_unbind();

	return( (OCList * )avst_result->avseq_av.av_struct );
}




/***************************************************************************************
 *                      af_dir_delete_Certificate_from_targetObject                    *
 ***************************************************************************************/





RC
af_dir_delete_Certificate_from_targetObject(target, serial, issuer, type)
DName		 * target;
int		   serial;
DName 		 * issuer;
CertificateType    type;
{

	PE pe;

	/* Arguments used by ds_read(): */
	struct ds_read_arg    read_arg;
	struct DSError        read_error;
	struct ds_read_result read_result;

	/* Arguments used by ds_modifyentry(): */
	struct ds_modifyentry_arg mod_arg;
	struct DSError            mod_error;

	AV_Sequence    avst_result = NULLAV;    /*pointer*/
	AV_Sequence    avseq = NULLAV;		/*pointer*/
	AV_Sequence    avst_arg = NULLAV;       /*pointer*/
	AttributeType  at;             	        /*pointer*/
	Attr_Sequence  as;                      /*pointer*/
	AttributeValue av;	                /*pointer*/

	struct acl_info *acl;
	struct entrymod *emnew;

	struct certificate *quipu_cert_tmp, *quipu_cert_found;

	DN quipu_issuer;

	objectclass * obj_class;
	int	      found = 0;

	PS rps;
	char	    * proc = "af_dir_delete_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( ! target || serial < 0 || ((type != userCertificate) && (type != cACertificate)) ) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);
		return(- 1);
	}

	rps = ps_alloc(std_open);
	std_setup(rps, stdout);


	/* set up the needed function pointers: */
	quipu_syntaxes();
	security_syntaxes();
	dsap_init(&af_x500_count, &af_x500_vecptr);


	if (issuer) {
		build_IF_Name(&pe, 1, 0, NULLCP, issuer);
		if ( pe == NULLPE ) {
			aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
			return(- 1);
		}

		if ( (quipu_issuer = dn_dec(pe)) == NULLDN ) {
			pe_free(pe);
			aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
			return(- 1);
		}

		pe_free(pe);
	}

	if(set_bindarg()){
		aux_add_error(EINVALID, "set_bindarg failed", CNULL, 0, proc);
		return(- 1);
	};

	if ( secure_ds_bind(&bindarg, &binderr, &bindresult) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_bind_error(rps, &binderr);
		ds_unbind();
		dn_free (bindarg.dba_dn);
		bindarg.dba_dn = NULLDN;
		dn_free(directory_user_dn);
		directory_user_dn = NULLDN;
		free(directory_user_name);
		aux_add_error(set_bind_error(binderr), "secure_ds_bind failed", CNULL, 0, proc);
		if(auth_level == DBA_AUTH_SIMPLE){
			bindarg.dba_passwd[0] = 0;
			Password[0] = '\0';
		}
		return(- 1);
	}

	if (auth_level == DBA_AUTH_SIMPLE && store_password_on_PSE == TRUE) {
		store_password_on_PSE = FALSE;			
		rc = af_pse_update_QuipuPWD(Password);
		if (rc < 0) {
			aux_add_error(EWRITEPSE, "af_pse_update_QuipuPWD failed", CNULL, 0, proc);
			return(- 1);
		}
	}

#ifdef STRONG
	if(auth_level == DBA_AUTH_STRONG){
		if(verify_bindres()){
			aux_add_error(EVERIFICATION, "verify_bindres failed", CNULL, 0, proc);
			if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  f a i l e d !\n\n");
			return(- 1);  
		}
		if(af_verbose) fprintf(stderr, "\nS T R O N G  authentication  s u c c e e d e d !\n\n");
	}
#endif

	build_IF_Name(&pe, 1, 0, NULLCP, target);
	if ( pe == NULLPE ) {
		ds_unbind();
		aux_add_error(EENCODE, "Encoding name", CNULL, 0, proc);
		return(- 1);
	}

	if ( (read_arg.rda_object = dn_dec(pe)) == NULLDN ) {
		pe_free(pe);
		ds_unbind();
		aux_add_error(EDECODE, "Decoding name", CNULL, 0, proc);
		return(- 1);
	}

	pe_free(pe);

	read_arg.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	read_arg.rda_eis.eis_allattributes = FALSE;

	if ( type == userCertificate )
		at = AttrT_new("userCertificate");
	else
		at = AttrT_new("cACertificate");

	if (at == NULLAttrT) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "at==NULLAttrT", CNULL, 0, proc);
		return (- 1);
	}

	as = as_comp_new(AttrT_cpy(at), NULLAV, NULLACL_INFO);
	read_arg.rda_eis.eis_select = as_cpy(as);
	read_result.rdr_entry.ent_attr = NULLATTR;

	read_arg.rda_common = ca;
	read_arg.rda_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ReadArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		read_arg.rda_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		read_arg.rda_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&read_arg, _ZReadArgumentDataDAS);
		if(! read_arg.rda_common.ca_sig){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign read_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
	read_result.rdr_common.cr_sig = (struct signature * )0;
	read_result.rdr_common.cr_security == (struct security_parms *) 0;
#endif


	if ( ds_read(&read_arg, &read_error, &read_result) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &read_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(read_error), "ds_read failed", CNULL, 0, proc);
		return(- 1);
	}


#ifdef STRONG

	/****  V E R I F Y  ReadResult  ****/

	if(read_result.rdr_common.cr_sig){  /*read_result is SIGNED and must be evaluated*/
		/* Policy : signed messages must have security parameters present. */
  		if (read_result.rdr_common.cr_security == (struct security_parms *) 0){
			ds_unbind();
			dn_free(read_arg.rda_object);
			aux_add_error(EINVALID, "Security Policy Violation: No security parameters present", CNULL, 0, proc);
			return(- 1);
		}
	        if (dsap_security && dsap_security->serv_ckpath && dsap_security->serv_cknonce){
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			rc = (dsap_security->serv_ckpath) 
				((caddr_t) &read_result, read_result.rdr_common.cr_security->sp_path, read_result.rdr_common.cr_sig, &real_name, _ZReadResultDataDAS);
			fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
			/* CHECK whether real_name is needed within "serv_ckpath" !!!*/
			if (rc != OK){
				ds_unbind();
				dn_free(read_arg.rda_object);
				aux_add_error(EVERIFICATION, "Cannot verify signature applied to read_result", CNULL, 0, proc);
				return(- 1);
			}
		}
	}
#endif


	/*  The cACertificate attribute is MANDATORY within the directory entry of
	 *  a certificationAuthority, and the userCertificate attribute MANDATORY within
	 *  the directory entry of a strongAuthenticationUser; it has multiple value, namely
	 *  one or more EncrCertificates and one or more SignCertificates.
	 */
	if ( read_result.rdr_entry.ent_attr == NULLATTR ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "read_result.rdr_entry.ent_attr == NULLATTR", CNULL, 0, proc);
		return(- 1);
	}

	avst_result = read_result.rdr_entry.ent_attr->attr_value;
	acl = read_result.rdr_entry.ent_attr->attr_acl;

	if ( avst_result == NULLAV ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EINVALID, "avst_result == NULLAV", CNULL, 0, proc);
		return(- 1);
	}

	if (issuer) {
		for ( avseq = avst_result, found = 0 ; avseq ; avseq = avseq->avseq_next ) {
			quipu_cert_tmp = (struct certificate *)avseq->avseq_av.av_struct;
			if ( !dn_cmp(quipu_cert_tmp->issuer, quipu_issuer) && 
			    (serial == quipu_cert_tmp->serial) ) {    /*equal*/
				quipu_cert_found = quipu_cert_tmp;
				found = 1;
				break;
			}
		}  /*for*/
	} 
	else {
		for ( avseq = avst_result, found = 0 ; avseq ; avseq = avseq->avseq_next ) {
			quipu_cert_tmp = (struct certificate *)avseq->avseq_av.av_struct;
			if (serial == quipu_cert_tmp->serial) {
				if (!found) {
					quipu_cert_found = quipu_cert_tmp;
					found = 1;
				}
				else {
					ds_unbind();
					dn_free (read_arg.rda_object);
					aux_add_error(EOBJ, "More than one certificate with specified serial number", CNULL,
					    0, proc);
					return(- 1);
				}
			}
		}  /*for*/
	}

	if ( !found ) {
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(EOBJNAME, "Specified certificate does not exist in Your directory entry", CNULL, 0, proc);
		return(- 1);
	}

	emnew = em_alloc();
	if (!emnew) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "emnew", CNULL, 0, proc);
		return(- 1);
	}
	emnew->em_type = EM_REMOVEVALUES;
	av = AttrV_alloc();
	if (!av) {
		ds_unbind ();
		dn_free (read_arg.rda_object);
		aux_add_error(EMALLOC, "av", CNULL, 0, proc);
		return(- 1);
	}
	av->av_struct = (caddr_t) cert_cpy(quipu_cert_found);
	av->av_syntax = avst_result->avseq_av.av_syntax;
	avst_arg = avs_comp_new(av);
	emnew->em_what = as_comp_new(AttrT_cpy(at), avst_arg, acl);
	emnew->em_next = NULLMOD;
	mod_arg.mea_changes = NULLMOD;
	if ( emnew != NULLMOD )
		mod_arg.mea_changes = ems_append_local (mod_arg.mea_changes, emnew);

	mod_arg.mea_object = read_arg.rda_object;

	mod_arg.mea_common = ca;
	mod_arg.mea_common.ca_requestor = directory_user_dn;


#ifdef STRONG

	/****  S I G N  ModifyentryArgument  ****/

	if(auth_level == DBA_AUTH_STRONG){
		if(set_SecurityParameter() == NOTOK){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "set_SecurityParameter failed", CNULL, 0, proc);
			return(- 1);
		}
		mod_arg.mea_common.ca_security = ca_security;
		fprintf(stderr, "\n\n\n\n\n\n\n\n\n\n\n\n");
		mod_arg.mea_common.ca_sig = (dsap_security->serv_sign)((caddr_t)&mod_arg, _ZModifyEntryArgumentDataDAS);
		if(! mod_arg.mea_common.ca_sig){
			ds_unbind();
			dn_free (read_arg.rda_object);
			aux_add_error(EINVALID, "Cannot sign mod_arg", CNULL, 0, proc);
			return(- 1);
		}
	}
#endif


	if ( ds_modifyentry(&mod_arg, &mod_error) != DS_OK ) {
		fprintf(stderr, "\n");
		ds_error(rps, &mod_error);
		ds_unbind();
		dn_free (read_arg.rda_object);
		aux_add_error(set_error(mod_error), "ds_modifyentry failed", CNULL, 0, proc);
		return(- 1);
	}

	ems_part_free_local(mod_arg.mea_changes);

	ds_unbind();
	dn_free (read_arg.rda_object);

	return(0);
}

#endif



#ifdef AFDBFILE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include "af.h"

#ifdef MAC
#include <stdlib.h>
#include <string.h>
#endif /* MAC */

/* af_afdb_retrieve_Certificate(dname, ktype) : get 'dname's Certificate of type 'ktype' */

SET_OF_Certificate*
af_afdb_retrieve_Certificate(dname, ktype)
DName   * dname;
KeyType   ktype;
{
	SET_OF_Certificate  * ret = (SET_OF_Certificate *)0;
	char	              certfile[256];
	char	            * certdir;
	OctetString         * loaded;
	Certificate         * cert = (Certificate *)0;
	Name                * name;
	Boolean		      onekeypaironly = FALSE;

	char	            * proc = "af_afdb_retrieve_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!dname || (ktype != SIGNATURE && ktype != ENCRYPTION)){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return ( (SET_OF_Certificate *) 0);
	}

	name = aux_DName2CAPITALName(dname);
	if (!name)	
		return ( (SET_OF_Certificate *) 0);

	strcpy(certfile, AFDBFILE);       /* file = .af-db/ */
	strcat(certfile, name);           /* file = .af-db/'name' */

	certdir = certfile + strlen(certfile);
	*certdir = '/';
	certdir[1] = '\0';               /* file = .af-db/'name'/ */

	strcat(certfile, Cert_name);

	loaded = aux_file2OctetString(certfile);
	if (loaded) {    
		cert = d_Certificate(loaded);
		aux_free_OctetString(&loaded);
	}
	else {
		certfile[strlen(certfile) - 4] = '\0';
		if(ktype == SIGNATURE) 
			strcat(certfile, SignCert_name);
		else strcat(certfile, EncCert_name);
		loaded = aux_file2OctetString(certfile);
		if (loaded) {    
			cert = d_Certificate(loaded);
			aux_free_OctetString(&loaded);
		}
	}

	if (! cert)
		return ret;

	if (!(ret = (SET_OF_Certificate * )malloc(sizeof(SET_OF_Certificate)))) {
		aux_add_error(EMALLOC, "ret" , CNULL, 0, proc);
		return ( (SET_OF_Certificate *) 0);
	}
	ret->next = (SET_OF_Certificate *) 0;
	ret->element = aux_cpy_Certificate(cert);
	aux_free_Certificate(&cert);

	return ret;
}


/* af_afdb_enter_Certificate(cert, ktype, replace) : store  Certificate in Directory
 * NOTE: only a single Certificate can be stored
 *       the name of the owner is used from the Certificate itself
 */

RC
af_afdb_enter_Certificate(cert, ktype, replace)
Certificate    * cert;
KeyType          ktype;
Boolean          replace;
{
	char	      certfile[256];
	char	    * certdir;
	OctetString * encoded;
	Name	    * name;
	int	      rc;
	Boolean       onekeypaironly = FALSE;
	char	    * proc = "af_afdb_enter_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (! cert || (ktype != SIGNATURE && ktype != ENCRYPTION && ktype)) {
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return(- 1);
	}

	encoded = e_Certificate(cert);
	if (!encoded)  {
		aux_add_error(EENCODE, "e_Certificate failed", cert, Certificate_n, proc);
		return(- 1);
	}
	name = aux_DName2CAPITALName(cert->tbs->subject);
	strcpy(certfile, AFDBFILE);       /* file = .af-db/ */
	strcat(certfile, name);           /* file = .af-db/'name' */

	if ((mkdir(certfile, 0755) < 0) && (errno != EEXIST)) {
		aux_add_error(ESYSTEM, "Name entry", CNULL, 0, proc);
		return(- 1);
	}

	certdir = certfile + strlen(certfile);
	*certdir = '/';
	certdir[1] = '\0';               /* file = .af-db/'name'/ */

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (- 1);
	}
	if(onekeypaironly == TRUE)
		strcat(certfile, Cert_name);
	else{
		if (ktype == ENCRYPTION) 
			strcat(certfile, EncCert_name);
		else
			strcat(certfile, SignCert_name);
	}

	if ((open(certfile, O_RDONLY) >= 0) && replace == FALSE){
		if(onekeypaironly == TRUE)
			aux_add_error(ECREATEOBJ, "You have already stored a certificate in your directory entry", CNULL, 0, proc);
		else
			aux_add_error(ECREATEOBJ, "There is a certificate of the appropriate keytype already stored in your directory entry", CNULL, 0, proc);
		return(- 1);
	}

	if ((rc = aux_OctetString2file(encoded, certfile, 2)) < 0) {
		aux_add_error(ESYSTEM, "can't write certificate into .af-db", certfile, char_n, proc);
	}
	aux_free_OctetString(&encoded);

	return rc;
}


RC
af_afdb_delete_Certificate(dname, ktype)
DName   * dname;
KeyType   ktype;
{
	char	      certfile[256];
	char	    * certdir;
	Name        * name;
	Boolean       onekeypaironly = FALSE;

	char	    * proc = "af_afdb_delete_Certificate";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname || (ktype != SIGNATURE && ktype != ENCRYPTION) ){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);      
		return(- 1);
	}

	name = aux_DName2CAPITALName(dname);
	if (!name)	
		return(- 1);

	strcpy(certfile, AFDBFILE);       /* file = .af-db/ */
	strcat(certfile, name);           /* file = .af-db/'name' */

	certdir = certfile + strlen(certfile);
	*certdir = '/';
	certdir[1] = '\0';               /* file = .af-db/'name'/ */

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		aux_add_error(LASTERROR, "af_check_if_onekeypaironly failed", CNULL, 0, proc);
		return (- 1);
	}
	if(onekeypaironly == TRUE)
		strcat(certfile, Cert_name);
	else{
		if (ktype == ENCRYPTION) 
			strcat(certfile, EncCert_name);
		else
			strcat(certfile, SignCert_name);
	}

	if ( open(certfile, O_RDONLY) < 0 ) {
		if (errno != ENOENT) 
			aux_add_error( EDAMAGE,  "can't open directory", certfile, char_n, proc);
		else 
			aux_add_error( EOBJNAME,  "specified object does not exist", certfile, char_n, proc);
		return(- 1);
	}

	unlink(certfile);

	return 0;
}


RC
af_afdb_enter_PemCrl(pemcrl)
PemCrl *pemcrl;
{
	char	      pemcrlfile[256];
	char	    * pemcrldir;
	OctetString * encoded;
	Name	    * name;
	int	      rc;
	char	    * proc = "af_afdb_enter_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!pemcrl){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return(- 1);
	}

	encoded = e_PemCrl(pemcrl);
	if (!encoded)  {
		aux_add_error(EENCODE, "e_PemCrl failed", pemcrl, PemCrl_n, proc);
		return(- 1);
	}

	name = aux_DName2CAPITALName(pemcrl->tbs->issuer);
	strcpy(pemcrlfile, AFDBFILE);       /* file = .af-db/ */
	strcat(pemcrlfile, name);           /* file = .af-db/'name' */

	if ((mkdir(pemcrlfile, 0755) < 0) && (errno != EEXIST)) {
		aux_add_error(ESYSTEM, "Name entry", CNULL, 0, proc);
		return(- 1);
	}

	pemcrldir = pemcrlfile + strlen(pemcrlfile);
	*pemcrldir = '/';
	pemcrldir[1] = '\0';               /* file = .af-db/'name'/ */
	strcat(pemcrlfile, "PemCRL");

	if ((rc = aux_OctetString2file(encoded, pemcrlfile, 2)) < 0) {
		aux_add_error(ESYSTEM, "can't write pemcrl into .af-db", pemcrlfile, char_n, proc);
	}
	aux_free_OctetString(&encoded);

	return rc;
}


PemCrl *af_afdb_retrieve_PemCrl(dname)
DName *dname;
{
	char	       pemcrlfile[256];
	char	     * pemcrldir;
	OctetString  * loaded;
	PemCrl   * ret;
	Name         * name;
	char	     * proc = "af_afdb_retrieve_PemCrl";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!dname){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return ( (PemCrl *) 0);
	}

	name = aux_DName2CAPITALName(dname);
	if (!name)	
		return ( (PemCrl *) 0);

	strcpy(pemcrlfile, AFDBFILE);       /* file = .af-db/ */
	strcat(pemcrlfile, name);           /* file = .af-db/'name' */

	pemcrldir = pemcrlfile + strlen(pemcrlfile);
	*pemcrldir = '/';
	pemcrldir[1] = '\0';               /* file = .af-db/'name'/ */
	strcat(pemcrlfile, "PemCRL");

	loaded = aux_file2OctetString(pemcrlfile);
	if (!loaded) 
		return ( (PemCrl *) 0);

	/* got pemcrl */
	ret = d_PemCrl(loaded);
	aux_free_OctetString(&loaded);
	if (!ret)  {
		aux_add_error(EDECODE, "d_PemCrl failed", CNULL, 0, proc);
		return ( (PemCrl *) 0);
	}

	return ret;
}


RC
af_afdb_enter_Crl()
{
	return(0);
}


Crl *af_afdb_retrieve_Crl()
{
	return((Crl *)0);
}


RC
af_afdb_enter_OCList()
{
	return(0);
}


OCList *af_afdb_retrieve_OCList()
{
	return((OCList *)0);
}


RC
af_afdb_enter_CertificatePair(cpair, dname)
CertificatePair *cpair;
DName *dname;
{
	char	                  cpairsetfile[256];
	char	                * cpairsetdir;
	SET_OF_CertificatePair  * cpairset, * cpairset_tmp;
	OctetString             * encoded, * loaded;
	Name	                * name;
	int	                  rc;
	char	                * proc = "af_afdb_enter_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!cpair){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);      
		return(- 1);
	}

	name = aux_DName2CAPITALName(dname);
	strcpy(cpairsetfile, AFDBFILE);       /* file = .af-db/ */
	strcat(cpairsetfile, name);           /* file = .af-db/'name' */

	if ((mkdir(cpairsetfile, 0755) < 0) && (errno != EEXIST)) {
		aux_add_error(ESYSTEM, "Name entry", CNULL, 0, proc);
		return(- 1);
	}

	cpairsetdir = cpairsetfile + strlen(cpairsetfile);
	*cpairsetdir = '/';
	cpairsetdir[1] = '\0';               /* file = .af-db/'name'/ */
	strcat(cpairsetfile, CrossCSet_name);

	if (open(cpairsetfile, O_RDONLY) < 0) {
		if (errno != ENOENT) {
			aux_add_error( EDAMAGE,  "can't open directory", cpairsetfile, char_n, proc);
			return(- 1);
		}
		else {
			if ( !(cpairset = (SET_OF_CertificatePair * )
					   malloc(sizeof(SET_OF_CertificatePair))) ) {
				aux_add_error(EMALLOC, "cpairset", CNULL, 0, proc);
				return(- 1);
			}
			cpairset->element = aux_cpy_CertificatePair(cpair);
			cpairset->next = (SET_OF_CertificatePair *) 0;
		}
	}
	else {
		loaded = aux_file2OctetString(cpairsetfile);
		if (!loaded) 
			return(- 1);

		/* got cpairset */
		cpairset = d_CertificatePairSet(loaded);
		aux_free_OctetString(&loaded);
		if (!cpairset)  {
			aux_add_error(EDECODE, "d_CertificatePairSet failed", CNULL, 0, proc);
			return(- 1);
		}
		if ( !(cpairset_tmp = (SET_OF_CertificatePair * )
					   malloc(sizeof(SET_OF_CertificatePair))) ) {
			aux_add_error(EMALLOC, "cpairset_tmp", CNULL, 0, proc);
			return(- 1);
		}
		cpairset_tmp->element = aux_cpy_CertificatePair(cpair);
		cpairset_tmp->next = cpairset;
		cpairset = cpairset_tmp;
	}	

	encoded = e_CertificatePairSet(cpairset);
	if (!encoded)  {
		aux_add_error(EENCODE, "e_CertificatePairSet failed", cpairset, SET_OF_CertificatePair_n, proc);
		return(- 1);
	}

	if ((rc = aux_OctetString2file(encoded, cpairsetfile, 2)) < 0) {
		aux_add_error(ESYSTEM, "can't write cpairset into .af-db", cpairsetfile, char_n, proc);
	}
	aux_free_OctetString(&encoded);

	return rc;
}


SET_OF_CertificatePair *af_afdb_retrieve_CertificatePair(dname)
DName *dname;
{
	char	                 cpairsetfile[256];
	char	               * cpairsetdir;
	OctetString            * loaded;
	SET_OF_CertificatePair * ret;
	Name		       * name;
	char	               * proc = "af_afdb_retrieve_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if (!dname){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return ( (SET_OF_CertificatePair *) 0);
	}

	name = aux_DName2CAPITALName(dname);
	if (!name)	
		return ( (SET_OF_CertificatePair *) 0);

	strcpy(cpairsetfile, AFDBFILE);       /* file = .af-db/ */
	strcat(cpairsetfile, name);           /* file = .af-db/'name' */

	cpairsetdir = cpairsetfile + strlen(cpairsetfile);
	*cpairsetdir = '/';
	cpairsetdir[1] = '\0';               /* file = .af-db/'name'/ */
	strcat(cpairsetfile, CrossCSet_name);

	loaded = aux_file2OctetString(cpairsetfile);
	if (!loaded) 
		return ( (SET_OF_CertificatePair *) 0);

	/* got cpairset */
	ret = d_CertificatePairSet(loaded);
	aux_free_OctetString(&loaded);
	if (!ret)  {
		aux_add_error(EDECODE, "d_CertificatePairSet failed", CNULL, 0, proc);
		return ( (SET_OF_CertificatePair *) 0);
	}

	return ret;
}

RC
af_afdb_delete_CertificatePair(dname, cpair)
DName * dname;
CertificatePair *cpair;
{
	char	                  cpairsetfile[256];
	char	                * cpairsetdir;
	SET_OF_CertificatePair  * cpairset, * np, * ahead_np;
	OctetString             * encoded, * loaded;
	Name	                * name;
	int	                  rc;
	char	                * proc = "af_afdb_delete_CertificatePair";

#ifdef TEST
	fprintf(stderr, "%s\n", proc);	
#endif

	if ( !dname || !cpair ){
		aux_add_error(EINVALID, "invalid parameter", CNULL, 0, proc);       
		return(- 1);
	}

	name = aux_DName2CAPITALName(dname);
	if (!name)	
		return(- 1);

	strcpy(cpairsetfile, AFDBFILE);       /* file = .af-db/ */
	strcat(cpairsetfile, name);           /* file = .af-db/'name' */

	cpairsetdir = cpairsetfile + strlen(cpairsetfile);
	*cpairsetdir = '/';
	cpairsetdir[1] = '\0';               /* file = .af-db/'name'/ */
	strcat(cpairsetfile, CrossCSet_name);

	loaded = aux_file2OctetString(cpairsetfile);
	if (!loaded) 
		return(- 1);

	/* got cpairset */
	cpairset = d_CertificatePairSet(loaded);
	aux_free_OctetString(&loaded);
	if (!cpairset)  {
		aux_add_error(EDECODE, "d_CertificatePairSet failed", CNULL, 0, proc);
		return(- 1);
	}

	for (np = cpairset, ahead_np = (SET_OF_CertificatePair *) 0; np; ahead_np = np, np = np->next) {
		if ( aux_cmp_CertificatePair(np->element, cpair) == 0 )
			break;
	}
	if (np) {      /* CertificatePair (to be deleted) found */
		if (!ahead_np) 
			cpairset = np->next;     /* firstelement */
		else 
			ahead_np->next = np->next;    /* not first */
		np->next = (SET_OF_CertificatePair *) 0;
		aux_free_CertificatePairSet(&np);

		if ( !cpairset )      /* last element deleted from cpairset */
			unlink(cpairsetfile);
		else {
			encoded = e_CertificatePairSet(cpairset);
			aux_free_CertificatePairSet(&cpairset);
			if (!encoded)  {
				aux_add_error(EENCODE, "e_CertificatePairSet failed", cpairset, SET_OF_CertificatePair_n, proc);
				return(- 1);
			}

			if ((rc = aux_OctetString2file(encoded, cpairsetfile, 2)) < 0) {
				aux_add_error(ESYSTEM, "can't write cpairset into .af-db", cpairsetfile, char_n, proc);
				return(- 1);
			}
			aux_free_OctetString(&encoded);
		}
	} 
	else {      /* CertificatePair (to be deleted) not found */
		aux_free_CertificatePairSet(&cpairset);
		aux_add_error(EOBJNAME, "CertificatePair (to be deleted) not found", CNULL, 0, proc);
		return(- 1);
	}

	return 0;
}


#endif
