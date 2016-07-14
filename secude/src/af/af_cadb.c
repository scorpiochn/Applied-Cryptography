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
	CA utilities

	af_cadb_add_Certificate, af_cadb_get_Certificate, 
	af_cadb_add_user, af_cadb_get_user, af_cadb_add_PemCrlWithCerts, af_cadb_list_PemCrlWithCerts,
	af_cadb_get_PemCrlWithCerts
	log CA events
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
/* #include <time.h> */
#include <errno.h>
#ifdef NDBM
#include <ndbm.h>
#else
#undef NULL
#include <dbm.h>
#endif

#include "cadb.h"

static char *conv_to_upper();

extern UTCTime *aux_current_UTCTime();


int
af_cadb_add_user(name, cadir)
Name	*name;
char    *cadir;
{
#ifdef NDBM
	DBM	 * user;
#endif
	datum	key, data;
	int	i, rc;
	DName   *dname;
	Name    *cname;
	char    *userdbpath;
	char    *homedir;
	char	*proc = "af_cadb_add_user";

	if (!cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return(-1);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		userdbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(USERDB)+3);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return (-1);
		}
		strcpy(userdbpath, homedir);
		strcat(userdbpath, "/");
		strcat(userdbpath, cadir);
	}
	else {
		userdbpath = (char *)malloc(strlen(cadir)+strlen(USERDB)+2);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return (-1);
		}
		strcpy(userdbpath, cadir);
	}
	if (userdbpath[strlen(userdbpath) - 1] != '/') strcat(userdbpath, "/");
	strcat(userdbpath, USERDB);

	/*	store subject user record */
#ifdef NDBM
	user = dbm_open(userdbpath, O_RDWR, 0);
	if (!user) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		free(userdbpath);
		return(-1);
	}
	free(userdbpath);
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, userdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, userdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(userdbpath) < 0)  {
			free(userdbpath);
 			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			return(-1);
		}
		free(userdbpath);


	}
#endif
	dname = aux_Name2DName(name);
	if(!dname) {
		aux_add_error(EINVALID, "wrong name", CNULL, 0, proc);
		return(-1);
	}		
	cname = aux_DName2CAPITALName(dname);
	aux_free_DName(&dname);
	key.dptr = cname;
	key.dsize = strlen(key.dptr);
	data.dptr = (char *)0;
	data.dsize = 0;
#ifdef NDBM
	rc = dbm_store(user, key, data, DBM_INSERT);
	if (rc < 0) {
		aux_add_error(EINVALID, "dbm_store failed", CNULL, 0, proc);
		free(cname);
		return(1);
	}

#else
	if (store(key, data) < 0) {
		aux_add_error(EINVALID, "store failed", CNULL, 0, proc);
		free(cname);
		return(1);
	}

#endif
	free(cname);
	if(rc == 0) LOGUSER(name);

#ifdef NDBM
	dbm_close(user);
#else
	dbmclose();
#endif

	return(0);
}


SET_OF_IssuedCertificate *
af_cadb_get_user(name, cadir)
Name	*name;
char	*cadir;
{
	SET_OF_IssuedCertificate *isscertset;
	OctetString 		 *ostr;
	char			 *userdbpath;
	char   			 *homedir;
	DName                    *dname;
	Name                     *cname;
	datum			  key, data;

	char			 *proc = "af_cadb_get_user";

#ifdef NDBM
	DBM	 * user;
#endif


	if (!cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return ((SET_OF_IssuedCertificate *)0);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		userdbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(USERDB)+3);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return ((SET_OF_IssuedCertificate *)0);
		}
		strcpy(userdbpath, homedir);
		strcat(userdbpath, "/");
		strcat(userdbpath, cadir);
	}
	else {
		userdbpath = (char *)malloc(strlen(cadir)+strlen(USERDB)+2);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return ((SET_OF_IssuedCertificate *)0);
		}
		strcpy(userdbpath, cadir);
	}
	if (userdbpath[strlen(userdbpath) - 1] != '/') strcat(userdbpath, "/");
	strcat(userdbpath, USERDB);


	/*	fetch subject user record */
#ifdef NDBM
	if (!name) {
		aux_add_error(EINVALID, "no name given", CNULL, 0, proc);
		free(userdbpath);
		return ((SET_OF_IssuedCertificate *)0);
	}
	user = dbm_open(userdbpath, O_RDONLY, 0);
	free(userdbpath);
	if (!user) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		return ((SET_OF_IssuedCertificate *)0);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, userdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, userdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(userdbpath) < 0) {
			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			return ((SET_OF_IssuedCertificate *)0);
		}
	}
#endif
	dname = aux_Name2DName(name);
	if(!dname) {
		aux_add_error(EINVALID, "wrong name", CNULL, 0, proc);
		return((SET_OF_IssuedCertificate *)0);
	}		
	cname = aux_DName2CAPITALName(dname);
	aux_free_DName(&dname);
	key.dptr = cname;
	key.dsize = strlen(key.dptr);
#ifdef NDBM
	data = dbm_fetch(user, key);
#else
	data = fetch(key);
#endif
	if (!data.dptr)	{
		aux_add_error(EINVALID, "(dbm_)fetch failed", CNULL, 0, proc);
		free(cname);
		return ((SET_OF_IssuedCertificate *)0);
	}
	ostr = (OctetString *) malloc(sizeof(OctetString));
	if( !ostr ) {
		aux_add_error(EMALLOC, "ostr", CNULL, 0, proc);
		return ((SET_OF_IssuedCertificate *)0);
	}
	free(cname);
	ostr->noctets = data.dsize;
	ostr->octets = data.dptr;
	isscertset = d_SET_OF_IssuedCertificate(ostr);
	free(ostr);
#ifdef NDBM
	dbm_close(user);
#else
	dbmclose();
#endif

	return (isscertset);
}


int
af_cadb_add_Certificate(keytype, newcert, cadir)
KeyType         keytype;
Certificate	*newcert;
char 		*cadir;
{
#ifdef NDBM
	DBM	 * user;
	DBM	 * cert;
#endif
	datum	key, data;
	OctetString * oct_cert;
	char	serialstr[12];
	SET_OF_IssuedCertificate *new_isscertset, *old_isscertset;
	OctetString *ostr;
	int	i, *p;
	char   *dbpath, *userdbpath, *certdbpath;
	char   *homedir, *username;

	char   *proc = "af_cadb_add_Certificate";


	if (!cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return (-1);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		dbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+3);
		if (!dbpath) {
			aux_add_error(EMALLOC, "dbpath", CNULL, 0, proc);
			return (-1);
		}
		strcpy(dbpath, homedir);
		strcat(dbpath, "/");
		strcat(dbpath, cadir);
	}
	else {
		dbpath = (char *)malloc(strlen(cadir)+2);
		if (!dbpath) {
			aux_add_error(EMALLOC, "dbpath", CNULL, 0, proc);
			return (-1);
		}
		strcpy(dbpath, cadir);
	}
	if (dbpath[strlen(dbpath) - 1] != '/') strcat(dbpath, "/");

	userdbpath = (char *)malloc(strlen(dbpath)+strlen(USERDB)+1);
	strcpy(userdbpath, dbpath);
	strcat(userdbpath, USERDB);
	certdbpath = (char *)malloc(strlen(dbpath)+strlen(CERTDB)+1);
	strcpy(certdbpath, dbpath);
	strcat(certdbpath, CERTDB);
	free(dbpath);

	/*	store new cert entry */
#ifdef NDBM
	cert = dbm_open(certdbpath, O_RDWR, 0);
	if (!cert) 	{
		aux_add_error(EINVALID, "dbm_open (cert) failed", CNULL, 0, proc);
		free(userdbpath);
		free(certdbpath);
		return(1);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, certdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, certdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(certdbpath) < 0) {
			aux_add_error(EINVALID, "dbminit (cert) failed", CNULL, 0, proc);
			free(userdbpath);
			free(certdbpath);
			return(1);
		}

	}
#endif
	oct_cert = e_Certificate(newcert);
	if (!oct_cert)  {
		aux_add_error(EENCODE, "e_Certificate failed", CNULL, 0, proc);
		free(userdbpath);
		free(certdbpath);
		return(1);
	}


	sprintf(serialstr, "%u", newcert->tbs->serialnumber);
	key.dptr = (char * )serialstr;
	key.dsize = strlen(serialstr);
	data.dptr = oct_cert->octets;
	data.dsize = oct_cert->noctets;
#ifdef NDBM
	if (dbm_store(cert, key, data, DBM_INSERT) < 0) {
		free(oct_cert);
		aux_add_error(EINVALID, "dbm_store (cert) failed", CNULL, 0, proc);
		free(userdbpath);
		free(certdbpath);
		return(1);
	}
#else
	if (store(key, data) < 0) {
		free(oct_cert);
		aux_add_error(EINVALID, "store (cert) failed", CNULL, 0, proc);
		free(userdbpath);
		free(certdbpath);
		return(1);
	}
#endif
	if(keytype == SIGNATURE) {
		LOGCERTSIGN(newcert);
	}
	else if(keytype == ENCRYPTION) {
		LOGCERTENCR(newcert);
	}
	else {
		LOGCERT(newcert);
	}
#ifdef NDBM
	dbm_close(cert);
#else
	dbmclose();
#endif
	free(certdbpath);
	free(oct_cert);

	/*	fetch subject user record */
#ifdef NDBM
	user = dbm_open(userdbpath, O_RDWR, 0);
	if (!user) {
		aux_add_error(EINVALID, "dbm_open (user) failed", CNULL, 0, proc);
		free(userdbpath);
		return(1);
	}

#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, userdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, userdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(userdbpath) < 0) {
			aux_add_error(EINVALID, "dbminit (user) failed", CNULL, 0, proc);
			free(userdbpath);
			return(1);
		}

	}
#endif

	new_isscertset = (SET_OF_IssuedCertificate *) malloc(sizeof(SET_OF_IssuedCertificate));
	if( !new_isscertset ) {
		aux_add_error(EMALLOC, "new_isscertset", CNULL, 0, proc);
		free(userdbpath);
		return (1);
	}
	new_isscertset->element = (IssuedCertificate *) malloc(sizeof(IssuedCertificate));
	if( !new_isscertset->element ) {
		aux_add_error(EMALLOC, "new_isscertset->element", CNULL, 0, proc);
		free(userdbpath);
		return (1);
	}

	new_isscertset->element->serial = newcert->tbs->serialnumber;
	new_isscertset->element->date_of_issue = aux_current_UTCTime();

        username = (char *)aux_DName2Name(newcert->tbs->subject);
	old_isscertset = af_cadb_get_user(username, cadir);

	if (!old_isscertset)   /* first entry for subject */
		new_isscertset->next = (SET_OF_IssuedCertificate *)0;	
	else 
		new_isscertset->next = old_isscertset;

	ostr = e_SET_OF_IssuedCertificate(new_isscertset);

	key.dptr = conv_to_upper(username);
	key.dsize = strlen(key.dptr);
	data.dptr = ostr->octets;
	data.dsize = ostr->noctets;

#ifdef NDBM
	if (dbm_store(user, key, data, DBM_REPLACE) < 0)  {
		aux_add_error(EINVALID, "dbm_store (user) failed", CNULL, 0, proc);
	        free(username);
	        free(ostr);
		free(new_isscertset->element->date_of_issue);
		free(new_isscertset->element);
		free(new_isscertset);
		return(1);
	}

	dbm_close(user);
#else
	if (store(key, data) < 0) {
		aux_add_error(EINVALID, "store (user) failed", CNULL, 0, proc);
	        free(username);
	        free(ostr);
		free(new_isscertset->element->date_of_issue);
		free(new_isscertset->element);
		free(new_isscertset);
		return(1);
	}
	dbmclose();
#endif
        free(username);
        free(ostr);
	free(new_isscertset->element->date_of_issue);
	free(new_isscertset->element);
	free(new_isscertset);
	return(0);
}


Certificate *
af_cadb_get_Certificate(serial, cadir)
int   serial;
char *cadir;
{
#ifdef NDBM
	DBM	    * cert;
#endif
	datum	      key, data;
	Certificate * certificate;
	OctetString * oct_cert;
	char	      serialstr[12];
	char        * certdbpath;
	char        * homedir;

	char   	    * proc = "af_cadb_get_Certificate";

	if (!cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return ((Certificate *)0);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		certdbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(CERTDB)+3);
		if (!certdbpath) {
			aux_add_error(EMALLOC, "certdbpath", CNULL, 0, proc);
			return ((Certificate *)0);
		}
		strcpy(certdbpath, homedir);
		strcat(certdbpath, "/");
		strcat(certdbpath, cadir);
	}
	else {
		certdbpath = (char *)malloc(strlen(cadir)+strlen(CERTDB)+2);
		if (!certdbpath) {
			aux_add_error(EMALLOC, "certdbpath", CNULL, 0, proc);
			return ((Certificate *)0);
		}
		strcpy(certdbpath, cadir);
	}
	if (certdbpath[strlen(certdbpath) - 1] != '/') strcat(certdbpath, "/");
	strcat(certdbpath, CERTDB);

#ifdef NDBM
	cert = dbm_open(certdbpath, O_RDONLY, 0);
	if (!cert) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		free(certdbpath);
		return ((Certificate *)0);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, certdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, certdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(certdbpath) < 0) {
			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			free(certdbpath);
			return ((Certificate *)0);
		}

	}
#endif
	free(certdbpath);
	sprintf(serialstr, "%u", serial);
	key.dptr = (char * )serialstr;
	key.dsize = strlen(serialstr);

#ifdef NDBM
	data = dbm_fetch(cert, key);
#else
	data = fetch(key);
#endif
	if (!data.dptr)	 {
		aux_add_error(EINVALID, "(dbm_)fetch failed", CNULL, 0, proc);
		return ((Certificate *)0);
	}

	oct_cert = (OctetString *) malloc(sizeof(OctetString));
	if( !oct_cert ) {
		aux_add_error(EMALLOC, "oct_cert", CNULL, 0, proc);
		return ((Certificate *)0);
	}
	oct_cert->noctets = data.dsize;
	oct_cert->octets = data.dptr;
	certificate = d_Certificate(oct_cert);
	free(oct_cert);
#ifdef NDBM
	dbm_close(cert);
#else
	dbmclose();
#endif

	return (certificate);
}


SET_OF_Name *
af_cadb_list_user(cadir)
char *cadir;
{
#ifdef NDBM
	DBM	    * user;
#endif
	datum	      key;
	SET_OF_Name * nameset, * tmp_nameset;
	char 	    * userdbpath;
	char        * homedir;

	char        * proc = "af_cadb_list_user";


	if (!cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return ((SET_OF_Name *)0);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		userdbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(USERDB)+3);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return ((SET_OF_Name *)0);
		}
		strcpy(userdbpath, homedir);
		strcat(userdbpath, "/");
		strcat(userdbpath, cadir);
	}
	else {
		userdbpath = (char *)malloc(strlen(cadir)+strlen(USERDB)+2);
		if (!userdbpath) {
			aux_add_error(EMALLOC, "userdbpath", CNULL, 0, proc);
			return ((SET_OF_Name *)0);
		}
		strcpy(userdbpath, cadir);
	}
	if (userdbpath[strlen(userdbpath) - 1] != '/') strcat(userdbpath, "/");
	strcat(userdbpath, USERDB);

#ifdef NDBM
	user = dbm_open(userdbpath, O_RDONLY, 0);
	if (!user) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		free(userdbpath);
		return ((SET_OF_Name *)0);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, userdbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, userdbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(userdbpath) < 0) {
			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			free(userdbpath);
			return ((SET_OF_Name *)0);
		}

	}
#endif
	free(userdbpath);
	nameset = tmp_nameset = (SET_OF_Name *) malloc(sizeof(SET_OF_Name));
	if( !tmp_nameset ) {
		aux_add_error(EMALLOC, "tmp_nameset", CNULL, 0, proc);
		return ((SET_OF_Name *)0);
	}

#ifdef NDBM
	key = dbm_firstkey(user);
#else
	key = dbm_firstkey();
#endif

	if (!key.dptr) {
		free(nameset);
		return ((SET_OF_Name *)0);
	}

	tmp_nameset->element = malloc(key.dsize + 1);
	if( !tmp_nameset->element ) {
		aux_add_error(EMALLOC, "tmp_nameset->element", CNULL, 0, proc);
		return ((SET_OF_Name *)0);
	}
	bcopy(key.dptr, conv_to_upper(tmp_nameset->element), key.dsize);
	*(tmp_nameset->element + key.dsize) = '\0';
	tmp_nameset->next = (SET_OF_Name *)0;

#ifdef NDBM
	key = dbm_nextkey(user);
#else
	key = dbm_nextkey();
#endif

	while (key.dptr != CNULL) {
		tmp_nameset->next = (SET_OF_Name *) malloc(sizeof(SET_OF_Name));
		if( !tmp_nameset->next ) {
			aux_add_error(EMALLOC, "tmp_nameset->next", CNULL, 0, proc);
			return ((SET_OF_Name *)0);
		}
		tmp_nameset = tmp_nameset->next;
		tmp_nameset->element = malloc(key.dsize + 1);
		if( !tmp_nameset->element ) {
			aux_add_error(EMALLOC, "tmp_nameset->element", CNULL, 0, proc);
			return ((SET_OF_Name *)0);
		}
		bcopy(key.dptr, conv_to_upper(tmp_nameset->element), key.dsize);
		*(tmp_nameset->element + key.dsize) = '\0';
		tmp_nameset->next = (SET_OF_Name *)0;

#ifdef NDBM
		key = dbm_nextkey(user);
#else
		key = dbm_nextkey();
#endif
	}

#ifdef NDBM
	dbm_close(user);
#else
	dbmclose();
#endif

	return (nameset);
}


char*	logtime()
{
	static char	tbuf[20];
	struct tm *now;
	time_t	intnow;

	intnow = time(0);
	now = localtime(&intnow);
	sprintf(tbuf, "%02d/%02d/%02d %02d:%02d:%02d",
	    now->tm_mon + 1,
	    now->tm_mday,
	    now->tm_year,
	    now->tm_hour,
	    now->tm_min,
	    now->tm_sec);

	return tbuf;
}

static char *conv_to_upper(c)
char *c;
{
        register char *cc = c;
        while(*cc) {
                if(*cc >= 'a' && *cc <= 'z') *cc -= 32;
                cc++;
        }
        return(c);
}


int
af_cadb_add_PemCrlWithCerts(pemcrlwithcerts, cadir)
PemCrlWithCerts	* pemcrlwithcerts;
char 	        * cadir;
{
#ifdef NDBM
	DBM	    * pemcrl;
#endif
	datum	      key, data;
	OctetString * oct_pemcrlwithcerts;
	int	      i, * p, rc;
	char        * dbpath, * pemcrldbpath, * homedir, * username;

	char        * proc = "af_cadb_add_PemCrlWithCerts";


	if (! cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return (-1);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		dbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+3);
		if (!dbpath) {
			aux_add_error(EMALLOC, "dbpath", CNULL, 0, proc);
			return (- 1);
		}
		strcpy(dbpath, homedir);
		strcat(dbpath, "/");
		strcat(dbpath, cadir);
	}
	else {
		dbpath = (char *)malloc(strlen(cadir)+2);
		if (!dbpath) {
			aux_add_error(EMALLOC, "dbpath", CNULL, 0, proc);
			return (- 1);
		}
		strcpy(dbpath, cadir);
	}
	if (dbpath[strlen(dbpath) - 1] != '/') strcat(dbpath, "/");

	pemcrldbpath = (char *)malloc(strlen(dbpath)+strlen(PEMCRLDB)+1);
	strcpy(pemcrldbpath, dbpath);
	strcat(pemcrldbpath, PEMCRLDB);
	free(dbpath);

	/*	store new pemcrl entry */
#ifdef NDBM
	pemcrl = dbm_open(pemcrldbpath, O_RDWR, 0);
	if (! pemcrl){
		aux_add_error(EINVALID, "dbm_open (pemcrl) failed", CNULL, 0, proc);
		free(pemcrldbpath);
		return(1);
	}
#else
	 {
		FILE  * fd;
		char	fn[64];

		strcpy(fn, pemcrldbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, pemcrldbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(pemcrldbpath) < 0) {
			aux_add_error(EINVALID, "dbminit (pemcrl) failed", CNULL, 0, proc);
			free(pemcrldbpath);
			return(1);
		}

	}
#endif
	free(pemcrldbpath);

	oct_pemcrlwithcerts = e_PemCrlWithCerts(pemcrlwithcerts);
	if (! oct_pemcrlwithcerts)  {
		aux_add_error(EENCODE, "e_PemCrlWithCerts failed", CNULL, 0, proc);
		return(1);
	}

	username = (char *)aux_DName2Name(pemcrlwithcerts->pemcrl->tbs->issuer);
	if(! username){
		aux_add_error(EINVALID, "aux_DName2Name failed", CNULL, 0, proc);
		return(1);
	}

	key.dptr = conv_to_upper(username);
	key.dsize = strlen(key.dptr);
	data.dptr = oct_pemcrlwithcerts->octets;
	data.dsize = oct_pemcrlwithcerts->noctets;

#ifdef NDBM
	rc = dbm_store(pemcrl, key, data, DBM_INSERT);
	if (rc < 0) {
		free(oct_pemcrlwithcerts);
		aux_add_error(EINVALID, "dbm_store (pemcrl) failed", CNULL, 0, proc);
		return(1);
	}
	if (rc == 1){
		/* see manual:							*/
		/* All functions that return an int indicate errors with  nega- */
		/* tive  values.   A  zero return indicates no error.  Routines */
		/* that return a datum indicate errors with a  NULL  (0)  dptr. */
		/* If  dbm_store  called with a flags value of DBM_INSERT finds */
		/* an existing entry with the same key it returns 1.     	*/

		rc = dbm_store(pemcrl, key, data, DBM_REPLACE);
		if (rc < 0) {
			free(oct_pemcrlwithcerts);
			aux_add_error(EINVALID, "dbm_store (pemcrl) failed", CNULL, 0, proc);
			return(1);
		}
	}
#else
	if (store(key, data) < 0) {
		free(oct_pemcrlwithcerts);
		aux_add_error(EINVALID, "store (pemcrl) failed", CNULL, 0, proc);
		return(1);
	}
#endif
	LOGPEMCRL(pemcrlwithcerts);

#ifdef NDBM
	dbm_close(pemcrl);
#else
	dbmclose();
#endif
	free(oct_pemcrlwithcerts);


	return(0);
}



SET_OF_PemCrlWithCerts *
af_cadb_list_PemCrlWithCerts(cadir)
char * cadir;
{
#ifdef NDBM
	DBM	               * pemcrl;
#endif
	SET_OF_PemCrlWithCerts * set, * tmp_set;
	char 	               * pemcrldbpath, * homedir;
	datum	                 key, data;
	OctetString	       * ostr;

	char                   * proc = "af_cadb_list_PemCrlWithCerts";


	if (! cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return ((SET_OF_PemCrlWithCerts *)0);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		pemcrldbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(PEMCRLDB)+3);
		if (!pemcrldbpath) {
			aux_add_error(EMALLOC, "pemcrldbpath", CNULL, 0, proc);
			return ((SET_OF_PemCrlWithCerts *)0);
		}
		strcpy(pemcrldbpath, homedir);
		strcat(pemcrldbpath, "/");
		strcat(pemcrldbpath, cadir);
	}
	else {
		pemcrldbpath = (char *)malloc(strlen(cadir)+strlen(PEMCRLDB)+2);
		if (!pemcrldbpath) {
			aux_add_error(EMALLOC, "pemcrldbpath", CNULL, 0, proc);
			return ((SET_OF_PemCrlWithCerts *)0);
		}
		strcpy(pemcrldbpath, cadir);
	}
	if (pemcrldbpath[strlen(pemcrldbpath) - 1] != '/') strcat(pemcrldbpath, "/");
	strcat(pemcrldbpath, PEMCRLDB);

#ifdef NDBM
	pemcrl = dbm_open(pemcrldbpath, O_RDONLY, 0);
	if (!pemcrl) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		free(pemcrldbpath);
		return ((SET_OF_PemCrlWithCerts *)0);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, pemcrldbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, pemcrldbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(pemcrldbpath) < 0) {
			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			free(pemcrldbpath);
			return ((SET_OF_PemCrlWithCerts *)0);
		}

	}
#endif
	free(pemcrldbpath);
	set = tmp_set = (SET_OF_PemCrlWithCerts * )malloc(sizeof(SET_OF_PemCrlWithCerts));
	if(! tmp_set) {
		aux_add_error(EMALLOC, "tmp_set", CNULL, 0, proc);
		return ((SET_OF_PemCrlWithCerts *)0);
	}

#ifdef NDBM
	key = dbm_firstkey(pemcrl);
#else
	key = dbm_firstkey();
#endif

	if (! key.dptr){
		aux_free_SET_OF_PemCrlWithCerts(&set);
		return ((SET_OF_PemCrlWithCerts * )0);
	}

#ifdef NDBM
	data = dbm_fetch(pemcrl, key);
#else
	data = fetch(key);
#endif
	if (! data.dptr){
		aux_add_error(EINVALID, "(dbm_)fetch failed", CNULL, 0, proc);
		return ((SET_OF_PemCrlWithCerts *)0);
	}
	ostr = (OctetString * )malloc(sizeof(OctetString));
	if(! ostr){
		aux_add_error(EMALLOC, "ostr", CNULL, 0, proc);
		return ((SET_OF_PemCrlWithCerts *)0);
	}
	ostr->noctets = data.dsize;
	ostr->octets = data.dptr;
	tmp_set->element = d_PemCrlWithCerts(ostr);
	free(ostr);
	if(! tmp_set->element){
		aux_add_error(EDECODE, "d_PemCrlWithCerts failed", CNULL, 0, proc);
		aux_free_SET_OF_PemCrlWithCerts(&set);
		return ((SET_OF_PemCrlWithCerts *)0);
	}
	tmp_set->next = (SET_OF_PemCrlWithCerts *)0;

#ifdef NDBM
	key = dbm_nextkey(pemcrl);
#else
	key = dbm_nextkey();
#endif

	while (key.dptr != CNULL) {
#ifdef NDBM
		data = dbm_fetch(pemcrl, key);
#else
		data = fetch(key);
#endif
		tmp_set->next = (SET_OF_PemCrlWithCerts *) malloc(sizeof(SET_OF_PemCrlWithCerts));
		if(! tmp_set->next){
			aux_add_error(EMALLOC, "tmp_set->next", CNULL, 0, proc);
			return ((SET_OF_PemCrlWithCerts * )0);
		}
		tmp_set = tmp_set->next;
		ostr = (OctetString * )malloc(sizeof(OctetString));
		if(! ostr){
			aux_add_error(EMALLOC, "ostr", CNULL, 0, proc);
			return ((SET_OF_PemCrlWithCerts *)0);
		}
		ostr->noctets = data.dsize;
		ostr->octets = data.dptr;
		tmp_set->element = d_PemCrlWithCerts(ostr);
		free(ostr);
		if(! tmp_set->element){
			aux_add_error(EDECODE, "d_PemCrlWithCerts failed", CNULL, 0, proc);
			aux_free_SET_OF_PemCrlWithCerts(&set);
			return ((SET_OF_PemCrlWithCerts *)0);
		}
		tmp_set->next = (SET_OF_PemCrlWithCerts *)0;

#ifdef NDBM
		key = dbm_nextkey(pemcrl);
#else
		key = dbm_nextkey();
#endif
	}

#ifdef NDBM
	dbm_close(pemcrl);
#else
	dbmclose();
#endif

	return (set);
}


PemCrlWithCerts *
af_cadb_get_PemCrlWithCerts(name, cadir)
Name	* name;
char	* cadir;
{
#ifdef NDBM
	DBM	             * pemcrl;
#endif
	PemCrlWithCerts      * pemcrlwithcerts;
	OctetString          * ostr;
	char	             * pemcrldbpath;
	char   		     * homedir;
	DName		     * dname;
	Name                 * cname;
	datum		       key, data;

	char		     * proc = "af_cadb_get_PemCrlWithCerts";


	if (! cadir) {
		aux_add_error(EINVALID, "No CA directory specified", CNULL, 0, proc);
		return ((PemCrlWithCerts *)0);
	}

	if(cadir[0] != '/') {
		homedir = getenv("HOME");
		pemcrldbpath = (char *)malloc(strlen(homedir)+strlen(cadir)+strlen(PEMCRLDB)+3);
		if (!pemcrldbpath) {
			aux_add_error(EMALLOC, "pemcrldbpath", CNULL, 0, proc);
			return ((PemCrlWithCerts *)0);
		}
		strcpy(pemcrldbpath, homedir);
		strcat(pemcrldbpath, "/");
		strcat(pemcrldbpath, cadir);
	}
	else {
		pemcrldbpath = (char *)malloc(strlen(cadir)+strlen(PEMCRLDB)+2);
		if (!pemcrldbpath) {
			aux_add_error(EMALLOC, "pemcrldbpath", CNULL, 0, proc);
			return ((PemCrlWithCerts *)0);
		}
		strcpy(pemcrldbpath, cadir);
	}
	if (pemcrldbpath[strlen(pemcrldbpath) - 1] != '/') strcat(pemcrldbpath, "/");
	strcat(pemcrldbpath, PEMCRLDB);


	/*	fetch subject pemcrl record */
 
 	if (!name) dname = af_pse_get_Name();		
	else dname = aux_Name2DName(name);
	
	if(! dname) {
		aux_add_error(EINVALID, "cannot transform 'name' into 'dname'", CNULL, 0, proc);
		return((PemCrlWithCerts *)0);
	}		

#ifdef NDBM
	pemcrl = dbm_open(pemcrldbpath, O_RDONLY, 0);
	free(pemcrldbpath);
	if (! pemcrl) {
		aux_add_error(EINVALID, "dbm_open failed", CNULL, 0, proc);
		return ((PemCrlWithCerts *)0);
	}
#else
	 {
		FILE * fd;
		char	fn[64];
		strcpy(fn, pemcrldbpath);
		strcat(fn, ".pag");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		strcpy(fn, pemcrldbpath);
		strcat(fn, ".dir");
		fd = fopen(fn, "r");
		if (fd) fclose(fd);
		else {
			fd = fopen(fn, "w");
			fclose(fd);
		}
		if (dbminit(pemcrldbpath) < 0) {
			aux_add_error(EINVALID, "dbminit failed", CNULL, 0, proc);
			return ((PemCrlWithCerts *)0);
		}
	}
#endif
	dname = aux_Name2DName(name);
	if(! dname) {
		aux_add_error(EINVALID, "cannot transform 'name' into 'dname'", CNULL, 0, proc);
		return((PemCrlWithCerts *)0);
	}		
	cname = aux_DName2CAPITALName(dname);
	aux_free_DName(&dname);
	key.dptr = cname;
	key.dsize = strlen(key.dptr);
#ifdef NDBM
	data = dbm_fetch(pemcrl, key);
#else
	data = fetch(key);
#endif
	free(cname);

	if (! data.dptr){
		aux_add_error(EINVALID, "(dbm_)fetch failed", CNULL, 0, proc);
		return ((PemCrlWithCerts *)0);
	}
	ostr = (OctetString *) malloc(sizeof(OctetString));
	if(! ostr) {
		aux_add_error(EMALLOC, "ostr", CNULL, 0, proc);
		return ((PemCrlWithCerts *)0);
	}
	ostr->noctets = data.dsize;
	ostr->octets = data.dptr;
	pemcrlwithcerts = d_PemCrlWithCerts(ostr);
	free(ostr);
	if(! pemcrlwithcerts){
		aux_add_error(EDECODE, "d_PemCrlWithCerts failed", CNULL, 0, proc);
		return ((PemCrlWithCerts *)0);
	}
#ifdef NDBM
	dbm_close(pemcrl);
#else
	dbmclose();
#endif

	return (pemcrlwithcerts);
}
