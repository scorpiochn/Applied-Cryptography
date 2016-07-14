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

#include "af.h"

/*----------------------------------------------------------------------------*/
/*     C A  s                                                                 */
/*----------------------------------------------------------------------------*/
   
#define DEF_CADIR               ".ca"         /* default CA directory         */
#define DEF_ISSUER_ALGID        md2WithRsaEncryption    /* default CA signature algid   */
#define DEF_SUBJECT_SIGNALGID   rsa           /* default CA encryption algid  */
#define DEF_SUBJECT_ENCRALGID   rsa           /* default CA encryption algid  */


#define CALOG	"calog"
#define	LOGFLAGS	"a+"

#define	LOGINIT		fprintf(logfile,"%s : INIT\n", logtime());
#define	LOGERR(msg)	fprintf(logfile,"%s : ERROR\t%s\n", logtime(), msg);
#define	LOGAFERR	fprintf(logfile,"%s : ERROR\t%s\n", logtime(), err_stack->e_text);
#define	LOGSECERR	fprintf(logfile,"%s : ERROR\t%s\n", logtime(), err_stack->e_text);
#define LOGUSER(N)	fprintf(logfile,"%s : NEW USER REGISTERED    <%s>\n", logtime(), N);
#define LOGCERT(C)	fprintf(logfile,"%s : CERTIFICATE ISSUED FOR <%s>\n                    SerialNo %u, Validity %s - %s\n",\
			logtime(), aux_DName2Name((C)->tbs->subject), (C)->tbs->serialnumber, \
                        aux_readable_UTCTime((C)->tbs->notbefore), aux_readable_UTCTime((C)->tbs->notafter));

#define LOGCERTSIGN(C)	fprintf(logfile,"%s : SIGN CERTIFICATE ISSUED FOR <%s>\n                    SerialNo %u, Validity %s - %s\n",\
			logtime(), aux_DName2Name((C)->tbs->subject), (C)->tbs->serialnumber, \
                        aux_readable_UTCTime((C)->tbs->notbefore), aux_readable_UTCTime((C)->tbs->notafter));

#define LOGCERTENCR(C)	fprintf(logfile,"%s : ENCR CERTIFICATE ISSUED FOR <%s>\n                    SerialNo %u, Validity %s - %s\n",\
			logtime(), aux_DName2Name((C)->tbs->subject), (C)->tbs->serialnumber, \
                        aux_readable_UTCTime((C)->tbs->notbefore), aux_readable_UTCTime((C)->tbs->notafter));

#define LOGPEMCRL(C)    fprintf(logfile,"%s : PemCrl ISSUED BY <%s>\n                    next update: %s\n",\
			logtime(), aux_DName2Name((C)->pemcrl->tbs->issuer), aux_readable_UTCTime((C)->pemcrl->tbs->nextUpdate));

char	*logtime();

# ifndef FILE
# include <stdio.h>
# endif
FILE    *logfile;

#define CAMAIL	 "camailaddr"
#define USERDB	 "user"
#define CERTDB	 "cert"
#define PEMCRLDB "pemcrlwithcerts"

#define MINKEYLEN 64
#define MAXKEYLEN 1024
#define DEFKEYLEN 512



/*-----------------------------------------------------------------------*/
/*     Definition of function types of KM  (if not int)                  */
/*-----------------------------------------------------------------------*/

SET_OF_IssuedCertificate    *af_cadb_get_user();

Certificate 		    *af_cadb_get_Certificate();
SET_OF_Name		    *af_cadb_list_user();

PemCrlWithCerts 	    *af_cadb_get_PemCrlWithCerts();
SET_OF_PemCrlWithCerts      *af_cadb_list_PemCrlWithCerts();
