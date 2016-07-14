/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   SCCOM                   VERSION 2.0            */
/*                                         DATE November 1991  */
/*                                           BY Levona Eckstein*/
/*    FILENAME                                                 */
/*      sccom.c                                                */
/*                                                             */
/*    DESCRIPTION                                              */
/*      SC  - Interface - Module                               */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*                                                             */
/*      sc_create               create SC-Request-Apdu         */
/*                                                             */
/*      sc_check                check  SC-Response-Apdu        */
/*                                                             */
/*      sc_enc                  encrypt SC-APDU                */
/*                                                             */
/*      sc_dec                  decrypt SC-APDU                */
/*                                                             */
/*      sc_crmac                create SC-APDU with MAC        */
/*                                                             */
/*      sc_checkmac             check SC-APDU with MAC         */
/*                                                             */
/*      e_KeyId                 create key identifier          */
/*                                                             */
/*      e_FileId                create file identifier         */
/*                                                             */
/*      e_KeyAttrList           create the key header          */
/*                                                             */
/*      sccom.h                                                */
/*                                                             */
/*      sc_errno                error-number                   */
/*                                                             */
/*      sc_errmsg               address of error message       */
/*                                                             */
/*                                                             */
/*    IMPORT                DESCRIPTION                        */
/*      sct_error             SCT-Error-Table                  */
/*                                                             */
/*      aux_fxdump        dump buffer in File              */
/*                                                             */
/*      sta_aux_sc_apdu       dump SC-APDU in file             */
/*                                                             */
/*      sta_aux_sc_resp       dump SC-RESP in file             */
/*                                                             */
/*      sta_aux_elemlen       eleminate length in resp. buffer */
/*                                                             */
/*    USES                  DESCRIPTION                        */
/*      sca.h                                                  */
/*                                                             */
/*      sctint.h                                               */
/*                                                             */
/*      sctloc.h                                               */
/*                                                             */
/*      sccom.h                                                */
/*                                                             */
/*      sctrc.h                                                */
/*                                                             */
/*      scloc.h                                                */
/*                                                             */
/*                                                             */
/*    INTERNAL              DESCRIPTION                        */
/*                                                             */
/*      e_FileTypeCat         create the parameter File Type / */
/*                            File Category                    */
/*          					               */
/*      e_OperationMode       create the Operation Mode Param. */
/*                      			               */
/*      e_TwoByte             create                           */
/*                            (HIGH/LOW-Byte) in sc_apdu       */
/*                                                             */
/*      Ioput                 transmit one byte in sc_apdu     */
/*                                                             */
/*      Ioputbuff             transmit string in sc_apdu       */
/*                                                             */
/*      SCalloc               allocate buffer                  */
/*                                                             */
/*      SCchecklen            check length of parameter        */
/*                                                             */
/*    Wichtig !!!!!:                                           */
/*    Es muessen noch die Funktionen sc_e_secure und           */
/*    sc_d_secure (fuer secure messaging) bereitgestellt werden*/
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/
#include <stdio.h>
#include <memory.h>
#include "sca.h"
#include "sctint.h"
#include "sctloc.h"
#include "sccom.h"
#include "sctrc.h"
#include "scloc.h"

/*-------------------------------------------------------------*/
/*   extern declarations                                       */
/*-------------------------------------------------------------*/
extern SCTerror sct_error[TABLEN];	/* message table */

extern void     aux_fxdump();
extern int      sta_aux_sc_apdu();
extern void     sta_aux_sc_resp();
extern void     sta_aux_elemlen();
extern void     sta_aux_bytestr_free();
extern void     aux_free2_OctetString();
extern void     aux_free2_BitString();
extern int      des_encrypt();
extern int      des_decrypt();

/*-------------------------------------------------------------*/
/*   forward global declarations                               */
/*-------------------------------------------------------------*/
int             sc_create();
int             sc_check();
int             sc_enc();
int             sc_dec();
int             sc_crmac();
int             sc_checkmac();
char            e_KeyId();
char            e_FileId();
void            e_KeyAttrList();

/*-------------------------------------------------------------*/
/*   forward local  declarations                               */
/*-------------------------------------------------------------*/
static char     e_FileTypeCat();
static char     e_OperationMode();
static void     e_TwoByte();
static void     Ioput();
static void     Ioputbuff();
static char    *SCalloc();
static int      SCchecklen();



/*-------------------------------------------------------------*/
/*   global  variable definitions                              */
/*-------------------------------------------------------------*/
unsigned int    sc_errno;	/* error variable               */
char           *sc_errmsg;	/* address of error message */

/*-------------------------------------------------------------*/
/*   local  Variable definitions                               */
/*-------------------------------------------------------------*/

#ifdef STREAM
static BOOL     first = FALSE;	/* FLAG, if Trace-File open     */

#endif

#ifdef STREAM
FILE           *sc_trfp;	/* Filepointer of trace file    */

#endif



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_create           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create SC-Command                                     */
/*  This procedure allocates the buffer for the           */
/*  SC-Command and generates the SC-APDU.                 */
/*  If sec_mode = TRUE, then the SSC will be set in the   */
/*  APDU.						  */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sc_cmd                    SC-Command-Structure       */
/*                                                        */
/*   sec_mode  		       Flag, if secure messaging  */
/*							  */
/*   ssc		       Send Sequence Counter      */
/*			       only used in case of       */
/*			       sec_mode = TRUE            */
/* OUT                                                    */
/*   sc_apdu                   Pointer of SC-Command-APDU */
/*			       Construction:              */
/*			       ______________________     */
/*			      | CLA,INS,P1,P2,L,DATA |    */
/*			       ______________________     */
/*			       or:			  */
/*			       __________________________ */
/*			      | CLA,INS,P1,P2,L,SSC,DATA |*/
/*			       __________________________ */
/*			      The memory for sc_apdu->bytes*/
/*			      will be allocated by this   */
/*			      programm and must be set    */
/*			      free by the calling program */
/*			      only in case of no error    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*			        EPARINC                   */
/*                              ETOOLONG		  */
/*				EMEMAVAIL		  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   e_KeyId                                              */
/*   e_FileId                                             */
/*   e_FileTypeCat                                        */
/*   e_OperationMode                                      */
/*   e_TwoByte                                            */
/*   Ioput                                                */
/*   Ioputbuff                                            */
/*   SCalloc                                              */
/*   SCchecklen                                           */
/*   sta_aux_sc_apdu                                      */
/*--------------------------------------------------------*/
int
sc_create(sc_cmd, sec_mode, ssc, sc_apdu)
	struct s_command *sc_cmd;	/* SC-Command    */
	Boolean         sec_mode;
	int             ssc;
	Bytestring     *sc_apdu;/* Structure of SC-APDU       */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *scapdu = NULL;
	unsigned int    lscapdu = HEADLEN;
	char           *ptr = NULL;
	char            oldpin[9];
	char            newpin[9];
	char            file_type_cat;
	char            finfolen;
	char            kid_1;
	char            kid_2;
	char            fid;
	unsigned int    len = 0;
	unsigned int    class;
	unsigned int    i;
	char            op_mode;
	int             ssc_len;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	sc_apdu->nbytes = 0;
	sc_apdu->bytes = NULL;

#ifdef STREAM
	if (!first) {
		sc_trfp = fopen("SCCOM.TRC", "wt");
		first = TRUE;
	};
#endif

	sc_errno = 0;

	if (sec_mode == TRUE) {
		ssc_len = 1;
		if (ssc != 0)
			ssc = ssc % 256;
	} else {
		ssc_len = 0;
	}

	lscapdu += ssc_len;

	switch (sc_cmd->sc_header.inscode) {
		/*--------------------------*/
		/* create SC_EXRND          */
		/*--------------------------*/
	case SC_EXRND:
		if (SCEXRND.di != ICC_TO_IFD) {
			if (SCEXRND.lrnd != RNDLEN) {
				sc_errno = ELENERR;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
			lscapdu += SCEXRND.lrnd;
		};
		len = RNDLEN;

		if ((SCEXRND.di < ICC_TO_IFD) || (SCEXRND.di > BOTH)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};


		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);

		ptr = scapdu + 2;
		Ioput(&ptr, (int) SCEXRND.di);
		Ioput(&ptr, SC_NOTUSED);
		Ioput(&ptr, len);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		if (SCEXRND.di != ICC_TO_IFD)
			Ioputbuff(&ptr, SCEXRND.rnd, SCEXRND.lrnd);

		break;

		/*--------------------------*/
		/* create SC_GET_CD         */
		/*--------------------------*/
	case SC_GET_CD:
		if (SCGETCD.cd_len > 8) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);

		ptr = scapdu + 2;
		Ioput(&ptr, SCGETCD.cd_len);
		Ioput(&ptr, SC_NOTUSED);
		Ioput(&ptr, SC_NOTUSED);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		break;
		/*--------------------------*/
		/* create SC_SETKEY         */
		/*--------------------------*/
	case SC_SETKEY:
		if ((kid_1 = e_KeyId(SCSETKEY.auth_kid)) == -1)
			return (-1);
		if ((kid_2 = e_KeyId(SCSETKEY.conc_kid)) == -1)
			return (-1);
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);

		ptr = scapdu + 2;
		Ioput(&ptr, kid_1);
		Ioput(&ptr, kid_2);
		Ioput(&ptr, SC_NOTUSED);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);


		break;

		/*--------------------------*/
		/* create SC_SELECT         */
		/*--------------------------*/
	case SC_SELECT:
		if ((SCSELECT.id > SF) ||
		    (SCSELECT.id < MF) ||
		    (SCSELECT.fi < NONE_INFO) ||
		    (SCSELECT.fi > SHORT_INFO) ||
		    (SCSELECT.fn == NULL) ||
		    (strlen(SCSELECT.fn) == 0)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		if (SCchecklen(strlen(SCSELECT.fn), MAX_FILENAME) == -1)
			return (-1);

		lscapdu += SCPLEN + strlen(SCSELECT.fn);

		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);

		ptr = scapdu + 2;

		Ioput(&ptr, (int) SCSELECT.id);
		Ioput(&ptr, (int) SCSELECT.fi);
		Ioput(&ptr, SCPLEN + strlen(SCSELECT.fn));
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, SCSELECT.scp);
		Ioputbuff(&ptr, SCSELECT.fn, strlen(SCSELECT.fn));

		break;

		/*--------------------------*/
		/* create SC_REGISTER       */
		/*--------------------------*/
	case SC_REGISTER:
		if ((SCREG.acv > 255) ||
		    (SCREG.fn == NULL) ||
		    (strlen(SCREG.fn) == 0) ||
		    (SCREG.units <= 0)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};

		if ((kid_1 = e_KeyId(SCREG.kid)) == -1)
			return (-1);

		if (SCchecklen(strlen(SCREG.fn), MAX_FILENAME))
			return (-1);
		lscapdu += KIDLEN + REGACVLEN + strlen(SCREG.fn);

		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		e_TwoByte(&ptr, SCREG.units);
		Ioput(&ptr, KIDLEN + REGACVLEN + strlen(SCREG.fn));
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, kid_1);
		Ioput(&ptr, SCREG.acv);
		Ioputbuff(&ptr, SCREG.fn, strlen(SCREG.fn));

		break;


		/*----------------------------*/
		/* create SC_READF            */
		/*----------------------------*/
	case SC_READF:
		if ((fid = e_FileId(SCREADF.fid)) == -1)
			return (-1);
		if ((SCREADF.data_sel->data_struc > TRANSPARENT) ||
		    (SCREADF.data_sel->data_struc < LIN_FIX) ||
		    ((SCREADF.data_sel->data_struc == LIN_FIX) &&
		   ((SCREADF.data_sel->data_ref.record_sel.record_id < 0) ||
		(SCREADF.data_sel->data_ref.record_sel.record_id > 255))) ||
		    ((SCREADF.data_sel->data_struc == LIN_VAR) &&
		   ((SCREADF.data_sel->data_ref.record_sel.record_id < 0) ||
		(SCREADF.data_sel->data_ref.record_sel.record_id > 254))) ||
		    (SCREADF.lrddata > MAXR_W_LEN)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};


		lscapdu += 2;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;

		switch (SCREADF.data_sel->data_struc) {
		case CYCLIC:
			Ioput(&ptr, SCREADF.data_sel->data_ref.element_sel.element_ref);
			Ioput(&ptr, SCREADF.data_sel->data_ref.element_sel.element_no);
			break;
		case TRANSPARENT:
			e_TwoByte(&ptr, SCREADF.data_sel->data_ref.string_sel);
			break;
		case LIN_FIX:
		case LIN_VAR:
			Ioput(&ptr, SCREADF.data_sel->data_ref.record_sel.record_id);
			Ioput(&ptr, SCREADF.data_sel->data_ref.record_sel.record_pos);
			break;
		};



		Ioput(&ptr, 0x02);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, fid);
		Ioput(&ptr, SCREADF.lrddata);
		break;

		/*----------------------------*/
		/* create SC_LOCKFILE         */
		/*----------------------------*/
	case SC_LOCKF:
		if ((fid = e_FileId(SCLOCKF.fid)) == -1)
			return (-1);
		lscapdu++;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, LOCK_CAT);
		Ioput(&ptr, SCLOCKF.co);
		Ioput(&ptr, FIDLEN);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, fid);
		break;

		/*----------------------------*/
		/* create SC_DELREC           */
		/*----------------------------*/
	case SC_DELREC:
		if ((SCDELREC.rid < 0) ||
		    (SCDELREC.rid > 255)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		if ((fid = e_FileId(SCDELREC.fid)) == -1)
			return (-1);
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, fid);
		Ioput(&ptr, SCDELREC.rid);
		Ioput(&ptr, SC_NOTUSED);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		break;

		/*----------------------------*/
		/* create SC_DELFILE          */
		/*----------------------------*/
	case SC_DELF:
		if (SCDELFILE.filecat > EF) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		if (SCDELFILE.filecat != EF) {
			if ((SCDELFILE.file_sel->file_name == NULL) ||
			    (strlen(SCDELFILE.file_sel->file_name) == 0)) {
				sc_errno = EPARINC;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
			if (SCchecklen(strlen(SCDELFILE.file_sel->file_name), MAX_FILENAME) == -1)
				return (-1);
			len = strlen(SCDELFILE.file_sel->file_name);
		} else {
			if ((fid = e_FileId(&SCDELFILE.file_sel->file_id)) == -1)
				return (-1);
			len = 1;
		}
		lscapdu += len;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;

		Ioput(&ptr, (int) SCDELFILE.filecat);
		Ioput(&ptr, SC_NOTUSED);
		Ioput(&ptr, len);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		if (SCDELFILE.filecat != EF)
			Ioputbuff(&ptr, SCDELFILE.file_sel->file_name, len);
		else
			Ioput(&ptr, fid);

		break;

		/*----------------------------*/
		/* create SC_CLOSE            */
		/*----------------------------*/
	case SC_CLOSE:
		if ((SCCLOSE.filecat > EF) ||
		    (SCCLOSE.filecat < MF) ||
		    (SCCLOSE.context > CLOSE_SELECT)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		if (SCCLOSE.filecat != EF) {
			if ((SCCLOSE.file_sel->file_name == NULL) ||
			    (strlen(SCCLOSE.file_sel->file_name) == 0)) {
				sc_errno = EPARINC;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
			if (SCchecklen(strlen(SCCLOSE.file_sel->file_name), MAX_FILENAME) == -1)
				return (-1);
			len = strlen(SCCLOSE.file_sel->file_name);
		} else {
			if ((fid = e_FileId(&SCCLOSE.file_sel->file_id)) == -1)
				return (-1);
			len = 1;
		}
		lscapdu += len;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;



		Ioput(&ptr, (int) SCCLOSE.filecat);
		Ioput(&ptr, (int) SCCLOSE.context);
		Ioput(&ptr, len);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		if (SCCLOSE.filecat != EF)
			Ioputbuff(&ptr, SCCLOSE.file_sel->file_name, len);
		else
			Ioput(&ptr, fid);
		break;


		/*----------------------------*/
		/* create SC_CHG_PIN          */
		/*----------------------------*/
	case SC_CHG_PIN:

		if ((SCCHGPIN.len_oldpin > PINLEN) ||
		    (SCCHGPIN.len_newpin > PINLEN)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};

		for (i = 0; i < 8; i++) {
			oldpin[i] = BLANK;
			newpin[i] = BLANK;
		}

		memcpy(oldpin, SCCHGPIN.old_pin, SCCHGPIN.len_oldpin);
		memcpy(newpin, SCCHGPIN.new_pin, SCCHGPIN.len_newpin);


		if ((kid_1 = e_KeyId(SCCHGPIN.kid)) == -1)
			return (-1);
		lscapdu += PINLEN * 2;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, (int) kid_1);
		Ioput(&ptr, (int) SC_NOTUSED);
		Ioput(&ptr, PINLEN * 2);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioputbuff(&ptr, oldpin, PINLEN);
		Ioputbuff(&ptr, newpin, PINLEN);
		break;


		/*----------------------------*/
		/* create SC_AUTH             */
		/*----------------------------*/
	case SC_AUTH:

		if ((kid_1 = e_KeyId(SCAUTH.kid)) == -1)
			return (-1);
		lscapdu += SCAUTH.len_authd;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, kid_1);
		Ioput(&ptr, (int) SCAUTH.acp);
		Ioput(&ptr, SCAUTH.len_authd);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioputbuff(&ptr, SCAUTH.authd, SCAUTH.len_authd);
		break;








		/*--------------------------*/
		/* create SC_CREATE         */
		/*--------------------------*/
	case SC_CREATE:
		if ((SCCREATE.filecat > EF) ||
		    (SCCREATE.filecat < MF) ||

		    (SCCREATE.filecontrolinfo->units <= 0) ||


		    ((SCCREATE.filecat == EF) &&
		     (SCCREATE.filetype > ISF)) ||

		    ((SCCREATE.filecat == EF) &&
		     ((SCCREATE.datastruc > TRANSPARENT) ||
		      (SCCREATE.datastruc < LIN_FIX))) ||

		    ((SCCREATE.filecat == EF) &&
		     (SCCREATE.filetype == WEF) &&
		     (SCCREATE.filecontrolinfo->readwrite > WRITE_ONLY)) ||

		    ((SCCREATE.filecat == EF) &&
		((SCCREATE.filetype == ISF) || (SCCREATE.filetype == ACF)) &&
		     (SCCREATE.filecontrolinfo->readwrite != WRITE_ONLY)) ||

		    ((SCCREATE.filecat == EF) &&
		((SCCREATE.filetype == ISF) || (SCCREATE.filetype == ACF)) &&
		     (SCCREATE.filecontrolinfo->not_erasable == FALSE)) ||

		    ((SCCREATE.filecat == EF) &&
		     (SCCREATE.filetype == PEF) &&
		     (SCCREATE.filecontrolinfo->readwrite != READ_ONLY)) ||

		    ((SCCREATE.filecat == EF) &&
		     ((SCCREATE.datastruc == LIN_VAR) ||
		      (SCCREATE.datastruc == TRANSPARENT)) &&
		     (SCCREATE.filecontrolinfo->recordsize > 0)) ||

		    ((SCCREATE.filecat == EF) &&
		     ((SCCREATE.datastruc == LIN_FIX) ||
		      (SCCREATE.datastruc == CYCLIC)) &&
		     (SCCREATE.filecontrolinfo->recordsize <= 0)) ||

		    ((SCCREATE.filecat != EF) &&
		     (SCCREATE.filecontrolinfo->recordsize > 0))) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		}
		if (SCchecklen(SCCREATE.filecontrolinfo->addinfo.noctets,
			       MAX_ADDINFO))
			return (-1);


		if (SCCREATE.filecat != EF) {
			if ((SCCREATE.filecontrolinfo->file_sel.file_name == NULL) ||
			    (strlen(SCCREATE.filecontrolinfo->file_sel.file_name) == 0)) {
				sc_errno = EPARINC;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
			if (SCchecklen(strlen(SCCREATE.filecontrolinfo->file_sel.file_name),
				       MAX_FILENAME) == -1)
				return (-1);
			len = strlen(SCCREATE.filecontrolinfo->file_sel.file_name);


		} else {
			if (SCCREATE.filecontrolinfo->file_sel.file_id.file_type !=
			    SCCREATE.filetype) {
				sc_errno = EPARINC;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
			if ((fid = e_FileId(&SCCREATE.filecontrolinfo->file_sel.file_id)) == -1)
				return (-1);
			len = 1;
		}

		finfolen = UNITLEN + SCILEN + OPLEN + SIZELEN +
			len + 1 +
			SCCREATE.filecontrolinfo->addinfo.noctets + 1;

		lscapdu += finfolen;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;

		file_type_cat =
			e_FileTypeCat((int) SCCREATE.filetype, (int) SCCREATE.filecat);
		Ioput(&ptr, file_type_cat);
		if (SCCREATE.filecat == EF)
			Ioput(&ptr, (int) SCCREATE.datastruc);
		else
			Ioput(&ptr, SC_NOTUSED);

		Ioput(&ptr, finfolen);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		e_TwoByte(&ptr, SCCREATE.filecontrolinfo->units);
		Ioput(&ptr, SCCREATE.filecontrolinfo->racv);
		Ioput(&ptr, SCCREATE.filecontrolinfo->wacv);
		Ioput(&ptr, SCCREATE.filecontrolinfo->dacv);
		op_mode = e_OperationMode(SCCREATE.filecontrolinfo);

		Ioput(&ptr, op_mode);
		if (SCCREATE.filecat == EF)
			Ioput(&ptr, SCCREATE.filecontrolinfo->recordsize);
		else
			Ioput(&ptr, SC_NOTUSED);

		Ioput(&ptr, len);
		if (SCCREATE.filecat != EF)
			Ioputbuff(&ptr, SCCREATE.filecontrolinfo->file_sel.file_name, len);
		else
			Ioput(&ptr, fid);

		Ioput(&ptr, SCCREATE.filecontrolinfo->addinfo.noctets);
		Ioputbuff(&ptr, SCCREATE.filecontrolinfo->addinfo.octets,
			  SCCREATE.filecontrolinfo->addinfo.noctets);



		break;


		/*----------------------------*/
		/* create SC_WR_KEY           */
		/*----------------------------*/
	case SC_WR_KEY:
		if ((kid_1 = e_KeyId(SCWRKEY.kid)) == -1)
			return (-1);
		if ((SCWRKEY.key_len > KEYLEN) ||
		    (SCWRKEY.keyattrlist->key_inst_mode > REPL) ||
		    (SCWRKEY.keyattrlist->key_attr.key_presentation > KEY_LOCAL) ||
		 (SCWRKEY.keyattrlist->key_attr.key_op_mode > NO_REPLACE) ||
		    (SCWRKEY.keyattrlist->key_fpc > 255) ||
		 (SCWRKEY.keyattrlist->key_status.key_state > KEY_LOCKED)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};
		lscapdu += KEYHEAD + SCWRKEY.key_len + 1;	/* RFU-Byte */
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, kid_1);
		Ioput(&ptr, (int) SCWRKEY.keyattrlist->key_inst_mode);
		Ioput(&ptr, KEYHEAD + SCWRKEY.key_len + 1);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, SC_NOTUSED);
		e_KeyAttrList(&ptr, SCWRKEY.keyattrlist, SCWRKEY.key_algid);
		Ioput(&ptr, SCWRKEY.key_len);
		Ioputbuff(&ptr, SCWRKEY.key_body, SCWRKEY.key_len);

		break;


		/*----------------------------*/
		/* create SC_WRITEF           */
		/*----------------------------*/
	case SC_WRITEF:
		if ((fid = e_FileId(SCWRITEF.fid)) == -1)
			return (-1);

		if ((SCWRITEF.data_sel->data_struc > TRANSPARENT) ||
		    (SCWRITEF.data_sel->data_struc < LIN_FIX) ||
		    ((SCWRITEF.data_sel->data_struc == LIN_FIX) &&
		  ((SCWRITEF.data_sel->data_ref.record_sel.record_id < 0) ||
		(SCWRITEF.data_sel->data_ref.record_sel.record_id > 255))) ||
		    ((SCWRITEF.data_sel->data_struc == LIN_VAR) &&
		  ((SCWRITEF.data_sel->data_ref.record_sel.record_id < 0) ||
		(SCWRITEF.data_sel->data_ref.record_sel.record_id > 254))) ||
		    (SCWRITEF.lwrdata > MAXR_W_LEN)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};

		lscapdu += SCWRITEF.lwrdata + FIDLEN;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;

		switch (SCWRITEF.data_sel->data_struc) {
		case CYCLIC:
			Ioput(&ptr, SCWRITEF.data_sel->data_ref.element_sel.element_ref);
			Ioput(&ptr, SCWRITEF.data_sel->data_ref.element_sel.element_no);
			break;
		case TRANSPARENT:
			e_TwoByte(&ptr, SCWRITEF.data_sel->data_ref.string_sel);
			break;
		case LIN_FIX:
		case LIN_VAR:
			Ioput(&ptr, SCWRITEF.data_sel->data_ref.record_sel.record_id);
			Ioput(&ptr, SCWRITEF.data_sel->data_ref.record_sel.record_pos);
			break;
		};



		Ioput(&ptr, SCWRITEF.lwrdata + FIDLEN);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioput(&ptr, fid);
		Ioputbuff(&ptr, SCWRITEF.wrdata, SCWRITEF.lwrdata);
		break;


		/*----------------------------*/
		/* create SC_LOCKKEY          */
		/*----------------------------*/
	case SC_LOCKKEY:
		if ((kid_1 = e_KeyId(SCLOCKK.kid)) == -1)
			return (-1);
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, kid_1);
		Ioput(&ptr, SCLOCKK.operation);
		Ioput(&ptr, SC_NOTUSED);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);
		break;

		/*----------------------------*/
		/* create SC_CRYPT            */
		/*----------------------------*/
	case SC_CRYPT:
		if ((kid_1 = e_KeyId(SCCRYPT.kid)) == -1)
			return (-1);

		if ((SCCRYPT.modi > SC_MAC) ||
		    (SCCRYPT.modi < SC_ENC)) {
			sc_errno = EPARINC;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		};

		lscapdu += SCCRYPT.lcrdata;
		if ((scapdu = SCalloc(lscapdu)) == NULL)
			return (-1);
		ptr = scapdu + 2;
		Ioput(&ptr, kid_1);
		Ioput(&ptr, SCCRYPT.modi);
		Ioput(&ptr, SCCRYPT.lcrdata);
		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);

		Ioputbuff(&ptr, SCCRYPT.crdata, SCCRYPT.lcrdata);

		if (sec_mode == TRUE)
			Ioput(&ptr, ssc);
		break;


		/*----------------------------*/
		/* DEFAULT                    */
		/*----------------------------*/
	default:
		sc_errno = ESCIN;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
		break;
	};




	/*------------------------------------*/
	/* create CLASS / INS       in s_apdu */
	/*------------------------------------*/
	class = SCHEAD.cmd_class;
	class |= (unsigned) SOURCE_DTE << 6;
	if (SCHEAD.security_mess.command != SEC_NORMAL)
		class |= (unsigned) SCHEAD.security_mess.command << 2;
	if (SCHEAD.security_mess.response != SEC_NORMAL)
		class |= (unsigned) SCHEAD.security_mess.response;

	*scapdu = class;
	*(scapdu + 1) = SCHEAD.inscode;


	/*------------------------------------*/
	/* print scapdu                       */
	/*------------------------------------*/

#ifdef STREAM
	sta_aux_sc_apdu(sc_trfp, scapdu, lscapdu);
#endif

	/*------------------------------------*/
	/* return sc_apdu                     */
	/*------------------------------------*/
	sc_apdu->nbytes = lscapdu;
	sc_apdu->bytes = scapdu;
	return (0);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_create              */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_check            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check  SC-Response (without Secure Messaging)         */
/*  The Response must have the structur:		  */
/*       ______________________                           */
/*      | L,DATA,SW1,SW2       |                          */
/*       ______________________                           */
/*  Check the SW1 / SW2 - Byte.                           */
/*  In case of O.K., sc_check remove the Length-field,    */
/*  the SW1 and the SW2 - field out of the response-buffer./

/*
    The response-buffer contains only the datafield
*/
/*  without SW1 / SW2.                                    */
/*  If SW1/SW2 indicates an error, sc_check      returns  */
/*  the value -1 and in sc_errno  the error number.       */
/*                                                        */
/*                                                        */
/*                                                        */
/* INOUT                     DESCRIPTION                  */
/*   sc_response               SC-Response-buffer         */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*                              sw/sw2 of SC response     */
/*							  */
/* CALLED FUNCTIONS					  */
/*  sta_aux_elemlen					  */
/*  sta_aux_bytestr_free				  */
/*  sta_aux_sc_resp					  */
/*--------------------------------------------------------*/
int
sc_check(sc_response)
	Bytestring     *sc_response;	/* Structure of SC-Response-Apdu */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    sw1;
	unsigned int    sw2;
	unsigned int    index = 0;
	unsigned int    listlen = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

#ifdef STREAM
	sta_aux_sc_resp(sc_trfp, sc_response->bytes, sc_response->nbytes);
#endif

	/*------------------------------------*/
	/* eleminate Length-field in Response */
	/*------------------------------------*/
	sta_aux_elemlen(sc_response);



	/*------------------------------------*/
	/* check SW1/SW2                      */
	/*------------------------------------*/
	sw1 = *(sc_response->bytes + (sc_response->nbytes - 2)) & 0xFF;
	sw2 = *(sc_response->bytes + (sc_response->nbytes - 1)) & 0xFF;
	/* delete sw1/sw2 in response-buffer */
	*(sc_response->bytes + (sc_response->nbytes - 2)) = 0x00;
	*(sc_response->bytes + (sc_response->nbytes - 1)) = 0x00;
	sc_response->nbytes -= 2;


	/*------------------------------------*/
	/* if sw1 indicates an error, then    */
	/* search in sct_error list sw1/sw2   */
	/* and return index in sc_errno  to   */
	/* calling procedure                  */
	/*------------------------------------*/

	if ((sw1 != OKSC) ||
	    ((sw1 == OKSC) && (sw2 == DATAINC))) {

		listlen = sizeof(sct_error) / sizeof(SCTerror);
		for (index = 0; index < listlen; index++) {

			if (sct_error[index].sw1 == sw1 && sct_error[index].sw2 == sw2) {
				sc_errno = index;
				sc_errmsg = sct_error[sc_errno].msg;
				return (-1);
			}
		}
		/* sw1 + sw2 not found */
		sc_errno = index - 1;	/* last element in error-list */
		sc_errmsg = sct_error[sc_errno].msg;
		sta_aux_bytestr_free(sc_response);
		return (-1);
	};

	return (0);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_check               */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_crmac            VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create SC-COMMAND-APDU  with MAC                      */
/*  This procedure can be called in case of               */
/*  secure messaging = AUTHENTIC.                         */
/*  In case of secure messaging=COMBINED, this procedure  */
/*  must be called before calling the procedure sc_enc.   */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   in_apdu		       Pointer of SC-APDU         */
/*                             The SC-APDU must have the  */
/*                             structur:                  */
/*			       __________________________ */
/*			      | CLA,INS,P1,P2,L,SSC,DATA |*/
/*			       __________________________ */
/*                            (= output of the procedure  */
/*				 sc_create)		  */
/*                                                        */
/*							  */
/*   algenc		       Encyption method		  */
/*							  */
/*   maclen		       Length of MAC (0 - 8)      */
/*			       In the current Version     */
/*  			       only 4 is allowed          */
/* OUT                                                    */
/*   out_apdu                  Pointer of SEC-APDU        */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*			       The APDU has the structure:*/
/*		           ______________________________ */
/*			  | CLA,INS,P1,P2,L,SSC,DATA,MAC |*/
/*		           ______________________________ */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESENC  		  */
/*				EMAC     		  */
/*				EALGO    		  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_encrypt                                          */
/*   aux_fxdump                                       */
/*   aux_free2_BitString                                  */
/*							  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
sc_crmac(sec_key, in_apdu, out_apdu, algenc, maclen)
	BitString      *sec_key;/* secure messaging key */
	Bytestring     *in_apdu;/* SC-APDU		 */
	Bytestring     *out_apdu;	/* SC-SEC-APDU		 */
	AlgEnc         algenc;	/* encryption method		 */
	int             maclen;	/* Length of MAC	 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     in_octets;
	char           *ptr, *mac_ptr;
	int             i;
	int             memolen;
	BitString       out_bits;
	KeyInfo         key_info;
	More            more;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	out_apdu->nbytes = 0;
	out_apdu->bytes = NULL;
	/* Test maclen) */
	if (maclen != 4) {
		sc_errno = EMAC;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
	in_octets.noctets = in_apdu->nbytes;
	in_octets.octets = in_apdu->bytes;


	/*---------------------------------------------------------*/
	/* encrypt data (CLA,INS,P1,P2,L,SSC,DATA)                 */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/

#ifdef STREAM
	fprintf(sc_trfp, "TRACE in sc_crmac\n");
	fprintf(sc_trfp, "   in_octets.noctets = %d\n", in_octets.noctets);
	fprintf(sc_trfp, "   in_octets.octets  = \n");
	aux_fxdump(sc_trfp, in_octets.octets, in_octets.noctets, 0);
#endif

	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		sc_errno = EALGO;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
		break;
	}
	more = END;

	/* allocate memory for out_bits  */
	/* the memory must be a multiple of 8 Bytes */
	if ((in_octets.noctets % 8) != 0)
		memolen = (in_octets.noctets - (in_octets.noctets % 8)) + 8;
	else
		memolen = in_octets.noctets;

	out_bits.nbits = 0;

#ifdef STREAM
	fprintf(sc_trfp, "   allocate out_bits = %d\n", memolen);
#endif

#ifdef MALLOC
	out_bits.bits = malloc(memolen);	/* will be set free in this
						 * proc. */
	if (out_bits.bits == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
#endif


	memolen = des_encrypt(&in_octets, &out_bits, more, &key_info);
	if (memolen == -1) {
		sc_errno = EDESENC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#ifdef STREAM
	fprintf(sc_trfp, "   out_bits.nbits    = %d\n", out_bits.nbits);
	fprintf(sc_trfp, "   out_bits.bits     = \n");
	aux_fxdump(sc_trfp, out_bits.bits, out_bits.nbits / 8, 0);
#endif

	memolen = in_octets.noctets + maclen;

#ifdef MALLOC
	out_apdu->bytes = malloc(memolen);	/* if no error => return;   */
	/* else will be set free in this proc. */
	if (out_apdu->bytes == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#endif

	out_apdu->nbytes = memolen;
	ptr = out_apdu->bytes;
	for (i = 0; i < in_octets.noctets; i++) {
		*ptr = *(in_octets.octets + i);
		ptr++;
	}

	/* if only 1 block encrypted => take the first 4 Bytes for MAC   */
	/* else take the last 4 bytes of the last block		       */

	if ((out_bits.nbits / 8) > 8)
		mac_ptr = out_bits.bits + ((out_bits.nbits / 8) - 8);
	else
		mac_ptr = out_bits.bits;

	for (i = 0; i < maclen; i++) {
		*ptr = *(mac_ptr + i);
		ptr++;
	};
	aux_free2_BitString(&out_bits);

#ifdef STREAM
	fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sc_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sc_trfp, "TRACE-END in sc_crmac\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_crmac               */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_enc              VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Encrypt SC-COMMAND-APDU (without CLA-Byte)            */
/*  This Procedure can be called in case of               */
/*  secure messaging = CONCEALED and in case of           */
/*  secure messaging = COMBINED after calling the         */
/*  procedure sc_crmac.

/*

*/
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   in_apdu		       Pointer of SC-APDU         */
/*                             The SC-APDU must have the  */
/*                             structur:                  */
/*			       __________________________ */
/*			      | CLA,INS,P1,P2,L,SSC,DATA |*/
/*			       __________________________ */
/*			      (= output of the procedure  */
/*				 sc_create)		  */
/*			       or			  */
/*		           ______________________________ */
/*			  | CLA,INS,P1,P2,L,SSC,DATA,MAC |*/
/*		           ______________________________ */
/*			       (= output of the procedure */
/*				  sc_crmac)		  */
/*							  */
/*   algenc		       Encryption method          */
/*							  */
/* OUT                                                    */
/*   out_apdu                  Pointer of SEC-APDU        */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*                             The SEC-APDU has the       */
/*                             structure:                 */
/*		           _____________________          */
/*			  | CLA,ENCRYPTED DATA  |         */
/*		           _____________________          */
/*							  */
/*

/*

*/
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESENC  		  */
/*				EALGO    		  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_encrypt                                          */
/*   aux_fxdump                                       */
/*   aux_free2_BitString                                  */
/*							  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
sc_enc(sec_key, in_apdu, out_apdu, algenc)
	BitString      *sec_key;/* secure messaging key */
	Bytestring     *in_apdu;/* SC-APDU		 */
	Bytestring     *out_apdu;	/* SC-SEC-APDU		 */
	AlgEnc         algenc;	/* encryption method		 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     in_octets;
	char           *ptr;
	int             i;
	int             memolen;
	BitString       out_bits;
	KeyInfo         key_info;
	More            more;


	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	out_apdu->nbytes = 0;
	out_apdu->bytes = NULL;
	in_octets.noctets = in_apdu->nbytes;
	in_octets.octets = in_apdu->bytes;

	/*---------------------------------------------------------*/
	/* encrypt data (INS,P1,P2,L,SSC,DATA)                     */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/
	in_octets.noctets -= 1;
	in_octets.octets++;

#ifdef STREAM
	fprintf(sc_trfp, "TRACE in sc_enc\n");
	fprintf(sc_trfp, "   in_octets.noctets = %d\n", in_octets.noctets);
	fprintf(sc_trfp, "   in_octets.octets  = \n");
	aux_fxdump(sc_trfp, in_octets.octets, in_octets.noctets, 0);
#endif

	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		sc_errno = EALGO;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
		break;
	}
	more = END;

	/* allocate memory for out_bits  */
	/* the memory must be a multiple of 8 Bytes */
	if ((in_octets.noctets % 8) != 0)
		memolen = (in_octets.noctets - (in_octets.noctets % 8)) + 8;
	else
		memolen = in_octets.noctets;

	out_bits.nbits = 0;

#ifdef STREAM
	fprintf(sc_trfp, "   allocate out_bits = %d\n", memolen);
#endif

#ifdef MALLOC
	out_bits.bits = malloc(memolen);	/* will be set free in this
						 * proc. */
	if (out_bits.bits == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
#endif



	memolen = des_encrypt(&in_octets, &out_bits, more, &key_info);
	if (memolen == -1) {
		sc_errno = EDESENC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#ifdef STREAM
	fprintf(sc_trfp, "   out_bits.nbits    = %d\n", out_bits.nbits);
	fprintf(sc_trfp, "   out_bits.bits     = \n");
	aux_fxdump(sc_trfp, out_bits.bits, out_bits.nbits / 8, 0);
#endif


	memolen = (out_bits.nbits / 8) + 1;

#ifdef MALLOC
	out_apdu->bytes = malloc(memolen);	/* if no error => return	  */
	/* else will gbe set free in this proc. */
	if (out_apdu->bytes == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#endif


	out_apdu->nbytes = memolen;
	ptr = out_apdu->bytes;
	*ptr = *in_apdu->bytes;	/* transfer CLA-Byte */
	ptr++;
	for (i = 0; i < (out_bits.nbits / 8); i++) {
		*ptr = *(out_bits.bits + i);
		ptr++;
	};
	aux_free2_BitString(&out_bits);

#ifdef STREAM
	fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sc_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sc_trfp, "TRACE-END in sc_enc\n");
#endif


	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_enc                 */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_checkmac         VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check MAC  and SSC of a received SC-RESPONSE-APDU     */
/*  This procedure can be called in case of               */
/*  secure messaging = AUTHENTIC or in case of            */
/*  secure messaging = COMBINED after calling the         */
/*  procedure sc_dec.                                     */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   ssc		       Send Sequence Counter      */
/*							  */
/*   in_apdu		       Pointer of SEC-APDU        */
/*                             The SC-APDU must have the  */
/*                             structur:                  */
/*			       ________________________   */
/*			      | L,SSC,DATA,MAC,SW1,SW2 |  */
/*			       ________________________   */
/*                                                        */
/*   algenc		       Encryption method          */
/*							  */
/*   maclen		       Length of MAC (0 - 8)      */
/*			       In the current Version     */
/*  			       only 4 is allowed          */
 /* *//* OUT                                              */
/*   out_apdu                  Pointer of SC-APDU         */
/*			       (without SSC and MAC)      */
/*			       L,DATA,SW1,SW2 will be     */
/*			       returned 		  */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*			       The APDU has the structure:*/
/*		                _________________         */
/*			       | L,DATA,SW1,SW2  |        */
/*		                _________________         */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESENC  		  */
/*				ESSC			  */
/*				EMAC			  */
/*				EALGO			  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_encrypt                                          */
/*   aux_fxdump                                           */
/*   aux_free2_OctetString				  */
/*   aux_free2_BitString				  */
/*							  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
sc_checkmac(sec_key, ssc, in_apdu, out_apdu, algenc, maclen)
	BitString      *sec_key;/* secure messaging key */
	int             ssc;	/* Send sequence Counter */
	Bytestring     *in_apdu;/* SEC-APDU		 */
	Bytestring     *out_apdu;	/* SC-APDU		 */
	AlgEnc          algenc;	/* encryption method		 */
	int             maclen;	/* Length of MAC	 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     in_octets;
	char           *ptr, *apdu_ptr, *mac_ptr;
	int             i;
	int             memolen;
	BitString       out_bits;
	KeyInfo         key_info;
	More            more;
	int             rec_ssc, data_len, mac_len;
	char           *mac_field;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	out_apdu->nbytes = 0;
	out_apdu->bytes = NULL;

#ifdef STREAM
	fprintf(sc_trfp, "TRACE in sc_checkmac\n");
	fprintf(sc_trfp, "   in_apdu->nbytes   = %d\n", in_apdu->nbytes);
	fprintf(sc_trfp, "   in_apdu->bytes    = \n");
	aux_fxdump(sc_trfp, in_apdu->bytes, in_apdu->nbytes, 0);
	fprintf(sc_trfp, "   sec_key->nbits    = %d\n", sec_key->nbits / 8);
	fprintf(sc_trfp, "   sec_key->bits     = \n");
	aux_fxdump(sc_trfp, sec_key->bits, sec_key->nbits / 8, 0);
#endif

	if (in_apdu->nbytes == 3) {
		/* only L,SW1,SW2 received */
		out_apdu->nbytes = in_apdu->nbytes;

#ifdef MALLOC
		out_apdu->bytes = malloc(out_apdu->nbytes);	/* if no error => return */
		if (out_apdu->bytes == NULL) {
			sc_errno = EMEMAVAIL;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		}
#endif

		/* copy L,SW1,SW2 into out_apdu->bytes */
		ptr = out_apdu->bytes;
		for (i = 0; i < 3; i++)
			*ptr++ = *(in_apdu->bytes + i);

#ifdef STREAM
		fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
		fprintf(sc_trfp, "   out_apdu->bytes   = \n");
		aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
		fprintf(sc_trfp, "TRACE-END in sc_checkmac\n");
#endif

		return (0);
	}
	in_octets.noctets = *in_apdu->bytes + 4;	/* 4 =
							 * L,SSC,DATA,SW1,SW2 */
	mac_field = in_apdu->bytes + (*in_apdu->bytes + 2);
	mac_len = in_apdu->nbytes - in_octets.noctets;

#ifdef MALLOC
	in_octets.octets = malloc(in_octets.noctets);	/* will be set free in
							 * this proc. */
	if (in_octets.octets == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
#endif

	/* copy L,SSC,DATA,SW1,SW2 from in_apdu->bytes into in_octets.octets */
	ptr = in_octets.octets;
	apdu_ptr = in_apdu->bytes;
	*ptr = *apdu_ptr++;	/* Length-field */
	data_len = *ptr;
	ptr++;

	*ptr = *apdu_ptr++;	/* SSC		 */
	rec_ssc = *ptr & 0xFF;
	ptr++;

	for (i = 0; i < data_len; i++) {	/* Data		 */
		*ptr = *apdu_ptr++;
		ptr++;
	}

	apdu_ptr = in_apdu->bytes + (in_apdu->nbytes - 2);
	*ptr++ = *apdu_ptr++;	/* SW1		 */
	*ptr = *apdu_ptr;	/* SW2		 */



	/*---------------------------------------------------------*/
	/* encrypt data (L,SSC,DATA,SW1,SW2)                       */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/

#ifdef STREAM
	fprintf(sc_trfp, "   in_octets.noctets = %d\n", in_octets.noctets);
	fprintf(sc_trfp, "   in_octets.octets  = \n");
	aux_fxdump(sc_trfp, in_octets.octets, in_octets.noctets, 0);
	fprintf(sc_trfp, "   rec_ssc           = %x\n", rec_ssc);
	fprintf(sc_trfp, "   akt_ssc           = %x\n", (ssc & 0xFF) % 256);
	fprintf(sc_trfp, "   mac_len           = %d\n", mac_len);
	fprintf(sc_trfp, "   mac_field         = \n");
	aux_fxdump(sc_trfp, mac_field, mac_len, 0);
#endif



	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		aux_free2_OctetString(&in_octets);
		sc_errno = EALGO;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
		break;
	}
	more = END;

	/* allocate memory for out_bits  */
	/* the memory must be a multiple of 8 Bytes */
	if ((in_octets.noctets % 8) != 0)
		memolen = (in_octets.noctets - (in_octets.noctets % 8)) + 8;
	else
		memolen = in_octets.noctets;

	out_bits.nbits = 0;

#ifdef STREAM
	fprintf(sc_trfp, "   allocate out_bits = %d\n", memolen);
#endif

#ifdef MALLOC
	out_bits.bits = malloc(memolen);	/* will be set free in this
						 * proc. */
	if (out_bits.bits == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&in_octets);
		return (-1);
	}
#endif


	memolen = des_encrypt(&in_octets, &out_bits, more, &key_info);
	if (memolen == -1) {
		sc_errno = EDESENC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&in_octets);
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#ifdef STREAM
	fprintf(sc_trfp, "   out_bits.nbits    = %d\n", out_bits.nbits);
	fprintf(sc_trfp, "   out_bits.bits     = \n");
	aux_fxdump(sc_trfp, out_bits.bits, out_bits.nbits / 8, 0);
#endif

	/* check SSC	 */
	if (rec_ssc != ((ssc & 0xFF) % 256)) {
		sc_errno = ESSC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&in_octets);
		aux_free2_BitString(&out_bits);

		return (-1);
	}
	/* check MAC	 */
	if (mac_len != maclen) {
		sc_errno = EMAC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&in_octets);
		aux_free2_BitString(&out_bits);
		return (-1);
	}
	/* if only 1 block encrypted => take the first 4 Bytes for MAC   */
	/* else take the last 4 bytes of the last block		       */

	if ((out_bits.nbits / 8) > 8)
		mac_ptr = out_bits.bits + ((out_bits.nbits / 8) - 8);
	else
		mac_ptr = out_bits.bits;

#ifdef STREAM
	fprintf(sc_trfp, "   mac_ptr           = \n");
	aux_fxdump(sc_trfp, mac_ptr, mac_len, 0);
#endif


	for (i = 0; i < mac_len; i++) {
		if (mac_field[i] != *(mac_ptr + i)) {
			sc_errno = EMAC;
			sc_errmsg = sct_error[sc_errno].msg;
			aux_free2_OctetString(&in_octets);
			aux_free2_BitString(&out_bits);
			return (-1);
		}
	}



	memolen = in_octets.noctets - 1;	/* - SSC-Byte */

#ifdef MALLOC
	out_apdu->bytes = malloc(memolen);	/* if no error => return   */
	/* else will be set free in this proc. */
	if (out_apdu->bytes == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&in_octets);
		aux_free2_BitString(&out_bits);
		return (-1);
	}
#endif

	out_apdu->nbytes = memolen;
	ptr = out_apdu->bytes;
	*ptr++ = *in_octets.octets;
	for (i = 2; i < in_octets.noctets; i++) {
		*ptr = *(in_octets.octets + i);
		ptr++;
	}
	aux_free2_OctetString(&in_octets);
	aux_free2_BitString(&out_bits);

#ifdef STREAM
	fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sc_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sc_trfp, "TRACE-END in sc_checkmac\n");
#endif

	return (0);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_checkmac            */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sc_dec              VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Decrypt SEC-RESPONSE-APDU                             */
/*  This procedure can be called in case of               */
/*  secure messaging = CONCEALED or in case of            */
/*  secure messaging = COMBINED before calling the        */
/*  procedure sc_checkmac.				  */
/*  In case of seucre messaging = CONCEALED this procedure*/
/*  also checks the SSC.				  */
/*  In case of secure messaging = COMBINED the calling    */
/*  procedure must set the parameter maclen.              */
/*  This parameter will be need to allocate the           */
/*  buffer out_apdu->bytes correctly.			  */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   sec_key		       Secure Messaging key	  */
/*							  */
/*   sec_mode  		       security mode              */
/*							  */
/*   ssc		       Send Sequence Counter      */
/*			       only used in case of       */
/*			       sec_mode = CONCEALED       */
/*							  */
/*   in_apdu		       Pointer of SEC-APDU        */
/*			       The SEC-APDU have the      */

 /*
  * structure	          *//* _______________ __
  */
/*			      | ENCRYPTED DATA  |         */
/*		               _________________          */
/*			       or			  */
/*		                _________________         */
/*			       | L = 0,SW1,SW2   |        */
/*		                _________________         */
/*   algenc		       Encryption method          */
/*							  */
/*   maclen		       Length of MAC		  */
/*			       Only used in case of       */
/*			       sec_mode = COMBINED;       */
/*			       (COMBINED-Mode)            */
/*							  */
/* OUT                                                    */
/*   out_apdu                  Pointer of SC-APDU         */
/*			       out_apdu->bytes will be    */
/*			       allocated by the called    */
/*			       program			  */
/*			       and must be set free by the*/
/*			       calling program            */
/*			       The APDU has the structure:*/
/*		                _________________         */
/*			       | L,DATA,SW1,SW2  |        */
/*		                _________________         */
/*                             or                         */
/*			       ________________________   */
/*			      | L,SSC,DATA,MAC,SW1,SW2 |  */
/*			       ________________________   */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                         o.k                        */
/*   -1                        Error                      */
/*				EMEMAVAIL		  */
/*				EDESDEC  		  */
/*				ESSC			  */
/*				EALGO			  */
/*						          */
/* CALLED FUNCTIONS					  */
/*   des_decrypt                                          */
/*   aux_fxdump                                       */
/*   sta_aux_bytestr_free			          */
/*   aux_free2_OctetString				  */
/* Bemerkung:						  */
/* Derzeit wird nur der DES-CBC-Mode unterstuetzt.        */
/* Der DES-3-CBC-Mode noch nicht.			  */
/*--------------------------------------------------------*/
int
sc_dec(sec_key, sec_mode, ssc, in_apdu, out_apdu, algenc, maclen)
	BitString      *sec_key;/* secure messaging key */
	SecMessMode     sec_mode;	/* security mode        */
	int             ssc;	/* Send sequence Counter */
	Bytestring     *in_apdu;/* SEC-APDU		 */
	Bytestring     *out_apdu;	/* SC-APDU		 */
	AlgEnc          algenc;	/* encryption method		 */
	int             maclen;	/* MAC-Length		 */
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	OctetString     out_octets;
	char           *ptr, *apdu_ptr;
	int             i;
	int             memolen;
	BitString       in_bits;
	KeyInfo         key_info;
	More            more;
	int             rec_ssc, data_len;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

#ifdef STREAM
	fprintf(sc_trfp, "TRACE in sc_dec\n");
	fprintf(sc_trfp, "   in_apdu->nbytes   = %d\n", in_apdu->nbytes);
	fprintf(sc_trfp, "   in_apdu->bytes    = \n");
	aux_fxdump(sc_trfp, in_apdu->bytes, in_apdu->nbytes, 0);
#endif

	if (in_apdu->nbytes == 3) {
		/* only L,SW1,SW2 received */
		out_apdu->nbytes = in_apdu->nbytes;

#ifdef MALLOC
		out_apdu->bytes = malloc(out_apdu->nbytes);	/* if no error => return       */
		/* else will be set free in this proc. */
		if (out_apdu->bytes == NULL) {
			sc_errno = EMEMAVAIL;
			sc_errmsg = sct_error[sc_errno].msg;
			return (-1);
		}
#endif

		/* copy L,SW1,SW2 into out_apdu->bytes */
		ptr = out_apdu->bytes;
		for (i = 0; i < 3; i++) {
			*ptr = *(in_apdu->bytes + i);
			ptr++;
		}

#ifdef STREAM
		fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
		fprintf(sc_trfp, "   out_apdu->bytes   = \n");
		aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
		fprintf(sc_trfp, "TRACE-END in sc_dec\n");
#endif

		return (0);
	}
	/*---------------------------------------------------------*/
	/* decrypt data                                            */
	/* with Secure Messaging Key                               */
	/*---------------------------------------------------------*/
	/* allocate memory for out_octets  */
	out_octets.noctets = 0;

#ifdef MALLOC
	out_octets.octets = malloc(in_apdu->nbytes);	/* will be set free in
							 * this proc. */
	if (out_octets.octets == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
#endif

	key_info.subjectkey.nbits = sec_key->nbits;
	key_info.subjectkey.bits = sec_key->bits;
	switch (algenc) {
	case DES:
		key_info.subjectAI = desCBC;
		break;
	default:
		aux_free2_OctetString(&out_octets);
		sc_errno = EALGO;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
		break;
	}
	more = END;

	in_bits.nbits = in_apdu->nbytes * 8;
	in_bits.bits = in_apdu->bytes;
	more = END;
	memolen = des_decrypt(&in_bits, &out_octets, more, &key_info);

	if (memolen == -1) {
		sc_errno = EDESDEC;
		sc_errmsg = sct_error[sc_errno].msg;
		aux_free2_OctetString(&out_octets);
		return (-1);
	}
#ifdef STREAM
	fprintf(sc_trfp, "   out_octets.noctets= %d\n", out_octets.noctets);
	fprintf(sc_trfp, "   out_octets.octets = \n");
	aux_fxdump(sc_trfp, out_octets.octets, out_octets.noctets, 0);
#endif

	if (sec_mode == CONCEALED) {
		/* CONCEALED-Mode -> Test SSC; return L,DATA,SW1,SW2 */
		/* allocate out_data->bytes */
		out_apdu->nbytes = *out_octets.octets + 3;	/* 4 = L,DATA,SW1,SW2 */

#ifdef MALLOC
		out_apdu->bytes = malloc(out_apdu->nbytes);	/* if no error => return */
		/* else will be set free in this proc. */
		if (out_apdu->bytes == NULL) {
			sc_errno = EMEMAVAIL;
			sc_errmsg = sct_error[sc_errno].msg;
			aux_free2_OctetString(&out_octets);
			return (-1);
		}
#endif

		/*
		 * copy L,DATA,SW1,SW2 from out_octets.octets into
		 * out_apdu->bytes
		 */
		ptr = out_apdu->bytes;
		apdu_ptr = out_octets.octets;
		*ptr = *apdu_ptr++;	/* Length-field */
		data_len = *ptr;
		ptr++;
		rec_ssc = *apdu_ptr++ & 0xFF;	/* SSC		 */

#ifdef STREAM
		fprintf(sc_trfp, "   rec_ssc           = %x\n", rec_ssc);
		fprintf(sc_trfp, "   akt_ssc           = %x\n", (ssc & 0xFF) % 256);
#endif

		/* check SSC	 */
		if (rec_ssc != ((ssc & 0xFF) % 256)) {
			sc_errno = ESSC;
			sc_errmsg = sct_error[sc_errno].msg;
			aux_free2_OctetString(&out_octets);
			sta_aux_bytestr_free(out_apdu);
			return (-1);
		}
		for (i = 0; i < data_len + 2; i++) {	/* Data, SW1, SW2 */
			*ptr = *apdu_ptr++;
			ptr++;
		}

	} else {
		/* COMBINED-Mode-> return L,SSC,DATA,MAC,SW1,SW2 */
		/* allocate out_data->bytes */
		out_apdu->nbytes = *out_octets.octets + 4 + maclen;

#ifdef MALLOC
		out_apdu->bytes = malloc(out_apdu->nbytes);	/* if no error => return	    */
		/* else will be set free in this proc. */
		if (out_apdu->bytes == NULL) {
			sc_errno = EMEMAVAIL;
			sc_errmsg = sct_error[sc_errno].msg;
			aux_free2_OctetString(&out_octets);
			return (-1);
		}
#endif

		/* copy L,SSC,DATA,MAC,SW1,SW2 from out_octets.octets into   */
		/* out_apdu->bytes */
		ptr = out_apdu->bytes;
		apdu_ptr = out_octets.octets;


		for (i = 0; i < out_apdu->nbytes; i++) {
			*ptr = *apdu_ptr++;
			ptr++;
		}

	}
	aux_free2_OctetString(&out_octets);

#ifdef STREAM
	fprintf(sc_trfp, "   out_apdu->nbytes  = %d\n", out_apdu->nbytes);
	fprintf(sc_trfp, "   out_apdu->bytes   = \n");
	aux_fxdump(sc_trfp, out_apdu->bytes, out_apdu->nbytes, 0);
	fprintf(sc_trfp, "TRACE-END in sc_dec\n");
#endif

	return (0);



}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sc_dec                 */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_KeyId             VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create the key identifier byte                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   kid                       kid structure              */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      Value of Byte              */
/*--------------------------------------------------------*/
char
e_KeyId(kid)
	KeyId          *kid;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char            kidvalue;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((kid->key_number > 63) ||
	    (kid->key_level > SC_SF)) {
		sc_errno = EPARINC;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	};

	kidvalue = (((char) kid->key_number & 0xFF) << 2) |
		((char) kid->key_level & 0xff);

	return (kidvalue);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_KeyId                */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_FileId             VERSION   2.0               */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create the file identifier byte                       */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   fid                       file id structure          */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      Value of Byte              */
/*--------------------------------------------------------*/
char
e_FileId(fid)
	FileId         *fid;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char            fidvalue;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if ((fid->name > 15) ||
	    (fid->file_type > ISF)) {
		sc_errno = EPARINC;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	};

	fidvalue = (((char) fid->name & 0xFF) << 4) |
		(((char) fid->file_type & 0xFF) << 2) |
		((char) fid->file_level & 0xff);

	return (fidvalue);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_FileId               */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_keyAttrList       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  create parameter KATTR1,KATTR2,KFPC,KSTAT in APDU     */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   apdu                      Pointer of APDU-buffer     */
/*                                                        */
/*   keyattrlist               Pointer of KEYattrlist     */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
void
e_KeyAttrList(apdu, keyattrlist, key_algid)
	char          **apdu;
	KeyAttrList    *keyattrlist;
	KeyAlgId        key_algid;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	unsigned        kattr;
	unsigned        bit;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *apdu;
	kattr = 0x00;


	/*----------------------------------------------------*/
	/* create KATTR - Bytes                             */
	/*----------------------------------------------------*/
	/* 1. Byte    */


	kattr |= (unsigned) keyattrlist->key_attr.key_purpose.cipherment << 4 |
		(unsigned) keyattrlist->key_attr.key_purpose.sec_mess_con << 3 |
		(unsigned) keyattrlist->key_attr.key_purpose.sec_mess_auth << 1 |
		(unsigned) keyattrlist->key_attr.key_purpose.authenticate;



	*p++ = (char) ~kattr;

	/* 2. Byte    */
	kattr = 0x00;
	bit = 0x00;
	bit = (unsigned) key_algid << 2;

	kattr = bit | ((unsigned) keyattrlist->key_attr.key_op_mode << 1) |
		(unsigned) keyattrlist->key_attr.key_presentation;


	if (keyattrlist->key_attr.MAC_length == 0)
		kattr |= (unsigned) (keyattrlist->key_attr.MAC_length) << 5;
	else
		kattr |= (unsigned) (keyattrlist->key_attr.MAC_length - 1) << 5;
	*p++ = (char) kattr;

	/*----------------------------------------------------*/
	/* create KFPC - Byte                               */
	/*----------------------------------------------------*/
	kattr = 0x00;
	if (keyattrlist->key_fpc != 0) {
		kattr = (unsigned) keyattrlist->key_fpc;
		kattr |= (unsigned) keyattrlist->key_fpc << 4;
	}
	*p++ = (char) kattr;

	/*----------------------------------------------------*/
	/* create KSTAT - Byte                              */
	/*----------------------------------------------------*/
	kattr = 0x00;
	kattr = (unsigned) keyattrlist->key_status.key_state << 1 |
		(unsigned) keyattrlist->key_status.PIN_check;
	*p++ = (char) kattr;


	*apdu = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_KeyAttrList          */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_FileTypeCat       VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Transform the values for File Type and File Category  */
/*  into one Byte and returns its value.                  */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   filetype                  File Type                  */
/*                                                        */
/*   filecat                   File Category              */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      Value of Byte              */
/*--------------------------------------------------------*/
static char
e_FileTypeCat(filetype, filecat)
	int             filetype;
	int             filecat;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char            file_type_cat;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if (filecat != EF)
		filetype = 0;

	file_type_cat = (((char) filetype & 0xFF) << 2) |
		((char) filecat & 0xff);

	return (file_type_cat);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_FileTypeCat          */
/*-------------------------------------------------------------*/




/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_OperationMode     VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Transform the values for Operation Mode               */
/*  into one Byte and returns its value.                  */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   filecontrolinfo           Pointer to Filecontrolinfo */
/*                             structure                  */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   char                      Value of Byte              */
/*--------------------------------------------------------*/
static char
e_OperationMode(finfo)
	FileControlInfo *finfo;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char            opmode = 0x00;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	opmode = (((char) finfo->not_erasable & 0xFF) << 7) |
		((char) finfo->readwrite & 0xFF);

	return (opmode);


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_OperationMode        */
/*-------------------------------------------------------------*/







/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  e_TwoByte           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Create two bytes in scapdu                            */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   unit                      units-value                */
/*                                                        */
/*                                                        */
/* INOUT                                                  */
/*   io                        Pointer of buffer          */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
e_TwoByte(io, units)
	char          **io;
	unsigned        units;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	p = *io;
	if (units < 255) {
		*p++ = 0x00;
		*p++ = units;
	} else {
		*p++ = units >> 8;
		*p++ = units;
	};
	*io = p;


}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      e_TwoByte              */
/*-------------------------------------------------------------*/





/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  Ioput               VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Put one byte in scabdu                                */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   byte                      Byte                       */
/*                                                        */
/*                                                        */
/* INOUT                                                  */
/*   io                        Pointer of buffer          */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
Ioput(io, byte)
	char          **io;
	unsigned        byte;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *io;
	*p = byte;
	p++;
	*io = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      Ioput                  */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  Ioputbuff           VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Put more than one byte in scapdu                      */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   buff                      Pointer of databuffer      */
/*                                                        */
/*   len                       Length of data             */
/*                                                        */
/*                                                        */
/* INOUT                                                  */
/*   io                        Pointer of scapdu          */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
static void
Ioputbuff(io, buff, len)
	char          **io;
	char           *buff;
	unsigned        len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	int             i;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = *io;
	for (i = 0; i < len; i++) {
		*p = *buff;
		p++;
		buff++;
	}
	*io = p;
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      Ioputbuff              */
/*-------------------------------------------------------------*/



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCalloc             VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Allocate buffer                                       */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   pdulen                     length of scapdu          */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   pointer                   o.k.                       */
/*                                                        */
/*   NULL                      error                      */
/*                              EMEMAVAIL;                */
/*--------------------------------------------------------*/
static char    *
SCalloc(pdulen)
	unsigned int    pdulen;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *buffer = NULL;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

#ifdef MALLOC
	buffer = malloc(pdulen);/* must be set free in calling procedure */
	if (buffer == NULL) {
		sc_errno = EMEMAVAIL;
		sc_errmsg = sct_error[sc_errno].msg;
	}
#endif


	return (buffer);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCalloc                */
/*-------------------------------------------------------------*/





/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  SCchecklen          VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Check length of parameter                             */
/*                                                        */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   len                       length                     */
/*                                                        */
/*   maxlen                    maximal length             */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*   0                          o.k                       */
/*  -1                          error                     */
/*                               ETOOLONG                 */
/*--------------------------------------------------------*/
static int
SCchecklen(len, maxlen)
	unsigned int    len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/

	if ((len < 0) || (len > maxlen)) {
		sc_errno = ETOOLONG;
		sc_errmsg = sct_error[sc_errno].msg;
		return (-1);
	}
	return (0);
}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      SCchecklen             */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/* E N D   O F   P A C K A G E       sccom                     */
/*-------------------------------------------------------------*/
