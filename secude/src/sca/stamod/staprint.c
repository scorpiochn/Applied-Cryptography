/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 2.0		                             +-----*/
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-staprint                             VERSION 2.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	staprint.c                       		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides a function which prints the error message.	           */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*	sca_print_errmsg()     print error message    			           */
/*							                           */
/*      									   */
/*      									   */
/*                                                                                 */
/*    IMPORT		    DESCRIPTION 		                           */
/*				   -  libsctint.a                                  */
/*							                           */
/*      sct_perror()           Print error message                                 */
/*							                           */
/*                                                                                 */
/*      sca_errno              global error variable set by STAMOD                 */
/*                                                                                 */
/*      sca_errmsg             global pointer to error message set by STAMOD       */
/*                                                                                 */
/*                                                                                 */
/*                                                                                 */
/*                                                                                 */
/*    INTERNAL                                                                     */
/*                                                                                 */
/*                                                                                 */
/*---------------------------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files					       */
/*-------------------------------------------------------------*/
#include "stamod.h"
#include "stamsg.h"
#include "sctint.h"
#include "sccom.h"
#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <stdlib.h>
#endif /* !MAC */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/

extern int      sct_perror();
extern unsigned int sca_errno;	/* error number set by STAMOD       */
extern char    *sca_errmsg;	/* pointer to error msg set by      */

 /* STAMOD                           */


/*-------------------------------------------------------------*/
/*   globale variable definitions			       */
/*-------------------------------------------------------------*/

#ifdef TEST
char            text1[27] = "file_type               : ";
char            text2[23] = "file_type           : ";
void            print_filecat();
void            print_filetype();
void            print_datastruc();
void            print_filecontinfo();
void            print_secmess();
void            print_filesel();
void            print_fileid();
void            print_inforeq();
void            print_closecontext();
void            print_datasel();
void            print_keyid();
void            print_recordlist();
void            print_transmode();
void            print_keydevpurpose();
void            print_keydevsel();
void            print_keyattrlist();
void            print_pinstruc();
void            print_keydevlist();

#endif





/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*   local Variable definitions			               */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_print_errmsg         VERSION   2.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   U.Viebeg           */
/*							       */
/* DESCRIPTION						       */
/*  Print the given text together with the global error        */
/*  message on stderr.                 			       */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   msg		       text, which is printed 	       */
/*                             together with error message     */
/*                                                             */
/*							       */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*				 wrong sca_errno	       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  sct_perror                ERROR-Codes		       */
/*			         0  (ok)		       */
/*							       */
/*							       */
/*-------------------------------------------------------------*/
int
sca_print_errmsg(msg)
	char           *msg;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             rc, err_no;

	rc = 0;


	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/
	rc = 0;

	/*-----------------------------------------------------*/
	/* call check_sct_sc    		               */
	/*-----------------------------------------------------*/


#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_print_errmsg ********************************************\n\n");
	fprintf(stdout, "input-parameters:\n");
	if ((msg != NULL) && (strlen(msg) > 0)) {
		fprintf(stdout, "msg:     %s\n", msg);
	}
	fprintf(stdout, "\n\n");
#endif

	if (sca_errno <= 0) {	/* no error number set */
		err_no = 0;
		if (msg && strlen(msg))
			fprintf(stdout, "%s: ", msg);
		fprintf(stdout, "%s\n", stamod_error[err_no].msg);
	} else {
		if (sca_errno < MIN_STAMOD_ERRNO) {
			rc = sct_perror(msg);	/* error from SCT-Interface */
			if (rc < 0)
				return (rc);
		} else {	/* error from STAMOD */
			err_no = sca_errno - MIN_STAMOD_ERRNO;
			if (err_no < 0)
				return (-1);
			if (msg && strlen(msg))
				fprintf(stdout, "%s: ", msg);
			fprintf(stdout, "%s\n", stamod_error[err_no].msg);
		}		/* end else */

	}			/* end else */

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_print_errmsg *********************************************\n\n");
#endif

	return (0);





}				/* end  sca_print_errmsg */

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_print_errmsg       */
/*-------------------------------------------------------------*/

#ifdef TEST


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  print_routines           VERSION   2.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Trace functions                     	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*-------------------------------------------------------------*/
void
print_filecat(file_cat)
	FileCat         file_cat;
{
	switch (file_cat) {
	case MF:
		fprintf(stdout, "file_cat 		: MF\n");
		break;
	case DF:
		fprintf(stdout, "file_cat 		: DF\n");
		break;
	case SF:
		fprintf(stdout, "file_cat 		: SF\n");
		break;
	case EF:
		fprintf(stdout, "file_cat 		: EF\n");
		break;
	default:
		fprintf(stdout, "file_cat 		: undefined\n");
		break;
	};
}
void
print_filetype(file_type, msg)
	FileType        file_type;
	char           *msg;
{


	if (msg == NULL)
		fprintf(stdout, "%s", text1);
	else {
		fprintf(stdout, "%s", msg);
		fprintf(stdout, "%s", text2);
	}

	switch (file_type) {
	case PEF:
		fprintf(stdout, "PEF\n");
		break;
	case WEF:
		fprintf(stdout, "WEF\n");
		break;
	case ACF:
		fprintf(stdout, "ACF\n");
		break;
	case ISF:
		fprintf(stdout, "ISF\n");
		break;
	default:
		fprintf(stdout, "undefined\n");
		break;
	};
}

void
print_datastruc(data_struc)
	DataStruc       data_struc;
{
	switch (data_struc) {
	case LIN_FIX:
		fprintf(stdout, "data_struc 		: LIN_FIX\n");
		break;
	case LIN_VAR:
		fprintf(stdout, "data_struc 		: LIN_VAR\n");
		break;
	case CYCLIC:
		fprintf(stdout, "data_struc 		: CYCLIC\n");
		break;
	case TRANSPARENT:
		fprintf(stdout, "data_struc 		: TRANSPARENT\n");
		break;
	default:
		fprintf(stdout, "data_struc 		: undefined\n");
		break;
	};
}
void
print_filecontinfo(file_cat, file_control_info)
	FileCat         file_cat;
	FileControlInfo *file_control_info;
{
	fprintf(stdout, "file_control_info       :\n");
	fprintf(stdout, "    units               : %d\n", file_control_info->units);
	fprintf(stdout, "    racv                : %x\n", file_control_info->racv);
	fprintf(stdout, "    wacv                : %x\n", file_control_info->wacv);
	fprintf(stdout, "    dacv                : %x\n", file_control_info->dacv);
	switch (file_control_info->readwrite) {
	case READ_WRITE:
		fprintf(stdout, "    readwrite           : READ_WRITE\n");
		break;
	case WORM:
		fprintf(stdout, "    readwrite           : WORM\n");
		break;
	case READ_ONLY:
		fprintf(stdout, "    readwrite           : READ_ONLY\n");
		break;
	case WRITE_ONLY:
		fprintf(stdout, "    readwrite           : WRITE_ONLY\n");
		break;
	default:
		fprintf(stdout, "    readwrite           : undefined\n");
		break;
	};
	fprintf(stdout, "                          set to 0x00 in case of MF,DF or SF \n");
	fprintf(stdout, "    execute             : not used in this version \n");
	fprintf(stdout, "    mac                 : not used in this version \n");
	fprintf(stdout, "    enc                 : not used in this version \n");
	if (file_control_info->not_erasable == TRUE)
		fprintf(stdout, "    not_erasable        : TRUE\n");
	else
		fprintf(stdout, "    not_erasable        : FALSE\n");
	fprintf(stdout, "    recordsize          : %d\n", file_control_info->recordsize);
	fprintf(stdout, "                          set to 0x00 in case of MF,DF,SF or \n");
	fprintf(stdout, "                          EF and data_struc <> LIN_FIX and CYCLIC \n");
	print_filesel(file_cat, &file_control_info->file_sel);
	fprintf(stdout, "    addinfo             : %s\n", file_control_info->addinfo.octets);

}
void
print_filesel(file_cat, file_sel)
	FileCat         file_cat;
	FileSel        *file_sel;
{
	if (file_cat != EF)
		fprintf(stdout, "file_name               : %s\n", file_sel->file_name);
	else
		print_fileid(&file_sel->file_id);
}

void
print_fileid(file_id)
	FileId         *file_id;
{

	fprintf(stdout, "file_id                 :\n");
	switch (file_id->file_level) {
	case MF_LEVEL:
		fprintf(stdout, "    file_level          : MF_LEVEL\n");
		break;
	case DF_LEVEL:
		fprintf(stdout, "    file_level          : DF_LEVEL\n");
		break;
	case SF_LEVEL:
		fprintf(stdout, "    file_level          : SF_LEVEL\n");
		break;
	default:
		fprintf(stdout, "    file_level          : undefined\n");
		break;
	};

	print_filetype(file_id->file_type, "    ");
	fprintf(stdout, "    name                : %d\n", file_id->name);
}

void
print_keyid(key_id)
	KeyId          *key_id;
{
	if (!key_id)
		fprintf(stdout, "KeyId                   : NULL\n");
	else {

		fprintf(stdout, "KeyId                   :\n");
		switch (key_id->key_level) {
		case SC_MF:
			fprintf(stdout, "    key_level           : SC_MF\n");
			break;
		case SC_DF:
			fprintf(stdout, "    key_level           : SC_DF\n");
			break;
		case SC_SF:
			fprintf(stdout, "    key_level           : SC_SF\n");
			break;
		case SCT:
			fprintf(stdout, "    key_level           : SCT\n");
			break;
		default:
			fprintf(stdout, "    key_level           : undefined\n");
			break;
		};

		fprintf(stdout, "    key_number          : %d\n", key_id->key_number);
	}
}
void
print_closecontext(file_close_context)
	FileCloseContext file_close_context;
{

	switch (file_close_context) {
	case CLOSE_CREATE:
		fprintf(stdout, "file_close_context      : CLOSE_CREATE\n");
		break;
	case CLOSE_SELECT:
		fprintf(stdout, "file_close_context      : CLOSE_SELECT\n");
		break;
	default:
		fprintf(stdout, "file_close_context      : undefined\n");
		break;
	};

}
void
print_transmode(trans_mode)
	TransMode       trans_mode;
{

	switch (trans_mode) {
	case TRANSP:
		fprintf(stdout, "trans_mode              : TRANSP\n");
		break;
	case SECURE:
		fprintf(stdout, "trans_mode              : SECURE\n");
		break;
	default:
		fprintf(stdout, "trans_mode              : undefined\n");
		break;
	};

}
void
print_secmess(sec_mess)
	SecMess        *sec_mess;
{

	fprintf(stdout, "sec_mess                :\n");
	switch (sec_mess->command) {
	case SEC_NORMAL:
		fprintf(stdout, "    command             : SEC_NORMAL\n");
		break;
	case AUTHENTIC:
		fprintf(stdout, "    command             : AUTHENTIC\n");
		break;
	case CONCEALED:
		fprintf(stdout, "    command             : CONCEALED\n");
		break;
	case COMBINED:
		fprintf(stdout, "    command             : COMBINED\n");
		break;
	default:
		fprintf(stdout, "    command             : undefined\n");
		break;
	};

	switch (sec_mess->response) {
	case SEC_NORMAL:
		fprintf(stdout, "    response            : SEC_NORMAL\n");
		break;
	case AUTHENTIC:
		fprintf(stdout, "    response            : AUTHENTIC\n");
		break;
	case CONCEALED:
		fprintf(stdout, "    response            : CONCEALED\n");
		break;
	case COMBINED:
		fprintf(stdout, "    response            : COMBINED\n");
		break;
	default:
		fprintf(stdout, "    response            : undefined\n");
		break;
	};

}
void
print_datasel(data_sel)
	DataSel        *data_sel;
{

	fprintf(stdout, "data_sel                :\n");
	switch (data_sel->data_struc) {
	case LIN_FIX:
		fprintf(stdout, "    data_struc          : LIN_FIX\n");
		fprintf(stdout, "    record_id           : %d\n", data_sel->data_ref.record_sel.record_id);
		fprintf(stdout, "    record_pos          : %d\n", data_sel->data_ref.record_sel.record_pos);
		break;
	case LIN_VAR:
		fprintf(stdout, "    data_struc          : LIN_VAR\n");
		fprintf(stdout, "    record_id           : %d\n", data_sel->data_ref.record_sel.record_id);
		fprintf(stdout, "    record_pos          : %d\n", data_sel->data_ref.record_sel.record_pos);
		break;
	case CYCLIC:
		fprintf(stdout, "    data_struc 	  : CYCLIC\n");
		fprintf(stdout, "    element_ref         : %d\n", data_sel->data_ref.element_sel.element_ref);
		fprintf(stdout, "    element_no          : %d\n", data_sel->data_ref.element_sel.element_no);
		break;
	case TRANSPARENT:
		fprintf(stdout, "    data_struc          : TRANSPARENT\n");
		fprintf(stdout, "    string_sel          : %d\n", data_sel->data_ref.string_sel);
		break;
	default:
		fprintf(stdout, "    data_struc 	  : undefined\n");
		break;
	};
}
void
print_inforeq(info_req)
	FileInfoReq     info_req;
{

	switch (info_req) {
	case NONE_INFO:
		fprintf(stdout, "file_info_req           : NONE\n");
		break;
	case SHORT_INFO:
		fprintf(stdout, "file_info_req           : SHORT\n");
		break;
	default:
		fprintf(stdout, "file_info_req           : undefined\n");
		break;
	};


}

void
print_recordlist(recordlist)
	RecordList     *recordlist;
{
	RecordList     *dp_tail;

	dp_tail = recordlist;
	fprintf(stdout, "PTR of BEGIN            : %x\n", dp_tail);

	while (dp_tail != RECNULL) {
		fprintf(stdout, "   PTR of octets        : %x\n", dp_tail->record.octets);
		aux_xdump(dp_tail->record.octets, dp_tail->record.noctets, 0);
		dp_tail = dp_tail->next;
		fprintf(stdout, "PTR of NEXT             : %x\n", dp_tail);
	};
}

void
print_keydevpurpose(key_dev_purpose)
	KeyDevPurpose  *key_dev_purpose;
{
	if (!key_dev_purpose)
		fprintf(stdout, "KeyDevPurpose           : NULL\n");
	else {
		fprintf(stdout, "KeyDevPurpose           : \n");
		fprintf(stdout, "    key_purpose         : \n");
		switch (key_dev_purpose->key_purpose.authenticate) {
		case TRUE:
			fprintf(stdout, "        authenticate    : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        authenticate    : FALSE\n");
			break;
		default:
			fprintf(stdout, "        authenticate    : undefined\n");
			break;
		}
		switch (key_dev_purpose->key_purpose.sec_mess_auth) {
		case TRUE:
			fprintf(stdout, "        sec_mess_auth   : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        sec_mess_auth   : FALSE\n");
			break;
		default:
			fprintf(stdout, "        sec_mess_auth   : undefined\n");
			break;
		}

		switch (key_dev_purpose->key_purpose.sec_mess_con) {
		case TRUE:
			fprintf(stdout, "        sec_mess_con    : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        sec_mess_conc   : FALSE\n");
			break;
		default:
			fprintf(stdout, "        sec_mess_conc   : undefined\n");
			break;
		}
		fprintf(stdout, "        cipherment      : is not used for a device key\n");

		if (key_dev_purpose->key_dev_status == DEV_ANY)
			fprintf(stdout, "    key_dev_status      : DEV_ANY\n");
		else
			fprintf(stdout, "    key_dev_status      : value not allowed\n");

		if (key_dev_purpose->key_type == MASTER)
			fprintf(stdout, "    key_type            : MASTER\n");
		else
			fprintf(stdout, "    key_type            : value not supported\n");





	}			/* key_dev_purpose <> NULL */

}

void
print_keydevsel(key_dev_sel)
	KeyDevSel      *key_dev_sel;
{
	if (!key_dev_sel)
		fprintf(stdout, "KeyDevSEL               : NULL\n");
	else {
		fprintf(stdout, "KeyDevSel               : \n");
		switch (key_dev_sel->key_status) {
		case DEV_OWN:
			fprintf(stdout, "        key_status      : DEV_OWN\n");
			break;
		case DEV_ANY:
			fprintf(stdout, "        key_status      : DEV_ANY\n");
			break;
		default:
			fprintf(stdout, "        key_status      : undefined\n");
			break;
		}

		if (key_dev_sel->key_status == DEV_ANY)
			print_keyid(&key_dev_sel->dev_ref.key_id);
		else {
			fprintf(stdout, "    key_purpose         : \n");
			switch (key_dev_sel->dev_ref.key_purpose.authenticate) {
			case TRUE:
				fprintf(stdout, "        authenticate    : TRUE\n");
				break;
			case FALSE:
				fprintf(stdout, "        authenticate    : FALSE\n");
				break;
			default:
				fprintf(stdout, "        authenticate    : undefined\n");
				break;
			}
			switch (key_dev_sel->dev_ref.key_purpose.sec_mess_auth) {
			case TRUE:
				fprintf(stdout, "        sec_mess_auth   : TRUE\n");
				break;
			case FALSE:
				fprintf(stdout, "        sec_mess_auth   : FALSE\n");
				break;
			default:
				fprintf(stdout, "        sec_mess_auth   : undefined\n");
				break;
			}

			switch (key_dev_sel->dev_ref.key_purpose.sec_mess_con) {
			case TRUE:
				fprintf(stdout, "        sec_mess_con    : TRUE\n");
				break;
			case FALSE:
				fprintf(stdout, "        sec_mess_conc   : FALSE\n");
				break;
			default:
				fprintf(stdout, "        sec_mess_conc   : undefined\n");
				break;
			}
			fprintf(stdout, "        cipherment      : is not used for a device key\n");
		}

	}			/* key_dev_sel <> NULL */

}


void
print_keyattrlist(key_attr_list)
	KeyAttrList    *key_attr_list;
{
	if (!key_attr_list)
		fprintf(stdout, "KeyAttrList             : NULL\n");
	else {
		fprintf(stdout, "KeyAttrList             : \n");
		switch (key_attr_list->key_inst_mode) {
		case INST:
			fprintf(stdout, "    key_inst_mode       : INST\n");
			break;
		case REPL:
			fprintf(stdout, "    key_inst_mode       : REPL\n");
			break;
		default:
			fprintf(stdout, "    key_inst_mode       : undefined\n");
			break;
		}

		fprintf(stdout, "    key_attr            : \n");
		fprintf(stdout, "       key_purpose      : \n");
		switch (key_attr_list->key_attr.key_purpose.authenticate) {
		case TRUE:
			fprintf(stdout, "        authenticate    : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        authenticate    : FALSE\n");
			break;
		default:
			fprintf(stdout, "        authenticate    : undefined\n");
			break;
		}
		switch (key_attr_list->key_attr.key_purpose.sec_mess_auth) {
		case TRUE:
			fprintf(stdout, "        sec_mess_auth   : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        sec_mess_auth   : FALSE\n");
			break;
		default:
			fprintf(stdout, "        sec_mess_auth   : undefined\n");
			break;
		}

		switch (key_attr_list->key_attr.key_purpose.sec_mess_con) {
		case TRUE:
			fprintf(stdout, "        sec_mess_con    : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        sec_mess_conc   : FALSE\n");
			break;
		default:
			fprintf(stdout, "        sec_mess_conc   : undefined\n");
			break;
		}

		switch (key_attr_list->key_attr.key_purpose.cipherment) {
		case TRUE:
			fprintf(stdout, "        cipherment      : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "        cipherment      : FALSE\n");
			break;
		default:
			fprintf(stdout, "        cipherment      : undefined\n");
			break;
		}

		switch (key_attr_list->key_attr.key_presentation) {
		case KEY_GLOBAL:
			fprintf(stdout, "       key_presenation  : KEY_GLOBAL\n");
			break;
		case KEY_LOCAL:
			fprintf(stdout, "       key_presenation  : KEY_LOCAL\n");
			break;
		default:
			fprintf(stdout, "       key_presenation  : value not defined\n");
			break;
		}

		switch (key_attr_list->key_attr.key_op_mode) {
		case REPLACE:
			fprintf(stdout, "       key_op_mode      : REPLACE\n");
			break;
		case NO_REPLACE:
			fprintf(stdout, "       key_op_mode      : NO_REPLACE\n");
			break;
		default:
			fprintf(stdout, "       key_op_mode      : value not defined\n");
			break;
		}



		fprintf(stdout, "       MAC_length       : %d\n",
			key_attr_list->key_attr.MAC_length);

		fprintf(stdout, "    key_fpc             : %d\n", key_attr_list->key_fpc);

		fprintf(stdout, "    key_status          : \n");
		switch (key_attr_list->key_status.PIN_check) {
		case TRUE:
			fprintf(stdout, "       PIN_check        : TRUE\n");
			break;
		case FALSE:
			fprintf(stdout, "       PIN_check        : FALSE\n");
			break;
		default:
			fprintf(stdout, "       PIN_check        : value not defined\n");
			break;
		}

		switch (key_attr_list->key_status.key_state) {
		case KEY_NORMAL:
			fprintf(stdout, "       key_state        : KEY_NORMAL\n");
			break;
		case KEY_LOCKED:
			fprintf(stdout, "       key_state        : KEY_LOCKED\n");
			break;
		default:
			fprintf(stdout, "       key_state        : value not defined\n");
			break;
		}

	}


}

void
print_pinstruc(pin)
	PINStruc       *pin;
{
	if (!pin)
		fprintf(stdout, "PINStruc                : NULL\n");
	else {
		fprintf(stdout, "PINStruc                : \n");
		switch (pin->pin_type) {
		case PIN:
			fprintf(stdout, "    pin_type            : PIN\n");
			fprintf(stdout, "    pin_info            :\n");
			fprintf(stdout, "       min_len          : %d\n",
				pin->PINBody.pin_info.min_len);
			if (!pin->PINBody.pin_info.pin)
				fprintf(stdout, "       pin              : NULL\n");
			else
				fprintf(stdout, "       pin              : %s\n",
					pin->PINBody.pin_info.pin);
			if (!pin->PINBody.pin_info.clear_pin)
				fprintf(stdout, "       clear_pin        : NULL\n");
			else
				fprintf(stdout, "       clear_pin        : %s\n",
					pin->PINBody.pin_info.clear_pin);


			break;
		case PUK:
			fprintf(stdout, "    pin_type            : PUK\n");
			fprintf(stdout, "    puk_info            :\n");
			if (!pin->PINBody.puk_info.puk)
				fprintf(stdout, "       puk              : NULL\n");
			else
				fprintf(stdout, "       pin              : %s\n",
					pin->PINBody.puk_info.puk);

			fprintf(stdout, "       PIN_key_id       :\n");
			switch (pin->PINBody.puk_info.pin_key_id.key_level) {
			case SC_MF:
				fprintf(stdout, "          key_level     : SC_MF\n");
				break;
			case SC_DF:
				fprintf(stdout, "          key_level     : SC_DF\n");
				break;
			case SC_SF:
				fprintf(stdout, "          key_level     : SC_SF\n");
				break;
			default:
				fprintf(stdout, "          key_level     : value not allowed\n");
				break;
			};

			fprintf(stdout, "          key_number    : %d\n",
				pin->PINBody.puk_info.pin_key_id.key_number);
			break;
		default:
			fprintf(stdout, "    pin_type            : value not defined\n");
			break;
		}
	}
}

void
print_keydevlist(key_dev_list)
	KeyDevList     *key_dev_list;
{

	if (!key_dev_list)
		fprintf(stdout, "KeyDevList              : NULL\n");
	else {
		fprintf(stdout, "KeyDevList              : \n");
		fprintf(stdout, "auth_key                : \n");
		print_keyid(key_dev_list->auth_key);
		fprintf(stdout, "sec_auth_key            : \n");
		print_keyid(key_dev_list->sec_auth_key);
		fprintf(stdout, "sec_con_key             : \n");
		print_keyid(key_dev_list->sec_con_key);
	}
}

#endif



/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-staprint	       */
/*-------------------------------------------------------------*/
