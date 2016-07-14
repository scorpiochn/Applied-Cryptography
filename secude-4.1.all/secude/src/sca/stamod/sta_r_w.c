/*---------------------------------------------------------------------------+-----*/
/*							                     | GMD */
/*   SYSTEM   STAPAC  -  Version 1.0		                             +-----*/
/*							                           */
/*---------------------------------------------------------------------------------*/
/*							                           */
/*    PACKAGE	STAMOD-stasc                                VERSION 1.0	           */
/*					                       DATE Januar 1992    */
/*					                         BY Ursula Viebeg  */
/*					                            Levona Eckstein*/
/*			       				                           */
/*    FILENAME     					                           */
/*	sta_r_w.c                          		         		   */
/*							                           */
/*    DESCRIPTION	   				                           */
/*      This modul provides all functions for file handling and data access        */
/*      on the smartcard  of the smartcard application interface                   */
/*							                           */
/*    EXPORT		    DESCRIPTION 		                           */
/*      sca_read_data()       Read data from EF on the smartcard                   */
/*										   */
/*      sca_read_file()       Read complete file from smartcard                    */
/*										   */
/*      sca_write_data()      Write data in EF on the smartcard			   */
/*										   */
/*      sca_write_file()      Write complete file on the smartcard		   */
/*    									           */
/*      sca_delete_record()   Delete record in EF on the smartcard		   */
/*										   */
/*      sca_lock_key()        Lock key on smartcard				   */
/*   										   */
/*      sca_unlock_key()      Unlock key on the smartcard			   */
/*										   */
/*							                           */
/*                                                                                 */
/*							                           */
/*                                                                                 */
/*    IMPORT		    DESCRIPTION 		                           */
/*                                 -  aux_xdmp.c (libcrypt)                        */
/*                                                                                 */
/*	aux_fxdump()                  dump buffer in File	                   */
/*							                           */
/*							                           */
/*                                 -  sta_free.c (libsm)                           */
/*                                                                                 */
/*      sta_aux_bytestr_free()        set the bytes-buffer in Bytestring free      */
/*                                                                                 */
/*                                                                                 */
/*				   -  sta_dev.c (libsm)                            */
/*                                                                                 */
/*      check_sct_sc()                check SCT and SC                             */
/*                                                                                 */
/*      check_sec_mess()              check security mode(s) for command and response*/
/*                                                                                 */
/*      set_errmsg()                  set sca_errmsg                               */
/*                                                                                 */
/*      err_analyse()                 error analyse and handling                   */
/*                                                                                 */
/*      sca_errno                     global error variable set by STAMOD          */
/*                                                                                 */
/*      sca_errmsg                    global pointer to error message set by STAMOD*/
/*                                                                                 */
/*				   -  stasc.c   (libsm)                            */
/*                                                                                 */
/*      create_trans()		      send SC command				   */
/*                                                                                 */
/*      cr_header()		      create SC-Command header			   */
/*									           */
/*      request			      global variable for create_trans		   */
/*										   */
/*      response		      global variable	for create_trans           */
/*										   */
/*      sc_param		      global variable for create_trans             */
/*										   */
 /* sc_apdu			      global variable for create_trans	           *//* */
/*				   -  staprint.c   (libsm) for TEST-output         */
/*                                                                                 */
/*      print_filecat()							           */
/*      print_filetype()                                                           */
/*      print_datastruc()                                                          */
/*      print_filecontinfo()                                                       */
/*      print_secmess()                                                            */
/*      print_filesel()                                                            */
/*      print_fileid()                                                             */
/*      print_inforeq()                                                            */
/*      print_closecontext()                                                       */
/*      print_datasel()                                                            */
/*      print_datastruc()                                                          */
/*      print_keyid()                                                              */
/*      print_recordlist()                                                         */
/*      print_transmode()                                                          */
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
#endif
#include <stdio.h>
#include <fcntl.h>
#include <string.h>


/*-------------------------------------------------------------*/
/*   extern declarations				       */
/*-------------------------------------------------------------*/

extern void     sta_aux_bytestr_free();
extern void     aux_fxdump();
extern int      check_sct_sc();
extern int      check_sec_mess();
extern int      set_errmsg();
extern void     err_analyse();
extern int      create_trans();
extern int      cr_header();

extern unsigned int sca_errno;	/* error number set by STAMOD-      */

 /* stadevice			       */
extern char    *sca_errmsg;	/* pointer to error message set by  */

 /* STAMOD-stadevice                 */

#ifdef TEST
extern void     print_filecat();
extern void     print_filetype();
extern void     print_datastruc();
extern void     print_filecontinfo();
extern void     print_secmess();
extern void     print_filesel();
extern void     print_fileid();
extern void     print_inforeq();
extern void     print_closecontext();
extern void     print_datasel();
extern void     print_keyid();
extern void     print_recordlist();
extern void     print_transmode();

#endif

extern Request  request;	/* body of the SCT commands         */
extern Bytestring response;	/* body of the response of the SCT  */
extern int      command;	/* INS-Code of the SCT command      */

extern struct s_command sc_param;	/* structure of parameters for the  */

 /* SC-commands                      */
extern Bytestring sc_apdu;	/* generated apdu of the SC-command */




/*-------------------------------------------------------------*/
/*   globale variable definitions			       */
/*-------------------------------------------------------------*/




/*-------------------------------------------------------------*/
/*   type definitions					       */
/*-------------------------------------------------------------*/

/* definitions for the SC-Interface */
#define SCCMD                   sc_param.sc_header.inscode
#define SCHEAD                  sc_param.sc_header
#define SCREADF                 sc_param.sc_uval.sc_readf
#define SCWRITEF                sc_param.sc_uval.sc_writef
#define SCDELREC                sc_param.sc_uval.sc_delrec
#define SCLOCKK                 sc_param.sc_uval.sc_lockkey


#define FIRST_FIX_RID     0x00
#define FIRST_VAR_RID     0x00


/*-------------------------------------------------------------*/
/*   local Variable definitions			               */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   local procedure definitions	                       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_read_data            VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Read data from elementary file on the smartcard.           */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   data_sel                  Offset of the data to be read   */
/*			                         	       */
/*   data_length               Number of octets to be read     */
/*			                 		       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*   out_data                  Buffer where the returned data  */
/*			       are stored		       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*                               M_EMEMORY                     */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_read_data(sct_id, file_id, data_sel, data_length, out_data, sec_mess)
	int             sct_id;
	FileId         *file_id;
	DataSel        *data_sel;
	int             data_length;
	OctetString    *out_data;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i, rc;
	int             data_incon = 0;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_read_data *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_datasel(data_sel);
	fprintf(stdout, "data_length             : %d\n", data_length);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command READF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_READF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCREADF.data_sel = data_sel;
	SCREADF.fid = file_id;
	SCREADF.lrddata = (unsigned) data_length;



	/* call create_trans			  */
	rc = create_trans(sct_id, TRUE);
	if (rc == -1) {
		switch (sca_errno) {

		case EDATAINC_CLPEN:
			if (response.nbytes != 0) {
				data_incon = 1;
			} else {
				sta_aux_bytestr_free(&response);
				return (-1);
			}
			break;
		default:
			/*---------------------------------------*/
			/* error while reading file              */
			/*---------------------------------------*/
			sta_aux_bytestr_free(&response);
			return (-1);
			break;
		}
	};


	/* get data from SC  */
	out_data->noctets = response.nbytes;
	if ((out_data->octets = (char *) malloc(out_data->noctets)) == NULL) {
		sca_errno = M_EMEMORY;
		set_errmsg();
		sta_aux_bytestr_free(&response);
		return (-1);
	}
	for (i = 0; i < out_data->noctets; i++)
		out_data->octets[i] = response.bytes[i];



	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	fprintf(stdout, "out_data                : \n");
	fprintf(stdout, "    noctets             : %d\n", out_data->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, out_data->octets, out_data->noctets, 0);
	fprintf(stdout, "\n***** Normal end of   sca_read_data *****\n\n");
#endif

	if (data_incon)
		return (-1);
	else
		return (0);




}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_read_data	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_read_file            VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Read complete file from smartcard.        	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   data_struc                Data structure                  */
/*			       (LIN_FIX or LIN_VAR)   	       */
/*   sec_mess		       security modes                  */
/*							       */
/* OUT							       */
/*							       */
/*   out_data                  Buffer where the returned data  */
/*                             are stored       	       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       file completly read             */
/*  -1			       error			       */
/*                               out_data may be present       */
/*				 M_EDATASTRUC		       */
/*				 M_EFILEEMPTY		       */
/*				 M_EMEMORY		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_read_file(sct_id, file_id, data_struc, out_data, sec_mess)
	int             sct_id;
	FileId         *file_id;
	DataStruc       data_struc;
	RecordList    **out_data;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/

	int             end_flag = 0;
	int             first_read = 1;
	int             data_incon = 0;
	int             rc, i;
	RecordList     *p_head, *p_last;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_read_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_datastruc(data_struc);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* check parameter                    */
	/*-------------------------------------*/
	if ((data_struc != LIN_FIX) &&
	    (data_struc != LIN_VAR)) {
		sca_errno = M_EDATASTRUC;
		set_errmsg();
		return (-1);
	}
	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command READF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_READF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCREADF.data_sel->data_struc = data_struc;
	if (data_struc == LIN_FIX)
		SCREADF.data_sel->data_ref.record_sel.record_id = FIRST_FIX_RID;
	else
		SCREADF.data_sel->data_ref.record_sel.record_id = FIRST_VAR_RID;
	SCREADF.fid = file_id;
	SCREADF.data_sel->data_ref.record_sel.record_pos = 0;
	SCREADF.lrddata = 0;

	*out_data = NULL;


	while (!end_flag) {

		/*---------------------------------------*/
		/* call create_trans			  */
		/*---------------------------------------*/
		rc = create_trans(sct_id, TRUE);

		if (rc == -1) {
			switch (sca_errno) {
			case EINVRID:
				if (first_read) {
					/*---------------------------------------*/
					/* file empty                            */
					/*---------------------------------------*/

#ifdef TEST
					fprintf(stdout, "\n***** File empty *****\n\n");
					fprintf(stdout, "\n***** Normal end of   sca_read_file *****\n\n");
#endif

					sca_errno = M_EFILEEMPTY;
					set_errmsg();
					sta_aux_bytestr_free(&response);
					return (-1);
				}
				/*---------------------------------------*/
				/* end of file reached                   */
				/*---------------------------------------*/
				*out_data = p_head;
				sta_aux_bytestr_free(&response);

#ifdef TEST
				fprintf(stdout, "\n***** end of file reached *****\n\n");
				fprintf(stdout, "TRACE of the output parameters : \n");
				print_recordlist(*out_data);
				fprintf(stdout, "\n***** Normal end of   sca_read_file *****\n\n");
#endif

				return (0);
				break;

			case EDATAINC_CLPEN:
				if (response.nbytes != 0) {
					/* Data inconsistency */
					end_flag = 1;
					data_incon = 1;

#ifdef TEST
					fprintf(stdout, "\n***** Data inconsistency, but data reached *****\n\n");
#endif
				} else {
					*out_data = p_head;

#ifdef TEST
					fprintf(stdout, "\n***** error while reading data *****\n\n");
					fprintf(stdout, "TRACE of the output parameters : \n");
					print_recordlist(*out_data);
#endif

					sta_aux_bytestr_free(&response);
					return (-1);
				}
				break;
			default:
				/*---------------------------------------*/
				/* error while reading file              */
				/*---------------------------------------*/
				*out_data = p_head;
				sta_aux_bytestr_free(&response);

#ifdef TEST
				fprintf(stdout, "\n***** error while reading data *****\n\n");
				fprintf(stdout, "TRACE of the output parameters : \n");
				print_recordlist(*out_data);
#endif

				return (-1);
				break;
			}
		};

		/*---------------------------------------------------------*/
		/* allocate new RecordList - element and get data from SC  */
		/*---------------------------------------------------------*/
		if (first_read) {
			/*---------------------------------------*/
			/* create first element                  */
			/*---------------------------------------*/

			if ((p_head = (RecordList *) malloc(sizeof(RecordList))) == RECNULL) {

#ifdef TEST
				fprintf(stdout, "\n***** error while creating first recordlist - element *****\n\n");
#endif

				sca_errno = M_EMEMORY;
				set_errmsg();
				sta_aux_bytestr_free(&response);
				return (-1);
			}
			p_head->next = RECNULL;
			p_last = p_head;
		} else {
			/*---------------------------------------*/
			/* create next RecordList element        */
			/*---------------------------------------*/

			if ((p_last->next = (RecordList *) malloc(sizeof(RecordList))) == RECNULL) {
				*out_data = p_head;

#ifdef TEST
				fprintf(stdout, "\n***** error while creating next recordlist - element *****\n\n");
				fprintf(stdout, "TRACE of the output parameters : \n");
				print_recordlist(*out_data);
#endif

				sca_errno = M_EMEMORY;
				set_errmsg();
				sta_aux_bytestr_free(&response);
				return (-1);
			}
			p_last = p_last->next;
			p_last->next = RECNULL;
		}


		p_last->record.noctets = response.nbytes;

		/*---------------------------------------*/
		/* allocate record.octets */
		/*---------------------------------------*/
		if ((p_last->record.octets = (char *) malloc(p_last->record.noctets)) == NULL) {
			*out_data = p_head;

#ifdef TEST
			fprintf(stdout, "\n***** error while creating next octet - element *****\n\n");
			fprintf(stdout, "TRACE of the output parameters : \n");
			print_recordlist(*out_data);
#endif

			sca_errno = M_EMEMORY;
			set_errmsg();
			sta_aux_bytestr_free(&response);
			return (-1);
		}
		for (i = 0; i < p_last->record.noctets; i++)
			p_last->record.octets[i] = response.bytes[i];

		sta_aux_bytestr_free(&response);
		SCREADF.data_sel->data_ref.record_sel.record_id++;	/* next record */
		first_read = 0;

	}



	sta_aux_bytestr_free(&response);

	*out_data = p_head;

#ifdef TEST
	fprintf(stdout, "TRACE of the output parameters : \n");
	print_recordlist(*out_data);
#endif

	if (data_incon)
		return (-1);
	else
		return (0);





}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_read_file	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_write_data           VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Write data in elementary file on the smartcard.            */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   data_sel                  Offset where the data shall     */
/*			       be written		       */
/*   in_data                   Data to be written              */
/*			                 		       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_write_data(sct_id, file_id, data_sel, in_data, sec_mess)
	int             sct_id;
	FileId         *file_id;
	DataSel        *data_sel;
	OctetString    *in_data;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	int             i;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_write_data *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_datasel(data_sel);
	fprintf(stdout, "in_data                 : \n");
	fprintf(stdout, "    noctets             : %d\n", in_data->noctets);
	fprintf(stdout, "    octets              : \n");
	aux_fxdump(stdout, in_data->octets, in_data->noctets, 0);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command WRITEF           */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_WRITEF, sec_mess))
		return (-1);


	/* set parameters			  */
	SCWRITEF.data_sel = data_sel;
	SCWRITEF.fid = file_id;
	SCWRITEF.lwrdata = (unsigned) in_data->noctets;
	SCWRITEF.wrdata = in_data->octets;



	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);


	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_write_data *****\n\n");
#endif

	return (0);





}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_write_data         */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_write_file          VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Write complete file on the smartcard.                      */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   data_struc                Data structure                  */
/*			       (LIN_FIX or LIN_VAR)  	       */
/*   in_data                   Data to be written              */
/*			                 		       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*			         M_EPOINTER  		       */
/*				 M_EDATASTRUC		       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_write_file(sct_id, file_id, data_struc, in_data, sec_mess)
	int             sct_id;
	FileId         *file_id;
	DataStruc       data_struc;
	RecordList     *in_data;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	RecordList     *dp_tail;

	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_write_file *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	print_datastruc(data_struc);
	print_recordlist(in_data);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* check parameter                    */
	/*-------------------------------------*/
	if ((data_struc != LIN_FIX) &&
	    (data_struc != LIN_VAR)) {
		sca_errno = M_EDATASTRUC;
		set_errmsg();
		return (-1);
	}
	if (in_data == RECNULL) {
		/* file empty */
		sca_errno = M_EPOINTER;
		set_errmsg();
		return (-1);
	}
	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command WRITEF           */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_WRITEF, sec_mess))
		return (-1);


	/* set parameters			  */

	SCWRITEF.data_sel->data_struc = data_struc;
	if (data_struc == LIN_FIX)
		SCWRITEF.data_sel->data_ref.record_sel.record_id = FIRST_FIX_RID;
	else
		SCWRITEF.data_sel->data_ref.record_sel.record_id = FIRST_VAR_RID;
	SCWRITEF.fid = file_id;
	SCWRITEF.data_sel->data_ref.record_sel.record_pos = 0;


	dp_tail = in_data;

	while (dp_tail != RECNULL) {
		if ((dp_tail->record.noctets == 0) ||
		    (dp_tail->record.octets == NULL)) {
			/* file complete processed */
			return (0);
		}
		SCWRITEF.lwrdata = (unsigned) dp_tail->record.noctets;
		SCWRITEF.wrdata = dp_tail->record.octets;


		/* call create_trans			  */
		if (create_trans(sct_id, TRUE))
			return (-1);

		/*----------------------------------------------*/
		/* normal end => release response storage       */
		/*----------------------------------------------*/
		sta_aux_bytestr_free(&response);

		/*----------------------------------------------*/
		/* transfer next record                         */
		/*----------------------------------------------*/

		SCWRITEF.data_sel->data_ref.record_sel.record_id++;
		dp_tail = dp_tail->next;

	}

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_write_file *****\n\n");
#endif

	return (0);






}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_write_file	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_delete_record        VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Delete record in elementary file on the smartcard.         */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   file_id                   File identifier                 */
/*							       */
/*   record_id                 Record identifier               */
/*			                         	       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_delete_record(sct_id, file_id, record_id, sec_mess)
	int             sct_id;
	FileId         *file_id;
	unsigned int    record_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_delete_record *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_fileid(file_id);
	fprintf(stdout, "record_id               : %d\n", record_id);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_DELREC, sec_mess))
		return (-1);


	/* set parameters			  */
	SCDELREC.fid = file_id;
	SCDELREC.rid = record_id;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_delete_record *****\n\n");
#endif

	return (0);





}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_delete_record      */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_lock_key             VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Lock key on smartcard.              	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id                    Key identifier                  */
/*							       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_lock_key(sct_id, key_id, sec_mess)
	int             sct_id;
	KeyId          *key_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_lock_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_keyid(key_id);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_LOCKKEY, sec_mess))
		return (-1);


	/* set parameters			  */
	SCLOCKK.kid = key_id;
	SCLOCKK.operation = CO_LOCK;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_lock_key *****\n\n");
#endif

	return (0);







}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_lock_key	       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*						         | GMD */
/*						         +-----*/
/* PROC  sca_unlock_key           VERSION   1.0	    	       */
/*				     DATE   Januar 1992	       */
/*			      	       BY   Levona Eckstein    */
/*							       */
/* DESCRIPTION						       */
/*  Unlock key on the smartcard.         	               */
/*							       */
/*							       */
/* IN			     DESCRIPTION		       */
/*   sct_id		       SCT identifier		       */
/*                                                             */
/*   key_id                    Key identifier                  */
/*							       */
 /* sec_mess		       security modes                  *//* */
/* OUT							       */
/*							       */
/*							       */
/* RETURN		     DESCRIPTION	      	       */
/*   0	         	       o.k			       */
/*  -1			       error			       */
/*							       */
/* CALLED FUNCTIONS					       */
/*  check_sct_sc               ERROR-Codes		       */
/*			         ENOCARD		       */
/*			         ESIDUNK		       */
/*			 	 ENOSHELL		       */
/*                               EOPERR                        */
/*			         EEMPTY                        */
/*                               EMEMAVAIL                     */
/*                               ECLERR                        */
/*                               ERDERR                        */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*							       */
/*  cr_header         	       ERROR-Codes    		       */
/*                               M_ESECMESS		       */
/*							       */
/*							       */
/*  create_trans   	       ERROR-Codes	               */
/*                               EINVARG		       */
/*                               ETOOLONG		       */
/*                               EMEMAVAIL		       */
/*                               ESIDUNK                       */
/*                               EPARMISSED                    */
/*			         EPARINC		       */
/*                               INVPAR                        */
/*                               EINVINS                       */
/*                               sw1/sw2 from SCT response     */
/*                               T1 - ERROR                    */
/*                               sw1/sw2 from SC  response     */
/*							       */
/*-------------------------------------------------------------*/
int
sca_unlock_key(sct_id, key_id, sec_mess)
	int             sct_id;
	KeyId          *key_id;
	SecMess        *sec_mess;
{
	/*----------------------------------------------------------*/
	/* Definitions					       */
	/*----------------------------------------------------------*/
	/*----------------------------------------------------------*/
	/* Statements					       */
	/*----------------------------------------------------------*/

#ifdef TEST
	fprintf(stdout, "\n***** STAMOD-Routine sca_unlock_key *****\n\n");
	fprintf(stdout, "TRACE of the input parameters : \n");
	fprintf(stdout, "sct_id                  : %d\n", sct_id);
	print_keyid(key_id);
	print_secmess(sec_mess);
#endif

	/*-------------------------------------*/
	/* call check_sct_sc                  */
	/*-------------------------------------*/
	if (check_sct_sc(sct_id, TRUE))
		return (-1);


	/*-------------------------------------*/
	/* create SC command LOCKF            */
	/*-------------------------------------*/
	/* create header                       */
	if (cr_header(SC_LOCKKEY, sec_mess))
		return (-1);


	/* set parameters			  */
	SCLOCKK.kid = key_id;
	SCLOCKK.operation = CO_UNLOCK;


	/* call create_trans			  */
	if (create_trans(sct_id, TRUE))
		return (-1);

	/*----------------------------------------------*/
	/* normal end => release response storage       */
	/*----------------------------------------------*/
	sta_aux_bytestr_free(&response);

#ifdef TEST
	fprintf(stdout, "\n***** Normal end of   sca_unlock_key *****\n\n");
#endif

	return (0);







}

/*-------------------------------------------------------------*/
/* E N D   O F	 P R O C E D U R E	sca_unlock_key	       */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/* E N D   O F	 P A C K A G E	     STAMOD-stasc 	       */
/*-------------------------------------------------------------*/
