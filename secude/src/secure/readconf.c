
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

/*----------------Read SC Configuration File------------------------*/
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (F2.G3)               */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990                                      */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer et alii                 */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PACKAGE   readconfig              VERSION   4.0                  */
/*                                      DATE   23.9.92	            */
/*                                        BY   UV	            */
/* DESCRIPTION                                                      */
/*                                                                  */
/* EXPORT                                                           */
/*   check_SCapp_configuration() Check consistency of configuration */
/*				 data for an SC-application.	    */
/*   get_default_configuration() Set "sc_app_list[]" to default	    */
/*  				 configuration.			    */
/*   display_SC_configuration() Display the actual SC configuration */
/*				("sc_app_list[]").  		    */
/*   read_SC_configuration()    Read SC configuration file into     */
/*				global structure "sc_app_list[]".   */
/*                                                                  */
/* STATIC                                                           */
/*   char2int()			Transform ASCII string to integer   */
/*				value.				    */
/*   free_sc_app_list()		Release all allocated memory in     */
/*   				in "sc_app_list[]".		    */
/*   check_app_name()		Check whether the actual read 	    */
/*				application name is unique in       */
/*				"sc_app_list[]".		    */
/*   check_config_list()	Check whether the object list of    */
/*				an SC-application contains all      */
/*				mandatory objects.		    */
/*   check_obj_info()		Check whether the actual read       */
/* 				object is unique in object list.    */
/*   get_app_info()		Get information (e.g. object list)  */
/*                              for current application.	    */
/*   get_default_index()        Get index in default object list.   */
/*   get_first_app_record()     Get first application record in     */
/*			        file (incl. SC_encrypt, SC_verify). */
/*   get_next_correct_record()  Get next correct record in file and */
/* 				return the parameters.		    */
/*   get_next_word_from_record() Return next word in record.	    */
/*   get_obj_par()		Get object parameters from read     */
/*				record.				    */
/*   handle_mandatory_obj()     Handle mandatory objects in         */
/*				object list.			    */
/*   is_char_relevant()		Check whether character is relevant.*/
/*   is_record_correct()	Check whether parameter in record   */
/*				are correct and return the par.     */
/*   is_record_relevant()	Check whether read record is a 	    */
/*				comment record. 		    */
/*   read_record()	        Read one record from file.	    */
/*   								    */
/*                                                                  */
/* IMPORT              		              		            */
/*                                                                  */
/*  Auxiliary Functions of SECUDE		                    */
/*   aux_add_error()		Add error to error stack.	    */
/*								    */
/*                                                                  */
/*  Global Variables                                                */
/*								    */
/*   sc_app_list[]		List of the applications available  */
/*				on the SC, including the list of    */
/*				all objects (app specific),         */
/*				-which shall be stored on the SC or */
/*				-which are stored on the SC.	    */
/*   default_sc_app_list[]	Default SC application list.	    */
/*   default_sc_obj_list[]	Default SC object list.		    */
/*   man_sc_obj_list[] 		List of the mandatory objects 	    */
/*				belonging to one SC application.    */
/*   onekeypair_sc_obj_list[] 	List of the mandatory objects 	    */
/*				for an SC application with one RSA  */
/*				keypair.   			    */
/*   twokeypairs_sc_obj_list[] 	List of the mandatory objects 	    */
/*				for an SC application with two RSA  */
/*				keypairs.   			    */
/*------------------------------------------------------------------*/

#ifdef SCA

#include "secsc_config.h"	/* contains default SC configuration lists	 */


#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

typedef enum {
	NO_KEYWORD, APP_NAME, IGNORE, OBJ_NAME, SC_ENCRYPT, SC_VERIFY
}               ParType;


typedef struct Par_In_Record {
	ParType         par_type;
	union {
		char           *app_name;
		Boolean         boolean_flag;
		SCObjEntry      obj_par;
	}               conf_par;
}               ParInRecord;


/*
 *    Extern declarations
 */

extern SCAppEntry *aux_AppName2SCApp();
extern SCObjEntry *aux_AppObjName2SCObj();
extern void     aux_add_error();



RC		check_SCapp_configuration();




/*
 *    Local variables, but global within readconf.c
 */
char           *strcat();



/*
 *    Local definitions, but global within readconf.c
 */


/*
 *    Local declarations
 */

static int      char2int();
static int      char2int();
static int      check_app_name();
static int 	check_config_list();
static int      check_obj_info();
static int      get_app_info();
static int      get_default_index();
static int      get_first_app_record();
static int      get_next_correct_record();
static char    *get_next_word_from_record();
static int      handle_mandatory_obj();
static int      get_obj_par();
static Boolean  is_char_relevant();
static Boolean  is_record_correct();
static int      is_record_relevant();
static RC       free_sc_app_list();
static int      read_record();



/*--------------------------------------------------------------*/
/*						                */
/* PROC  read_SC_configuration				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read the SC configuration file and stores the information   */
/*  in the global list "sc_app_list[]".			        */
/*								*/
/*  Case 1:							*/
/*  If configuration file can not be opened 			*/
/*      => - "sc_app_list[]" remains unchanged.			*/
/*         - return(0).						*/
/*								*/
/*  Case 2:							*/
/*  If configuration file can be opened, the file is read until */
/*  EOF is found or more than MAX_SC_APP applications are read.	*/
/*								*/
/*  In case of error(s): -  all errors are stacked with 	*/
/*  			    "aux_add_error()",			*/
/*                       -  sc_app_list is set to 0,            */
/*                       -  return (-1).			*/
/*								*/
/****************************************************************/
/*  Handling of SC_encrypt, SC_verify flag:			*/
/*  One record for each flag may be in the configuration file	*/
/*  before the record with the first application name.		*/
/*								*/
/****************************************************************/
/*  Handling of mandatory objects:				*/
/*  For each application it is checked whether the belonging    */
/*  object list contains all mandatory objects.  If a  		*/
/*  mandatory object is missing, the default values for this    */
/*  object is added to the current object list.			*/
/*  The global list "man_sc_obj_list[]" contains the list of the*/
/*  mandatory objects.						*/
/*								*/
/****************************************************************/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   which_SCconfig	       = USER_CONF			*/
/*				 Search for the SC configuration*/
/*			         in the user directory.		*/
/*			       = SYSTEM_CONF			*/
/*			         Take name of SC configuration  */
/*				 file from define variable      */
/*				 SCINIT.			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  -1			       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*   free_sc_app_list()	       Release all allocated memory in  */
/*   			       in "sc_app_list[]".		*/
/*   check_app_name()	       Check whether the actual read 	*/
/*			       application name is unique in    */
/*			       "sc_app_list[]".		        */
/*   get_app_info()	       Get information (e.g. object list)*/
/*                             for current application.	        */
/*   get_first_app_record()    Get first application record in  */
/*			       file.				*/
/*   handle_mandatory_obj()    Handle mandatory objects in      */
/*			       object list.			*/
/*   aux_add_error()	       Add error to error stack.	*/
/*--------------------------------------------------------------*/


RC 
read_SC_configuration(which_SCconfig)
WhichSCConfig	which_SCconfig;
{
	int             n = 0;
	int             i = 0;
	int             rc = 0;

	char           *homedir = "";
	char           *config_file_name = "";
	int             fd_conf;
	FILE           *fp_conf;
	int             function_rc = 0;
	int             app_no;
	char           *next_app_name;

	ParInRecord     par_in_record;


	char           *proc = "read_SC_configuration";

/********************************************************************************/
/*
 *	Compose name of configuration file: 
 */

	switch (which_SCconfig) {

	case USER_CONF: 

		/* 
		 *   Name = "home directory || SC_CONFIG_name"
		 */

		homedir = getenv("HOME");
		if (!homedir) {
			aux_add_error(ESYSTEM, "Getenv failed in read_SC_configuration", CNULL, 0, proc);
			return (-1);
		}
		config_file_name = (char *) malloc(strlen(homedir) + strlen(SC_CONFIG_name) + 64);
		if (!config_file_name) {
			aux_add_error(EMALLOC, "Config_file_name", CNULL, 0, proc);
			return (-1);
		}
		strcpy(config_file_name, homedir);
		if (strlen(homedir))
			if (config_file_name[strlen(config_file_name) - 1] != '/')
				strcat(config_file_name, "/");
		strcat(config_file_name, SC_CONFIG_name);

		break;

	case SYSTEM_CONF: 

		/* 
		 *   configuration file name is taken from define variable "SCINIT".
		 */

#ifdef SCINIT
		config_file_name = (char *) malloc(256);
		if (!config_file_name) {
			aux_add_error(EMALLOC, "Config_file_name", CNULL, 0, proc);
			return (-1);
		}

		strcpy(config_file_name, SCINIT);

#else
		fprintf(stderr,"Global variable SCINIT not defined\n");
		free(config_file_name);
		return (0);

#endif

		break;
	default:
		aux_add_error(ESYSTEM, "invalid input parameter for read_SC_configuration", CNULL, 0, proc);
		return -1;

	}  /* end switch */
		


#ifdef CONFIGTEST
	fprintf(stderr, "Name of SC configuration file: %s\n", config_file_name);
#endif



/********************************************************************************/
/*
 *	Open configuration file
 */

	if ((fd_conf = open(config_file_name, O_RDONLY)) < 0) {
#ifdef SECSCTEST
		fprintf(stderr, "Configuration file %s missing!\n", config_file_name);
#endif
		free(config_file_name);
		return (0);
	}
	if ((fp_conf = fdopen(fd_conf, "r")) == (FILE * ) 0) {
		aux_add_error(ECONFIG, "Configuration file cannot be opened", config_file_name, char_n, proc);
	        close(fd_conf);
	        free(config_file_name);
		return(-1);
	}
/********************************************************************************/
/*
 *	Read configuration file and store information into application list
 */

	/* init */
	next_app_name = CNULL;

	/*
	 * Get first application name in configuration file (incl.
	 * SC_encrypt- , SC_verify-flag)
	 */

	rc = get_first_app_record(fp_conf, &par_in_record);
	if (rc == ERR_flag) {
		aux_add_error(ECONFIG, "APP: Error in get first application name ", CNULL, 0, proc);
		function_rc = ERR_flag;
	}
	if ((rc == EOF_flag) || (rc == EOF_with_ERR) || (par_in_record.par_type != APP_NAME)) {
		aux_add_error(ECONFIG, "APP: No application in configuration file", CNULL, 0, proc);
		goto err_case;
	}
	/* name of first application */
	next_app_name = par_in_record.conf_par.app_name;


	/*
	 * Loop for SC-application(s) in configuration file (until EOF or too
	 * many applications in file ( max number = MAX_SCAPP))
	 * 
	 * Errors are stacked with "aux_add_error()"
	 * 
	 */

	app_no = 0;
	sc_app_list[app_no].app_name = CNULL;

	while ((app_no < MAX_SCAPP) && (next_app_name != CNULL) &&
	       (rc != EOF_flag) && (rc != EOF_with_ERR)) {

		/* check next application name */
		rc = check_app_name(next_app_name);
		if (rc < 0) {
			aux_add_error(ECONFIG, "APP: Invalid name for application ", next_app_name, char_n, proc);
			function_rc = ERR_flag;
		}

		/*
		 * new entry in sc_app_list (next_app_name becomes current
		 * app_name)
		 */
		sc_app_list[app_no].app_name = next_app_name;

		next_app_name = CNULL;

		/*
		 * get parameters (e.g. object list) for application until
		 * EOF or next app. found
		 */
		rc = get_app_info(fp_conf, &sc_app_list[app_no], &next_app_name);
		if ((rc == ERR_flag) || (rc == EOF_with_ERR)) {
			aux_add_error(ECONFIG, "APP: Error in get info for application ", sc_app_list[app_no].app_name, char_n, proc);
			function_rc = ERR_flag;
		}

		/*
		 * If mandatory objects are missing in current object list =>
		 * add them.
		 */
		rc = handle_mandatory_obj(&sc_app_list[app_no]);
		if (rc == ERR_flag) {
			aux_add_error(ECONFIG, "APP: Error in handle_mandatory_obj for application ", sc_app_list[app_no].app_name, char_n, proc);
			function_rc = ERR_flag;
		}
		app_no++;
		sc_app_list[app_no].app_name = CNULL;

	}			/* end while */


	if (app_no >= MAX_SCAPP) {
		aux_add_error(ECONFIG, "APP: Too many application in configuration file", CNULL, 0, proc);
		goto err_case;
	}
	if ((rc == EOF_with_ERR) || (function_rc == ERR_flag)) {
		aux_add_error(ECONFIG, "Error in configuration file", CNULL, 0, proc);
		goto err_case;
	}

/*
 *	release allocated memory (normal end)
 */

	close(fd_conf);
	fclose(fp_conf);
	free(config_file_name);
	return (0);




/*
 *	release allocated memory (in case or error)
 */

err_case:

	/* release all allocated memory and set "sc_app_list[]" to 0 */
	rc = free_sc_app_list();

	close(fd_conf);
	fclose(fp_conf);
	free(config_file_name);
	if (next_app_name != CNULL)
		free(next_app_name);
	return (-1);

}				/* end read_SC_configuration */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  display_SC_configuration			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Display the actual SC configuration ("sc_app_list[]").      */
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*--------------------------------------------------------------*/


RC display_SC_configuration()
{
	int             rc, n, i;


	fprintf(stderr, "S C   C O N F I G U R A T I O N \n\n");

	if (SC_encrypt == TRUE)
		fprintf(stderr, "    SC_encrypt= TRUE\n");
	else
		fprintf(stderr, "    SC_encrypt= FALSE\n");


	if (SC_verify == TRUE)
		fprintf(stderr, "    SC_verify=  TRUE\n");
	else
		fprintf(stderr, "    SC_verify=  FALSE\n");



	for (n = 0; sc_app_list[n].app_name; n++) {
		fprintf(stderr, "\n\n%d.  APPLICATION= %s\n", n + 1, sc_app_list[n].app_name);
		if (sc_app_list[n].ignore_flag == TRUE)
			fprintf(stderr, "    IGNORE FLAG= TRUE\n");
		else
			fprintf(stderr, "    IGNORE FLAG= FALSE\n");

		fprintf(stderr, "\n    List of the SC-objects:\n");
		for (i = 0; sc_app_list[n].sc_obj_list[i].name; i++) {
			 /*name*/ fprintf(stderr, "\n      %d. OBJECT=  %s", i + 1, sc_app_list[n].sc_obj_list[i].name);

			 /*id=key*/ if (sc_app_list[n].sc_obj_list[i].type == SC_KEY_TYPE) {
				fprintf(stderr, "\n         SC_KEY_TYPE  ");
				 /*key_level*/ if (sc_app_list[n].sc_obj_list[i].sc_id.level == SC_MF)
					fprintf(stderr, " MF");
				else if (sc_app_list[n].sc_obj_list[i].sc_id.level == SC_DF)
					fprintf(stderr, " DF");
				else if (sc_app_list[n].sc_obj_list[i].sc_id.level == SC_SF)
					fprintf(stderr, " SF");
				else if (sc_app_list[n].sc_obj_list[i].sc_id.level == SCT)
					fprintf(stderr, " SCT");
				else
					fprintf(stderr, "\nunknown key_level\n");

				 /*key_number*/ fprintf(stderr, " key_no= %d", sc_app_list[n].sc_obj_list[i].sc_id.no);

			} else {
				if (sc_app_list[n].sc_obj_list[i].type == SC_FILE_TYPE) {
					 /*id=File*/ fprintf(stderr, "\n         SC_FILE_TYPE ");
					 /*file_level*/ if (sc_app_list[n].sc_obj_list[i].sc_id.level == MF_LEVEL)
						fprintf(stderr, " MF");
					else if (sc_app_list[n].sc_obj_list[i].sc_id.level == DF_LEVEL)
						fprintf(stderr, " DF");
					else if (sc_app_list[n].sc_obj_list[i].sc_id.level == SF_LEVEL)
						fprintf(stderr, " SF");
					else
						fprintf(stderr, "\nunknown file_level\n");

					 /*file_type*/ if (sc_app_list[n].sc_obj_list[i].sc_id.type == PEF)
						fprintf(stderr, " PEF");
					else if (sc_app_list[n].sc_obj_list[i].sc_id.type == WEF)
						fprintf(stderr, " WEF");
					else
						fprintf(stderr, "\ninvalid file type\n");

					 /*file_name*/ fprintf(stderr, " file_name= %d", sc_app_list[n].sc_obj_list[i].sc_id.no);

					 /*no of bytes*/ fprintf(stderr, "  NOB=%d ", sc_app_list[n].sc_obj_list[i].size);

				} else
					fprintf(stderr, "\nunknown object id\n");
			}


			fprintf(stderr, "   SM_PAR= (");
/*sec_mess sm_SCT*/
			if (sc_app_list[n].sc_obj_list[i].sm_SCT == SEC_NORMAL)
				fprintf(stderr, " NORM");
			else if (sc_app_list[n].sc_obj_list[i].sm_SCT == AUTHENTIC)
				fprintf(stderr, " AUTH");
			else if (sc_app_list[n].sc_obj_list[i].sm_SCT == CONCEALED)
				fprintf(stderr, " CONC");
			else if (sc_app_list[n].sc_obj_list[i].sm_SCT == COMBINED)
				fprintf(stderr, " COMB");
			else
				fprintf(stderr, "\nInvalid sm_sCT\n");
/*sec_mess sm_SC_read_command*/
			if (sc_app_list[n].sc_obj_list[i].sm_SC_read.command == SEC_NORMAL)
				fprintf(stderr, " NORM");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.command == AUTHENTIC)
				fprintf(stderr, " AUTH");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.command == CONCEALED)
				fprintf(stderr, " CONC");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.command == COMBINED)
				fprintf(stderr, " COMB");
			else
				fprintf(stderr, "\nInvalid sm_SC_read_command");

/*sec_mess sm_SC_read_response*/
			if (sc_app_list[n].sc_obj_list[i].sm_SC_read.response == SEC_NORMAL)
				fprintf(stderr, " NORM");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.response == AUTHENTIC)
				fprintf(stderr, " AUTH");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.response == CONCEALED)
				fprintf(stderr, " CONC");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_read.response == COMBINED)
				fprintf(stderr, " COMB");
			else
				fprintf(stderr, "\nInvalid sm_SC_read.response\n");

/*sec_mess sm_SC_write_command*/
			if (sc_app_list[n].sc_obj_list[i].sm_SC_write.command == SEC_NORMAL)
				fprintf(stderr, " NORM");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.command == AUTHENTIC)
				fprintf(stderr, " AUTH");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.command == CONCEALED)
				fprintf(stderr, " CONC");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.command == COMBINED)
				fprintf(stderr, " COMB");
			else
				fprintf(stderr, "\nInvalid sm_SC_write.command\n");

/*sec_mess sm_SC_write_response*/
			if (sc_app_list[n].sc_obj_list[i].sm_SC_write.response == SEC_NORMAL)
				fprintf(stderr, " NORM");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.response == AUTHENTIC)
				fprintf(stderr, " AUTH");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.response == CONCEALED)
				fprintf(stderr, " CONC");
			else if (sc_app_list[n].sc_obj_list[i].sm_SC_write.response == COMBINED)
				fprintf(stderr, " COMB");
			else
				fprintf(stderr, "\nInvalid sm_SC_write.response\n");

			fprintf(stderr, " )");

		}		/* end for objects */


	}			/* end for applications */
	fprintf(stderr, "\n\n");

	return (0);


}				/* end display_SC_configuration */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_default_configuration			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Store the default configuration list "default_sc_app_list[]"*/
/*  in the configuration list "sc_app_list[]". For each         */
/*  application the "default_sc_obj_list[]" is used as default  */
/*  object list.						*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*                                                              */
/*--------------------------------------------------------------*/


RC get_default_configuration()
{
	int             n = 0;
	int             i = 0;


	char           *proc = "get_default_configuration";

	for (n = 0; default_sc_app_list[n]; n++) {

		sc_app_list[n].app_name = default_sc_app_list[n];

		/* get SC object list */
		for (i = 0; default_sc_obj_list[i].name; i++)
			sc_app_list[n].sc_obj_list[i] = default_sc_obj_list[i];
		sc_app_list[n].sc_obj_list[i].name = CNULL;
	}

	sc_app_list[n].app_name = CNULL;

	return (0);

}				/* end get_default_configuration */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  free_sc_app_list				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Release all allocated memory in "sc_app_list[]" and set 	*/
/*  "sc_app_list[]" to 0.					*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/

static
RC 
free_sc_app_list()
{

	int             n = 0;
	int             i = 0;

	char 		*proc  = "free_sc_app_list";




	for (n = 0; sc_app_list[n].app_name; n++) {

		if (sc_app_list[n].app_name)
			free(sc_app_list[n].app_name);

		for (i = 0; sc_app_list[n].sc_obj_list[i].name; i++) {
			if (sc_app_list[n].sc_obj_list[i].name)
				free(sc_app_list[n].sc_obj_list[i].name);
		}		

	}

	sc_app_list[0].app_name = CNULL;

	return (0);

}





/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_app_info					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read information (object list) for the current application 	*/
/*  and returns the information in paramter "sc_app_entry" .    */
/*								*/
/*  Read file until next application or EOF. Errors are stacked */
/*  with "aux_add_error()".					*/
/*								*/
/****************************************************************/
/*  Handling of the IGNORE flag:				*/
/*  The IGNORE flag is expected in the first found correct      */
/*  record. IGNORE flags within the object list are ignored.    */
/*								*/
/****************************************************************/
/*  Handling of the SC_Encrypt, SC_verify flag:			*/
/*  These flags are ignored within the list of the application  */
/*  parameters.							*/
/*								*/
/****************************************************************/
/*  Handling of the OBJECTS					*/
/*  If the number of objects read for one application is greater*/
/*  than MAX_SCOBJ, all further objects are stored in 		*/
/*  "sc_app_entry->sc_obj_list[MAX_SCOBJ]".			*/
/*  								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   fp_conf			Pointer to configuration file 	*/
/*   *sc_app_entry  		Pointer to an entry in the      */
/*				"sc_app_list[]".		*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   sc_app_entry  		Entry of the "sc_app_list":	*/
/*				- ignore flag			*/
/*				- object_list			*/
/*   next_app_name		name of the next application    */
/*				(memory for next_app_name is    */
/*				 allocated)			*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  ERR_flag		       Error			       	*/
/*  EOF_flag		       EOF found		       	*/
/*  EOF_with_ERR	       Error and EOF found .       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   check_obj_info()	       Check whether the actual read    */
/* 			       object is unique in object list. */
/*   get_next_correct_record() Get next correct record in file  */
/* 			       and return the parameters.       */
/*   aux_add_error()	       Add error to error stack.	*/
/*--------------------------------------------------------------*/


static
int 
get_app_info(fp_conf, sc_app_entry, next_app_name)
	FILE           *fp_conf;
	SCAppEntry     *sc_app_entry;
	char          **next_app_name;

{
	int             n = 0;
	int             i = 0;
	int             rc = 0;


	int             obj_no;
	ParInRecord     par_in_record;
	Boolean         found_next_app_name;
	int             function_rc = 0;


	char           *proc = "get_app_info";

	/* init */
	sc_app_entry->ignore_flag = SC_ignore_SWPSE;
	sc_app_entry->sc_obj_list[0].name = CNULL;


	/*
	 * Get next correct record in file and return all parameters
	 */

	rc = get_next_correct_record(fp_conf, &par_in_record);
	if (rc == ERR_flag) {
/*	   aux_add_error (ECONFIG , "OBJ: Error in get correct record ", CNULL, 0, proc); */
		function_rc = ERR_flag;
	}
	if ((rc == EOF_flag) || (rc == EOF_with_ERR)) {
		return (rc);
	}

	/*
	 * Handle ignore flag, this parameter is optional (default value =
	 * TRUE)
	 */

	if (par_in_record.par_type == IGNORE) {
		sc_app_entry->ignore_flag = par_in_record.conf_par.boolean_flag;

		rc = get_next_correct_record(fp_conf, &par_in_record);
		if (rc == ERR_flag) {
/*	      aux_add_error (ECONFIG , "OBJ: Error in get correct record ", CNULL, 0, proc);*/
			function_rc = ERR_flag;
		}
		if ((rc == EOF_flag) || (rc == EOF_with_ERR)) {
			return (rc);
		}
	}			/* end if (par_type == IGNORE) */

	/*
	 * Loop for objects belonging to actual application (until error or
	 * EOF or next application found)
	 */
	obj_no = 0;
	sc_app_entry->sc_obj_list[obj_no].name = CNULL;
	found_next_app_name = FALSE;

	while ((rc != EOF_flag) && (rc != EOF_with_ERR) &&
	       (found_next_app_name == FALSE)) {

		switch (par_in_record.par_type) {
		case APP_NAME:
			/* get name of the next application in file */
			*next_app_name = par_in_record.conf_par.app_name;
			found_next_app_name = TRUE;
			break;

		case IGNORE:
		case SC_ENCRYPT:
		case SC_VERIFY:

			/*
			 * within the object list "IGNORE", "SC_ENCRYPT",
			 * "SC_VERIFY" flags are ignored.
			 */

			break;

		case OBJ_NAME:

			/*
			 * check new object (e.g. compare with already
			 * entered objects)
			 */
			rc = check_obj_info(sc_app_entry, &par_in_record.conf_par.obj_par);
			if (rc < 0) {
				aux_add_error(ECONFIG, "OBJ: Invalid object for application", sc_app_entry->app_name, char_n, proc);
				function_rc = ERR_flag;
			}

			/*
			 * enter new object in obj_list[obj_no].
			 */
			sc_app_entry->sc_obj_list[obj_no] = par_in_record.conf_par.obj_par;

#ifdef CONFIGTEST
			fprintf(stderr, "Name of new entered object : %s\n", sc_app_entry->sc_obj_list[obj_no].name);
#endif


			obj_no++;

			/*
			 * if obj_no >= MAX_SCOBJ => obj_no will be set to
			 * MAX_SCOBJ
			 */
			if (obj_no >= MAX_SCOBJ) {
				aux_add_error(ECONFIG, "OBJ: Too many objects for application ", sc_app_entry->app_name, char_n, proc);
				obj_no = MAX_SCOBJ;
				function_rc = ERR_flag;
			}
			sc_app_entry->sc_obj_list[obj_no].name = CNULL;
			break;

		default:
			aux_add_error(ECONFIG, "Invalid parameter record for application ", sc_app_entry->app_name, char_n, proc);
			function_rc = ERR_flag;
			break;

		}		/* end switch */

		if (found_next_app_name == FALSE) {
			rc = get_next_correct_record(fp_conf, &par_in_record);
			if ((rc == ERR_flag) || (rc == EOF_with_ERR)) {
/*	         aux_add_error (ECONFIG , "OBJ: Error in get correct record ", CNULL, 0, proc); */
				function_rc = ERR_flag;
			}
		}
	}			/* end while */


	/*
	 * Return value
	 */

	if (rc == EOF_with_ERR)
		return (EOF_with_ERR);

	if (rc == EOF_flag) {
		if (function_rc == ERR_flag)
			return (EOF_with_ERR);
		else
			return (EOF_flag);
	} else
		return (function_rc);




}				/* end get_app_info */










/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_first_app_record				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read configuration file until first record with application */
/*  name is found or EOF.					*/
/*								*/
/****************************************************************/
/*  Handling of SC_encrypt, SC_verify flag:			*/
/*  The first relevant records of the file may contain the 	*/
/*  SC_ENCRYPT and/or SC_VERIFY flags. According to these flags */
/*  the global variables SC_encrypt, SC_verify are set.		*/
/*								*/
/****************************************************************/
/*  Case 1:							*/
/*  If app-name can be found:					*/
/*     => - app_name is set in "par_in_record->conf_par.app_name"*/
/*        - return(0)						*/
/*								*/
/*  Case 2:							*/
/*  If no app-name can be found (EOF reached):			*/
/*     => return (EOF_with_ERR)					*/
/*								*/
/*  Case 3:							*/
/*  If records with application parameters (IGNORE, OBJECT) are */
/*  found before the record with an application name:		*/
/*     => - error(s) are stacked with "aux_add_error()",	*/
/*        - "par_in_record->conf_par.app_name" is set to the the*/
/*          found application name,				*/
/*        - return(ERR_flag).					*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   fp_conf			Pointer to configuration file 	*/
/*   *par_in_record		Pointer to structure.		*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   par_in_record		If not ERR, this structure	*/
/*			        contains the correct app_name	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  ERR_flag		       Error			       	*/
/*  EOF_with_ERR	       Error and EOF found	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_next_correct_record()  Get next correct record in file */
/* 				and return the parameters.      */
/*   aux_add_error()	       Add error to error stack.	*/
/*--------------------------------------------------------------*/
static
int 
get_first_app_record(fp_conf, par_in_record)
	FILE           *fp_conf;
	ParInRecord    *par_in_record;
{


	int             function_rc = 0;
	Boolean         app_name_found = FALSE;
	int             rc;

	char           *proc = "get_first_app_record";

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  get_first_app_record\n\n");*/
#endif


	do {

		rc = get_next_correct_record(fp_conf, par_in_record);
		if ((rc == EOF_flag) || (rc == EOF_with_ERR)) {
			aux_add_error(ECONFIG, "APP: Cannot find first app_name in file. ", CNULL, 0, proc);
			return (EOF_with_ERR);
		}
		if (rc == ERR_flag)
			function_rc = 0;	/* ignore all leading invalid
						 * records */

		/* check type of record */
		switch (par_in_record->par_type) {

		case APP_NAME:
			app_name_found = TRUE;
			break;

		case OBJ_NAME:
			aux_add_error(ECONFIG, "APP: Object record found before app_name", CNULL, 0, proc);
			/* release memory for object name */
			free(par_in_record->conf_par.obj_par.name);
			par_in_record->conf_par.obj_par.name = CNULL;
			function_rc = ERR_flag;
			break;

		case IGNORE:
			aux_add_error(ECONFIG, "APP: Ignore flag found before app_name", CNULL, 0, proc);
			function_rc = ERR_flag;
			break;

		case SC_ENCRYPT:
			SC_encrypt = par_in_record->conf_par.boolean_flag;
			break;

		case SC_VERIFY:
			SC_verify = par_in_record->conf_par.boolean_flag;
			break;

		default:
			aux_add_error(ECONFIG, "APP: Unknown record type found before app_name", CNULL, 0, proc);
			function_rc = ERR_flag;
			break;

		}		/* end switch */


	} while (app_name_found == FALSE);


	/*
	 * Return value
	 */

	return (function_rc);

}				/* end get_first_app_record */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_next_correct_record			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Get next correct record in file and return all parameters	*/
/*  i.e. jumb over all leading comment-, blank- or  empty 	*/
/*  and incorrect records.					*/
/*								*/
/*  This function reads the file until a correct record is found*/
/*  or EOF. 							*/
/*								*/
/*  In case of an error (e.g. invalid keyword, invalid par.)    */
/*  the error together with the actual record is stacked  	*/
/*  in function "is_record_correct" with "aux_add_error()".	*/
/*  								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   fp_conf			Pointer to configuration file 	*/
/*   *par_in_record		Pointer to structure.		*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   par_in_record		If not EOF, this structure	*/
/*			        contains the correct par.	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  ERR_flag		       Error			       	*/
/*  EOF_flag		       EOF found		       	*/
/*  EOF_with_ERR	       Error and EOF found	       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   is_record_correct()       Check whether parameter in record*/
/*			       are correct and return the par.  */
/*   is_record_relevant()      Check whether read record is a 	*/
/*			       comment record. 		        */
/*   read_record()	       Read one record from file.	*/
/*--------------------------------------------------------------*/
static
int 
get_next_correct_record(fp_conf, par_in_record)
	FILE           *fp_conf;
	ParInRecord    *par_in_record;
{


	int             function_rc = 0;
	Boolean         found_relevant_record = FALSE;
	Boolean         found_correct_record = FALSE;
	char            record[MAX_RECORD + 1];	/* one character for '\0'             */
	int             rc;

	char           *proc = "get_next_correct_record";

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  get_next_correct_record\n\n");*/
#endif


	do {

		rc = read_record(fp_conf, record, MAX_RECORD);

		if (rc != EOF_flag) {
			found_relevant_record = is_record_relevant(record);
			if (found_relevant_record == TRUE) {
				found_correct_record = is_record_correct(record, par_in_record);
				if (found_correct_record == FALSE)
					function_rc = ERR_flag;
			}
		}
	} while ((found_correct_record == FALSE) && (rc != EOF_flag));


	/*
	 * Return value
	 */

	if (rc == EOF_flag) {
		if (function_rc == ERR_flag)
			return (EOF_with_ERR);
		else
			return (EOF_flag);
	} else
		return (function_rc);

}				/* end get_next_correct_record */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  read_record					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Read one record or max n chars from file. The read chars	*/
/*  are concatenated with '\0' and returned in parameter 	*/
/*  "record".						        */
/*  								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   fp_conf			Pointer to configuration file 	*/
/*   rmax			Max no. of chars to be read.	*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   record			Read record			*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*  EOF_flag		       EOF found		       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
read_record(fp, record, rmax)
	FILE           *fp;
	char            record[];
	int             rmax;
{

	int             ctr;	/* counter for read chars */
	int             c;	/* single read character */
	int             NL_found;


#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  read_record\n\n");*/
#endif

	ctr = 0;
	NL_found = 0;


	do {
		c = getc(fp);
		if (c != EOF) {
			if (c == '\n')
				NL_found = 1;
			record[ctr] = c;
			ctr++;
		}		/* end if */
	} while ((c != EOF) && (ctr < rmax) && (NL_found == 0));

	if (NL_found == 1) {
		record[ctr - 1] = '\0';
		return (ctr);
	}
	if (c == EOF)
		return (EOF_flag);


	record[ctr] = '\0';
	return (ctr);		/* return number of read characters */


}				/* read_record */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  is_record_relevant				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check delivered record and 					*/
/*        return FALSE, if record is empty or			*/
/*        	        if record consists of blanks or		*/
/*                      if record contains a comment.		*/
/*  Otherwise tailing comments are cut off in record and TRUE is*/
/*  returned.							*/
/*  The delivered record is supposed to be a string (null-	*/
/*  terminated). 						*/
/*  								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE	         	Record is relevant.       	*/
/*   FALSE	         	Record is not relevant.       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
is_record_relevant(record)
	char           *record;
{


	int             i, ind;
	Boolean         relevant_sign_found;
	Boolean         comment_sign_found;
	char           *ptr_to_comment;

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  is_record_relevant\n\n");*/
#endif


	/*
	 * is record empty ?
	 */

	if ((record == CNULL) || (strlen(record) == 0))
		return (FALSE);


	/* get first character which is != BLANK, COMMENT, TAB */

	i = 0;
	relevant_sign_found = FALSE;
	while ((i < strlen(record)) &&
	       (record[i] != COMMENT) && (relevant_sign_found == FALSE)) {

		if ((record[i] == BLANK_CHAR) ||
		    (record[i] == TAB) ||
		    (record[i] == CR_CHAR))
			i++;
		else
			relevant_sign_found = TRUE;
	}			/* end while */


	if (relevant_sign_found == FALSE)
		return (FALSE);	/* record not relevant */


	/* cut off tailing comment in relevant record */
	comment_sign_found = FALSE;
	while ((i < strlen(record)) && (comment_sign_found == FALSE)) {

		if (record[i] == COMMENT) {
			record[i] = '\0';
			comment_sign_found = TRUE;
		} else
			i++;
	}			/* end while */


	return (TRUE);

}				/* is_record_relevant */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  is_record_correct		      		       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check wether record contains correct parameters. If values  */
/*  are correct, all parameters are returned in "par_in_record".*/
/*								*/
/*  In case of an error (e.g. invalid keyword, invalid par.)    */
/*  the error together with the actual record is stacked with 	*/
/*  "aux_add_error()" and FALSE is returned.		 	*/
/*  								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   record			Pointer to the record to be	*/
/*				checked.		 	*/
/*   *par_in_record		Pointer to structure.		*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   par_in_record		In case of correct parameter    */
/*				values, this structure		*/
/*			        contains the correct par.	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE	               Record is correct.	       	*/
/*   FALSE		       Record contains invalid values.	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   char2int()		       Transform ASCII string to integer*/
/*			       value.				*/
/*   get_next_word_from_record() Return next word in record.	*/
/*   get_obj_par()	       Get object parameters from read  */
/*			       record.				*/
/*   is_char_relevant()	       Check whether character is       */
/*			       relevant.			*/
/*   aux_add_error()	       Add error to error stack.	*/
/*--------------------------------------------------------------*/
static
Boolean 
is_record_correct(record, par_in_record)
	char            record[];
	ParInRecord    *par_in_record;
{


	Boolean         found_relevant_record = FALSE;
	int             rindex;	/* index for record 	              */

	/* where to start read word in record */
	int             rc;
	char           *word;	/* one word in record	              */
	Boolean         flag;

	char           *proc = "is_record_correct";

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  is_record_correct\n\n");*/
#endif


/*******************************************************************************************/
/*
 * Input:		 1. A relevant record.
 *			 2. A tailing comment has been cut off.
 *			 3. record is a null-terminated string.
 *
 * Next to do:		 1. Get first word in record, which is supposed to be one of the
 *		            following keywords: APP_KEY_WORD, OBJ_KEY_WORD, IGN_KEY_WORD
 *			 2. Get the parameters according to the keyword
 */


#ifdef CONFIGTEST
	if (record)
		fprintf(stderr, " relevant record: \n%s\n\n", record);
#endif

	/*
	 * get keyword (first word in record)
	 */

	rindex = 0;
	word = get_next_word_from_record(record, &rindex);
	if ((word == CNULL) || (strlen(word) == 0)) {
		aux_add_error(ECONFIG, "PAR: No keyword found in record", record, char_n, proc);
		return (FALSE);
	}

	/*
	 * keyword  analyse
	 */

	if (!strncmp(word, OBJ_KEY_WORD, strlen(OBJ_KEY_WORD)))
		par_in_record->par_type = OBJ_NAME;
	else if (!strncmp(word, APP_KEY_WORD, strlen(APP_KEY_WORD)))
		par_in_record->par_type = APP_NAME;
	else if (!strncmp(word, IGN_KEY_WORD, strlen(IGN_KEY_WORD)))
		par_in_record->par_type = IGNORE;
	else if (!strncmp(word, SC_ENC_KEY_WORD, strlen(SC_ENC_KEY_WORD)))
		par_in_record->par_type = SC_ENCRYPT;
	else if (!strncmp(word, SC_VER_KEY_WORD, strlen(SC_VER_KEY_WORD)))
		par_in_record->par_type = SC_VERIFY;

	else {
		par_in_record->par_type = NO_KEYWORD;
		free(word);
		aux_add_error(ECONFIG, "PAR: Unknown keyword found in record", record, char_n, proc);
		return (FALSE);
	}			/* end else */
	free(word);


	/*
	 * get parameters depending on keyword
	 */

	switch (par_in_record->par_type) {

	case OBJ_NAME:
		/* init object name */
		par_in_record->conf_par.obj_par.name = CNULL;

		/* get object parameters */
		rc = get_obj_par(record, &rindex, &par_in_record->conf_par.obj_par);
		if (rc == ERR_flag) {
/*	                    aux_add_error(ECONFIG, "PAR: Invalid parameter for object in record", record, char_n, proc); */
			if (par_in_record->conf_par.obj_par.name != CNULL)
				free(par_in_record->conf_par.obj_par.name);
			return (FALSE);
		}
		break;

	case APP_NAME:
		/* get app_name */
		word = get_next_word_from_record(record, &rindex);
		if ((word == CNULL) || (strlen(word) == 0)) {
			aux_add_error(ECONFIG, "PAR: No application name found in record", record, char_n, proc);
			return (FALSE);
		}
		par_in_record->conf_par.app_name = word;
		break;

	case IGNORE:
	case SC_ENCRYPT:
	case SC_VERIFY:
		/* get_boolean_flag */
		par_in_record->conf_par.boolean_flag = TRUE;

		word = get_next_word_from_record(record, &rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if (!strncmp(word, TRUE_WORD, strlen(TRUE_WORD)))
				par_in_record->conf_par.boolean_flag = TRUE;
			else if (!strncmp(word, FALSE_WORD, strlen(FALSE_WORD)))
				par_in_record->conf_par.boolean_flag = FALSE;
			else {
				aux_add_error(ECONFIG, "PAR: Invalid boolean flag in record", record, char_n, proc);
				free(word);
				return (FALSE);
			}
		}		/* end if */
		free(word);

		break;


	default:
		par_in_record->par_type = NO_KEYWORD;
		aux_add_error(ECONFIG, "PAR: Unknown keyword found in record", record, char_n, proc);
		return (FALSE);

	}			/* end switch */


	return (TRUE);


}				/* is_record_correct */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_obj_par					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Get parameters for object from delivered record.		*/
/*								*/
/*  The delivered record is supposed to be a string (null-	*/
/*  terminated).  This function gets the parameters from record */
/*  from the offset record + *rindex.				*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   record			Pointer to record.		*/
/*   rindex			Pointer to index in record.	*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*   obj_par			Parameters for object.    	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*   ERR_flag		       error				*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   char2int()		       Transform ASCII string to integer*/
/*			       value.				*/
/*   get_next_word_from_record() Return next word in record.	*/
/*   is_char_relevant()	       Check whether character is       */
/*			       relevant.			*/
/*--------------------------------------------------------------*/
static
int 
get_obj_par(record, rindex, obj_par)
	char           *record;
	int            *rindex;
	SCObjEntry     *obj_par;

{


	int             i;
	char           *word;
	int             no;
	SecMessMode     sm_list[NO_OF_SM];

	char           *proc = "get_obj_par";




	/*
	 * get object_name
	 */

	word = get_next_word_from_record(record, rindex);
	if ((word == CNULL) || (strlen(word) == 0)) {
		aux_add_error(ECONFIG, "PAR: No object name found in record", record, char_n, proc);
		return (ERR_flag);
	}
	obj_par->name = word;


	/*
	 * get type
	 */

	word = get_next_word_from_record(record, rindex);
	if ((word != CNULL ) && (strlen(word) != 0)) {
		if (!strncmp(word, SC_KEY_WORD, strlen(SC_KEY_WORD)))
			obj_par->type = SC_KEY_TYPE;
		else if (!strncmp(word, SC_FILE_WORD, strlen(SC_FILE_WORD)))
			obj_par->type = SC_FILE_TYPE;
		else {
			aux_add_error(ECONFIG, "PAR: Invalid type of object in record", record, char_n, proc);
			free(word);
			return (ERR_flag);
		}
	}
	 /* end if */ 
	else {
		aux_add_error(ECONFIG, "PAR: Type of object in record missing", record, char_n, proc);
		return (ERR_flag);
	}
	free(word);


	/*
	 * get id depending on type
	 */


	switch (obj_par->type) {

	case SC_KEY_TYPE:

		/*
		 * get level of key on SC
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if (!strncmp(word, DF_WORD, strlen(DF_WORD)))
				obj_par->sc_id.level = DF_LEVEL;
			else if (!strncmp(word, MF_WORD, strlen(MF_WORD)))
				obj_par->sc_id.level = MF_LEVEL;
			else if (!strncmp(word, SF_WORD, strlen(SF_WORD)))
				obj_par->sc_id.level = SF_LEVEL;
			else {
				aux_add_error(ECONFIG, "PAR: Invalid level of key object in record", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
		}
		 /* end if */ 
		else {
			aux_add_error(ECONFIG, "PAR: Level of key object in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);


		/*
		 * get key number
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if ((no = char2int(word)) < 0) {
				aux_add_error(ECONFIG, "PAR: Invalid key number in record ", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
			obj_par->sc_id.no = no;

		} else {
			aux_add_error(ECONFIG, "PAR: Key number in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);

		/* init parameters which are not used for a key_id */
		obj_par->sc_id.type = 0;
		obj_par->size = 0;

		break;

	case SC_FILE_TYPE:

		/*
		 * get level of file on SC
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if (!strncmp(word, DF_WORD, strlen(DF_WORD)))
				obj_par->sc_id.level = DF_LEVEL;
			else if (!strncmp(word, MF_WORD, strlen(MF_WORD)))
				obj_par->sc_id.level = MF_LEVEL;
			else if (!strncmp(word, SF_WORD, strlen(SF_WORD)))
				obj_par->sc_id.level = SF_LEVEL;
			else {
				aux_add_error(ECONFIG, "PAR: Invalid level of file object in record", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
		}
		 /* end if */ 
		else {
			aux_add_error(ECONFIG, "PAR: Level of file object in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);


		/*
		 * get type of file on SC
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if (!strncmp(word, WEF_WORD, strlen(WEF_WORD)))
				obj_par->sc_id.type = WEF;
			else {
				aux_add_error(ECONFIG, "PAR: Invalid type of file object in record", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
		}
		 /* end if */ 
		else {
			aux_add_error(ECONFIG, "PAR: Type of file object in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);


		/*
		 * get file number
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if ((no = char2int(word)) < 0) {
				aux_add_error(ECONFIG, "PAR: Invalid file number in record. ", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
			obj_par->sc_id.no = no;
		} else {
			aux_add_error(ECONFIG, "PAR: File number in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);


		/*
		 * get size = number of bytes to be reserved for WEF file on
		 * SC
		 */

		word = get_next_word_from_record(record, rindex);
		if ((word != CNULL) && (strlen(word) != 0)) {
			if ((no = char2int(word)) <= 0) {
				aux_add_error(ECONFIG, "PAR: Invalid no. of bytes for file on SC.", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
			obj_par->size = no;
		}
		 /* end if */ 
		else {
			aux_add_error(ECONFIG, "PAR: File size in record missing", record, char_n, proc);
			return (ERR_flag);
		}
		free(word);

		break;
	default:
		break;

	}			/* end switch */



	/*
	 * get secure messaging parameters
	 */


	/*
	 * Init with default value SEC_NORMAL
	 */

	for (i = 0; i < NO_OF_SM;)
		sm_list[i++] = SEC_NORMAL;

	i = 0;
	do {
		word = get_next_word_from_record(record, rindex);

		if ((word != CNULL) && (strlen(word) != 0)) {
			if (!strncmp(word, NORM_WORD, strlen(NORM_WORD)))
				sm_list[i++] = SEC_NORMAL;
			else if (!strncmp(word, AUTH_WORD, strlen(AUTH_WORD)))
				sm_list[i++] = AUTHENTIC;
			else if (!strncmp(word, CONC_WORD, strlen(CONC_WORD)))
				sm_list[i++] = CONCEALED;
			else if (!strncmp(word, CONC_WORD, strlen(CONC_WORD)))
				sm_list[i++] = COMBINED;
			else {
				aux_add_error(ECONFIG, "PAR: Invalid secure messaging parameter for object in record", record, char_n, proc);
			        free(word);
				return (ERR_flag);
			}
			free(word);
		}		/* end if */
	} while ((i < NO_OF_SM) && (word != CNULL));


	obj_par->sm_SCT = sm_list[0];
	obj_par->sm_SC_read.command = sm_list[1];
	obj_par->sm_SC_read.response = sm_list[2];
	obj_par->sm_SC_write.command = sm_list[3];
	obj_par->sm_SC_write.response = sm_list[4];


	return(0);

}				/* get_obj_par */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_next_word_from_record			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  This function returns the next word found in record from the*/
/*  offset record + *rindex.					*/
/*  The null-pointer is returned, if no word could be found.	*/
/*  The value of *rindex is incremented and points to the next  */
/*  character in record after the returned word.		*/
/*  Memory for the returned word is allocated by this function.	*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   record			Pointer to record.		*/
/*							       	*/
/* INOUT						       	*/
/*   rindex			Pointer to index in record.	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   NULL	         	No word found 		       	*/
/*   ptr. to word					       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   is_char_relevant()	       Check whether character is       */
/*			       relevant.			*/
/*--------------------------------------------------------------*/
static
char           *
get_next_word_from_record(record, rindex)
	char           *record;
	int            *rindex;
{

	char           *word;
	int             i;
	int             start_word;
	int             len_word;

	char           *proc = "get_next_word_from_record";

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  get_next_word_from_record\n\n");*/
#endif


	/*
	 * input check
	 */

	if ((record == CNULL) || (strlen(record) == 0) || (*rindex >= strlen(record))) {
		return (CNULL);
	}

	/*
	 * jump over all leading not relevant characters
	 */

	while ((*rindex < strlen(record)) && ((is_char_relevant(record[*rindex])) == FALSE)) {

		(*rindex)++;

	}


	if (*rindex >= strlen(record))
		return (CNULL);	/* no relevant character found */


	/*
	 * get relevant characters until first not relevant character
	 */

	start_word = *rindex;
	len_word = 0;

	while ((*rindex < strlen(record)) && ((is_char_relevant(record[*rindex])) == TRUE)) {

		(*rindex)++;

	}


	/*
	 * allocate memory for word, get word from record and return ptr to
	 * word.
	 */

	len_word = *rindex - start_word;


#ifdef CONFIGTEST
/*	fprintf(stderr, "in record: %s\n", record);
	fprintf(stderr, "strlen(record): %d\n", strlen(record));
	fprintf(stderr, "start_word: %d\n", start_word);
	fprintf(stderr, "len_word: %d\n", len_word);
	fprintf(stderr, "*rindex: %d\n", *rindex);*/

#endif



	if (len_word <= 0)
		return (CNULL);

	word = (char *) malloc(len_word + 1);
	if (!word) {
		aux_add_error(EMALLOC, "Word", CNULL, 0, proc);
		return (CNULL);
	}
	for (i = 0; i < len_word;)
		word[i++] = record[start_word++];
	word[i] = '\0';		/* terminate word with null */

#ifdef CONFIGTEST
/*	fprintf(stderr, "\nfound word: %s\n\n", word);*/

#endif


	return (word);

}				/* get_next_word_from_record */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  is_char_relevant				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Return TRUE if delivered character is  relevant else return */
/*  FALSE.							*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   one_char			One character.			*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   TRUE         	       Character is relevant.	       	*/
/*   FALSE         	       Character is not relevant.      	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
Boolean 
is_char_relevant(one_char)
	char            one_char;
{

	char           *proc = "is_char_relevant";



	if (!one_char)
		return (FALSE);

	if ((one_char == BLANK_CHAR) ||
	    (one_char == COMMENT) ||
	    (one_char == COMMA) ||
	    (one_char == TAB) ||
	    (one_char == EQUAL) ||
	    (one_char == CR_CHAR) ||
	    (one_char == '\n') ||
	    (one_char == '\0'))
		return (FALSE);


	return (TRUE);

}				/* is_char_relevant */





/*--------------------------------------------------------------*/
/*						                */
/* PROC  check_app_name					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check whether the actual read application name is unique in */
/*  "sc_app_list[]".			   	    		*/
/*								*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   read_app_name		application name		*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*   ERR_flag		       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
check_app_name(read_app_name)
	char           *read_app_name;
{

	char           *proc = "check_app_name";

#ifdef CONFIGTEST
	fprintf(stderr, "READ_CONFIG function:  check_app_name\n\n");
#endif


	/* check the given app_name */
	if (read_app_name) {
		if (strlen(read_app_name) > MAXL_APPNAME) {
			aux_add_error(ECONFIG, "PAR: Application name too long", read_app_name, char_n, proc);
			return (ERR_flag);
		}
	} else {
		aux_add_error(ECONFIG, "PAR: Application name empty", CNULL, 0, proc);
		return (ERR_flag);
	}


	if (aux_AppName2SCApp(read_app_name)) {
		aux_add_error(ECONFIG, "PAR: Application name not unique.", read_app_name, char_n, proc);
		return (ERR_flag);
	}
	return (0);

}				/* check_app_name */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  handle_mandatory_obj				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check whether object list contains all mandatory objects    */
/*  ("man_sc_obj_list[]"). If a mandatory object is missing, the*/
/*  default values for this object is added to the current 	*/
/*  object list ( in this case memory for the object name is	*/
/*  allocated explicitly => it can be released with free().	*/
/*								*/
/*  The global list "man_sc_obj_list[]" contains the list of the*/
/*  mandatory objects.						*/
/*  The global list "default_sc_obj_list[]" contains the list of*/
/*  the  defaults values for objects.				*/
/*  								*/
/*  If the number of objects is greater	than MAX_SCOBJ, ERR_flag*/
/*  is returned.				 		*/
/*  								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   sc_app_entry		One entry in SC application     */
/*                              list.				*/
/*   								*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*   ERR_flag		       Error			      	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   get_default_index()       Get index in default object list.*/
/*--------------------------------------------------------------*/
static
int 
handle_mandatory_obj(sc_app_entry)
	SCAppEntry     *sc_app_entry;
{

	int             n, i;
	int             def_ind;
	Boolean         man_obj_found;

	char           *proc = "handle_mandatory_obj";

#ifdef CONFIGTEST
/*	   fprintf(stderr, "READ_CONFIG function:  handle_mandatory_obj\n\n");*/
#endif

	if (!sc_app_entry) {
		aux_add_error(ECONFIG, "Invalid parameter value for sc_app_entry", CNULL, 0, proc);
		return (ERR_flag);
	}

	/*
	 * Loop for the list of the mandatory objects:
	 */

	for (n = 0; man_sc_obj_list[n]; n++) {

		man_obj_found = FALSE;
		i = 0;
		while ((i <= MAX_SCOBJ) &&
		       (sc_app_entry->sc_obj_list[i].name) && (man_obj_found == FALSE)) {

			if (strcmp(sc_app_entry->sc_obj_list[i].name, man_sc_obj_list[n]) == 0)
				man_obj_found = TRUE;
			else
				i++;
		}		/* end while */


		if (man_obj_found == FALSE) {

			/*
			 * Mandatory object missing in object list => add
			 * mandatory object.
			 */

			if (i >= MAX_SCOBJ) {
				aux_add_error(ECONFIG, "OBJ: Too many objects for application ", sc_app_entry->app_name, char_n, proc);
				return (ERR_flag);
			}
			def_ind = get_default_index(man_sc_obj_list[n]);
			if ((def_ind < 0) || (!default_sc_obj_list[def_ind].name)) {
				aux_add_error(ECONFIG, "OBJ: Invalid default list for object ", man_sc_obj_list[n], char_n, proc);
				return (ERR_flag);
			}
			sc_app_entry->sc_obj_list[i] = default_sc_obj_list[def_ind];


			/*
			 *  Allocate memory for object name
			 *  => free(obj_name) causes no error
			 */

	                sc_app_entry->sc_obj_list[i].name = (char *) malloc (strlen(default_sc_obj_list[def_ind].name));
			if (!sc_app_entry->sc_obj_list[i].name) {
				aux_add_error(EMALLOC, "object name", CNULL, 0, proc);
				return (ERR_flag);
			}
			strcpy (sc_app_entry->sc_obj_list[i].name, default_sc_obj_list[def_ind].name);

			i++;
			sc_app_entry->sc_obj_list[i].name = CNULL;

		}		/* end if */
	}			/* end for */

	return (0);


}				/* handle_mandatory_obj */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  get_default_index				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Get index in default object list ("sc_obj_list[]") for the  */
/*  delivered object name.					*/
/*  								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   object_name		Object name.			*/
/*   								*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   index (>= 0)	       Index in default object list.  	*/
 /*   ERR_flag		       No entry found.			*//* */
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
get_default_index(object_name)
	char           *object_name;
{
	int             n;
	char           *proc = "get_default_index";

	if (!object_name) {
		aux_add_error(ECONFIG, "OBJ: Invalid object_name ", CNULL, 0, proc);
		return (ERR_flag);
	}
	for (n = 0; default_sc_obj_list[n].name; n++) {
		if (strcmp(default_sc_obj_list[n].name, object_name) == 0)
			return (n);
	}

	return (ERR_flag);


}				/* end get_default_index */




/*--------------------------------------------------------------*/
/*						         	*/
/* PROC  check_SCapp_configuration			       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check consistency of configuration data for an SC-		*/
/*  application.	    					*/
/*								*/
/*								*/
/*  1) Perform SC configuration (read SC configuration file 	*/
/*     (".scinit")).       					*/
/*								*/
/*  2) Check whether given application (app_name) is an 	*/
/*     SC-application.   					*/
/*     								*/
/*     Case 1:  Application is an SC-application:		*/
/*	        Depending on the value of the parameter 	*/
/*	        "onekeypair" it is checked whether the 		*/
/*		configuration file contains the necessary	*/
/*		objects for this kind of application.		*/
/*								*/
/*     Case 2: Application is not an SC-application:		*/
/*             => return error					*/
/*  								*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   app_name		       Name of the application for which*/
/*			       the configuration data shall be  */
/*			       checked.				*/
/*   onekeypair		       TRUE means that the application  */
/*			            works with one RSA keypair.	*/
/*			       FALSE means that the application */
/*			             works with two RSA 	*/
/*				     keypairs.			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0		  	       Configuration data for the given */
/*			       application are consistent.	*/
/*   -1		               - Necessary objects missing in	*/
/*			         configuration data.		*/
/*   		               - error (e.g. application not an */
/*			         SC-application)		*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*   check_config_list()	Check whether the object list of*/
/*				an SC-application contains all  */
/*				mandatory objects.		*/
/*   aux_AppName2SCApp()	Get information about an SC app.*/
/*   aux_add_error()		Add error to error stack.	*/
/*			         		       		*/
/*--------------------------------------------------------------*/

RC 
check_SCapp_configuration(app_name, onekeypair)
	char             *app_name;
	Boolean		  onekeypair;
{

	int		SC_available;
	SCAppEntry     *sc_app_entry;
	Boolean		data_consistent;



	char            *proc = "check_SCapp_configuration";



#ifdef SECSCTEST
	fprintf(stderr, "SECSC-Function: %s\n", proc);
	fprintf(stderr, "                   Application-Name: %s\n", app_name);
	if (onekeypair == TRUE)
		fprintf(stderr, "                with onekeypair\n");
	else	fprintf(stderr, "                with twokeypairs\n");

#endif


	if (app_name == CNULL) {
		aux_add_error(EINVALID, "No application name specified", CNULL, 0, proc);
		return (-1);
	}


	/*
	 *  Perform SC configuration
	 */

	if ((SC_available = SC_configuration()) == -1) {
		aux_add_error(ECONFIG, "Error during SC configuration.", CNULL, 0, proc);
		return (-1);
	}
	if (SC_available == FALSE) {

		/*
		 *  no SC configuration file found)
		 */

		aux_add_error(ECONFIG, "No SC configuration file found.", CNULL, 0, proc);
		return (-1);
	}



	/*
	 *  Check whether application is an SC-application
	 */

	sc_app_entry = aux_AppName2SCApp(app_name);
	if (sc_app_entry == (SCAppEntry * ) 0) 	{
		aux_add_error(EINVALID, "Application is not an SC-application", CNULL, 0, proc);
		return (-1);
	}


	/*
	 *  Check consistency of the configuration data for the given application.
	 */

	if (onekeypair == TRUE) 
		data_consistent = check_config_list(sc_app_entry, onekeypair_sc_obj_list);
	else 	data_consistent = check_config_list(sc_app_entry, twokeypairs_sc_obj_list);


	if (data_consistent == -1) {
		aux_add_error(EOBJ, "Inconsistent configuration data for SC-application ", app_name, char_n, proc);	
		return (-1);
	}

	return (0);


}				/* end check_SCapp_configuration */




/*--------------------------------------------------------------*/
/*						                */
/* PROC  check_config_list				       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check whether a given object list of an SC-application 	*/
/*  contains all mandatory objects.				*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   sc_app_entry		One entry in SC application     */
/*                              list.				*/
/*   man_obj_list		List of the mandatory objects.  */
/*   								*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0		         	All mandatory objects found in  */
/*				given "sc_app_entry".		*/
/*   -1			      	Objects missing.	      	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
check_config_list(sc_app_entry, man_obj_list)
	SCAppEntry     *sc_app_entry;
	char	       *man_obj_list[];
{

	int             n, i;
	Boolean         man_obj_found;

	char           *proc = "check_config_list";


	if (!sc_app_entry) {
		aux_add_error(EINVALID, "Invalid parameter value for sc_app_entry", CNULL, 0, proc);
		return (-1);
	}

	/*
	 * Loop for the list of the mandatory objects:
	 */

	for (n = 0; man_obj_list[n]; n++) {

		man_obj_found = FALSE;
		i = 0;
		while ((i <= MAX_SCOBJ) &&
		       (sc_app_entry->sc_obj_list[i].name) && (man_obj_found == FALSE)) {

			if (strcmp(sc_app_entry->sc_obj_list[i].name, man_obj_list[n]) == 0)
				man_obj_found = TRUE;
			else
				i++;
		}		/* end while */


		if (man_obj_found == FALSE) {

			/*
			 * Mandatory object missing.
			 */

			aux_add_error(EOBJ, "Mandatory SC-object missing in configuration file", man_obj_list[n], char_n,  proc);
			return (-1);

		}		
	}			

	return (0);


}				/* check_config_list */








/*--------------------------------------------------------------*/
/*						                */
/* PROC  check_obj_info					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Check new object for an application.			*/
/*  (e.g. compare with already entered object for the actual    */
/*   application).						*/
/*								*/
/*								*/
/* IN			     DESCRIPTION		       	*/
/*   sc_app_entry		Entry in sc_app_list for the    */
/*                              actual application.		*/
/*   new_obj_par		Parameter for the new object.	*/
/*   								*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/*							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*   0	         	       o.k			       	*/
/*   ERR_flag		       Error			       	*/
/*							       	*/
/* CALLED FUNCTIONS	     DESCRIPTION		       	*/
/*--------------------------------------------------------------*/
static
int 
check_obj_info(sc_app_entry, new_obj_par)
	SCAppEntry     *sc_app_entry;
	SCObjEntry     *new_obj_par;

{

	char           *proc = "check_obj_info";

#ifdef CONFIGTEST
	fprintf(stderr, "READ_CONFIG function:  check_obj_info\n\n");
#endif


	/* check input parameters */
	if ((!sc_app_entry) || (!sc_app_entry->app_name) ||
	    (!new_obj_par) || (!new_obj_par->name)) {
		aux_add_error(ECONFIG, "PAR: Invalid input values for check_obj_info", CNULL, 0, proc);
		return (ERR_flag);
	}
	if (aux_AppObjName2SCObj(sc_app_entry->app_name, new_obj_par->name)) {
		aux_add_error(ECONFIG, "PAR: Object name not unique", new_obj_par->name, char_n, proc);
		return (ERR_flag);
	}
	return (0);

}				/* check_obj_info */






/*--------------------------------------------------------------*/
/*						                */
/* PROC  char2int					       	*/
/*							       	*/
/* DESCRIPTION						       	*/
/*								*/
/*  Transform an character string (ASCII) into an integer value */
/*  and returns this integer value.			 	*/
/*								*/
/*  If a character in string is not a digit, -1 is returned.	*/
/*							        */
/* IN			     DESCRIPTION		       	*/
/*   s 	   		       Pointer to char_string to be	*/
/*			       transformed.			*/
/*							       	*/
/* OUT							       	*/
/*							       	*/
/* RETURN		     DESCRIPTION	      	       	*/
/*    -1		       Error			        */
/*   int_value	 	       Integer value.			*/
/*--------------------------------------------------------------*/


static
int 
char2int(s)
	char           *s;
{

	unsigned int    n;

	char           *proc = "char2int";

#ifdef CONFIGTEST
	fprintf(stderr, "\nATOI: string: %s", s);
#endif


	if (!s) {
		aux_add_error(ECONFIG, "PAR: ASCII string = NULL", CNULL, 0, proc);
		return (-1);
	}
	n = 0;

	while (*s) {
		if ((*s < '0') || (*s > '9')) {
			aux_add_error(ECONFIG, "PAR: ASCII character is not a digit", CNULL, 0, proc);
			return (-1);
		}
		n = 10 * n + *s - '0';
		s++;
	}

#ifdef CONFIGTEST
	fprintf(stderr, ", integer: %d\n", n);
#endif
	return (n);
}				/* end char2int */


#else			/* SCA */
readconf_dummy()
{
	return(0);
}
#endif				
