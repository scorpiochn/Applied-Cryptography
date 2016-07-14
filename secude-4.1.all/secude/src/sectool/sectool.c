
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

/*-----------------------sectool.c----------------------------------*/
/*                                                                  */
/*------------------------------------------------------------------*/
/* GMD Darmstadt Institute for System Technic (I2)                  */
/* Rheinstr. 75 / Dolivostr. 15                                     */
/* 6100 Darmstadt                                                   */
/* Project ``Secure DFN'' 1990 / "SecuDE" 1991/92/93                */
/* Grimm/Nausester/Schneider/Viebeg/Vollmer 	                    */
/* Luehe/Surkau/Reichelt/Kolletzki		                    */
/*------------------------------------------------------------------*/
/* PACKAGE   util            VERSION   3.0                          */
/*                              DATE   20.01.1992                   */
/*                                BY   ws                           */
/*                                                                  */
/*------------------------------------------------------------------*/
/*                                                                  */
/* PROGRAM   sectool         VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Zhu/Kolletzki                */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/* DESCRIPTION                                                      */
/*   SecTool is an OpenWindows Tool to maintain the PSE             */
/*   based on psemaint.c	    				    */
/*                                                                  */
/* CALLS TO                                                         */
/*                                                                  */
/*                                                                  */
/*                                                                  */
/* USAGE:                                                           */
/*     sectool [-c ca_dir] [-p pse_name] [-d dsaname] [-hmv] 	    */
/*------------------------------------------------------------------*/



#include "sect_inc.h"

static void usage();


/*
 *	SecTool MAIN
 */

int
main(cnt, parm)
	int		cnt;
	char		**parm;
{
	char 		*env_auth_level, *dd;
	char		*proc = "main (sectool)";


	sectool_argc = cnt;
	sectool_argp = parm;

	pgm_name = *sectool_argp;

	if(dd = strrchr(parm[0], '/')) dd++;
	else dd = parm[0];
        if(!strcmp(dd, "aliastool")) alias_tool = TRUE;
        if(!strcmp(dd, "directorytool")) directory_tool = TRUE;

	if (! (unix_home = getenv("HOME")) || !strlen(unix_home))  {

		fprintf(stderr, "SECTOOL: Can't get $HOME from environment !\n");
		exit(-1);
	}

	strcpy(tempfile, unix_home);
	strcat(tempfile, TEMP_FILE);
	strcpy(rmtemp, "rm -rf ");
	strcat(rmtemp, tempfile);

	strcpy(user_aliasfile, unix_home);
	strcat(user_aliasfile, ALIAS_FILE);
	strcpy(system_aliasfile, AFDBFILE);
	strcat(system_aliasfile, ALIAS_FILE);

	/* 
	 * 	get X args, Initialize XView.
	 */
	xv_init(XV_INIT_ARGC_PTR_ARGV, &sectool_argc, sectool_argp, NULL);

	/* 
	 *      get SecuDE args
	 */

	optind = 1;
	opterr = 0;

#ifdef X500
	af_x500_vecptr = (char**)calloc(30,sizeof(char*));			/* used for dsap_init() in af_dir.c */
	af_x500_count  = 1;	/* default, binding to local DSA */
	dsap_index = 4;
	callflag = "-call";
	auth_level = DBA_AUTH_SIMPLE;
#endif


#ifdef X500
	while ( (opt = getopt(sectool_argc, sectool_argp, "c:p:d:AhtvVWh")) != -1 ) switch(opt) {
#else
	while ( (opt = getopt(sectool_argc, sectool_argp, "c:p:htvVWh")) != -1 ) switch(opt) {
#endif
		case 'h':
			usage(LONG_HELP);
			continue;
		case 'c':
			ca_dir = optarg;
			continue;
		case 'p':
			pse_name = optarg;
			continue;
#ifdef X500
		case 'A':
			if (! strcasecmp(optarg, "STRONG"))
				auth_level = DBA_AUTH_STRONG;
			else if (! strcasecmp(optarg, "SIMPLE"))
				auth_level = DBA_AUTH_SIMPLE;
			break;
		case 'd':
			af_x500_count = 3;
			af_x500_vecptr[0] = sectool_argp[0];
			af_x500_vecptr[1] = (char *)malloc(strlen(callflag) + 1);
			strcpy(af_x500_vecptr[1],callflag);
			af_x500_vecptr[2] = (char *)malloc(strlen(optarg) + 1);
			strcpy(af_x500_vecptr[2], optarg);
			af_x500_vecptr[3] = CNULL;
			i = sectool_argc+1;
			while (sectool_argp[i])
				af_x500_vecptr[dsap_index++] = sectool_argp[i++];
			continue;
#endif
		case 't':							
			MF_check = TRUE;
			break;
		case 'v':							
			verbose = TRUE;
			break;
		case 'V':
			sectool_verbose = TRUE;
			break;
		case 'W':
			sec_verbose = TRUE;
			break;
		default:
			usage(SHORT_HELP);
	}                    


	if (sectool_verbose && MF_check && sectool_verbose) sec_debug = 2;		/* print all allocation stuff to stderr */

	while (optind < sectool_argc) {

		if(strlen(inp)) strcat(inp, " ");
		strcat(inp, sectool_argp[optind++]);
		interactive = FALSE;
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
#endif

	/* pse stuff only for complete SecTool, not used in alias-/directory-subtool */ 
	if (!alias_tool && !directory_tool)  {
	
		if(!pse_name)  {

			if(ca_dir) pse_name = DEF_CAPSE;
			else pse_name = DEF_PSE;
		}
	
		if(ca_dir)   {

			pse_path = (char *)malloc(strlen(ca_dir)+strlen(pse_name) + 2);
			strcpy(pse_path, ca_dir);
			if(pse_path[strlen(pse_path) - 1] != '/') strcat(pse_path, "/");
			strcat(pse_path, pse_name);

		} else  {

			pse_path = (char *)malloc(strlen(pse_name) + 2);
			strcpy(pse_path, pse_name);
		}
	}

	
	/*
	 *	Initialize user interface components.
	 */

	INSTANCE = xv_unique_key();
	get_xdefaults();

	/*
	 *	Alias Subtool
	 */
	if (alias_tool)  {

		if (sectool_verbose) fprintf(stderr, "--> MAIN Init: starting Alias Tool...");

		sectxv_alias_window = sectxv_alias_window_objects_initialize(NULL, NULL);

		notify_interpose_destroy_func(sectxv_alias_window->alias_window, alias_destroy_func);

		/* Basics for this display */
		get_root_basics(sectxv_alias_window->alias_window);

		/*
		 * Turn control over to XView.
		 */
		xv_main_loop(sectxv_alias_window->alias_window);
	} 

	/*
	 *	Directory Subtool
	 */
	if (directory_tool)  {

		if (sectool_verbose) fprintf(stderr, "--> MAIN Init: starting Directory Tool...");

		sectxv_dir_window = sectxv_dir_window_objects_initialize(NULL, NULL);

		notify_interpose_destroy_func(sectxv_dir_window->dir_window, dir_destroy_func);

		/* Basics for this display */
		get_root_basics(sectxv_dir_window->dir_window);

		/*
		 * Turn control over to XView.
		 */
		xv_main_loop(sectxv_dir_window->dir_window);
	} 

	/*
	 *	complete SecTool
	 */
	if (!alias_tool && !directory_tool)  {

		sectxv_alias_window = (sectxv_alias_window_objects *) 0;

		sectxv_base_window = sectxv_base_window_objects_initialize(NULL, NULL);
		sectxv_key_popup = sectxv_key_popup_objects_initialize(NULL, sectxv_base_window->base_window);
		sectxv_ca_popup = sectxv_ca_popup_objects_initialize(NULL, sectxv_base_window->base_window);
		sectxv_chpin_popup = sectxv_chpin_popup_objects_initialize(NULL, sectxv_base_window->base_window);
		sectxv_pin_popup = sectxv_pin_popup_objects_initialize(NULL, sectxv_base_window->base_window);	
		sectxv_create_popup = sectxv_create_popup_objects_initialize(NULL, sectxv_base_window->base_window);
		sectxv_addalias_popup = sectxv_addalias_popup_objects_initialize(NULL, sectxv_base_window->base_window);

		notify_interpose_destroy_func(sectxv_base_window->base_window, base_destroy_func);

		/* Basics for this display */
		get_root_basics(sectxv_base_window->base_window);
	
		/* keep CA panels inactive for PSE session */
		if (!ca_dir)  {

			SECTXV_INACTIVE(sectxv_base_window->ca_button);
			SECTXV_INACTIVE(sectxv_base_window->base_ca_textfield);
		}
		
		/* start with small base_window version (don't show EKList-Panels) */
		xv_set(sectxv_base_window->base_window, XV_HEIGHT, SECTXV_SMALL_BASE_HEIGHT, NULL);
	
		/* enter pin popup init */
		xv_set(sectxv_pin_popup->pin_popup,		FRAME_SHOW_HEADER,	FALSE,
								NULL);
		xv_set(sectxv_pin_popup->pin_textfield,		PANEL_MASK_CHAR, 	'*',
								NULL);
	
		/* change pin popup init */
		xv_set(sectxv_chpin_popup->chpin_popup,		FRAME_SHOW_HEADER,	FALSE,
								NULL);
		xv_set(sectxv_chpin_popup->chpin_old_textfield,	PANEL_MASK_CHAR, 	'*',
								NULL);
		xv_set(sectxv_chpin_popup->chpin_new_textfield,	PANEL_MASK_CHAR, 	'*',
								NULL);
		xv_set(sectxv_chpin_popup->chpin_re_textfield,	PANEL_MASK_CHAR, 	'*',
								NULL);
	
		/* create popup init */
		xv_set(sectxv_create_popup->create_popup,	FRAME_SHOW_HEADER,	FALSE,
								NULL);
	
		if (verbose) fprintf(stderr, "--> MAIN Init: starting SecTool with ca_dir = %s, pse_name = %s, pse_path = %s\n",
			ca_dir, pse_name, pse_path);
					
		/*
		 * Turn control over to XView.
		 */
		xv_main_loop(sectxv_base_window->base_window);
	}


	exit(0);

}







/*
 * *** *** *** *** *** ***
 * 	Non-XView stuff
 * *** *** *** *** *** ***
 */



/*
 *	SecTool usage help
 */

static
void usage(help)
int     help;
{

	aux_fprint_version(stderr);

	fprintf(stderr, "sectool: Maintain your PSE\n");
	fprintf(stderr, "aliastool: Maintain your aliases (Alias sub-tool of sectool)\n");
	fprintf(stderr, "directorytool: Access Directory (Directory sub-tool of sectool)\n\n\n");
	fprintf(stderr, "Description:\n\n"); 
	fprintf(stderr, "'sectool' is, like psemaint,  a maintenance program which can be used by both\n");
	fprintf(stderr, "certification authority administrators and users for the purpose\n");
	fprintf(stderr, "of maintaining their PSEs. This includes moving information (e.g. keys,\n");
	fprintf(stderr, "certificates, revocation lists etc.) from Unix files or a X.500 Directory\n");
	fprintf(stderr, "into the PSE and vice versa, generating keys, changing PINs, displaying\n"); 
	fprintf(stderr, "the content of the PSE, and maintaining the user's aliases. In contrast\n");
        fprintf(stderr, "to psemaint, which is line-oriented, sectool is an OpenWindows tool.\n\n\n");

        fprintf(stderr, "usage:\n\n");
#ifdef X500
	fprintf(stderr, "sectool [-tADvVWh] [-p <pse>] [-c <cadir>] [-d <dsa name>]\n");
#else 
	fprintf(stderr, "sectool [-tADvVWh] [-p <pse>] [-c <cadir>]\n");
#endif   
#ifdef X500
	fprintf(stderr, "aliastool [-tDvVWh] [-p <pse>] [-c <cadir>] [-d <dsa name>]\n");
#else 
	fprintf(stderr, "aliastool [-tDvVWh] [-p <pse>] [-c <cadir>]\n");
#endif   
#ifdef X500
	fprintf(stderr, "directorytool [-tADvVWh] [-p <pse>] [-c <cadir>] [-d <dsa name>]\n");
#else 
	fprintf(stderr, "directorytool [-tADvVWh] [-p <pse>] [-c <cadir>]\n");
#endif   

        if(help == LONG_HELP) {

        fprintf(stderr, "with:\n\n");
        fprintf(stderr, "-p <psename>        PSE name (default: environment variable PSE or .pse)\n");
        fprintf(stderr, "-c <cadir>          Name of CA-directory (default: environment variable CADIR or .ca)\n");
	fprintf(stderr, "-t                  control malloc/free behaviour\n");
        fprintf(stderr, "-v                  verbose\n");
        fprintf(stderr, "-V                  Verbose\n");
        fprintf(stderr, "-W                  Grand Verbose (for testing only)\n");
#ifdef X500
	fprintf(stderr, "-d <dsa name>       Name of the DSA to be initially accessed (default: locally configured DSA)\n");
	fprintf(stderr, "-A <authlevel>      Level of authentication used for X.500 Directory access\n");
	fprintf(stderr, "                    <authlevel> may have one of the values 'SIMPLE' or 'STRONG'\n");
	fprintf(stderr, "                    (default: environment variable AUTHLEVEL or 'No authentication')\n");
	fprintf(stderr, "                    STRONG implies the use of signed DAP operations\n");
#endif
        }

        if(MF_check) MF_fprint(stderr);

        exit(-1);                                /* IRREGULAR EXIT FROM SECTOOL */
} 

