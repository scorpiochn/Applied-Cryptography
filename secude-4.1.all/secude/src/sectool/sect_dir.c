
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

/*-----------------------sect_dir.c---------------------------------*/
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
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/* MODULE   sect_dir         VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/*------------------------------------------------------------------*/



#include "sect_inc.h"

#define NO	0
#define YES	1
#define SAVE	2





/*
 * *** *** *** *** *** ***
 *	Directory stuff
 * *** *** *** *** *** ***
 */



/*
 * Notify callback function for `dir_button'.
 */
void
dir_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "dir_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fprintf(stderr, "--> %s: starting Directory Tool...", proc);


	/*
	 *	create and open another DirTool (more than one is welcome for parallel usage of different DSA's)
	 */
	sectxv_dir_window = sectxv_dir_window_objects_initialize(NULL, NULL);

	notify_interpose_destroy_func(sectxv_dir_window->dir_window, dir_destroy_func);

	SECTXV_OPEN(sectxv_dir_window->dir_window);
	SECTXV_SHOW(sectxv_dir_window->dir_window);

}



/*
 * Event callback function for `dir_window'.
 */
Notify_value
dir_event_handler(win, event, arg, type)
	Xv_window	win;
	Event		*event;
	Notify_arg	arg;
	Notify_event_type type;
{
	static Boolean			first_event_happened = FALSE;

	sectxv_dir_window_objects	*ip = (sectxv_dir_window_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);
	
	/*

	 *	Read Aliaslist if neccessary: WIN_MAP_NOTIFY is the first event after running xv_main_loop() processed by the handler
	 */
	if ( (event_id(event) == WIN_MAP_NOTIFY) && (first_event_happened == FALSE) )  {

		if (sectool_verbose) fprintf(stderr, "  first_event in dir_window\n");

		first_event_happened = TRUE;

	
		fill_dir_list(ip);
	
	}

	return notify_next_event_func(win, (Notify_event) event, arg, type);
}

/* ---------------------------------------------------------------------------------------------------------------------
 *	Destroy Interposer of SecTool Base Window
 */	

Notify_value
dir_destroy_func(client, status)
	Notify_client		client;
	Destroy_status		status;
{
	static int		triedonce;
	
	char			*proc = "dir_destroy_func";
	int			answer;
	Xv_notice		notice;


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc); 





	switch(status) 	{

		case DESTROY_CHECKING:

			if (directory_tool) system(rmtemp);
			xv_destroy_safe(client);
			break;

		case DESTROY_CLEANUP:

			return(notify_next_destroy_func(client, status));
			break;

		case DESTROY_PROCESS_DEATH:

			exit(-1);
			break;
	}


	return(NOTIFY_DONE);

}




/*
 * Notify callback function for `dir_list'.
 */
int
dir_content_handler(item, string, client_data, op, event)
	Panel_item	item;
	char		*string;
	Xv_opaque	client_data;
	Panel_list_op	op;
	Event		*event;
{
	sectxv_dir_window_objects	*ip = (sectxv_dir_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch(op) {
	case PANEL_LIST_OP_DESELECT:
		fprintf(stderr, "sectxv: dir_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_SELECT:
		fprintf(stderr, "sectxv: dir_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_VALIDATE:
		fprintf(stderr, "sectxv: dir_content_handler: PANEL_LIST_OP_VALIDATE: %s\n",string);
		break;

	case PANEL_LIST_OP_DELETE:
		fprintf(stderr, "sectxv: dir_content_handler: PANEL_LIST_OP_DELETE: %s\n",string);
		break;
	}
	return XV_OK;
}



/*
 * Notify callback function for `dir_enter_button'.
 */
void
dir_enter_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	sectxv_dir_window_objects	*ip = (sectxv_dir_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	fputs("sectxv: dir_enter_handler\n", stderr);
}

/*
 * Notify callback function for `dir_retrieve_button'.
 */
void
dir_retrieve_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	sectxv_dir_window_objects	*ip = (sectxv_dir_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	fputs("sectxv: dir_retrieve_handler\n", stderr);
}

/*
 * Notify callback function for `dir_delete_button'.
 */
void
dir_delete_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	sectxv_dir_window_objects	*ip = (sectxv_dir_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	fputs("sectxv: dir_delete_handler\n", stderr);
}




int
fill_dir_list(ip)
	sectxv_dir_window_objects	*ip;
{


	/* */

	return(0);


}
