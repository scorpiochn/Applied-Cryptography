
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

/*-----------------------sect_props.c-------------------------------*/
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
/* MODULE   sect_props       VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*                                                                  */
/*------------------------------------------------------------------*/



#include "sect_inc.h"






/*
 * *** *** *** *** *** ***
 *	Properties stuff
 * *** *** *** *** *** ***
 */



/*
 * Menu handler for `prop_menu (Toggle)'.
 */
Menu_item
prop_toggle_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_toggle_handler";

	sectxv_base_window_objects * ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_toggle_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}




/*
 * Menu handler for `prop_menu (DSA Name ?)'.
 */
Menu_item
prop_dsa_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_dsa_handler";

	sectxv_base_window_objects * ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_dsa_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_dua_menu (Simple)'.
 */
Menu_item
prop_dua_simple_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_dua_simple_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_dua_simple_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_dua_menu (Strong)'.
 */
Menu_item
prop_dua_strong_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_dua_strong_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_dua_strong_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_algs_menu (Show)'.
 */
Menu_item
prop_algs_algs_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_algs_algs_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_algs_algs_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_algs_menu (Set)'.
 */
Menu_item
prop_algs_setparm_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_algs_setparm_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_algs_setparm_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_debug_menu (Errors)'.
 */
Menu_item
prop_debug_errors_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_debug_errors_handler";
	int	i; 

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_debug_errors_handler: MENU_NOTIFY\n", stderr);
	
		
		if (open_write_tempfile(sectxv_base_window->base_window) < 0) break;
	
		fprintf(logfile, "\n\n=====   Error stack      =====\n\n");
	
		aux_fprint_error(logfile, 0);
		if (MF_check)  {
			fprintf(logfile, "\n\n=====   Memory Allocation Table      =====\n\n");
			MF_fprint(logfile);
		}
	
		close_tempfile();


		open_text_window(sectxv_base_window->base_window, tempfile, "Error stack");
	

		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `prop_debug_menu (Reset)'.
 */
Menu_item
prop_debug_reset_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "prop_debug_reset_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: prop_debug_reset_handler: MENU_NOTIFY\n", stderr);


		aux_free_error();
	
		notice_continue(sectxv_base_window->prop_button, "Reset error stack OK");


		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



