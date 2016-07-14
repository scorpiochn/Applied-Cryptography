
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

/*-----------------------sect_ca.c----------------------------------*/
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
/* MODULE   sect_ca          VERSION   2.0                          */
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
 * *** *** *** ***
 *	CA stuff
 * *** *** *** ***
 */



/*
 * Done callback function for `ca_popup'.
 */
void
ca_done_handler(frame)
	Frame		frame;
{
	char	*proc = "ca_done_handler";


	if (af_verbose)  fputs("sectxv: ca_done_handler\n", stderr);

	SECTXV_HIDE(frame);
}




/*
 * Menu handler for `ca_menu (List)'.
 */
Menu_item
ca_causers_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ca_causers_handler";

	sectxv_base_window_objects * ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		fputs("sectxv: ca_causers_handler: MENU_NOTIFY\n", stderr);



		SECTXV_SHOW(sectxv_ca_popup->ca_popup);



		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `ca_menu (Log-file)'.
 */
Menu_item
ca_calog_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ca_calog_handler";

	sectxv_base_window_objects * ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);


	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		fputs("sectxv: ca_calog_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `ca_user_menu (Show)'.
 */
Menu_item
ca_caserialnumbers_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ca_caserialnumbers_handler";

	sectxv_ca_popup_objects * ip = (sectxv_ca_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);


	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		fputs("sectxv: ca_caserialnumbers_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `ca_user_menu (Tag)'.
 */
Menu_item
ca_tag_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ca_tag_handler";

	sectxv_ca_popup_objects * ip = (sectxv_ca_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);


	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		fputs("sectxv: ca_tag_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Notify callback function for `ca_show_button'.
 */
void
ca_cacertificate_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char			*proc = "ca_cacertificate_handler";
	sectxv_ca_popup_objects	*ip = (sectxv_ca_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);


	fputs("sectxv: ca_cacertificate_handler\n", stderr);
}



/*
 * Notify callback function for `ca_revoke_button'.
 */
void
ca_revoke_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char			*proc = "ca_revoke_handler";
	sectxv_ca_popup_objects	*ip = (sectxv_ca_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);

	
	fputs("sectxv: ca_revoke_handler\n", stderr);
}



/*
 * Notify callback function for `ca_list'.
 */
int
ca_content_handler(item, string, client_data, op, event)
	Panel_item	item;
	char		*string;
	Xv_opaque	client_data;
	Panel_list_op	op;
	Event		*event;
{
	char			*proc = "ca_content_handler";
	sectxv_ca_popup_objects	*ip = (sectxv_ca_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (af_verbose)  fprintf(stderr, "--> %s\n", proc);


	switch(op) {
	case PANEL_LIST_OP_DESELECT:
		if (sectool_verbose) fprintf(stderr, "sectxv: ca_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_SELECT:
		if (sectool_verbose) fprintf(stderr, "sectxv: ca_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_VALIDATE:
		if (sectool_verbose) fprintf(stderr, "sectxv: ca_content_handler: PANEL_LIST_OP_VALIDATE: %s\n",string);
		break;

	case PANEL_LIST_OP_DELETE:
		if (sectool_verbose) fprintf(stderr, "sectxv: ca_content_handler: PANEL_LIST_OP_DELETE: %s\n",string);
		break;
	}
	return XV_OK;
}

