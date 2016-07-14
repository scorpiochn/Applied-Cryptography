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

/*-----------------------sect_alias.c-------------------------------*/
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
/* MODULE   sect_alias       VERSION   2.0                          */
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

static Boolean	first_event_happened = FALSE;
static Boolean	addalias_finished;
static char	*alias_to_add;


/*
 * *** *** *** *** ***
 *	Alias stuff
 * *** *** *** *** ***
 */



/* ---------------------------------------------------------------------------------------------------------------------
 * Notify callback function for `alias_button': Open Alias window from Base window
 */
void
alias_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "alias_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);

	
	if (!sectxv_alias_window)  {

		sectxv_alias_window = sectxv_alias_window_objects_initialize(NULL, NULL);

		notify_interpose_destroy_func(sectxv_alias_window->alias_window, alias_destroy_func);

		alias_save_needed = FALSE;
		first_event_happened = FALSE;
	}

	SECTXV_OPEN(sectxv_alias_window->alias_window);
	SECTXV_SHOW(sectxv_alias_window->alias_window);

}



/*
 * Event callback function for `alias_window'.
 */
Notify_value
alias_event_handler(win, event, arg, type)
	Xv_window			win;
	Event				*event;
	Notify_arg			arg;
	Notify_event_type 		type;
{
	char				*proc = "alias_event_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);

	
	if (sectool_verbose) fprintf(stderr, "sectxv: alias_event_handler: event %d arg %d type %d\n", event_id(event), arg, type);

	/*
	 *	Read Aliaslist if neccessary: WIN_MAP_NOTIFY is the first event after running xv_main_loop() processed by the handler
	 */
	if ((event_id(event) == WIN_MAP_NOTIFY) && (first_event_happened == FALSE))  {

		if (sectool_verbose) fprintf(stderr, "  first_event in alias_window\n");

		first_event_happened = TRUE;


		SECTXV_SHOW(ip->alias_window);
		SECTXV_BUSY(ip->alias_window, "Initializing...");
	
		if (!aux_get_AliasList())  {
	
			notice_quitcont(ip->alias_list, "Can't read alias file");
		}
	

		if (open_write_tempfile(ip->alias_window) >= 0)  {

			if (!aux_check_AliasList(logfile))  {
	
				close_tempfile();
				if (!notice_contshow(ip->alias_list, "Warning: AliasList is inconsistent!\nDouble aliases were found."))
					open_text_window(ip->alias_window, tempfile, "Check AliasList");
			}
		}
	
		xv_set(ip->alias_list, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);
	
		fill_alias_list(ip);
	
	}


	return(notify_next_event_func(win, (Notify_event) event, arg, type));

}

/* ---------------------------------------------------------------------------------------------------------------------
 *	Destroy Interposer of Alias Subtool Window
 */	

Notify_value
alias_destroy_func(client, status)
	Notify_client		client;
	Destroy_status		status;
{
	static Boolean		triedonce;

	char			*proc = "alias_destroy_func";
	int			answer;
	Xv_notice		notice;


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc); 


	if (alias_save_needed)  {

		if (status == DESTROY_CHECKING)  {

			answer = notice_savequitcancel(client, "AliasList has changed");
			triedonce = TRUE;

		} else if (!triedonce)  {

			answer = notice_savequit(client, "AliasList has changed");

		} else  {

			/* perhaps something has gone wrong. */
			answer = YES;
		}

		switch (answer)  {

			case SAVE:
				alias_save_needed = FALSE;
				aux_put_AliasList(useralias);
				break;

			case YES:
				break;

			case NO:
				return((Notify_value)notify_veto_destroy(client));
				break;
		}
	}

	switch(status) 	{

		case DESTROY_CHECKING:

			if (alias_tool) system(rmtemp);
			xv_destroy_safe(client);
			sectxv_alias_window = (sectxv_alias_window_objects *) 0;
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
 * Notify callback function for `alias_file_setting'.
 */
void
alias_file_setting_handler(item, value, event)
	Panel_item	item;
	int		value;
	Event		*event;
{
	static int			last_value = SECTXV_ALIAS_USER;

	char				*proc = "alias_file_setting_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose) fprintf(stderr, "sectxv: alias_file_setting_handler: value: %u event %d\n", value, event_id(event));
	

	/*
	 *	no choice: force USER choice
	 */

	if (value == SECTXV_ALIAS_NONE && last_value == SECTXV_ALIAS_SYSTEM)  {

		value = SECTXV_ALIAS_USER;
		xv_set(ip->alias_file_setting, PANEL_VALUE, value, NULL);
	}
	if (value == SECTXV_ALIAS_NONE && last_value == SECTXV_ALIAS_USER)  {

		value = SECTXV_ALIAS_SYSTEM;
		xv_set(ip->alias_file_setting, PANEL_VALUE, value, NULL);
	}
	
	/* same selection as last time: do nothing */
	if (value == last_value) return;
	else last_value = value;

	SECTXV_BUSY(ip->alias_window, "");

	fill_alias_list(ip);

}



/*
 * Notify callback function for `alias_type_setting'.
 */
void
alias_type_setting_handler(item, value, event)
	Panel_item			item;
	int				value;
	Event				*event;
{
	static int			last_value = SECTXV_ALIAS_LOCALNAME;

	char				*proc = "alias_type_setting_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose) fprintf(stderr, "sectxv: alias_type_setting_handler: value: %u event %d\n", value, event_id(event));


	/* same selection as last time: do nothing */
	if (value == last_value) return;
	else last_value = value;

	SECTXV_BUSY(ip->alias_window, "");

	fill_alias_list(ip);
	
}




/*
 * Notify callback function for `alias_list'.
 */
int
alias_content_handler(item, string, client_data, op, event)
	Panel_item			item;
	char				*string;
	Xv_opaque			client_data;		/* delivers PANEL_LIST_CLIENT_DATA set in fill_alias_list */
	Panel_list_op			op;
	Event				*event;
{
	char				*proc = "alias_content_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose)  fprintf(stderr, "--> %s  CLIENT_DATA: %s\n", proc, (char *)client_data);

	
	switch(op) {
	case PANEL_LIST_OP_DESELECT:

		xv_set(item, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL); 

		SECTXV_IDLE(ip->alias_window, "");

		fill_alias_textfields(ip); 

		break;

	case PANEL_LIST_OP_SELECT:

		xv_set(item, PANEL_CLIENT_DATA, (char *)client_data, NULL);

		SECTXV_IDLE(ip->alias_window, "");

		fill_alias_textfields(ip); 

		break;

	case PANEL_LIST_OP_DELETE:
		break;	
	}


	return(XV_OK);

}




/*
 * Menu handler for `alias_find_menu (Next)'.
 */
Menu_item
alias_find_next_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "alias_find_next_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: alias_find_next_handler: MENU_NOTIFY\n", stderr);

		alias_find_pattern(ip, "");

		break;

	case MENU_NOTIFY_DONE:
		break;
	}


	return(item);

}

/*
 * Menu handler for `alias_find_menu (Top Down)'.
 */
Menu_item
alias_find_topdown_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{

	char				*proc = "alias_find_topdown_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: alias_find_topdown_handler: MENU_NOTIFY\n", stderr);

		alias_find_pattern(ip, CNULL);

		break;

	case MENU_NOTIFY_DONE:
		break;
	}


	return(item);

}



/*
 *	find pattern (given in alias_clipboard_textfield) in alias list
 */

int
alias_find_pattern(ip, init_string)
	sectxv_alias_window_objects	*ip;
	char				*init_string;
{
	static char			*list_selection_data = CNULL;

	char				*proc = "alias_find_topdown_handler";
	char				*name;
	char				*pattern;
	int				entry;
	char				*list_data;



	if (! (pattern = aux_cpy_ReducedString( (char *)xv_get(ip->alias_clipboard_textfield, PANEL_VALUE) )) ) return(-1);

	SECTXV_BUSY(ip->alias_window, "Searching...");

	name = aux_search_AliasList(init_string, pattern);
	if (!name)  {

		notice_continue(ip->alias_find_button, "No match");
		xv_set(ip->alias_list,	PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);

	} else   {

		for (entry = (int)xv_get(ip->alias_list, PANEL_LIST_NROWS) - 1; entry >= 0; entry--)  {

			if ((list_data = (char *)xv_get(ip->alias_list, PANEL_LIST_CLIENT_DATA, entry)) && !strcmp(list_data, name))  {
			
				xv_set(ip->alias_list, PANEL_LIST_SELECT, entry, TRUE, NULL);
				break;
			} else if ((Boolean)xv_get(ip->alias_list, PANEL_LIST_SELECTED, entry))
					xv_set(ip->alias_list, PANEL_LIST_SELECT, entry, FALSE, NULL);
		}
		if (list_selection_data) free(list_selection_data);
		list_selection_data = aux_cpy_String(name);

		xv_set(ip->alias_list, PANEL_CLIENT_DATA, list_selection_data, NULL);
	}

	if (name) free(name);

	SECTXV_IDLE(ip->alias_window, "");

	fill_alias_textfields(ip);


	return(0);

}



/*
 * Menu handler for `alias_names_menu (<Insert>)'.
 */
Menu_item
alias_names_insert_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char				*proc = "alias_names_insert_handler";
	sectxv_alias_window_objects 	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*new_alias;

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: alias_names_insert_handler: MENU_NOTIFY\n", stderr);

		new_alias = aux_cpy_ReducedString((char *)xv_get(ip->alias_names_textfield, PANEL_VALUE));

		if (!new_alias) return(item);
		if (aux_alias(new_alias))  {

			SECTXV_IDLE(ip->alias_window, "Alias already exists");
			return(item);
		}
			
		aux_add_alias_name(new_alias, (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA), useralias, FALSE, FALSE);
		SECTXV_SAVENEEDED(ip->alias_window);
		alias_save_needed = TRUE;

		fill_alias_list(ip);
		fill_alias_textfields(ip);

		SECTXV_IDLE(ip->alias_window, "Extra alias inserted");

		break;

	case MENU_NOTIFY_DONE:
		break;
	}


	return(item);

}


/*
 * Menu handler for `alias_names_menu (remove an alias item)'.
 */
Menu_item
alias_names_remove_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char				*proc = "alias_names_remove_handler";
	sectxv_alias_window_objects 	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: alias_names_remove_handler: MENU_NOTIFY\n", stderr);

		/* copy menu item value to textfield and remove it from menu */
		xv_set(ip->alias_names_textfield, PANEL_VALUE, (char *)xv_get(item, MENU_STRING), NULL);

		if (aux_delete_alias((char *)xv_get(item, MENU_STRING), useralias, FALSE) < 0)  {

			SECTXV_IDLE(ip->alias_window, "Can't delete System alias");
			return(item);
		}

		SECTXV_SAVENEEDED(ip->alias_window);
		alias_save_needed = TRUE;

		fill_alias_list(ip); 
		fill_alias_textfields(ip);

		SECTXV_IDLE(ip->alias_window, "Extra alias removed");

		break;

	case MENU_NOTIFY_DONE:
		break;
	}



	return(item);

}




/*
 * Notify callback function for `alias_new_button'.
 */
void
alias_new_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "alias_new_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	int				entry;

	
	if (sectool_verbose) fputs("sectxv: alias_new_handler\n", stderr);

	SECTXV_IDLE(ip->alias_window, "");

	/* deselect list entry */
	if ( (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA) != SECTXV_NO_SELECTION )  {

		for (entry = 0; !xv_get(ip->alias_list, PANEL_LIST_SELECTED, entry); entry++)
			;

		xv_set(ip->alias_list,	PANEL_CLIENT_DATA, SECTXV_NO_SELECTION,
					PANEL_LIST_SELECT, entry, FALSE,
					NULL);
	}


	fill_alias_textfields(ip);

	
	return;

}




/*
 * Notify callback function for `alias_add_button'.
 */
void
alias_add_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	static char			*list_selection_data = CNULL;

	char				*proc = "alias_add_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*name;
	DName				*dname;
	char				*localnamealias;
	char				*rfcmailalias;
	char				*x400mailalias;
	Boolean				do_refresh = FALSE;



	if (sectool_verbose) fputs("sectxv: alias_add_handler\n", stderr);

	SECTXV_IDLE(ip->alias_window, "");

	if (list_selection_data) free(list_selection_data);

	/* adding new dname with at least one alias */
	name = aux_cpy_ReducedString( (char *)xv_get(ip->alias_dname_textfield, PANEL_VALUE) );

	if (!name)  {

		notice_continue(item, "Empty DName textfield");
		return;
	}

	dname = aux_Name2DName(name);
	if (!dname)  {

		notice_continue(item, "DName field represents no distinguished name");
		if (name) free(name);
		return;
	}

	if (aux_alias_chkfile(name, useralias))  {

		notice_continue(item, "User's DName entry exists\nUse Change");
		if (name) free(name);
		return;
	}

	localnamealias = aux_cpy_ReducedString((char *)xv_get(ip->alias_localname_textfield, PANEL_VALUE));
	rfcmailalias = aux_cpy_ReducedString((char *)xv_get(ip->alias_rfcmail_textfield, PANEL_VALUE));
	x400mailalias = aux_cpy_ReducedString((char *)xv_get(ip->alias_x400mail_textfield, PANEL_VALUE));


	if (localnamealias && !aux_alias(localnamealias))  {

		aux_add_alias(localnamealias, dname, useralias, TRUE, FALSE);
		do_refresh = TRUE;
	}

	if (rfcmailalias && !aux_alias(rfcmailalias))  {

		aux_add_alias(rfcmailalias, dname, useralias, TRUE, FALSE);
		do_refresh = TRUE;
	}

	if (x400mailalias && !aux_alias(x400mailalias))  {

		aux_add_alias(x400mailalias, dname, useralias, TRUE, FALSE);
		do_refresh = TRUE;
	}
	
	if (do_refresh)  {

		list_selection_data = aux_cpy_String(name);

		xv_set(ip->alias_list, PANEL_CLIENT_DATA, list_selection_data, NULL);	

		SECTXV_SAVENEEDED(ip->alias_window);
		alias_save_needed = TRUE;

		SECTXV_ACTIVE(ip->alias_change_button);
		SECTXV_ACTIVE(ip->alias_delete_button);
		SECTXV_ACTIVE(ip->alias_names_button);

		fill_alias_list(ip);
		fill_alias_textfields(ip);

	} else  {

		notice_continue(item, "Can't add DName entry\nEnter at least one new alias");
	}

	if (name) free(name);
	if (dname) aux_free_DName(&dname);
	if (localnamealias) free(localnamealias);
	if (rfcmailalias) free(rfcmailalias);
	if (x400mailalias) free(rfcmailalias);


	return;

}





/*
 * Notify callback function for `alias_change_button'.
 */
void
alias_change_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "alias_change_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*name;
	DName				*dname;
	char				*old_localnamealias;
	char				*old_rfcmailalias;
	char				*old_x400mailalias;
	char				*localnamealias;
	char				*rfcmailalias;
	char				*x400mailalias;
	Boolean				do_refresh = FALSE;


	
	if (sectool_verbose) fputs("sectxv: alias_change_handler\n", stderr);

	SECTXV_IDLE(ip->alias_window, "");

	name = aux_cpy_ReducedString( (char *)xv_get(ip->alias_dname_textfield, PANEL_VALUE) );

	if (!name)  {

		notice_continue(item, "Empty DName textfield");
		return;
	}

	if (strcmp(xv_get(ip->alias_dname_textfield, PANEL_CLIENT_DATA), name))  {

		notice_continue(item, "DName field has changed, use Add");
		if (name) free(name);
		return;
	}

	dname = aux_Name2DName(name);
	if (!dname)  {

		notice_continue(item, "DName field represents no distinguished name");
		if (name) free(name);
		return;
	}


	/* insert new aliases on top of dname's alias list, delete old user aliases */	

	old_localnamealias = (char *)xv_get(ip->alias_localname_textfield, PANEL_CLIENT_DATA);
	old_rfcmailalias = (char *)xv_get(ip->alias_rfcmail_textfield, PANEL_CLIENT_DATA);
	old_x400mailalias = (char *)xv_get(ip->alias_x400mail_textfield, PANEL_CLIENT_DATA);

	localnamealias = aux_cpy_ReducedString( (char *)xv_get(ip->alias_localname_textfield, PANEL_VALUE) );
	rfcmailalias = aux_cpy_ReducedString( (char *)xv_get(ip->alias_rfcmail_textfield, PANEL_VALUE) );
	x400mailalias = aux_cpy_ReducedString( (char *)xv_get(ip->alias_x400mail_textfield, PANEL_VALUE) );

	if (!localnamealias && !rfcmailalias && !x400mailalias)  {

		notice_continue(item, "Can't change DName entry\nEnter at least one alias\nor use Delete");
		if (name) free(name);
		if (dname) aux_free_DName(&dname);
		if (localnamealias) free(localnamealias);
		if (rfcmailalias) free(rfcmailalias);
		if (x400mailalias) free(x400mailalias);
		return;
	}

	if ((!localnamealias && strcmp(old_localnamealias, "")) || (localnamealias && strcmp(old_localnamealias, localnamealias)))  {

		if (localnamealias && aux_alias(localnamealias))  {

			notice_continue(item, "Local name exists");
			if (name) free(name);
			if (dname) aux_free_DName(&dname);
			if (localnamealias) free(localnamealias);
			if (rfcmailalias) free(rfcmailalias);
			if (x400mailalias) free(x400mailalias);
			return;
		}

		if (localnamealias) aux_add_alias(localnamealias, dname, useralias, TRUE, FALSE);
		aux_delete_alias(old_localnamealias, useralias, FALSE);

		do_refresh = TRUE;
	}

	if ((!rfcmailalias && strcmp(old_rfcmailalias, "")) || (rfcmailalias && strcmp(old_rfcmailalias, rfcmailalias)))  {

		if (rfcmailalias && aux_alias(rfcmailalias))  {

			notice_continue(item, "Internet Mail name exists");
			if (name) free(name);
			if (dname) aux_free_DName(&dname);
			if (localnamealias) free(localnamealias);
			if (rfcmailalias) free(rfcmailalias);
			if (x400mailalias) free(x400mailalias);
			return;
		}

		if (rfcmailalias) aux_add_alias(rfcmailalias, dname, useralias, TRUE, FALSE);
		aux_delete_alias(old_rfcmailalias, useralias, FALSE);

		do_refresh = TRUE;
	}

	if ((!x400mailalias && strcmp(old_x400mailalias, "")) || (x400mailalias && strcmp(old_x400mailalias, x400mailalias)))  {

		if (x400mailalias && aux_alias(x400mailalias))  {

			notice_continue(item, "X.400 Mail name exists");
			if (name) free(name);
			if (dname) aux_free_DName(&dname);
			if (localnamealias) free(localnamealias);
			if (rfcmailalias) free(rfcmailalias);
			if (x400mailalias) free(x400mailalias);
			return;
		}

		if (x400mailalias) aux_add_alias(x400mailalias, dname, useralias, TRUE, FALSE);
		aux_delete_alias(old_x400mailalias, useralias, FALSE);

		do_refresh = TRUE;
	}

	if (name) free(name);
	if (dname) aux_free_DName(&dname);
	if (localnamealias) free(localnamealias);
	if (rfcmailalias) free(rfcmailalias);
	if (x400mailalias) free(x400mailalias);

	if (do_refresh)  {

		SECTXV_SAVENEEDED(ip->alias_window);
		alias_save_needed = TRUE;

		if (old_localnamealias) free(old_localnamealias);
		if (old_rfcmailalias) free(old_rfcmailalias);
		if (old_x400mailalias) free(old_x400mailalias);

		fill_alias_list(ip);
		fill_alias_textfields(ip);
	}

}



/*
 * Notify callback function for `alias_reset_button'.
 */
void
alias_reset_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	static char			*list_selection_data = CNULL;

	char				*proc = "alias_reset_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fputs("sectxv: alias_reset_handler\n", stderr);

	SECTXV_BUSY(ip->alias_window, "Initializing...");

	/* save old list client data before alias list is freed */
	if (list_selection_data) free(list_selection_data);
	list_selection_data = (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA);
 
	if (list_selection_data) list_selection_data = aux_cpy_String(list_selection_data);

	/* free alias list, get old one again */
	if (!aux_get_AliasList())  {

		notice_quitcont(item, "Can't read alias file");
		SECTXV_IDLE(ip->alias_window, "");
		return;
	}

	xv_set(ip->alias_list, PANEL_CLIENT_DATA, list_selection_data, NULL);	

	SECTXV_CLRFOOTER(ip->alias_window);
	alias_save_needed = FALSE;

	fill_alias_list(ip);
	fill_alias_textfields(ip);

}




/*
 * Notify callback function for `alias_delete_button'.
 */
void
alias_delete_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char				*proc = "alias_delete_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*name;
	char				*alias;

	
	if (sectool_verbose) fputs("sectxv: alias_delete_handler\n", stderr);

	SECTXV_IDLE(ip->alias_window, "");

	name = (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA); 

	if (!aux_alias_chkfile(name, useralias))  {

		sprintf(notice_text, "No User aliases stored for\n%s", name);
		notice_continue(item, notice_text);
		return;
	}

	sprintf(notice_text, "Delete User's DName entry for\n%s ?", name);
	if (!notice_confcancel(item, notice_text)) return;

	while (alias = aux_Name2aliasf(name, ANYALIAS, useralias))
		if (aux_delete_alias(alias, useralias, FALSE) < 0) break;

	xv_set(ip->alias_list, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);
	if (name) free(name);

	SECTXV_INACTIVE(ip->alias_change_button);
	SECTXV_INACTIVE(ip->alias_delete_button);
	SECTXV_INACTIVE(ip->alias_names_button);

	SECTXV_SAVENEEDED(ip->alias_window);
	alias_save_needed = TRUE;

	fill_alias_list(ip);

}



/*
 * Notify callback function for `alias_apply_button'.
 */
void
alias_apply_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "alias_apply_handler";
	sectxv_alias_window_objects	*ip = (sectxv_alias_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fputs("sectxv: alias_apply_handler\n", stderr);


	/* write alias list to user's file */
	aux_put_AliasList(useralias);
	alias_save_needed = FALSE;

	SECTXV_CLRFOOTER(ip->alias_window);
	SECTXV_IDLE(ip->alias_window, "");

}





/* 
 *	 fill alias_list of actual alias_window
 */

int
fill_alias_list(ip)
	sectxv_alias_window_objects	*ip;
{
	char				*proc = "fill_alias_list";
	int				i;
	AliasFile			current_afile;
	unsigned			file_setting_value = (unsigned)xv_get(ip->alias_file_setting, PANEL_VALUE);
	unsigned			type_setting_value = (unsigned)xv_get(ip->alias_type_setting, PANEL_VALUE);
	Boolean				dname_in_both_files;
	char				*list_selection_data;
	Name				*al_name;		
	char				*al_alias;
	char				aliaslist_string[SECTXV_ALIASLISTSTR_LENGTH + 1];
	int				total_rows;
	int				selected_row = -1;
	char				*fill = "";
	char				*dummy = "     ???";
	Xv_opaque			glyph_object;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	/*
	 *	clear alias_list
	 */

	/* check which (if any) list item is selected */
	list_selection_data = (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA);

	for (total_rows = xv_get(ip->alias_list, PANEL_LIST_NROWS); total_rows > 0; total_rows--)
		xv_set(ip->alias_list,	PANEL_LIST_DELETE, total_rows - 1, 
					PANEL_PAINT, PANEL_NONE,
					NULL);

	/*
         *	Read all DNames from aliaslist->dname, get alias
         */

	for (i = 0; i < 2; i++)  {

		current_afile = (i == 0) ? useralias : systemalias; 

		if ( (file_setting_value == SECTXV_ALIAS_USER && current_afile == systemalias) ||
		     (file_setting_value == SECTXV_ALIAS_SYSTEM && current_afile == useralias)		) continue;

		al_name = aux_alias_nxtname(TRUE);

		while (al_name) {

			if (!aux_alias_chkfile(al_name, current_afile))  {

				al_name = aux_alias_nxtname(FALSE);
				continue;
			}

			/* read demanded alias or next best */
			switch(type_setting_value)  {

				case SECTXV_ALIAS_LOCALNAME:

					al_alias = aux_Name2aliasf(al_name, LOCALNAME, current_afile);
					break;

				case SECTXV_ALIAS_RFCMAIL:

					al_alias = aux_Name2aliasf(al_name, RFCMAIL, current_afile);
					break;

				case SECTXV_ALIAS_X400MAIL:

					al_alias = aux_Name2aliasf(al_name, X400MAIL, current_afile);
					break;

				case SECTXV_ALIAS_NEXTBEST:

					al_alias = aux_Name2aliasf(al_name, ANYALIAS, current_afile);
					break;
			}
			if (!al_alias)  {

				if (verbose) fprintf(stderr, "No alias of type %d stored for %s\n", type_setting_value, al_name);

				/* another type of alias ? */
				if (al_alias = aux_Name2aliasf(al_name, ANYALIAS, current_afile))  {
					free(al_alias);
					al_alias = aux_cpy_String(dummy);
				}
			}
			if (!al_alias)  {

				if (verbose) fprintf(stderr, "No alias stored for %s\n", al_name);

			} else  {

				/* *** be careful when changing sprintf-formats! *** */
				sprintf(aliaslist_string, "%-25.25s%2s%-50.50s", al_alias, fill, al_name);
				if (sectool_verbose) fprintf(stderr, "    %s\n", aliaslist_string);
	
				total_rows = xv_get(ip->alias_list, PANEL_LIST_NROWS);

				glyph_object = (Xv_opaque) 0;
				
				/* display with BOTH-glyph-image if dname in both files (only in first pass of loop) */
				dname_in_both_files = (aux_alias_chkfile(al_name, useralias) && aux_alias_chkfile(al_name, systemalias));

				if ( (dname_in_both_files && (current_afile == useralias)) ||
				     (dname_in_both_files && (current_afile == systemalias) &&
				     (file_setting_value == SECTXV_ALIAS_SYSTEM)) )
				
					glyph_object = sectxv_alias_list_both_glyph;

				/* display with USER-glyph-image */
				else if (current_afile == useralias)

					glyph_object = sectxv_alias_list_user_glyph;

				/* display with SYSTEM-glyph-image */
				else if ( !dname_in_both_files && (current_afile == systemalias) )

					glyph_object = sectxv_alias_list_system_glyph;

				if (glyph_object)  {

					xv_set(ip->alias_list,	PANEL_LIST_INSERT, total_rows,
								PANEL_LIST_GLYPH, total_rows, glyph_object,
								PANEL_LIST_STRING, total_rows, aliaslist_string,
								PANEL_LIST_CLIENT_DATA, total_rows, al_name,
								PANEL_PAINT, PANEL_NONE,
								NULL);

					if (list_selection_data && !strcmp(list_selection_data, al_name)) selected_row = total_rows;
				}
			}
			if (al_alias) free(al_alias);
			al_name = aux_alias_nxtname(FALSE);
		}
	}

	if (selected_row >= 0)
		xv_set(ip->alias_list,	PANEL_LIST_SELECT, selected_row, TRUE,
					PANEL_CLIENT_DATA, (char *)xv_get(ip->alias_list, PANEL_LIST_CLIENT_DATA, selected_row),
					NULL);

	panel_paint(ip->alias_list, PANEL_CLEAR);

	SECTXV_IDLE(ip->alias_window, "");


        return(0);

}

	


/* 
 *	 fill alias_textfields, (un)activate buttons of actual alias_window
 */

int
fill_alias_textfields(ip)
	sectxv_alias_window_objects	*ip;
{
	char				*proc = "fill_alias_textfields";
	Name				*name;
	char				*localnamealias;
	char				*rfcmailalias;
	char				*x400mailalias;
	DName				*dname;
	int				total_rows;
	char				*fill = "";
	char				*dummy = "";
	char				*divider = " : ";
	Menu				menu = xv_get(ip->alias_names_button, PANEL_ITEM_MENU);
	Menu_item			mi;
	int				nitems = xv_get(menu, MENU_NITEMS);
	int				menu_row;
	char				*alias_string;
	char				*alias;
	char				*m_string;
	char				*s;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	name = (char *)xv_get(ip->alias_list, PANEL_CLIENT_DATA);

	if (name == SECTXV_NO_SELECTION)  {

		/*
		 *	no list selection
		 */

		SECTXV_INACTIVE(ip->alias_change_button);
		SECTXV_INACTIVE(ip->alias_delete_button);
		SECTXV_INACTIVE(ip->alias_names_button);

		/* clear alias textfields */
		if (s = (char *)xv_get(ip->alias_dname_textfield, PANEL_CLIENT_DATA)) free(s);
		xv_set(ip->alias_dname_textfield, PANEL_CLIENT_DATA, CNULL, PANEL_VALUE, "", NULL);

		if (s = (char *)xv_get(ip->alias_localname_textfield, PANEL_CLIENT_DATA)) free(s);
		xv_set(ip->alias_localname_textfield, PANEL_CLIENT_DATA, CNULL, PANEL_VALUE, "", NULL);

		if (s = (char *)xv_get(ip->alias_rfcmail_textfield, PANEL_CLIENT_DATA)) free(s);
		xv_set(ip->alias_rfcmail_textfield, PANEL_CLIENT_DATA, CNULL, PANEL_VALUE, "", NULL);

		if (s = (char *)xv_get(ip->alias_x400mail_textfield, PANEL_CLIENT_DATA)) free(s);
		xv_set(ip->alias_x400mail_textfield, PANEL_CLIENT_DATA, CNULL, PANEL_VALUE, "", NULL);

		xv_set(ip->alias_names_textfield, PANEL_VALUE, "", NULL);

		/* clear alias_name_menu: 4 items minimum, 1 for title, 1 for <Insert>, 2 separators */
		for (menu_row = nitems; menu_row > 3; menu_row--)
			xv_set(menu, MENU_REMOVE, menu_row, NULL);

	} else  {

		/*
		 *	list selection
		 */

		dname = aux_Name2DName(name);
	
		/* fill textfields */

		xv_set(ip->alias_dname_textfield, PANEL_CLIENT_DATA, aux_cpy_String(name), PANEL_VALUE, name, NULL);

		if (! (localnamealias = aux_DName2alias(dname, LOCALNAME)) ) localnamealias = aux_cpy_String(dummy);
		xv_set(ip->alias_localname_textfield, PANEL_CLIENT_DATA, localnamealias, PANEL_VALUE, localnamealias, NULL);

		if (! (rfcmailalias = aux_DName2alias(dname, RFCMAIL)) ) rfcmailalias = aux_cpy_String(dummy);
		xv_set(ip->alias_rfcmail_textfield, PANEL_CLIENT_DATA, rfcmailalias, PANEL_VALUE, rfcmailalias, NULL);

		if (! (x400mailalias = aux_DName2alias(dname, X400MAIL)) ) x400mailalias = aux_cpy_String(dummy);
		xv_set(ip->alias_x400mail_textfield, PANEL_CLIENT_DATA, x400mailalias, PANEL_VALUE, x400mailalias, NULL);

		/* clear alias_name_menu: 4 items minimum, 1 for title, 1 for <Insert>, 2 separators */
		for (menu_row = nitems; menu_row > 3; menu_row--)
			xv_set(menu, MENU_REMOVE, menu_row, NULL);

		alias_string = aux_alias_getall(name);
		if (alias_string)  {
			alias = strtok(alias_string, ":");
			do  {
				if (alias) if ( strcmp(alias, localnamealias) &&
					    	strcmp(alias, rfcmailalias)   &&
					    	strcmp(alias, x400mailalias)	)  {
		
						/* different alias found, add to others */
						m_string = aux_cpy_String(alias);
						mi = (Menu_item)xv_create(menu,	MENUITEM,
										XV_KEY_DATA, INSTANCE, ip,
										MENU_STRING, m_string,
										MENU_GEN_PROC, alias_names_remove_handler,
										MENU_RELEASE,
										NULL);

						if (mi == XV_NULL) notice_abort(ip->alias_names_button, "Memory allocation");

						xv_set(menu,	MENU_APPEND_ITEM, mi,
								PANEL_PAINT, PANEL_NONE,
								NULL);

				}
				alias = strtok(CNULL, ":");

			} while (alias);

			free(alias_string);
		}

		if (dname) aux_free_DName(&dname);

		SECTXV_ACTIVE(ip->alias_change_button);
		SECTXV_ACTIVE(ip->alias_delete_button);
		SECTXV_ACTIVE(ip->alias_names_button);
	}


	return(0);

}







/*
 * *** *** *** *** *** *** ***
 *	Add alias stuff
 * *** *** *** *** *** *** ***
 */


/*
 * Event callback function for `addalias_window'.
 */
Notify_value
addalias_event_handler(win, event, arg, type)
	Xv_window			win;
	Event				*event;
	Notify_arg			arg;
	Notify_event_type 		type;
{
	char				*proc = "addalias_event_handler";
	sectxv_addalias_popup_objects	*ip = (sectxv_addalias_popup_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);

	
	if (sectool_verbose) fprintf(stderr, "sectxv: addalias_event_handler: event %d arg %d type %d\n", event_id(event), arg, type);


	return(notify_next_event_func(win, (Notify_event) event, arg, type));

}


/*
 * Done callback function for `addalias_popup'.
 */
void
addalias_done_handler(frame)
	Frame		frame;
{
	if (sectool_verbose) fputs("sectxv: addalias_done_handler\n", stderr);


	addalias_finished = TRUE;
	SECTXV_HIDE(frame);

}



/*
 * Notify callback function for `addalias_apply_button'.
 */
void
addalias_apply_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	sectxv_addalias_popup_objects	*ip = (sectxv_addalias_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: addalias_apply_handler\n", stderr);


	alias_to_add = aux_cpy_ReducedString((char *)xv_get(ip->addalias_alias_textfield, PANEL_VALUE));

	if (alias_to_add)  {

		if (aux_alias(alias_to_add))  {
	
			notice_continue(sectxv_addalias_popup->addalias_alias_textfield, "Alias already exists");
			free(alias_to_add);
			alias_to_add = CNULL;

		} else addalias_done_handler(ip->addalias_popup);

	} else SECTXV_ALARM();

}



/*
 * Notify callback function for `addalias_cancel_button'.
 */
void
addalias_cancel_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	sectxv_addalias_popup_objects	*ip = (sectxv_addalias_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: addalias_cancel_handler\n", stderr);


	addalias_done_handler(ip->addalias_popup);

}



/* ---------------------------------------------------------------------------------------------------------------------
 *	get DName's alias or force entering a new alias for it
 *	return alias, CNULL if canceled
 */

char *
search_add_alias(item, dname, type)
	Panel_item			item;
	DName				*dname;
	AliasType			type;
{
	sectxv_addalias_popup_objects	*ip = sectxv_addalias_popup;
	char				*proc = "search_add_alias";
	char				*alias;
	char				*name;


	if (verbose) fprintf(stderr, "--> %s\n", proc);


	if (! (alias = aux_DName2alias(dname, type)) )  {

		name = aux_DName2Name(dname);

		if (verbose) fprintf(stderr, "  Warning: No alias found for %s\n", name);
		sprintf(notice_text, "No alias found for\n%s", name);
		notice_continue(item, notice_text);

/*
 *	I would like to open this popup and wait until it is closed by the user.
 *	But this seems to be a difficult piece of work...
 *
		addalias_finished = FALSE;
		alias_to_add = CNULL;

		xv_set(ip->addalias_name_textfield, PANEL_VALUE, name, NULL);
		xv_set(ip->addalias_alias_textfield, PANEL_VALUE, "", NULL);

		SECTXV_CENTER(ip->addalias_popup);
		SECTXV_SHOW(ip->addalias_popup);



	
		while (!addalias_finished)  {
			test_print();
		}
		fprintf(stderr, "OK\n");

		if (alias_to_add) aux_add_alias_name(alias_to_add, name, useralias, TRUE, TRUE);

 *
 *	However, at the moment it is sufficient to return NULL if no alias exists...
 */



		if (name) free(name);
	}



	return(alias);

}







