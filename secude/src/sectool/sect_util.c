
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

/*-----------------------sect_util.c--------------------------------*/
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
/* MODULE   sect_util        VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*------------------------------------------------------------------*/



#include "sect_inc.h"

#define NO	0
#define YES	1
#define SAVE	2


/* ---------------------------------------------------------------------------------------------------------------------
 * Event callback function for `base_window': Does some startup stuff (open files/pse), exits on error with notice
 */
Notify_value
base_event_handler(win, event, arg, type)
	Xv_window			win;
	Event				*event;
	Notify_arg			arg;
	Notify_event_type		 type;
{
	static Boolean			first_event_happened = FALSE;

	char				*proc = "base_event_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fprintf(stderr, "-->base_event_handler: event is %d\n", event_id(event)); 


	/*
	 *	Open PSE if neccessary: WIN_MAP_NOTIFY is the first event after running xv_main_loop() processed by the handler
	 */
	if ((event_id(event) == WIN_MAP_NOTIFY) && (first_event_happened == FALSE))  {

		if (sectool_verbose) fprintf(stderr, "  first_event in base_window\n");

		first_event_happened = TRUE;

		SECTXV_BASE_BUSY("Initializing...");
	
        	if(!sec_sctest(pse_name)) ppin = getenv("USERPIN");

		if ( aux_create_AFPSESel(pse_path, ppin) < 0 )  {

			fprintf(stderr, "%s: ",sectool_argp[0]);
			fprintf(stderr, "Cannot create AFPSESel.\n"); 
			if (verbose) aux_fprint_error(stderr, 0);

			notice_abort(ip->base_window, "Cannot create AFPSESel");
		}
	
		if (verbose) fprintf(stderr, "  aux_create_AFPSESel() OK\n");

		/* SW-PSE and USERPIN unset: pin_popup, its notifiers will open pse */
		if (!sec_sctest(pse_name) && !ppin)  {

			if (verbose) fprintf(stderr, "  SW-PSE, USERPIN unset\n");

			pin_popup_open(NULL);

		/* SC or SW-PSE with USERPIN set */
		}  else  {
			
			if (verbose) fprintf(stderr, "  SC or SW-PSE with USERPIN set\n");	
			
			if(!(pse_sel = af_pse_open((ObjId *)0, FALSE))) {
				if(verbose) aux_fprint_error(stderr, 0);
	
				if (verbose) fprintf(stderr, "%s: unable to open PSE %s\n", sectool_argp[0], AF_pse.app_name);
	
				if (!sec_sctest(pse_name)) notice_abort(ip->base_window, "Unable to open PSE: Check USERPIN");
				else notice_abort(ip->base_window, "Unable to open SC");
			}

			if (verbose) fprintf(stderr, "  af_pse_open OK\n");
	
			if(af_check_if_onekeypaironly(&onekeypaironly)){
				if(verbose) aux_fprint_error(stderr, 0);
				fprintf(stderr, "%s: unable to determine whether or not PSE shall hold one keypair only\n", sectool_argp[0]);
	
				notice_abort(ip->base_window, "Unable to determine whether or not PSE shall hold one keypair only");
			}

			if (verbose) fprintf(stderr, "  af_check_if_onekeypaironly: %d keypairs\n", 2 - onekeypaironly);
	
			aux_free_PSESel(&pse_sel);
	
			std_pse.app_name = aux_cpy_String(AF_pse.app_name);
			std_pse.object.name = CNULL;
			std_pse.object.pin = aux_cpy_String(AF_pse.pin);
			std_pse.pin = aux_cpy_String(AF_pse.pin);
			std_pse.app_id = AF_pse.app_id;
	
			if (af_verbose) fprintf(stderr, "  std_pse: app_name = %s, app_id = %d\n", std_pse.app_name, std_pse.app_id); 
		
#ifdef AFDBFILE
			/* Determine whether X.500 directory shall be accessed */
			strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
			strcat(afdb, "X500");           /* file = .af-db/'X500' */
			if (open(afdb, O_RDONLY) < 0) 
				x500 = FALSE;
#endif
		
#ifdef X500
			if (x500) directory_user_dname = af_pse_get_Name();
#endif
		
		
			if (af_verbose) fprintf(stderr, "  afdb = %s\n", afdb);

			fill_base_panels(ip);		

			SECTXV_BASE_IDLE("");
		}
	}


	return(notify_next_event_func(win,(Notify_event)event, arg, type));
}




/* ---------------------------------------------------------------------------------------------------------------------
 *	Destroy Interposer of SecTool Base Window
 */	

Notify_value
base_destroy_func(client, status)
	Notify_client		client;
	Destroy_status		status;
{
	static int		triedonce;

	char			*proc = "base_destroy_func";


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	switch(status) 	{

		case DESTROY_CHECKING:
				
			system(rmtemp);

/****************
 *	close SC-Port here
 ****************/


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
 * *** *** *** ***
 *	PIN stuff
 * *** *** *** ***
 */



/* ---------------------------------------------------------------------------------------------------------------------
 * 	Event callback function for `pin_popup'.
 *	UNUSED
 */
Notify_value
pin_event_handler(win, event, arg, type)
	Xv_window			win;
	Event				*event;
	Notify_arg			arg;
	Notify_event_type		type;
{
	sectxv_pin_popup_objects	*ip = (sectxv_pin_popup_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fprintf(stderr, "sectxv: pin_event_handler: event %d\n", event_id(event));
	return notify_next_event_func(win, (Notify_event) event, arg, type);
}



/*
 * Done callback function for `pin_popup'.
 */
void
pin_done_handler(frame)
	Frame		frame;
{
	char		*proc = "pin_done_handler";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	/* Do nothing at all to avoid quit from window menu */
}



/*
 * Notify callback function for `pin_button'.
 */
void
pin_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "pin_handler";
	sectxv_pin_popup_objects	*ip = (sectxv_pin_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				pin[SECTXV_PIN_LENGTH + 1];
	char				*separator = " ";
	

	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	strcpy(pin, (char *)xv_get(ip->pin_textfield, PANEL_VALUE));

	/*
	 *	empty PIN: wait for next event
	 */
	if (!strcmp(pin, ""))  {

		SECTXV_ALARM();

		return;
	}

	if ( aux_create_AFPSESel(pse_path, pin) < 0 )  {
		fprintf(stderr, "%s: ", sectool_argp[0]);
		fprintf(stderr, "Cannot create AFPSESel.\n"); 
		if (verbose) aux_fprint_error(stderr, 0);

		notice_abort(sectxv_base_window->base_window, "Cannot create AFPSESel");
	}

	if (verbose) fprintf(stderr, "  aux_create_AFPSESel() OK\n");

	if(! (pse_sel = af_pse_open((ObjId *)0, FALSE)) || !sec_pin_check(pse_sel, "pse", pin) )  {
		if(verbose) aux_fprint_error(stderr, 0);

		if (verbose) fprintf(stderr, "%s: unable to open PSE %s\n", sectool_argp[0], AF_pse.app_name);

		/*
	 	 *	Start pin_popup for next trial, leave handler
		 */
		pin_popup_open(++pin_failure_count);
	
		return;

	}

	if (verbose) fprintf(stderr, "  af_pse_open OK\n");

	if(af_check_if_onekeypaironly(&onekeypaironly)){
		if(verbose) aux_fprint_error(stderr, 0);
		fprintf(stderr, "%s: unable to determine whether or not PSE shall hold one keypair only\n", sectool_argp[0]);

		notice_abort(sectxv_base_window->base_window, "Unable to determine whether or not PSE shall hold one keypair only");
	}

	if (verbose) fprintf(stderr, "  af_check_if_onekeypaironly: %d keypairs\n", 2 - onekeypaironly);

	aux_free_PSESel(&pse_sel);

	std_pse.app_name = aux_cpy_String(AF_pse.app_name);
	std_pse.object.name = CNULL;
	std_pse.object.pin = aux_cpy_String(AF_pse.pin);
	std_pse.pin = aux_cpy_String(AF_pse.pin);
	std_pse.app_id = AF_pse.app_id;

	if (af_verbose) fprintf(stderr, "  std_pse: app_name = %s, app_id = %d\n", std_pse.app_name, std_pse.app_id); 

#ifdef AFDBFILE
	/* Determine whether X.500 directory shall be accessed */
	strcpy(afdb, AFDBFILE);         /* file = .af-db/ */
	strcat(afdb, "X500");           /* file = .af-db/'X500' */
	if (open(afdb, O_RDONLY) < 0) 
		x500 = FALSE;
#endif

#ifdef X500
	if ( x500 ) directory_user_dname = af_pse_get_Name();
#endif

	if (af_verbose) fprintf(stderr, "  afdb = %s\n", afdb);

	fill_base_panels( (sectxv_base_window_objects *)xv_get(xv_get(ip->pin_popup, XV_OWNER), XV_KEY_DATA, INSTANCE) );		

	SECTXV_HIDE(ip->pin_popup);
	SECTXV_BASE_IDLE("");
	
	pin_done_handler(ip->pin_popup);

}



/*
 *	Set PIN popup panels, check count of wrong inputs
 */

int
pin_popup_open(pin_failure_count_init)
	int				pin_failure_count_init;
{
	char				*proc = "pin_popup_open";
	sectxv_pin_popup_objects	*ip = sectxv_pin_popup;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	pin_failure_count = pin_failure_count_init;

	if (verbose) fprintf(stderr, " pin_failure_count = %d\n", pin_failure_count); 

	if (pin_failure_count >= SECTXV_PIN_FAILURES)  {

		 notice_abort(sectxv_base_window->base_window, "Can't open PSE");
	}
	
	xv_set(ip->pin_textfield, PANEL_VALUE, "", NULL);

	SECTXV_ALARM();
	SECTXV_CENTER(ip->pin_popup);
	SECTXV_SHOW(ip->pin_popup);
						
}




/*
 * *** *** *** *** *** *** *** 
 *	Base setting events
 * *** *** *** *** *** *** ***
 */



/* ---------------------------------------------------------------------------------------------------------------------
 * Event callback function for `base_setting'.
 */
void
base_setting_event_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	char				*proc = "base_setting_event_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);

	
	if (sectool_verbose) fprintf(stderr, "--> %s: no action for event %d\n", proc, event_id(event));

/*
 * 	prevent setting choice by user: skip default handler
 *	panel_default_handle_event(item, event);
 */


}




/*
 * *** *** *** *** *** 
 * 	Notice stuff
 * *** *** *** *** *** 
 */


/* ---------------------------------------------------------------------------------------------------------------------
 *	Continue-Notice
 */

int
notice_continue(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_continue";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Continue", YES,
					XV_SHOW, TRUE,
					NULL);
	xv_destroy_safe(notice);

	return;

}


/* ---------------------------------------------------------------------------------------------------------------------
 *	Cancel-Notice
 */

int
notice_cancel(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_cancel";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Cancel", YES,
					XV_SHOW, TRUE,
					NULL);
	xv_destroy_safe(notice);

	return;

}


/*
 *	Continue/Show-Notice
 */

Boolean
notice_contshow(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_contshow";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Continue", YES,
					NOTICE_BUTTON, "Show", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	if (result == YES) return(TRUE);

	
	return(FALSE);

}




/*
 *	Quit/Continue-Notice
 */

int
notice_quitcont(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_quitcont";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Continue", YES,
					NOTICE_BUTTON, "Quit", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	if (result == YES) return;

	window_done(panel);
	

	exit(-1);

}



/*
 *	Cancel/Retry-Notice
 */

int
notice_cancelretry(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_cancelretry";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel,	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Cancel", YES,
					NOTICE_BUTTON, "Retry", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	if (result == YES) return(FALSE);


	return(TRUE);

}




/*
 *	Confirm/Cancel-Notice
 */

int
notice_confcancel(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_confcancel";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Confirm", YES,
					NOTICE_BUTTON, "Cancel", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	if (result == YES) return(TRUE);


	return(FALSE);

}



/*
 *	Cancel/Continue-Notice
 */

int
notice_cancelcont(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_cancelcont";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Cancel", YES,
					NOTICE_BUTTON, "Continue", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	if (result == YES) return(TRUE);


	return(FALSE);

}




/*
 *	Abort/Restart-Notice: exit SecTool when Abort-button pressed
 */

int
notice_abortrestart(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_abortrestart";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, "FATAL ERROR !", text, NULL,
					NOTICE_BUTTON, "Abort", YES,
					NOTICE_BUTTON, "Restart", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);
	
	xv_destroy_safe(notice);


	if (result == NO) return;


	window_done(panel);


	exit(-1);

}



/*
 *	Abort-Notice: exit SecTool
 */

int
notice_abort(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_abort";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel, 	NOTICE,
					NOTICE_MESSAGE_STRINGS, "FATAL ERROR !", text, NULL,
					NOTICE_BUTTON, "Abort", YES,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	window_done(panel);


	exit(-1);

}




/*
 *	Save/Quit/Cancel-Notice
 */

int
notice_savequitcancel(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_savequitcancel";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel,	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Save & Quit", SAVE,
					NOTICE_BUTTON, "Quit", YES,
					NOTICE_BUTTON, "Cancel", NO,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	return(result);

}


/*
 *	Save/Quit-Notice
 */

int
notice_savequit(item, text)
	Panel_item		item;
	char			*text;
{
	char			*proc = "notice_savequit";
	Panel			panel = (Panel)xv_get(item, PANEL_PARENT_PANEL);
	Xv_notice 		notice;
	int			result;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	notice = xv_create(panel,	NOTICE,
					NOTICE_MESSAGE_STRINGS, text, NULL,
					NOTICE_BUTTON, "Save & Quit", SAVE,
					NOTICE_BUTTON, "Quit", YES,
					NOTICE_STATUS, &result,
					XV_SHOW, TRUE,
					NULL);

	xv_destroy_safe(notice);


	return(result);

}



/*
 * *** *** *** *** *** *** ***
 * 	helpful XView stuff
 * *** *** *** *** *** *** ***
 */




/* ---------------------------------------------------------------------------------------------------------------------
 *	get root basics --- sets globals ScreenServer, DisplayNo, ScreenNo, FullX, FullY
 */

int
get_root_basics(owner)
Xv_opaque		owner;
{
	char		*proc = "get_root_basics";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	Srv = XV_SERVER_FROM_WINDOW(owner);
	Dspl = (Display *)xv_get(owner, XV_DISPLAY);
	ScreenNo = (int)xv_get(XV_SCREEN_FROM_WINDOW(owner), SCREEN_NUMBER);
	FullX = DisplayWidth(Dspl, ScreenNo);
	FullY = DisplayHeight(Dspl, ScreenNo);

	
	return(0);

}
	
	


/* ---------------------------------------------------------------------------------------------------------------------
 *	get XDefaults
 */

int
get_xdefaults()
{
	char		*proc = "get_xdefaults";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	sectool_drag_threshold = defaults_get_integer("openWindows.dragThreshold","OpenWindows.DragThreshold",5);
	sectool_click_timeout = (double)defaults_get_integer("openWindows.multiClickTimeout", "OpenWindows.MultiClickTimeout", 4)/10.0;

	if (sectool_verbose) fprintf(stderr, "XDefaults: Drag threshold = %d\n           Multi click timeout = %f\n",
		sectool_drag_threshold, sectool_click_timeout);


	return(0);

}




/* ---------------------------------------------------------------------------------------------------------------------
 *	Create a new text base window, load text file
 */

int
open_text_window(owner, filename, label)
	Xv_opaque			owner;
	char				*filename;
	char				*label;
{
	char				*proc = "open_text_window";
	sectxv_text_window_objects	*sectxv_text_window;
	Textsw_status			status;

	
	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	sectxv_text_window = sectxv_text_window_objects_initialize(NULL, owner, label);
	xv_set(sectxv_text_window->textpane,	TEXTSW_STATUS,	&status,
						TEXTSW_FILE, 	filename,
						NULL);

	if (sectool_verbose) fprintf(stderr, "  TEXTSW_STATUS = %d\n", status);

	if (status != TEXTSW_STATUS_OKAY)  {

		notice_quitcont(owner, "Can't load temporary file");

	} else SECTXV_SHOW(sectxv_text_window->text_window);	


	return;

}





/* ---------------------------------------------------------------------------------------------------------------------
 *	Set show/print-options (read prop_show_menu)
 */

int
set_show_options()
{
	char		*proc = "set_show_options";
	int		i;


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


        print_keyinfo_flag = ALGID;
        print_cert_flag = TBS | ALG | SIGNAT;
	opt = 0;

	for (i = (int)xv_get(sectxv_show_options_menu, MENU_NITEMS); i > 0; i--)  {

		if (xv_get(xv_get(sectxv_show_options_menu, MENU_NTH_ITEM, i), MENU_SELECTED))  {

			if (sectool_verbose) fprintf(stderr, "  prop_show_menu: item %d selected\n", i);

			switch (i - 1)  {	/* menu-item 0 is no toggle item */

				case (SECTXV_SHOW_ALG):		opt |= ALG;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: ALG selected\n");
								break;	
				case (SECTXV_SHOW_BSTR):	print_keyinfo_flag |= BSTR;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: BSTR selected\n");
								break;
				case (SECTXV_SHOW_DER):		opt |= DER;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: DER selected\n");
								break;
				case (SECTXV_SHOW_ISSUER):	opt |= ISSUER;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: ISSUER selected\n");
								break;
				case (SECTXV_SHOW_KEYBITS):	print_keyinfo_flag |= KEYBITS;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: KEYBITS selected\n");
								break;
				case (SECTXV_SHOW_KEYINFO):	opt |= KEYINFO;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: KEYINFO selected\n");
								break;
				case (SECTXV_SHOW_SIGNAT):	opt |= SIGNAT;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: SIGNAT selected\n");
								break;
				case (SECTXV_SHOW_TBS):		opt |= TBS;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: TBSd selected\n");
								break;
				case (SECTXV_SHOW_VAL):		opt |= VAL;
								if (sectool_verbose) fprintf(stderr, "  prop_show_menu: VAL selected\n");
								break;
			}
		}
	}

        if(opt && opt != DER) print_cert_flag = 0;
        print_cert_flag |= opt;
			

	return;

}




/*
 * *** *** *** *** *** *** ***
 *	miscelaneous stuff
 * *** *** *** *** *** *** ***
 */




/* ---------------------------------------------------------------------------------------------------------------------
 *	Build key info for object
 */

Key *
build_key_object(item, object_name, command, open_flag) 
	Panel_item	item;
	char		*object_name;
	commands	command;
	int 		open_flag;  
{
	char		*proc = "build_key_object";
        char *cc;
	char answ[8];
	int i;
        KeyInfo zwkey;
        OctetString ostring;
	char newstring[64];
	Key *newkey;



	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	newkey = (Key *)calloc(1, sizeof(Key));

/*******
        if(command == GENKEY) {
                newkey->key = (KeyInfo *)calloc(1, sizeof(KeyInfo));
	        newkey->key->subjectAI = aux_Name2AlgId(algname);
                if(!newkey->key->subjectAI) {
			free(newkey->key);
			free(newkey);
                        return((Key *)0);
                }

        }
*******/

/*******
        if(num(object_name)) {

                if(strlen(object_name) == 0) {
			newkey->keyref = -1;
		}
                else sscanf(object_name, "%d", &(newkey->keyref));
		if(newkey->keyref == 0) newkey->keyref = -1;

		if(command == GENKEY && publickey && newkey->keyref != -1) if(newkey->keyref == publickey->keyref) {
                       	fprintf(stderr, "Public key and secret key must have different keyrefs\n");
			aux_free_Key(&newkey);
			return((Key *)0);
		}
		if(newkey->keyref > 0 && command == GENKEY && replace == FALSE) {
			if(sec_get_key(&zwkey, newkey->keyref, (Key *)0) == 0) {
				aux_free2_KeyInfo(&zwkey);
                               	fprintf(stderr, "Keyref %d exists already. Replace? (y/n): ", newkey->keyref);
                               	gets(answ);
                               	if(answ[0] == 'y') {
					sec_del_key(newkey->keyref);
					if(strcmp(s, "generated secret ") == 0) replace = TRUE;
				}
				else {
					aux_free_Key(&newkey);
					return((Key *)0);
				}
			} 
		}
        }
        else
*******/
		{

                newkey->pse_sel = aux_cpy_PSESel(&std_pse);
		strrep(&(newkey->pse_sel->object.name), object_name);

		for (i = 0; i < PSE_MAXOBJ; i++) 
			if(strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name) == 0) {
				strrep(&(newkey->pse_sel->object.pin), AF_pse.object[i].pin);
				break;
               		}



/*******
		if(command == GENKEY) {
			if(publickey) if(strcmp(newkey->pse_sel->object.name, publickey->pse_sel->object.name) == 0) {
	                       	fprintf(stderr, "Public key and secret key must be stored in different objects\n");
				aux_free_Key(&newkey);
				return((Key *)0);
			}
#ifdef SCA
			if(sec_sctest(newkey->pse_sel->app_name) == TRUE && handle_in_SCTSC(newkey) == TRUE) {
				if(strcmp(s, "generated secret ") == 0) {
                                	fprintf(stderr, "Replace existing secret key? (y/n): ");
                                	gets(answ);
                                	if(answ[0] == 'y') replace = TRUE;    
				}
				return(newkey);
                        }
#endif
		}
*******/


                if(sec_open(newkey->pse_sel) < 0) {

			/* READ only */
                        if(open_flag == OPEN_TO_READ) {
                                fprintf(stderr, "Can't open Object %s\n", newkey->pse_sel->object.name);
				aux_add_error(EINVALID, "sec_open failed", CNULL, 0, proc);
				aux_free_Key(&newkey);

				/*
				 *	Error: Quit/Continue
				 */
				sprintf(notice_text, "Can't open Object %s", object_name);
				notice_quitcont(item, notice_text);

                                return((Key *)0);
                        }

			/* Create object */
                        if (verbose) fprintf(stderr, "Create object %s\n", newkey->pse_sel->object.name);

                        strrep(&(newkey->pse_sel->object.pin), newkey->pse_sel->pin);
                        if(sec_create(newkey->pse_sel) < 0) {
                                fprintf(stderr, "Can't create Object %s\n", newkey->pse_sel->object.name);
				aux_add_error(EINVALID, "sec_open failed", CNULL, 0, proc);
				aux_free_Key(&newkey);

				/*
				 *	Error: Quit/Continue
				 */
				sprintf(notice_text, "Can't create Object %s", object_name);
				notice_quitcont(item, notice_text);

                                return((Key *)0);
                        }

/*******		if(strcmp(s, "generated public ")) replace = TRUE;
*******/
			for (i = 0; i < PSE_MAXOBJ; i++) {
				if (!strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name)) {
					strrep(&(AF_pse.object[i].pin), newkey->pse_sel->object.pin);
					break;
                      	        }
			}
                        return(newkey);
                }
 
		for (i = 0; i < PSE_MAXOBJ; i++) {
			if (!strcmp(AF_pse.object[i].name, newkey->pse_sel->object.name)) {
				strrep(&(AF_pse.object[i].pin), newkey->pse_sel->object.pin);
				break;
                        }
                        else if(open_flag == OPEN_TO_WRITE) {
				if(command == GENKEY && replace == TRUE) return(newkey);

				/*
				 *	Overwrite: Confirm/Cancel
				 */
				if (!notice_confcancel(item, "Overwrite existing object ?"))  {

					aux_free_Key(&newkey);
					return((Key *)0);

				}


/*******			if(strcmp(s, "generated public ")) replace = TRUE;
*******/

                                return(newkey);
                        }
                }
        }
        return(newkey);
}



/* ---------------------------------------------------------------------------------------------------------------------
 *	Open temporary text file
 */

int
open_write_tempfile(win)
	Xv_opaque	win;
{
	char		*proc = "open_write_tempfile";


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	logfile = fopen(tempfile, "w");
	if (logfile == (FILE * ) 0)  {

		if (verbose) fprintf(stderr, "%s: Can't open %s\n", tempfile);
		notice_quitcont(win, "Can't open temporary file");
		return(-1);
	}


	return(0);

}




/*
 *	Close temporary text file
 */

int
close_tempfile()
{
	char		*proc = "close_tempfile";


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	fclose(logfile);
	logfile = (FILE * )0;


	return;

}





/*
 *	Animation for busy state
 */

test_print()
{

	static int	i = 0;
	char		*c = " \|/-";


	fflush(stderr);

	if (! (i%3000)) fprintf(stderr, "\b%c", c[(i/3000) % 5]);
	i++;

}	
	




