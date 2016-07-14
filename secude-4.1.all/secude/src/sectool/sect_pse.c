
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

/*-----------------------sect_pse.c---------------------------------*/
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
/* MODULE   sect_pse         VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*------------------------------------------------------------------*/



#include "sect_inc.h"




static void (*pse_list_event_func)();			/* default handler */
static void (*pk_list_event_func)();			/* default handler */
static void (*ek_list_event_func)();			/* default handler */





/* ---------------------------------------------------------------------------------------------------------------------
 *	get default handler for pse list
 */
void get_pse_list_event_proc(ip)
	sectxv_base_window_objects	*ip;
{
	pse_list_event_func = (void (*)())xv_get(ip->pse_list, PANEL_EVENT_PROC);
	if (pse_list_event_func == (void (*)())NULL) {
		fprintf(stderr, "SECTOOL: Can't get default event handler for pse list\n");
		exit(-1);
	}
}


/* ---------------------------------------------------------------------------------------------------------------------
 *	get default handler for pk list
 */
void get_pk_list_event_proc(ip)
	sectxv_base_window_objects	*ip;
{
	pk_list_event_func = (void (*)())xv_get(ip->pk_list, PANEL_EVENT_PROC);
	if (pk_list_event_func == (void (*)())NULL) {
		fprintf(stderr, "SECTOOL: Can't get default event handler for pk list\n");
		exit(-1);
	}
}


/* ---------------------------------------------------------------------------------------------------------------------
 *	get default handler for ek list
 */
void get_ek_list_event_proc(ip)
	sectxv_base_window_objects	*ip;
{
	ek_list_event_func = (void (*)())xv_get(ip->ek_list, PANEL_EVENT_PROC);
	if (ek_list_event_func == (void (*)())NULL) {
		fprintf(stderr, "SECTOOL: Can't get default event handler for ek list\n");
		exit(-1);
	}
}






/*
 * *** *** *** ***
 *	PSE stuff
 * *** *** *** ***
 */





/* ---------------------------------------------------------------------------------------------------------------------
 * Event callback function for `pse_list'.
 */
void
pse_event_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	static int			drag_pixels;

	char				*proc = "pse_event_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fprintf(stderr, "sectxv: pse_event_handler: event %d\n", event_id(event));


	switch(event_action(event)) {

		case ACTION_SELECT:

			if (!event_is_down(event)) drag_pixels = 0;
			break;

		case LOC_DRAG:
			if (action_select_is_down(event))  {

				if (xv_get(ip->pse_list, PANEL_CLIENT_DATA) && (drag_pixels++ >= sectool_drag_threshold))  {

					switch (dnd_send_drop(ip->dnd))  {		/* source the drag */

						case XV_OK:
							break;
						case DND_TIMEOUT:
							SECTXV_BASE_IDLE("Drag and Drop: Timed out");
							break;
						case DND_ILLEGAL_TARGET:
							SECTXV_BASE_IDLE("Drag and Drop: Illegal target");
							break;
						case DND_SELECTION:
							SECTXV_BASE_IDLE("Drag and Drop: Bad selection");
							break;
						case DND_ROOT:
							SECTXV_BASE_IDLE("Drag and Drop: Root");
							break;
						case XV_ERROR:
							SECTXV_BASE_IDLE("Drag and Drop: Failed");
							break;
						}
					drag_pixels = 0;
					return;
				} 
			} else drag_pixels = 0;
			break;
	}

	(*pse_list_event_func)(item, event);			/* call default handler to process other events */


	return;

}





/* ---------------------------------------------------------------------------------------------------------------------
 * Notify callback function for `pse_list'.
 */
int
pse_content_handler(item, string, client_data, op, event)
	Panel_item			item;
	char				*string;
	Xv_opaque			client_data;
	Panel_list_op			op;
	Event				*event;
{
	static char	 		*lastselected;
	static double 			lasttime;

	char				*proc = "pse_content_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char 				*list_data = (char *)client_data;
	double				newtime;
	int				ret;
	
	
	switch(op)  {

		case PANEL_LIST_OP_DESELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: pse_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);
			break;
	
		case PANEL_LIST_OP_SELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: pse_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, (char *)client_data, NULL);
			break;

		default:

			return(XV_OK);
	}

	/* process double click */
	if (list_data == lastselected)  {

		newtime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;
		if ((newtime - lasttime) <= sectool_click_timeout)  {

			if (open_write_tempfile(ip->base_window) < 0) return(XV_OK);
			SECTXV_BASE_BUSY("Reading from PSE...");
			set_show_options();
			ret = fprintf_pse_object(ip, list_data);
			close_tempfile();
			if (ret >= 0) open_text_window(ip->base_window, tempfile, list_data);
			SECTXV_BASE_IDLE("");
			lastselected = CNULL;

			return(XV_OK);
		}
	}

	lastselected = list_data;
	lasttime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;


	return(XV_OK);

}




/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_menu (Key Pool)'.
 */
Menu_item
pse_key_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pse_key_handler";
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_key_handler: MENU_NOTIFY\n", stderr);


		SECTXV_BASE_BUSY("Reading from Keypool...");
		SECTXV_SHOW(sectxv_key_popup->key_popup);
		SECTXV_BASE_IDLE("");

		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_pse_menu (Change PIN)'.
 */
Menu_item
pse_chpin_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char		*proc = "pse_chpin_handler";
	Xv_opaque 	ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);



	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);



	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_chpin_handler: MENU_NOTIFY\n", stderr);


		chpin_popup_open(sectxv_chpin_popup);


		break;

	case MENU_NOTIFY_DONE:
		break;
	}

	return item;
}



	

/*
 * Done callback function for `chpin_popup'.
 */
void
chpin_done_handler(frame)
	Frame		frame;
{
	char	*proc = "chpin_done_handler";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);

	SECTXV_HIDE(frame);
	SECTXV_BASE_IDLE("");

}



/*
 * Notify callback function for `chpin_apply_button'.
 */
void
chpin_apply_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char				*proc = "chpin_apply_handler";
	sectxv_chpin_popup_objects	*ip = (sectxv_chpin_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);




/*---------------------------------
	confirm change pse pin
---------------TEST----------------*/




	chpin_done_handler(sectxv_chpin_popup->chpin_popup);
	
}



/*
 * Notify callback function for `chpin_cancel_button'.
 */
void
chpin_cancel_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char				*proc = "chpin_cancel_handler";
	sectxv_chpin_popup_objects	*ip = (sectxv_chpin_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	chpin_done_handler(sectxv_chpin_popup->chpin_popup);


}



/*
 *	Set CHPIN popup panels
 */
int
chpin_popup_open(ip)
	sectxv_chpin_popup_objects	*ip;
{
	char				*proc = "chpin_popup_open";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);
	

	SECTXV_BASE_BUSY("Reading from PSE...");
	SECTXV_SHOW(ip->chpin_popup);
	SECTXV_ALARM();
	SECTXV_CENTER(ip->chpin_popup);
					
}
	
						






/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_pse_menu (Check)'.
 */ 
Menu_item
pse_check_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pse_check_handler";

	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_check_handler: MENU_NOTIFY\n", stderr);


		if (open_write_tempfile(ip->base_window) < 0) break;

		SECTXV_BASE_BUSY("Reading from PSE...");

		secretkey = (Key *)malloc(sizeof(Key));
		secretkey->key = (KeyInfo *)0;
		secretkey->keyref = 0;
		secretkey->pse_sel = &std_pse;
		signpk = (KeyInfo *)0;
		encpk = (KeyInfo *)0;
		signsubject = NULLDNAME;
		encsubject = NULLDNAME;

		certs = af_pse_get_Certificates(SIGNATURE, NULLDNAME);
		if(!certs)  {

			if (onekeypaironly == TRUE)  {

				fprintf(logfile, "Can't get Certificates from PSE (Cert and/or FCPath missing\n");
				free(secretkey);
				goto show_results;

			} else  {

				fprintf(logfile, "Can't get SIGNATURE Certificates from PSE (SignCert and/or FCPath missing\n");
				goto enccert;
			}
		}
		signpk = aux_cpy_KeyInfo(certs->usercertificate->tbs->subjectPK);
		secretkey->alg = signpk->subjectAI;
		signsubject = aux_cpy_DName(certs->usercertificate->tbs->subject);
		sectool_verbose = TRUE;
		if(onekeypaironly == TRUE)
			fprintf(logfile, "\nVerifying Cert with FCPath and PKRoot ...\n");
		else
			fprintf(logfile, "\nVerifying SignCert with FCPath and PKRoot ...\n");
		rcode = af_verify_Certificates(certs, (UTCTime *)0, (PKRoot *)0);
		aux_free_Certificates(&certs);
		if(onekeypaironly == TRUE)
			fprintf(logfile, "\nChecking whether the keys in Cert and SKnew are an RSA key pair ... ");
		else
			fprintf(logfile, "\nChecking whether the keys in SignCert and SignSK are an RSA key pair ... ");
		if(onekeypaironly == TRUE)
			std_pse.object.name = SKnew_name;
		else
			std_pse.object.name = SignSK_name;
		rcode = sec_checkSK(secretkey, signpk);
		if(rcode < 0){
			if(onekeypaironly == TRUE)
				fprintf(logfile, "\nRSA keys in SKnew and Cert do not fit\n");
			else
				fprintf(logfile, "\nRSA keys in SignSK and SignCert do not fit\n");
		}
		else fprintf(logfile, "O.K.\n");
		if(onekeypaironly == TRUE)
			goto show_results;
enccert:
		certs = af_pse_get_Certificates(ENCRYPTION, NULLDNAME);
		if(!certs) {
			fprintf(logfile, "Can't get ENCRYPTION Certificates from PSE (EncCert and/or FCPath missing)\n");
			if(signpk) aux_free_KeyInfo(&signpk);
			if(signsubject) aux_free_DName(&signsubject);
			free(secretkey);
			goto show_results;
		}
		encpk = aux_cpy_KeyInfo(certs->usercertificate->tbs->subjectPK);
		encsubject = aux_cpy_DName(certs->usercertificate->tbs->subject);
		if(signsubject) if(aux_cmp_DName(signsubject, encsubject)) {
			fprintf(logfile, "SignCert and EncCert have different subject names\n");
		}
		own_dname = af_pse_get_Name();
		if(!own_dname) fprintf(logfile, "Can't read Name from PSE\n");
		if(own_dname)  if(aux_cmp_DName(encsubject, own_dname)) {
			fprintf(logfile, "Distinguished name in Name is differnt to that of SignCert/EncCert\n");
		}
		if(own_dname) aux_free_DName(&own_dname);
		if(signsubject) aux_free_DName(&signsubject);
		aux_free_DName(&encsubject);
		fprintf(logfile, "\nVerifying EncCert with FCPath and PKRoot ...\n");
		rcode = af_verify_Certificates(certs, (UTCTime *)0, (PKRoot *)0);
		aux_free_Certificates(&certs);
		fprintf(logfile, "\nChecking whether the keys in EncCert and DecSKnew are an RSA key pair ... ");
		std_pse.object.name = DecSKnew_name;
		secretkey->alg = encpk->subjectAI;
		rcode = sec_checkSK(secretkey, encpk);
		if(rcode < 0) fprintf(logfile, "\nRSA keys in DecSKnew and EncCert do not fit\n");
		else fprintf(logfile, "O.K.\n");
		aux_free_KeyInfo(&signpk);
		aux_free_KeyInfo(&encpk);
		free(secretkey);


show_results:
	
		close_tempfile();

		SECTXV_BASE_IDLE("");
			
		open_text_window(ip->base_window, tempfile, "PSE check");

	
		break;


	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}






/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_pse_menu (Prototype)'.
 */
Menu_item
pse_prototype_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_prototype_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Show)'.
 */
Menu_item
pse_show_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pse_show_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*object_name;
	

	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	switch (op) {

	case MENU_NOTIFY:

		if (open_write_tempfile(ip->base_window) < 0) return(-1);

		SECTXV_BASE_BUSY("Reading from PSE...");

		/* get show options from prop_show_menu */
		set_show_options();

		if (object_name = (char *)xv_get(ip->pse_list, PANEL_CLIENT_DATA))  {

			fprintf_pse_object(ip, object_name);
			close_tempfile();
			open_text_window(ip->base_window, tempfile, object_name);
		}

		SECTXV_BASE_IDLE("");
		break;
	}


	return(item);

}




/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Create)'.
 */
Menu_item
pse_create_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_create_handler";

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:


		create_popup_open(sectxv_create_popup);


		break;


	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}


/* 
 * Event callback function for `create_popup'
 */
Notify_value
create_event_handler(win, event, arg, type)
	Xv_window			win;
	Event				*event;
	Notify_arg			arg;
	Notify_event_type		 type;
{
	char				*proc = "create_event_handler";
	sectxv_create_popup_objects	*ip = (sectxv_create_popup_objects *) xv_get(win, XV_KEY_DATA, INSTANCE);
	Fullscreen			fs;
	Inputmask			im;


	if (!xv_get(win, FRAME_CLOSED))  { 

		fprintf(stderr, "--> %s\n", proc);
	
	
		win_setinputcodebit(&im, MS_LEFT);
		win_setinputcodebit(&im, MS_MIDDLE);
		win_setinputcodebit(&im, MS_RIGHT);
		win_setinputcodebit(&im, LOC_MOVE);
		
		xv_set(ip->create_popup,
			WIN_CONSUME_EVENTS,
				WIN_MOUSE_BUTTONS, LOC_MOVE, NULL,
			NULL);
	
		while (xv_input_readevent(win, event, TRUE, TRUE, &im) != -1)
			if (event_is_button(event)) break;
	
		xv_destroy(fs);					
	
	
		fprintf(stderr, "--> %s ready\n", proc);
	}
	

	return(notify_next_event_func(win,(Notify_event)event, arg, type));


}



/*
 * Done callback function for `create_popup'.
 */
void
create_done_handler(frame)
	Frame		frame;
{
	if (sectool_verbose) fputs("sectxv: create_done_handler\n", stderr);

	SECTXV_BASE_IDLE("");
	SECTXV_HIDE(frame);


	return;

}




/*
 * Notify callback function for `create_apply_button'.
 */
void
create_apply_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char				*proc = "create_apply_handler";
	sectxv_create_popup_objects	*ip = (sectxv_create_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*newname;
	PSEToc				*main_toc;
	struct PSE_Objects 		*obj = (struct PSE_Objects *) 0;
	char				*create;
	char				*update;
	unsigned int			i;
	Xv_opaque			glyph_object;
	

	if (sectool_verbose) fprintf(stderr, "-->%s", proc);


	newname = aux_cpy_ReducedString((char *)xv_get(ip->create_textfield, PANEL_VALUE));

	if (sectool_verbose) fprintf(stderr, "  new name = %s\n", newname);

	/* New name = CNULL: wait for next event */
	if (!newname)  {

		SECTXV_ALARM();

		return;
	}

        if(std_pse.object.name) free(std_pse.object.name);
        std_pse.object.name = newname;

	if((rcode = sec_create(&std_pse)) == 0)  {

		if (verbose) fprintf(stderr, "  object created: %s\n", newname);

		AF_pse.app_name = std_pse.app_name;
		AF_pse.pin = std_pse.pin;
		AF_pse.app_id = std_pse.app_id;
		if (std_pse.object.name)  {
			for (i = 0; i < PSE_MAXOBJ; i++) 
				if (strcmp(AF_pse.object[i].name, std_pse.object.name) == 0)  {
					if(std_pse.object.pin)  {
						AF_pse.object[i].pin = (char *)malloc(strlen(std_pse.object.pin) + 1);
						strcpy (AF_pse.object[i].pin, std_pse.object.pin);
					}
					else AF_pse.object[i].pin = (char *)0;
				}  
		}
	} else  {

		if (verbose) fprintf(stderr, "  Can't create object: %s\n", newname);
		notice_quitcont(item, "Can't create object");
		if (newname) free(newname);

		create_done_handler(ip->create_popup);
		
		return;
	}

	/* read toc */
	if (sec_read_tocs(&std_pse, &sctoc, &psetoc) < 0 || (!sctoc && !psetoc))  {		

		aux_add_error(EREADPSE, "sec_read_tocs failed", CNULL, 0, proc);
		notice_abort(sectxv_base_window->pse_list, "Can't read Table Of Contents");
	}

	if (sctoc)  {
	
		obj = sctoc->obj;
		while (obj)  {
	
			/* object is in sctoc */
			if (! strcmp(obj->name, std_pse.object.name) )  {

				create = aux_readable_UTCTime(obj->create);
				update = aux_readable_UTCTime(obj->update);

				glyph_object = sectxv_pse_list_sc_glyph;	

				break;
			}
			obj = obj->next;
		}
	}

	if (!obj && psetoc)  {
	
		obj = psetoc->obj;
		while (obj)  {
	
			/* object is in psetoc */
			if (! strcmp(obj->name, std_pse.object.name) )  {

				create = aux_readable_UTCTime(obj->create);
				update = aux_readable_UTCTime(obj->update);	

				glyph_object = sectxv_pse_list_swpse_glyph;	

				break;
			}
			obj = obj->next;
		}
	}

	if (obj)  {

		pse_list_panel_update(sectxv_base_window, obj->name, create, update, &(obj->noOctets), glyph_object);

		if (create) free(create);
		if (update) free(update);
	
	} else  {

		if (verbose) fprintf(stderr, "  Can't read new object from toc: %s\n", std_pse.object.name);
		notice_quitcont(sectxv_base_window->pse_list, "Can't read new object from Table Of Contents");
	}		

	pse_toc_panels_update(sectxv_base_window, CNULL);

	if (newname) free(newname);	

	create_done_handler(ip->create_popup);

	
	return;
	
}




/*
 * Notify callback function for `create_cancel_button'.
 */
void
create_cancel_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	sectxv_create_popup_objects	*ip = (sectxv_create_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: create_cancel_handler\n", stderr);


	create_done_handler(ip->create_popup);

}



/*
 *	Set CREATE popup panels
 */
int
create_popup_open(ip)
	sectxv_create_popup_objects	*ip;
{
	char				*proc = "create_popup_open";


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);
	

	xv_set(ip->create_textfield, PANEL_VALUE, "", NULL);

	SECTXV_BASE_BUSY("Writing to PSE...");
	SECTXV_CENTER(ip->create_popup);
	SECTXV_SHOW(ip->create_popup);
						
}
	
						



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (File Out)'.
 */
Menu_item
pse_read_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_read_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_read_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (File In)'.
 */
Menu_item
pse_write_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_write_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_write_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Rename)'.
 */
Menu_item
pse_rename_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_rename_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_rename_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Generate)'.
 */
Menu_item
pse_generate_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_generate_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_generate_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Split Cross)'.
 */
Menu_item
pse_split_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_split_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_split_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (XDump)'.
 */
Menu_item
pse_xdump_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "pse_xdump_handler";

	Xv_opaque ip = (Xv_opaque) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pse_xdump_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Menu handler for `pse_objects_menu (Delete)'.
 */
Menu_item
pse_delobject_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pse_delobject_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*object_name;


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	switch (op) {

	case MENU_NOTIFY:

		if (sectool_verbose) fputs("sectxv: pse_delobject_handler: MENU_NOTIFY\n", stderr);

		if (! (object_name = (char *)xv_get(ip->pse_list, PANEL_CLIENT_DATA)) ) return(item);

		SECTXV_BASE_BUSY("Accessing PSE...");

		/* delete only empty PKList/EKList */
		if (!strcmp(object_name, "PKList") && af_pse_get_PKList(SIGNATURE))  {

			notice_cancel(ip->pk_list, "PKList is not empty");

		} else if (!onekeypaironly && !strcmp(object_name, "EKList") && af_pse_get_PKList(ENCRYPTION))  {

			notice_cancel(ip->ek_list, "EKList is not empty");

		} else  {
		
			std_pse.object.name = object_name;

			sprintf(notice_text, "Delete object\n%s ?", object_name);
			if (notice_confcancel(ip->pse_list, notice_text))  {

				if (sec_delete(&std_pse))  {		/* not deleted */

					if (verbose) fprintf(stderr, "Can't delete object %s\n", object_name);
					sprintf(notice_text, "Can't delete object\n%s", object_name);
					notice_quitcont(ip->pse_list, notice_text);

				} else  {				/* deleted */
	
					if (verbose) fprintf(stderr, "Deleted: %s\n", object_name);
					pse_toc_panels_update(ip, object_name);
					if (object_name) free(object_name);
				}
			}
		}

		SECTXV_BASE_IDLE("");

		break;

	}


	return(item);
}



/* ---------------------------------------------------------------------------------------------------------------------
 * 	Write selected pselist entries in tempfile
 */
int
fprintf_pse_object(ip, name)
	sectxv_base_window_objects	*ip;
	char				*name;
{
	char				*proc = "fprintf_pse_object";
	

	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	
	if(! (key = build_key_object(ip->pse_list, name, SHOW, OPEN_TO_READ)))  {

		if (sectool_verbose) fprintf(stderr, "  build_key_object failed\n");
		return(-1);
	}

	if(opt && opt != DER) print_cert_flag = 0;
	print_cert_flag |= opt;

	if(key->pse_sel)  {

		ostr = &octetstring;
		if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {

			if (verbose) fprintf(stderr,"  Can't read from PSE: %s\n", name);
			sprintf(notice_text,"  Can't read object from PSE\n%s", name);
			notice_quitcont(ip->pse_list, notice_text);
			aux_free_Key(&key);


			return(-1);

		} else  {

			fprintf(logfile, "\n\n\n ________________________________________________\n");
			fprintf(logfile,       "|                                                |\n");
			fprintf(logfile,       "|    %-40.40s    |\n", name);
			fprintf(logfile,       "|________________________________________________|\n\n");
	
			if(aux_cmp_ObjId(&object_oid, SignSK_OID) == 0
			     || aux_cmp_ObjId(&object_oid, DecSKnew_OID) == 0 
			     || aux_cmp_ObjId(&object_oid, DecSKold_OID) == 0
			     || aux_cmp_ObjId(&object_oid, SKnew_OID) == 0 
			     || aux_cmp_ObjId(&object_oid, SKold_OID) == 0)  {
				if(!(keyinfo = d_KeyInfo(ostr))) goto decodeerr;
				fprintf(logfile, "SecretKeyAid: ");
				print_keyinfo_flag |= SK;
				aux_fprint_KeyInfo(logfile, keyinfo);
				aux_free_KeyInfo(&keyinfo);
			}
			else if(aux_cmp_ObjId(&object_oid, Name_OID) == 0) {
				if(!(dname = d_DName(ostr))) goto decodeerr;
				if(!(name = aux_DName2Name(dname))) {
					       fprintf(logfile, "Can't build printable repr. of %s\n", key->pse_sel->object.name);
			}
			else fprintf(logfile, "%s\n", name);
			aux_free_DName(&dname);
			}
			else if(aux_cmp_ObjId(&object_oid, SerialNumbers_OID) == 0){
				if(! (serialnums = d_SerialNumbers(ostr))) goto decodeerr;
				aux_fprint_SerialNumbers(logfile, serialnums);
				aux_free_SerialNumbers(& serialnums);
			}
			else if(aux_cmp_ObjId(&object_oid, SignCert_OID) == 0
				   || aux_cmp_ObjId(&object_oid, EncCert_OID) == 0
				   || aux_cmp_ObjId(&object_oid, Cert_OID) == 0) { 
					if(!(certificate = d_Certificate(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_Certificate(logfile, certificate);
					aux_free_Certificate(&certificate);
				}
			else if(aux_cmp_ObjId(&object_oid, SignCSet_OID) == 0
				   || aux_cmp_ObjId(&object_oid, EncCSet_OID) == 0
				   || aux_cmp_ObjId(&object_oid, CSet_OID) == 0) { 
					if(!(certset = d_CertificateSet(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_CertificateSet(logfile, certset);
					aux_free_CertificateSet(&certset);
				}
			else if(aux_cmp_ObjId(&object_oid, FCPath_OID) == 0) {
					if(!(fcpath = d_FCPath(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_FCPath(logfile, fcpath);
					aux_free_FCPath(&fcpath);
				}
			else if(aux_cmp_ObjId(&object_oid, PKRoot_OID) == 0) {
					if(!(pkroot = d_PKRoot(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_PKRoot(logfile, pkroot);
				}
			else if(aux_cmp_ObjId(&object_oid, PKList_OID) == 0
				   || aux_cmp_ObjId(&object_oid, EKList_OID) == 0) { 
					if(!(pklist = d_PKList(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_PKList(logfile, pklist);
				}
			else if(aux_cmp_ObjId(&object_oid, CrossCSet_OID) == 0) {
					if(!(cpairset = d_CertificatePairSet(ostr))) goto decodeerr;
					print_keyinfo_flag |= PK;
					aux_fprint_CertificatePairSet(logfile, cpairset);
					aux_free_CertificatePairSet(&cpairset);
				}
/*******                else if(aux_cmp_ObjId(&object_oid, CrlSet_OID) == 0) {
					if(!(crlset = d_CrlSet(ostr))) goto decodeerr;
					aux_fprint_CrlSet(logfile, crlset);
					aux_free_CrlSet(&crlset);
				}
*******/		else {
				fprintf(logfile, "Object OID { ");

				if((certificate = d_Certificate(ostr))) {
					print_keyinfo_flag |= PK;
					aux_fprint_Certificate(logfile, certificate);
					aux_free_Certificate(&certificate);
				}
				else if((dname = d_DName(ostr))) {
						if(!(name = aux_DName2Name(dname))) {
							       fprintf(logfile, "Can't build printable repr. of %s\n", key->pse_sel->object.name);
						}
						else fprintf(logfile, "%s\n", name);
						aux_free_DName(&dname);
				}
				else if((fcpath = d_FCPath(ostr))) {
						aux_fprint_FCPath(logfile, fcpath);
						aux_free_FCPath(&fcpath);
				}
				else if((pkroot = d_PKRoot(ostr))) {
						aux_fprint_PKRoot(logfile, pkroot);
						aux_free_PKRoot(&pkroot);
				}
				else if((certset = d_CertificateSet(ostr))) {
						aux_fprint_CertificateSet(logfile, certset);
						aux_free_CertificateSet(&certset);
				}
				else if((pklist = d_PKList(ostr))) {
						aux_fprint_PKList(logfile, pklist);
						aux_free_PKList(&pklist);
				}
				else if((keyinfo = d_KeyInfo(ostr))) {
						fprintf(logfile, "PublicKeyAid: ");
						print_keyinfo_flag |= PK;
						aux_fprint_KeyInfo(logfile, keyinfo);
						aux_free_KeyInfo(&keyinfo);
				}
				else if ((cpairset = d_CertificatePairSet(ostr))) {
						aux_fprint_CertificatePairSet(logfile, cpairset);
						aux_free_CertificatePairSet(&cpairset);
				}
/*******	                else if((crlset = d_CrlSet(ostr))) {
						aux_fprint_CrlSet(logfile, crlset);
						aux_free_CrlSet(&crlset);
				}
*******/			else {
					for(i = 0; i < object_oid.oid_nelem; i++) {
						     printf("%d ", object_oid.oid_elements[i]);
					}
					fprintf(logfile, " }\n");
					aux_xdump(ostr->octets, ostr->noctets, 0);
				}
			}

			print_keyinfo_flag = ALGID;
			print_cert_flag = TBS | ALG | SIGNAT;
			if(ostr->octets) free(ostr->octets);
			aux_free2_ObjId(&object_oid);
			aux_free_Key(&key);
		}
	}

	/* skip decode error handling */
	return(0);

decodeerr:
	fprintf(logfile, "Can't decode %s\n", key->pse_sel->object.name);
	if(ostr->octets) free(ostr->octets);
	aux_free_Key(&key);

	sprintf(notice_text,"Can't decode object name\n%s", key->pse_sel->object.name);
	notice_quitcont(ip->pse_list, notice_text);


	return(-1);

}





/*
 * *** *** *** *** ***
 *	PKList stuff
 * *** *** *** *** ***
 */



/* ---------------------------------------------------------------------------------------------------------------------
 * Event callback function for `pk_list'.
 */
void
pk_event_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	static int			drag_pixels;

	char				*proc = "pk_event_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose) fprintf(stderr, "sectxv: pk_event_handler: event %d\n", event_id(event));


	switch(event_action(event)) {

		case ACTION_SELECT:

			if (!event_is_down(event)) drag_pixels = 0;
			break;

		case LOC_DRAG:
			if (action_select_is_down(event))  {

				if (xv_get(ip->pk_list, PANEL_CLIENT_DATA) && (drag_pixels++ >= sectool_drag_threshold))  {

					switch (dnd_send_drop(ip->dnd))  {		/* source the drag */

						case XV_OK:
							break;
						case DND_TIMEOUT:
							SECTXV_BASE_IDLE("Drag and Drop: Timed out");
							break;
						case DND_ILLEGAL_TARGET:
							SECTXV_BASE_IDLE("Drag and Drop: Illegal target");
							break;
						case DND_SELECTION:
							SECTXV_BASE_IDLE("Drag and Drop: Bad selection");
							break;
						case DND_ROOT:
							SECTXV_BASE_IDLE("Drag and Drop: Root");
							break;
						case XV_ERROR:
							SECTXV_BASE_IDLE("Drag and Drop: Failed");
							break;
						}
					drag_pixels = 0;
					return;
				} 
			} else drag_pixels = 0;
			break;
	}

	(*pk_list_event_func)(item, event);			/* call default handler to process other events */


	return;

}



/* ---------------------------------------------------------------------------------------------------------------------
 * Notify callback function for `pk_list'.
 */
int
pk_content_handler(item, string, client_data, op, event)
	Panel_item			item;
	char				*string;
	Xv_opaque			client_data;
	Panel_list_op			op;
	Event				*event;
{
	static PKList_client_data	*lastselected;
	static double 			lasttime;

	char				*proc = "pk_content_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	PKList_client_data 		*list_data = (PKList_client_data *)client_data;
	double				newtime;
	int				ret;

	
	switch(op)  {

		case PANEL_LIST_OP_DESELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: pk_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);
			break;

		case PANEL_LIST_OP_SELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: pk_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, (PKList_client_data *)client_data, NULL);
			break;

		default:

			return(XV_OK);
	}

	/* process double click */
	if (list_data == lastselected)  {

		newtime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;
		if ((newtime - lasttime) <= sectool_click_timeout)  {

			if (open_write_tempfile(ip->base_window) < 0) return(XV_OK);
			SECTXV_BASE_BUSY("Reading from PSE...");
			set_show_options();
			ret = fprintf(logfile, "\n\n	<SerialNumber> %d\n\n", list_data->serial);
			close_tempfile();
			if (ret >= 0) open_text_window(ip->base_window, tempfile, "PKList content");
			SECTXV_BASE_IDLE("");
			lastselected = (PKList_client_data *) 0;

			return(XV_OK);
		}
	}

	lastselected = list_data;
	lasttime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;


	return XV_OK;

}



/*
 * Menu handler for `pk_menu (Show)'.
 */
Menu_item
pk_show_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char				*proc = "pk_show_handler";


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:


		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `pk_menu (XDump)'.
 */
Menu_item
pk_xdump_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	sectxv_base_window_objects *ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: pk_xdump_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `pk_menu (Add)'.
 */
Menu_item
pk_addpk_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pk_addpk_handler";
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	

	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);


	switch (op) {

		case MENU_NOTIFY:
			if (sectool_verbose) fputs("sectxv: pk_addpk_handler: MENU_NOTIFY\n", stderr);


			/* add selected pse_list entry to pk_list*/
			pk_add_list(ip, SIGNATURE);
	
			break;
	}


	return item;
}



/*
 * Menu handler for `pk_menu (Delete)'.
 */
Menu_item
pk_delpk_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "pk_delpk_handler";
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	switch (op) {

	case MENU_NOTIFY:

		if (sectool_verbose) fputs("sectxv: pk_delpk_handler: MENU_NOTIFY\n", stderr);


		/* delete selected list entry */
		pk_delete_list(ip, SIGNATURE);



		break;


	}


	return item;

}





/*
 * *** *** *** *** ***
 *	EKList stuff
 * *** *** *** *** ***
 */




/* ---------------------------------------------------------------------------------------------------------------------
 * Event callback function for `ek_list'.
 */
void
ek_event_handler(item, event)
	Panel_item			item;
	Event				*event;
{
	static int			drag_pixels;

	char				*proc = "ek_event_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);


	if (sectool_verbose) fprintf(stderr, "sectxv: ek_event_handler: event %d\n", event_id(event));


	switch(event_action(event)) {

		case ACTION_SELECT:

			if (!event_is_down(event)) drag_pixels = 0;
			break;

		case LOC_DRAG:
			if (action_select_is_down(event))  {

				if (xv_get(ip->ek_list, PANEL_CLIENT_DATA) && (drag_pixels++ >= sectool_drag_threshold))  {

					switch (dnd_send_drop(ip->dnd))  {		/* source the drag */

						case XV_OK:
							break;
						case DND_TIMEOUT:
							SECTXV_BASE_IDLE("Drag and Drop: Timed out");
							break;
						case DND_ILLEGAL_TARGET:
							SECTXV_BASE_IDLE("Drag and Drop: Illegal target");
							break;
						case DND_SELECTION:
							SECTXV_BASE_IDLE("Drag and Drop: Bad selection");
							break;
						case DND_ROOT:
							SECTXV_BASE_IDLE("Drag and Drop: Root");
							break;
						case XV_ERROR:
							SECTXV_BASE_IDLE("Drag and Drop: Failed");
							break;
						}
					drag_pixels = 0;
					return;
				} 
			} else drag_pixels = 0;
			break;
	}

	(*ek_list_event_func)(item, event);			/* call default handler to process other events */
	return;
}



/* ---------------------------------------------------------------------------------------------------------------------
 * Notify callback function for `ek_list'.
 */
int
ek_content_handler(item, string, client_data, op, event)
	Panel_item	item;
	char		*string;
	Xv_opaque	client_data;
	Panel_list_op	op;
	Event		*event;
{
	static char		 	*lastselected;
	static double 			lasttime;

	char				*proc = "ek_content_handler";
	sectxv_base_window_objects	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	char 				*list_data = (char *)client_data;
	double				newtime;
	int				ret;
	
	switch(op)  {

		case PANEL_LIST_OP_DESELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: ek_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, SECTXV_NO_SELECTION, NULL);
			break;

		case PANEL_LIST_OP_SELECT:

			if (sectool_verbose) fprintf(stderr, "sectxv: ek_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
			xv_set(item, PANEL_CLIENT_DATA, (char *)client_data, NULL);
			break;

		default:

			return(XV_OK);
	}

	/* process double click */
	if (list_data == lastselected)  {

		newtime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;
		if ((newtime - lasttime) <= sectool_click_timeout)  {

			if (open_write_tempfile(ip->base_window) < 0) return(XV_OK);
			SECTXV_BASE_BUSY("Reading from PSE...");
			set_show_options();
			ret = fprintf_pse_object(ip, list_data);
			close_tempfile();
			if (ret >= 0) open_text_window(ip->base_window, tempfile, list_data);
			SECTXV_BASE_IDLE("");
			lastselected = CNULL;

			return(XV_OK);
		}
	}

	lastselected = list_data;
	lasttime = event->ie_time.tv_sec + event->ie_time.tv_usec/1000000.0;


	return XV_OK;

}




/*
 * Menu handler for `ek_menu (Show)'.
 */
Menu_item
ek_show_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ek_show_handler";

	sectxv_base_window_objects *ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: ek_show_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `ek_menu (XDump)'.
 */
Menu_item
ek_xdump_handler(item, op)
	Menu_item	item;
	Menu_generate	op;
{
	char	*proc = "ek_xdump_handler";

	sectxv_base_window_objects *ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {
	case MENU_DISPLAY:
		break;

	case MENU_DISPLAY_DONE:
		break;

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: ek_xdump_handler: MENU_NOTIFY\n", stderr);
		break;

	case MENU_NOTIFY_DONE:
		break;
	}
	return item;
}



/*
 * Menu handler for `ek_menu (Add)'.
 */
Menu_item
ek_addek_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "ek_addek_handler";
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch (op) {

	case MENU_NOTIFY:
		if (sectool_verbose) fputs("sectxv: ek_addek_handler: MENU_NOTIFY\n", stderr);


		/* add selected pse_list entry to ek_list*/
		pk_add_list(ip, ENCRYPTION);

	
		break;

	}
	return item;
}



/*
 * Menu handler for `ek_menu (Delete)'.
 */
Menu_item
ek_delek_handler(item, op)
	Menu_item			item;
	Menu_generate			op;
{
	char				*proc = "ek_delek_handler";
	sectxv_base_window_objects 	*ip = (sectxv_base_window_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	switch (op) {

	case MENU_NOTIFY:

		if (sectool_verbose) fputs("sectxv: ek_delek_handler: MENU_NOTIFY\n", stderr);


		/* delete selected list entry */
		pk_delete_list(ip, ENCRYPTION);


		break;


	}


	return item;

}



/*
 * *** *** *** *** *** ***
 *	Key Pool stuff
 * *** *** *** *** *** ***
 */



/* ---------------------------------------------------------------------------------------------------------------------
 * Done callback function for `key_popup'.
 */
void
key_done_handler(frame)
	Frame		frame;
{
	char	*proc = "key_done_handler";

	if (sectool_verbose) fputs("sectxv: key_done_handler\n", stderr);
	SECTXV_HIDE(frame);
}




/*
 * Notify callback function for `key_show_button'.
 */
void
key_show_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_show_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_show_handler\n", stderr);
}



/*
 * Notify callback function for `key_xdump_button'.
 */
void
key_xdump_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_xdump_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_xdump_handler\n", stderr);
}



/*
 * Notify callback function for `key_genkey_button'.
 */
void
key_generate_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_generate_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_generate_handler\n", stderr);
}



/*
 * Notify callback function for `key_string2key_button'.
 */
void
key_string2key_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_string2key_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_string2key_handler\n", stderr);
}



/*
 * Notify callback function for `key_cert2keyinfo_button'.
 */
void
key_cert2key_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_cert2key_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_cert2key_handler\n", stderr);
}



/*
 * Notify callback function for `key_delkey_button'.
 */
void
key_delkey_handler(item, event)
	Panel_item	item;
	Event		*event;
{
	char	*proc = "key_delkey_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	if (sectool_verbose) fputs("sectxv: key_delkey_handler\n", stderr);
}



/*
 * Notify callback function for `key_list'.
 */
int
key_content_handler(item, string, client_data, op, event)
	Panel_item	item;
	char		*string;
	Xv_opaque	client_data;
	Panel_list_op	op;
	Event		*event;
{
	char	*proc = "key_content_handler";

	sectxv_key_popup_objects	*ip = (sectxv_key_popup_objects *) xv_get(item, XV_KEY_DATA, INSTANCE);
	
	switch(op) {
	case PANEL_LIST_OP_DESELECT:
		if (sectool_verbose) fprintf(stderr, "sectxv: key_content_handler: PANEL_LIST_OP_DESELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_SELECT:
		if (sectool_verbose) fprintf(stderr, "sectxv: key_content_handler: PANEL_LIST_OP_SELECT: %s\n",string);
		break;

	case PANEL_LIST_OP_VALIDATE:
		if (sectool_verbose) fprintf(stderr, "sectxv: key_content_handler: PANEL_LIST_OP_VALIDATE: %s\n",string);
		break;

	case PANEL_LIST_OP_DELETE:
		if (sectool_verbose) fprintf(stderr, "sectxv: key_content_handler: PANEL_LIST_OP_DELETE: %s\n",string);
		break;
	}
	return XV_OK;
}






/*
 * *** *** *** *** *** ***
 *	Misc. list stuff
 * *** *** *** *** *** ***
 */




/* ---------------------------------------------------------------------------------------------------------------------
 *	Fill PSE-List, PK-List, EK-List, text-items
 */

int
fill_base_panels(ip)
	sectxv_base_window_objects	*ip;
{
	char				*proc = "fill_base_panels";
	PSEToc				*main_toc;
	Name				*owner_name;
	DName				*owner_mail;
	char				*create;
	char				*update;
	struct PSE_Objects 		*obj;
	char				setting_value = 0;
	PKList				*pk_list, *ek_list;
	char				*alias;
	char				*alias_subject;
	char				*alias_issuer;



	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	/*
	 *	fill panels
	 */

	if (ca_dir) xv_set(ip->base_ca_textfield, PANEL_VALUE, ca_dir, NULL);
	if (pse_path) xv_set(ip->base_pse_textfield, PANEL_VALUE, pse_path, NULL);

/****** CHANGE FOR DIR NAME ********/
	if (TRUE) xv_set(ip->base_dir_textfield, PANEL_VALUE, "", NULL);

	/* toc-header-panels */
	pse_toc_panels_update(ip, CNULL);		

	/* PSE-List */
	if (sctoc)  {

		obj = sctoc->obj;
		while (obj) {
	
			create = aux_readable_UTCTime(obj->create);
			update = aux_readable_UTCTime(obj->update);

			pse_list_panel_update(ip, obj->name, create, update, &(obj->noOctets), sectxv_pse_list_sc_glyph);

			if (create) free(create);
			if (update) free(update);

			obj = obj->next;
		}
	} 
	if (psetoc)  {

		obj = psetoc->obj;
		while (obj) {
	
			create = aux_readable_UTCTime(obj->create);
			update = aux_readable_UTCTime(obj->update);

			pse_list_panel_update(ip, obj->name, create, update, &(obj->noOctets), sectxv_pse_list_swpse_glyph);

			if (create) free(create);
			if (update) free(update);

			obj = obj->next;
		}
	} 

	/* PKList */
	if (! (pk_list = af_pse_get_PKList(SIGNATURE)) )  {

		if (verbose) fprintf(stderr, "  Warning: Can't read PKList\n");
	
	}  else while (pk_list)  {

		if (!pk_list->element) notice_quitcont(ip->pse_list, "Empty ToBeSigned field in PKList");
		else  {

			if (! (alias_subject = search_add_alias(ip->pk_list, pk_list->element->subject, LOCALNAME)) ) break;
			if (! (alias_issuer = search_add_alias(ip->pk_list, pk_list->element->issuer, LOCALNAME)) ) break;

			pk_list_panel_append(ip, SIGNATURE,	alias_subject, alias_issuer,
								pk_list->element->subject, pk_list->element->issuer,
								&(pk_list->element->serialnumber));

			if (alias_subject) free(alias_subject);
			if (alias_issuer) free(alias_issuer);
		}
		pk_list = pk_list->next;
	}


	/* EKList */
	if (onekeypaironly)  {

		if (verbose) fprintf(stderr, "  EKList is not supported\n");

	} else  {	/* create EKList panels */

		if (!ip->base_message8)
			ip->base_message8 = sectxv_base_window_base_message8_create(ip, ip->base_controls);
		if (!ip->base_message9)
			ip->base_message9 = sectxv_base_window_base_message9_create(ip, ip->base_controls);
		if (!ip->base_message10)
			ip->base_message10 = sectxv_base_window_base_message10_create(ip, ip->base_controls);
		if (!ip->ek_list)
			ip->ek_list = sectxv_base_window_ek_list_create(ip, ip->base_controls);
		if (!ip->ek_button)
			ip->ek_button = sectxv_base_window_ek_button_create(ip, ip->base_controls);

		/* get default event handler */
		get_ek_list_event_proc(ip);
		xv_set(ip->ek_list, PANEL_EVENT_PROC, ek_event_handler, NULL);

		if (! (ek_list = af_pse_get_PKList(ENCRYPTION)) )  {

			if (verbose) fprintf(stderr, "  Warning: Can't read EKList\n");
	
		} else while (ek_list)  {

			if (! (ek_list->element) ) notice_quitcont(ip->pse_list, "Empty ToBeSigned field in EKList");

			else  {

				if (! (alias_subject = search_add_alias(ip->ek_list, ek_list->element->subject, LOCALNAME)) ) break;
				if (! (alias_issuer = search_add_alias(ip->ek_list, ek_list->element->issuer, LOCALNAME)) ) break;

				pk_list_panel_append(ip, ENCRYPTION,	alias_subject, alias_issuer,
									ek_list->element->subject, ek_list->element->issuer,
									&(ek_list->element->serialnumber));

				if (alias_subject) free(alias_subject);
				if (alias_issuer) free(alias_issuer);
			}
			ek_list = ek_list->next;
		}
		xv_set(ip->base_window, XV_HEIGHT, SECTXV_LARGE_BASE_HEIGHT, NULL);
	}


	return(0);


}




/*
 *	update object in pse-list-panel / append if object not found
 */

int
pse_list_panel_update(ip, name, created, changed, size, glyph_object)
	sectxv_base_window_objects	*ip;
	char				*name;
	char				*created;
	char				*changed;
	int				*size;
	Xv_opaque			glyph_object;
{
	char				*proc = "pse_list_panel_update";
	char				pselist_string[SECTXV_PSELISTSTR_LENGTH + 1];
	char				*pl_name;
	char				pl_size[7];			/* max. length is 7 digits! */
	char				*fill = "";
	int				total_rows;
	int				entry = 0;
	char				*list_selection_data;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	/* *** be careful when changing sprintf-formats! *** */

	if (name) pl_name = aux_cpy_String(name);
	if (size) sprintf(pl_size, "%6d", *size);					/* SECTXV_PSEOBJSIZE_LENGTH */

	sprintf(pselist_string, "%-20.20s%6s%-20.20s%4s%-20.20s%3s%-6.6s",
				name, fill, created, fill, changed, fill, pl_size);

	if (sectool_verbose) fprintf(stderr, "    %s\n", pselist_string);

	total_rows = xv_get(ip->pse_list, PANEL_LIST_NROWS);

	/* update if found */
	while (entry < total_rows)  {

		if (!strcmp(pl_name, (char *)xv_get(ip->pse_list, PANEL_LIST_CLIENT_DATA, entry)))  {

			xv_set(ip->pse_list, PANEL_LIST_STRING, entry, pselist_string, NULL);
			break;
		}
		entry++;
	}

	/* append if not found */
	if (entry >= total_rows) xv_set(ip->pse_list,	PANEL_LIST_INSERT, total_rows,
							PANEL_LIST_GLYPH, total_rows, glyph_object,
							PANEL_LIST_STRING, total_rows, pselist_string,
							PANEL_LIST_CLIENT_DATA, total_rows, pl_name,
							NULL);


	return(0);

}




/*
 *	update toc-header-fields
 *	if object name is given: 
 *		update entry in PSE-List-Panel if in toc & in list
 *		append entry in list if in toc & not in list
 *		delete entry from list if not in toc
 */

int
pse_toc_panels_update(ip, object_name)
	sectxv_base_window_objects	*ip;
	char				*object_name;
{
	char				*proc = "pse_toc_panels_update";
	PSEToc				*main_toc;
	Name				*owner_name;
	DName				*owner_dname;
	char				*name;
	char				*create;
	char				*update;
	struct PSE_Objects 		*obj;
	char				setting_value = 0;
	char				pselist_string[SECTXV_PSELISTSTR_LENGTH + 1];
	char				*fill = "";
	int				total_rows;
	int				entry = 0;
	Xv_opaque			glyph_object;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);

		
	/* read toc */
	if (sec_read_tocs(&std_pse, &sctoc, &psetoc) < 0 || (!sctoc && !psetoc))  {		

		aux_add_error(EREADPSE, "sec_read_tocs failed", CNULL, 0, proc);
		notice_abort(ip->pse_list, "Can't read Table Of Contents");
	}

	if (sctoc) main_toc = sctoc;
	else main_toc = psetoc;

	/* owner, dname, mail, created, changed textfields */
	xv_set(ip->base_owner_textfield, PANEL_VALUE, main_toc->owner, NULL);

	if (owner_name = aux_alias2Name(main_toc->owner))  {

		xv_set(ip->base_dname_textfield, PANEL_VALUE, owner_name, NULL);
		free(owner_name);
	}
	
	if (owner_dname = aux_alias2DName(main_toc->owner))  {

		if (alias = search_add_alias(ip->base_mail_textfield, owner_dname, RFCMAIL))  {

			xv_set(ip->base_mail_textfield, PANEL_VALUE, alias, NULL);
			free(alias);
		}
		aux_free_DName(&owner_dname);
	}
	
	if (create = aux_readable_UTCTime(main_toc->create))  {

		xv_set(ip->base_created_textfield, PANEL_VALUE, create + 4, NULL);
		free(create);
	}

	if (update = aux_readable_UTCTime(main_toc->update))  {

		xv_set(ip->base_changed_textfield, PANEL_VALUE, update + 4, NULL);
		free(update);
	}

	/* SC/SWPSE/ONE setting */
	if (sctoc)		setting_value |= SECTXV_BASE_SETTING_SC;
	else			setting_value |= SECTXV_BASE_SETTING_SWPSE;
	if (psetoc)		setting_value |= SECTXV_BASE_SETTING_SWPSE;
	if (onekeypaironly)	setting_value |= SECTXV_BASE_SETTING_ONEKP;
	xv_set(ip->base_setting, PANEL_VALUE, setting_value, NULL);



	/* update for given object_name */
	if (object_name)  {
	
		obj = (struct PSE_Objects *)NULL;

		/* PSE-List */
		if (sctoc)  {

			obj = sctoc->obj;
			while (obj)  {
		
				if (!strcmp(object_name, obj->name))  {			/* SC object */
				
					create = aux_readable_UTCTime(obj->create);
					update = aux_readable_UTCTime(obj->update);

					glyph_object = sectxv_pse_list_sc_glyph;
	
					break;
				}
				obj = obj->next;
			}
		} 

		if (!obj && psetoc)  {

			obj = psetoc->obj;
			while (obj)  {
		
				if (!strcmp(object_name, obj->name))  {			/* SW-PSE object */

					create = aux_readable_UTCTime(obj->create);
					update = aux_readable_UTCTime(obj->update);
		
					glyph_object = sectxv_pse_list_swpse_glyph;
	
					break;

				}
				obj = obj->next;
			}
		}

		if (obj)  {

			pse_list_panel_update(ip, obj->name, create, update, &(obj->noOctets), glyph_object);
		
			if (create) free(create);
			if (update) free(update);
	
		} else  {			/* not in toc: try to delete from list */

			total_rows = xv_get(ip->pse_list, PANEL_LIST_NROWS);
			while (entry < total_rows)  {

				if (!strcmp(object_name, (char *)xv_get(ip->pse_list, PANEL_LIST_CLIENT_DATA, entry)))  {

					xv_set(ip->pse_list,	PANEL_CLIENT_DATA, SECTXV_NO_SELECTION,
								PANEL_LIST_DELETE, entry,
								NULL);
					break;
				}
				entry++;
			}
		}
	}	


	return(0);

}




/* ---------------------------------------------------------------------------------------------------------------------
 *	append entry in PK/EK-List-Panel
 */
int
pk_list_panel_append(ip, type, subject, issuer, dn_subject, dn_issuer, serial)
	sectxv_base_window_objects	*ip;
	KeyType				type;
	char				*subject;
	char				*issuer;
	DName				*dn_subject;
	DName				*dn_issuer;
	int				*serial;
{
	char				*proc = "pk_list_panel_append";
	Xv_opaque			window_list;
	char				*window_list_name;
	PKList_client_data		*list_data;
	char				list_string[SECTXV_PKLISTSTR_LENGTH + 1];
	char				list_serial[SECTXV_PKSERIAL_LENGTH + 1];
	char				*fill = "";
	int				total_rows;


	if (sectool_verbose)  fprintf(stderr, "--> %s\n", proc);


	if (type == SIGNATURE)  {

		window_list = (Xv_opaque)ip->pk_list;
		window_list_name = PKList_name;

	} else if (type == ENCRYPTION)  {

		window_list = (Xv_opaque)ip->ek_list;
		window_list_name = EKList_name;

	} else  {

		if (sectool_verbose) fprintf(stderr, "WARNING: Unsupported list type\n");
	
		return(-1);
	}

	list_data = (PKList_client_data *)malloc(sizeof(PKList_client_data));
	list_data->subject = aux_cpy_DName(dn_subject);
	list_data->issuer = aux_cpy_DName(dn_issuer);
	list_data->serial = *serial;

	/* *** be careful when changing sprintf-formats! *** */
	if (serial) sprintf(list_serial, "%10d", *serial);				/* SECTXV_PKSERIAL_LENGTH */
	sprintf(list_string, "%-25.25s%5s%-25.25s%5s%-10.10s", subject, fill, issuer, fill, list_serial); 

	if (sectool_verbose) fprintf(stderr, "    %s: %s\n", window_list_name, list_string);
		
	total_rows = xv_get(window_list, PANEL_LIST_NROWS);
	xv_set(window_list,	PANEL_LIST_INSERT, total_rows,
				PANEL_LIST_STRING, total_rows, list_string,
				PANEL_LIST_CLIENT_DATA, total_rows, list_data,
				NULL);


	return(0);

}





/* ---------------------------------------------------------------------------------------------------------------------
 * 	delete selected entries in PSE's PK/EK-List
 */
int
pk_delete_list(ip, type)
	sectxv_base_window_objects	*ip;
	KeyType				type;
{
	char				*proc = "pk_delete_list";
	Xv_opaque			window_list;
	PKList_client_data		*list_data;
	char				*window_list_name;
	char				*subject;
	char				*issuer;
	int				entry = 0;
	


	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	if (type == SIGNATURE)  {

		window_list = (Xv_opaque)ip->pk_list;
		window_list_name = PKList_name;

	} else if (type == ENCRYPTION)  {

		window_list = (Xv_opaque)ip->ek_list;
		window_list_name = EKList_name;

	} else  {

		if (sectool_verbose) fprintf(stderr, "WARNING: Unsupported list type\n");
	
		return(-1);
	}

	SECTXV_BASE_BUSY("Accessing PSE...");

	/* scan list for selected entries, delete such entries confirmed */
	while (entry < xv_get(window_list, PANEL_LIST_NROWS))  {

		if (xv_get(window_list, PANEL_LIST_SELECTED, entry))  {

			if (sectool_verbose) fprintf(stderr, "  selected entry = %d\n", entry);

			list_data = (PKList_client_data *)xv_get(window_list, PANEL_LIST_CLIENT_DATA, entry);

			if (! (subject = aux_DName2Name(list_data->subject)) ) notice_quitcont(window_list, "No DName");
			if (! (issuer = aux_DName2Name(list_data->issuer)) ) notice_quitcont(window_list, "No DName");

			if (verbose) fprintf(stderr, "  Selected Public Key of %s/%s/%d\n", subject, issuer, list_data->serial);
				
			sprintf(notice_text, "Delete selected Public Key of\nSubject = %s\nIssuer = %s\nSerial No. = %d\n",
				subject, issuer, list_data->serial);
			if (notice_confcancel(window_list, notice_text))  {

				/* not deleted */
				if (af_pse_delete_PK(type, list_data->subject, list_data->issuer, list_data->serial) < 0)  {

					if (verbose)
						fprintf(stderr, "Can't delete Public Key of %s/%s/%d\n", subject, issuer, list_data->serial);
					sprintf(notice_text, "Can't delete Public Key of\nSubject = %s\nIssuer = %s\nSerial No. = %d\n",
						subject, issuer, list_data->serial);
					notice_quitcont(window_list, notice_text);

				/* deleted */
				} else  {
		
					if (verbose)  {
						fprintf(stderr, "Deleted Public Key of %s/%s/%d\n", subject, issuer, list_data->serial);
					
						aux_free_DName(& (list_data->subject));
						aux_free_DName(& (list_data->issuer));
					}

					xv_set(window_list,	PANEL_CLIENT_DATA, SECTXV_NO_SELECTION,
								PANEL_LIST_DELETE, entry,	
								NULL);

					entry--;
				}
			}
		}
		entry++;
	}

	pse_toc_panels_update(ip, window_list_name);

	SECTXV_BASE_IDLE("");


	return(0);


}




/* ---------------------------------------------------------------------------------------------------------------------
 * 	add pse-list-selection to PSE's PK/EK-List
 */
int
pk_add_list(ip, type)
	sectxv_base_window_objects	*ip;
	KeyType				type;
{
	char				*proc = "pk_add_list";
	Xv_opaque			window_list;
	char				*window_list_name;
	commands			command;
	char				*object_name;
	char				*alias_subject;
	char				*alias_issuer;
	Boolean				pklist_exists = FALSE;
	

	if (sectool_verbose) fprintf(stderr, "-->%s\n", proc);

	
	if (type == SIGNATURE)  {

		window_list = (Xv_opaque)ip->pk_list;
		window_list_name = PKList_name;
		command = ADDPK;

	} else if (type == ENCRYPTION)  {

		window_list = (Xv_opaque)ip->ek_list;
		window_list_name = EKList_name;
		command = ADDEK;

	} else  {

		if (verbose) fprintf(stderr, "WARNING: Unsupported list type\n");
	
		return(-1);
	}

	SECTXV_BASE_BUSY("Writing to PSE...");

	if (! (object_name = (char *)xv_get(ip->pse_list, PANEL_CLIENT_DATA)) )  {

		sprintf(notice_text,"No selection");
		SECTXV_BASE_IDLE(notice_text);

		return(0);
	}

	if(! (key = build_key_object(ip->pse_list, object_name, command, OPEN_TO_READ)))  {

		if (verbose) fprintf(stderr, "  build_key_object failed\n");
		sprintf(notice_text,"build_key_object failed for\n%s", object_name);
		notice_quitcont(ip->pse_list, notice_text);
		SECTXV_BASE_IDLE("");

		return(-1);
	}

	if(key->pse_sel)  {

		/* read, decode, add ToBeSigned */	
		ostr = &octetstring;
		if(sec_read_PSE(key->pse_sel, &object_oid, ostr) < 0)  {

			if (verbose) fprintf(stderr,"Can't read object from PSE: %s\n", object_name);

			aux_free2_ObjId(&object_oid);
			aux_free_Key(&key);

			sprintf(notice_text,"Can't read object from PSE\n%s", object_name);
			notice_quitcont(ip->pse_list, notice_text);
			SECTXV_BASE_IDLE("");

			return(-1);
		}

		aux_free2_ObjId(&object_oid);
		if(!(certificate = d_Certificate(ostr)))  {

			if (verbose) fprintf(stderr,"Can't decode Certificate: %s\n", object_name);

			aux_free_Key(&key);
			free(ostr->octets);

			sprintf(notice_text,"Can't decode Certificate\n%s", object_name);
			notice_quitcont(ip->pse_list, notice_text);
			SECTXV_BASE_IDLE("");

			return(-1);
		}

		free(ostr->octets);
		aux_free_Key(&key);

		if (! (alias_subject = search_add_alias(window_list, certificate->tbs->subject, LOCALNAME)) )  {

			aux_free_Certificate(&certificate);
			SECTXV_BASE_IDLE("");
	
			return(-1);
		}
		if (! (alias_issuer = search_add_alias(window_list, certificate->tbs->issuer, LOCALNAME)) )  {

			aux_free_Certificate(&certificate);
			if (alias_subject) free(alias_subject);
			SECTXV_BASE_IDLE("");

			return(-1);
		}

		if (af_pse_add_PK(type, certificate->tbs) < 0)  {

			if (verbose) fprintf(stderr, "Can't add cert to %s: %s\n", window_list_name, object_name);

			aux_free_Certificate(&certificate);
			if (alias_subject) free(alias_subject);
			if (alias_issuer) free(alias_issuer);
			
			sprintf(notice_text, "Can't add cert to %s\n%s", window_list_name, object_name);
			notice_quitcont(window_list, notice_text);
			SECTXV_BASE_IDLE("");

			return(-1);
		}

		/* append to list panel */
		pk_list_panel_append(ip, type,	alias_subject, alias_issuer,
						certificate->tbs->subject, certificate->tbs->issuer,
						&(certificate->tbs->serialnumber));

		if (alias_subject) free(alias_subject);
		if (alias_issuer) free(alias_issuer);

		aux_free_Certificate(&certificate);
	}

	pse_toc_panels_update(ip, window_list_name);

	SECTXV_BASE_IDLE("");


	return(0);

}




