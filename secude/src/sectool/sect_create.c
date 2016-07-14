
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

/*-----------------------sect_create.c------------------------------*/
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
/* MODULE   sect_create      VERSION   2.0                          */
/*                              DATE   02.04.1993                   */
/*                                BY   Kolletzki                    */
/*                                                                  */
/*                            REVIEW                                */
/*                              DATE                                */
/*                                BY                                */
/*------------------------------------------------------------------*/



#include "sect_inc.h"



/*
 * Create object `ca_menu' in the specified instance.
 */

Xv_opaque
sectxv_ca_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	ca_causers_handler();
	extern Menu_item	ca_calog_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "List",
			MENU_GEN_PROC, ca_causers_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Log-file",
			MENU_GEN_PROC, ca_calog_handler,
			NULL,
		MENU_DEFAULT, 1,
		NULL);
	return obj;
}

/*
 * Create object `pse_menu' in the specified instance.
 */

Xv_opaque
sectxv_pse_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	pse_key_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "PSE",
			MENU_PULLRIGHT, sectxv_pse_pse_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Objects",
			MENU_PULLRIGHT, sectxv_pse_objects_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Key Pool",
			MENU_GEN_PROC, pse_key_handler,
			NULL,
		MENU_DEFAULT, 2,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "PSE",
		NULL);
	return obj;
}

/*
 * Create object `ca_user_menu' in the specified instance.
 */

Xv_opaque
sectxv_ca_user_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	ca_tag_handler();
	extern Menu_item	ca_caserialnumbers_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Tag",
			MENU_GEN_PROC, ca_tag_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, ca_caserialnumbers_handler,
			NULL,
		MENU_DEFAULT, 2,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Users",
		NULL);
	return obj;
}

/*
 * Create object `pse_pse_menu' in the specified instance.
 */

Xv_opaque
sectxv_pse_pse_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	pse_check_handler();
	extern Menu_item	pse_chpin_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Check",
			MENU_GEN_PROC, pse_check_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Change PIN",
			MENU_GEN_PROC, pse_chpin_handler,
			NULL,
		MENU_DEFAULT, 1,
		NULL);
	return obj;
}

/*
 * Create object `pse_objects_menu' in the specified instance.
 */

Xv_opaque
sectxv_pse_objects_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	pse_show_handler();
	extern Menu_item	pse_create_handler();
	extern Menu_item	pse_read_handler();
	extern Menu_item	pse_write_handler();
	extern Menu_item	pse_rename_handler();
	extern Menu_item	pse_generate_handler();
	extern Menu_item	pse_xdump_handler();
	extern Menu_item	pse_delobject_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, pse_show_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Create",
			MENU_GEN_PROC, pse_create_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "File Out",
			MENU_GEN_PROC, pse_read_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "File In",
			MENU_GEN_PROC, pse_write_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Rename",
			MENU_GEN_PROC, pse_rename_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Generate",
			MENU_GEN_PROC, pse_generate_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "XDump",
			MENU_GEN_PROC, pse_xdump_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Delete",
			MENU_GEN_PROC, pse_delobject_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Expert",
			MENU_PULLRIGHT, sectxv_pse_expert_menu_create(ip, NULL),
			NULL,
		MENU_DEFAULT, 2,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Objects",
		NULL);
	return obj;
}

/*
 * Create object `prop_menu' in the specified instance.
 */

Xv_opaque
sectxv_prop_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	prop_toggle_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Errors",
			MENU_PULLRIGHT, sectxv_prop_debug_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Authentication method",
			MENU_PULLRIGHT, sectxv_prop_dua_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Algorithms",
			MENU_PULLRIGHT, sectxv_prop_algs_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show options",
			MENU_PULLRIGHT, sectxv_show_options_menu = (Menu)sectxv_prop_show_menu_create(ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Toggle Software/SCT",
			MENU_GEN_PROC, prop_toggle_handler,
			NULL,
		MENU_DEFAULT, 2,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Properties",
		NULL);
	return obj;
}

/*
 * Create object `prop_dua_menu' in the specified instance.
 */

Xv_opaque
sectxv_prop_dua_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	prop_dua_simple_handler();
	extern Menu_item	prop_dua_strong_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_CHOICE_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "None",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Simple",
			MENU_GEN_PROC, prop_dua_simple_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Strong",
			MENU_GEN_PROC, prop_dua_strong_handler,
			NULL,
		MENU_DEFAULT, 1,
		NULL);
	return obj;
}

/*
 * Create object `prop_algs_menu' in the specified instance.
 */

Xv_opaque
sectxv_prop_algs_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	prop_algs_algs_handler();
	extern Menu_item	prop_algs_setparm_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, prop_algs_algs_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Set",
			MENU_GEN_PROC, prop_algs_setparm_handler,
			NULL,
		MENU_DEFAULT, 1,
		NULL);
	return obj;
}

/*
 * Create object `prop_debug_menu' in the specified instance.
 */

Xv_opaque
sectxv_prop_debug_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	prop_debug_errors_handler();
	extern Menu_item	prop_debug_reset_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, prop_debug_errors_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Reset",
			MENU_GEN_PROC, prop_debug_reset_handler,
			NULL,
		MENU_DEFAULT, 1,
		NULL);
	return obj;
}

/*
 * Create object `ek_menu' in the specified instance.
 */

Xv_opaque
sectxv_ek_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	ek_show_handler();
	extern Menu_item	ek_xdump_handler();
	extern Menu_item	ek_addek_handler();
	extern Menu_item	ek_delek_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, ek_show_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "XDump",
			MENU_GEN_PROC, ek_xdump_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Add",
			MENU_GEN_PROC, ek_addek_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Delete",
			MENU_GEN_PROC, ek_delek_handler,
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "EKList",
		NULL);
	return obj;
}

/*
 * Create object `pk_menu' in the specified instance.
 */

Xv_opaque
sectxv_pk_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	pk_show_handler();
	extern Menu_item	pk_xdump_handler();
	extern Menu_item	pk_addpk_handler();
	extern Menu_item	pk_delpk_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			MENU_GEN_PROC, pk_show_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "XDump",
			MENU_GEN_PROC, pk_xdump_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Add",
			MENU_GEN_PROC, pk_addpk_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Delete",
			MENU_GEN_PROC, pk_delpk_handler,
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "PKList",
		NULL);
	return obj;
}

/*
 * Create object `ca_list_menu' in the specified instance.
 */

Xv_opaque
sectxv_ca_list_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "User",
			MENU_PULLRIGHT, sectxv_ca_user_menu_create((caddr_t *) ip, NULL),
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Revoke",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "List",
		NULL);
	return obj;
}

/*
 * Create object `key_list_menu' in the specified instance.
 */

Xv_opaque
sectxv_key_list_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Show",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "XDump",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Generate",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "String2Key",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Cert2Key",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Delete",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Keypool",
		NULL);
	return obj;
}

/*
 * Create object `utilities_menu' in the specified instance.
 */

Xv_opaque
sectxv_utilities_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "DName",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Alias",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Encode",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Decode",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Utilities",
		NULL);
	return obj;
}

/*
 * Create object `prop_show_menu' in the specified instance.
 */

Xv_opaque
sectxv_prop_show_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_TOGGLE_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_NCOLS, 3,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "ALG",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "BSTR",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "DER",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "ISSUER",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "KEYBITS",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "KEYINFO",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "SIGNAT",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "TBS",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "VAL",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Show Options",
		NULL);
	return obj;
}

/*
 * Create object `dir_user_menu' in the specified instance.
 */

Xv_opaque
sectxv_dir_user_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Tag",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Users",
		NULL);
	return obj;
}

/*
 * Create object `pse_expert_menu' in the specified instance.
 */

Xv_opaque
sectxv_pse_expert_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Split Cross Cert",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Cert to Root",
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Prototype Cert",
			NULL,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "Expert",
		NULL);
	return obj;
}

/*
 * Create object `alias_find_menu' in the specified instance.
 */

Xv_opaque
sectxv_alias_find_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	alias_find_next_handler();
	extern Menu_item	alias_find_topdown_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU_COMMAND_MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Next",
			MENU_GEN_PROC, alias_find_next_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "Top Down",
			MENU_GEN_PROC, alias_find_topdown_handler,
			NULL,
		MENU_DEFAULT, 2,
		MENU_GEN_PIN_WINDOW, (Xv_opaque) ip[0], "",
		NULL);
	return obj;
}

/*
 * Create object `alias_names_menu' in the specified instance.
 */

Xv_opaque
sectxv_alias_names_menu_create(ip, owner)
	caddr_t		*ip;
	Xv_opaque	owner;
{
	extern Menu_item	alias_names_insert_handler();
	Xv_opaque	obj;
	
	obj = xv_create(XV_NULL, MENU,
		XV_KEY_DATA, INSTANCE, ip,
		MENU_TITLE_ITEM, "  Other names  ",
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "<Insert>",
			MENU_GEN_PROC, alias_names_insert_handler,
			NULL,
		MENU_ITEM,
			XV_KEY_DATA, INSTANCE, ip,
			MENU_STRING, "",
			MENU_FEEDBACK, FALSE,
			NULL,
		MENU_DEFAULT, 2,
		NULL);
	return obj;
}


/*
 * Initialize an instance of object `base_window'.
 */

sectxv_base_window_objects *
sectxv_base_window_objects_initialize(ip, owner)
	sectxv_base_window_objects	*ip;
	Xv_opaque	owner;
{
	extern void		pse_event_handler();
	extern void		pk_event_handler();
	extern void		ek_event_handler();


	if (!ip && !(ip = (sectxv_base_window_objects *) calloc(1, sizeof (sectxv_base_window_objects))))
		return (sectxv_base_window_objects *) NULL;
	if (!ip->base_window)
		ip->base_window = sectxv_base_window_base_window_create(ip, owner);
	if (!ip->base_controls)
		ip->base_controls = sectxv_base_window_base_controls_create(ip, ip->base_window);
	if (!ip->ca_button)
		ip->ca_button = sectxv_base_window_ca_button_create(ip, ip->base_controls);
	if (!ip->pse_button)
		ip->pse_button = sectxv_base_window_pse_button_create(ip, ip->base_controls);
	if (!ip->dir_button)
		ip->dir_button = sectxv_base_window_dir_button_create(ip, ip->base_controls);
	if (!ip->alias_button)
		ip->alias_button = sectxv_base_window_alias_button_create(ip, ip->base_controls);
	if (!ip->prop_button)
		ip->prop_button = sectxv_base_window_prop_button_create(ip, ip->base_controls);
	if (!ip->utilities_button)
		ip->utilities_button = sectxv_base_window_utilities_button_create(ip, ip->base_controls);
	if (!ip->base_clipboard_textfield)
		ip->base_clipboard_textfield = sectxv_base_window_base_clipboard_textfield_create(ip, ip->base_controls);
	if (!ip->base_setting)
		ip->base_setting = sectxv_base_window_base_setting_create(ip, ip->base_controls);
	if (!ip->base_ca_textfield)
		ip->base_ca_textfield = sectxv_base_window_base_ca_textfield_create(ip, ip->base_controls);
	if (!ip->base_owner_textfield)
		ip->base_owner_textfield = sectxv_base_window_base_owner_textfield_create(ip, ip->base_controls);
	if (!ip->base_pse_textfield)
		ip->base_pse_textfield = sectxv_base_window_base_pse_textfield_create(ip, ip->base_controls);
	if (!ip->base_dname_textfield)
		ip->base_dname_textfield = sectxv_base_window_base_dname_textfield_create(ip, ip->base_controls);
	if (!ip->base_dir_textfield)
		ip->base_dir_textfield = sectxv_base_window_base_dir_textfield_create(ip, ip->base_controls);
	if (!ip->base_mail_textfield)
		ip->base_mail_textfield = sectxv_base_window_base_mail_textfield_create(ip, ip->base_controls);
	if (!ip->base_created_textfield)
		ip->base_created_textfield = sectxv_base_window_base_created_textfield_create(ip, ip->base_controls);
	if (!ip->base_changed_textfield)
		ip->base_changed_textfield = sectxv_base_window_base_changed_textfield_create(ip, ip->base_controls);
	if (!ip->base_message)
		ip->base_message = sectxv_base_window_base_message_create(ip, ip->base_controls);
	if (!ip->base_message1)
		ip->base_message1 = sectxv_base_window_base_message1_create(ip, ip->base_controls);
	if (!ip->base_message2)
		ip->base_message2 = sectxv_base_window_base_message2_create(ip, ip->base_controls);
	if (!ip->base_message3)
		ip->base_message3 = sectxv_base_window_base_message3_create(ip, ip->base_controls);
	if (!ip->pse_list)
		ip->pse_list = sectxv_base_window_pse_list_create(ip, ip->base_controls);
	if (!ip->base_message5)
		ip->base_message5 = sectxv_base_window_base_message5_create(ip, ip->base_controls);
	if (!ip->base_message6)
		ip->base_message6 = sectxv_base_window_base_message6_create(ip, ip->base_controls);
	if (!ip->base_message7)
		ip->base_message7 = sectxv_base_window_base_message7_create(ip, ip->base_controls);
	if (!ip->pk_list)
		ip->pk_list = sectxv_base_window_pk_list_create(ip, ip->base_controls);
	if (!ip->pk_button)
		ip->pk_button = sectxv_base_window_pk_button_create(ip, ip->base_controls);
	/* ek_list panels are created only for two-key-paired-pse */

	/* Drag & Drop stuff */
	ip->drop_site = xv_create(ip->base_window, DROP_SITE_ITEM,
		DROP_SITE_ID, 1234,
		DROP_SITE_REGION, xv_get(ip->pse_list, XV_RECT),
		NULL);
	ip->dnd = xv_create(ip->base_window, DRAGDROP,
		DND_TYPE, DND_COPY,
		NULL);
	ip->sel = xv_create(ip->base_window, SELECTION_REQUESTOR,
		NULL);

	/* get default event handler */
	get_pse_list_event_proc(ip);
	xv_set(ip->pse_list, PANEL_EVENT_PROC, pse_event_handler, NULL);
	get_pk_list_event_proc(ip);
	xv_set(ip->pk_list, PANEL_EVENT_PROC, pk_event_handler, NULL);
	


	return ip;
}

/*
 * Create object `base_window' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_window_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern Notify_value	base_event_handler();
	Xv_opaque	obj;
	Xv_opaque		base_window_image;
	static unsigned short	base_window_bits[] = {
#include "sectool.icon"
	};
	Xv_opaque		base_window_image_mask;
	static unsigned short	base_window_mask_bits[] = {
#include "sectool.mask.icon"
	};
	static unsigned short	pse_sc_bits[] = {
#include "sectpsesc.glyph"
	};
	static unsigned short	pse_swpse_bits[] = {
#include "sectpseswpse.glyph"
	};
	

	base_window_image = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, base_window_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	base_window_image_mask = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, base_window_mask_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	obj = xv_create(owner, FRAME,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 635,
		XV_HEIGHT, 637,
		XV_LABEL, "SecuDE  Tool   2.1",
		FRAME_CLOSED, FALSE,
		FRAME_SHOW_FOOTER, TRUE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_ICON, xv_create(XV_NULL, ICON,
			ICON_IMAGE, base_window_image,
			ICON_MASK_IMAGE, base_window_image_mask,
			ICON_TRANSPARENT, TRUE,
			XV_LABEL, pse_name,
			NULL),
		XV_FONT, (Xv_Font)load_font(),
		NULL);
 	xv_set(obj, WIN_CONSUME_EVENTS,
		NULL, NULL);
 	notify_interpose_event_func(obj,
		(Notify_func) base_event_handler, NOTIFY_SAFE);


	/*
	 * Create object `sectxv_pse_list_sc_glyph'.
	 */
	sectxv_pse_list_sc_glyph = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, pse_sc_bits,
		XV_WIDTH, 16,
		XV_HEIGHT, 16,
		NULL);

	/*
	 * Create object `sectxv_pse_list_swpse_glyph'.
	 */
	sectxv_pse_list_swpse_glyph = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, pse_swpse_bits,
		XV_WIDTH, 16,
		XV_HEIGHT, 16,
		NULL);


	return obj;
}

/*
 * Create object `base_controls' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `ca_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_ca_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 5,
		XV_WIDTH, 49,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "CA",
		PANEL_ITEM_MENU, sectxv_ca_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `pse_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_pse_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 86,
		XV_Y, 5,
		XV_WIDTH, 54,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "PSE",
		PANEL_ITEM_MENU, sectxv_pse_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `dir_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_dir_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		dir_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 160,
		XV_Y, 5,
		XV_WIDTH, 39,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "DIR",
		PANEL_NOTIFY_PROC, dir_handler,
		NULL);
	return obj;
}

/*
 * Create object `alias_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_alias_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 212,
		XV_Y, 5,
		XV_WIDTH, 47,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Alias",
		PANEL_NOTIFY_PROC, alias_handler,
		NULL);
	return obj;
}

/*
 * Create object `prop_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_prop_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 292,
		XV_Y, 5,
		XV_WIDTH, 94,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Properties",
		PANEL_ITEM_MENU, sectxv_prop_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `utilities_button' in the specified instance.
 */

Xv_opaque
sectxv_base_window_utilities_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 408,
		XV_Y, 8,
		XV_WIDTH, 84,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Utilities",
		PANEL_ITEM_MENU, sectxv_utilities_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `base_clipboard_textfield' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_clipboard_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 508,
		XV_Y, 8,
		XV_WIDTH, 80,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 508,
		PANEL_VALUE_Y, 8,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 10,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `base_setting' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_setting_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		base_setting_event_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TOGGLE, PANEL_FEEDBACK, PANEL_MARKED,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 516,
		XV_Y, 44,
		XV_WIDTH, 109,
		XV_HEIGHT, 81,
		PANEL_VALUE_X, 516,
		PANEL_VALUE_Y, 44,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_CHOICE_NROWS, 3,
		PANEL_EVENT_PROC, base_setting_event_handler,
		PANEL_CHOICE_STRINGS,
			"Smartcard",
			"Software",
			"One Keypair",
			0,
		NULL);
	return obj;
}

/*
 * Create object `base_ca_textfield' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_ca_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 73,
		XV_Y, 48,
		XV_WIDTH, 189,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "CA:",
		PANEL_VALUE_X, 102,
		PANEL_VALUE_Y, 48,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_owner_textfield' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_owner_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 278,
		XV_Y, 48,
		XV_WIDTH, 216,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Owner:",
		PANEL_VALUE_X, 334,
		PANEL_VALUE_Y, 48,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_pse_textfield' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_pse_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 67,
		XV_Y, 68,
		XV_WIDTH, 195,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "PSE:",
		PANEL_VALUE_X, 102,
		PANEL_VALUE_Y, 68,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_dname_textfield' in the specified instance.
 */

Xv_opaque
sectxv_base_window_base_dname_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 274,
		XV_Y, 68,
		XV_WIDTH, 220,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "DName:",
		PANEL_VALUE_X, 334,
		PANEL_VALUE_Y, 68,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_dir_textfield' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_dir_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 88,
		XV_WIDTH, 234,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Directory:",
		PANEL_VALUE_X, 102,
		PANEL_VALUE_Y, 88,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_mail_textfield' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_mail_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 293,
		XV_Y, 88,
		XV_WIDTH, 201,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Mail:",
		PANEL_VALUE_X, 334,
		PANEL_VALUE_Y, 88,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_created_textfield' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_created_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 271,
		XV_Y, 116,
		XV_WIDTH, 223,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Created:",
		PANEL_VALUE_X, 334,
		PANEL_VALUE_Y, 116,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_changed_textfield' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_changed_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 264,
		XV_Y, 136,
		XV_WIDTH, 230,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Changed:",
		PANEL_VALUE_X, 334,
		PANEL_VALUE_Y, 136,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 176,
		XV_WIDTH, 102,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Objects in PSE:",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message1' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message1_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 232,
		XV_Y, 176,
		XV_WIDTH, 111,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Date of Creation",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message2' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message2_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 400,
		XV_Y, 176,
		XV_WIDTH, 104,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Date of Change",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message3' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message3_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 570,
		XV_Y, 176,
		XV_WIDTH, 28,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Size",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}


/*
 * Create object `pse_list' in the specified instance.

 */
Xv_opaque
sectxv_base_window_pse_list_create(ip, owner)
	caddr_t			ip;
	Xv_opaque		owner;
{
	extern int		pse_content_handler();
	Xv_opaque		obj;


	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 12,
		XV_Y, 196,
		PANEL_LIST_WIDTH, 600,
		XV_HEIGHT, 110,
		PANEL_LAYOUT, PANEL_VERTICAL,
		PANEL_LIST_DISPLAY_ROWS, 5,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, TRUE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_ITEM_MENU, sectxv_pse_objects_menu_create((caddr_t *) ip, NULL),
		PANEL_NOTIFY_PROC, pse_content_handler,
		NULL);
	return obj;
}

/*
 * Create object `base_message5' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message5_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 110,
		XV_Y, 324,
		XV_WIDTH, 51,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Subject",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message6' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message6_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 320,
		XV_Y, 324,
		XV_WIDTH, 44,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Issuer",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message7' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message7_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 544,
		XV_Y, 324,
		XV_WIDTH, 58,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "SerialNo",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `pk_list' in the specified instance.

 */
Xv_opaque
sectxv_base_window_pk_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		pk_event_handler();
	extern int		pk_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 92,
		XV_Y, 344,
		PANEL_LIST_WIDTH, 520,
		XV_HEIGHT, 110,
		PANEL_LAYOUT, PANEL_VERTICAL,
		PANEL_LIST_DISPLAY_ROWS, 5,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, FALSE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_ITEM_MENU, sectxv_pk_menu_create((caddr_t *) ip, NULL),
		PANEL_NOTIFY_PROC, pk_content_handler,
		NULL);
	return obj;
}

/*
 * Create object `pk_button' in the specified instance.

 */
Xv_opaque
sectxv_base_window_pk_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 16,
		XV_Y, 384,
		XV_WIDTH, 71,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "PKList",
		PANEL_ITEM_MENU, sectxv_pk_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `base_message8' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message8_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 110,
		XV_Y, 476,
		XV_WIDTH, 51,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Subject",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message9' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message9_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 320,
		XV_Y, 476,
		XV_WIDTH, 44,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "Issuer",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `base_message10' in the specified instance.

 */
Xv_opaque
sectxv_base_window_base_message10_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_MESSAGE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 544,
		XV_Y, 476,
		XV_WIDTH, 58,
		XV_HEIGHT, 13,
		PANEL_LABEL_STRING, "SerialNo",
		PANEL_LABEL_BOLD, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `ek_list' in the specified instance.

 */
Xv_opaque
sectxv_base_window_ek_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		ek_event_handler();
	extern int		ek_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 92,
		XV_Y, 496,
		PANEL_LIST_WIDTH, 520,
		XV_HEIGHT, 110,
		PANEL_LAYOUT, PANEL_VERTICAL,
		PANEL_LIST_DISPLAY_ROWS, 5,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, FALSE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_ITEM_MENU, sectxv_ek_menu_create((caddr_t *) ip, NULL),
		PANEL_NOTIFY_PROC, ek_content_handler,
		NULL);
	return obj;
}

/*
 * Create object `ek_button' in the specified instance.

 */
Xv_opaque
sectxv_base_window_ek_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 16,
		XV_Y, 528,
		XV_WIDTH, 71,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "EKList",
		PANEL_ITEM_MENU, sectxv_ek_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `key_popup'.
 */
sectxv_key_popup_objects *
sectxv_key_popup_objects_initialize(ip, owner)
	sectxv_key_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_key_popup_objects *) calloc(1, sizeof (sectxv_key_popup_objects))))
		return (sectxv_key_popup_objects *) NULL;
	if (!ip->key_popup)
		ip->key_popup = sectxv_key_popup_key_popup_create(ip, owner);
	if (!ip->key_controls)
		ip->key_controls = sectxv_key_popup_key_controls_create(ip, ip->key_popup);
	if (!ip->key_show_button)
		ip->key_show_button = sectxv_key_popup_key_show_button_create(ip, ip->key_controls);
	if (!ip->key_xdump_button)
		ip->key_xdump_button = sectxv_key_popup_key_xdump_button_create(ip, ip->key_controls);
	if (!ip->key_delkey_button)
		ip->key_delkey_button = sectxv_key_popup_key_delkey_button_create(ip, ip->key_controls);
	if (!ip->key_genkey_button)
		ip->key_genkey_button = sectxv_key_popup_key_genkey_button_create(ip, ip->key_controls);
	if (!ip->key_string2key_button)
		ip->key_string2key_button = sectxv_key_popup_key_string2key_button_create(ip, ip->key_controls);
	if (!ip->key_cert2keyinfo_button)
		ip->key_cert2keyinfo_button = sectxv_key_popup_key_cert2keyinfo_button_create(ip, ip->key_controls);
	if (!ip->key_clipboard_textfield)
		ip->key_clipboard_textfield = sectxv_key_popup_key_clipboard_textfield_create(ip, ip->key_controls);
	if (!ip->key_list)
		ip->key_list = sectxv_key_popup_key_list_create(ip, ip->key_controls);
	return ip;
}

/*
 * Create object `key_popup' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void	key_done_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 456,
		XV_HEIGHT, 299,
		XV_LABEL, "SecTool: Key Pool",
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, TRUE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, key_done_handler,
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}

/*
 * Create object `key_controls' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `key_show_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_show_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_show_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 5,
		XV_WIDTH, 51,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Show",
		PANEL_NOTIFY_PROC, key_show_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_xdump_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_xdump_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_xdump_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 88,
		XV_Y, 5,
		XV_WIDTH, 63,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "XDump",
		PANEL_NOTIFY_PROC, key_xdump_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_delkey_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_delkey_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_delkey_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 208,
		XV_Y, 5,
		XV_WIDTH, 57,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Delete",
		PANEL_NOTIFY_PROC, key_delkey_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_genkey_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_genkey_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_generate_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 36,
		XV_WIDTH, 73,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Generate",
		PANEL_NOTIFY_PROC, key_generate_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_string2key_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_string2key_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_string2key_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 112,
		XV_Y, 36,
		XV_WIDTH, 84,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "String2Key",
		PANEL_NOTIFY_PROC, key_string2key_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_cert2keyinfo_button' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_cert2keyinfo_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		key_cert2key_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 208,
		XV_Y, 36,
		XV_WIDTH, 74,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Cert2Key",
		PANEL_NOTIFY_PROC, key_cert2key_handler,
		NULL);
	return obj;
}

/*
 * Create object `key_clipboard_textfield' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_clipboard_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 20,
		XV_Y, 108,
		XV_WIDTH, 400,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 20,
		PANEL_VALUE_Y, 108,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `key_list' in the specified instance.

 */
Xv_opaque
sectxv_key_popup_key_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		key_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 16,
		XV_Y, 140,
		PANEL_LIST_WIDTH, 400,
		XV_HEIGHT, 145,
		PANEL_LABEL_STRING, "    Objects in Key Pool:",
		PANEL_LAYOUT, PANEL_VERTICAL,
		PANEL_LIST_DISPLAY_ROWS, 6,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, FALSE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_ITEM_MENU, sectxv_key_list_menu_create((caddr_t *) ip, NULL),
		PANEL_NOTIFY_PROC, key_content_handler,
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `ca_popup'.
 */
sectxv_ca_popup_objects *
sectxv_ca_popup_objects_initialize(ip, owner)
	sectxv_ca_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_ca_popup_objects *) calloc(1, sizeof (sectxv_ca_popup_objects))))
		return (sectxv_ca_popup_objects *) NULL;
	if (!ip->ca_popup)
		ip->ca_popup = sectxv_ca_popup_ca_popup_create(ip, owner);
	if (!ip->ca_controls)
		ip->ca_controls = sectxv_ca_popup_ca_controls_create(ip, ip->ca_popup);
	if (!ip->ca_show_button)
		ip->ca_show_button = sectxv_ca_popup_ca_show_button_create(ip, ip->ca_controls);
	if (!ip->ca_revoke_button)
		ip->ca_revoke_button = sectxv_ca_popup_ca_revoke_button_create(ip, ip->ca_controls);
	if (!ip->ca_user_button)
		ip->ca_user_button = sectxv_ca_popup_ca_user_button_create(ip, ip->ca_controls);
	if (!ip->ca_clipboard_textfield)
		ip->ca_clipboard_textfield = sectxv_ca_popup_ca_clipboard_textfield_create(ip, ip->ca_controls);
	if (!ip->ca_list)
		ip->ca_list = sectxv_ca_popup_ca_list_create(ip, ip->ca_controls);
	return ip;
}

/*
 * Create object `ca_popup' in the specified instance.
 */
Xv_opaque
sectxv_ca_popup_ca_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void	ca_done_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 438,
		XV_HEIGHT, 271,
		XV_LABEL, "SecTool: CA",
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, TRUE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, ca_done_handler,
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}

/*
 * Create object `ca_controls' in the specified instance.
 */
Xv_opaque
sectxv_ca_popup_ca_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `ca_show_button' in the specified instance.

 */
Xv_opaque
sectxv_ca_popup_ca_show_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		ca_cacertificate_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 28,
		XV_Y, 5,
		XV_WIDTH, 51,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Show",
		PANEL_NOTIFY_PROC, ca_cacertificate_handler,
		NULL);
	return obj;
}

/*
 * Create object `ca_revoke_button' in the specified instance.

 */
Xv_opaque
sectxv_ca_popup_ca_revoke_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		ca_revoke_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 88,
		XV_Y, 5,
		XV_WIDTH, 61,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Revoke",
		PANEL_NOTIFY_PROC, ca_revoke_handler,
		NULL);
	return obj;
}

/*
 * Create object `ca_user_button' in the specified instance.

 */
Xv_opaque
sectxv_ca_popup_ca_user_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 190,
		XV_Y, 8,
		XV_WIDTH, 60,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "User",
		PANEL_ITEM_MENU, sectxv_ca_user_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `ca_clipboard_textfield' in the specified instance.

 */
Xv_opaque
sectxv_ca_popup_ca_clipboard_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 258,
		XV_Y, 8,
		XV_WIDTH, 160,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 258,
		PANEL_VALUE_Y, 8,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `ca_list' in the specified instance.

 */
Xv_opaque
sectxv_ca_popup_ca_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		ca_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 12,
		XV_Y, 44,
		PANEL_LIST_WIDTH, 400,
		XV_HEIGHT, 217,
		PANEL_LABEL_STRING, "    Serial No.         Subject",
		PANEL_LAYOUT, PANEL_VERTICAL,
		PANEL_LIST_DISPLAY_ROWS, 10,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, FALSE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_ITEM_MENU, sectxv_ca_list_menu_create((caddr_t *) ip, NULL),
		PANEL_NOTIFY_PROC, ca_content_handler,
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `chpin_popup'.
 */
sectxv_chpin_popup_objects *
sectxv_chpin_popup_objects_initialize(ip, owner)
	sectxv_chpin_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_chpin_popup_objects *) calloc(1, sizeof (sectxv_chpin_popup_objects))))
		return (sectxv_chpin_popup_objects *) NULL;
	if (!ip->chpin_popup)
		ip->chpin_popup = sectxv_chpin_popup_chpin_popup_create(ip, owner);
	if (!ip->chpin_controls)
		ip->chpin_controls = sectxv_chpin_popup_chpin_controls_create(ip, ip->chpin_popup);
	if (!ip->chpin_old_textfield)
		ip->chpin_old_textfield = sectxv_chpin_popup_chpin_old_textfield_create(ip, ip->chpin_controls);
	if (!ip->chpin_new_textfield)
		ip->chpin_new_textfield = sectxv_chpin_popup_chpin_new_textfield_create(ip, ip->chpin_controls);
	if (!ip->chpin_re_textfield)
		ip->chpin_re_textfield = sectxv_chpin_popup_chpin_re_textfield_create(ip, ip->chpin_controls);
	if (!ip->chpin_apply_button)
		ip->chpin_apply_button = sectxv_chpin_popup_chpin_apply_button_create(ip, ip->chpin_controls);
	if (!ip->chpin_cancel_button)
		ip->chpin_cancel_button = sectxv_chpin_popup_chpin_cancel_button_create(ip, ip->chpin_controls);
	return ip;
}

/*
 * Create object `chpin_popup' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void	chpin_done_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 233,
		XV_HEIGHT, 169,
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, FALSE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, chpin_done_handler,
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}

/*
 * Create object `chpin_controls' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `chpin_old_textfield' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_old_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 58,
		XV_Y, 20,
		XV_WIDTH, 126,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Old PIN:",
		PANEL_VALUE_X, 120,
		PANEL_VALUE_Y, 20,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 8,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `chpin_new_textfield' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_new_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 53,
		XV_Y, 50,
		XV_WIDTH, 131,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "New PIN:",
		PANEL_VALUE_X, 120,
		PANEL_VALUE_Y, 50,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 8,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `chpin_re_textfield' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_re_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 33,
		XV_Y, 80,
		XV_WIDTH, 151,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "#2 New PIN:",
		PANEL_VALUE_X, 120,
		PANEL_VALUE_Y, 80,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 8,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `chpin_apply_button' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_apply_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		chpin_apply_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 32,
		XV_Y, 128,
		XV_WIDTH, 89,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Change PIN",
		PANEL_NOTIFY_PROC, chpin_apply_handler,
		NULL);

	xv_set(owner, PANEL_DEFAULT_ITEM, obj, NULL);

	return obj;
}

/*
 * Create object `chpin_cancel_button' in the specified instance.

 */
Xv_opaque
sectxv_chpin_popup_chpin_cancel_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		chpin_cancel_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 140,
		XV_Y, 128,
		XV_WIDTH, 59,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Cancel",
		PANEL_NOTIFY_PROC, chpin_cancel_handler,
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `pin_popup'.
 */
sectxv_pin_popup_objects *
sectxv_pin_popup_objects_initialize(ip, owner)
	sectxv_pin_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_pin_popup_objects *) calloc(1, sizeof (sectxv_pin_popup_objects))))
		return (sectxv_pin_popup_objects *) NULL;
	if (!ip->pin_popup)
		ip->pin_popup = sectxv_pin_popup_pin_popup_create(ip, owner);
	if (!ip->pin_controls)
		ip->pin_controls = sectxv_pin_popup_pin_controls_create(ip, ip->pin_popup);
	if (!ip->pin_textfield)
		ip->pin_textfield = sectxv_pin_popup_pin_textfield_create(ip, ip->pin_controls);
	if (!ip->pin_button)
		ip->pin_button = sectxv_pin_popup_pin_button_create(ip, ip->pin_controls);
	return ip;
}

/*
 * Create object `pin_popup' in the specified instance.

 */
Xv_opaque
sectxv_pin_popup_pin_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void	pin_done_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 200,
		XV_HEIGHT, 100,
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, FALSE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, pin_done_handler,
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}

/*
 * Create object `pin_controls' in the specified instance.

 */
Xv_opaque
sectxv_pin_popup_pin_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `pin_textfield' in the specified instance.

 */
Xv_opaque
sectxv_pin_popup_pin_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 70,
		XV_Y, 25,
		XV_WIDTH, 64,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 70,
		PANEL_VALUE_Y, 25,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 8,
		PANEL_VALUE_STORED_LENGTH, 80,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `pin_button' in the specified instance.

 */
Xv_opaque
sectxv_pin_popup_pin_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		pin_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 65,
		XV_Y, 56,
		XV_WIDTH, 75,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Enter PIN",
		PANEL_NOTIFY_PROC, pin_handler,
		NULL);

	xv_set(owner, PANEL_DEFAULT_ITEM, obj, NULL);

	return obj;
}

/*
 * Initialize an instance of object `create_popup'.
 */
sectxv_create_popup_objects *
sectxv_create_popup_objects_initialize(ip, owner)
	sectxv_create_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_create_popup_objects *) calloc(1, sizeof (sectxv_create_popup_objects))))
		return (sectxv_create_popup_objects *) NULL;
	if (!ip->create_popup)
		ip->create_popup = sectxv_create_popup_create_popup_create(ip, owner);
	if (!ip->create_controls)
		ip->create_controls = sectxv_create_popup_create_controls_create(ip, ip->create_popup);
	if (!ip->create_textfield)
		ip->create_textfield = sectxv_create_popup_create_textfield_create(ip, ip->create_controls);
	if (!ip->create_apply_button)
		ip->create_apply_button = sectxv_create_popup_create_apply_button_create(ip, ip->create_controls);
	if (!ip->create_cancel_button)
		ip->create_cancel_button = sectxv_create_popup_create_cancel_button_create(ip, ip->create_controls);
	return ip;
}

/*
 * Create object `create_popup' in the specified instance.

 */
Xv_opaque
sectxv_create_popup_create_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern Notify_value	create_event_handler();
	extern void	create_done_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 248,
		XV_HEIGHT, 97,
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, FALSE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, create_done_handler,
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
/*
	notify_interpose_event_func(obj,
		(Notify_func) create_event_handler, NOTIFY_SAFE);
*/
	return obj;
}

/*
 * Create object `create_controls' in the specified instance.

 */
Xv_opaque
sectxv_create_popup_create_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `create_textfield' in the specified instance.

 */
Xv_opaque
sectxv_create_popup_create_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 20,
		XV_Y, 24,
		XV_WIDTH, 210,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Name:",
		PANEL_VALUE_X, 70,
		PANEL_VALUE_Y, 24,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 20,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `create_apply_button' in the specified instance.

 */
Xv_opaque
sectxv_create_popup_create_apply_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		create_apply_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 50,
		XV_Y, 64,
		XV_WIDTH, 58,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Create",
		PANEL_NOTIFY_PROC, create_apply_handler,
		NULL);

	xv_set(owner, PANEL_DEFAULT_ITEM, obj, NULL);

	return obj;
}

/*
 * Create object `create_cancel_button' in the specified instance.

 */
Xv_opaque
sectxv_create_popup_create_cancel_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		create_cancel_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 140,
		XV_Y, 64,
		XV_WIDTH, 59,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Cancel",
		PANEL_NOTIFY_PROC, create_cancel_handler,
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `dir_window'.
 */
sectxv_dir_window_objects *
sectxv_dir_window_objects_initialize(ip, owner)
	sectxv_dir_window_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_dir_window_objects *) calloc(1, sizeof (sectxv_dir_window_objects))))
		return (sectxv_dir_window_objects *) NULL;
	if (!ip->dir_window)
		ip->dir_window = sectxv_dir_window_dir_window_create(ip, owner);
	if (!ip->dir_controls)
		ip->dir_controls = sectxv_dir_window_dir_controls_create(ip, ip->dir_window);
	if (!ip->dir_enter_button)
		ip->dir_enter_button = sectxv_dir_window_dir_enter_button_create(ip, ip->dir_controls);
	if (!ip->dir_retrieve_button)
		ip->dir_retrieve_button = sectxv_dir_window_dir_retrieve_button_create(ip, ip->dir_controls);
	if (!ip->dir_delete_button)
		ip->dir_delete_button = sectxv_dir_window_dir_delete_button_create(ip, ip->dir_controls);
	if (!ip->dir_user_button)
		ip->dir_user_button = sectxv_dir_window_dir_user_button_create(ip, ip->dir_controls);
	if (!ip->dir_clipboard_textfield)
		ip->dir_clipboard_textfield = sectxv_dir_window_dir_clipboard_textfield_create(ip, ip->dir_controls);
	if (!ip->dir_textfield)
		ip->dir_textfield = sectxv_dir_window_dir_textfield_create(ip, ip->dir_controls);
	if (!ip->dir_list)
		ip->dir_list = sectxv_dir_window_dir_list_create(ip, ip->dir_controls);
	return ip;
}

/*
 * Create object `dir_window' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_window_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern Notify_value	dir_event_handler();
	Xv_opaque	obj;
	Xv_opaque		dir_window_image;
	static unsigned short	dir_window_bits[] = {
#include "sectdir.icon"
	};
	Xv_opaque		dir_window_image_mask;
	static unsigned short	dir_window_mask_bits[] = {
#include "sectdir.mask.icon"
	};
	
	dir_window_image = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, dir_window_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	dir_window_image_mask = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, dir_window_mask_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	obj = xv_create(owner, FRAME,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 551,
		XV_HEIGHT, 257,
		XV_LABEL, "SecuDE  Tool   2.1        Directory Services",
		FRAME_CLOSED, FALSE,
		FRAME_SHOW_FOOTER, TRUE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_ICON, xv_create(XV_NULL, ICON,
			ICON_IMAGE, dir_window_image,
			ICON_MASK_IMAGE, dir_window_image_mask,
			ICON_TRANSPARENT, TRUE,
			NULL),
		XV_FONT, (Xv_Font)load_font(),
		NULL);
 	xv_set(obj, WIN_CONSUME_EVENTS,
		NULL, NULL);
 	notify_interpose_event_func(obj,
		(Notify_func) dir_event_handler, NOTIFY_SAFE);
	return obj;
}

/*
 * Create object `dir_controls' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `dir_enter_button' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_enter_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		dir_enter_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 36,
		XV_Y, 8,
		XV_WIDTH, 50,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Enter",
		PANEL_NOTIFY_PROC, dir_enter_handler,
		NULL);
	return obj;
}

/*
 * Create object `dir_retrieve_button' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_retrieve_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		dir_retrieve_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 100,
		XV_Y, 8,
		XV_WIDTH, 68,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Retrieve",
		PANEL_NOTIFY_PROC, dir_retrieve_handler,
		NULL);
	return obj;
}

/*
 * Create object `dir_delete_button' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_delete_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		dir_delete_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 200,
		XV_Y, 8,
		XV_WIDTH, 57,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Delete",
		PANEL_NOTIFY_PROC, dir_delete_handler,
		NULL);
	return obj;
}

/*
 * Create object `dir_user_button' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_user_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 320,
		XV_Y, 10,
		XV_WIDTH, 60,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "User",
		PANEL_ITEM_MENU, sectxv_dir_user_menu_create((caddr_t *) ip, NULL),
		NULL);
	return obj;
}

/*
 * Create object `dir_clipboard_textfield' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_clipboard_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 396,
		XV_Y, 10,
		XV_WIDTH, 112,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 396,
		PANEL_VALUE_Y, 10,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 14,
		PANEL_VALUE_STORED_LENGTH, 200,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `dir_textfield' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 40,
		XV_Y, 52,
		XV_WIDTH, 474,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Directory:",
		PANEL_VALUE_X, 114,
		PANEL_VALUE_Y, 52,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 120,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `dir_list' in the specified instance.

 */
Xv_opaque
sectxv_dir_window_dir_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		dir_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 16,
		XV_Y, 80,
		PANEL_LIST_WIDTH, 500,
		XV_HEIGHT, 164,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_LIST_DISPLAY_ROWS, 8,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, FALSE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_NOTIFY_PROC, dir_content_handler,
		NULL);
	return obj;
}

/*
 * Initialize an instance of object `alias_window'.
 */
sectxv_alias_window_objects *
sectxv_alias_window_objects_initialize(ip, owner)
	sectxv_alias_window_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_alias_window_objects *) calloc(1, sizeof (sectxv_alias_window_objects))))
		return (sectxv_alias_window_objects *) NULL;
	if (!ip->alias_window)
		ip->alias_window = sectxv_alias_window_alias_window_create(ip, owner);
	if (!ip->alias_controls)
		ip->alias_controls = sectxv_alias_window_alias_controls_create(ip, ip->alias_window);
	if (!ip->alias_type_setting)
		ip->alias_type_setting = sectxv_alias_window_alias_type_setting_create(ip, ip->alias_controls);
	if (!ip->alias_file_setting)
		ip->alias_file_setting = sectxv_alias_window_alias_file_setting_create(ip, ip->alias_controls);
	if (!ip->alias_find_button)
		ip->alias_find_button = sectxv_alias_window_alias_find_button_create(ip, ip->alias_controls);
	if (!ip->alias_clipboard_textfield)
		ip->alias_clipboard_textfield = sectxv_alias_window_alias_clipboard_textfield_create(ip, ip->alias_controls);
	if (!ip->alias_list)
		ip->alias_list = sectxv_alias_window_alias_list_create(ip, ip->alias_controls);
	if (!ip->alias_dname_textfield)
		ip->alias_dname_textfield = sectxv_alias_window_alias_dname_textfield_create(ip, ip->alias_controls);
	if (!ip->alias_localname_textfield)
		ip->alias_localname_textfield = sectxv_alias_window_alias_localname_textfield_create(ip, ip->alias_controls);
	if (!ip->alias_rfcmail_textfield)
		ip->alias_rfcmail_textfield = sectxv_alias_window_alias_rfcmail_textfield_create(ip, ip->alias_controls);
	if (!ip->alias_x400mail_textfield)
		ip->alias_x400mail_textfield = sectxv_alias_window_alias_x400mail_textfield_create(ip, ip->alias_controls);
 	if (!ip->alias_names_button)
 		ip->alias_names_button = sectxv_alias_window_alias_names_button_create(ip, ip->alias_controls);
 	if (!ip->alias_names_textfield)
 		ip->alias_names_textfield = sectxv_alias_window_alias_names_textfield_create(ip, ip->alias_controls);
	if (!ip->alias_apply_button)
		ip->alias_apply_button = sectxv_alias_window_alias_apply_button_create(ip, ip->alias_controls);
	if (!ip->alias_reset_button)
		ip->alias_reset_button = sectxv_alias_window_alias_reset_button_create(ip, ip->alias_controls);
	if (!ip->alias_new_button)
		ip->alias_new_button = sectxv_alias_window_alias_new_button_create(ip, ip->alias_controls);
	if (!ip->alias_add_button)
		ip->alias_add_button = sectxv_alias_window_alias_add_button_create(ip, ip->alias_controls);
	if (!ip->alias_change_button)
		ip->alias_change_button = sectxv_alias_window_alias_change_button_create(ip, ip->alias_controls);
	if (!ip->alias_delete_button)
		ip->alias_delete_button = sectxv_alias_window_alias_delete_button_create(ip, ip->alias_controls);
	return ip;
}

/*
 * Create object `alias_window' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_window_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern Notify_value	alias_event_handler();
	Xv_opaque	obj;
	Xv_opaque		alias_window_image;
	static unsigned short	alias_window_bits[] = {
#include "sectalias.icon"
	};
	Xv_opaque		alias_window_image_mask;
	static unsigned short	alias_window_mask_bits[] = {
#include "sectalias.mask.icon"
	};
	static unsigned short	alias_user_bits[] = {
#include "sectaliasuser.glyph"
	};
	static unsigned short	alias_system_bits[] = {
#include "sectaliassystem.glyph"
	};
	static unsigned short	alias_both_bits[] = {
#include "sectaliasboth.glyph"
	};
	
	
	
	alias_window_image = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, alias_window_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	alias_window_image_mask = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, alias_window_mask_bits,
		SERVER_IMAGE_DEPTH, 1,
		XV_WIDTH, 64,
		XV_HEIGHT, 64,
		NULL);
	obj = xv_create(owner, FRAME,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 550,
		XV_HEIGHT, 417,
		XV_LABEL, "SecuDE  Tool   2.1        Alias Services",
		FRAME_CLOSED, FALSE,
		FRAME_SHOW_FOOTER, TRUE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_ICON, xv_create(XV_NULL, ICON,
			ICON_IMAGE, alias_window_image,
			ICON_MASK_IMAGE, alias_window_image_mask,
			ICON_TRANSPARENT, TRUE,
			NULL),
		XV_FONT, (Xv_Font)load_font(),
		NULL);
 	xv_set(obj, WIN_CONSUME_EVENTS,
		NULL, NULL);
 	notify_interpose_event_func(obj,
		(Notify_func) alias_event_handler, NOTIFY_SAFE);


	/*
	 * Create object `sectxv_alias_list_user_glyph'.
	 */
	sectxv_alias_list_user_glyph = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, alias_user_bits,
		XV_WIDTH, 16,
		XV_HEIGHT, 16,
		NULL);

	/*
	 * Create object `sectxv_alias_list_system_glyph'.
	 */
	sectxv_alias_list_system_glyph = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, alias_system_bits,
		XV_WIDTH, 16,
		XV_HEIGHT, 16,
		NULL);

	/*
	 * Create object `sectxv_alias_list_both_glyph'.
	 */
	sectxv_alias_list_both_glyph = xv_create(XV_NULL, SERVER_IMAGE,
		SERVER_IMAGE_BITS, alias_both_bits,
		XV_WIDTH, 16,
		XV_HEIGHT, 16,
		NULL);

	return obj;
}





/*
 * Create object `alias_controls' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_controls",
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `alias_type_setting' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_type_setting_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		alias_type_setting_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_CHOICE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_type_setting",
		XV_X, 198,
		XV_Y, 8,
		XV_WIDTH, 294,
		XV_HEIGHT, 46,
		PANEL_VALUE_X, 198,
		PANEL_VALUE_Y, 8,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_CHOICE_NROWS, 2,
		PANEL_NOTIFY_PROC, alias_type_setting_handler,
		PANEL_CHOICE_STRINGS,
			"     Local Name",
			"Internet Mail Address",
			"      Next Best",
			" X.400 Mail Address",
			0,
		NULL);
	return obj;
}

/*
 * Create object `alias_file_setting' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_file_setting_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		alias_file_setting_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TOGGLE,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_file_setting",
		XV_X, 48,
		XV_Y, 20,
		XV_WIDTH, 114,
		XV_HEIGHT, 23,
		PANEL_VALUE_X, 48,
		PANEL_VALUE_Y, 20,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_CHOICE_NROWS, 1,
		PANEL_NOTIFY_PROC, alias_file_setting_handler,
		PANEL_CHOICE_STRINGS,
			"User",
			"System",
			0,
		PANEL_VALUE, SECTXV_ALIAS_USER,
		NULL);
	return obj;
}

/*
 * Create object `alias_find_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_find_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
 	obj = xv_create(owner, PANEL_BUTTON,
  		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_find_button",
 		XV_X, 50,
 		XV_Y, 70,
 		XV_WIDTH, 59,
 		XV_HEIGHT, 19,
  		PANEL_LABEL_STRING, "Find",
  		PANEL_ITEM_MENU, sectxv_alias_find_menu_create((caddr_t *) ip, NULL),
  		NULL);
	return obj;
}

/*
 * Create object `alias_clipboard_textfield' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_clipboard_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 116,
		XV_Y, 72,
		XV_WIDTH, 400,
		XV_HEIGHT, 15,
		PANEL_VALUE_X, 116,
		PANEL_VALUE_Y, 72,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}


/*
 * Create object `alias_list' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_list_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern int		alias_content_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_LIST,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_list",
		XV_X, 16,
		XV_Y, 96,
		PANEL_LIST_WIDTH, 500,
		XV_HEIGHT, 164,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_LIST_DISPLAY_ROWS, 8,
		PANEL_READ_ONLY, TRUE,
		PANEL_CHOOSE_ONE, TRUE,
		PANEL_CHOOSE_NONE, TRUE,
		PANEL_NOTIFY_PROC, alias_content_handler,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}

/*
 * Create object `alias_dname_textfield' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_dname_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 58,
		XV_Y, 266,
		XV_WIDTH, 460,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "DName:",
		PANEL_VALUE_X, 118,
		PANEL_VALUE_Y, 266,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}

/*
 * Create object `alias_localname_textfield' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_localname_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 29,
		XV_Y, 286,
		XV_WIDTH, 489,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Local name:",
		PANEL_VALUE_X, 118,
		PANEL_VALUE_Y, 286,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}

/*
 * Create object `alias_rfcmail_textfield' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_rfcmail_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 18,
		XV_Y, 310,
		XV_WIDTH, 500,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Internet Mail:",
		PANEL_VALUE_X, 118,
		PANEL_VALUE_Y, 310,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}

/*
 * Create object `alias_x400mail_textfield' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_x400mail_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 37,
		XV_Y, 330,
		XV_WIDTH, 481,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "X.400 Mail:",
		PANEL_VALUE_X, 118,
		PANEL_VALUE_Y, 330,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 50,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}

/*
 * Create object `alias_names_textfield' in the specified instance.
 
 */
Xv_opaque
sectxv_alias_window_alias_names_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
 	Xv_opaque	obj;
 	
  	obj = xv_create(owner, PANEL_TEXT,
  		XV_KEY_DATA, INSTANCE, ip,
 		XV_X, 118,
 		XV_Y, 356,
 		XV_WIDTH, 400,
  		XV_HEIGHT, 15,
  		PANEL_VALUE_X, 118,
 		PANEL_VALUE_Y, 356,
  		PANEL_LAYOUT, PANEL_HORIZONTAL,
  		PANEL_VALUE_DISPLAY_LENGTH, 50,
  		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		PANEL_PAINT, PANEL_CLEAR,
		NULL);
	return obj;
}


/*
 * Create object `alias_names_button' in the specified instance.
  
 */
Xv_opaque
sectxv_alias_window_alias_names_button_create(ip, owner)
  	caddr_t		ip;
  	Xv_opaque	owner;
{
  	Xv_opaque	obj;
  	
 	obj = xv_create(owner, PANEL_ABBREV_MENU_BUTTON,
 		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_names_button",
 		XV_X, 16,
 		XV_Y, 356,
 		XV_WIDTH, 94,
 		XV_HEIGHT, 15,
 		PANEL_LABEL_STRING, "Name list",
		PANEL_ITEM_MENU, sectxv_alias_names_menu_create((caddr_t *) ip, NULL),
		PANEL_INACTIVE, TRUE,
 		NULL);
 	return obj;
}
 

/*
 * Create object `alias_apply_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_apply_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_apply_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_apply_button",
		XV_X, 64,
		XV_Y, 392,
		XV_WIDTH, 53,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Apply",
		PANEL_NOTIFY_PROC, alias_apply_handler,
		NULL);

	xv_set(owner, PANEL_DEFAULT_ITEM, obj, NULL);

	return obj;
}

/*
 * Create object `alias_reset_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_reset_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_reset_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_reset_button",
		XV_X, 132,
		XV_Y, 392,
		XV_WIDTH, 51,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Reset",
		PANEL_NOTIFY_PROC, alias_reset_handler,
		NULL);
	return obj;
}

/*
 * Create object `alias_new_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_new_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_new_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 224,
		XV_Y, 392,
		XV_WIDTH, 45,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "New",
		PANEL_NOTIFY_PROC, alias_new_handler,
		NULL);
	return obj;
}

/*
 * Create object `alias_add_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_add_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_add_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_add_button",
		XV_X, 288,
		XV_Y, 392,
		XV_WIDTH, 42,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Add",
		PANEL_NOTIFY_PROC, alias_add_handler,
		NULL);
	return obj;
}

/*
 * Create object `alias_change_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_change_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_change_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_change_button",
		XV_X, 348,
		XV_Y, 392,
		XV_WIDTH, 64,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Change",
		PANEL_NOTIFY_PROC, alias_change_handler,
		PANEL_INACTIVE, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `alias_delete_button' in the specified instance.

 */
Xv_opaque
sectxv_alias_window_alias_delete_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		alias_delete_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_HELP_DATA, "sectool:alias_delete_button",
		XV_X, 428,
		XV_Y, 392,
		XV_WIDTH, 57,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Delete",
		PANEL_NOTIFY_PROC, alias_delete_handler,
		PANEL_INACTIVE, TRUE,
		NULL);
	return obj;
}




/*
 * Initialize an instance of object `addalias_popup'.
 */
sectxv_addalias_popup_objects *
sectxv_addalias_popup_objects_initialize(ip, owner)
	sectxv_addalias_popup_objects	*ip;
	Xv_opaque	owner;
{
	if (!ip && !(ip = (sectxv_addalias_popup_objects *) calloc(1, sizeof (sectxv_addalias_popup_objects))))
		return (sectxv_addalias_popup_objects *) NULL;
	if (!ip->addalias_popup)
		ip->addalias_popup = sectxv_addalias_popup_addalias_popup_create(ip, owner);
	if (!ip->addalias_controls)
		ip->addalias_controls = sectxv_addalias_popup_addalias_controls_create(ip, ip->addalias_popup);
	if (!ip->addalias_name_textfield)
		ip->addalias_name_textfield = sectxv_addalias_popup_addalias_name_textfield_create(ip, ip->addalias_controls);
	if (!ip->addalias_alias_textfield)
		ip->addalias_alias_textfield = sectxv_addalias_popup_addalias_alias_textfield_create(ip, ip->addalias_controls);
	if (!ip->addalias_apply_button)
		ip->addalias_apply_button = sectxv_addalias_popup_addalias_apply_button_create(ip, ip->addalias_controls);
	if (!ip->addalias_cancel_button)
		ip->addalias_cancel_button = sectxv_addalias_popup_addalias_cancel_button_create(ip, ip->addalias_controls);
	return ip;
}

/*
 * Create object `addalias_popup' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_popup_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		addalias_done_handler();
	extern Notify_value	addalias_event_handler();
	Xv_opaque		obj;
	
	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 563,
		XV_HEIGHT, 128,
		XV_SHOW, FALSE,
		FRAME_SHOW_FOOTER, FALSE,
		FRAME_SHOW_RESIZE_CORNER, FALSE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		FRAME_DONE_PROC, addalias_done_handler,
		NULL);
 	xv_set(obj, WIN_CONSUME_EVENTS,
		NULL, NULL);
 	notify_interpose_event_func(obj,
		(Notify_func) addalias_event_handler, NOTIFY_SAFE);
 	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}

/*
 * Create object `addalias_controls' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_controls_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		WIN_BORDER, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `addalias_name_textfield' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_name_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 20,
		XV_Y, 24,
		XV_WIDTH, 530,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Name:",
		PANEL_VALUE_X, 70,
		PANEL_VALUE_Y, 24,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 60,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, TRUE,
		NULL);
	return obj;
}

/*
 * Create object `addalias_alias_textfield' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_alias_textfield_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_TEXT,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 24,
		XV_Y, 52,
		XV_WIDTH, 206,
		XV_HEIGHT, 15,
		PANEL_LABEL_STRING, "Alias:",
		PANEL_VALUE_X, 70,
		PANEL_VALUE_Y, 52,
		PANEL_LAYOUT, PANEL_HORIZONTAL,
		PANEL_VALUE_DISPLAY_LENGTH, 20,
		PANEL_VALUE_STORED_LENGTH, 256,
		PANEL_READ_ONLY, FALSE,
		NULL);
	return obj;
}

/*
 * Create object `addalias_apply_button' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_apply_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		addalias_apply_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 204,
		XV_Y, 96,
		XV_WIDTH, 53,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Apply",
		PANEL_NOTIFY_PROC, addalias_apply_handler,
		NULL);

	xv_set(owner, PANEL_DEFAULT_ITEM, obj, NULL);

	return obj;
}

/*
 * Create object `addalias_cancel_button' in the specified instance.

 */
Xv_opaque
sectxv_addalias_popup_addalias_cancel_button_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	extern void		addalias_cancel_handler();
	Xv_opaque	obj;
	
	obj = xv_create(owner, PANEL_BUTTON,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 294,
		XV_Y, 96,
		XV_WIDTH, 59,
		XV_HEIGHT, 19,
		PANEL_LABEL_STRING, "Cancel",
		PANEL_NOTIFY_PROC, addalias_cancel_handler,
		NULL);
	return obj;
}



/*
 * Initialize an instance of object `text_window'.
 */
sectxv_text_window_objects *
sectxv_text_window_objects_initialize(ip, owner, label)
	sectxv_text_window_objects	*ip;
	Xv_opaque			owner;
	char				*label;
{


	if (!ip && !(ip = (sectxv_text_window_objects *) calloc(1, sizeof (sectxv_text_window_objects))))
		return (sectxv_text_window_objects *) NULL;
	if (!ip->text_window)
		ip->text_window = sectxv_text_window_text_window_create(ip, owner, label);
	if (!ip->textpane)
		ip->textpane = sectxv_text_window_textpane_create(ip, ip->text_window);
	return ip;
}


/*
 * Create object `text_window' in the specified instance.
 */
Xv_opaque
sectxv_text_window_text_window_create(ip, owner, label)
	caddr_t		ip;
	Xv_opaque	owner;
	char		*label;
{
	Xv_opaque	obj;
	char		full_label[50];


	strcpy(full_label, "SecuDE  Tool  2.1 :   ");
	strcat(full_label, label);

	obj = xv_create(owner, FRAME_CMD,
		XV_KEY_DATA, INSTANCE, ip,
		XV_WIDTH, 700,
		XV_HEIGHT, 400,
		XV_LABEL, full_label,
		FRAME_CLOSED, TRUE,
		FRAME_SHOW_FOOTER, FALSE,
		FRAME_SHOW_RESIZE_CORNER, TRUE,
		FRAME_CMD_PUSHPIN_IN, TRUE,
		XV_FONT, (Xv_Font)load_font(),
		NULL);
	xv_set(xv_get(obj, FRAME_CMD_PANEL), WIN_SHOW, FALSE, NULL);
	return obj;
}



/*
 * Create object `textpane' in the specified instance.
 */
Xv_opaque
sectxv_text_window_textpane_create(ip, owner)
	caddr_t		ip;
	Xv_opaque	owner;
{
	Xv_opaque	obj;
	
	obj = xv_create(owner, TEXTSW,
		XV_KEY_DATA, INSTANCE, ip,
		XV_X, 0,
		XV_Y, 0,
		XV_WIDTH, WIN_EXTEND_TO_EDGE,
		XV_HEIGHT, WIN_EXTEND_TO_EDGE,
		OPENWIN_SHOW_BORDERS, TRUE,
		TEXTSW_BROWSING, FALSE,
		TEXTSW_READ_ONLY, TRUE,
		TEXTSW_DISABLE_LOAD, TRUE,
		NULL);
	return obj;
}





/* ---------------------------------------------------------------------------------------------------------------------
 * 	Load font: Lucida Sans Fixedwidth for lists and textpanes (if not found, load Courier or take default font)
 */
Xv_Font
load_font()
{
	char		*proc = "load_font";
	Xv_Font		font;

	
	font = (Xv_Font)xv_find(XV_NULL, FONT, FONT_FAMILY, FONT_FAMILY_LUCIDA_FIXEDWIDTH, FONT_SCALE, WIN_SCALE_MEDIUM, NULL);
	if (!font)  {
		fprintf(stderr, "SecTool.load_font: cannot use default fixedwidth font.\n");
		font = (Xv_Font)xv_find(XV_NULL, FONT, FONT_NAME, "courier", NULL);
		if (!font)  {
			fprintf(stderr, "SecTool.load_font: cannot use font 'courier'.\n");
			font = (Xv_Font)xv_get(XV_NULL, XV_FONT);
		}
	}
	if (sectool_verbose) fprintf(stderr, "  SecTool.load_font: selected font is: %d %s\n", font, (char *)xv_get(font, FONT_NAME));


	return(font);

}



