/*--- adduser.c -- Routines to process user email addresses.
 */
#include <stdio.h>
#include <ctype.h>
#if !defined(__MACH__) && !defined(MACTC) && !defined(I386BSD) \
  && !defined(apollo) && !defined(__TURBOC__) && !defined(mips)
#include <malloc.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "list.h"
#include "listprot.h"
#include "strutilp.h"
#include "adduserp.h"

/*--- function AddUniqueUserToList --------------------------------------------
 *
 *  Add a TypUser structure to a list, first checking to ensure that
 *  the user isn't already on the list.
 *
 *  Entry:	user 		points to a TypUser structure.
 *
 *	 Exit:	list     may have been updated to include this entry.
 *				Returns NULL if successful, else a pointer to an error message.
 */
char *
AddUniqueUserToList(user,list)
TypUser *user;
TypList *list;
{
	extern int NRecip;
	TypListEntry *entry_ptr = list->firstptr;
	TypUser *user_ptr;
	BOOL found=FALSE;
	
	for(; !found && entry_ptr; entry_ptr = entry_ptr->nextptr) {
		user_ptr = (TypUser *)(entry_ptr->dataptr);
		
		if(match(user_ptr->emailaddr,user->emailaddr)) {
			found = TRUE;
		}
	}
	if(!found) {
		NRecip++;
		return AddToList(NULL,user,sizeof *user,list);
	} else {
		return NULL;
	}
}

