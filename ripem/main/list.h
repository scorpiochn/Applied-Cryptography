/*--- list.h -- definitions for our "list" data structure.
 *
 *  Mark Riordan  June - July 1992
 *  In the public domain.
 */
 
#ifndef LIST_INCLUDED
#define LIST_INCLUDED

typedef struct struct_list {
	struct struct_list_entry *firstptr;
	struct struct_list_entry *lastptr;
} TypList;

typedef struct struct_list_entry {
	struct struct_list_entry *nextptr; /* Address of next entry */
	struct struct_list_entry *prevptr; /* Address of previous entry */
	void               *dataptr; /* Pointer to actual data */
	unsigned int  		  datalen; /* Number of bytes of data in this entry */
} TypListEntry;

#define FORLIST(mylistptr) \
	{ TypListEntry *entry_ptr; \
		void *dptr;  \
		for(entry_ptr=(mylistptr)->firstptr; entry_ptr; \
		  entry_ptr=entry_ptr->nextptr) {  \
			dptr = entry_ptr->dataptr; 

#define ENDFORLIST } }
	

#endif
