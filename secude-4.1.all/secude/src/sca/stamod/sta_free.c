/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   AUX_FREE                  VERSION 2.0          */
/*                                         DATE                */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME                                                 */
/*      sta_free.c                                             */
/*                                                             */
/*    DESCRIPTION                                              */
/*      Auxiliary functions to free allocated space            */
/*                                                             */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*      sta_aux_bytestr_free   release bytes - pointer         */
/*                                                             */
/*      sta_aux_reclist_free   release reclist-structure       */
/*-------------------------------------------------------------*/


/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/
#include <stdio.h>
#include "sca.h"
#include "sctint.h"



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_bytestr_freeVERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Frees the bytes-buffer in Bytestring                  */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   pointer                   Bytestring structure       */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
void
sta_aux_bytestr_free(bytestr)
	Bytestring     *bytestr;/* IN - Puffer     */
{

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	if(bytestr->bytes) free(bytestr->bytes);
	bytestr->nbytes = 0;
	bytestr->bytes = NULL;

}


/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sta_aux_bitstr_free    */
/*-------------------------------------------------------------*/


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_reclist_freeVERSION   2.0               */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Frees the RecordList - structure                      */
/*                                                        */
/*                                                        */
/* IN                        DESCRIPTION                  */
/*   pointer                   RecordList  structure      */
/*                                                        */
/*                                                        */
/* OUT                                                    */
/*                                                        */
/*                                                        */
/* RETURN                    DESCRIPTION                  */
/*--------------------------------------------------------*/
void
sta_aux_reclist_free(recordlist)
	RecordList    **recordlist;	/* IN - Puffer     */
{

	/*----------------------------------------------------------*/
	/* Declarations                                           */
	/*----------------------------------------------------------*/
	RecordList     *ptr_head, *ptr_tail;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	ptr_tail = *recordlist;
	ptr_head = *recordlist;
	while (ptr_tail != RECNULL) {

#ifdef TRACE
		printf("TEST: ptr_tail: %x\n", ptr_tail);
		printf("TEST: ptr_tail->record: %x\n", ptr_tail->record.octets);
#endif

		ptr_head = ptr_head->next;
		if(ptr_tail) {
			if(ptr_tail->record.octets) free(ptr_tail->record.octets);
			free(ptr_tail);
		}
		ptr_tail = ptr_head;


	};

	*recordlist = RECNULL;

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sta_aux_reclist_free  */
/*-------------------------------------------------------------*/
