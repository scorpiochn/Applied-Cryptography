/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   AUX_RESP                  VERSION 2.0          */
/*                                         DATE                */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME                                                 */
/*      sta_resp.c                                             */
/*                                                             */
/*    DESCRIPTION                                              */
/*      Auxiliary functions for response                       */
/*                                                             */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*      sta_aux_resp         eleminate length field in response*/
/*                           buffer                            */
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
/* PROC  sta_aux_elemlen     VERSION   2.0                */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Eleminate Length field in response-buffer             */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INOUT                     DESCRIPTION                  */
/*  resp                      response-structure          */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
void
sta_aux_elemlen(resp)
	Bytestring     *resp;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	char           *p;
	int             offset;
	int             i;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	p = resp->bytes;
	offset = 1;

	if ((resp->nbytes = ((int) *p) & 0xFF) >= 255) {
		p++;
		resp->nbytes = ((((int) *p++) & 0xff) << 8);
		resp->nbytes += (((int) *p) & 0xFF);
		offset = 3;
	};
	resp->nbytes += 2;

	for (i = 0; i < resp->nbytes; i++)
		*(resp->bytes + i) = *(resp->bytes + i + offset);

}

/*-------------------------------------------------------------*/
/* E N D   O F   P R O C E D U R E      sta_aux_elemlen        */
/*-------------------------------------------------------------*/
