/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   AUX_XDUMP                 VERSION 2.0          */
/*                                         DATE                */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME                                                 */
/*      sta_xdmp.c                                             */
/*                                                             */
/*    DESCRIPTION                                              */
/*      Auxiliary functions for trace                          */
/*                                                             */
/*                                                             */
/*    EXPORT                DESCRIPTION                        */
/*      sta_aux_sct_apdu     print SCT-APDU in file            */
/*                                                             */
/*      sta_aux_sct_resp     print SCT-RESP in file            */
/*                                                             */
/*      sta_aux_sc_apdu      print SC-APDU in file             */
/*                                                             */
/*      sta_aux_sc_resp      print SC-RESP in file             */
/*                                                             */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/
#ifndef MAC
#include <sys/types.h>
#include <sys/stat.h>
#else 
#include "MacTypes.h"
#endif /* !MAC */
#include <fcntl.h>
#include <stdio.h>
#include "sca.h"
#define  INSANZ 	28
#define  SC_INSANZ	17

static struct sct_ins {
	int             ins_code;
	char            ins_text[20];
}               SCTins[INSANZ] =

{
	{
		0x01, "S_REQUEST_SC"
	},
	{
		0x02, "S_STATUS"
	},
	{
		0x03, "S_EJECT_SC"
	},
	{
		0x04, "S_DISPLAY "
	},
	{
		0x05, "S_RESET"
	},
	{
		0x11, "S_TRANS"
	},
	{
		0x21, "S_GEN_USER_KEY"
	},
	{
		0x22, "S_INST_USER_KEY"
	},
	{
		0x23, "S_DEL_USER_KEY"
	},
	{
		0x24, "S_GET_RNO"
	},
	{
		0x25, "S_RSA_SIGN"
	},
	{
		0x26, "S_RSA_VERIFY"
	},
	{
		0x27, "S_DES_ENC"
	},
	{
		0x28, "S_RSA_ENC"
	},
	{
		0x29, "S_DES_DEC"
	},
	{
		0x2A, "S_RSA_DEC"
	},
	{
		0x2B, "S_ENC_DES_KEY"
	},
	{
		0x2C, "S_DEC_DES_KEY"
	},
	{
		0x31, "S_GEN_DEV_KEY"
	},
	{
		0x32, "S_INST_DEV_KEY"
	},
	{
		0x33, "S_DEL_DEV_KEY"
	},
	{
		0x41, "S_INST_PIN"
	},
	{
		0x42, "S_CHANGE_PIN"
	},
	{
		0x43, "S_AUTH"
	},
	{
		0x51, "S_GET_TRANSPORT_KEY"
	},
	{
		0x52, "S_GEN_SESSION_KEY"
	},
	{
		0x61, "S_WRITE_KEYCARD"
	},
	{
		0x62, "S_READ_KEYCARD"
	}
};

static struct sc_ins {
	int             ins_code;
	char            ins_text[20];
}               SCins[SC_INSANZ] =

{
	{
		0xF8, "SC_EXRND"
	},
	{
		0xF6, "SC_GET_CD"
	},
	{
		0x88, "SC_SETKEY"
	},
	{
		0xA6, "SC_SELECT"
	},
	{
		0xA4, "SC_REGISTER"
	},
	{
		0xB2, "SC_READF"
	},
	{
		0x8E, "SC_LOCKF"
	},
	{
		0x8A, "SC_DELREC"
	},
	{
		0xC8, "SC_DELF"
	},
	{
		0xA8, "SC_CLOSE"
	},
	{
		0x24, "SC_CHG_PIN"
	},
	{
		0x42, "SC_AUTH"
	},
	{
		0xD4, "SC_CREATE"
	},
	{
		0xF7, "SC_WR_KEY"
	},
	{
		0xB8, "SC_WRITEF"
	},
	{
		0x82, "SC_CRYPT"
	},
	{
		0x86, "SC_LOCKKEY"
	}
};






#ifdef DOS
typedef unsigned char u_char;
typedef unsigned long u_long;

struct hex_overlay {
	u_long          b0, b1, b2, b3;
};

#endif

typedef
union {
	struct {
		u_long          b0, b1, b2, b3;
	}               w;	/* for xdump, fxdump */
	char            c[16];
}               XBUF;








/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_sct_apdu       VERSION   2.0             */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print SCT-APDU in TRACE-File SCTINT.TRC               */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INPUT                     DESCRIPTION                  */
/*  dump_file                 File-pointer                */
/*                                                        */
/*  buffer                    information                 */
/*                                                        */
/*  len                       length of information       */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
int
sta_aux_sct_apdu(dump_file, buffer, len)
	FILE           *dump_file;
	char           *buffer;
	int             len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    index = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	fprintf(dump_file, "SCT_COMMAND: ");
	for (index = 0; index < INSANZ; index++) {

		if (SCTins[index].ins_code == (*(buffer + 1) & 0xFF)) {
			fprintf(dump_file, "%s\n", SCTins[index].ins_text);
			fprintf(dump_file, "      CL(0x%02x) INS(0x%02x) P1(0x%02x) P2(0x%02x) L(0x%02x)\n",
				*buffer & 0xFF,
				*(buffer + 1) & 0xFF,
				*(buffer + 2) & 0xFF,
				*(buffer + 3) & 0xFF,
				*(buffer + 4) & 0xFF);
			if ((*(buffer + 1) & 0xFF) == 0x11) {	/* = S_TRANS */
				fprintf(dump_file, "      DATA: ");
				sta_aux_sc_apdu(dump_file, buffer + 5, len - 5);
			} else {
				fprintf(dump_file, "      DATA:\n");
				aux_fxdump(dump_file, buffer + 5, len - 5, 0);
			}
			return (0);

		}
	}
	/* INS not found */
	fprintf(dump_file, "SCT_COMMAND: INS not defined\n");
	return (-1);



}



/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_sct_resp       VERSION   2.0             */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print SCT-RESP in TRACE-File SCTINT.TRC               */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INPUT                     DESCRIPTION                  */
/*  dump_file                 File-pointer                */
/*                                                        */
/*  buffer                    information                 */
/*                                                        */
/*  len                       length of information       */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
void
sta_aux_sct_resp(dump_file, buffer, len)
	FILE           *dump_file;
	char           *buffer;
	int             len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	fprintf(dump_file, "SCT-RESPONSE\n");

	fprintf(dump_file, "      L(0x%02x)\n", *buffer & 0xFF);
	fprintf(dump_file, "      DATA:\n");
	aux_fxdump(dump_file, buffer + 1, len - 3, 0);
	fprintf(dump_file, "      SW1(0x%02x) SW2(0x%02x)\n",
		*(buffer + len - 2) & 0xFF,
		*(buffer + len - 1) & 0xFF);




}

/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_sc_apdu        VERSION   2.0             */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print SC-APDU in TRACE-File SCCOM.TRC                 */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INPUT                     DESCRIPTION                  */
/*  dump_file                 File-pointer                */
/*                                                        */
/*  buffer                    information                 */
/*                                                        */
/*  len                       length of information       */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
int
sta_aux_sc_apdu(dump_file, buffer, len)
	FILE           *dump_file;
	char           *buffer;
	int             len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/
	unsigned int    index = 0;

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	fprintf(dump_file, "SC_COMMAND: ");
	for (index = 0; index < SC_INSANZ; index++) {

		if (SCins[index].ins_code == (*(buffer + 1) & 0xFF)) {
			fprintf(dump_file, "%s\n", SCins[index].ins_text);
			fprintf(dump_file, "      CL(0x%02x) INS(0x%02x) P1(0x%02x) P2(0x%02x) L(0x%02x)\n",
				*buffer & 0xFF,
				*(buffer + 1) & 0xFF,
				*(buffer + 2) & 0xFF,
				*(buffer + 3) & 0xFF,
				*(buffer + 4) & 0xFF);
			fprintf(dump_file, "      DATA:\n");
			aux_fxdump(dump_file, buffer + 5, len - 5, 0);
			return (0);

		}
	}
	/* INS not found */
	fprintf(dump_file, "SC_COMMAND: INS not defined\n");
	return (-1);



}


/*--------------------------------------------------------*/
/*                                                  | GMD */
/*                                                  +-----*/
/* PROC  sta_aux_sc_resp        VERSION   2.0             */
/*                              DATE   November 1991      */
/*                                BY   L.Eckstein,GMD     */
/*                                                        */
/* DESCRIPTION                                            */
/*  Print SC-RESP in TRACE-File SCCOM.TRC                 */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/*                                                        */
/* INPUT                     DESCRIPTION                  */
/*  dump_file                 File-pointer                */
/*                                                        */
/*  buffer                    information                 */
/*                                                        */
/*  len                       length of information       */
/*                                                        */
/*                                                        */
/*--------------------------------------------------------*/
void
sta_aux_sc_resp(dump_file, buffer, len)
	FILE           *dump_file;
	char           *buffer;
	int             len;
{
	/*----------------------------------------------------------*/
	/* Definitions                                            */
	/*----------------------------------------------------------*/

	/*----------------------------------------------------------*/
	/* Statements                                             */
	/*----------------------------------------------------------*/
	fprintf(dump_file, "SC-RESPONSE\n");

	fprintf(dump_file, "      L(0x%02x)\n", *buffer & 0xFF);
	fprintf(dump_file, "      DATA:\n");
	aux_fxdump(dump_file, buffer + 1, len - 3, 0);
	fprintf(dump_file, "      SW1(0x%02x) SW2(0x%02x)\n",
		*(buffer + len - 2) & 0xFF,
		*(buffer + len - 1) & 0xFF);




}
