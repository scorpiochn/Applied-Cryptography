
/*-------------------------------------------------------+-----*/
/*                                                       | GMD */
/*   SYSTEM   STAMOD  -  Version 2.0                     +-----*/
/*                                                             */
/*-------------------------------------------------------------*/
/*                                                             */
/*    PACKAGE   INSTALL                 VERSION 2.0            */
/*                                         DATE November 1991  */
/*                                           BY Levona Eckstein*/
/*                                                             */
/*    FILENAME			                 	       */
/*      install.c 		         		       */
/*                                                             */
/*    DESCRIPTION                                              */
/*      Installation program                                   */
/*                                                             */
/*     Administration of installation file                     */
/*     A record includes the following informations            */
/*     24 characters = port_name                               */
/*     Decimal       = bwt                                     */
/*     Dezimal       = cwt                                     */
/*     Decimal       = baud                                    */
/*     Decimal       = databits                                */
/*     Decimal       = stopbits                                */
/*     Decimal       = parity                                  */
/*     Decimal       = dataformat                              */
/*     Decimal       = tpdu_size                               */
/*     Decimal       = apdu_size                               */
/*     Decimal       = ec (Error detection Code )              */
/*                                                             */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/*   include-Files                                             */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include "install.h"


FILE *fd;
struct s_record portrecord;

main()
{

        char *fileptr;
        char portname[25];
        char aw1;
        int  rc;
        int  i;

        for (i=0; i < 25; i++)
          portname[i] = ' ';
        portname[0] = '\0';



        /* creat Installation file              */
        /* read shell - variable STAMOD        */
        if ((fileptr = getenv("STAMOD")) == NULL)
        {
         printf("No STAMOD variable in Environment\n");
         return(-1);
        };

        if ((fd = fopen(fileptr,"w")) == NULL)       /* Write only */
        {
         printf("ERROR: can't create File\n");
        return(-1);
        };

        fprintf(stderr,"CREATE NEW INSTALLATION FILE (Y / N): \n");
	scanf("%c",&aw1);
        getchar();


	while ((aw1 != 'N') && (aw1 != 'n'))
	{


          fprintf(stderr,"Portname (f.e.: /dev/ttya): ");
   	  scanf("%s",portname);
	  getchar();

          fprintf(stderr,"Default values: \n");
          fprintf(stderr,"BWT          = 3/10 sec\n ");
          fprintf(stderr,"CWT          = 1 sec\n ");
          fprintf(stderr,"BAUD         = 19200\n ");
          fprintf(stderr,"DATABITS     = 8\n ");
          fprintf(stderr,"STOPBITS     = 1\n ");
          fprintf(stderr,"PARITY       = NONE\n ");
          fprintf(stderr,"DATAFORMAT   = 0x3B\n ");
          fprintf(stderr,"TPDUSIZE     = 258\n ");
          fprintf(stderr,"APDUSIZE     = 254\n ");
          fprintf(stderr,"EDC          = XOR\n ");

          /* save record in installation file */


          portname[strlen(portname)] = ' ';
          for (i=0; i<24; i++)
            portrecord.port_name[i] = portname[i];
          portrecord.bwt = 3;
          portrecord.cwt = 1;
          portrecord.baud= 19200;
          portrecord.databits = 8;
          portrecord.stopbits = 1;
          portrecord.parity   = 0;
/* if odd => portrecord.parity = 768;
   if even=> portrecord.parity = 256  */

          portrecord.dataformat = 0x3B,
          portrecord.tpdu_size = 258;
          portrecord.apdu_size = 254;
          portrecord.edc = 0;

          fwrite(&portrecord,sizeof(struct s_record),1,fd);
          for (i=0; i < 25; i++)
            portname[i] = ' ';
          portname[0] = '\0';

          fprintf(stderr,"CREATE NEXT PORTRECORD (Y / N): \n");
	  scanf("%c",&aw1);
          getchar();
        }



        fclose(fd);
        exit(0);

}


