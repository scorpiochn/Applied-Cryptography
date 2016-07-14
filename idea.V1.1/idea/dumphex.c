/******************************************************************************/
/*                                                                            */
/*     D U M P   F I L E   I N   H E X A D E C I M A L   N O T A T I O N      */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ee.ethz.ch)                */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Created:      November 16, 1993                                            */
/* System:       SUN SPARCstation, SUN acc ANSI-C-Compiler, SUN-OS 4.1.3      */
/******************************************************************************/
/* Usage:        dumphex inFile                                               */
/******************************************************************************/
#include <stdio.h>
#include "idea.h"

#ifdef ANSI_C
  int main(int argc, char *argv[])
#else
  int main(argc, argv)
  int argc;
  char *argv[];
#endif

{ int count, ch;
  FILE *inFile;

  if (argc != 2) { fprintf(stderr, "Usage: dumphex inFile\n"); return -1; }
  if ((inFile = fopen(argv[1], "rb")) == NULL) { perror(argv[1]); return -1; }
  for (count = 0; (ch = fgetc(inFile)) != EOF; count++) {
    if ((count % 16) == 0) printf("\n ");
    printf(" %02x", ch);
  }
  printf("\n\n");
  return 0;
}
