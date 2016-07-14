/*--- function usage -----------------------------------------------
 *
 *  Prints out a "usage" message.
 *
 *  Written by Mark Riordan in late 1990.
 *  This code is hereby placed in the public domain.
 *
 *  Entry   line1  points to a zero-terminated string that will
 *                 be written to the standard error stream.
 *                 This would typically be a one-line error message.
 *          msg    points to an array of pointers to zero-terminated
 *                 strings to be written to standard output.
 *                 This would typically be a general-purpose "usage"
 *                 message.
 */
#include <stdio.h>
#include "usagepro.h"

void
usage(line1,msg)
char *line1;
char **msg;
{
   if(line1) {
      fputs(line1,stderr);
      fputc('\n',stderr);
   } else {
      fputs("Usage message sent to standard output.\n",stderr);
   }
   fflush(stderr);
   while(*msg) {
      fputs(*msg,stdout);
      fputc('\n',stdout);
      msg++;
   }
}
