/*--- alfaonly.c -- Program to remove all non-alphabetic chars
 * from input & map all chars to lower-case.
 *
 * Mark Riordan 2 April 93
 */

#include <stdio.h>
#include <ctype.h>

int 
main(int argc, char *argv[])
{
	int ch;

	while(EOF != (ch=getchar())) {
		if(isalpha(ch) && ch != ' ') {
			if(isupper(ch)) ch=tolower(ch);
			putchar(ch); 
		}
	}	
	return 0;
}
