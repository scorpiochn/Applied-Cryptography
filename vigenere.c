#include <stdio.h>

/* This program enciphers files using one of Vigenere, Beauford or
   Varian Beauford ciphers. Note inverses means this code also
   decrypts - eg encipherment by Vigenere can be deciphered by
   enciphering with Variant Beauford with the same key. Similarly,
   Beauford is its own inverse.

  Author: Dr Leisa Condie. December 1992.
          phoenix@neumann.une.edu.au
          Dept of Mathematics, Statistics and Computing Science,
          University of New England - Armidale,
          New South Wales, 2351, AUSTRALIA.
*/

#define ALPHA        26     /* length of alphabet for modulo */
#define MAXKEYLENGTH 10     /* maximum length of the key used */
#define BLOCKLENGTH   5     /* for output, how many chars in a block */
#define LINELENGTH   80     /* maximum output characters per line */

char key[MAXKEYLENGTH+1];   /* encipherment key: +1 for possible newline */
int  blockcount = 0;        /* counts of chars in printed block */
int  linechars = 0;         /* count of chars printed on current line */
int  keylength = 0;         /* holds actual length of the key */
int  vigenere=0,beauford=0,varbeau=0;
                            /* cipher type is set to 1 (TRUE) if chosen */
FILE *fp;                   /* set to stdin if interactive, else file */

void getsetup(void)
{
  char ch;                  /* generic character variable */
  char *tmp = key;          /* pointer to key array */

  /* find cipher type */
  ch = getc(fp);
  if (ch == 'V' || ch == 'v')         vigenere = 1;
  else if (ch == 'B' || ch == 'b')    beauford = 1;
  else if (ch == 'A' || ch == 'a')    varbeau  = 1;
  else { /* otherwise error, so notify by stderr and use Vigenere */
    fprintf(stderr,"V/B/A ciphers only - Vigenere assumed\n");
    vigenere = 1;
  }

  while ((ch = getc(fp)) != '\n');  /* if extraneous input, clear it! */
  
  /* get key - anything after the MAXKEYLENGTH'th char is discarded */
  
  for (keylength=0; keylength < MAXKEYLENGTH; keylength++)
    if ((key[keylength]= getc(fp)) == '\n') break;

  if (key[keylength] != '\n') {
    while ((ch = getc(fp)) != '\n'); /* if excess key, clear it! */
    fprintf(stderr,"Key truncated to %d characters\n", keylength);
  }
}

int encipher(int i)
{
  /* Takes argument i - where we are in the key,
     Returns tmp - the ciphertext equivalent of the input if
        the input was alphabetic, else the input character unchanged */
  char ch;                  /* character read in */
  int tmp;                  /* for cipher char calculation */

  ch = getc(fp);
  if (ch >= 'A' && ch <= 'Z') {  /* convert to lowercase */
    ch = ch - 'A' + 'a';         /* don't trust tolower() */
  }
  if (ch >= 'a' && ch <= 'z') {  /* encipher */
    if (vigenere)
      tmp = (ch + key[i] - 2*'a') % ALPHA;
    else if (beauford)
      tmp = (key[i] - ch) % ALPHA;
    else 
      tmp = (ch - key[i]) % ALPHA;

    /* make offset positive and convert to lowercase char */
    while (tmp < 0) tmp += ALPHA;
    tmp += 'a';
  } 
  else tmp = ch;         /* else return character unchanged */
  return(tmp);
}

void outputcipher(void)
{
  int cipherch, i=0;              /* cipher character */
  
  while (!feof(fp)) {             /* keep going whilst there is input */
    cipherch = encipher(i);  /* generate cipher character */
    if (cipherch < 'a' || cipherch > 'z') /* invalid char in */
      continue;              /* ignore code below - restart loop */
    
    /* check we haven't finished key and need to restart it */
    if (i == keylength-1)   i=0;
    else                   i++;

    /* if a BLOCKLENGTH block is finished print a space */
    if (blockcount == BLOCKLENGTH) {
      /* check whether a newline is needed yet */
      if (linechars > LINELENGTH - BLOCKLENGTH) {
        putchar('\n');
        linechars = 0;
      }
      else {
        putchar(' ');
        linechars++;
      }
      blockcount = 0;
    }
    /* print enciphered character */
    putchar(cipherch);
    blockcount++;
    linechars++;
  }
  putchar('\n');
}

/* This version of main is set for input to come from the keyboard either
   directly or through file redirection: e.g. program < input_file
*/
/*
void main(void)
{
  fp = stdin;
  getsetup();
  outputcipher();
}
*/

/* This version of main looks for an input file whose name is specified on
   the argument line: e.g. program input_file
*/
void main(int argc, char *argv[])
{
  if (argc != 2) {
    fprintf(stderr, "Usage: program <input_file>\n");
    exit(1);
  }

  if ((fp = fopen(argv[1],"r")) == NULL) {
    fprintf(stderr, "File %s cannot be read from\n", argv[1]);
    exit(1);
  }

  getsetup();
  outputcipher();
}




