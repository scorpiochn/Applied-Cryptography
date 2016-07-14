/*--- rdwrmsg.c -- Routine to help read and write messages. 
 *
 *  Mark Riordan  May 92 - July 92
 *
 *  This code is placed into the public domain.
 */
 
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "ripemglo.h"
#include "rdwrmsgp.h"
#include "strutilp.h"
#include "listprot.h"
#include "adduserp.h"
#include "prcodepr.h"
#include "ripempro.h"
 
 
/*--- function CodeAndWriteBytes ------------------------------
 *
 *  Convert a buffer of bytes to RFC1113 format and write
 *  the encoded data to a file.
 *
 *	 Entry: buf		is the buffer of data.
 *			   nbytes	is the number of bytes in the buffer.  There must
 *                   be room for one more byte in the buffer.
 *				prefix	is a zero-terminated string to write at the
 *							beginning of each line.	 Typically either
 *							empty string or one space.
 *				pstream is the stream to which to write the lines.
 *
 *	 Exit:	 Returns zero normally, else non-zero if error.
 */
int
CodeAndWriteBytes(buf,nbytes,prefix,pstream)
unsigned char *buf;
unsigned int nbytes;
char *prefix;
FILE *pstream;
{
#define CHUNKSIZE 48
	unsigned int line_bytes;
	char line[2*CHUNKSIZE];

   while(nbytes > 0) {
      line_bytes = nbytes<CHUNKSIZE ? nbytes : CHUNKSIZE;
		/* Make sure byte beyond last is zero.  Not strictly
		 * necessary, but makes the encoding more predictable.
		 */
		buf[nbytes] = 0;  
      prencode(buf,(int)line_bytes,line);
		fputs(prefix,pstream);
      fputs(line,pstream);
		fputc('\n',pstream);
      buf += line_bytes;
      nbytes -= line_bytes;
   }
	return 0;
}

/*--- function WriteCoded ----------------------------------------------
 *
 *  Write a chunk of coded bytes to the specified stream.
 *  Split the chunk into lines of "PR_CHUNKSIZE" characters.
 *
 *  Entry:	buf		is a buffer of ASCII characters.
 *				nbytes	 is the number of bytes in buf.
 *				prefix	 is a prefix to write at the beginning of each line.
 *				pstream	 is the stream to write to.
 *
 *  Exit:
 */
void
WriteCoded(buf,nbytes,prefix,pstream)
unsigned char *buf;
unsigned int nbytes;
char *prefix;
FILE *pstream;
{
#define PR_CHUNKSIZE 64
	unsigned char line_bytes;
	unsigned int j;

   while(nbytes > 0) {
      line_bytes = nbytes<PR_CHUNKSIZE ? nbytes : PR_CHUNKSIZE;
		fputs(prefix,pstream);
      for(j=0; j<line_bytes; j++) putc((char)buf[j],pstream);
		putc('\n',pstream);
      buf += line_bytes;
      nbytes -= line_bytes;
   }
}

/*--- function ReadMessage ---------------------------------------
 *
 *  Read the plaintext of an entire message into memory,
 *  converting it to RFC 821 format (CR/LF at end of line)
 *  as we go.  Optionally extract recipient names.
 *  The input is read one line at a time, so messages with
 *  extremely long lines will not be processed correctly.
 *
 *	 Entry:  stream			is the stream from which to read.
 *          stripQuotedHyphens means strip "- " from lines in body
 *                         which begin with "- -".
 *				addRecip			is TRUE if we should add to the recipient list
 *									recipients specified on To: and cc: lines
 *									in the message header.
 *				stripEOL			is TRUE if end-of-line sequences should be
 *									stripped from input; useful only for decrypting
 *									printably-encoded messages.
 *				includeHeaders is TRUE if the headers should be included
 *									in the message.
 *				lookForEndHeader  is TRUE if we should stop reading from
 *									the stream when we encounter the PEM boundary
 *									line; useful only for decrypting.
 *				prependHeaders is TRUE if we need to save the message header
 *									so it can be prepended to the output.
 *
 *  Exit:	text				points to the message.
 *				nbytes			is the number of bytes in the message.
 *				recipList		may have some additional recipients added.
 *				headerList     is the message header, if prependHeaders is TRUE.
 *				Returns NULL if everything went OK, else an error message.
 */
char *
ReadMessage(stream,stripQuotedHyphens,addRecip,stripEOL,includeHeaders,
lookForEndHeader,prependHeaders,headerList,text,nbytes,recipList)
FILE *stream;
BOOL stripQuotedHyphens;
BOOL addRecip;
BOOL stripEOL;
BOOL includeHeaders;
BOOL lookForEndHeader;
BOOL prependHeaders;
TypList *headerList;
unsigned char **text;
unsigned int  *nbytes;
TypList *recipList;
{
#define ALLOC_INC 24576
#define INLINESIZE 1024

	unsigned char line[INLINESIZE], *linecp;
	unsigned char ch;
   unsigned char *nextcp;
	unsigned int totbytes, bytesleft, to_field=FALSE;
	char *err_msg = NULL;
	int header_len = strlen(HEADER_STRING_END);
	BOOL inside_header=TRUE;

	if(prependHeaders) {
		InitList(headerList);
	}
	nextcp = *text = (unsigned char *)malloc(ALLOC_INC);
	if(!nextcp) {
		return("Can't allocate memory.");
	} else {
		bytesleft = totbytes = ALLOC_INC;
	}

	while(fgets((char *)line,INLINESIZE,stream)) {
		if(lookForEndHeader) {
			if(strncmp((char *)line,HEADER_STRING_END,header_len)==0) {
				break;
			}
		}
		
		/* Strip end-of-line CR and/or NL */
		for(linecp=line; *linecp && *linecp!='\r' && *linecp!='\n'; linecp++);
		*linecp = '\0';
		
		if(inside_header) {
			if(line[0] == '\0') {
				inside_header = FALSE;
				if(!includeHeaders) continue;
			} else {
				if(addRecip) {
					if(matchn((char *)line,"To:",3) ||
					 matchn((char *)line,"cc:",3)) {
						to_field = TRUE;
						CrackRecipients((char *)line+3,recipList);
					} else if(to_field) {
						if(WhiteSpace(line[0])) {
							CrackRecipients((char *)line,recipList);
						} else {
							to_field = FALSE;
						}
					}
				}
				if(prependHeaders) {
					AppendLineToList((char *)line,headerList);
				}
			}
		}
		
		if(!inside_header || includeHeaders) {
		  linecp=line;
		  if(stripQuotedHyphens) {
		    	if(strncmp((const char *)linecp,
			    (const char *)"- -", 3) == 0)
		      	linecp += 2;
		  }
			for(;ch = *(linecp++); ) {
				*(nextcp++) = ch;
				if((--bytesleft) == 0) {
					if(ReallocMessage(text,
							  &nextcp,
							  &bytesleft,
							  &totbytes)) {
						return("Can't allocate memory.");
					}
				}
			}
			if(!stripEOL) {
				*(nextcp++) = '\r';
				if((--bytesleft)==0) {
					if(ReallocMessage(text,
							  &nextcp,
							  &bytesleft,
							  &totbytes)) {
						return("Can't allocate memory.");
					}
				}
				*(nextcp++) = '\n';
				if((--bytesleft)==0) {
					if(ReallocMessage(text,&nextcp,&bytesleft,&totbytes)) {
						return("Can't allocate memory.");
					}
				}
			}
		}
	}

   *nbytes = totbytes - bytesleft;

	return err_msg;
}

/*--- function CrackRecipients ------------------------------------
 *
 */
char *
CrackRecipients(line,list)
char *line;
TypList *list;
{
	char *cptr=line, *targptr, *nptr, *beg_addr;
	char recip[INLINESIZE];
	BOOL good_recip;
	TypUser *recip_ptr;

	while(*cptr) {
		/* Skip white space at beginning of recipient name */
		while(WhiteSpace(*cptr) && *cptr) cptr++;

	/* Copy characters from recipient name to next delimiter */

		for(targptr=recip;*cptr && *cptr!=',' && *cptr!='\n';) {
			*(targptr++) = *(cptr++);
		}
		*targptr = '\0';
		if(*cptr) cptr++;
		/* Extract the address properly, even with <>  and () addresses. */
		beg_addr = ExtractEmailAddr(recip);
      /* Store the name of this recipient, if non-empty.  */
		for(nptr=beg_addr,good_recip=FALSE; !good_recip && *nptr; nptr++) {
			if(!WhiteSpace(*nptr)) good_recip = TRUE;
		}
		if(good_recip) {
			InitUser(beg_addr,&recip_ptr);
			nptr = AddUniqueUserToList(recip_ptr,list);
			if(nptr) return nptr;
		}
	}

	return NULL;
}


/*--- function ReallocMessage -----------------------------------
 *
 *  Increase the size of the buffer holding the message.
 */
int
ReallocMessage(text,nextcp,bytesleft,totbytes)
unsigned char **text;
unsigned char **nextcp;
unsigned int *bytesleft;
unsigned int *totbytes;
{
	unsigned char *base;

   base = (unsigned char *) realloc(*text,*totbytes+ALLOC_INC);
	if(base) {
		*text = base;
		*bytesleft = ALLOC_INC;
		*nextcp = *text + *totbytes;
		*totbytes += ALLOC_INC;
	} else {
		free(*text);
		return 1;
	}
	return 0;
}

/*--- function WriteEOL ---------------------------------------
 *
 *  Write an end-of-line sequence to the specified stream.
 *  This routine is intended to localize differences amoungst
 *  operating systems with respect to end-of-line sequences.
 *  (In Unix, convention is that EOL = newline.)
 *
 *  Entry:	stream	is an I/O stream to which we can write.
 *
 *  Exit:   An end-of-line sequence has been written.
 */
void
WriteEOL(stream)
FILE *stream;
{
	putc('\n',stream);
}

/*--- function WriteMessage --------------------------------------------------
 * quoteHyphens means add "- " before lines which start with a hyphen.
 */
void
WriteMessage(text,textLen,quoteHyphens,stream)
unsigned char *text;
unsigned int textLen;
BOOL quoteHyphens;
FILE *stream;
{
	register int ch;
	
	if(quoteHyphens && textLen > 1 && *text == '-') {
	  putc('-',stream);
	  putc(' ',stream);
	}

	while(textLen--) {
		ch = (int) *(text++);
		if(ch == '\r') {
			/* Ignore CR's */
		} else if(ch == '\n') {
			WriteEOL(stream);
			if(quoteHyphens && textLen >= 1 && *text == '-') {
			  putc('-',stream);
			  putc(' ',stream);
			}
		} else {
			putc(ch,stream);
		}
	}
}
