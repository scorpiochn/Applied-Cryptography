/*--- Crackhed.c ---------------------------------------------------
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "ripemglo.h"
#include "prcodepr.h"
#include "crackhpr.h"
#include "strutilp.h"
#include "hexbinpr.h"
#include "derkeypr.h"
#include "listprot.h"

	int this_user = FALSE; /* TRUE if the last Recipient-ID is us. */
	int got_msgkey = FALSE;

/*--- function CrackHeader -----------------------------------------
 *
 *  Crack the Privacy Enhanced Message header.
 *
 *  Entry:  stream      is a stream positioned somewhere before the
 *                      the privacy enhanced message boundary.
 * userPublicKey is the user's public key used for Recipent-Key-Asymmetric
 *   fields.  If it is NULL, it means the public key was not found.
 *
 *  Exit:   Returns NULL if the header cracked OK, else a pointer
 *            to an error message.
 *          The variables below describe information obtained from
 *            the header.
 */
char *
CrackHeader(stream,prependHeaders,headerList,userList,userPublicKey,msgInfo)
FILE *stream;
BOOL prependHeaders;
TypList *userList;
R_RSA_PUBLIC_KEY *userPublicKey;
TypList *headerList;
TypMsgInfo *msgInfo;
{
#define MAX_LINE_SIZE 1024
   char *line, *line1, *line_prev=NULL, *ext_line=NULL;
#ifdef USE_TOKEN_PASTING
   char **fields;
#endif
   char *cptr;
	BOOL doing_header = TRUE;
	BOOL in_msg_headers = TRUE;
	int mylen;
	enum enum_state {ST_Begin, ST_Begin_Field, ST_Cont_Field} state = ST_Begin;

/*  IGNORE */
#if 0

	/* Ahhh, the joys of portability.
	 * I refuse to give up my enum's on non-Ultrix systems.
	 */
#ifdef ultrix
#define STRICT_ENUM
#endif

#ifdef STRICT_ENUM
#define PROC_TYPE       0
#define FILE_MODE       1
#define RECIPIENT       2
#define DEK             3
#define SENDER          4
#define SENDER_PUB_KEY  5
#define MESSAGE_KEY     6
#define LAST            7
   int fld;
   typedef int typfield;
#else
   enum enum_field {PROC_TYPE, FILE_MODE, RECIPIENT, DEK, SENDER,
    SENDER_PUB_KEY, MESSAGE_KEY, LAST} fld;
   typedef enum enum_field typfield;
#endif

#ifndef sun
#ifndef ultrix
#ifndef sgi
#define USE_TOKEN_PASTING
#endif
#endif
#endif

#ifdef USE_TOKEN_PASTING
#define f_ent(txt) {txt##_FIELD, txt, FALSE}
#else
#define f_ent(txt) {txt/**/_FIELD, txt, FALSE}
#endif

   static struct struct_field {
      char *fieldnm;
      typfield fieldtype;
      int  seen;
   } fields[] = {
      f_ent(PROC_TYPE), f_ent(FILE_MODE), f_ent(RECIPIENT), f_ent(DEK),
      f_ent(SENDER), f_ent(SENDER_PUB_KEY), f_ent(MESSAGE_KEY)
   };
#endif
/* END IGNORE */
   msgInfo->orig_name = NULL;
   msgInfo->got_orig_pub_key = FALSE;
	msgInfo->msg_key = (unsigned char *) 0;
	msgInfo->msg_key_len = 0;
	msgInfo->mic_len = 0;
  InitList (&msgInfo->certs);

	line = line1 = malloc(MAX_LINE_SIZE);
	if(!line) return("Can't allocate memory.");
	if(prependHeaders) {
		InitList(headerList);
	}


   while(doing_header) {
		if(line_prev) {
			line = line_prev;
			line_prev = NULL;
		} else {
			line = line1;
			cptr = fgets(line,MAX_LINE_SIZE,stream);
			if(!cptr) {
				doing_header = FALSE;
				if(!ext_line) break;
			} else {
				trim(line);
			}
		}
      /* Stop when we hit a blank line. */
      if(state != ST_Begin && LineIsWhiteSpace(line)) {
         doing_header = FALSE;
			if(!ext_line) break;
      }
      switch(state) {

         /* We haven't hit the beginning message boundary yet. */
         case ST_Begin:
            if(strncmp(line,HEADER_STRING_BEGIN,
				 strlen(HEADER_STRING_BEGIN))==0) {
               state = ST_Begin_Field;
				} else if(LineIsWhiteSpace(line)) {
					in_msg_headers = FALSE;
				} else if (prependHeaders && in_msg_headers) {
					AppendLineToList(line,headerList);
            } else if (Debug>2) {
				 	fprintf(DebugStream,"Skipping: %s\n",line);
			   }
            break;

         /* We are inside the PEM header. */
         case ST_Begin_Field:
			   /* Add white space to the end of the field name on the
				 * first line of a field.  This space is used by the
				 * tokenizing routines to separate the field name from
				 * from the values.
			    */
			   mylen = strlen(line);  /* We know mylen > 0 */
				if(line[mylen-1] == ':') {
					/* This is a field name. */
			   	line[mylen] = ' ';
			   	line[mylen+1] = '\0';
				}
            strcpyalloc(&ext_line,line);
			   state = ST_Cont_Field;
			   if(Debug>1) {
				   fprintf(DebugStream,"First line of field: \"%s\"\n",line);
			   }
			   break;

		   case ST_Cont_Field:
			   if(WhiteSpace(line[0])) {
				   cptr = line;
				   while(WhiteSpace(*cptr) && *cptr) cptr++;
				   strcatrealloc(&ext_line,cptr);
			   } else {

               line_prev = line;
			      state = ST_Begin_Field;
               if (cptr = DoHeaderLine(ext_line,userList,userPublicKey,msgInfo))
					return(cptr);
				
					free(ext_line);
			   	ext_line = NULL;
				}
			   break;
		}

   }

   cptr = NULL;
   if(state == ST_Begin) {
      cptr = "Could not find Privacy Enhanced Message header";
	}
	return cptr;
}

/*--- function DoHeaderLine ------------------------------------------------
 *
 * userPublicKey is the user's public key used for Recipent-Key-Asymmetric
 *   fields.  If it is NULL, it means the public key was not found.
 */
char *
DoHeaderLine(ext_line,userList,userPublicKey,msgInfo)
char *ext_line;
TypList *userList;
R_RSA_PUBLIC_KEY *userPublicKey;
TypMsgInfo *msgInfo;
{
#define MAXVALS 4
	char *vals[MAXVALS];
	enum enum_fields tok_field;
	enum enum_ids    tok_vals[MAXVALS];
	char field_name[MAX_LINE_SIZE];
	int  nvals, j, mylen;
	char *errmsg;
	TypList val_list;
	TypListEntry *entry;

   errmsg = CrackHeaderLine(ext_line,field_name,&val_list);
	if(errmsg) return errmsg;
   for(j=0,entry=val_list.firstptr; entry&&j<MAXVALS; 
	 entry=entry->nextptr,j++) {
      vals[j] = entry->dataptr;
   }
	nvals = j;
   if(Debug>1) {
      fprintf(DebugStream,"Field = \"%s\" [%d]",field_name,strlen(field_name));
      for(j=0; j<nvals; j++) {
         fprintf(DebugStream," \"%s\" [%d]",vals[j],strlen(vals[j]));
      }
      fputc('\n',DebugStream);
   }

   TokenizeHeaderLine(field_name,vals,nvals,&tok_field,tok_vals);
   if(Debug>1) {
	   int j;
	   fprintf(DebugStream,"Field == type %d. Vals are types",
		 tok_field);
	   for(j=0; j<nvals; j++) {
		   fprintf(DebugStream," %d",tok_vals[j]);
	   }
	   fprintf(DebugStream,".\n");
   }
   switch(tok_field) {
	   case PROC_TYPE_ENUM:
		   /* Look at Proc-Type number subfield (version). */
		   if(tok_vals[0] != PROC_TYPE_RIPEM_ID_ENUM  && tok_vals[0] != PROC_TYPE_PEM_ID_ENUM) {
			   sprintf(ErrMsgTxt,"RIPEM processes only Proc-Type %s and %s.",
				 IDNames[PROC_TYPE_RIPEM_ID_ENUM], IDNames[PROC_TYPE_PEM_ID_ENUM]);
			   return ErrMsgTxt;
		   }

		   /* Look at second Proc-Type subfield (encrypted vs. mic) */
		   msgInfo->proc_type = tok_vals[1];
		   if(msgInfo->proc_type < PROC_TYPE_ENCRYPTED_ID_ENUM ||
			 msgInfo->proc_type > PROC_TYPE_MIC_CLEAR_ID_ENUM) {
			   return("Bad Proc-Type in message header.");
		   }
		   break;

	   case CONTENT_DOMAIN_ENUM:
       /* Ignore Content-Domain */
       break;
       
	   case RECIPIENT_ENUM:
		   if(NameInList(vals[0],userList)) {
			   this_user = TRUE;
			   if(Debug>1) {
				   fprintf(DebugStream,"(This recipient is you.)\n");
			   }
		   }
		   break;

     case RECIPIENT_KEY_ENUM:
       if(nvals != 1) {
         return "Bad Recipient-Key-Asymmetric value.";
       } else {
         R_RSA_PUBLIC_KEY recipientPublicKey;
         int status, bin_len;
         unsigned char *bytes;

         if (userPublicKey == (R_RSA_PUBLIC_KEY *)NULL)
           return ("Cannot find user's public key.");

         /* Decode the recipient public key and check if it is the user's.
          */
         bin_len = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
         if ((bytes = (unsigned char *)malloc (bin_len))
             == (unsigned char *)NULL)
           return ("Could not allocate Recipient-Key-Asymmetric buffer.");
         
         prdecode (vals[0], bytes, bin_len);
         status = DERToPubKey (bytes, &recipientPublicKey);
         free (bytes);
         if (status != 0)
           return
             ("Could not decode Originator's public key in message header");

         if (R_memcmp
             ((POINTER)&recipientPublicKey, (POINTER)userPublicKey,
              sizeof (recipientPublicKey)) == 0) {
           this_user = TRUE;
           if(Debug>1) {
             fprintf(DebugStream,"(This recipient is you via public key.)\n");
           }
         }
       }
       break;

	   case DEK_ENUM:
		   /* Get the message encryption type & if it
			 * involves Cipher Block Chaining, also
			 * get the Initialization Vector.
			 */
		   if(tok_vals[0] != DEK_ALG_DES_CBC_ID_ENUM &&
		      tok_vals[0] != DEK_ALG_TDES_CBC_ID_ENUM
				) {
			   sprintf(ErrMsgTxt,"Can't process encryption type \"%s\".",
				 vals[0]);
			   return ErrMsgTxt;
		   }
  		   if (tok_vals[0] == DEK_ALG_DES_CBC_ID_ENUM)
              msgInfo->ea = EA_DES_CBC;
  		   else
              msgInfo->ea = EA_DES_EDE2_CBC;

		   if(nvals<2 || strlen(vals[1])!=16) {
			   return "Invalid initialization vector.";
		   }
		   HexToBin(vals[1],8,msgInfo->iv);
		   break;

	   case SENDER_ENUM:
		   if(nvals != 1) {
			   return "Bad Originator-Name value.";
		   }
			mylen = strlen(vals[0])+1;
		   msgInfo->orig_name = malloc(mylen);
			if(!msgInfo->orig_name) return "Can't allocate memory.";
		   strcpy(msgInfo->orig_name,vals[0]);
			if(Debug>1) {
				fprintf(DebugStream,"Originator-Name = %s [%d chars] %s\n",
				 vals[0],mylen-1,msgInfo->orig_name);
			}

		   break;

	   case SENDER_PUB_KEY_ENUM:
		   if(nvals != 1) {
			   return "Bad Originator-Key-Asymmetric value.";
		   } else {
            int bin_len;
            unsigned char *bytes;

	   	   bin_len = DECRYPTED_CONTENT_LEN((int)strlen(vals[0]));
			   bytes = (unsigned char *)malloc(bin_len);
			   bin_len = prdecode(vals[0],bytes,bin_len);
			   if(DERToPubKey(bytes,&(msgInfo->orig_pub_key))) {
				   return "Could not decode Originator's public key in message header";
			   }
			   msgInfo->got_orig_pub_key = TRUE;
		   }
		   break;

     case ORIGINATOR_CERT_ENUM:
       if(nvals != 1) {
         return "Bad Originator-Certificate value.";
       } else {
         int bin_len, certDERLen;
         unsigned char *bytes;

         /* Decode the certificate and add the DER to the list.
          */
         bin_len = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
         if ((bytes = (unsigned char *)malloc (bin_len))
             == (unsigned char *)NULL)
           return ("Could not allocate cert DER buffer.");
         
         certDERLen = prdecode (vals[0], bytes, bin_len);
         if ((errmsg = AddToList
              ((TypListEntry *)NULL, bytes, certDERLen, &msgInfo->certs))
             != (char *)NULL) {
           /* Could not add to list, so free the cert DER buffer */
           free (bytes);
           return (errmsg);
         }

         /* Don't free the bytes since they are adopted into the certs list. */
       }
       break;

	   case MESSAGE_KEY_ENUM:
		   /* Get the algorithm used to encrypt the message
			 * key, and get the encrypted message key.
			 */
		   if(this_user) {
			   this_user = FALSE;
			   got_msgkey = TRUE;
			   if(tok_vals[0] != ENCRYPTION_ALG_RSA_ID_ENUM) {
				   sprintf(ErrMsgTxt,"Unrecognized encryption type: %s",vals[0]);
				   return(ErrMsgTxt);
			   } else {
               msgInfo->msg_key_len = strlen(vals[1]);
				   msgInfo->msg_key = 
					  (unsigned char *) malloc(msgInfo->msg_key_len+1);
				   if(!msgInfo->msg_key) {
					   return "Can't allocate memory.";
				   }
					strcpy((char *)(msgInfo->msg_key),vals[1]);
			   }
		   }
		   break;

	   case MIC_INFO_ENUM:
		   if(tok_vals[0]==MIC_MD2_ID_ENUM) {
			   msgInfo->da = DA_MD2;
		   } else if(tok_vals[0]==MIC_MD5_ID_ENUM) {
			   msgInfo->da = DA_MD5;
         } else {
			   return "Unrecognized MIC algorithm.";
		   }

		   if(tok_vals[1] != ENCRYPTION_ALG_RSA_ID_ENUM) {
			   return "Unrecognized MIC encryption algorithm.";
		   }
		   if(nvals != 3) {
			   return "Missing encrypted MIC.";
		   } else {
            msgInfo->mic_len = strlen(vals[2]);
			   msgInfo->mic = (unsigned char *) malloc(msgInfo->mic_len+1);
			   if(!msgInfo->mic) {
				   return "Can't allocate memory.";
			   }
				strcpy((char *)msgInfo->mic,vals[2]);
   	   }

	   break;

	   default:
	   break;
   }

	FreeList(&val_list);
	return NULL;
}

/*--- function CrackHeaderLine ---------------------------------------
 *
 *  Break a header line into its constituent components.
 *  The line is considered to consist of a field name,
 *  optionally followed by comma-separated values.
 *
 *  Entry:  line        is a line from the message header.
 *
 *  Exit:   field_name  is the field name, starting in the first column.
 *          valList     contains pointers to cracked-off comma-separated
 *                      values.  Leading and trailing spaces have
 *                      been trimmed.
 *          Returns the number of values cracked.
 */
char *
CrackHeaderLine(line,field_name,valList)
char *line;
char *field_name;
TypList *valList;
{
	int leng;
	register char *cptr=line;

	for(leng=0; *cptr && !WhiteSpace(*cptr) && leng<MAX_LINE_SIZE-1; leng++) {
		*(field_name++) = *(cptr++);
	}
	*field_name = '\0';
	
	return CrackLine(cptr,valList);
	
}

/*--- function CrackLine --------------------------------------------------
 *
 *  Crack a comma-delimited line of text into individual elements.
 *
 *  Entry:  line        is a line from the message header.
 *          maxvals     is the number of entries in the array "vals".
 *
 *  Exit:   valList     is a list of the cracked-off comma-separated
 *                      values.  Leading and trailing spaces have
 *                      been trimmed.
 *          Returns NULL, or an error message.
 */
char *
CrackLine(line,valList)
char *line;
TypList *valList;
{
	int leng;
	register char *cptr=line;
	char *cvalp, *errmsg;
	char myline[MAX_LINE_SIZE];
	
	InitList(valList);
	
	while(*cptr) {
		while(*cptr && WhiteSpace(*(cptr))) cptr++;
		if(*cptr) {
			/* We have found a value.  Copy it into the array. */
			cvalp = myline;
			for(leng=0; *cptr && *cptr!=',' && *cptr!='\n' &&
			 leng<MAX_LINE_SIZE-1; leng++) {
				*(cvalp++) = *(cptr++);
			}
			/* Trim trailing blanks. */
			while(leng > 0 && *(cvalp-1) == ' ') {
				cvalp--;
				leng--;
			}
			*cvalp = '\0';
			errmsg = AppendLineToList(myline,valList);
			if(errmsg) return errmsg;
			/* If we're not already at a comma, skip to the comma or EOL */
			while(*cptr && *cptr != ',' && *cptr != '\n') cptr++;
			if(*cptr == ',') {
				cptr++;
			}
		}
	}
	return NULL;
}

/*--- function TokenizeHeaderLine ----------------------------------
 *
 */
void
TokenizeHeaderLine(field_name,vals,nvals,tok_field,tok_vals)
char *field_name;
char **vals;
int nvals;
enum enum_fields *tok_field;
enum enum_ids    tok_vals[];
{
	int j, ival;

	for(j=0; FieldNames[j] && !match(FieldNames[j],field_name);j++);

	*tok_field = (enum enum_fields) j;

	for(ival=0; ival<nvals; ival++) {
		for(j=0; IDNames[j] && !match(IDNames[j],vals[ival]); j++);
#if 0
fprintf(DebugStream,"IDNames[%d]=%lx '%s'\n",j,IDNames[j],IDNames[j]);
fprintf(DebugStream,"\n");
#endif
		tok_vals[ival] = (enum enum_ids)j;
	}
}

/*--- function NameInList ----------------------------------------------
 *
 *  Determine whether a given username matches any of the aliases
 *  for a email address.
 *
 *  Entry:	name			the name we're checking, zero-terminated.
 *				userList		List of aliases to my username.
 *
 *	 Exit:	Returns TRUE if a match found, else FALSE.
 */
BOOL
NameInList(name,userList)
char *name;
TypList *userList;
{
	TypListEntry *entry;
	BOOL found=FALSE;
	
	for(entry=userList->firstptr; entry && !found; entry=entry->nextptr) {
		found = match(name,entry->dataptr);
	}
	return found;
}
