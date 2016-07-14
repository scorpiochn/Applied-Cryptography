/*--- file keyman.c -- Manage public keys
 *
 *  Mark Riordan  20 May 1992
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "p.h"
#include "global.h"
#include "rsaref.h"
#include "md5.h"
#include "ripem.h"
#include "ripemglo.h"
#ifdef USE_DDES
#include "ddes.h"
#else
#include "des.h"
#endif
#include "keymanpr.h"
#include "strutilp.h"
#include "derkeypr.h"
#include "prcodepr.h"
#include "hexbinpr.h"
#include "getsyspr.h"
#include "ripemsop.h"
#include "pubinfop.h"
#include "ripemglo.h"
#include "keyderpr.h"
#include "rdwrmsgp.h"
#include "ripempro.h"
#include "certder.h"
#include "certutil.h"

#include "bemparse.h"

#define  DER_SEQ     0x30

/*--- function GetPublicKey -------------------------------------
 *
 *  Get the public key of a user.
 *
 *  Entry:  user        is a TypUser record.  Look up the  public keyis the
 *                    user's email address given by user->emailaddr.
 *          source      tells us where to look.
 *        certFilter: if not NULL, then search the record for a CertificateInfo
 *                    field and get the public key from the cert.  This will
 *                    decode the cert, call the certFilter->checkCert, and if
 *                    OK this uses certFilter->issuerPublicKey to verify the
 *                    cert signature.
 * 
 *  Exit:   user->pubkey         is the key (if found).
 *          user->gotpubkey         is TRUE if we found the key.
 *          user->validationStatus is CERT_UNVALIDATED if certFilter is NULL,
 *            otherwise it is the key's validation status.
 *          user->userDN         is the users full DN if certFilter is not NULL.
 *          Returns an error message if something goes wrong more 
 *            serious than not being able to find the key.
 */
char *
GetPublicKey(user,source, certFilter)
TypUser *user;
TypKeySource *source;
CertFilter *certFilter;
{
   unsigned char *bytes = NULL;
   char *err_msg=NULL;
   int sour, der_len = 0;
#if 0 /* see below, currently unused */
   BOOL got_new_addr=FALSE;
   char *addr;
   unsigned int nbytes;
#endif
   static BOOL server_ok=TRUE;
#define RECSIZE 3000
   char rec[RECSIZE];
#define MAXKEYBYTES 1024
   char coded_bytes[MAXKEYBYTES];
   unsigned char key_bytes[MAXKEYBYTES];
#define MAXDIGESTSIZE 36
   char computed_hex_digest[MAXDIGESTSIZE], records_hex_digest[MAXDIGESTSIZE];
   TypFile *fptr;

   user->gotpubkey = FALSE;
   
   for(sour=0; !user->gotpubkey && sour<MAX_KEY_SOURCES; sour++)
   switch(source->origin[sour]) {
      /* Search the key file */
      case KEY_FROM_FILE:
         FORLIST(&(source->filelist));
         fptr = (TypFile *)dptr;
         if(!fptr->stream) {
            sprintf(ErrMsgTxt,"Can't open public key file \"%s\".",
             fptr->filename);
            err_msg = ErrMsgTxt;
            continue;
         }

         /* Get the user record for this user from the file. */
         err_msg = GetUserRecordFromFile(user->emailaddr,fptr,RECSIZE,rec,&user->gotpubkey, certFilter);
         if(user->gotpubkey) goto decodekey;
         ENDFORLIST;
         break;

      /* Get key from server. */
      case KEY_FROM_SERVER:
         if(server_ok) {
       /* Only files have certs made by the user, so only look on servers
            if we are not looking for a certificate. */
       if (certFilter == (CertFilter *)NULL)
            err_msg = GetUserRecordFromServer(user->emailaddr,source,
             rec,RECSIZE,&server_ok,&user->gotpubkey);
            goto decodekey;
         }
            
      /* Get key from finger. */
      case KEY_FROM_FINGER:
     /* Only files have certs made by the user, so only look in finger
          if we are not looking for a certificate. */
     if (certFilter == (CertFilter *)NULL)
      /* Only files have certs made by the user, so don't look in finger. */
         err_msg = GetUserRecordFromFinger(user->emailaddr,rec,RECSIZE,&user->gotpubkey);
   decodekey:;
         if(Debug>1) {
            if(err_msg) {
               fprintf(DebugStream,
               "Error retrieving key for %s from server: %s\n",
               user->emailaddr,err_msg);
            } else if(user->gotpubkey) {
               fprintf(DebugStream,
                "Found %s's public key record:\n%s\n",user->emailaddr,rec);
            } else {
               fprintf(DebugStream,
                "Couldn't find %s's public key record.\n", user->emailaddr);
            }
         }
         if(user->gotpubkey) {
        if (certFilter != (CertFilter *)NULL)
          /* User record has a certificate, so use it. */
          CrackKeyField (rec, CERT_INFO_FIELD, coded_bytes, MAXKEYBYTES);
        else {
            CrackKeyField(rec,PUBLIC_KEY_FIELD,coded_bytes,MAXKEYBYTES);
            if(Debug>1) {
               fprintf(DebugStream,"Coded pub key=\"%s\"\n",coded_bytes);
            }
        }
        /* Decode either the cert or public key into key_bytes. */
            der_len = prdecode(coded_bytes,key_bytes,MAXKEYBYTES);
            bytes = key_bytes;
         }
            
         break;

      default:
         break;   /* XXX */
   }
   if(user->gotpubkey) {
    if (certFilter != (CertFilter *)NULL) {
      /* bytes has a certificate, so get public key from it also set
           the user->userDN.
         Since FindAndCheckCertInRecord already decoded it once,
           don't expect decoding errors.
       */
      CertificateStruct certStruct;
      unsigned char *innerDER;
      unsigned int innerDERLen;

      DERToCertificate (bytes, &certStruct, &innerDER, &innerDERLen);
      user->pubkey = certStruct.publicKey;
      user->userDN = certStruct.subject;
      user->validationStatus = CERT_VALID;
    }
    else {
      /* Convert key bytes to public key structure format. */
      if(DERToPubKey(bytes,&user->pubkey)) {
         /* Conversion didn't work. */
         sprintf(ErrMsgTxt,"Error parsing public key for %s.",user->emailaddr);
         err_msg = ErrMsgTxt;
      } else {
      /* Mark the key as unvalidated since it didn't come from a cert.*/
      user->validationStatus = CERT_UNVALIDATED;

         /* Conversion from BER format worked OK.
          * Now check this public key against the enclosed digest.
          */
         MakeHexDigest((unsigned char *)bytes,der_len,computed_hex_digest);
         if(CrackKeyField(rec,PUBLIC_KEY_DIGEST_FIELD,
           records_hex_digest,MAXDIGESTSIZE)) {
            if(Debug > 2) {
               fprintf(DebugStream,
                "der_len=%d\nComputed  MD5 of %s's pubkey=%s\n",der_len,
                 user->emailaddr, computed_hex_digest);
               fprintf(DebugStream,
                "Retrieved MD5 of %s's pubkey=%s\n",user->emailaddr,
               records_hex_digest);
            }
            if(strcmp(computed_hex_digest,records_hex_digest)) {
               sprintf(ErrMsgTxt,
               "Public key of '%s' is garbled--digest does not match.",user->emailaddr);
               err_msg = ErrMsgTxt;
            }
         } else {
            fprintf(stderr,"Warning--could not find %s's key digest.\n",
              user->emailaddr);
         }
      }
    }
   } 
   return err_msg;
}

/*--- function GetPublicKeyList ----------------------------------
 *
 *  Get the public keys of each of the users in a list.
 *
 *  Entry:  userList    is a TypList structure of the users whose keys
 *                      we need.
 *
 *  Exit:   userList    has been updated with the keys of none/some/all
 *                      of the users.
 *          Returns NULL if no fatal errors, else error message.
 *          
 */
char *
GetPublicKeyList(userList,pubKeySource, certFilter)
TypList *userList;
TypKeySource *pubKeySource;
CertFilter *certFilter;
{
   TypListEntry *entry_ptr;
   TypUser *recip_ptr;
   char *err_msg = NULL;
   
   for(entry_ptr = userList->firstptr; entry_ptr;
      entry_ptr = entry_ptr->nextptr) {
      recip_ptr = (TypUser *)entry_ptr->dataptr;
    if (recip_ptr->gotpubkey == TRUE)
      /* Already have the key for this user, so try the next one. */
      continue;
   
      if(Debug>1) {
         fprintf(DebugStream,"== Getting public key for %s\n",
          recip_ptr->emailaddr);
      }   
      err_msg = GetPublicKey(recip_ptr,pubKeySource, certFilter); 
      if(err_msg) return err_msg;   
   }        
   
   return err_msg;
}

/*--- function CheckKeyList ----------------------------------------
 *
 *  Check a list of users to make sure that we have a public key for
 *  each one.  
 *
 *  Entry:  userList is a list of TypUser types, containing
 *                   information on users (including whether
 *                   we know their public keys).
 *
 *  Exit:   Returns TRUE if it is OK to proceed, else FALSE.
 *          It's OK if we have the key of each user, or if the
 *          user has been prompted and has said it's OK to proceed
 *          even if some keys are unknown.
 */
 
BOOL
CheckKeyList(userList)
TypList *userList;
{
   extern BOOL AbortIfRecipUnknown;
   TypListEntry *entry_ptr;
   TypUser *recip_ptr;
   int bad_users = 0;
   BOOL ok = TRUE, asking=TRUE;
#define REPLY_BYTES 4
   unsigned char userbytes[REPLY_BYTES],timebytes[REPLY_BYTES];
   char reply;
   int n_userbytes, n_timebytes;
   
   for(entry_ptr = userList->firstptr; ok && entry_ptr;
      entry_ptr = entry_ptr->nextptr) {
      recip_ptr = (TypUser *)entry_ptr->dataptr;

      if(!recip_ptr->gotpubkey) bad_users++; 
   }        
   
   if(bad_users) {
      if(AbortIfRecipUnknown) {
         ok = FALSE;
      } else {
         if(bad_users==1) {
            fprintf(stderr,"Could not find public keys for this user:\n");
         } else {
            fprintf(stderr,"Could not find public keys for these %d users:\n",
             bad_users);
         }
         for(entry_ptr = userList->firstptr; ok && entry_ptr;
          entry_ptr = entry_ptr->nextptr) {
            recip_ptr = (TypUser *)entry_ptr->dataptr;
            if(!recip_ptr->gotpubkey) {
               fprintf(stderr,"   %s\n",recip_ptr->emailaddr);
            }
         }
         do {
            fprintf(stderr,"Proceed anyway, deleting these users? ");
            n_userbytes = n_timebytes = REPLY_BYTES;
            GetUserInput(userbytes,&n_userbytes,timebytes,&n_timebytes,TRUE);
            reply = (char) userbytes[0];
            if(reply == 'y' || reply=='Y') {
               ok = TRUE;
               asking = FALSE;
            } else if(reply=='n' || reply=='N') {
               ok = FALSE;
               asking = FALSE;
            }
         } while(asking);
      }
   }
   return ok;
}

/*--- function GetPrivateKey -------------------------------------
 *
 *  Get the private key of a user.
 */
char *
GetPrivateKey(user,source,key)
char *user;
TypKeySource *source;
R_RSA_PRIVATE_KEY *key;
{
   unsigned char *bytes;
   unsigned int nbytes;
   char *err_msg=NULL;
   unsigned char password[MAX_PASSWORD_SIZE], salt[SALT_SIZE];
   unsigned char *enc_key;
   BOOL found;
   unsigned int enc_key_len, iter_count;
   int digest_alg;
   unsigned int password_len, num_der_bytes;
   int sour;
   TypFile *fptr;

   for(sour=0; sour<MAX_KEY_SOURCES; sour++)
   switch(source->origin[sour]) {
      /* Search the key file */
      case KEY_FROM_FILE:
         FORLIST(&(source->filelist));
         fptr = (TypFile *)dptr;
         if(!fptr->stream) {
            sprintf(ErrMsgTxt,"Can't open private key file \"%s\".",
             fptr->filename);
            err_msg = ErrMsgTxt;
            continue;
         }
         err_msg = GetKeyBytesFromFile(user,fptr,
          PRIVATE_KEY_FIELD,&found,&bytes,&nbytes);
         if(!err_msg & !found) {
            err_msg = "Can't find user's private key.";
         }
         if(found) {
            err_msg = NULL;
            break;
         }
         ENDFORLIST;
         break;

      default:
         break;   /* XXX */
   }

   /* We now have the DER-encoded encrypted private key structure.
    * First, decode it to obtain the encryption algorithm parameters
    * and the actual bytes of the encrypted key.
    */
   if(!err_msg) {
      if(Debug>1) {
         fprintf(DebugStream,"Obtained %u byte encrypted private key for %s:\n",
          nbytes,user);
         BEMParse(bytes,DebugStream);
      }
      enc_key = (unsigned char *) malloc(nbytes);
      if(!enc_key) return "Can't allocate memory.";
      if(DERToEncryptedPrivKey (bytes,nbytes, &digest_alg,salt,&iter_count,
       enc_key,&enc_key_len)) {
         return "Error decoding encrypted private key.";
      }

      /* Now decrypt the encrypted key.
       */
      password_len = GetPasswordToPrivKey(FALSE,FALSE,
       password,MAX_PASSWORD_SIZE);

      if(pbeWithMDAndDESWithCBC(FALSE,digest_alg,enc_key,enc_key_len,
       password,password_len,salt,iter_count,&num_der_bytes)) {
         return "Can't decrypt private key.";
      }
      ClearBuffer(password,MAX_PASSWORD_SIZE);
      if(KeyToPrivKey) ClearBuffer(KeyToPrivKey,strlen(KeyToPrivKey));
   
      /* We have the plaintext private key in DER format.
       * Check to make sure it looks as if it was decrypted OK.
       * Then Decode to RSAREF format.
       */
      if(enc_key[0] != DER_SEQ) {
         return "Private key could not be decrypted with this password.";
      }

      if(DERToPrivKey(enc_key,key)) {
         sprintf(ErrMsgTxt,"Error parsing private key for %s.",user);
         err_msg = ErrMsgTxt;
      }

      if(Debug>1) {
         fprintf(DebugStream,"Dump of decrypted private key:\n");
         DumpPrivKey(key);
      }

   }
   return err_msg;
}

/*--- function GetKeyBytesFromFile ---------------------------------
 *  
 *  Obtain the value of a field from a flat file.
 *  The file is ASCII newline-delimited and consists of
 *  keys of form:   Key: value
 *  and fields of form:
 *     Fieldname:
 *        value...  (RFC1113 encoded)
 *
 *  Entry:  user        is the key value.  
 *          fileptr     contains the stream pointing at the file.
 *          keyFieldName  is the name of the field, e.g. PublicKeyInfo.
 *          
 *  Exit:   keyBytes    points to the bytes 
 *          numBytes    is the number of bytes retrieved.
 *          found       is TRUE if we found the key.
 *          Returns an error message if an error was found (more serious
 *          than the key value not being found).
 */
char *
GetKeyBytesFromFile(user,fileptr,keyFieldName,found,keyBytes,numBytes)
char *user;
TypFile *fileptr;
char *keyFieldName;
BOOL *found;
unsigned char **keyBytes;
unsigned int  *numBytes;
{
#define KALLOC_INC 1080
#define VALUELEN 120
   char value[VALUELEN];
   BOOL reading=TRUE;
   unsigned char *bytes, *base;
   char *err_msg = NULL;
   int bytesleft, alloc_size, bytes_in_line;

   *found = FALSE;
   fseek(fileptr->stream,0L,0);
   bytes = (unsigned char *)malloc(KALLOC_INC);
   *keyBytes = bytes;
   if(!*keyBytes) return ("Can't allocate memory.");
   alloc_size = bytesleft = KALLOC_INC;
   *numBytes = 0;

   /* Position to just after the line containing the user's name. */
   while(reading && GetFileLine(fileptr->stream,"User:",
    value,VALUELEN)) {
      if(match(value,user)) {
         reading = FALSE;
         *found = TRUE;
      }
   }
   /* We are now in the section of the file that corresponds
    * to this user.  Position to the desired field.
    * (There aren't many fields; we do this in case there
    * are multiple "User:" fields & to account for future changes.)
    */
   if(*found) {
      *found = FALSE;
      if(PosFileLine(fileptr->stream,keyFieldName)) {
         *found = TRUE;
         /* Now read the RFC1113-encoded lines and translate
          * them to binary.
          */

         for(reading=TRUE; reading; ) {
            if(fgets(value,VALUELEN,fileptr->stream)) {
               if(WhiteSpace(value[0]) && !LineIsWhiteSpace(value)) {
                  /* If we need more room in keyBytes, allocate more.
                   * Reassign pointers as necessary.
                   */
                  if(bytesleft < MAX_PRENCODE_BYTES) {
                     alloc_size += KALLOC_INC;
                     base = (unsigned char *)realloc(*keyBytes,alloc_size);
                     if(base) {
                     *keyBytes = base;
                     bytes = *keyBytes + *numBytes;
                     } else {
                        free(*keyBytes);
                        return("Can't allocate memory.");
                     }
                  }
                  /* Decode the line into the keyBytes buffer. */
                  bytes_in_line = prdecode(value+1,bytes,bytesleft);
                  bytes += bytes_in_line;
                  *numBytes += bytes_in_line;
                  bytesleft -= bytes_in_line;
               } else {
                  reading = FALSE; /* Have reached end of field */
               }
            } else {
               reading = FALSE; /* Have reached end of file. */
            }
         }
      }
   }

   if(Debug>1) {
      if(*found) {
         fprintf(DebugStream,"Obtained %s for %s from file %s.\n",
          keyFieldName,user,fileptr->filename);
      } else {
         fprintf(DebugStream,
          "Could not find %s of user %s in file %s.\n",
          keyFieldName,user,fileptr->filename);
      } 
   }
   return err_msg;
}

/*--- function GetUserRecordFromFile --------------------------------------
 *
 *  Get the user record for a user from a file.  A user record
 *  is a series of ASCII lines like:
 *    User: joe@bigu.edu
 *    PublicKeyInfo:
 *     MIGcMAoGBFUIAQECAgQAA4GNADCBiQKBgQDGQci5pOCGqQgW6XUYyGCcZFIyyLb7
 *     18nsKtQNjHZRODHkd+5tmHzMWp2BdFfV+CQzbMeNcdC9lC/RhLb7AgMBAAE=
 *    MD5OfPublicKey: E69AB9AA2A2697FCB5B1821DC3596345
 *
 *  Entry:  user     is the user name (email address) whose record we want.
 *          fileptr  contains the stream pointing at the file.
 *          maxBytes is the size of the buffer used to return data.
 *        certFilter: if not NULL, use certFilter->checkCert before returning
 *                    the record
 * 
 *  Exit:   userRec  contains the user record, if found.  It is 
 *                   zero-terminated.
 *          found    is TRUE if we found the key.
 *          Returns an error message if an error was found (more serious
 *          than the key value not being found), else NULL.
 */
char *
GetUserRecordFromFile(user,fileptr,maxBytes,userRec,found, certFilter)
char *user;
TypFile *fileptr;
unsigned int maxBytes;
char *userRec;
BOOL *found;
CertFilter *certFilter;
{
   char *errmsg=NULL;
   BOOL got_next_rec, looking=TRUE;
   
   *found = FALSE;
   fseek(fileptr->stream,0L,0);  /* Rewind the file. */
      
   if(Debug>1) {
      fprintf(DebugStream,"Looking in '%s' for public key for %s.\n",
         fileptr->filename,user);
   }
   while(looking) {
      GetNextUserRecordFromFile(fileptr->stream,maxBytes,
       userRec,&got_next_rec);
      if(got_next_rec) {
         if(FindUserInRecord(user,userRec)) {
        if (certFilter != (CertFilter *)NULL) {
          if ((errmsg = FindAndCheckCertInRecord
               (found, userRec, certFilter)) != (char *)NULL)
            break;

          if (*found)
            looking = FALSE;
        } else {
            *found = TRUE;
            looking = FALSE;
        }
         }
      } else {
         looking = FALSE;
      }
   }
   if(Debug>1) {
      if(*found) {
         fprintf(DebugStream,"Found %s's public key record in file.\n",
            user);
      } else {
         fprintf(DebugStream,"Didn't find %s's public key in file.\n",
           user);
      }
   }
   return errmsg;
}

/*--- function GetNextUserRecordFromFile ----------------------------------
 *
 *  Get the next user record from a sequential file.
 *  A user record is just a sequence of lines limited by a 
 *  blank line or a line starting with "--".
 *
 *  Entry:  ustream     is the stream of the file.
 *          maxBytes    is the buffer size of userRec.
 *
 *  Exit:   userRec     is the user record, if found.
 *          found       is TRUE if we successfully retrieved a record.
 *          Returns an error message if there was a problem worse
 *          than EOF, else NULL.
 */
char *
GetNextUserRecordFromFile(ustream,maxBytes,userRec,found)
FILE *ustream;
unsigned int maxBytes;
char *userRec;
BOOL  *found;
{
#define LINELEN 256
   char line[LINELEN];
   char *errmsg=NULL;
   char *uptr=userRec;
   char *got_line;
   unsigned int mylen;
   
   *found = FALSE;
   /* Skip past leading blank lines */
   do {
      if(!fgets(line,LINELEN,ustream)) {
         goto endnext;
      }
   } while(LineIsWhiteSpace(line) || strncmp(line,"---",2)==0);
   
   /* We hit a non-blank line.
    * Copy lines into the buffer until we hit EOF or blank line. 
    */
   *found = TRUE;
   do {
      mylen = (unsigned int)strlen(line);
      /* Copy this line into the buffer if there's room, 
       * else just return the truncated buffer.
       */
      if(maxBytes > mylen) {
         strcpy(uptr,line);
         uptr += mylen;
         maxBytes -= mylen;
      } else {
         goto endnext;
      }
      got_line = fgets(line,LINELEN,ustream);
   } while(got_line && !LineIsWhiteSpace(line) && strncmp(line,"---",2));
   
endnext:;
   return errmsg;
}


/*--- function WritePublicKey ----------------------------------------------
 *
 * Encode and write a public key.
 *
 * Entry:   pubKey      is a public key
 *          outStream   is a stream;
 *
 * Exit:    The key has been written.
 */
void
WritePublicKey(pubKey,outStream)
R_RSA_PUBLIC_KEY *pubKey;
FILE *outStream;
{
   char hex_digest[36];
   unsigned char *der;
   unsigned int derlen;
   
   derlen = PubKeyToDERLen(pubKey);
   der = (unsigned char *)malloc(2*derlen);

   PubKeyToDER (pubKey, der, &derlen);
   fprintf(outStream,"PublicKeyInfo:\n");
   CodeAndWriteBytes(der,derlen," ",outStream);
   MakeHexDigest(der,derlen,hex_digest);
   fprintf(outStream,"%s %s\n",PUBLIC_KEY_DIGEST_FIELD,hex_digest);
   
   if(Debug > 2) {
      fprintf(DebugStream,"DER encoding of public key:\n");
      BEMParse(der,DebugStream);

   }
   free(der);
}

/*--- function pbeWithMDAndDESWithCBC --------------------------------------
 *
 * Encrypt or decrypt a buffer with DES-CBC, using a key derived
 * from using a message disest (MDx) function on a password
 * and salt value.
 */
int
pbeWithMDAndDESWithCBC(encrypt,digestAlg,buf,numInBytes,password,
  passwordLen,salt,iterationCount,numOutBytes)
int encrypt;
int digestAlg;
unsigned char *buf;
unsigned int   numInBytes;
unsigned char *password;
unsigned int   passwordLen;
unsigned char *salt;
unsigned int   iterationCount;
unsigned int  *numOutBytes;
{
#define DIGEST_SIZE 16
   unsigned char *pass_and_salt, byte, parity, *bptr;
   MD5_CTX context;
   unsigned char digest[DIGEST_SIZE], des_key[DES_KEY_SIZE];
   unsigned char iv[DES_BLOCK_SIZE];
   unsigned int n_pad_bytes;
   unsigned int j, bit;

   if(digestAlg != DA_MD5) return 1;

   /* Create concatenation of password and salt */
   pass_and_salt = (unsigned char *) malloc(passwordLen+SALT_SIZE);
   if(!pass_and_salt) return 1;
   R_memcpy(pass_and_salt,password,passwordLen);
   R_memcpy(pass_and_salt+passwordLen,salt,SALT_SIZE);

   /* First iteration is a digest of password || salt */
   MD5Init(&context);
   MD5Update(&context,pass_and_salt, passwordLen+SALT_SIZE);
   MD5Final(digest,&context);

   free(pass_and_salt);

   /* Subsequent iterations are digests of the previous digest. */
   while(--iterationCount) {
      MD5Init(&context);
      MD5Update(&context,digest,DIGEST_SIZE);
      MD5Final(digest,&context);
   }

   /* Create the DES key by taking the first 8 bytes of the
    * digest and setting the low order bit to be an odd parity bit.
    */
   for(j=0; j<DES_KEY_SIZE; j++) {
      byte = digest[j];
      for(parity=0x01,bit=0; bit<7; bit++) {
         byte >>= 1;
         parity ^= (byte&0x01);
      }
      des_key[j] = (digest[j]&0xfe) | parity;
   }

   /* Create the initialization vector from the last 8 bytes of the digest */
   R_memcpy(iv,digest+DES_KEY_SIZE,DES_BLOCK_SIZE);

   /* Now we have the DES key and the init vector.
    * Do the encrypt or decrypt.
    */

   if(encrypt) {
      /* Pad the last block of the buffer with 1 to 8 bytes of
       * the value 01 or 0202 or 030303 or...
       */

      n_pad_bytes = DES_BLOCK_SIZE - numInBytes%DES_BLOCK_SIZE;
      for(bptr=buf+numInBytes,j=0; j<n_pad_bytes; j++,bptr++) {
         *bptr = n_pad_bytes;
      }
      *numOutBytes = numInBytes+n_pad_bytes;

      DESWithCBC(encrypt,buf,*numOutBytes,des_key,iv);

   } else {
      /* Do the decryption */
      if(numInBytes%DES_BLOCK_SIZE) return 1;
      DESWithCBC(encrypt,buf,numInBytes,des_key,iv);
      n_pad_bytes = buf[numInBytes-1];
      *numOutBytes = numInBytes - n_pad_bytes;
   }

   return 0;
}


/*--- function DESWithCBC ------------------------------------------
 *
 * Encrypt or decrypt a buffer with DES with Cipher Block Chaining.
 *
 *  Entry:  encrypt  is TRUE to encrypt, else decrypt.
 *          buf      is the beginning of the buffer.
 *          numBytes is the number of bytes to encrypt/decrypt.
 *                   It is rounded up to a multiple of 8.
 *          key      is the 8-byte key.
 *          iv       is the initialization vector.  (We pretend
 *                   it is the output from the previous round
 *                   of encryption.)
 *
 *  Exit:   buf      has been encrypted/decrypted.
 */
void
DESWithCBC(encrypt,buf,numBytes,key,iv)
int encrypt;
unsigned char *buf;
unsigned int numBytes;
unsigned char *key;
unsigned char *iv;
{
#ifdef USE_DDES
   int mode = !encrypt, count;
   unsigned char my_iv[DES_BLOCK_SIZE], save_iv[DES_BLOCK_SIZE];
   unsigned char *source, *targ;
   unsigned int block_cnt = (numBytes+DES_BLOCK_SIZE-1)/DES_BLOCK_SIZE;

   deskey(key,mode);
   R_memcpy(my_iv,iv,DES_BLOCK_SIZE);

   if(encrypt) {
      while(block_cnt--) {
         for(targ=buf,source=my_iv,count=DES_BLOCK_SIZE; count; count--) {
            *(targ++) ^= *(source++);
         }
         des(buf,buf);
         R_memcpy(my_iv,buf,DES_BLOCK_SIZE);
         buf += DES_BLOCK_SIZE;
      }
   } else {
      while(block_cnt--) {
         R_memcpy(save_iv,buf,DES_BLOCK_SIZE);
         des(buf,buf);
         for(targ=buf,source=my_iv,count=DES_BLOCK_SIZE; count; count--) {
            *(targ++) ^= *(source++);
         }
         R_memcpy(my_iv,save_iv,DES_BLOCK_SIZE);
         buf += DES_BLOCK_SIZE;
      }
   }
#else
   DES_CBC_CTX context;
   unsigned int len;

   len = (numBytes+DES_BLOCK_SIZE-1)/DES_BLOCK_SIZE;
   len *= DES_BLOCK_SIZE;

   DES_CBCInit(&context, key, iv, encrypt);
   (void)DES_CBCUpdate(&context, buf, buf, len);
   DES_CBCFinal(&context);
#endif
}

/*--- function GetPasswordToPrivKey ---------------------------------
 *
 *  Get the password to the encrypted private key.
 *
 *  Entry:  verify   is TRUE if we should prompt twice.
 *          new      is TRUE if it's a new password (change prompt)
 *          maxchars is the buffer size for password.
 *
 *  Exit:   password is the zero-terminated password.
 *
 *  Look for it in this order:
 *    Argument extracted from command line,
 *    value of environment variable,
 *    prompt user interactively.
 */
unsigned int
GetPasswordToPrivKey(verify,new,password,maxchars)
BOOL           verify;
BOOL           new;
unsigned char *password;
unsigned int   maxchars;
{
   unsigned int pw_len = 0;
   BOOL got_pw = FALSE;
   char *cptr;

  if (new) {
    if(NewKeyToPrivKey) {
      strncpy((char *)password,NewKeyToPrivKey,maxchars);
      pw_len = (unsigned int)strlen((char *)password);
      got_pw = TRUE;
    }
  }
  else {
   if(KeyToPrivKey) {
      strncpy((char *)password,KeyToPrivKey,maxchars);
      pw_len = (unsigned int)strlen((char *)password);
      got_pw = TRUE;
   }
  }

   if(!got_pw && !new) {
      GetEnvAlloc(KEY_TO_PRIVATE_KEY_ENV, &cptr);
      if(cptr && *cptr) {
         strncpy((char *)password,cptr,maxchars);
         pw_len = (unsigned int)strlen((char *)password);
         got_pw = TRUE;
      }
   }

   if(!got_pw) {
      if(new) {
         cptr = "Enter new password to private key: ";
      } else {
         cptr = "Enter password to private key: ";
      }
      pw_len = GetPasswordFromUser(cptr,verify,password,maxchars);
   }

   return pw_len;
}

/*--- function DumpPubKey ------------------------------------------
 *
 */
void
DumpPubKey(pubKey)
R_RSA_PUBLIC_KEY *pubKey;
{
   fprintf(DebugStream,"Dump of %d bit key:\n",pubKey->bits);
   fprintf(DebugStream,"    Mod=");
   DumpBigNum(pubKey->modulus,MAX_RSA_MODULUS_LEN);
   fputs("    exp=",DebugStream);
   DumpBigNum(pubKey->exponent,MAX_RSA_MODULUS_LEN);
}

/*--- function DumpPrivKey ------------------------------------------
 *
 */
void
DumpPrivKey(privKey)
R_RSA_PRIVATE_KEY *privKey;
{
   fprintf(DebugStream,"Dump of %d bit private key:\n",privKey->bits);
   fputs(" mod   =",DebugStream);
   DumpBigNum(privKey->modulus,MAX_RSA_MODULUS_LEN);
   fputs(" pubExp=",DebugStream);
   DumpBigNum(privKey->publicExponent,MAX_RSA_MODULUS_LEN);
   fputs(" exp   =",DebugStream);
   DumpBigNum(privKey->exponent,MAX_RSA_MODULUS_LEN);
   fputs(" prime1=",DebugStream);
   DumpBigNum(privKey->prime[0],MAX_RSA_PRIME_LEN);
   fputs(" prime2=",DebugStream);
   DumpBigNum(privKey->prime[1],MAX_RSA_PRIME_LEN);
   fputs(" prExp1=",DebugStream);
   DumpBigNum(privKey->primeExponent[0],MAX_RSA_PRIME_LEN);
   fputs(" prExp2=",DebugStream);
   DumpBigNum(privKey->primeExponent[1],MAX_RSA_PRIME_LEN);
   fputs(" coeffi=",DebugStream);
   DumpBigNum(privKey->coefficient,MAX_RSA_PRIME_LEN);
}

/*--- function DumpBigNum -------------------------------------------
 *
 */
void
DumpBigNum(bigNum,numLen)
unsigned char *bigNum;
int numLen;
{
   char buf[4];
   int j, bytesonline=0;

   for(j=0; j<numLen && !bigNum[j]; j++);
   for(; j<numLen; j++) {
      BinToHex(bigNum+j,1,buf);
      if(++bytesonline >= 32) {
         fputs("\n        ",DebugStream);
         bytesonline=1;
      }
      fputs(buf,DebugStream);
   }
   fputs("\n",DebugStream);
}
