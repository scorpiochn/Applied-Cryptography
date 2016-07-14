/*--- ripemmai.c --  Main program for RIPEM
 *
 *   RIPEM -- Riordan's Internet Privacy Enhanced Mail
 *
 *            (aka RSAREF-based Internet Privacy Enhanced Mail)
 *
 *   RIPEM is a public key encryption package.
 *
 *   This program implements almost a subset of RFC 1113-1115 Privacy
 *   Enhanced Mail.  It uses RSA Data Security's RSAREF cryptographic
 *   toolkit for the encryption/decryption/verification of messages.
 *
 *   "ripem" is meant to be called to pre-process a mail message
 *   prior to being sent.  The recipient runs the encrypted
 *   message through "ripem" to get the plaintext back.
 *
 *   For the calling sequence, see the usagemsg.c file.
 *   For more information, see the accompanying files
 *   in this distribution.
 *
 *   Mark Riordan   May - September 1992
 *   (After RPEM, March - May 1991.)
 *
 *   This code is hereby placed in the public domain.
 *   RSAREF, however, is not in the public domain.
 *   Therefore, use of this program must be governed by RSA DSI's
 *   RSAREF Program License.  This license basically allows free
 *   non-commercial use within the United States and Canada.
 */

#define MAIN 1

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef SVRV32
#include <sys/types.h>
#endif /* SVRV32 */
#include "global.h"
#include "rsaref.h"
#include "ripem.h"

#ifdef MSDOS
#include <io.h>
#include <time.h>
#ifndef __TURBOC__
#include <malloc.h>
#else
#include <alloc.h>
#endif
#endif

#ifndef IBMRT
#include <stdlib.h>
#endif
#include <errno.h>

#if !defined (__convexc__) && !defined(apollo) && !defined(__TURBOC__)
#include <memory.h>
#endif

#include <string.h>

#include "ripemglo.h"
#include "prcodepr.h"
#include "usagepro.h"
#include "getoptpr.h"
#include "ripempro.h"
#include "getsyspr.h"
#include "strutilp.h"
#include "keyderpr.h"
#include "derkeypr.h"
#include "keymanpr.h"
#include "listprot.h"
#include "adduserp.h"
#include "r_random.h"
#include "bemparse.h"
#include "hexbinpr.h"
#include "crackhpr.h"
#include "rdwrmsgp.h"
#include "parsitpr.h"
#include "certder.h"
#include "certutil.h"
#include "p.h"

#ifdef UNIX
#ifdef __MACH__
#include <libc.h>
#endif
#include <pwd.h>
#endif

#ifdef MACTC
#include <stdlib.h>
#include <console.h>
#include <time.h>
#endif

#ifdef __BORLANDC__
extern unsigned _stklen = 12192;  /* Increase stack size for Borland C */
#endif

#ifndef UNUSED_ARG
#define UNUSED_ARG(x) x = *(&x);
#endif

char author[] = "Mark Riordan  1100 Parker  Lansing MI  48912";
char author2[] = 
  "mrr@scss3.cl.msu.edu or riordanmr@clvax1.cl.msu.edu   Sept 1992";

static void MainEnd P((int stat));
static char *LoginUser P((int *));
static char *LoginCheckCert
  P((THIS_CERT_FILTER *, int *, unsigned char *, unsigned int,
     struct CertificateStruct *));
static char *InitHomeDir P(());


/* Global variables used to return information from the
 * the command line.
 */

int Argc;
char **Argv;
extern char *usage_msg[];
TypList RecipientList, HeaderList, UserList;
char *Username=NULL;
int  MaxRecipients, NRecip = 0;
TypKeySource PubKeySource, PrivKeySource;
char *PubKeyOutFileName=NULL, *PrivKeyOutFileName=NULL;
char *InFileName=NULL, *OutFileName=NULL;
char *RandomFileName=NULL, *DebugFileName=NULL;
BOOL AddRecip=FALSE, IncludeHeaders=FALSE, PrependHeaders=FALSE;
BOOL AbortIfRecipUnknown=FALSE, MyselfAsRecip = FALSE;
int  RandomCmdIndex=0;
BOOL UseRndCmdLine=FALSE, UseRndFile=FALSE, UseRndKeyboard=FALSE;
BOOL UseRndMessage=FALSE, UseRndSystem=FALSE;
enum enum_action {ACT_NOT_SPEC, ACT_ENCRYPT, ACT_DECRYPT, ACT_GEN_KEY,
 ACT_CHANGE_PW} Action=ACT_NOT_SPEC;
enum enum_ids EncryptionMode = PROC_TYPE_ENCRYPTED_ID_ENUM;
R_RANDOM_STRUCT RandomStruct;
int	RandomStructInitialized = 0;
char *HomeDir = NULL;

R_RSA_PUBLIC_KEY  PublicKey;
R_RSA_PRIVATE_KEY PrivateKey;
DistinguishedNameStruct UserDN;
unsigned char *UserCertDER = (unsigned char *)NULL;
unsigned int UserCertDERLen;

int Bits=0;
int ValidityMonths = 24;
BOOL GotValidityMonths = FALSE;
int encryptionAlgorithm=EA_DES_CBC;

FILE *InStream, *OutStream;
FILE *PubOutStream=NULL, *PrivOutStream=NULL;
FILE *RandomStream = (FILE *)0;

#ifdef MACTC  /* rwo */
clock_t Time0, Time1;
#endif

#ifdef TESTDOS386
extern int ProcessorType(void);
int Got386 = 0;
#endif

int used_pub_key_in_message = 0;

int
main(argc,argv)
int argc;
char *argv[];
{
	int j;
	unsigned char buf[4];
   char *err_msg, *cptr;
	
#ifdef MACTC
   setvbuf(stderr, NULL, _IONBF, 0);
   fprintf(stderr, "Off we go...\n");
   argc = ccommand(&argv);
   Time0 = clock();
#endif

	Argc = argc; Argv = argv;
   InitMain();

   /* Parse the command line. */
   err_msg = CrackCmd(argc,argv);

   if(err_msg) {
      usage(err_msg,usage_msg);
      MainEnd(4);
  }

   /* Open files. */
	err_msg = OpenFiles();
	if(err_msg) {
		fprintf(stderr,"%s\n",err_msg);
		MainEnd(3);
	}

	if(Debug>1) ShowParams();

	/* Obtain "random" data from various sources and initialize
    * random structure with it.
    */
   if(Action != ACT_DECRYPT) {
		err_msg = DoRandom();
		if(err_msg) {
			fprintf(stderr,"%s\n",err_msg);
			MainEnd(2);
		}
	}

   /* Clear the parameters so that users typing "ps" or "w" can't
    * see what parameters we are using.
    */

   for(j=1; j<argc; j++) {
      cptr = argv[j];
      while(*cptr) *(cptr++) = '\0';
   }

   /* Get down to business and do the action requested of us. */
   if(Action == ACT_ENCRYPT) {
      err_msg = DoEncipher(OutStream);
   } else if(Action == ACT_DECRYPT){
      err_msg = DoDecipher(InStream,OutStream);
	} else if(Action == ACT_CHANGE_PW) {
		err_msg = DoChangePW(TRUE);
   } else {
		if(!Bits) {
			R_GenerateBytes(buf,1,&RandomStruct);
			Bits = 508 + (0x0f & buf[0]);
			if(Bits < 512) Bits = 512;
			if(Debug>1) {
				fprintf(DebugStream,
				 "Selected size of key being generated = %d bits.\n",
				  Bits);
			}
		}
		err_msg = DoGenerateKeys();
   }

   if(err_msg) {
      fputs(err_msg,stderr);
      fputc('\n',stderr);
      MainEnd(1);
   }
	ClearBuffer(&PrivateKey,sizeof PrivateKey);
	ClearBuffer(&RandomStruct,sizeof RandomStruct);
   MainEnd(used_pub_key_in_message);
   /*NOTREACHED*/
   return (0);	/* to shut up compiler warnings */
}

/*--- function MainEnd ------------------------------------------
 *
 *  End the program and return a returncode to the system.
 */
static void 
MainEnd(stat) 
int stat;
{
#ifdef MACTC
	double x;
	(void)fflush((FILE *)NULL);
	Time1 = clock();
	x = (Time1 - Time0)/60.0;
	fprintf(stderr, "Exit %d; Elapsed : %5.2f seconds.", stat, x);
#endif
	exit(stat);
}
	
/*--- function InitMain -----------------------------------------------
 *
 *  Do any necessary initialization before we really get going.
 *
 *       Entry: The program has just started.
 *
 *       Exit:  Some global variables have been initialized.
 */
char *
InitMain()
{
	InitList(&RecipientList);

	InitList(&(PubKeySource.filelist));
	InitList(&(PrivKeySource.filelist));
	InitList(&(PrivKeySource.serverlist));
	InitList(&(PubKeySource.serverlist));
	PubKeySource.origin[0] = KEY_FROM_SERVER;
	PrivKeySource.origin[0] = KEY_FROM_SERVER;
	PubKeySource.origin[1] = KEY_FROM_FILE;
	PrivKeySource.origin[1] = KEY_FROM_FILE;
	PubKeySource.origin[2] = KEY_FROM_FINGER;
	PrivKeySource.origin[2] = KEY_FROM_FINGER;
	
	PublicKey.bits = 0;

#ifdef TESTDOS386
	Got386 = (ProcessorType() >= 3);
#endif

	return NULL;
}

/*--- function CrackCmd ---------------------------------------------------
 *
 *  Parse the command line.
 *
 *  Entry   argc     is the usual argument count.
 *          argv     is the usual vector of pointers to arguments.
 *
 *  Exit    Returns the address of a string if an error occurred,
 *            else NULL is returned and some subset of the following
 *            global variables has been set:
 *
 *    encipher       = TRUE if enciphering selected; FALSE for deciphering.
 *    recipient      is the name of the recipient (if enciphering).
 *    file_mode      indicates the mode of the input file (ASCII vs binary)
 *                   if enciphering.
 *    user_init_vec  is the desired initialization vector if specified.
 *    init_vec_size  is the number of bytes in user_init_vec, if specified.
 *    username       is the name of the user running the program.
 *    algorithm      is the desired encryption technique if enciphering.
 *    block_mode     is the block mode (CBC vs. ECB) if enciphering.
 *    prompt         = TRUE if we are to prompt the user for a "random"
 *                   string to help generate the message key.
 *    garble         is TRUE if the private key is encrypted, if deciphering.
 *    PubKeySource.filename    is the name of the public key file if encrypting.
 *    PrivFileSource.filename   is the name of the private key file.
 *    debug          is TRUE if debugging has been selected.
 *    infilename     is the name of the input file if specified.
 *                   Normally, standard input is used; this option was
 *                   implemented due to shortcomings in Microsoft's
 *                   Codeview, which was used during development.
 *    got_infilename is TRUE if the input file was specified explicitly.
 */

char *
CrackCmd(argc, argv)
int argc;
char *argv[];
{
	extern char *optarg;
	extern int optind, optsp;

   int got_action = FALSE;
   int got_username = FALSE;
	int got_key_to_priv_key = FALSE;
	BOOL cracking=TRUE;
   int j, ch, found, myargc[2], iarg;
   char *err_msg = NULL, *cptr, **myargv[2], *env_args;
	char *random_sources = "efms";
	char *key_sources = "sf";
	char *header_opts = "i";
	char *recip_opts = "n";
	TypUser *recipient;
	char *usernameStr, *key_server_str=NULL;
	TypList mylist;
	TypFile *fptr;

	/* We crack a command line twice:  
	 * First, we crack the pseudo-command line in the environment variable
	 *   RIPEM_ARGS (if any).  This environment variable exists to make it
	 *   easy for users who don't want to type the otherwise lengthy
	 *   RIPEM command line, and is an alternative to the other individual 
	 *   environment variables.
	 * Then we crack the real command line.  
	 * Processing in this way causes the real command line variables
	 * to supercede the environment variables.
	 *
	 * Start by allocating space for a copy of RIPEM_ARGS.  
	 * We need to fill in the first token, the name of the program.
	 */ 
	env_args = malloc(8);
	strcpy(env_args,"ripem ");
	GetEnvAlloc(RIPEM_ARGS_ENV, &cptr);
	if(cptr) {
		/* If the environment variable exists, call parsit to tokenize
		 * the line as the shell normally does.
		 */
		strcatrealloc(&env_args,cptr);
		myargv[0] = (char **)NULL;
		myargc[0] = parsit(env_args,&(myargv[0]));
		free(env_args);
	} else {
		/* No environment variable exists; just dummy this up. */
		myargv[0] = (char **)NULL;
		myargc[0] = 0;
	}
	myargv[1] = argv;
	myargc[1] = argc;
	/* Now execute the argument processing loop twice. */
	for(iarg=0; iarg<2; optind=1,optsp=1,cracking=TRUE,iarg++)  {
		while(cracking &&
		 (ch = mygetopt(myargc[iarg],myargv[iarg],
		   "3edgcr:h:b:A:R:p:s:P:S:m:u:k:K:i:o:D:F:Z:C:y:Y:T:v:H:")) != -1) {
			switch (ch) {
				/* Program modes */
				case 'd':    /* Decipher */
					Action = ACT_DECRYPT;
					got_action++;
					break;

				case 'e':       /* Encipher */
					Action = ACT_ENCRYPT;
					got_action++;
					break;

				case 'g':       /* Generate keypair */
					Action = ACT_GEN_KEY;
					got_action++;
					break;
					
				case 'c':		/* Change key to private key */
					Action = ACT_CHANGE_PW;
					got_action++;
					break;

				/* Names (email addresses) of users */
				case 'r':
					/* Store the name of another recipient.  */
					InitUser(optarg,&recipient);
					cptr = AddUniqueUserToList(recipient,&RecipientList);
					if(cptr) return cptr;
					break;
					
				case 'T':		/* Flags governing recipient processing */
					strcpyalloc(&recip_opts,optarg);
					break;

				case 'h':       /* Flags governing message headers */
					/* See processing of this string below.
					 */
					strcpyalloc(&header_opts,optarg);
					break;

				case 'u':       /* My username */
					strcpyalloc(&usernameStr,optarg);
					got_username = TRUE;
					break;

                case '3':       /* short for -A des-ede-cbc */
                    encryptionAlgorithm = EA_DES_EDE2_CBC;
                    break;

                case 'A':       /* symmetric cipher */
                    encryptionAlgorithm = -1;
                    if (!strcmp(optarg, "des-cbc"))
                        encryptionAlgorithm = EA_DES_CBC;
                    if (!strcmp(optarg, "des-ede-cbc"))
                        encryptionAlgorithm = EA_DES_EDE2_CBC;
                    if (encryptionAlgorithm < 0) {
                        err_msg = "Symmetric cipher must be either \"des-cbc\"\
                            or \"des-ede-cbc\".";
                    }
                    break;

				case 'm':       /* Encryption mode */
					for(EncryptionMode=PROC_TYPE_ENCRYPTED_ID_ENUM, found=FALSE;
					 EncryptionMode<=PROC_TYPE_MIC_CLEAR_ID_ENUM && !found;
					 EncryptionMode++) {
						if(match(optarg,IDNames[EncryptionMode])) {
							found = TRUE;
							break;
						}
					}
					if(!found) {
						err_msg = "Processing mode must be one of \"encrypted\"\
	\"mic-only\" or \"mic-clear\".";
					}
					break;

				case 'b':       /* Number of bits in generated key */
					Bits = atoi(optarg);
					if(Bits < MIN_RSA_MODULUS_BITS || Bits > MAX_RSA_MODULUS_BITS) {
						sprintf(ErrMsgTxt,"Number of bits must be %d <= bits <= %d",
						  MIN_RSA_MODULUS_BITS,MAX_RSA_MODULUS_BITS);
						err_msg = ErrMsgTxt;
					}
					break;

        case 'v':                 /* Number of months to validate sender for */
          ValidityMonths = atoi (optarg);
          if (ValidityMonths <= 0)
            err_msg = "Validity months must be > 0";
          else
            GotValidityMonths = TRUE;
          break;

				case 'p':       /* Public key filename */
					fptr = (TypFile *)malloc(sizeof(TypFile));
					fptr->stream = NULL;
					strcpyalloc(&(fptr->filename),optarg);
					AddToList(NULL,fptr,sizeof(TypFile),&PubKeySource.filelist);
					break;
					
				case 'P':       /* Public key output filename */
					strcpyalloc(&PubKeyOutFileName,optarg);
					break;

				case 's':       /* Secret (private) key filename */
					fptr = (TypFile *)malloc(sizeof(TypFile));
					fptr->stream = NULL;
					strcpyalloc(&(fptr->filename),optarg);
					AddToList(NULL,fptr,sizeof(TypFile),&PrivKeySource.filelist);
					break;
					
				case 'S':       /* Private key output filename */
					strcpyalloc(&PrivKeyOutFileName,optarg);
					break;

				case 'y':       /* Name of public key server */
					strcpyalloc(&key_server_str,optarg);
					break;

				case 'Y':       /* Order of sources for keys (server vs. file) */
					strcpyalloc(&key_sources,optarg);
					break;

				case 'k':       /* Key to private key */
					strcpyalloc((char **)&KeyToPrivKey,optarg);
					got_key_to_priv_key = TRUE;
					break;

				case 'K':       /* New key to private key for changing password */
					strcpyalloc((char **)&NewKeyToPrivKey,optarg);
					break;

				case 'H':       /* RIPEM home directory */
					strcpyalloc ((char **)&HomeDir, optarg);
					break;

				case 'i':       /* Input file */
					strcpyalloc(&InFileName,optarg);
					break;

				case 'o':       /* Output file */
					strcpyalloc(&OutFileName,optarg);
					break;

				case 'D':       /* Debug level */
					Debug = atoi(optarg);
					break;

				case 'Z':       /* Debug output file */
					strcpyalloc(&DebugFileName,optarg);
					break;

				case 'F':       /* Random input file */
					strcpyalloc(&RandomFileName,optarg);
					break;

				case 'R':       /* Sources of random data */
					strcpyalloc(&random_sources,optarg);
					break;

				case 'C':       /* Random command args */
					RandomCmdIndex = optind-1;
					cracking = FALSE;
					break;

			}
		}
   }

	/* Parse the -R argument string (sources of random info) */

	for(cptr=random_sources; *cptr; cptr++) {
		switch(*cptr) {
			case 'c':
				UseRndCmdLine = TRUE;
				break;
			case 'e':
				UseRndCmdLine = TRUE;
				RandomCmdIndex = 0;
				break;
			case 'f':
				UseRndFile = TRUE;
				break;
			case 'k':
				UseRndKeyboard = TRUE;
				break;
			case 'm':
				UseRndMessage = TRUE;
				break;
			case 's':
				UseRndSystem = TRUE;
				break;
			default:
				err_msg = "-R option should be one or more of \"cefks\"";
				break;
		}
	}

	/* Parse the -Y argument string (sources of key info) */

	for(j=0; j<MAX_KEY_SOURCES; j++) {
		switch(key_sources[j]) {
			case 's':
			case 'S':
				PubKeySource.origin[j] = KEY_FROM_SERVER;
				break;

			case 'f':
			case 'F':
				PubKeySource.origin[j] = KEY_FROM_FILE;
				break;
				
			case 'g':
			case 'G':
				PubKeySource.origin[j] = KEY_FROM_FINGER;
				break;
		
			default:
				PubKeySource.origin[j] = KEY_FROM_NONE;
				break;
		}
	}
	
	/* Parse the -h option (how to process plaintext message headers) */
	
	for(cptr=header_opts; *cptr; cptr++) {
		switch(*cptr) {
			case 'r':
				AddRecip = TRUE;
				break;
			
			case 'i':
				IncludeHeaders = TRUE;
				break;
				
			case 'p':
				PrependHeaders = TRUE;
				break;
				
			default:
				err_msg = "-h option should be one or more of \"ipr\"";
				break;
		}
	}
	
	/* Parse the -T option (options for recipients) */
	
	for(cptr=recip_opts; *cptr; cptr++) {
		switch(*cptr) {
			case 'm':     /* Send a copy to myself */
				MyselfAsRecip = TRUE;
				break;
			
			case 'a':     /* Always abort if I can't find key for user */
				AbortIfRecipUnknown = TRUE;
				break;
				
			case 'n':     /* None of the above */
				MyselfAsRecip = FALSE;
				AbortIfRecipUnknown = FALSE;
				break;
				
			default:
				err_msg = "-T option should be one or more of \"amn\"";
				break;
		}
	}

  if (!HomeDir) {
    GetEnvFileName (HOME_DIR_ENV, "", &HomeDir);
    if (*HomeDir == '\0')
      /* GetEnvFileName returned the "" */
      HomeDir = NULL;
  }

  /* Add the public key file, etc. from the RIPEM home dir */
  if ((err_msg = InitHomeDir ()) != (char *)NULL)
    return (err_msg);

   /* Check for syntax error. */

   if(got_action != 1) {
      err_msg = "Must specify one of -e, -d, -g, -c";
   } else if(Action==ACT_ENCRYPT && 
	   EncryptionMode==PROC_TYPE_ENCRYPTED_ID_ENUM) {
      if(!RecipientList.firstptr && !AddRecip) {
	 err_msg = "Must specify recipient(s) when enciphering.";
      }
   } else if(Action != ACT_ENCRYPT && NRecip) {
      err_msg = "-r should be specified only when enciphering.";
   } else if(Action == ACT_ENCRYPT && PubKeySource.origin[0] == KEY_FROM_NONE
		 && PubKeySource.origin[1] == KEY_FROM_NONE) {
		err_msg = "Must specify at least one source of public keys.";
	} else if(Action == ACT_GEN_KEY && (!PubKeyOutFileName || 
	  !PrivKeyOutFileName)) {
		err_msg = "Must specify public and private (-P, -S) key output files.";
	} else if(Action == ACT_CHANGE_PW && !PrivKeyOutFileName) {
		err_msg = "Must specify private key output file (-S).";
	}
	
	if(err_msg) return err_msg;

   /* Obtain the username if it wasn't specified. */

   if(!got_username) {
      GetUserAddress(&usernameStr);
   }
	
	/* Crack the username string (which can contain multiple aliases
	 * separated by commas) into a list.
	 */
	
	CrackLine(usernameStr,&UserList);
	strcpyalloc(&Username,(char *)(UserList.firstptr->dataptr));

	/* Include the sender as cryptorecipient if specified and if
	 * encrypting.
	 */
	if (MyselfAsRecip && Action==ACT_ENCRYPT && 
	  EncryptionMode==PROC_TYPE_ENCRYPTED_ID_ENUM) {
		InitUser(Username,&recipient);
		cptr = AddUniqueUserToList(recipient,&RecipientList);
		if(cptr)return cptr;
	}
	
	/* Obtain the name of the public key server. */
	if(!key_server_str) {
		GetEnvAlloc(SERVER_NAME_ENV,&key_server_str);
	}
	err_msg = CrackKeyServer(key_server_str);
	if(err_msg) return err_msg;

   /* Obtain the names of the files containing the private keys.
    */

   if(!PrivKeySource.filelist.firstptr) {
		GetEnvFileName(PRIVATE_KEY_FILE_ENV,PRIVATE_KEY_FILE_DEFAULT,
		  &cptr);
		CrackLine(cptr,&mylist);
		free(cptr);
		FORLIST(&mylist);
			fptr = (TypFile *)malloc(sizeof(TypFile));
			fptr->stream = NULL;
			strcpyalloc(&(fptr->filename),dptr);
			ExpandFilename(&(fptr->filename));
			AddToList(NULL,fptr,sizeof(TypFile),&PrivKeySource.filelist);
		/* if(strlen(PrivKeySource.filename)==0) PrivKeySource.filename=NULL; */
		ENDFORLIST;
   }

   /* Obtain the names of the files containing
    * the public keys.
    */
   if(!PubKeySource.filelist.firstptr) {
		GetEnvFileName(PUBLIC_KEY_FILE_ENV,PUBLIC_KEY_FILE_DEFAULT,
		  &cptr);
		CrackLine(cptr,&mylist);
		free(cptr);
		FORLIST(&mylist);
			fptr = (TypFile *)malloc(sizeof(TypFile));
			fptr->stream = NULL;
			strcpyalloc(&(fptr->filename),dptr);
			ExpandFilename(&(fptr->filename));
			AddToList(NULL,fptr,sizeof(TypFile),&PubKeySource.filelist);
		/* if(strlen(PubKeySource.filename)==0) PubKeySource.filename=NULL; */
		ENDFORLIST;
   }

	/* Obtain the name of the file containing random data. */
	if(UseRndFile && !RandomFileName) {
		GetEnvFileName(RANDOM_FILE_ENV,"",&RandomFileName);
		if(strlen(RandomFileName)==0) RandomFileName=NULL;
	}

	
	/* Special processing for the key to the private key:
	 * A key of - means to read the key to the private key
	 * from standard input.
	 */
	if(got_key_to_priv_key) {
		if(strcmp(KeyToPrivKey,"-")==0) {
#define PWLEN 256
			char line[PWLEN];

			fgets(line,PWLEN,stdin);
			strcpyalloc((char **)&KeyToPrivKey,line);
			for(cptr=KeyToPrivKey; *cptr; cptr++) {
				if(*cptr=='\n' || *cptr=='\r') *cptr='\0';
			}
		}
	}
   return(err_msg);
}

/*--- function CrackKeyServer ----------------------------------------
 * 
 *  Function to help CrackCmd parse the list of key server names.
 *  The list is specified as a string (either in the -y option or
 *  in the RIPEM_KEY_SERVER env variable) that looks like:
 *
 *     domain_name[:port_num][,domain_name2[:port_num2]...
 *
 *  Entry:	keyServerStr	is a zero-terminated string that contains
 *									one or more key server names as above,
 *									or NULL.
 *
 *  Exit:	PubKeySource	contains the cracked information.
 */
char *
CrackKeyServer(keyServerStr)
char *keyServerStr;
{
	TypList name_list;
	TypListEntry *entry;
	TypServer *server_ent;
	char *cptr, *errmsg;
	
	InitList(&(PubKeySource.serverlist));
	
	if(keyServerStr) {
		CrackLine(keyServerStr,&name_list);
		for(entry=name_list.firstptr; entry; entry=entry->nextptr) {
			server_ent = (TypServer *) malloc(sizeof(TypServer));
			
			server_ent->servername = entry->dataptr;
			server_ent->serverport = 0;
			cptr = strchr(server_ent->servername,':');
			if(cptr) {
				server_ent->serverport = atoi(cptr+1);
				if(!server_ent->serverport) {
					return "Invalid server port number";
				}
				*cptr = '\0';
			} else {
				server_ent->serverport = SERVER_PORT;
			}
			errmsg = AddToList(NULL,server_ent,sizeof(TypServer),
			 &(PubKeySource.serverlist));
			if(errmsg) return errmsg;
		}
	}
	return NULL;		
}

/*--- function ShowParams -------------------------------------
 *
 *  Display the values of various user-supplied options,
 *  defaults, filenames, etc., for debugging purposes.
 */
void
ShowParams()
{
	char *cptr;
	char *not_present = "<none>";
	int j;
	TypListEntry *entry;
#define IFTHERE(str) (str ? str : not_present)

	fprintf(DebugStream,"%s\n",usage_msg[0]);
	fprintf(DebugStream,"Action=");
	switch(Action) {
		case ACT_NOT_SPEC:
			cptr = "<none>";
			break;
		case ACT_ENCRYPT:
			cptr = "Encrypt";
			break;
		case ACT_DECRYPT:
			cptr = "Decrypt";
			break;
		case ACT_GEN_KEY:
			cptr = "Generate";
			break;
		case ACT_CHANGE_PW:
			cptr = "Change PW";
			break;
	}
	fprintf(DebugStream,"%s  ",cptr);
	fprintf(DebugStream,"Recipients=");
#if 0
	for(j=0; j<NRecip; j++) fprintf(DebugStream,"%s ",RecipientList[j]);
#endif
	fprintf(DebugStream,"\n");
   fprintf(DebugStream,"Your Username=%s  KeyToPrivKey=%s\n",
	 IFTHERE(Username), IFTHERE(KeyToPrivKey));
	fprintf(DebugStream,"List of aliases to your username: \n");
	for(entry=UserList.firstptr; entry; entry=entry->nextptr) {
		fprintf(DebugStream,"   %s\n",(char *)entry->dataptr);
	}
	
	if(Action==ACT_GEN_KEY) {
		fprintf(DebugStream,"Bits in gen key=%d  ",Bits);
   }
	if(Action==ACT_ENCRYPT) {
      fprintf(DebugStream,"Proc mode=\"%s\"",IDNames[EncryptionMode]);
	}
	fprintf(DebugStream,"\n");

	fprintf(DebugStream,"Input=%s Output=%s\n",
    InFileName ? InFileName : "<stdin>",
    OutFileName ? OutFileName : "<stdout>");
	fprintf(DebugStream,"PubKeyFiles=");
	FORLIST(&PubKeySource.filelist);
		fprintf(DebugStream,"%s ",((TypFile *)dptr)->filename);
	ENDFORLIST;
	fprintf(DebugStream,"\n");
	fprintf(DebugStream,"PrivKeyFiles=");
	FORLIST(&PrivKeySource.filelist);
		fprintf(DebugStream,"%s ",((TypFile *)dptr)->filename);
	ENDFORLIST;
	fprintf(DebugStream,"\n");
	fprintf(DebugStream,"Sources of \"random\" data: ");
	if(UseRndCmdLine) {
		fprintf(DebugStream,"Command line, args %d-%d;\n ",
       RandomCmdIndex,Argc);
	}
	if(UseRndFile) fprintf(DebugStream,"File \"%s\"; ",IFTHERE(RandomFileName));
	if(UseRndKeyboard) fprintf(DebugStream,"Keyboard; ");
	if(UseRndMessage) fprintf(DebugStream,"Message; ");
	if(UseRndSystem) fprintf(DebugStream,"running System.");
	fprintf(DebugStream,"\n");

   if(UseRndCmdLine) {
		fprintf(DebugStream,"Random command-line arguments: ");
		for(j=RandomCmdIndex; j<Argc; j++) {
			fprintf(DebugStream,"%s ",Argv[j]);
		}
		fprintf(DebugStream,"\n");
	}

	fprintf(DebugStream, "Public key servers:\n");
	{ TypServer *server_ent;
		TypListEntry *entry;
		
		for(entry=PubKeySource.serverlist.firstptr; entry; 
		 entry=entry->nextptr) {
			server_ent = (TypServer *) entry->dataptr;
			if(server_ent->servername)
	 			fprintf(DebugStream,"   %s port %d\n",server_ent->servername,
				 server_ent->serverport);
		}
	}
	fprintf(DebugStream,"Public key key sources (in order) = ");
	for(j=0; j<MAX_KEY_SOURCES; j++) {
		switch(PubKeySource.origin[j]) {
			case KEY_FROM_FILE:
				fprintf(DebugStream,"file ");
				break;
			case KEY_FROM_SERVER:
				fprintf(DebugStream,"server ");
				break;
			case KEY_FROM_FINGER:
				fprintf(DebugStream,"finger ");
				break;
			default:
				fprintf(DebugStream,"UNKNOWN");
				break;
		}
	}
	putc('\n',DebugStream);

	{ R_RSA_PRIVATE_KEY *privKey = &PrivateKey;

	fprintf(DebugStream,"sizeof PrivateKey=%d ",sizeof(PrivateKey));
   fprintf(DebugStream,"sizeof components = %d %d %d %d %d %d %d %d %d \n",
    sizeof(privKey->bits),sizeof(privKey->modulus),
    sizeof(privKey->publicExponent),
    sizeof(privKey->exponent),sizeof(privKey->prime[0]),
	 sizeof(privKey->prime[1]),
	 sizeof(privKey->primeExponent[0]),sizeof(privKey->primeExponent[1]),
	 sizeof(privKey->coefficient));
	}
}

/*--- function OpenFiles --------------------------------------
 *
 *  Open files for RIPEM.
 *
 *  Entry:
 *
 *  Exit:   InStream, OutStream, PubStream, PrivStream,
 *          RandomStream contain file pointers to the corresponding
 *          files (or streams), if there's no error.
 *
 *          Returns NULL if no error, else address of error string.
 */
char *
OpenFiles()
{
   if(InFileName) {
      InStream = fopen(InFileName,"r");
      if(!InStream) {
	 sprintf(ErrMsgTxt,"Can't open input file %s.",InFileName);
	 return(ErrMsgTxt);
      }
   } else {
      InStream = stdin;
   }

   if(OutFileName) {
      OutStream = fopen(OutFileName,"w");
      if(!OutStream) {
	 sprintf(ErrMsgTxt,"Can't open output file %s.",OutFileName);
	 return(ErrMsgTxt);
      }
   } else {
      OutStream = stdout;
   }

   if(DebugFileName) {
      DebugStream = fopen(DebugFileName,"w");
      if(!DebugStream) {
	 sprintf(ErrMsgTxt,"Can't open debug file %s.",DebugFileName);
	 return(ErrMsgTxt);
      }
   } else {
      DebugStream = stderr;
   }
	CertinfoStream = DebugStream;

	if(Action != ACT_GEN_KEY ) {
		FORLIST(&PrivKeySource.filelist);
		   ((TypFile*)dptr)->stream = 
			 fopen(((TypFile*)dptr)->filename,"r");
		   if(!((TypFile*)dptr)->stream) {
		      sprintf(ErrMsgTxt,"Can't open private key file \"%s\".",
				 ((TypFile*)dptr)->filename);
		      return(ErrMsgTxt);
			}
		ENDFORLIST;
	}

	if(Action != ACT_GEN_KEY ) {
		FORLIST(&PubKeySource.filelist);	
		   ((TypFile*)dptr)->stream = 
			 fopen(((TypFile*)dptr)->filename,"r");
			if(Debug>1 && !((TypFile*)dptr)->stream ) {
				fprintf(DebugStream,"Warning:  can't open public key file %s\n",
				 ((TypFile*)dptr)->filename);
			}
		ENDFORLIST;
	}

	if(Action != ACT_DECRYPT && UseRndFile) {
		if(RandomFileName) {
			RandomStream = fopen(RandomFileName,"r");
			if(!RandomStream) {
				sprintf(ErrMsgTxt,
				 "Can't open random data file \"%s\".",RandomFileName);
				return(ErrMsgTxt);
			} else {
#ifdef MSDOS
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#ifdef __GNUC__
				_setmode(fileno(RandomStream),O_BINARY);
#else
#ifdef __TURBOC__
#define _setmode setmode
#define _fileno fileno
#endif
				_setmode(_fileno(RandomStream),O_BINARY);
#endif
#endif
			}
		}
	}
	return NULL;
}

/*--- function InitUser ---------------------------------------
 *
 *  Initialize a TypUser structure.
 *
 *  Entry: email       points to the user's email address (zero-terminated).
 *
 *  Exit:  userEntry       points to a pointer to a newly-allocated TypUser 
 *                                              structure.
 */
char *
InitUser(email,userEntry)
char *email;
TypUser **userEntry;
{
	char *err_msg = NULL;
	char *cptr;
	
	*userEntry = (TypUser *) malloc(sizeof **userEntry);
	if(*userEntry) {
		(*userEntry)->gotpubkey = FALSE;
		if(!strcpyalloc(&cptr,email)) {
			err_msg = "Can't allocate memory";
		} else {
			(*userEntry)->emailaddr = cptr;
		}
	} else {
		err_msg = "Can't allocate memory";
	}
	
	return err_msg;
}                       

/*--- function DoRandom ---------------------------------------
 *
 *  Assemble pseudo-random data from various locations and
 *  feed it into a R_RANDOM_STRUCT structure.
 *
 *  Entry: UseRndCmdLine     \
 *         UseRndFile         \
 *         UseRndKeyboard     / These tell which sources to use
 *         UseRndSystem      /  for random data
 *         RandomCmdIndex       "argv" index at which to start, if
 *                              using command line params as random.
 *          RandomStream        Stream pointer to random file, if any.
 *
 *   Exit:  RandomStruct    contains the init'ed random struct.
 *          Returns NULL if no error, else pointer to error message.
 */
char *
DoRandom()
{
#define RANBUFSIZE 1024
	unsigned char ranbuf[RANBUFSIZE];
	unsigned char timebuf[RANBUFSIZE];
	int nbytes, ntimebytes, jarg, totbytes=0, getting_random=TRUE;


	R_RandomInit(&RandomStruct);
	R_memset(ranbuf,0,RANBUFSIZE);
	RandomStructInitialized = 1;

	/* Because we use the random struct during the
    * process of obtaining random data, we seed it first
    * to avoid RE_NEED_RANDOM errors.
    */
	while(getting_random) {
		unsigned int nbytes_needed;

		R_GetRandomBytesNeeded(&nbytes_needed,&RandomStruct);
		if(nbytes_needed) {
			R_RandomUpdate(&RandomStruct,ranbuf,256);
		} else {
			getting_random = FALSE;
		}
	}

	/* If requested, obtain random info from the running system. */
	if(UseRndSystem) {
		nbytes = GetRandomBytes(ranbuf,RANBUFSIZE);
      R_RandomUpdate(&RandomStruct,ranbuf,nbytes);
		totbytes += nbytes;
   }

	/* If requested, obtain random info from the user at the
    * keyboard.
    */
	if(UseRndKeyboard) {
		fprintf(stderr,"Enter random string: ");
		nbytes = ntimebytes = RANBUFSIZE;
		GetUserInput(ranbuf,&nbytes,timebuf,&ntimebytes,TRUE);
      R_RandomUpdate(&RandomStruct,ranbuf,nbytes);
      R_RandomUpdate(&RandomStruct,timebuf,ntimebytes);
		totbytes += nbytes+ntimebytes;
	}

	/* If requested, obtain random info from the command line
    * arguments.
    */
   if(UseRndCmdLine) {
		for(jarg=RandomCmdIndex; jarg<Argc; jarg++) {
			nbytes = strlen(Argv[jarg]);
			R_RandomUpdate(&RandomStruct,(unsigned char *)Argv[jarg],
			 nbytes);
			totbytes += nbytes;
		}
	}

   /* If requested & available, read random information from
    * randomly-selected spots on the "random" file.
    */
   if(UseRndFile && RandomStream) {
		long int filesize, myoffset;
		int iterations;

		/* Find the size of the file by seeking to the end
		 * and then finding out where we are.
       */
		fseek(RandomStream,0L,2);  /* seek to end of file */
		filesize = ftell(RandomStream);

		/* Figure out how many blocks to read. Do this by
		 * computing a pseudo-random number from the information
		 * seeded so far.
		 */

		R_GenerateBytes(ranbuf,1,&RandomStruct);
		iterations = 1 + (ranbuf[0] & 7);
		if(Debug>1) {
			fprintf(DebugStream,"Random file: seeking to byte ");
		}

      while(iterations--) {
			R_GenerateBytes((unsigned char *)&myoffset,sizeof(myoffset),
			 &RandomStruct);
			if(myoffset<0) myoffset = (-myoffset);
			myoffset %= filesize;
			if(Debug>1) fprintf(DebugStream,"%ld ",myoffset);
			fseek(RandomStream,myoffset,0); /* seek to location */
			nbytes = fread(ranbuf,1,RANBUFSIZE,RandomStream);
	      R_RandomUpdate(&RandomStruct,ranbuf,nbytes);
			totbytes += nbytes;
		}
		if(Debug>1) fprintf(DebugStream,"\n");
	}

	if(Debug>1) {
		fprintf(DebugStream,"%d bytes of pseudo-random data obtained.\n",
		 totbytes);
	}

	return NULL;
}

/*--- function DoGenerateKeys -----------------------------------
 *
 *  Generate a keypair for the user.
 *
 *  Entry: Randomstruct is initialized.
 *         Username     is set
 *         PubStream and PrivStream are the streams
 *                      to which the keys should be written.
 *
 *  Exit:  The keypair has been generated and written out.
 */
char *
DoGenerateKeys()
{
	char *err_msg = NULL;
  /* der and derlen are not used.
	unsigned char *der;
	unsigned int derlen;
   */
	int retcode;
	R_RSA_PROTO_KEY proto_key;

	/* Open the output file. */

	PubOutStream = fopen(PubKeyOutFileName,"w");
	if(!PubOutStream) {
		sprintf(ErrMsgTxt,"Can't open public key output file %s.",
		 PubKeyOutFileName);
		return ErrMsgTxt;
	}
	
	/* Set up the desired properties of the key to generate. */
	proto_key.bits = Bits;
   /* Always use Fermat # F4 as public exponent. */
	proto_key.useFermat4 = 1;

	R_memset((POINTER)&PublicKey, 0,sizeof PublicKey);
	R_memset((POINTER)&PrivateKey,0,sizeof PrivateKey);
	retcode = R_GeneratePEMKeys(&PublicKey,&PrivateKey,
	 &proto_key,&RandomStruct);

	if(retcode) {
		err_msg = FormatRSAError(retcode);
	} else {
      /* The key generation worked.  Now for each key component
       * (public and private), translate the key to DER format,
       * encode it in RFC1113 format, and write it out in an
       * appropriately-formated file.
		 *
		 * Start with the public component.
		 */
#if 0
		derlen = PubKeyToDERLen(&PublicKey);
		der = (unsigned char *) malloc(2*derlen);
		if(der) {
#endif
			fprintf(PubOutStream,"%s\n",PUB_KEY_STRING_BEGIN);
			fprintf(PubOutStream,"%s %s\n",USER_FIELD,Username);

			WritePublicKey(&PublicKey,PubOutStream);
      if ((err_msg = WriteSelfSignedCert
           (Username, &PublicKey, &PrivateKey, (unsigned int)ValidityMonths,
            PubOutStream)) != (char *)NULL)
        return (err_msg);

			fprintf(PubOutStream,"%s\n",PUB_KEY_STRING_END);
#if 0
			free(der);

		} else {
			return ("Can't allocate memory.");
		}
#endif
		/* Now encode, encrypt, and write out the private key. */
		DoChangePW(FALSE);
	}
	return err_msg;
}

/*--- function DoChangePW -----------------------------------
 *
 *  Write a private key file, containing the private component
 *  encrypted with a key.
 *
 *  Entry: 	newpwonly		is TRUE if this is a change PW request
 *									to an existing private key.
 *				Randomstruct	is initialized.
 *         	Username    	is set
 *         	PrivStream  	is the stream
 *                     		to which the keys should be written.
 *				PublicKey		contains the public key, if !newPWonly.
 *
 *  Exit:  The keypair has been generated and written out.
 */
char *
DoChangePW(newPWOnly)
BOOL newPWOnly;
{
	char *err_msg = NULL;
	BOOL found=FALSE;
	unsigned char *der, *der_enc_priv, salt[SALT_SIZE];
	unsigned int derlen, iter_count=100, enc_priv_len, der_enc_priv_len;
	size_t nbytes;
	TypListEntry *entry;
	
	if(newPWOnly) {
		err_msg = GetPrivateKey(Username,&PrivKeySource,&PrivateKey);
		if(err_msg) return err_msg;

    /* When changing the password, close the private key files so
         that the output can (over)write to the same file if requested.
     */
    FORLIST (&PrivKeySource.filelist);
      fclose (((TypFile*)dptr)->stream);
      ((TypFile*)dptr)->stream = NULL;
    ENDFORLIST;

    /* Use LoginUser to set up the PublicKey and check if the user
         already has a self-signed cert.
     */
    if ((err_msg = LoginUser (&found)) != (char *)NULL)
      return (err_msg);

    if (found) {
      CertificateStruct certStruct;
      unsigned char *innerDER;
      unsigned int innerDERLen;

      /* There is already a self-signed cert, so announce the user's
           name and cert digest.  Don't check the error return
           on DERToCertificate since we just decoded it.
       */
      DERToCertificate (UserCertDER, &certStruct, &innerDER, &innerDERLen);
      PrintCertNameAndDigest (&certStruct, innerDER, innerDERLen, CertinfoStream);
    }
    else {
      if (PubKeyOutFileName != (char *)NULL) {
        /* Create a self-signed cert and append to public key file.
         */
        if (PubOutStream == NULL) {
          if ((PubOutStream = fopen (PubKeyOutFileName, "a")) == NULL)
            return ("Can't open public key output file");
        }

        fprintf (PubOutStream, "\n");
        fprintf (PubOutStream, "%s %s\n", USER_FIELD, Username);
        
        if ((err_msg = WriteSelfSignedCert
             (Username, &PublicKey, &PrivateKey, (unsigned int)ValidityMonths,
              PubOutStream)) != (char *)NULL)
          return (err_msg);
      }
    }
	}
	
	/* Open the private key output file and write:
	 * -- The header.
	 * -- The list of usernames for this user.
	 * -- The public key.
	 */
	PrivOutStream = fopen(PrivKeyOutFileName,"w");
	if(!PrivOutStream) {
		sprintf(ErrMsgTxt,"Can't open private key output file %s.",
		 PrivKeyOutFileName);
		return ErrMsgTxt;
	}
	
	fprintf(PrivOutStream,"%s\n",PRIV_KEY_STRING_BEGIN);
	for(entry=UserList.firstptr; entry; entry=entry->nextptr) {
		fprintf(PrivOutStream,"User: %s\n",(char *)entry->dataptr);
	}
#if 0 /* Don't write out the public key since we use self-signed certs */
	if(newPWOnly) {
		GetPublicKey(Username,&PrivKeySource,&PublicKey,&found);
	} else {
		found = TRUE;
	}
	if(!found) {
		GetPublicKey(Username,&PubKeySource,&PublicKey,&found);
	}
	if(found) {
		WritePublicKey(&PublicKey,PrivOutStream);
	} else {
		fprintf(DebugStream,"Warning: could not find your public key.\n");
	}
#endif

		/* Now process the private key.
		 */
		nbytes = PrivKeyToDERLen(&PrivateKey)+DES_BLOCK_SIZE;
		der = (unsigned char *) malloc(nbytes);
		if(der) {
			unsigned char password[MAX_PASSWORD_SIZE];
			unsigned int password_len;

			/* DER encode the private key */
			PrivKeyToDER (&PrivateKey, der, &derlen);
			if(Debug>1) {
				fprintf(DebugStream,"DER encoding of private key:\n        ");
				BEMParse(der,DebugStream);
			}

			/* Encrypt the private key.  We must get the
			 * password from the user, and we must calculate a 
			 * pseudo-random salt.
			 */
			password_len = GetPasswordToPrivKey(TRUE,newPWOnly,
			 password,MAX_PASSWORD_SIZE);

			R_RandomUpdate(&RandomStruct,password,password_len);
			R_GenerateBytes(salt,sizeof(salt),&RandomStruct);

			if(pbeWithMDAndDESWithCBC(TRUE,DA_MD5,der,derlen,password,
			 password_len,salt,iter_count,&enc_priv_len)) {
				return "Can't encrypt private key.";
			}

			/* DER-encode the encrypted private key and write it out.
			 */
			der_enc_priv = (unsigned char *) 
			 malloc(EncryptedPrivKeyToDERLen(iter_count,enc_priv_len));
			if(!der_enc_priv) return "Can't allocate memory.";

			if(EncryptedPrivKeyToDER(salt,iter_count,der,enc_priv_len,
			 der_enc_priv,&der_enc_priv_len)) {
				return "Can't DER encode encrypted private key.";
			}

			if(Debug>1) {
				fprintf(DebugStream,"DER encoding of encrypted private key:\n");
				BEMParse(der_enc_priv,DebugStream);
			}

			fprintf(PrivOutStream,"EncryptedPrivateKeyInfo:\n");
	      CodeAndWriteBytes(der_enc_priv,der_enc_priv_len," ",PrivOutStream);

			if(Debug>1) {
				DumpPubKey(&PublicKey);
				DumpPrivKey(&PrivateKey);
			}

			fprintf(PrivOutStream,"%s\n",PRIV_KEY_STRING_END);
			free(der_enc_priv);
			free(der);
		} else {
			return ("Can't allocate memory.");
		}


	return err_msg;
}

/*--- function DoEncipher ------------------------------------------------
 *
 *  Obtain or generate the necessary information (recipient public key,
 *  message key, etc.) to encipher the message, output the message
 *  header, and call the routine that will do the work of enciphering.
 *
 *  Entry:  Global variables contain the result of cracking the
 *            control statement.
 *
 *  Exit:   Returns NULL if encipherment completed OK, else the
 *            address of an error message.
 */
char *
DoEncipher(stream)
FILE *stream;
{
#define MAX_SAVE_BYTES 16
#define IV_SIZE        8
	unsigned char *plaintext;
	char *err_msg=NULL;
	unsigned int totplain;
	int retval;
	int n_valid_recips=0;
	BOOL recode;
	unsigned char *encrypted_content;
	unsigned char *encrypted_signature;
	unsigned char iv[IV_SIZE];
	unsigned int encrypted_content_len, encrypted_signature_len;
	R_RANDOM_STRUCT saved_random_struct;
	unsigned int save_content_len = 0;
	BOOL did_first_encryption = FALSE;
	TypListEntry *entry_ptr;
	TypUser *recip_ptr;
#ifndef RIPEMSIG
  CertFilter certFilter;
  unsigned char *encrypted_key, *this_enc_key;
	unsigned char save_content[MAX_SAVE_BYTES], save_iv[IV_SIZE];
  unsigned int encrypted_key_len;
	char *cptr;
  BOOL ok;
#endif

	err_msg = ReadMessage(InStream,FALSE,AddRecip, FALSE, IncludeHeaders, FALSE,
	 PrependHeaders, &HeaderList, &plaintext, &totplain, &RecipientList);
	if(err_msg) return err_msg;
	
	/* If requested, further seed the random data structure with the
    * plaintext.
    */
   if(UseRndMessage) {
		R_RandomUpdate(&RandomStruct,(unsigned char *)plaintext,
			totplain);
		if(Debug>1) {
			fprintf(DebugStream,
			 "Added %d bytes of message plaintext to random seed.\n",totplain);
		}
	}

	if(Debug>1) {
#define DEBUGCHARS 500
		unsigned int maxbytes=totplain<DEBUGCHARS?totplain:DEBUGCHARS, idx=0;
		unsigned char dch;

		fprintf(DebugStream,"%d bytes read; first %d bytes are:\n",
			totplain,maxbytes);
		while(idx<maxbytes) {
			dch = plaintext[idx++];
			if(isprint((char)dch)) putc((char)dch,DebugStream);
			else fprintf(DebugStream,"\\x%2.2x",dch);
		}
		putc('\n',DebugStream);

		fprintf(DebugStream,"%d Recipients: ",NRecip);
		
		for(entry_ptr = RecipientList.firstptr; entry_ptr;
		 entry_ptr = entry_ptr->nextptr) {
			recip_ptr = (TypUser *)entry_ptr->dataptr;
			fprintf(DebugStream,"%s,",recip_ptr->emailaddr);
		}
		putc('\n',DebugStream);
	}
	err_msg = GetPrivateKey(Username,&PrivKeySource,&PrivateKey);
	if(err_msg) return err_msg;
	if(Debug>2) {
		DumpPrivKey(&PrivateKey);
	}

  if ((err_msg = LoginUser ((int *)NULL)) != (char *)NULL)
    return (err_msg);
  
	R_memcpy((POINTER)&saved_random_struct,(POINTER)&RandomStruct,sizeof(RandomStruct));

	encrypted_signature = (unsigned char *) 
	 malloc(MAX_PEM_ENCRYPTED_SIGNATURE_LEN);
	if(!encrypted_signature) return("Can't allocate memory.");

	switch(EncryptionMode) {
		case PROC_TYPE_ENCRYPTED_ID_ENUM:
#ifdef RIPEMSIG
      return ("RIPEM/SIG cannot prepare encrypted messages. Try mic-only or mic-clear.");
#else
			encrypted_content = (unsigned char *) 
			  malloc(ENCRYPTED_CONTENT_LEN(totplain));
			if(!encrypted_content) return("Can't allocate memory.");
			encrypted_key = (unsigned char *) malloc(MAX_PEM_ENCRYPTED_KEY_LEN);
			if(!encrypted_key) return("Can't allocate memory.");
			
			/* Get the public keys of all the users first.
			 * We do this first because we want to know whether some
			 * of the keys are unavailable before we do a lot of
			 * time-consuming RSA encryption.
			 */
			 
      certFilter.checkCert = NULL;
      certFilter.issuerPublicKey = &PublicKey;
      /* Try getting the public keys from certificates. */
			cptr = GetPublicKeyList(&RecipientList,&PubKeySource, &certFilter);
			if(cptr) return cptr;

      /* Now try getting public keys from non-certificates, finger, etc. */
			cptr = GetPublicKeyList(&RecipientList,&PubKeySource,(CertFilter *)NULL);
			if(cptr) return cptr;

			ok = CheckKeyList(&RecipientList);
			if(!ok) {
				return "Can't find some public keys; RIPEM aborting.";
			}

			/* Loop through the list of recipients, calling the RSAREF
			 * encryption routine for this message for each recipient.
			 * The encrypted message is the same for each recipient, but
			 * the encrypted key and signature do vary, so we must save
			 * them for each recipient.
			 */
			for(entry_ptr = RecipientList.firstptr; entry_ptr;
				entry_ptr = entry_ptr->nextptr) {
				recip_ptr = (TypUser *)entry_ptr->dataptr;

				/* Skip users for whom we can't find a public key. */
				if(!recip_ptr->gotpubkey) continue;
				n_valid_recips++;
#if 0                           
				err_msg = GetPublicKey(recip_ptr->emailaddr,
				 &PubKeySource, &PublicKey);
				if(err_msg) return err_msg;
#endif
				R_memcpy((POINTER)&RandomStruct,(POINTER)&saved_random_struct,
				 sizeof(RandomStruct));
				if(Debug>1) ReportCPUTime("Before R_SealPEMBlock");
				retval = R_SealPEMBlock(encrypted_content,&encrypted_content_len,
				 encrypted_key,&encrypted_key_len,
				 encrypted_signature,&encrypted_signature_len,
               iv,plaintext,totplain,
                 DA_MD5 | (encryptionAlgorithm << 8),
                   &(recip_ptr->pubkey),&PrivateKey,
               &RandomStruct,MODE_STANDARD);
				if(Debug>1) ReportCPUTime("After  R_SealPEMBlock");

				if(retval) {
					err_msg = FormatRSAError(retval);
					return err_msg;
				}
				if(Debug>1) {
					char hex_digest[36], line[80];

					fprintf(DebugStream,"Encrypted for recip. EncContentLen=%u, keyLen=%u, sigLen=%u, user=%s\n",
					 encrypted_content_len,encrypted_key_len,encrypted_signature_len,
					 recip_ptr->emailaddr);
					MakeHexDigest(encrypted_content,encrypted_content_len,
					 hex_digest);
					fprintf(DebugStream,
					 " MD5 of encrypted content = %s\n",hex_digest);
					MakeHexDigest(encrypted_key,encrypted_key_len,hex_digest);
					fprintf(DebugStream,
					   " MD5 of Encrypted Key     = %s\n",hex_digest);
					MakeHexDigest(encrypted_signature,
					  encrypted_signature_len,hex_digest);
					fprintf(DebugStream," MD5 of encrypted signat. = %s\n",hex_digest);
					fprintf(DebugStream,"  Encrypted, encoded MIC =\n");
					WriteCoded(encrypted_signature,encrypted_signature_len,"   ",DebugStream);
					BinToHex(iv,8,line);
					fprintf(DebugStream," Initializing vector      = %s DigAlg=%d\n",
					 line,DA_MD5);
				}
				/* The first time through the loop, save the first few bytes
				 * of the encrypted message.  This will be used as a check
				 * to make sure it comes out the same each time.
				 */
				if(!did_first_encryption) {
					save_content_len = encrypted_content_len < MAX_SAVE_BYTES ?
					 encrypted_content_len : MAX_SAVE_BYTES;
					R_memcpy(save_content,encrypted_content,save_content_len);
					R_memcpy(save_iv,iv,IV_SIZE);
					did_first_encryption = TRUE;
				} else {

					/* Do a spot-check to make sure that the encrypted content
					 * really is the same each time through the loop.  This
					 * ensures that we really can throw away the encrypted
					 * content for all but one of the recipients.
					 */
					if(R_memcmp(save_content,encrypted_content,save_content_len)) {
						return("Encrypted content does not match between recipients.");
					}
					if(R_memcmp(iv,save_iv,IV_SIZE)) {
						return("Initialization vector does not match between recipients.");
					}
				}

				/* Save the encrypted key for this recipient. */
				this_enc_key = (unsigned char *)malloc(encrypted_key_len);
				if(!this_enc_key) return "Can't allocate memory.";
				R_memcpy(this_enc_key,encrypted_key,encrypted_key_len);
	    recip_ptr->enckey = this_enc_key;
				recip_ptr->enckeylen = encrypted_key_len;
			}
			if(!n_valid_recips) return "No valid recipients.";
			
			/* Write out the original message header if requested. */
			if(PrependHeaders) {
				WritePrependedHeaders(HeaderList,OutStream);
			}
			
      /* Write recipient distinguished names to cert info stream.
       */
      fputs ("Recipient status:\n", CertinfoStream);
			for (entry_ptr = RecipientList.firstptr; entry_ptr;
           entry_ptr = entry_ptr->nextptr) {
				recip_ptr = (TypUser *)entry_ptr->dataptr;

				/* Skip users for whom we can't find a public key. */
				if (!recip_ptr->gotpubkey)
          continue;

        /* Write the recipient's name to the output. */
        if (recip_ptr->validationStatus == CERT_UNVALIDATED)
          fprintf (CertinfoStream, "%s (on file but not validated)\n", recip_ptr->emailaddr);
        else {
          fprintf (CertinfoStream, "%s: ",
                   GetCertStatusString (recip_ptr->validationStatus));
          WritePrintableName (CertinfoStream, &recip_ptr->userDN);
          fprintf (CertinfoStream, "\n");
        }
			}
      /* Put a blank line after the recipients */
      fputs ("\n", CertinfoStream);      			

			err_msg = WriteHeader(OutStream,
			 iv,RecipientList,encrypted_signature,encrypted_signature_len);

			if(err_msg) return err_msg;

			/* Write the encrypted message. */

			WriteCoded(encrypted_content,encrypted_content_len,"",OutStream);
			fputs(HEADER_STRING_END,OutStream);
			WriteEOL(OutStream);

			free(encrypted_content);
			free(encrypted_key);
			break;
#endif /* end RIPEMSIG */

		case PROC_TYPE_MIC_ONLY_ID_ENUM:
			recode = TRUE;
			encrypted_content = (unsigned char *) 
			  malloc(ENCRYPTED_CONTENT_LEN(totplain));
			if(!encrypted_content) return("Can't allocate memory.");
			goto proc_mic;

		case PROC_TYPE_MIC_CLEAR_ID_ENUM:
			recode = FALSE;
			encrypted_content = plaintext;
		 proc_mic:

			/* "Sign" the message by taking a message digest of the
			 * message and encrypting it with the sender's private key.
			 * We pay no attention to who the recipients are.
			 * Note that R_Sign ignores the first parameter if recode=0.
			 */
			retval = R_SignPEMBlock(encrypted_content,&encrypted_content_len,
			 encrypted_signature,&encrypted_signature_len,
			 plaintext,totplain,recode,DA_MD5,&PrivateKey,MODE_STANDARD);

			if(retval) {
				err_msg = FormatRSAError(retval);
				return err_msg;
			}
			
			/* Write out the original message header if requested. */
			if(PrependHeaders) {
				WritePrependedHeaders(HeaderList,OutStream);
			}
			
			err_msg = WriteHeader(OutStream,
			 iv,RecipientList,encrypted_signature,encrypted_signature_len);

			if(err_msg) return err_msg;

			/* Write the message.  RFC1113 encode it for MIC-ONLY */

			if(EncryptionMode == PROC_TYPE_MIC_ONLY_ID_ENUM) {
				WriteCoded(encrypted_content,encrypted_content_len,"",OutStream);
			} else {
				WriteMessage(plaintext,totplain,TRUE,OutStream);
			}
			fputs(HEADER_STRING_END,OutStream);
			WriteEOL(OutStream);

			if(EncryptionMode == PROC_TYPE_MIC_ONLY_ID_ENUM) {
				free(encrypted_content);
			}

			break;

		default:
			break;
	}

	ClearBuffer(&saved_random_struct,sizeof saved_random_struct);
	free(encrypted_signature);
	return err_msg;
}

/*--- function WritePrependedHeaders -----------------------------
 *
 *  Write out the original mail headers.
 *
 *  Entry:	headerList	is a list of lines of headers.
 *				outStream	is a stream to which to write the headers.
 */
void
WritePrependedHeaders(headerList,outStream)
TypList headerList;
FILE *outStream;
{
		TypListEntry *entry_ptr;
		long int nlines=0;
		
		for(entry_ptr=headerList.firstptr; entry_ptr; 
 		 entry_ptr = entry_ptr->nextptr) {
			fputs((char *)entry_ptr->dataptr,outStream);
			WriteEOL(outStream);
			nlines++;
		}
		if(nlines) WriteEOL(outStream);
}

/*--- function WriteHeader ---------------------------------------
 *
 *  Write the Privacy Enhanced Mail header.
 *
 *  Entry:   stream    is the I/O stream to write to.
 *           iv        is the init vector that was used to encrypt.
 *           recipList is the list of recipients.
 *           encryptedSignature      is the encrypted & encoded signature.
 *           encryptedSignatureLen is the number of bytes in above.
 *
 *  Exit:    We have written the header out to the stream, followed
 *             by a blank line.
 *           Returns NULL if no error, else error message.
 */
char *
WriteHeader(stream,iv,recipList,
encryptedSignature,encryptedSignatureLen)
FILE *stream;
unsigned char iv[];
TypList recipList;
unsigned char *encryptedSignature;
unsigned int encryptedSignatureLen;
{
	char *err_msg = NULL;
	char iv_hex[2*IV_SIZE+1];
	TypListEntry *entry_ptr;
	TypUser *recip_ptr;

	/* Put out header indicating encapsulated message follows. */
   fputs(HEADER_STRING_BEGIN,stream);  WriteEOL(stream);

	/* Put out field indicating processing type. */
	fputs(PROC_TYPE_FIELD,stream);
	fputs(" ",stream);
	fputs(PROC_TYPE_RIPEM_ID,stream);
	fputs(SPEC_SEP,stream);

	fputs(IDNames[EncryptionMode],stream);
	WriteEOL(stream);

	/* Put out content domain. */
	fputs (CONTENT_DOMAIN_FIELD, stream);
  fputs (" RFC822", stream);
	WriteEOL (stream);
  
	/* If encrypting, put out DEK-Info field. */
	if(EncryptionMode == PROC_TYPE_ENCRYPTED_ID_ENUM) {
		fputs(DEK_FIELD,stream);
		fputs(" ",stream);
      if (encryptionAlgorithm == EA_DES_EDE2_CBC)
			fputs(DEK_ALG_TDES_CBC_ID,stream);
		else
			fputs(DEK_ALG_DES_CBC_ID,stream);
		fputs(SPEC_SEP,stream);
		BinToHex(iv,IV_SIZE,iv_hex);
		fputs(iv_hex,stream);
		WriteEOL(stream);
   }

	/* Write Originator's name. */

	fputs(SENDER_FIELD,stream);
	fputs(" ",stream);
	fputs(Username,stream);
	WriteEOL(stream);

#if 0
	/* Find the originator's public key by looking in the private
	 * key file.  If we find it, we write out the
    * Originator-Key-Asymmetric: line.  Otherwise, it's not
	 * a fatal error, so we just don't write out the line.
	 */

	{
		unsigned char *key_bytes;
		unsigned int num_bytes;
		BOOL found;

		FORLIST(&(PrivKeySource.filelist));
		err_msg = GetKeyBytesFromFile(Username,
		(TypFile *)dptr,PUBLIC_KEY_FIELD,
		 &found, &key_bytes, &num_bytes);
		if(found) {
			fputs(SENDER_PUB_KEY_FIELD,stream);
			WriteEOL(stream);
			CodeAndWriteBytes(key_bytes,num_bytes," ",stream);
			free(key_bytes);
			break;
		}
		ENDFORLIST;
	}
#endif
  
  /* Write originator's self-signed certificate.
   */
  fputs (ORIGINATOR_CERT_FIELD, stream);
	WriteEOL(stream);
  CodeAndWriteBytes (UserCertDER, UserCertDERLen, " ", stream);  

	/* Write out the digital signature. */

	fputs(MIC_INFO_FIELD,stream);
	fputs(" ",stream);
	fputs(MIC_MD5_ID,stream);
	fputs(SPEC_SEP,stream);
	fputs(ENCRYPTION_ALG_RSA_ID,stream);
	fputs(SPEC_SEP,stream);
	WriteEOL(stream);

	WriteCoded(encryptedSignature,encryptedSignatureLen," ",stream);

	if(EncryptionMode == PROC_TYPE_ENCRYPTED_ID_ENUM) {
		/* For each recipient for whom we have a public key, 
		 * write out the recipient's name,
		 * and the encrypted message key.
		 */

		for(entry_ptr = recipList.firstptr; entry_ptr;
			entry_ptr = entry_ptr->nextptr) {
			recip_ptr = (TypUser *)entry_ptr->dataptr;
			
			if(!recip_ptr->gotpubkey) continue;
			/* Write user name (email address) */
			fputs(RECIPIENT_FIELD,stream);
			fputs(" ",stream);
			fputs(recip_ptr->emailaddr,stream);
			WriteEOL(stream);
      {
        unsigned char *der;
        unsigned int derLen;

        /* Write the recipient's public key */
        fputs (RECIPIENT_KEY_FIELD, stream);
        WriteEOL (stream);
        derLen = PubKeyToDERLen (&recip_ptr->pubkey);
        der = (unsigned char *)malloc (derLen + 1);
        PubKeyToDER (&recip_ptr->pubkey, der, &derLen);
        CodeAndWriteBytes (der, derLen, " ", stream);
        free (der);
      }

			/* Write encrypted message key. */
			fputs(MESSAGE_KEY_FIELD,stream);
			fputs(" ",stream);
			fputs(ENCRYPTION_ALG_RSA_ID,stream);
			fputs(SPEC_SEP,stream);
			WriteEOL(stream);

			WriteCoded(recip_ptr->enckey,recip_ptr->enckeylen," ",stream);

		}
	}


	/* Write blank line that separates headers from text. */
	WriteEOL(stream);

	return err_msg;
}

/*--- function DoDecipher --------------------------------------------
 *
 */
char *
DoDecipher(inStream,outStream)
FILE *inStream;
FILE *outStream;
{
	char *err_msg;
	TypMsgInfo msg_info;
	int retval;
	unsigned char *cip_text, *plain_text;
	unsigned int cip_len, plain_len;
	R_RSA_PUBLIC_KEY *sender_key_ptr;
  CertificateStruct senderCertStruct;
  int isSelfSigned;
  unsigned char *innerDER;
  unsigned int innerDERLen;
  TypUser user;

  err_msg = GetPrivateKey (Username, &PrivKeySource, &PrivateKey);
  if (err_msg)
    return err_msg;
  if (Debug > 2)
    DumpPrivKey (&PrivateKey);

  if ((err_msg = LoginUser ((int *)NULL)) != (char *)NULL)
    return (err_msg);
  
	err_msg = CrackHeader(inStream,PrependHeaders,&HeaderList,
	 &UserList, &PublicKey, &msg_info);
	if(err_msg) return err_msg;
	if(!msg_info.msg_key && msg_info.proc_type==PROC_TYPE_ENCRYPTED_ID_ENUM) {
		err_msg = "You are not listed as a recipient in this message.";
		return err_msg;
	}
	if(Debug>1) {
		fprintf(DebugStream,"From input encapsulated message header:\n");
		fprintf(DebugStream,"  Proc-Type = %s",IDNames[msg_info.proc_type]);
		if(msg_info.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
			char ivhex[20];
			char hex_digest[36];

			BinToHex(msg_info.iv,8,ivhex);
			fprintf(DebugStream,"  DES iv = %s",ivhex);

			MakeHexDigest(msg_info.msg_key,msg_info.msg_key_len,hex_digest);
			fprintf(DebugStream," Digest of Encrypted Key = %s\n",hex_digest);
		}
		fprintf(DebugStream,"\n");
		if(msg_info.orig_name) {
			fprintf(DebugStream,"  Originator-Name = %s\n",
			 msg_info.orig_name);
		}
		fprintf(DebugStream,"  %s Originator's public key in header.\n",
		 msg_info.got_orig_pub_key ? "Got" : "Didn't get");
		fprintf(DebugStream,"  %d bytes in encoded & encrypted MIC:\n",msg_info.mic_len);
		fprintf(DebugStream,"   %s\n",msg_info.mic);
		if(msg_info.msg_key) {
			fprintf(DebugStream,"  %d bytes in encoded & encrypted message key:\n",
			 msg_info.msg_key_len);
			fprintf(DebugStream,"   %s\n",msg_info.msg_key);
		}

	}

  if (msg_info.certs.firstptr != (TypListEntry *)NULL) {
    /* There is an Originator-Certificate, so use it.
     */
    
    /* Decode originator cert. */
    if (DERToCertificate
        ((unsigned char *)msg_info.certs.firstptr->dataptr, &senderCertStruct,
         &innerDER, &innerDERLen) < 0)
      return ("Cannot decode originator certificate");

    user.userDN = senderCertStruct.subject;
    if ((err_msg = SelectKeyBySubject
         (&user, &PubKeySource, &UserDN, &PublicKey)) != (char *)NULL)
      return (err_msg);

    if (user.gotpubkey)
      sender_key_ptr = &user.pubkey;
    else {
      CheckSelfSignedCert
        (&isSelfSigned, &senderCertStruct, innerDER, innerDERLen);

      if (!isSelfSigned)
        return ("The sender has not been validated. Have them send a self-signed certificate.");
      else {
        if (GotValidityMonths && PubKeyOutFileName != (char *)NULL) {
          /* The user specified the validity months, so validate
               the sender's certificate.
           */
          if (PubOutStream == NULL) {
            if ((PubOutStream = fopen (PubKeyOutFileName, "a")) == NULL)
              return ("Can't open public key output file");
          }

          if ((err_msg = ValidateAndWriteCert
               (&senderCertStruct, &PrivateKey, &UserDN,
                (unsigned int)ValidityMonths, PubOutStream)) != (char *)NULL)
            return (err_msg);
          fflush (PubOutStream);

          /* We just validated the user, so proceed to decipher. */
          sender_key_ptr = &senderCertStruct.publicKey;
          user.validationStatus = CERT_VALID;
        }
        else {
          /* We are not supposed to validate the sender's public key,
               so just output a message giving the sender's name and
               self-signed digest.
           */
             
          fprintf (CertinfoStream, "The following sender has not been validated:\n");
          PrintCertNameAndDigest (&senderCertStruct, innerDER, innerDERLen, CertinfoStream);
          fprintf (CertinfoStream, "Contact sender to verify certificate digest.\n");
          return
        ("To validate sender, receive message again in validation mode (-v).");
        }
      }
    }

    if (msg_info.mic_len == 0 &&
        (msg_info.proc_type == PROC_TYPE_MIC_ONLY_ID_ENUM ||
         msg_info.proc_type == PROC_TYPE_MIC_CLEAR_ID_ENUM)) {
      /* There is no signature, so this is a certs only message.
       */
      fputs ("-------------------------\n", CertinfoStream);
      fputs ("Received certificates-only message from:\n", CertinfoStream);
      WritePrintableName (CertinfoStream, &user.userDN);
      fputs ("\n-------------------------\n", CertinfoStream);

      return ((char *)NULL);
    }
  } else {
    /* Process non-certificate based message */
    
	if(!msg_info.orig_name) {
		return "Can't find Originator's name in message.";
	}

	/* Obtain the sender's public key. */

  user.emailaddr = msg_info.orig_name;
	err_msg = GetPublicKey(&user,&PubKeySource, (CertFilter *)NULL);

	if(err_msg || !user.gotpubkey) {
		if(msg_info.got_orig_pub_key) {
			if(!err_msg) {
				fprintf(stderr,"Warning: public key of \"%s\" not on file.\n",
					msg_info.orig_name);
			} else {
				fprintf(stderr,"Warning: problem encountered with public key of \"%s\":\n",msg_info.orig_name);
				fprintf(stderr,"  %s\n",err_msg);
			}
			fprintf(stderr,"Using key supplied in message.\n");
			sender_key_ptr = &msg_info.orig_pub_key;
			used_pub_key_in_message = 1;
			
#if 0
			/* Record this key from the message header in an output file,
			 * if possible.
			 */
			 
			if(!PubOutStream && PubKeyOutFileName) {
				PubOutStream = fopen(PubKeyOutFileName,"a");
			}
			if(PubOutStream) {
				fprintf(PubOutStream,"\n");
				fprintf(PubOutStream,"%s %s\n",USER_FIELD,msg_info.orig_name);
				WritePublicKey(sender_key_ptr,PubOutStream);
				if(Debug>1) {
					fprintf(DebugStream,"Writing pubkey of %s to file %s\n",
						msg_info.orig_name,PubKeyOutFileName);
				}
			}
#endif
		} else {
			return err_msg;
		}
	} else {
		sender_key_ptr = &user.pubkey;
		/* Check to make sure that the sender's public key in the
		 * message header matches the sender's recorded public key.
		 */
		if(msg_info.got_orig_pub_key) {
			if(R_memcmp((POINTER) &msg_info.orig_pub_key,
			 (POINTER) sender_key_ptr,(unsigned int) sizeof PublicKey)) {
				fprintf(stderr,"Warning: %s's public key in message does not match retrieved value.\n",msg_info.orig_name);
			}
		}
	}
  }

	switch(msg_info.proc_type) {
		case PROC_TYPE_ENCRYPTED_ID_ENUM:
#ifdef RIPEMSIG
      return ("RIPEM/SIG cannot process ENCRYPTED messages. Try MIC-ONLY or MIC-CLEAR.");
#else
#if 0 /*  We already got the private key above. */
			err_msg = GetPrivateKey(Username,&PrivKeySource,&PrivateKey);
			if(err_msg) return err_msg;
			if (Debug>2){
					DumpPrivKey(&PrivateKey);
			}
#endif

			if(Debug>1) {
				fprintf(DebugStream,"Before call to ReadMessage, Username=%s\n",Username);
			}
			err_msg = ReadMessage(InStream,FALSE,FALSE,TRUE,TRUE,TRUE,
			 FALSE,(TypList *)NULL,&cip_text,&cip_len,&RecipientList);
			if(err_msg) return err_msg;

			plain_text = (unsigned char *)malloc(DECRYPTED_CONTENT_LEN(cip_len));
			if(!plain_text) {
				return("Can't allocate memory.");
			}
			if(Debug>1) {
				char hex_digest[36], line[120];

				fprintf(DebugStream,"Decrypting.    Enc. ContentLen=%u, keyLen=%u, sigLen=%u, user=%s\n",
				 cip_len,msg_info.msg_key_len,msg_info.mic_len,
				 Username);
				MakeHexDigest(cip_text,cip_len,hex_digest);
				fprintf(DebugStream," MD5 of encrypted content = %s\n",hex_digest);
				MakeHexDigest(msg_info.msg_key,
				  msg_info.msg_key_len,hex_digest);
				fprintf(DebugStream," MD5 of Encrypted Key     = %s\n",hex_digest);
				MakeHexDigest(msg_info.mic,msg_info.mic_len,hex_digest);
				fprintf(DebugStream," MD5 of encrypted signat. = %s\n",hex_digest);
				fprintf(DebugStream,"  Encrypted, encoded MIC =\n");
				WriteCoded(msg_info.mic,msg_info.mic_len,"   ",DebugStream);
				BinToHex(msg_info.iv,8,line);
				fprintf(DebugStream," Initializing vector      = %s DigAlg=%d\n",
				 line,msg_info.da);
			}

			retval = R_OpenPEMBlock(plain_text,&plain_len,cip_text,cip_len,
			 msg_info.msg_key, msg_info.msg_key_len,
			 msg_info.mic,     msg_info.mic_len,    msg_info.iv,
           msg_info.da | (msg_info.ea << 8), &PrivateKey, sender_key_ptr,MODE_STANDARD);
			if(retval) {
				err_msg = FormatRSAError(retval);
				return err_msg;
			}

			break;
#endif /* end RIPEMSIG */

		case PROC_TYPE_MIC_ONLY_ID_ENUM:
			err_msg = ReadMessage(InStream,FALSE,FALSE,TRUE,TRUE,TRUE,
			 FALSE,(TypList *)NULL,&cip_text,&cip_len,&RecipientList);
			if(err_msg) return err_msg;

			plain_text = (unsigned char *)
			   malloc(DECRYPTED_CONTENT_LEN(cip_len+4));
			if(!plain_text) {
				return("Can't allocate memory for plaintext.");
			}
			retval = R_VerifyPEMSignature(plain_text,&plain_len,
			 cip_text,cip_len,msg_info.mic, msg_info.mic_len,TRUE,
			 msg_info.da, sender_key_ptr,MODE_STANDARD);
			if(retval) {
				err_msg = FormatRSAError(retval);
				return err_msg;
			}

			break;

		case PROC_TYPE_MIC_CLEAR_ID_ENUM:
			err_msg = ReadMessage(InStream,TRUE,FALSE,FALSE,TRUE,TRUE,
			 FALSE,(TypList *)NULL,&cip_text,&cip_len,&RecipientList);
			if(err_msg) return err_msg;

			plain_text = cip_text;
			retval = R_VerifyPEMSignature(plain_text,&plain_len,
			 cip_text,cip_len,msg_info.mic, msg_info.mic_len,FALSE,
			 msg_info.da, sender_key_ptr,MODE_STANDARD);
			if(retval) {
				err_msg = FormatRSAError(retval);
				return err_msg;
			}
			break;

		default:
			return ("Invalid message proc type");
	}
	
	/* Write out the original message header if requested. */
	if(PrependHeaders) {
		WritePrependedHeaders(HeaderList,outStream);
	}

	WriteMessage(plain_text,plain_len,FALSE,outStream);

  /* Write out the sender information.
   */
  fputs ("-------------------------\n", CertinfoStream);
  if (user.validationStatus == CERT_UNVALIDATED) {
    fprintf (CertinfoStream, "Sender username: %s\n", user.emailaddr);
    fprintf (CertinfoStream, "Signature status: key found but not validated.\n");
  }
  else {
    fprintf (CertinfoStream, "Sender name: ");
    WritePrintableName (CertinfoStream, &user.userDN);
    fprintf (CertinfoStream, "\n");

    fprintf
      (CertinfoStream, "Signature status: %s.\n",
       GetCertStatusString (user.validationStatus));
  }
  fputs ("-------------------------\n", CertinfoStream);
  
	return err_msg;
}

/*--- function FormatRSAError -----------------------------------------
 *
 */
char *
FormatRSAError(errorCode)
int errorCode;
{
	char *err_msg;

	switch(errorCode) {
      case RE_CONTENT_ENCODING:
	err_msg = "(Encrypted) content has RFC 1113 encoding error";
	break;
      case RE_DIGEST_ALGORITHM:
	err_msg = "Message-digest algorithm is invalid";
		  break;
      case RE_KEY:
	err_msg = "Recovered DES key cannot decrypt encrypted content or encrypt signature";
	break;
      case RE_KEY_ENCODING:
	err_msg = "Encrypted key has RFC 1113 encoding error";
	break;
      case RE_MODULUS_LEN:
	err_msg = "Modulus length is invalid";
	break;
		case RE_NEED_RANDOM:
	err_msg = "Random structure is not seeded";
	break;
      case RE_PRIVATE_KEY:
	err_msg = "Private key cannot encrypt message digest, or cannot decrypt encrypted key";
	break;
      case RE_PUBLIC_KEY:
	err_msg = "Public key cannot encrypt DES key, or cannot decrypt signature";
	break;
      case RE_SIGNATURE:
	err_msg = "Signature on content or block is incorrect";
	break;
      case RE_SIGNATURE_ENCODING:
	err_msg = "(Encrypted) signature has RFC 1113 encoding error";
	break;
	default:
		  err_msg = "Unknown error returned from RSAREF routines";
		  break;
	}
	return err_msg;
}

/* This uses the global variables for the user.
   The PrivateKey has already been set.  This sets the PublicKey from
     the private key and finds the user's self-signed certificate, setting
     UserDN and UserCertDER.
   If found is (int *)NULL and the self-signed cert is not found, this
     returns an error.
   If found is not (int *)NULL, this sets it to whether the self-signed
     cert is found.  (If it is not found, this does not return an error.)
     Whether it is found or not, PublicKey is still set from PrivateKey.
     This option is used when changing a password to see if there is
     already a self-signed cert.
 */
static char *LoginUser (found)
int *found;
{
  CertFilter certFilter;
  TypUser user;
  char *errMessage;
  
  /* Construct the public key from the private key.
   */
  PublicKey.bits = PrivateKey.bits;
  R_memcpy (PublicKey.modulus, PrivateKey.modulus, sizeof (PublicKey.modulus));
  R_memcpy
    (PublicKey.exponent, PrivateKey.publicExponent,
     sizeof (PublicKey.modulus));

  /* Set up a certFilter using LoginCheckCert and call GetPublicKey.
     As an effect, LoginCheckCert will be called to set the
       UserDN and UserCertDER.
   */
  certFilter.checkCert = LoginCheckCert;
  certFilter.issuerPublicKey = &PublicKey;
  user.emailaddr = Username;
  if ((errMessage = GetPublicKey (&user, &PubKeySource, &certFilter))
      != (char *)NULL)
    return (errMessage);

  if (found == (int *)NULL) {
    if (!user.gotpubkey)
      return ("Can't find your self-signed certificate. Change password (-c) to create one.");
  }
  else
    *found = user.gotpubkey;

  return ((char *)NULL);
}

static char *LoginCheckCert
  (certFilter, certOK, certDER, certDERLen, certStruct)
CertFilter *certFilter;
int *certOK;
unsigned char *certDER;
unsigned int certDERLen;
CertificateStruct *certStruct;
{
UNUSED_ARG (certFilter)

  /* Accept this cert if the issuer name == subject name and the
       public key is the user's public key.
   */
  *certOK =
    ((R_memcmp ((POINTER)&certStruct->issuer, (POINTER)&certStruct->subject,
                sizeof (certStruct->issuer)) == 0) &&
     (R_memcmp ((POINTER)&certStruct->publicKey, (POINTER)&PublicKey,
                sizeof (PublicKey)) == 0));

  /* Save the distingushed name and self-signed cert DER.
   */
  if (*certOK) {
    UserDN = certStruct->subject;

    /* malloc and copy the cert DER.  Allocate an extra space as required
         by CodeAndWriteBytes.
     */
    if ((UserCertDER = (unsigned char *)malloc (certDERLen + 1)) ==
        (unsigned char *)NULL)
      return ("Cannot allocate memory for user self-signed cert");

    R_memcpy (UserCertDER, certDER, certDERLen);
    UserCertDERLen = certDERLen;
  }

  return ((char *)NULL);
}

/* Add the public and private key files in the homedir to the front
     of the lists.
   If the private key file is not in the homedir try to create one and if
     successful set newPrivateKeyFile.  This way, the calling routine
     can copy the private key in from elsewhere.
   If HomeDir is NULL, this does nothing.
 */
static char *InitHomeDir ()
{
  FILE *fp = (FILE *)NULL;
	TypFile *typFile;
  char *path = (char *)NULL, *errMessage = (char *)NULL;

  if (!HomeDir)
    return ((char *)NULL);

  /* Try to make sure there is the correct separator between the
       directory and the file name.  E.g. on UNIX, ensure an ending /
     If we don't recognize the machine type, then just hope the user
       already put the right separator.
     Assume only one of UNIX, MSDOS, MACTC, etc. are set.
   */
  if (*HomeDir != '\0') {
#ifdef UNIX
    if (HomeDir[strlen (HomeDir) - 1] != '/')
      strcatrealloc (&HomeDir, "/");
#endif
  
#ifdef MSDOS
    if (HomeDir[strlen (HomeDir) - 1] != '\\' &&
        HomeDir[strlen (HomeDir) - 1] != ':')
      strcatrealloc (&HomeDir, "\\");  
#endif

#ifdef MACTC
    if (HomeDir[strlen (HomeDir) - 1] != ':')
      strcatrealloc (&HomeDir, ":");  
#endif
    
    if (!HomeDir)
      /* Error in reallocating the string */
      return ("Can't allocate memory");
  }

  do {
    if ((path = malloc (strlen (HomeDir) + 9)) == (char *)NULL) {
      errMessage = ("Can't allocate memory");
      break;
    }

    /* Check for the existence of the privkey file by trying to open it
         for read.
       If it can't be opened for read, open it for write to make sure
         we can create it.
     */
    strcpy (path, HomeDir);
    strcat (path, "privkey");
    if ((fp = fopen (path, "r")) == (FILE *)NULL) {
      /* Cannot open for read, try to open for write */
      if ((fp = fopen (path, "w")) == (FILE *)NULL) {
        sprintf (ErrMsgTxt,
                 "Can't write to directory %s. (Does it exist?)", HomeDir);
        errMessage = ErrMsgTxt;
        break;
      }

      fclose (fp);
      fp = (FILE *)NULL;
    }
    else {
      /* Successfully opened file for read.  Close it and prepend to the list.
       */
      fclose (fp);
      fp = (FILE *)NULL;

      typFile = (TypFile *)malloc (sizeof (TypFile));
      typFile->stream = NULL;
      strcpyalloc (&typFile->filename, path);
      PrependToList (typFile, sizeof (TypFile), &PrivKeySource.filelist);

      if (Action == ACT_GEN_KEY && !PrivKeyOutFileName)
        /* Private key in home dir already exists and we are going to
             overwrite it in keygen, so give warning */
        fprintf
          (stderr,"WARNING: key generation will replace existing file %s\n",
           path);
    }

    if (!PrivKeyOutFileName)
      /* User did not specify -S file, so set to file in home dir */
      strcpyalloc (&PrivKeyOutFileName, path);

    /* Try to open the public key file for read.  If successful, add to list.
     */
    strcpy (path, HomeDir);
    strcat (path, "pubkeys");
    if ((fp = fopen (path, "r")) != (FILE *)NULL) {
      fclose (fp);
      fp = (FILE *)NULL;

      typFile = (TypFile *)malloc (sizeof (TypFile));
      typFile->stream = NULL;
      strcpyalloc (&typFile->filename, path);
      PrependToList (typFile, sizeof (TypFile), &PubKeySource.filelist);

      if (Action == ACT_GEN_KEY && !PubKeyOutFileName)
        /* Public key in home dir already exists and we are going to
             overwrite it in keygen, so give warning */
        fprintf
          (stderr, "WARNING: key generation will replace existing file %s\n",
           path);
    }

    if (!PubKeyOutFileName)
      /* User did not specify -P file, so set to file in home dir */
      strcpyalloc (&PubKeyOutFileName, path);

    if (!RandomFileName) {
      /* Random file has not been specified on the command line, so
          try to random input file in home dir for read. If successful, use it.
       */
      strcpy (path, HomeDir);
      strcat (path, "randomin");
      if ((fp = fopen (path, "r")) != (FILE *)NULL) {
        fclose (fp);
        fp = (FILE *)NULL;
        strcpyalloc (&RandomFileName, path);
      }
    }
  } while (0);

  free (path);
  if (fp != (FILE *)NULL)
    fclose (fp);

  return (errMessage);
}
