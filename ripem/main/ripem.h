/*--- ripem.h -------------------------------------------------------*/

#include "list.h"

#define BOOL int
#define TRUE 1
#define FALSE 0

#ifndef MSDOS
#if defined(__MSDOS__) || defined(_MSDOS)
#define MSDOS
#endif
#endif

#ifdef __TURBOC__
#define __STDC__ 1
#endif


#define MAX_PRENCODE_BYTES 48
#define INC_RECIP_ALLOC     16

#define MAX_PASSWORD_SIZE  256

#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE   8
#define SALT_SIZE      8

#define SERVER_PORT 1611

#define TRUE 1
#define FALSE 0

#ifndef MACTC	/* rwo */

#define PUBLIC_KEY_FILE_ENV   	"RIPEM_PUBLIC_KEY_FILE"
#define PRIVATE_KEY_FILE_ENV    	"RIPEM_PRIVATE_KEY_FILE"
#define USER_NAME_ENV           	"RIPEM_USER_NAME"
#define KEY_TO_PRIVATE_KEY_ENV  	"RIPEM_KEY_TO_PRIVATE_KEY"
#define RANDOM_FILE_ENV				"RIPEM_RANDOM_FILE"
#define SERVER_NAME_ENV				"RIPEM_SERVER_NAME"
#define RIPEM_ARGS_ENV 				"RIPEM_ARGS"
#define HOME_DIR_ENV 				"RIPEM_HOME_DIR"

#else

/* The idea is to have these correspond to "STR " resources */

#define PUBLIC_KEY_FILE_ENV   		0x5231
#define PRIVATE_KEY_FILE_ENV    	0x5232
#define USER_NAME_ENV           	0x5233
#define KEY_TO_PRIVATE_KEY_ENV  	0x5234
#define RANDOM_FILE_ENV				0x5235
#define SERVER_NAME_ENV				0x5236
#define RIPEM_ARGS_ENV 				0x5237
#define HOME_DIR_ENV 				0x5238

#endif

#define SERVER_PORT					1611
#define USER_NAME_DEFAULT    "me"

#ifdef MSDOS
#define PRIVATE_KEY_FILE_DEFAULT "\\RIPEMPRV"
#define PUBLIC_KEY_FILE_DEFAULT  "\\RIPEMPUB"
#else
#ifndef MACTC	/* rwo */
#define PRIVATE_KEY_FILE_DEFAULT "~/.ripemprv"
#define PUBLIC_KEY_FILE_DEFAULT 	"/usr/local/etc/rpubkeys"
#else
#define PRIVATE_KEY_FILE_DEFAULT	"ripemprv"
#define PUBLIC_KEY_FILE_DEFAULT 	"rpubkeys"
#endif
#endif


#ifdef MAIN
#define DEF
#else
#define DEF extern
#endif

#include "keyfield.h"
#include "headers.h"

typedef enum enum_key_source {KEY_FROM_NONE, KEY_FROM_FILE, KEY_FROM_SERVER,
  KEY_FROM_FINGER}
  TypKeyOrigin;

#define MAX_KEY_SOURCES 3

/* Certification status.
 */
#define CERT_VALID 1
#define CERT_PENDING 2
#define CERT_EXPIRED 3
#define CERT_CRL_EXPIRED 4
#define CERT_REVOCATION_UNKNOWN 5
#define CERT_UNVALIDATED 6
#define CERT_REVOKED 7

/* The implementation of DNs here is rather inefficient as it uses fixed
     length RDNs. */
#define MAX_NAME_LENGTH 64
#define MAX_RDN 20
#define MAX_AVA 20

#define ATTRTYPE_COMMONNAME 3
#define ATTRTYPE_STREETADDRESS 9
#define ATTRTYPE_ORGANIZATIONALUNITNAME 11
#define ATTRTYPE_ORGANIZATIONNAME 10
#define ATTRTYPE_LOCALITYNAME 7
#define ATTRTYPE_STATEPROVINCENAME 8
#define ATTRTYPE_COUNTRYNAME 6
#define ATTRTYPE_TITLE 12
#define ATTRTYPE_POSTALCODE 17

typedef struct DistinguishedNameStruct {
  /* Most significant AVAs and RDN are listed first. */
  char AVAValues[MAX_AVA][MAX_NAME_LENGTH + 1];                 /* C strings */
  short AVATypes[MAX_AVA];                                 /* -1 means none. */
  int AVAIsT61[MAX_AVA];             /* boolean for PRINTABLE vs. T61 STRING */
  short RDNIndexStart[MAX_RDN];              /* index into AVAs for ea. RDN. */
  short RDNIndexEnd[MAX_RDN];                              /* -1 means none. */
} DistinguishedNameStruct;

typedef struct struct_server {
	char *servername;
	int  serverport;
} TypServer;	

typedef struct struct_file {
	FILE *stream;
	char *filename;
} TypFile;

typedef struct struct_pubkeysource {
   TypList filelist;
	TypList serverlist;
	TypKeyOrigin origin[MAX_KEY_SOURCES];
} TypKeySource;

typedef struct struct_user {
	char *emailaddr;  /* Email address */
	BOOL gotpubkey;   /* =TRUE if we have his/her public key */
	R_RSA_PUBLIC_KEY  pubkey;  /* public key of this user */	
	unsigned char *enckey; /* Encrypted key, RFC1113 encoded */
	unsigned int   enckeylen; /* # of bytes in above */
  DistinguishedNameStruct userDN; /* distinguished name */
  int validationStatus; /* cert status of overall validation "chain" */
} TypUser;

typedef struct struct_msg_info {
	enum enum_ids proc_type;/* Processing type (ENCRYPTED, MIC-ONLY, etc.) */
	unsigned char iv[8]; 	/* DES Initialization Vector. */
	int 	da;               /* Digest algorithm (DA_ symbol) */
	unsigned char *mic;     /* Encrypted MIC */
	unsigned int mic_len;   /* # of bytes in above. */
	unsigned char *msg_key; /* Encrypted message key */
	unsigned int msg_key_len; 		/* # of bytes in above. */
	char *orig_name;        /* Originator's name, or NULL if not found */
	R_RSA_PUBLIC_KEY orig_pub_key; 	/* Originator's pub key */
	BOOL  got_orig_pub_key; /* TRUE if header has Orig pub key */
   int   ea;
 TypList certs;                       /* First is the Originator-Certificate */
} TypMsgInfo;

/*--- End of ripem.h ------------------------------------------------*/
