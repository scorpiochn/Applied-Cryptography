#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

struct CertFilter;

/* keyman.c */
char *GetPublicKey P((TypUser *user , TypKeySource *source, struct CertFilter *));
char *GetPublicKeyList P((TypList *userList , TypKeySource *pubKeySource, struct CertFilter * ));
BOOL CheckKeyList P((TypList *userList ));
char *GetPrivateKey P((char *user , TypKeySource *source , R_RSA_PRIVATE_KEY *key ));
char *GetKeyBytesFromFile P((char *user , TypFile *fileptr , char *keyFieldName , BOOL *found , unsigned char **keyBytes , unsigned int *numBytes ));
char *GetUserRecordFromFile P((char *user , TypFile *fileptr , unsigned int maxBytes , char *userRec , BOOL *found, struct CertFilter * ));
char *GetNextUserRecordFromFile P((FILE *ustream , unsigned int maxBytes , char *userRec , BOOL *found ));
void WritePublicKey P((R_RSA_PUBLIC_KEY *pubKey , FILE *outStream ));
int pbeWithMDAndDESWithCBC P((int encrypt , int digestAlg , unsigned char *buf , unsigned int numInBytes , unsigned char *password , unsigned int passwordLen , unsigned char *salt , unsigned int iterationCount , unsigned int *numOutBytes ));
void DESWithCBC P((int encrypt , unsigned char *buf , unsigned int numBytes , unsigned char *key , unsigned char *iv ));
unsigned int GetPasswordToPrivKey P((BOOL verify , BOOL new , unsigned char *password , unsigned int maxchars ));
void DumpPubKey P((R_RSA_PUBLIC_KEY *pubKey ));
void DumpPrivKey P((R_RSA_PRIVATE_KEY *privKey ));
void DumpBigNum P((unsigned char *bigNum , int numLen ));

#undef P
