#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


unsigned int PubKeyToDERLen P((R_RSA_PUBLIC_KEY *key ));
int PubKeyToDER P((R_RSA_PUBLIC_KEY *key , unsigned char *der , unsigned int *derlen ));
unsigned int PrivKeyToDERLen P((R_RSA_PRIVATE_KEY *key ));
int PrivKeyToDER P((R_RSA_PRIVATE_KEY *key , unsigned char *der , unsigned int *derlen ));
unsigned int EncryptedPrivKeyToDERLen P((unsigned int iterationCount , unsigned int encLen ));
int EncryptedPrivKeyToDER P((unsigned char *salt , unsigned int iterationCount , unsigned char *encBytes , unsigned int encLen , unsigned char *der , unsigned int *derlen ));

#undef P
