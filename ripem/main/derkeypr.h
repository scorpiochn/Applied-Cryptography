#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* derkey.c */
int DERToPubKey P((unsigned char *der , R_RSA_PUBLIC_KEY *key ));
int DERToPrivKey P((unsigned char *der , R_RSA_PRIVATE_KEY *key ));
int DERToEncryptedPrivKey P((unsigned char *der , unsigned int maxLen , int *digestAlgorithm , unsigned char *salt , unsigned int *iterationCount , unsigned char *encBytes , unsigned int *encLen ));

#undef P
