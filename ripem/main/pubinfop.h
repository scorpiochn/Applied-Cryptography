#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* pubinfo.c */
int ReadUserRecord P((FILE *stream , char *rec , int maxLen , int *dataLen ));
int ReadUserRecord P((FILE *stream , char *rec , int maxLen , int *dataLen ));
BOOL FindUserInRecord P((char *username , char *userRec ));
BOOL PosFileLine P((FILE *stream , char *field ));
BOOL GetFileLine P((FILE *stream , char *field , char *value , int valuelen ));
int ExtractValue P((char *bptr , char *val , unsigned int maxLen ));
int CrackKeyField P((char *bptr , char *field , char *val , int valSize ));
int GetPubInfoFromFile P((FILE *stream , char *buf , unsigned int bufLen , unsigned int *returnedLen ));
int NextLineInBuf P((char **buf ));
BOOL ExtractPublicKeyLines P((char *inBuf , char *outBuf , int outSize ));

#undef P
