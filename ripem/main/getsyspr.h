#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* getsys.c */
int GetRandomBytes P((unsigned char *bytes , int maxbytes ));
void CopyRandomBytes P((void *thisBuf , int thisSize , unsigned char *userBuf , int *numBytes , int *maxBytes , char *message ));
void ReportCPUTime P((char *msg));
void GetUserInput P((unsigned char userbytes [], int *num_userbytes , unsigned char timebytes [], int *num_timebytes , int echo ));
int  GetUserName P((char **name ));
unsigned int GetPasswordFromUser P((char *prompt , BOOL verify , unsigned char *password , unsigned int maxchars ));
void GetUserAddress P((char **address ));
void GetUserHome P((char **home ));
void ExpandFilename P((char **fileName));
#ifndef MACTC	/* rwo */
BOOL GetEnvFileName P((char *envName , char *defName , char **fileName ));
BOOL GetEnvAlloc P((char *envName , char **target ));
#else
BOOL GetEnvFileName P((short envName , char *defName , char **fileName ));
BOOL GetEnvAlloc P((short envName , char **target ));
#endif
#undef P
