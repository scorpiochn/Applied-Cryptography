#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* strutil.c */
int match P((char *str , char *pattern ));
int matchn P((char *str , char *pattern , int nchars ));
char *tail P((char *str , int num ));
int WhiteSpace P((int ch ));
BOOL LineIsWhiteSpace P((char *line ));
char *strcpyalloc P((char **target , char *source ));
char *strcatrealloc P((char **target , char *source ));
void trim P((char *line ));
char *ExtractEmailAddr P((char *addr ));
char *BreakUpEmailAddr P((char *addr , char *userName , int lenUser , char *hostName , int lenHost ));
int EmailHostnameComponents P((char *addr ));
int EmailAddrUpALevel P((char *addr ));
BOOL EmailMatch P((char *user , char *candidate ));
char *LowerCaseString P((char *str ));
void ClearBuffer P((void *buf , int nbytes ));
void MakeHexDigest P((unsigned char *buf , unsigned int buflen , char *hex_digest ));

#undef P
