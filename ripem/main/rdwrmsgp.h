#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* rdwrmsg.c */
int CodeAndWriteBytes P((unsigned char *buf , unsigned int nbytes , char *prefix , FILE *pstream ));
void WriteCoded P((unsigned char *buf , unsigned int nbytes , char *prefix , FILE *pstream ));
char *ReadMessage P((FILE *stream , BOOL stripQuotedHyphens, BOOL addRecip , BOOL stripEOL , BOOL includeHeaders , BOOL lookForEndHeader , BOOL prependHeaders , TypList *headerList , unsigned char **text , unsigned int *nbytes , TypList *recipList ));
char *CrackRecipients P((char *line , TypList *list ));
int ReallocMessage P((unsigned char **text , unsigned char **nextcp , unsigned int *bytesleft , unsigned int *totbytes ));
void WriteEOL P((FILE *stream ));
void WriteMessage P((unsigned char *text , unsigned int textLen , BOOL quoteHyphens, FILE *stream ));

#undef P


