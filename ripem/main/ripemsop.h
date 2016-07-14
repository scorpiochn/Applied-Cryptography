#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* ripemsoc.c */
char *GetUserRecordFromServer P((char *user , TypKeySource *source , char *bytes , int maxBytes , BOOL *serverOK , BOOL *found ));
char *GetUserRecordFromFinger P((char *user , char *bytes , int maxBytes , int *found ));

#undef P
