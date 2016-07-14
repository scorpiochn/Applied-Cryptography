#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* parsit.c */
int parsit P((char *line , char ***array ));

#undef P
