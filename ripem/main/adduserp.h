#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* adduser.c */
char *AddUniqueUserToList P((TypUser *user , TypList *list ));

#undef P
