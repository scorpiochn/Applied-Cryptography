#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* crackhed.c */
char *CrackHeader P((FILE *stream , BOOL prependHeaders, TypList *headerList, TypList *userList , R_RSA_PUBLIC_KEY *, TypMsgInfo *msgInfo ));
char *DoHeaderLine P((char *ext_line , TypList *userList , R_RSA_PUBLIC_KEY *, TypMsgInfo *msgInfo ));
char *CrackHeaderLine P((char *line , char *field_name , TypList *valList ));
char *CrackLine P((char *line , TypList *valList ));
void TokenizeHeaderLine P((char *field_name , char **vals , int nvals , enum enum_fields *tok_field , enum enum_ids tok_vals []));
BOOL NameInList P((char *name , TypList *userList ));

#undef P
