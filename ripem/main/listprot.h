#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* list.c */
void InitList P((TypList *list ));
char *AddToList P((TypListEntry *prevEntry , void *entry , unsigned int entryLen , TypList *list ));
char *AppendLineToList P((char *line , TypList *list ));
void FreeList P((TypList *list ));
char *PrependToList P((void *entry , unsigned int entryLen , TypList *list ));

#undef P
