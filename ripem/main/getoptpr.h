#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


int mygetopt P((int argc , char **argv , char *opts ));

#undef P
