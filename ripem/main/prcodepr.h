#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

int prencode P((unsigned char *bufin , unsigned int nbytes , char *bufcoded ));
int prdecode P((char *bufcoded , unsigned char *bufplain , int outbufsize ));

#undef P
