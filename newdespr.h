#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

unsigned int NewdesBuf P((unsigned char *buf , unsigned int buf_length , unsigned char *keyptr ));
void NewdesBlock P((unsigned char *block , unsigned char *keyptr ));
void NewdesSetKeyEncipher P((unsigned char *key , unsigned char *key_rav ));
void NewdesSetKeyDecipher P((unsigned char *key , unsigned char *key_rav ));

#undef P
