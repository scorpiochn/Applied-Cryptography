#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

int HexToBin P((char *hex , int maxbytes , unsigned char *bin ));
void BinToHex P((unsigned char *bin , int nbytes , char *hex ));
