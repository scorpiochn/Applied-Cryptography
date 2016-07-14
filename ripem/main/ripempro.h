#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* ripemmai.c */
int main P((int argc , char *argv []));
char *InitMain P((void ));
char *CrackCmd P((int argc , char *argv []));
char *CrackKeyServer P((char *keyServerStr ));
void ShowParams P((void ));
char *OpenFiles P((void ));
char *InitUser P((char *email , TypUser **userEntry ));
char *DoRandom P((void ));
char *DoGenerateKeys P((void ));
char *DoChangePW P((BOOL newPWOnly ));
char *DoEncipher P((FILE *stream ));
void WritePrependedHeaders P((TypList headerList , FILE *outStream ));
char *WriteHeader P((FILE *stream , unsigned char iv [], TypList recipList , unsigned char *encryptedSignature , unsigned int encryptedSignatureLen ));
char *DoDecipher P((FILE *inStream , FILE *outStream ));
char *FormatRSAError P((int errorCode ));

#undef P
