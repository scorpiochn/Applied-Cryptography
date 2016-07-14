#ifdef __STDC__
# define  P(s) s
#else
# define P(s) ()
#endif

/* Use the THIS_CERT_FILTER macro to define the type of object in the
     callback prototype.  It defaults to the most base class, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
#ifndef THIS_CERT_FILTER
#define THIS_CERT_FILTER struct CertFilter
#endif

/* Forward declaration. */
struct CertificateStruct;

typedef struct CertFilter {
  /* checkCert is a callback which returns NULL for no error or an error
       message. */
  char * (*checkCert)
    P ((THIS_CERT_FILTER *, int *, unsigned char *, unsigned int,
        struct CertificateStruct *));

  R_RSA_PUBLIC_KEY *issuerPublicKey;
} CertFilter;

void R_time P ((UINT4 *));
char *WriteSelfSignedCert
  P((char *, R_RSA_PUBLIC_KEY *, R_RSA_PRIVATE_KEY *, unsigned int, FILE *));
char *FindAndCheckCertInRecord P((int *, char *, CertFilter *));
char *SelectKeyBySubject
  P((TypUser *, TypKeySource *, DistinguishedNameStruct *,
     R_RSA_PUBLIC_KEY *));
char *ValidateAndWriteCert
  P((struct CertificateStruct *, R_RSA_PRIVATE_KEY *,
     DistinguishedNameStruct *, unsigned int, FILE *));
void PrintCertNameAndDigest
  P((struct CertificateStruct *, unsigned char *, unsigned int, FILE *));
void CheckSelfSignedCert
  P((int *, struct CertificateStruct *, unsigned char *, unsigned int));
void GetDNSmartNameIndex P((unsigned int *, DistinguishedNameStruct *));
void WritePrintableName P((FILE *, DistinguishedNameStruct *));
char *GetCertStatusString P((int));

#undef P
