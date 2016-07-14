#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

#define MAX_CERT_SIGNATURE_LEN 128

/* Define the max that DerCertToDerSigned can expand the encoding.
   4 is the beginning SEQ. 15 is the size of the md2WithRSA algorithm ID.
     3 + 1 is the beginning of the bit string for the signature.
 */
#define MAX_CERT_TO_SIGNED_DELTA (4 + 15 + 3 + 1 + MAX_CERT_SIGNATURE_LEN)

typedef struct CertificateStruct {
  unsigned int version;
  unsigned char serialNumber[16];                         /* up to 128 bits. */
  int digestAlgorithm;
  DistinguishedNameStruct issuer;
  unsigned long notBefore;                             /* seconds since 1970 */
  unsigned long notAfter;                              /* seconds since 1970 */
  DistinguishedNameStruct subject;
  R_RSA_PUBLIC_KEY publicKey;
  unsigned char signature[MAX_CERT_SIGNATURE_LEN];
  int signatureLen;
} CertificateStruct;

int DERToCertificate
  P((unsigned char *, CertificateStruct *, unsigned char **, unsigned int *));
int DERToDistinguishedName
  P((unsigned char **, DistinguishedNameStruct *));
int IsPrintableString P((unsigned char *, unsigned int));

unsigned int len_certificate P((CertificateStruct *, int));
void CertificateToDer
  P((CertificateStruct *, unsigned char *, unsigned int *));
void DerCertToDerSigned
  P((unsigned char *, unsigned int *, unsigned char *, unsigned int));
unsigned int len_distinguishedname P((DistinguishedNameStruct *));
void DistinguishedNameToDER P((DistinguishedNameStruct *, unsigned char **));

#undef P
