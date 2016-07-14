/* Define this so that the type of the 'this' pointer in the
     callback functions will be correct for this derived class.
 */
struct IssuerCertFilter;
#define THIS_CERT_FILTER struct IssuerCertFilter

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "certder.h"
#include "keyderpr.h"
#include "prcodepr.h"
#include "keyfield.h"
#include "rdwrmsgp.h"
#include "pubinfop.h"
#include "ripempro.h"
#include "certutil.h"
#include "keymanpr.h"
#include "ripemglo.h"
#include "p.h"

/* For a Macintosh, where time is returned in seconds since
     1/1/1904 12:00:00 AM, YEAR_BASE should be defined as 1904.
   For Microsoft C 7.0, YEAR_BASE should be defined as 1900.
   The following defines YEAR_BASE as 1970 if it has not already been
     defined as something else with C compiler flags.
 */
#ifndef YEAR_BASE
#define YEAR_BASE 1970
#endif

/* Calculate the time adjustment the number of seconds between the year
     base and 1970. */
#define TIME_ADJUSTMENT \
  ((UINT4)(365 * (1970 - YEAR_BASE) + ((1970 - YEAR_BASE) + 2) / 4) * \
   (UINT4)24 * (UINT4)3600)

/* If the time() function returns local time, define GMT_OFFSET to be
     the number of hours that local time is EARLIER than GMT.
*/
#ifndef GMT_OFFSET
#define GMT_OFFSET 0
#endif

#define SECONDS_IN_MONTH \
  ((UINT4)((UINT4)365 * (UINT4)24 * (UINT4)3600) / (UINT4)12)

typedef struct IssuerCertFilter {
  CertFilter certFilter;                                     /* "base class" */

  DistinguishedNameStruct *rootDN;
  DistinguishedNameStruct *subjectDN;
} IssuerCertFilter;

static char *IssuerCheckCert
  P((THIS_CERT_FILTER *, int *, unsigned char *, unsigned int,
     struct CertificateStruct *));
static void SignCert
  P((unsigned char *, unsigned int *, struct CertificateStruct *,
     R_RSA_PRIVATE_KEY *));

#define MAX_AVA_TYPE 17
static char *AVA_TYPES[MAX_AVA_TYPE + 1] = {
  "unknownType", "type1", "type2", "CN", "type4", "type5", "C", "L", "ST",
  "SA", "O", "OU", "T", "type13", "type14", "type15", "type16", "PC"
};

void R_time (theTime)
UINT4 *theTime;
{
  time ((time_t *)theTime);

  /* Correct for a year base different than 1970 */
  (*theTime) -= TIME_ADJUSTMENT;

  /* Correct for local time to GMT */
  (*theTime) += (UINT4)3600 * GMT_OFFSET;
}

char *WriteSelfSignedCert
  (username, publicKey, privateKey, validityMonths, outStream)
char *username;
R_RSA_PUBLIC_KEY *publicKey;
R_RSA_PRIVATE_KEY *privateKey;
unsigned int validityMonths;
FILE *outStream;
{
  CertificateStruct certStruct;
  unsigned char *certDER, *innerDER;
  unsigned int i, digestLen, maxCertDERLen, certDERLen, innerDERLen;

  /* We are going to digest the struct to get a uniqe serial number, so
       pre-zerioze.
     This also pre-sets AVAIsT61 to 0. */
  R_memset ((POINTER)&certStruct, 0, sizeof (certStruct));

  certStruct.digestAlgorithm = DA_MD2;

  /* Construct a name for the Persona CA with the Username as common name.
   */
  strcpy (certStruct.issuer.AVAValues[0], "US");
  certStruct.issuer.AVATypes[0] = ATTRTYPE_COUNTRYNAME;
  certStruct.issuer.RDNIndexStart[0] = certStruct.issuer.RDNIndexEnd[0] = 0;
  
  strcpy (certStruct.issuer.AVAValues[1], "RSA Data Security, Inc.");
  certStruct.issuer.AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
  certStruct.issuer.RDNIndexStart[1] = certStruct.issuer.RDNIndexEnd[1] = 1;
  
  strcpy (certStruct.issuer.AVAValues[2], "Persona Certificate");
  certStruct.issuer.AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
  certStruct.issuer.RDNIndexStart[2] = certStruct.issuer.RDNIndexEnd[2] = 2;
  
  strcpy (certStruct.issuer.AVAValues[3], username);
  certStruct.issuer.AVATypes[3] = ATTRTYPE_COMMONNAME;
  certStruct.issuer.AVAIsT61[3] =
    (IsPrintableString ((unsigned char *)username, strlen (username)) ? 0 : 1);
  certStruct.issuer.RDNIndexStart[3] = certStruct.issuer.RDNIndexEnd[3] = 3;

  /* Set the rest of the RDN indexes to -1. */
  for(i = 4; i < MAX_RDN; ++i)
    certStruct.issuer.RDNIndexStart[i] = certStruct.issuer.RDNIndexEnd[i] = -1;

  /* Set validity to now to now plus validity months. */
  R_time (&certStruct.notBefore);
  certStruct.notAfter = certStruct.notBefore +
    ((UINT4)((UINT4)validityMonths * SECONDS_IN_MONTH));

  /* Set subject name to the issuer name. */
  certStruct.subject = certStruct.issuer;

  certStruct.publicKey = *publicKey;

  /* Now set the serial number to the digest of the certStruct. */
  R_DigestBlock
    (certStruct.serialNumber, &digestLen, (unsigned char *)&certStruct,
     sizeof (certStruct), certStruct.digestAlgorithm, MODE_STANDARD);

  /* Allocate buffer for certificate DER and sign it.
     Alloca space for an extra byte as required by CodeAndWriteBytes.
   */
  maxCertDERLen =
    len_certificate (&certStruct, PubKeyToDERLen (&certStruct.publicKey)) + 4 +
    MAX_CERT_TO_SIGNED_DELTA + 1;

  if ((certDER = (unsigned char *)malloc
       (maxCertDERLen)) == (unsigned char *)NULL)
    return ("Can't allocate memory");

  SignCert (certDER, &certDERLen, &certStruct, privateKey);

  fprintf (outStream, "%s ", USER_DN_FIELD);
  WritePrintableName (outStream, &certStruct.subject);
  fprintf (outStream, "\n");

  fprintf (outStream, "%s\n", CERT_INFO_FIELD);
  CodeAndWriteBytes (certDER, certDERLen, " ", outStream);

  /* Write the cert's DN and self-signed digest.  Don't check the error return
       on DERToCertificate since we just encoded it.
   */
  DERToCertificate (certDER, &certStruct, &innerDER, &innerDERLen);
  PrintCertNameAndDigest (&certStruct, innerDER, innerDERLen, CertinfoStream);

  free (certDER);
  return ((char *)NULL);
}

/* Decode the CertificateInfo field, run certFilter->checkCert if not NULL,
     and check the cert signature with certFilter->issuerPublicKey.
   If all there succeed, set *found TRUE.
   Returns NULL for ok, otherwise error message.
 */
char *FindAndCheckCertInRecord (found, userRec, certFilter)
int *found;
char *userRec;
CertFilter *certFilter;
{
  CertificateStruct certStruct;
  char *encodedCert = (char *)NULL, *errMessage = (char *)NULL;
  int certOK, certDERLen, status;
  unsigned char *certDER = (unsigned char *)NULL, *innerDER;
  unsigned int userRecLen, innerDERLen;

  /* Default to not found */
  *found = FALSE;

  do {
    userRecLen = strlen (userRec);

    if ((encodedCert = (char *)malloc (userRecLen)) == (char *)NULL ||
        (certDER = (unsigned char *)malloc (userRecLen))
        == (unsigned char *)NULL) {
      errMessage = "Can't allocate memory";
      break;
    }

    /* Get the certDER from the record.
     */
    if (!CrackKeyField (userRec, CERT_INFO_FIELD, encodedCert, userRecLen))
      /* *found is already FALSE */
      break;    
    prdecode (encodedCert, certDER, userRecLen);

    if ((certDERLen = DERToCertificate
         (certDER, &certStruct, &innerDER, &innerDERLen)) < 0) {
      errMessage = "Cannot decode certificate";
      break;
    }

    if (certFilter->checkCert) {
      /* Use checkCert callback */
      if ((errMessage = (*certFilter->checkCert)
           ((THIS_CERT_FILTER *)certFilter, &certOK, certDER,
            (unsigned int)certDERLen, &certStruct)) != (char *)NULL)
        break;
      if (!certOK)
        break;
    }

    /* Use the RSAREF verify routine to check the signature on the
         inner cert info.
     */
    if ((status = R_VerifyBlockSignature
         (innerDER, innerDERLen, certStruct.signature, certStruct.signatureLen,
          certStruct.digestAlgorithm, certFilter->issuerPublicKey,
          MODE_STANDARD)) != 0) {
      errMessage = FormatRSAError (status);
      break;
    }

    *found = TRUE;
  } while (0);

  free (encodedCert);
  free (certDER);
  return (errMessage);
}

/* On entry, user->userDN is the distinguished name to search for.
   Set user->pubkey to the public key for the subject DN by looking in
     publicKeySource.  This also sets user->emailaddr to the smart name.
   On return, the calling routine must check user->gotpubkey.  If it is
     FALSE, could not find a validation path.
   Return NULL for OK, or error message.
 */
char *SelectKeyBySubject (user, publicKeySource, rootDN, rootPublicKey)
TypUser *user;
TypKeySource *publicKeySource;
DistinguishedNameStruct *rootDN;
R_RSA_PUBLIC_KEY *rootPublicKey;
{
  IssuerCertFilter issuerCertFilter;
  unsigned int smartNameIndex;

  issuerCertFilter.certFilter.checkCert = IssuerCheckCert;
  issuerCertFilter.certFilter.issuerPublicKey = rootPublicKey;
  issuerCertFilter.rootDN = rootDN;
  issuerCertFilter.subjectDN = &user->userDN;

  /* Get smart name of the issuer to use in the search. */
  GetDNSmartNameIndex (&smartNameIndex, &user->userDN);

  user->emailaddr = user->userDN.AVAValues[smartNameIndex];
  return (GetPublicKey (user, publicKeySource, &issuerCertFilter.certFilter));
}

char *ValidateAndWriteCert
  (senderCertStruct, issuerPrivateKey, issuerDN, validityMonths, outStream)
CertificateStruct *senderCertStruct;
R_RSA_PRIVATE_KEY *issuerPrivateKey;
DistinguishedNameStruct *issuerDN;
unsigned int validityMonths;
FILE *outStream;
{
  CertificateStruct certStruct;
  unsigned char *certDER;
  unsigned int digestLen, maxCertDERLen, certDERLen, smartNameIndex;

  /* We are going to digest the struct to get a uniqe serial number, so
       pre-zerioze. */
  R_memset ((POINTER)&certStruct, 0, sizeof (certStruct));

  certStruct.digestAlgorithm = DA_MD2;
  certStruct.issuer = *issuerDN;
  
  /* Set validity to now to now plus validity months. */
  R_time (&certStruct.notBefore);
  certStruct.notAfter = certStruct.notBefore +
    ((UINT4)((UINT4)validityMonths * SECONDS_IN_MONTH));

  /* Set subject name and key to the sender's. */
  certStruct.subject = senderCertStruct->issuer;
  certStruct.publicKey = senderCertStruct->publicKey;

  /* Now set the serial number to the digest of the certStruct. */
  R_DigestBlock
    (certStruct.serialNumber, &digestLen, (unsigned char *)&certStruct,
     sizeof (certStruct), certStruct.digestAlgorithm, MODE_STANDARD);

  /* Allocate buffer for certificate DER and sign it.
     Alloca space for an extra byte as required by CodeAndWriteBytes.
   */
  maxCertDERLen =
    len_certificate (&certStruct, PubKeyToDERLen (&certStruct.publicKey)) + 4 +
    MAX_CERT_TO_SIGNED_DELTA + 1;

  if ((certDER = (unsigned char *)malloc
       (maxCertDERLen)) == (unsigned char *)NULL)
    return ("Can't allocate memory");

  SignCert (certDER, &certDERLen, &certStruct, issuerPrivateKey);

  /* Get the sender's smart name and write it as the User: field.
   */
  GetDNSmartNameIndex (&smartNameIndex, &certStruct.subject);
  fprintf (outStream, "\n");
  fprintf
    (outStream, "%s %s\n", USER_FIELD,
     certStruct.subject.AVAValues[smartNameIndex]);
  
  fprintf (outStream, "%s ", USER_DN_FIELD);
  WritePrintableName (outStream, &certStruct.subject);
  fprintf (outStream, "\n");

  fprintf (outStream, "%s\n", CERT_INFO_FIELD);
  CodeAndWriteBytes (certDER, certDERLen, " ", outStream);

  free (certDER);
  return ((char *)NULL);
}

void PrintCertNameAndDigest (certStruct, innerDER, innerDERLen, outStream)
CertificateStruct *certStruct;
unsigned char *innerDER;
unsigned int innerDERLen;
FILE *outStream;
{
  unsigned char digest[16];
  unsigned int digestLen, i;

  R_DigestBlock
    (digest, &digestLen, innerDER, innerDERLen, certStruct->digestAlgorithm,
     MODE_STANDARD);

  fputs ("User: ", outStream);
  WritePrintableName (outStream, &certStruct->subject);
  fprintf (outStream, "\n");

  fprintf (outStream, "User certificate digest: ");
  for (i = 0; i < digestLen; ++i)
    fprintf (outStream, "%02X ", (int)digest[i]);
  fprintf (outStream, "\n");
}

/* If the certificate issuer and subject are the same and the public
     key verifies the signature, set isSelfSigned to non-zero, otherwise
     set to zero.
 */
void CheckSelfSignedCert (isSelfSigned, certStruct, innerDER, innerDERLen)
int *isSelfSigned;
CertificateStruct *certStruct;
unsigned char *innerDER;
unsigned int innerDERLen;
{
  /* Default to not self-signed */
  *isSelfSigned = 0;

  if (R_memcmp ((POINTER)&certStruct->issuer, (POINTER)&certStruct->subject,
                sizeof (certStruct->issuer)) != 0)
    /* issuer != subject */
    return;

  if (R_VerifyBlockSignature
      (innerDER, innerDERLen, certStruct->signature,
       certStruct->signatureLen, certStruct->digestAlgorithm,
       &certStruct->publicKey, MODE_STANDARD) != 0)
    /* public key does not verify signature. */
    return;

  *isSelfSigned = 1;
}

/* Get the index in the AVAValues of the smart name.
 */
void GetDNSmartNameIndex (smartNameIndex, dn)
unsigned int *smartNameIndex;
DistinguishedNameStruct *dn;
{
  int typePriority = 0;
  unsigned int i;

  /* Go through the AVAs, setting nameIndex to the last common name, or
       to the last title if there are no common names.
   */
  for (i = 0; i < MAX_AVA; ++i) {
    if (dn->AVATypes[i] == -1)
      /* There are no more AVAs */
      break;

    if (dn->AVATypes[i] == ATTRTYPE_TITLE && typePriority <= 1) {
      *smartNameIndex = i;
      typePriority = 1;
    }
    if (dn->AVATypes[i] == ATTRTYPE_COMMONNAME && typePriority <= 2) {
      *smartNameIndex = i;
      typePriority = 2;
    }
  }

  if (typePriority == 0)
    /* There are no common names or titles, so use the least significant AVA */
    *smartNameIndex = i - 1;
}

/* Write the dn to the stream in the format
   "CN = User, OU = Persona Certificate ...".
   This uses a + instead of , for AVAs on the same level.
   This does not write a newline at the end.
 */
void WritePrintableName (stream, dn)
FILE *stream;
DistinguishedNameStruct *dn;
{
  int rdn, ava;

  for (rdn = MAX_RDN - 1; rdn >= 0; --rdn) {
    if (dn->RDNIndexStart[rdn] == -1)
      continue;

    for (ava = dn->RDNIndexStart[rdn]; ava <= dn->RDNIndexEnd[rdn]; ++ava) {
      /* Output the AVA.  AVA_TYPES[0] is "unknown" for bad types.
       */
      fputs (dn->AVATypes[ava] >
             MAX_AVA_TYPE ? AVA_TYPES[0] : AVA_TYPES[dn->AVATypes[ava]],
             stream);
      fputs (" = ", stream);
      fputs (dn->AVAValues[ava], stream);

      if (ava == dn->RDNIndexEnd[rdn]) {
        /* This is the last AVA in the RDN, so put a comma.
           But don't put anything if it is the last RDN. */
        if (rdn != 0)
          fputs (", ", stream);
      }
      else
        /* Put a plus because there are more AVAs in this RDN. */
        fputs (" + ", stream);
    }
  }
}

/* Convert a CERT_ validity status into a string such as "VALID".
 */
char *GetCertStatusString (certStatus)
int certStatus;
{
  switch (certStatus) {
  case CERT_VALID:
    return ("VALID");
  case CERT_PENDING:
    return ("PENDING");
  case CERT_EXPIRED:
    return ("EXPIRED");
  case CERT_CRL_EXPIRED:
    return ("CRL EXPIRED");
  case CERT_REVOCATION_UNKNOWN:
    return ("REVOCATION UNKNOWN");
  case CERT_UNVALIDATED:
    return ("UNVALIDATED");
  case CERT_REVOKED:
    return ("REVOKED");
    
  default:
    return ("UNRECOGNIZED TYPE");
  }
}

static char *IssuerCheckCert
  (issuerCertFilter, certOK, certDER, certDERLen, certStruct)
IssuerCertFilter *issuerCertFilter;
int *certOK;
unsigned char *certDER;
unsigned int certDERLen;
CertificateStruct *certStruct;
{
  /* Accept this cert if the issuer name == the given rootDN and the
       subject name == the given subjectDN.
   */
  *certOK =
    ((R_memcmp
      ((POINTER)&certStruct->issuer, (POINTER)issuerCertFilter->rootDN,
       sizeof (certStruct->issuer)) == 0) &&
     (R_memcmp
      ((POINTER)&certStruct->subject, (POINTER)issuerCertFilter->subjectDN,
       sizeof (certStruct->subject)) == 0));

  return ((char *)NULL);
}

/* certDER buffer is already allocated.  Encode and sign the info in certStruct
     with the privateKey and return the length in certDERLen.
   This leaves the signature in the certStruct buffer.
 */
static void SignCert (certDER, certDERLen, certStruct, privateKey)
unsigned char *certDER;
unsigned int *certDERLen;
CertificateStruct *certStruct;
R_RSA_PRIVATE_KEY *privateKey;
{
  unsigned char encodedSignature[2*MAX_CERT_SIGNATURE_LEN];
  unsigned int encodedSignatureLen;

  CertificateToDer (certStruct, certDER, certDERLen);

  /* R_SignPEMBlock ASCII recodes the signature, so we have to decode it.
     Future versions of RSAREF may provide a signing call without encoding.
   */
  R_SignPEMBlock
    ((unsigned char *)NULL, (unsigned int *)NULL, encodedSignature,
     &encodedSignatureLen, certDER, *certDERLen, 0, DA_MD2, privateKey,
     MODE_STANDARD);
  encodedSignature[encodedSignatureLen] = 0;
  certStruct->signatureLen = prdecode
    ((char *)encodedSignature, certStruct->signature,
     sizeof (certStruct->signature));

  DerCertToDerSigned
    (certDER, certDERLen, certStruct->signature, certStruct->signatureLen);
}

