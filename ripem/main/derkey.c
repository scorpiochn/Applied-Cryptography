/*
 *   derkey.c
 *	Routines to translate to R_RSA_{PUBLIC,PRIVATE}_KEY
 *	from ASN.1 DER encodings.
 */

#include <stdio.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "derkeypr.h"
#include "certder.h"

/* Error return codes */
#define DK_ERR_FORMAT	-1		/* Badly formatted DER string */
#define	DK_ERR_ALG	-2		/* Unrecognized algorithm */

/* DER class/tag codes */
#define	DER_INT		0x02
#define	DER_BITSTRING	0x03
#define	DER_OCTETSTRING	0x04
#define	DER_NULL	0x05
#define	DER_OBJID	0x06
#define	DER_SEQ		0x30
#define	DER_SET		0x31


/* Alg ID - rsa - {2, 5, 8, 1, 1}*/
static unsigned char rsa_alg[] = { DER_OBJID, 4, 2*40+5, 0x08, 0x01, 0x01 };

/* rsaEncryption data structure, with algorithm {1 2 840 113549 1 1 1} and
 * NULL parameter.
   NOTE: this starts at the object ID, not the algorithm ID sequence.
 */
static unsigned char rsaEnc_alg[] = { DER_OBJID, 9,
			1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
			DER_NULL, 0 };

/* Version = 0 */
static unsigned char version[] = { DER_INT, 1, 0 };


/* Return the number of bits in large unsigned n */
static unsigned int
largeunsignedbits (n, nsize)
unsigned char		*n;
unsigned int		nsize;
{
    unsigned int	i, j;

    for (i=0; i<nsize && n[i]==0; ++i)
	;		/* Intentionally empty */
    if (i==nsize)
	return 0;
    j = n[i];
    i = ((nsize-i-1) << 3) + 1;
    while ((j>>=1))
	++i;
    return i;
}


/* Read the tag and length information from a DER string.  Advance
 * der to past the length.  Return negative on error.
 */
static int			/* Return < 0 on error */
gettaglen(tag, len, p)
UINT2		*tag;
unsigned int		*len;
unsigned char		**p;
{
    UINT2	t;
    unsigned int	l;
    int		c;
    int		n;

    t = *(*p)++;
    if (!t)
	return -1;
    c = *(*p)++;
    if (c & 0x80) {
	if (!(n = c & 0x7f))
	    return -1;
	l = 0;
	if (n > sizeof(unsigned int))
	    return -1;
	while (n--) {
	    c = *(*p)++;
	    l = (l<<8) + c;
	}
    } else {
	l = c & 0x7f;
    }
    *tag = t;
    *len = l;
    return 0;
}


/* Check DER byte string against literal data to make sure they match.
 * Return negative on error.  Advance der pointer p.
 * ALSO: for error return, this leaves p where it was.
 */
static int
chkdata (p, s, len)
unsigned char		**p;
unsigned char		*s;
unsigned int		len;
{	unsigned char *origp = *p;
    while (len--)
		if (*(*p)++ != *s++) {
			*p = origp;
			return -1;
		}
    return 0;
}


/* Read an integer from DER byte string.  It must be small enough to
 * fit in an int.  Return negative on error.
 */
static int
getsmallint (n, p)
unsigned int		*n;
unsigned char		**p;
{
    UINT2	tag;
    unsigned int	len;
    unsigned int	v;

    if (gettaglen(&tag,&len,p) < 0)
	return -1;
    if (tag != DER_INT)
	return -1;
    if (len > sizeof(int)  ||  len == 0)
	return -1;
    v = 0;
    while (len--)
	v = (v << 8) + *(*p)++;
    *n = v;
    return 0;
}


/* Read a large integer from the DER byte string pointed to by p.
 * Advance p as we read.  Put it into buffer n, of length nsize,
 * right justified.  Clear the rest of n.
 * Return negative on error.
 */
static int
getlargeunsigned (n, nsize, p)
unsigned char		*n;
unsigned int		nsize;
unsigned char		**p;
{
    UINT2	tag;
    unsigned int	len;

   if (gettaglen(&tag,&len,p) < 0)
		return -1;
   if (tag != DER_INT)
		return -1;
	 /* Skip a leading zero  in the input; it may overflow the output
	  * buffer if the large unsigned is just the same size as the output buffer.
	  */
	if(! **p) {
	 	(*p)++;
		len--;
	}
   if (len > nsize)
		return -1;
   nsize -= len;
   while (nsize--)
		*n++ = 0;
   while (len--)
		*n++ = *(*p)++;
   return 0;
}



/*
 *	Beginning of public entry points for this module
 */



/*   int DERToPubKey (der, key)
 *	Translate the byte string DER, in ASN.1 syntax using the
 *	Distinguished Encoding Rules, into RSA public key.
 *	Return 0 on success, nonzero on error.
 */
int				/* 0 for OK, nonzero on error */
DERToPubKey (der, key)
unsigned char	*der;
R_RSA_PUBLIC_KEY	*key;
{
    UINT2		tag;
    unsigned int		len;
    unsigned int		bits;
    unsigned char		*der1, *der2;

    /* Pre-zeroize public key struct so byte-wise comparison of two
         structs for the same public key will be the same. */
    R_memset ((POINTER)key, 0, sizeof (*key));

    if (gettaglen(&tag,&len,&der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
	return DK_ERR_FORMAT;
    der1 = der + len;		/* Position of end of string */
    if (gettaglen(&tag, &len, &der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
	return DK_ERR_FORMAT;
    der2 = der + len;		/* Position of end of alg info */
    if (chkdata(&der, rsa_alg, (unsigned int)sizeof(rsa_alg)) < 0) {
      /* Try the rsaEncryption algorithm ID. */
      if (chkdata(&der, rsaEnc_alg, (unsigned int)sizeof(rsaEnc_alg)) < 0)
        return DK_ERR_ALG;
      key->bits = 0;
    } else {
    if (getsmallint(&bits, &der) < 0)
	return DK_ERR_FORMAT;
    key->bits = (int)bits;
    }
    if (der != der2)		/* Check end of alg info */
	return DK_ERR_FORMAT;
    if (gettaglen(&tag, &len, &der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_BITSTRING)
	return DK_ERR_FORMAT;
    if (der + len != der1)	/* Should also be end of string */
	return DK_ERR_FORMAT;
    if (*der++ != 0)		/* Bitstring must be a mult of 8 bits */
	return DK_ERR_FORMAT;
    if (gettaglen(&tag, &len, &der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
	return DK_ERR_FORMAT;
    if (der + len != der1)	/* Should also be end of string */
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->modulus, (unsigned int)sizeof(key->modulus), &der) < 0)
	return DK_ERR_FORMAT;
    if(key->bits == 0) {
      /* In the rsaEncryption case, we must compute the modulus bits. */
    	key->bits = (int)largeunsignedbits
        (key->modulus, (unsigned int)sizeof(key->modulus));
    }
    if (getlargeunsigned (key->exponent, (unsigned int)sizeof(key->exponent),&der) < 0)
	return DK_ERR_FORMAT;
    if (der != der1)		/* Check end of string */
	return DK_ERR_FORMAT;
    return 0;
}

/*   int DERToPrivKey (der, key)
 *	Translate the byte string DER, in ASN.1 syntax using the
 *	Distinguished Encoding Rules, into RSA private key.
 *	Return 0 on success, nonzero on error.
 */
int				/* 0 for OK, nonzero on error */
DERToPrivKey (der, key)
unsigned char			*der;
R_RSA_PRIVATE_KEY	*key;
{
    UINT2		tag;
    unsigned int		len;
    unsigned char		*der1;

	R_memset((POINTER)key,0,sizeof *key);

    if (gettaglen(&tag,&len,&der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
	return DK_ERR_FORMAT;
    der1 = der + len;		/* Position of end of string */
    if (chkdata(&der, version, (unsigned int)sizeof(version)) < 0)
	return DK_ERR_ALG;
    /* rsaEnc_alg starts at the object ID, so decode the sequence here. */
    if (gettaglen(&tag, &len, &der) < 0)
      return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
      return DK_ERR_FORMAT;
    if (chkdata(&der, rsaEnc_alg, (unsigned int)sizeof(rsaEnc_alg)) < 0)
	return DK_ERR_ALG;
    if (gettaglen(&tag, &len, &der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_OCTETSTRING)
	return DK_ERR_FORMAT;
    if (der+len != der1)	/* Should match end of string */
	return DK_ERR_FORMAT;
    if (gettaglen(&tag,&len,&der) < 0)
	return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
	return DK_ERR_FORMAT;
    if (der+len != der1)	/* Should match end of string */
	return DK_ERR_FORMAT;
    if (chkdata(&der, version, (unsigned int)sizeof(version)) < 0)
	return DK_ERR_ALG;
    if (getlargeunsigned (key->modulus, (unsigned int)sizeof(key->modulus), &der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->publicExponent,
				(unsigned int)sizeof(key->publicExponent), &der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->exponent, (unsigned int)sizeof(key->exponent),&der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->prime[0], (unsigned int)sizeof(key->prime[0]),&der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->prime[1], (unsigned int)sizeof(key->prime[1]),&der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->primeExponent[0],
				(unsigned int)sizeof(key->primeExponent[0]), &der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->primeExponent[1],
				(unsigned int)sizeof(key->primeExponent[1]), &der) < 0)
	return DK_ERR_FORMAT;
    if (getlargeunsigned (key->coefficient,
				(unsigned int)sizeof(key->coefficient), &der) < 0)
	return DK_ERR_FORMAT;
    if (der != der1)		/* Check end of string */
	return DK_ERR_FORMAT;
    /* This info isn't in the DER format, so we have to calculate it */
    key->bits = (int)largeunsignedbits (key->modulus,
						 (unsigned int)sizeof(key->modulus));
    return 0;
}

/* Data structure specifying "algorithm=pbeWithMD2AndDES-CBC"
 * for encoding of encrypted private key.
 * Decodes to OBJECT_ID = 1 2 840 113549 1 5 1
 */
static unsigned char pbeWithMD2AndDES_CBC[] = { DER_OBJID, 9,
			1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x01 };

/* Data structure specifying "algorithm=pbeWithMD5AndDES-CBC"
 * for encoding of encrypted private key.
 * Decodes to OBJECT_ID = 1 2 840 113549 1 5 3
 */
static unsigned char pbeWithMD5AndDES_CBC[] = { DER_OBJID, 9,
			1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 };

/*--- function int DERToEncryptedPrivKey --------------------------
 *
 *	Translate the byte string DER, in ASN.1 syntax using the
 *	Distinguished Encoding Rules, into encrypted RSA private key.
 *	Return 0 on success, nonzero on error.
 *
 * Encrypted key encoding looks like this:
 *
 *	Sequence
 * 	Sequence                           # encryption algorithm
 *			Object ID 1 2 840 113549 1 5 3  # algorithm MD5AndDES-CBC (MD2 also OK)
 *			Sequence                        # algorithm parameters:
 *				Octet string, 8 bytes long   # salt
 *			   Integer                      # iteration count
 *		Octet string							  # encrypted data
 */
int				/* 0 for OK, nonzero on error */
DERToEncryptedPrivKey (der,maxLen, digestAlgorithm,salt,iterationCount,encBytes,encLen)
unsigned char			*der;
unsigned int maxLen;
int         *digestAlgorithm;
unsigned char *salt;
unsigned int *iterationCount;
unsigned char *encBytes;
unsigned int  *encLen;

{
   UINT2		tag;
   unsigned int		len;
   unsigned char		*der_end;

	/* Check first Sequence */
   if (gettaglen(&tag,&len,&der) < 0)
		return DK_ERR_FORMAT;
   if (tag != DER_SEQ)
		return DK_ERR_FORMAT;
   der_end = der + len;		/* Position of end of string */

	/* Check second Sequence */
	if(gettaglen(&tag,&len,&der) < 0)
		return DK_ERR_FORMAT;
	if(tag != DER_SEQ)
		return DK_ERR_FORMAT;

	/* Check algorithm */
   if (chkdata(&der,pbeWithMD5AndDES_CBC, (unsigned int)sizeof(pbeWithMD5AndDES_CBC)) < 0) {
		if (chkdata(&der,pbeWithMD2AndDES_CBC, (unsigned int)sizeof(pbeWithMD2AndDES_CBC)) < 0)
			return DK_ERR_ALG;
		*digestAlgorithm = DA_MD2;
	} else
	*digestAlgorithm = DA_MD5;

	/* Check Sequence of algorithm parameters. */
	if(gettaglen(&tag,&len,&der) < 0)
		return DK_ERR_FORMAT;
	if(tag != DER_SEQ)
		return DK_ERR_FORMAT;

	/* Fetch salt */
	if(gettaglen(&tag,&len,&der) < 0)
		return DK_ERR_FORMAT;
	if(tag != DER_OCTETSTRING)
		return DK_ERR_FORMAT;
	if(len != 8)
		return DK_ERR_FORMAT;
	R_memcpy(salt,der,8);
	der += 8;

	/* Fetch iteration count */

	if(getsmallint(iterationCount,&der) < 0)
		return DK_ERR_FORMAT;

   /* Fetch encrypted private key */
   if (gettaglen(&tag, &len, &der) < 0)
		return DK_ERR_FORMAT;
   if (tag != DER_OCTETSTRING)
		return DK_ERR_FORMAT;
   if (der+len != der_end)	/* Should match end of string */
		return DK_ERR_FORMAT;

	if(len > maxLen)
		return DK_ERR_FORMAT;
	R_memcpy(encBytes,der,len);
	*encLen = len;

	return 0;
}

/* Extensions for certificate encoding follow.
 */

#define DER_PRINTABLESTRING 0x13
#define DER_T61STRING 0x14
#define	DER_UTC		0x17

#define LEN_OF_MONTH(year, month) \
  ((((year) % 4) || (month) != 2) ? MONTH_LENS[((month)-1)] : 29)

#define SECONDS_IN_DAY ((unsigned long)3600 * (unsigned long)24)
    
static unsigned int MONTH_LENS[] =
  {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* Attribute type ID - joint-iso-ccittt(2) ds(5) 4 followed by attrtype */
static unsigned char attr_type[] = { DER_OBJID, 3, 2*40+5, 4 };

/* Data structure specifying "algorithm=md2WithRSAEncryption" followed by
     NULL param
   iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) pkcs-1(1) 2
   Decodes to OBJECT_ID = 1 2 840 113549 1 1 2
 */
static unsigned char md2WithRSAEncryption[] =
  { DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02,
    DER_NULL, 0 };

/* Returns 0 if no error, nonzero if error
   Currently only accepts the 3-byte object identifiers for countryName,
     organizationName, etc.  Also, only accepts PrintableString (no T.61).
 */
int DERToDistinguishedName (der, dn)
unsigned char **der;
DistinguishedNameStruct *dn;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *der1;
  int i, num_RDNs = 0, num_values = 0, sameSET;
  
  /* Pre-zeroize name struct so byte-wise comparison of two
       structs for the same name will be the same. */
  R_memset ((POINTER)dn, 0, sizeof (*dn));

  if (gettaglen (&tag, &len, der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
    
  /* AVAValues buffers are already zeroized. */
  for(i=0;i<MAX_AVA;i++)
    dn->AVATypes[i] = -1;

  for(i=0;i<MAX_RDN;i++)
    dn->RDNIndexStart[i] = dn->RDNIndexEnd[i] = -1;
    
  der1 = *der + len;
    
  while(*der < der1) {
    char attr;
      
    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    
    if(tag == DER_SEQ && num_RDNs) {
      /* same as last set */
      sameSET = 1;
      goto in_set;
    } else
      sameSET = 0;
      
    if(tag != DER_SET)
      return DK_ERR_FORMAT;
      
    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
      return DK_ERR_FORMAT;
  in_set:
    if (chkdata(der, attr_type, (unsigned int)sizeof(attr_type)) < 0)
      return DK_ERR_ALG;
    
    attr = *(*der)++;

    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    if (tag != DER_PRINTABLESTRING && tag != DER_T61STRING)
      return DK_ERR_FORMAT;
    if(len > MAX_NAME_LENGTH)
      return DK_ERR_FORMAT;
    
    if(num_values < MAX_AVA && num_RDNs < MAX_RDN) {
      /* Set AVAValues as a C string. */
      R_memcpy ((POINTER)dn->AVAValues[num_values], (POINTER)(*der), len);
      /* No need to set null terminator since buffer is already zeroized. */
    
      dn->AVATypes[num_values] = attr;
      dn->AVAIsT61[num_values] = (tag == DER_T61STRING ? 1 : 0);
      if(!sameSET) {
        /* new RDN */
        if(num_RDNs)
          /* Indicate where the end of the previous RDN was. */
          dn->RDNIndexEnd[num_RDNs-1] = num_values - 1;
        dn->RDNIndexStart[num_RDNs++] = num_values;
      }
      num_values++;
    }
    (*der) += len;
    
  }
  if(num_RDNs)
    /* Indicate where the end of the final RDN is. */
    dn->RDNIndexEnd[num_RDNs-1] = num_values - 1;

  return 0;
}

/* Read a large integer from the DER byte string pointed to by p.
 * Advance p as we read.  Put it into buffer n, of length nsize.
 * Zeroes out remaining bytes.
 * DOES NOT EXPECT AN INTEGER TAG. Caller must pass in length of of bits string
 * Return negative on error.
 */
static int getlargeunsignedbitstring (n, nsize, p, len)
unsigned char *n;
unsigned int nsize;
unsigned char **p;
int len;
{
  int extra = nsize - len;

  if (extra < 0)
    return -1;
  while (len--)
    *n++ = *(*p)++;
  while(extra--)
    *n++ = 0;
      
  return 0;
}

static void DateToSeconds (time, year, month, day, hour, minute, second)
unsigned long *time;
int year, month, day, hour, minute, second;
{
  if (year < 70)
    /* this is a year from 2000 to 2069 (intead of 1900 to 1969) */
    year += 100;
  
  /* "Carry" changes in minutes and hours through day, month and year.
   */
  if (minute < 0) {
    minute += 60;
    hour--;
  }
  else if (minute > 59) {
    minute -= 60;
    hour++;
  }
  
  if (hour < 0) {
    hour += 24;
    day--;
    if (day < 1) {
      month--;
      if (month < 1) {
        month += 12;
        year--;
        /* if year came in as 0, it was converted to 100, so the year cannot
           fall below 0 */
      }
      day += LEN_OF_MONTH (year, month);
    }
  }
  else if (hour > 23) {
    hour -= 24;
    day++;

    if (day > (int) LEN_OF_MONTH (year, month)) {
      day -= LEN_OF_MONTH (year, month);
      month++;
      if (month > 12) {
        month -= 12;
        year++;
      }
    }
  }
  
  *time = (unsigned long)second + (unsigned long)60 * (unsigned long)minute +
    (unsigned long)3600 * (unsigned long)hour +
    SECONDS_IN_DAY * (unsigned long)(day-1);
  
  /* Count month down to 2, adding up the number of seconds in the previous
       month.
   */
  while (month > 1) {
    *time += SECONDS_IN_DAY * (unsigned long)LEN_OF_MONTH (year, month - 1);
    month --;
  }

  /* Count year down to 71, adding up the number of seconds in the previous
       year.
   */
  while (year > 70) {
    *time += (year-1) % 4 ?
      (SECONDS_IN_DAY * (unsigned long)365)
      : (SECONDS_IN_DAY * (unsigned long)366);
    year--;
  }
}

/* Returns 0 if no error, nonzero if error.
   This sets time to seconds since 1970.  Also, if the incoming
     DER has a year less than '70', assume it is after the year 2000.
 */
static int DERToUTC (der, time)
unsigned char **der;
unsigned long *time;
{
  UINT2 tag;
  unsigned int len;
  char s[64],*sp;
  int year, month, day, hour, minute, second;
  
  if (gettaglen(&tag,&len,der) < 0)
    return DK_ERR_FORMAT;
  
  if(tag != DER_UTC)
    return DK_ERR_FORMAT;
  
  sp = s;
  while(len--)
    *sp++ = *(*der)++;
  *sp = 0;

  /* now parse the string. */
  sp = s;
  year = ((*sp++) - '0') * 10;
  year += *sp++ - '0';
  month = ((*sp++) - '0') * 10;
  month += *sp++ - '0';
  day = ((*sp++) - '0') * 10;
  day += *sp++ - '0';
  hour = ((*sp++) - '0') * 10;
  hour += *sp++ - '0';
  minute = ((*sp++) - '0') * 10;
  minute += *sp++ - '0';
  second = 0;
  
  if(*sp != 'Z') {  /* Z means is local time -- done. */
    if(*sp != '+' && *sp != '-') {
      /* get seconds */
      second = ((*sp++) - '0') * 10;
      second += *sp++ - '0';
    }
    
    if(*sp != 'Z') {  /* Z means is local time -- done. */
      int diff;
      
      if(*sp == '+') {    /* time is ahead, so subtract to get GMT. */
        sp++;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        hour -= diff;
        
        if(*sp++ != '\'')
          return DK_ERR_FORMAT;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        minute -= diff;
        if(*sp != '\'')
          return DK_ERR_FORMAT;
      } else if(*sp == '-') {   /* time is behind, so add to get GMT. */
        sp++;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        hour += diff;
        
        if(*sp++ != '\'')
          return DK_ERR_FORMAT;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        minute += diff;
        if(*sp != '\'')
          return DK_ERR_FORMAT;
      } else
        return DK_ERR_FORMAT;
    }
  }
  
  DateToSeconds (time, year, month, day, hour, minute, second);
  
  return 0;
}

/* Returns length advanced for OK, negative for error.  innderDER and
     innerDERLen will give the der portion up to end of CertificateInfo but
     not including outer signature alg & signature.  This is useful
     because the signature is of the CertificateInfo portion, DER coded,
     only.
   Note: This code does not support parsing the version and
     hence will only support default version certificates.  This needs to
     be fixed.
   THIS ALLOCATES SPACE FOR ISSUER & SUBJECT DN's
 */
int DERToCertificate (der, cert, innerDER, innerDERLen)
unsigned char *der;
CertificateStruct *cert;
unsigned char **innerDER;
unsigned int *innerDERLen;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *der1, *der_start = der;
  int result;

  if (gettaglen(&tag,&len,&der) < 0) /* SEQUENCE of cert, sig alg, signature */
    return DK_ERR_FORMAT;
  
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  der1 = der + len;                        /* Position of end of certificate */
   
  *innerDER = der;
  
  if (gettaglen(&tag,&len,&der) < 0)            /* SEQUENCE w/certinfo stuff */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  cert->version = 0;
  
  if (getlargeunsigned(cert->serialNumber,16, &der) < 0)
    return DK_ERR_FORMAT;
    
  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  if (chkdata
      (&der, md2WithRSAEncryption, (unsigned int)sizeof(md2WithRSAEncryption))
      < 0)
    return DK_ERR_ALG;
  cert->digestAlgorithm = DA_MD2;
  
  if(result = DERToDistinguishedName(&der,&cert->issuer))
    return result;
  
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  if(result = DERToUTC(&der,&cert->notBefore))
    return result;

  if(result = DERToUTC(&der,&cert->notAfter))
    return result;

  if(result = DERToDistinguishedName(&der,&cert->subject))
    return result;

  if((result = DERToPubKey(der,&cert->publicKey)) < 0)
    return result;
  /* Advance der past the public key.
   */
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  der += len;
  
  *innerDERLen = der - *innerDER;
  
  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  if (chkdata
      (&der, md2WithRSAEncryption, (unsigned int)sizeof(md2WithRSAEncryption))
      < 0)
    return DK_ERR_ALG;

  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_BITSTRING)
    return DK_ERR_FORMAT;
  if (*der++ != 0)                     /* Bitstring must be a mult of 8 bits */
    return DK_ERR_FORMAT;
  
  cert->signatureLen = len-1;                  /* subtract one for pad bits. */
  if(getlargeunsignedbitstring
     (cert->signature, sizeof(cert->signature), &der, len-1))
    return DK_ERR_ALG;
  
  if(der != der1)
    return DK_ERR_ALG;
  
  return (der - der_start);
}

/* Check for valid printable string character set.  Return a 1 if
     all characters are int the printable string set, 0 if not.
 */
int IsPrintableString (valuePointer, valueLen)
unsigned char *valuePointer;
unsigned int valueLen;
{
  unsigned char valueChar;
  unsigned int i;

  for (i = 0; i < valueLen; i++) {
    valueChar = valuePointer[i];
      
    if (! ((valueChar >= 0x41 && valueChar <= 0x5a) ||
           (valueChar >= 0x61 && valueChar <= 0x7a) ||
           valueChar == 0x20 ||
           (valueChar >= 0x27 && valueChar <= 0x3a && valueChar != 0x2a) ||
           valueChar == 0x3d || valueChar == 0x3f))
      return (0);
  }
  
  return (1);
}

