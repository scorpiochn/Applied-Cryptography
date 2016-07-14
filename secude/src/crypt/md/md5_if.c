/********************************************************************
 * Copyright (C) 1991, GMD. All rights reserved.                    *
 *                                                                  *
 *                                                                  *
 *                         NOTICE                                   *
 *                                                                  *
 *    Acquisition, use, and distribution of this module             *
 *    and related materials are subject to restrictions             *
 *    mentioned in each volume of the documentation.                *
 *                                                                  *
 ********************************************************************/

/*
 *  MD5 interface module between sec_hash, sec_sign, sec_verify and
 *  the "RSA Data Security, Inc. MD5 Message Digest Algorithm"
 *  Reference C version
 *
 *  WS 11.7.91
 *
 *  Last change: 11.7.91
 *
 *  Imports from RSADSI:
 *
 *  MD5Init(mdContext)
 *  MD5Update(mdContext, inBuf, inLen)
 *  MD5Final(mdContext)
 *
 *  Exports to libdes.a or libSECUDE.a:
 *
 *  md5_hash(in_octets, hash_result, more)
 *
 */

#include "global.h"
#include "md5.h"
#include "secure.h"


RC md5_hash(in_octets, hash_result, more)
OctetString *in_octets, *hash_result;
More more;
{
        static char first = TRUE;
        static MD5_CTX mdContext;
	unsigned char digest[16];

        if(first) {
                MD5Init(&mdContext);
                first = FALSE;
        }
        MD5Update(&mdContext, in_octets->octets, in_octets->noctets);

        if(more == END) {
                first = TRUE;
                MD5Final(digest, &mdContext);
                /* memory of hash_result->octets provided by calling program */
                bcopy(&digest[0], hash_result->octets, 16);
                hash_result->noctets = 16;
        }
        return(0);
}
