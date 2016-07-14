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
 *  MD4 interface module between sec_hash, sec_sign, sec_verify and
 *  the "RSA Data Security, Inc. MD4 Message Digest Algorithm"
 *  Reference C version
 *
 *  WS 27.2.91
 *
 *  Last change: 28.2.91
 *
 *  Imports from RSADSI:
 *
 *  MD4Init(mdContext)
 *  MD4Update(mdContext, inBuf, inLen)
 *  MD4Final(mdContext)
 *
 *  Exports to libdes.a or libSECUDE.a:
 *
 *  md4_hash(in_octets, hash_result, more)
 *
 */

#include "global.h"
#include "md4.h"
#include "secure.h"


RC md4_hash(in_octets, hash_result, more)
OctetString *in_octets, *hash_result;
More more;
{
        static char first = TRUE;
        static MD4_CTX mdContext;
	unsigned char digest[16];

        if(first) {
                MD4Init(&mdContext);
                first = FALSE;
        }
        MD4Update(&mdContext, in_octets->octets, in_octets->noctets);

        if(more == END) {
                first = TRUE;
                MD4Final(digest, &mdContext);
                /* memory of hash_result->octets provided by calling program */
                bcopy(&digest[0], hash_result->octets, 16);
                hash_result->noctets = 16;
        }
        return(0);
}
