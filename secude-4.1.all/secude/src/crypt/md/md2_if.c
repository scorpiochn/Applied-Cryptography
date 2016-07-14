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
 *  MD2 interface module between sec_hash, sec_sign, sec_verify and 
 *  the "RSA Data Security, Inc. MD2 Message Digest Algorithm"
 *  Reference C version
 *
 *  WS 27.2.91
 *
 *  Last change: 28.2.91
 *
 *  Imports from RSADSI:
 *
 *  MD2Init(mdContext)
 *  MD2Update(mdContext, inBuf, inLen)
 *  MD2Final(mdContext)
 *
 *  Exports to libdes.a or libSECUDE.a:
 *
 *  md2_hash(in_octets, hash_result, more)
 *
 */

#include "global.h"
#include "md2.h"
#include "secure.h"


RC md2_hash(in_octets, hash_result, more)
OctetString *in_octets, *hash_result;
More more;
{
        static char first = TRUE;
        static MD2_CTX mdContext;
	unsigned char digest[16];

        if(first) {
                MD2Init(&mdContext);
                first = FALSE;
        }
        MD2Update(&mdContext, in_octets->octets, in_octets->noctets);

        if(more == END) {
                first = TRUE;
                MD2Final(digest, &mdContext);
                /* memory of hash_result->octets provided by calling program */
                bcopy(&digest[0], hash_result->octets, 16);
                hash_result->noctets = 16;
        }
        return(0);
}
