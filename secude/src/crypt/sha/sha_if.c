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
 *  SHS interface module between sec_hash, sec_sign, sec_verify and 
 *  the C version by Peter Gutmann, HPACK Conspiracy Secret Laboratory
 *  
 *
 *  WS 8.9.92
 *
 *  Last change: 8.9.92
 *
 *  Imports:
 *
 *  shsInit(shsInfo)
 *  shsUpdate(shsInfo, inBuf, inLen)
 *  shsFinal(shsInfo)
 *
 *
 *  sha_hash(in_octets, hash_result, more)
 *
 */

#include "sha.h"
#include <secure.h>

RC sha_hash(in_octets, hash_result, more)
OctetString *in_octets, *hash_result;
More more;
{
        static char first = TRUE;
        static SHS_INFO shsInfo;

        if(first) {
                shsInit(&shsInfo);
                first = FALSE;
        }
        shsUpdate(&shsInfo, (BYTE *) in_octets->octets, in_octets->noctets);

        if(more == END) {
                first = TRUE;
                shsFinal(&shsInfo);
                /* memory of hash_result->octets provided by calling program */
                bcopy(&shsInfo.digest[0], (BYTE *) hash_result->octets, SHS_DIGESTSIZE);
                hash_result->noctets = SHS_DIGESTSIZE;
        }
        return(0);
}
