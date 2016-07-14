/*
 *  SecuDE Release 4.1 (GMD)
 */
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

/*-----------------------------------------------------------------------*/
/* FILE  strong_init.c                                                   */
/*-----------------------------------------------------------------------*/

#ifdef X500
#ifdef STRONG

#include "secude-stub.h"


/*
 *    ObjectIdentifier macro (parameter obj) builds 
 *               ObjId <obj>_oid
 *    from <obj>_OID 
 *
 */

#if !defined(MAC) && !defined(__HP__)
#define ObjectIdentifier(obj)                                             \
        unsigned int obj/**/_oid_elements[] = obj/**/_oid_EL;             \
        ObjId obj/**/_oid = {                                             \
        sizeof(obj/**/_oid_elements)/sizeof(int), obj/**/_oid_elements }; \
        ObjId *obj/**/_OID = &obj/**/_oid;

#else
#define ObjectIdentifier(obj)                                             \
        unsigned int obj##_oid_elements[] = obj##_oid_EL;                 \
        ObjId obj##_oid = {                                               \
        sizeof(obj##_oid_elements)/sizeof(int), obj##_oid_elements };     \
        ObjId *obj##_OID = &obj##_oid
#endif /* MAC */


#define Acl_oid_EL       { 0, 9, 2342, 19200300, 99, 1, 2 }

ObjectIdentifier(Acl);


#endif


#else
/* dummy */
strong_init_dummy() 
{
	return(0);
}

#endif
