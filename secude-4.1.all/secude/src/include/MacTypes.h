/***********
 * Name  : MacTypes.h 
 * Author: Armin Schmid, GMD-DA-RH
 * Date  : 05.05.92
 *******/
 
#ifndef _MACTYPES_
#define _MACTYPES_

#include <types.h>
#include <size_t.h>

/***********
 * TypeDefs
 ******/

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;
typedef unsigned short  ushort;         /* System V compatibility */
typedef unsigned int    uint;           /* System V compatibility */
typedef char *caddr_t;
typedef unsigned short mode_t;

typedef size_t off_t;

struct  stat                            /* Aus Kompabilitaetsgruenden mit Unix */
   {
   OSErr error;
   size_t st_size;
   };                       

#endif
