/* FEALNX.H - Specification for FEALNX package.
Version of 92.12.28 by Peter Pearson.
*/

/* Definitions
 * -----------
 * The user of this package is discouraged from referring to the internals
 * of these data types, in order that the implementation may be changed
 * without affecting client programs.
 */

typedef struct {
       int NRounds ;
       unsigned char *KSchedule ;
    } *KeyScheduleType ;

typedef unsigned char DataBlockType[8] ;

/* Services
 * --------
 * The intended usage of this package:
 *     #include "fealnx.h"
 *     KeyScheduleType KS ;
 *     unsigned char Key[16] = { ... } ;
 *     KS = NewKeySchedule( 32, Key ) ;
 *     Encrypt( KS, Plain, Cipher ) ;
 *     free( KS ) ;
 */

/***********************************************************************
 * NewKeySchedule takes a 16-byte key, builds a key schedule, and
 * returns a pointer to that key schedule. The caller should free
 * the key schedule (using the standard C runtime routine "free")
 * when it is no longer needed.
 * NewKeySchedule returns the value NULL (stdlib.h) if memory cannot
 * be allocated for the key schedule.
 **********************************************************************/

KeyScheduleType NewKeySchedule( int Rounds, unsigned char *Key ) ;

/**********************************************************************
 * Encrypt and Decrypt to the obvious. Note that the key schedule must
 * have been established by prior call to NewKeySchedule.
 **********************************************************************/

void Encrypt( KeyScheduleType K, DataBlockType Plain, DataBlockType Cipher ) ;
void Decrypt( KeyScheduleType K, DataBlockType Cipher, DataBlockType Plain ) ;


