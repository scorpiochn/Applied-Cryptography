#ifndef _BIGNUM_H_
#define _BIGNUM_H_

#include "internal.h"

typedef struct big_struct bignum;

#define BIG_SIGN_0 0
#define BIG_SIGN_PLUS 1
#define BIG_SIGN_MINUS -1

#define BIG_OK 0
#define BIG_MEMERR 1
#define BIG_DIV_ZERO 2
#define BIG_ARGERR 3

#ifdef BIG_SHORT_NAMES
#define big_set_big	big_sb
#define big_set_long	big_sl
#define big_set_ulong	big_usl
#define big_string	big_rs
#define big_leqp	big_lq
#define big_expt	big_x
#endif

/* External variables to take care about when using the bignums */
typedef int bigerr_t;
extern int big_errno;
extern char *big_end_string;

/* External functions to enable use of bignums */
extern bigerr_t big_init_pkg();
extern void big_release_pkg();

extern bigerr_t big_create();
extern void big_destroy();

extern unsigned long big_bitcount();

extern bigerr_t big_set_big();
extern void big_set_long();
extern void big_set_ulong();
extern bigerr_t big_set_string();

extern int big_long();
extern int big_ulong();
extern char *big_string();

extern int big_sign();
extern bigerr_t big_abs();

extern bigerr_t big_negate();

extern int big_compare();
extern int big_lessp();
extern int big_leqp();
extern int big_equalp();
extern int big_geqp();
extern int big_greaterp();

extern int big_zerop();
extern int big_evenp();
extern int big_oddp();

extern bigerr_t big_add();
extern bigerr_t big_sub();

extern bigerr_t big_mul();

extern bigerr_t big_trunc();
extern bigerr_t big_floor();
extern bigerr_t big_ceil();
extern bigerr_t big_round();

extern bigerr_t big_random();

extern bigerr_t big_expt();
extern bigerr_t big_exptmod();
extern bigerr_t big_gcd();

#ifndef NULL
#define NULL 0
#endif

#endif /* _BIGNUM_H_ */
