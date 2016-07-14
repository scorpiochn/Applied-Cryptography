#ifdef __alpha
#include	"des-private.h"

des_u_long_64	des_spe_table_64[] = {
#define Cast(x) ((unsigned long)((unsigned int)(x)))
#define Pair(a,b,c) ((Cast(b)<<32) | (Cast(a))),
#include "spe-table-64.h"
#undef Cast
#undef Pair
};
#endif
