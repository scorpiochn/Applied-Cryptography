/*
  Author:  Pate Williams (c) 1997

  Barrett modular reduction. See "Handbook of Applied
  Cryptography" by Alfred J. Menezes et al 14.3.3
  Section pages 603 - 604.
*/

#include <stdio.h>
#include "lip.h"

#define DEBUG

#ifdef DEBUG
void radix_representation(long b, long n, long *a, verylong za)
{
  long i = 0;
  verylong zb = 0, zq = 0, zr = 0, zx = 0;

  zintoz(b, &zb);
  zcopy(za, &zx);
  do {
    zdiv(zx, zb, &zq, &zr);
    a[i++] = ztoint(zr);
    zcopy(zq, &zx);
  } while (zscompare(zq, 0l) != 0);
  while (i < n) a[i++] = 0;
  zfree(&zb);
  zfree(&zq);
  zfree(&zr);
  zfree(&zx);
}
#endif

void Barrett_reduction(long b, long k,
                       verylong zm, verylong zmu,
                       verylong zx, verylong *zr)
{
  verylong zb = 0, zbk = 0, zq1 = 0, zq2 = 0, zq3 =0;
  verylong zr1 = 0, zr2 = 0;

  zintoz(b, &zb);
  zsexp(zb, k - 1, &zbk);
  zdiv(zx, zbk, &zq1, &zq2);
  zmul(zq1, zmu, &zq2);
  zsexp(zb, k + 1, &zbk);
  zdiv(zq2, zbk, &zq3, &zr1);
  zmod(zx, zbk, &zr1);
  zmulmod(zq3, zm, zbk, &zr2);
  zsub(zr1, zr2, zr);
  if (zscompare(*zr, 0l) < 0) {
    zadd(*zr, zbk, &zb);
    zcopy(zb, zr);
  }
  #ifdef DEBUG
  {
    long a[256], i, k2 = (k + 1) * 2;

    radix_representation(b, k2, a, zq1);
    printf("q1 = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(zq1);
    radix_representation(b, k2, a, zq2);
    printf("q2 = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(zq2);
    radix_representation(b, k2, a, zq3);
    printf("q3 = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(zq3);
    radix_representation(b, k2, a, zr1);
    printf("r1 = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(zr1);
    radix_representation(b, k2, a, zr2);
    printf("r2 = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(zr2);
    radix_representation(b, k2, a, *zr);
    printf("r  = ");
    for (i = k2 - 1; i >= 0; i--)
      printf("%ld", a[i]);
    printf(" = ");
    zwriteln(*zr);
  }
  #endif
  while (zcompare(*zr, zm) >= 0) {
    zsub(*zr, zm, &zb);
    zcopy(zb, zr);
  }
  zfree(&zb);
  zfree(&zbk);
  zfree(&zq1);
  zfree(&zq2);
  zfree(&zq3);
  zfree(&zr1);
  zfree(&zr2);
}

int main(void)
{
  verylong zm = 0, zmu = 0, zr = 0, zx = 0;

  zintoz(47l, &zm);
  zintoz(87l, &zmu);
  zintoz(3561l, &zx);
  Barrett_reduction(4, 3, zm, zmu, zx, &zr);
  zfree(&zm);
  zfree(&zmu);
  zfree(&zr);
  zfree(&zx);
  return 0;
}
