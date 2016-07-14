/*
  Author:  Pate Williams (c) 1997

  Left-to-right k-ary exponentiation. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et
  al 14.6.1 Section pages 614 - 616.
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "lip.h"

#define DEBUG

void radix_representation(long b, long *a, long *t, verylong za)
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
  *t = i;
  zfree(&zb);
  zfree(&zq);
  zfree(&zr);
  zfree(&zx);
}

void ltr_k_ary(long b, verylong ze, verylong zg, verylong *zA)
{
  long e[8192], i, t;
  verylong za = 0, *zg1;

  radix_representation(b, e, &t, ze);
  #ifdef DEBUG
  for (i = t - 1; i >= 0; i--)
    printf("%d", e[i]);
  printf("\n");
  #endif
  zg1 = calloc(b, sizeof(verylong));
  zone(&zg1[0]);
  for (i = 1; i < b; i++)
    zmul(zg1[i - 1], zg, &zg1[i]);
  zone(zA);
  for (i = t - 1; i >= 0; i--) {
    zsexp(*zA, b, &za);
    zmul(za, zg1[e[i]], zA);
  }
  free(zg1);
  zfree(&za);
}

int main(void)
{
  long b, e = 127l, k = 1l;
  verylong zA = 0, za = 0, ze = 0, zg = 0;

  b = pow(2, k);
  zintoz(2l, &zg);
  zintoz(e, &ze);
  ltr_k_ary(b, ze, zg, &zA);
  zwriteln(zA);
  zexp(zg, ze, &za);
  zwriteln(za);
  zfree(&zA);
  zfree(&za);
  zfree(&ze);
  zfree(&zg);
  return 0;
}
