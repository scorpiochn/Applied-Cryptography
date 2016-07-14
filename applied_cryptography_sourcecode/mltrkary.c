/*
  Author:  Pate Williams (c) 1997

  Modified left-to-right k-ary exponentiation. See
  "Handbook of Applied Cryptography" by Alfred J.
  Menezes et al 14.6.1 Section pages 614 - 616.
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

void mltr_k_ary(long b, long k, verylong ze,
                verylong zg, verylong *zA)
{
  long i, j, l, t;
  long e[8192], h[8192], u[8192];
  verylong za = 0, zb = 0, zc = 0, *zg1;

  radix_representation(b, e, &t, ze);
  #ifdef DEBUG
  for (i = t - 1; i >= 0; i--)
    printf("%ld", e[i]);
  printf("\n");
  #endif
  for (i = 0; i < t; i++) {
    j = e[i];
    if (j == 0) h[i] = u[i] = 0;
    else if (j & 1)  h[i] = 0, u[i] = j;
    else {
      l = 0;
      while (!(j & 1)) j >>= 1, l++;
      h[i] = l, u[i] = j;
    }
  }
  #ifdef DEBUG
  for (i = t - 1; i >= 0; i--)
    printf("%ld", h[i]);
  printf("\n");
  for (i = t - 1; i >= 0; i--)
    printf("%ld", u[i]);
  printf("\n");
  #endif
  zg1 = calloc(b + 2, sizeof(verylong));
  zone(&zg1[0]);
  zcopy(zg, &zg1[1]);
  zsq(zg, &zg1[2]);
  for (i = 1; i <= b / 2 - 1; i++)
    zmul(zg1[2 * i - 1], zg1[2], &zg1[2 * i + 1]);
  zone(zA);
  for (i = t - 1; i >= 0; i--) {
    zsexp(*zA, pow(2, k - h[i]), &za);
    zmul(za, zg1[u[i]], &zb);
    if (h[i] == 0) zcopy(zb, zA);
    else
      zsexp(zb, pow(2, h[i]), zA);
  }
  free(zg1);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
}

int main(void)
{
  long b = 8l, k = 3l;
  verylong zA = 0, za = 0, ze = 0, zg = 0;

  zintoz(116l, &ze);
  zintoz(2l, &zg);
  mltr_k_ary(b, k, ze, zg, &zA);
  zwriteln(zA);
  zsexp(zg, 116l, &za);
  zwriteln(za);
  zintoz(127l, &ze);
  zintoz(2l, &zg);
  mltr_k_ary(b, k, ze, zg, &zA);
  zwriteln(zA);
  zsexp(zg, 127l, &za);
  zwriteln(za);
  b = 2l, k = 1l;
  zintoz(129l, &ze);
  zintoz(2l, &zg);
  mltr_k_ary(b, k, ze, zg, &zA);
  zwriteln(zA);
  zsexp(zg, 129l, &za);
  zwriteln(za);
  zfree(&zA);
  zfree(&za);
  zfree(&ze);
  zfree(&zg);
  return 0;
}
