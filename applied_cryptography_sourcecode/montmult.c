/*
  Author:  Pate Williams (c) 1997

  Montgomery multiplication. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes
  et al Section 14.3.2 pages 600 - 603.
*/

#include <stdio.h>
#include <stdlib.h>
#include "lip.h"

#define DEBUG

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

void Montgomery_multiplication(long b, long n,
                               verylong zm, verylong zx,
                               verylong zy, verylong *zA)
{
  long i, n1 = n + 1, u, mp, *a, *m, *x, *y;
  verylong za = 0, zb = 0, zc = 0, zd = 0, zs = 0;

  a = calloc(n1, sizeof(long));
  m = calloc(n1, sizeof(long));
  x = calloc(n1, sizeof(long));
  y = calloc(n1, sizeof(long));
  if (a == 0 || m == 0 || x == 0 || y == 0) {
    printf("*error*\ncan't get memory from Montgomery");
    printf(" multiplication");
    exit(1);
  }
  zintoz(b, &zb);
  zinvmod(zm, zb, &za);
  znegate(&za);
  mp = zsmod(za, b);
  radix_representation(b, n1, m, zm);
  radix_representation(b, n1, x, zx);
  radix_representation(b, n1, y, zy);
  zzero(zA);
  for (i = 0; i < n; i++) {
    radix_representation(b, n1, a, *zA);
    u = ((a[0] + x[i] * y[0]) * mp) % b;
    zsmul(zy, x[i], &za);
    zsmul(zm, u, &zc);
    zadd(*zA, za, &zs);
    zadd(zs, zc, &zd);
    zsdiv(zd, b, zA);
    #ifdef DEBUG
    printf("%ld %ld %ld %ld ", i, x[i], x[i] * y[0], u);
    zwrite(za); printf(" ");
    zwrite(zc); printf(" ");
    zwriteln(*zA);
    #endif
  }
  if (zcompare(*zA, zm) >= 0) {
    zsub(*zA, zm, &za);
    zcopy(za, zA);
  }
  free(a);
  free(m);
  free(x);
  free(y);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&zs);
}

int main(void)
{
  long b = 10, n = 5;
  verylong zA = 0, zm = 0, zx = 0, zy = 0;

  zintoz(72639l, &zm);
  zintoz(5792l, &zx);
  zintoz(1229l, &zy);
  Montgomery_multiplication(b, n, zm, zx, zy, &zA);
  zwriteln(zA);
  zfree(&zA);
  zfree(&zm);
  zfree(&zx);
  zfree(&zy);
  return 0;
}