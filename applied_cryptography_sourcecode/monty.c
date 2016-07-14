/*
  Author:  Pate Williams (c) 1997

  Montgomery reduction. See "Handbook of Applied
  Cryptography" by Alfred J. Menezes et al Section
  14.3.2 pages 600 - 603.
*/

#include <malloc.h>
#include <stdio.h>
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

void Montgomery_reduction(long b, long n,
                          verylong zR, verylong zT,
                          verylong zm, verylong *zA)
{
  long *a, i, n2 = 2 * n;
  verylong za = 0, zb = 0, zc = 0, zd = 0, ze = 0;
  verylong zu = 0, zmp = 0;

  a = malloc(n2 * sizeof(long));
  radix_representation(b, n2, a, zT);
  zintoz(b, &zb);
  zinvmod(zm, zb, &za);
  znegate(&za);
  zmod(za, zb, &zmp);
  zone(&zc);
  #ifdef DEBUG
  zwriteln(zmp);
  #endif
  zcopy(zT, zA);
  for (i = 0; i < n; i++) {
    zintoz(a[i], &za);
    zmulmod(za, zmp, zb, &zu);
    zmul(zu, zm, &zd);
    zmul(zc, zd, &ze);
    zadd(*zA, ze, &za);
    zcopy(za, zA);
    zmul(zb, zc, &zd);
    zcopy(zd, &zc);
    #ifdef DEBUG
    printf("%ld ", i);
    zwrite(zu); printf(" ");
    zwrite(ze); printf(" ");
    zwriteln(*zA);
    #endif
    radix_representation(b, n2, a, *zA);
  }
  zdiv(*zA, zR, &za, &zb);
  zcopy(za, zA);
  free(a);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&ze);
  zfree(&zu);
  zfree(&zmp);
}

int main(void)
{
  long b = 10, n = 5;
  verylong zA = 0, zR = 0, zT = 0, zm = 0;

  zintoz(100000l, &zR);
  zintoz(7118368l, &zT);
  zintoz(72639l, &zm);
  Montgomery_reduction(b, n, zR, zT, zm, &zA);
  zwriteln(zA);
  return 0;
}