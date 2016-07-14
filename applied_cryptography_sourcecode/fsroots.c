/*
  Author:  Pate Williams (c) 1997

  The following program determines the square
  roots of a very long integer modulo a
  composite very long integer n = p * q where
  p and q are prime. See "Handbook of Applied
  Cryptography" by Alfred J. Menezes et al
  3.5.1 Section pages 100 - 101, 3.34 Algorithm
  page 100 and 3.5.2 Section pages 101 - 102
  3.44 Algorithm page 102.
*/

#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include "lip.h"

void zsquare_root(verylong za, verylong zp, verylong *zr)
{
  long i, s = 0, t;
  verylong zb = 0, zc = 0, zd = 0, ze = 0, zi = 0;
  verylong zq = 0, zs = 0, zt = 0, zx = 0, zy = 0;

  if (zcompare(za, zp) < 0) zcopy(za, &ze);
  else
    zmod(za, zp, &ze);
  if (zscompare(ze, 0l) == 0)
    zzero(zr);
  else if (zjacobi(ze, zp) == - 1)
    zzero(zr);
  else {
    do
      zrandomb(zp, &zb);
    while (zscompare(zb, 0l) == 0 || zjacobi(zb, zp) != - 1);
    zsadd(zp, - 1l, &zq);
    zcopy(zq, &zy);
    do {
      zrshift(zy, 1l, &zt);
      s++;
      t = zodd(zt);
      zcopy(zt, &zy);
    } while (!t);
    zinvmod(ze, zp, &zi);
    zexpmod(zb, zt, zp, &zc);
    zsadd(zt, 1l, &zs);
    zrshift(zs, 1l, &zx);
    zexpmod(ze, zx, zp, zr);
    for (i = 1; i < s; i++) {
      zsq(*zr, &zs);
      zmulmod(zs, zi, zp, &zx);
      zsexpmod(zx, pow(2, s - i - 1), zp, &zd);
      if (zcompare(zd, zq) == 0) {
        zmulmod(*zr, zc, zp, &zx);
        zcopy(zx, zr);
      }
      zmulmod(zc, zc, zp, &zx);
      zcopy(zx, &zc);
    }
  }
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&ze);
  zfree(&zi);
  zfree(&zq);
  zfree(&zs);
  zfree(&zt);
  zfree(&zx);
}

void zsquare_roots(verylong za, verylong zp, verylong zq,
                   verylong *zx1, verylong *zx2,
                   verylong *zy1, verylong *zy2)
{
  verylong zb = 0, zc = 0, zd = 0, ze = 0, zg = 0;
  verylong zn = 0, zr = 0, zs = 0, zx = 0, zy = 0;
  verylong zt = 0, zz = 0;

  zsquare_root(za, zp, &zr);
  if (zscompare(zr, 0l) != 0) {
    zsqrtmod(za, zp, &zx);
    assert(zcompare(zr, zx) == 0);
  }
  zsquare_root(za, zq, &zs);
  if (zscompare(zs, 0l) != 0) {
    zsqrtmod(za, zq, &zx);
    assert(zcompare(zs, zx) == 0);
  }
  zexteucl(zp, &zc, zq, &zd, &zg);
  if (zscompare(zg, 1l) == 0) {
    zmul(zp, zq, &zn);
    zmulmod(zr, zd, zn, &zb);
    zmulmod(zb, zq, zn, &zt);
    zmulmod(zs, zc, zn, &ze);
    zmulmod(ze, zp, zn, &zz);
    zaddmod(zt, zz, zn, &zx);
    zmulmod(zr, zq, zn, &zb);
    zmulmod(zs, zc, zn, &ze);
    zmulmod(ze, zp, zn, &zz);
    zsubmod(zt, zz, zn, &zy);
    zmod(zx, zn, zx1);
    znegate(&zx);
    zmod(zx, zn, zx2);
    zmod(zy, zn, zy1);
    znegate(&zy);
    zmod(zy, zn, zy2);
  }
  else {
    zzero(zx1);
    zzero(zx2);
    zzero(zy1);
    zzero(zy2);
  }
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&ze);
  zfree(&zg);
  zfree(&zn);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  zfree(&zx);
  zfree(&zy);
  zfree(&zz);
}

int main(void)
{
  char answer[256];
  verylong za = 0, zp = 0, zq = 0, zu = 0, zv = 0;
  verylong zx = 0, zy = 0;

  do {
    printf("enter the number whose square root is sought\n");
    zread(&za);
    printf("enter one of the modulus' prime factors\n");
    zread(&zp);
    printf("enter the other modulus prime factor\n");
    zread(&zq);
    zsquare_roots(za, zp, zq, &zu, &zv, &zx, &zy);
    printf("the square roots modulo the composite number are:\n");
    zwriteln(zu);
    zwriteln(zv);
    zwriteln(zx);
    zwriteln(zy);
    printf("compute another square root (n or y)? ");
    scanf("%s", answer);
  } while (tolower(answer[0]) == 'y');
  zfree(&za);
  zfree(&zp);
  zfree(&zq);
  zfree(&zu);
  zfree(&zv);
  zfree(&zx);
  zfree(&zy);
  return 0;
}
