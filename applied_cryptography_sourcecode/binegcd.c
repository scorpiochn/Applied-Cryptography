/*
  Author:  Pate Williams (c) 1997

  Extended binary Euclid algorithm. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et
  al Section 14.4.3 pages 608 - 610.
*/

#include <stdio.h>
#include "lip.h"

#define DEBUG

void zbinary_ext_gcd(verylong zx, verylong zy,
                     verylong *za, verylong *zb,
                     verylong *zv)
/* returns a * x + b * y = v, v = gcd(x, y) */
{
  verylong zA = 0, zB = 0, zC = 0, zD = 0;
  verylong zX = 0, zY = 0, zc = 0,  zg = 0;
  verylong zu = 0;

  zone(&zg);
  zcopy(zx, &zX);
  zcopy(zy, &zY);
  while (!zodd(zX) && !zodd(zY)) {
    zrshift(zX, 1l, &zc);
    zcopy(zc, &zX);
    zrshift(zY, 1l, &zc);
    zcopy(zc, &zY);
    zlshift(zg, 1l, &zc);
    zcopy(zc, &zg);
  }
  zcopy(zX, &zu);
  zcopy(zY, zv);
  zone(&zA);
  zzero(&zB);
  zzero(&zC);
  zone(&zD);
  do {
    while (!zodd(zu)) {
      zrshift(zu, 1l, &zc);
      zcopy(zc, &zu);
      if (!zodd(zA) && !zodd(zB)) {
        zrshift(zA, 1l, &zc);
        zcopy(zc, &zA);
        zrshift(zB, 1l, &zc);
        zcopy(zc, &zB);
      }
      else {
        zadd(zA, zY, &zc);
        zrshift(zc, 1l, &zA);
        zsub(zB, zX, &zc);
        zrshift(zc, 1l, &zB);
      }
    }
    while (!zodd(*zv)) {
      zrshift(*zv, 1l, &zc);
      zcopy(zc, zv);
      if (!zodd(zC) && !zodd(zD)) {
        zrshift(zC, 1l, &zc);
        zcopy(zc, &zC);
        zrshift(zD, 1l, &zc);
        zcopy(zc, &zD);
      }
      else {
        zadd(zC, zY, &zc);
        zrshift(zc, 1l, &zC);
        zsub(zD, zX, &zc);
        zrshift(zc, 1l, &zD);
      }
    }
    if (zcompare(zu, *zv) >= 0) {
      zsub(zu, *zv, &zc);
      zcopy(zc, &zu);
      zsub(zA, zC, &zc);
      zcopy(zc, &zA);
      zsub(zB, zD, &zc);
      zcopy(zc, &zB);
    }
    else {
      zsub(*zv, zu, &zc);
      zcopy(zc, zv);
      zsub(zC, zA, &zc);
      zcopy(zc, &zC);
      zsub(zD, zB, &zc);
      zcopy(zc, &zD);
    }
    #ifdef DEBUG
    zwrite(zu); printf(" ");
    zwrite(*zv); printf(" ");
    zwrite(zA); printf(" ");
    zwrite(zB); printf(" ");
    zwrite(zC); printf(" ");
    zwriteln(zD);
    #endif
  } while (zscompare(zu, 0l) != 0);
  zcopy(zC, za);
  zcopy(zD, zb);
  zmul(zg, *zv, &zc);
  zcopy(zc, zv);
  zfree(&zA);
  zfree(&zB);
  zfree(&zC);
  zfree(&zD);
  zfree(&zX);
  zfree(&zY);
  zfree(&zc);
  zfree(&zg);
  zfree(&zu);
}

int main(void)
{
  verylong za = 0, zb = 0, zv = 0, zx = 0, zy = 0;

  zintoz(693l, &zx);
  zintoz(609l, &zy);
  zbinary_ext_gcd(zx, zy, &za, &zb, &zv);
  printf("a = "); zwriteln(za);
  printf("b = "); zwriteln(zb);
  printf("v = "); zwriteln(zv);
  zfree(&za);
  zfree(&zb);
  zfree(&zv);
  zfree(&zx);
  zfree(&zy);
  return 0;
}
