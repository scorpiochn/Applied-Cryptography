/*
  Author:  Pate Williams (c) 1997

  14.57 Algorithm Lehmer's gcd algorithm
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al page 607.
*/

#include <stdio.h>
#include "lip.h"

#define DEBUG

void radix_representation(long b, verylong zx,
                          long *a, long *t)
{
  long i = 0;
  verylong za = 0, zq = 0, zr = 0;

  zcopy(zx, &za);
  a[i++] = zsdiv(za, b, &zq);
  while (zscompare(zq, 0l) > 0) {
    zcopy(zq, &za);
    a[i++] = zsdiv(zq, b, &zr);
    zcopy(zr, &zq);
  }
  *t = i;
  zfree(&za);
  zfree(&zq);
  zfree(&zr);
}

void Lehmer_gcd(long b, verylong zx, verylong zy,
                verylong *zv)
{
  long A, B, C, D, q, qp, t;
  long xp, xt, yp, yt, xa[4096], ya[4096];
  verylong zT = 0, za = 0, zb = 0, zc = 0, zd = 0;
  verylong zu = 0;

  zcopy(zx, &za);
  zcopy(zy, &zb);
  while (zscompare(zb, b) > 0) {
    radix_representation(b, za, xa, &xt);
    radix_representation(b, zb, ya, &yt);
    xp = xa[xt - 1];
    yp = ya[yt - 1];
    A = D = 1, B = C = 0;
    if (xt == yt) {
      while (yp + C != 0 && yp + D != 0) {
        q  = (xp + A) / (yp + C);
        qp = (xp + B) / (yp + D);
        #ifdef DEBUG
        printf("%3ld %3ld %2ld %2ld %2ld %2ld %2ld %2ld\n",
               xp, yp, A, B, C, D, q, qp);
        #endif
        if (q != qp) break;
        t = A - q * C, A = C, C = t;
        t = B - q * D, B = D, D = t;
        t = xp - q * yp, xp = yp, yp = t;
      }
    }
    if (B == 0) {
      zmod(za, zb, &zT);
      zcopy(zb, &za);
      zcopy(zT, &zb);
    }
    else {
      zsmul(za, A, &zc);
      zsmul(zb, B, &zd);
      zadd(zc, zd, &zT);
      zsmul(za, C, &zc);
      zsmul(zb, D, &zd);
      zadd(zc, zd, &zu);
      zcopy(zT, &za);
      zcopy(zu, &zb);
    }
    #ifdef DEBUG
    zwrite(za); printf(" "); zwriteln(zb);
    #endif
  }
  while (zcompare(zb, 0l) > 0) {
    zmod(za, zb, &zu);
    zcopy(zb, &za);
    zcopy(zu, &zb);
    #ifdef DEBUG
    zwrite(za); printf(" "); zwriteln(zb);
    #endif
  }
  zcopy(za, zv);
  zfree(&zT);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&zu);
}

int main(void)
{
  long b = 1000;
  verylong zv = 0, zx = 0, zy = 0;

  zintoz(768454923l, &zx);
  zintoz(542167814l, &zy);
  Lehmer_gcd(b, zx, zy, &zv);
  printf("x = "); zwriteln(zx);
  printf("y = "); zwriteln(zy);
  printf("gcd(x, y) = "); zwriteln(zv);
  zfree(&zv);
  zfree(&zx);
  zfree(&zy);
  return 0;
}
