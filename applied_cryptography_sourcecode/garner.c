/*
  Author:  Pate Williams (c) 1997

  14.71 Algorithm Garner's Algorithm for CRT
  See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al page 612.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define CRT_SIZE 8192l

void Garner(long t, verylong *zm, verylong *zv, verylong *zx)
/* solution of the Chinese remaider theorem */
{
  long i, j;
  verylong za = 0, zb = 0, zu = 0, zC[CRT_SIZE];

  for (i = 0; i < CRT_SIZE; i++) zC[i] = 0;
  for (i = 1; i < t; i++) {
    zone(&zC[i]);
    for (j = 0; j <= i - 1; j++) {
      zinvmod(zm[j], zm[i], &zu);
      zmulmod(zu, zC[i], zm[i], &za);
      zcopy(za, &zC[i]);
    }
  }
  zcopy(zv[0], &zu);
  zcopy(zu, zx);
  for (i = 1; i < t; i++) {
    zsub(zv[i], *zx, &za);
    zmulmod(za, zC[i], zm[i], &zu);
    zone(&za);
    for (j = 0; j <= i - 1; j++) {
      zmul(za, zm[j], &zb);
      zcopy(zb, &za);
    }
    zmul(za, zu, &zb);
    zadd(*zx, zb, &za);
    zcopy(za, zx);
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zu);
  for (i = 0; i < CRT_SIZE; i++) zfree(&zC[i]);
}

long OddRandom(long bit_length)
{
  long i, mask = 1, n;

  bit_length--;
  for (i = 1; i <= bit_length; i++)
    mask |= 1 << i;
  if (bit_length < 16)
    n = (1 << bit_length) | rand();
  else
    n = (1 << bit_length) | (rand() << 16) | rand();
  n &= mask;
  if ((n & 1) == 0) n++;
  return n;
}

void PROVABLE_PRIME(long k, verylong *zn)
{
  double c, r, s;
  int success;
  long B, m, n, p, sqrtn;
  verylong zI = 0, zR = 0, za = 0, zb = 0, zc = 0;
  verylong zd = 0, zk = 0, zl = 0, zq = 0, zu = 0;

  if (k <= 20) {
    do {
      n = OddRandom(k);
      sqrtn = sqrt(n);
      zpstart2();
      do p = zpnext(); while (n % p != 0 && p < sqrtn);
    } while (p < sqrtn);
    zintoz(n, zn);
  }
  else {
    c = 0.1;
    m = 20;
    B = c * k * k;
    if (k > 2 * m)
      do {
        s = rand() / (double) RAND_MAX;
        r = pow(2.0, s - 1.0);
      } while (k - r * k <= m);
    else
      r = 0.5;
    PROVABLE_PRIME(r * k + 1, &zq);
    zone(&za);
    zlshift(za, k - 1, &zk);
    zcopy(zq, &za);
    zlshift(za, 1l, &zl);
    zdiv(zk, zl, &zI, &za);
    zsadd(zI, 1l, &zl);
    zlshift(zI, 1l, &zu);
    success = 0;
    while (!success) {
      do zrandomb(zu, &zR); while (zcompare(zR, zl) < 0);
      zmul(zR, zq, &za);
      zlshift(za, 1l, &zb);
      zsadd(zb, 1l, zn);
      zcopy(zR, &za);
      zlshift(za, 1l, &zR);
      zpstart2();
      p = zpnext();
      while (zsmod(*zn, p) != 0 && p < B) p = zpnext();
      if (p >= B) {
        zcopy(*zn, &zc);
        zsadd(zc, - 2l, &zb);
        do
          zrandomb(*zn, &za);
        while (zscompare(za, 2l) < 0 || zcompare(za, zb) > 0);
        zsadd(*zn, - 1l, &zc);
        zexpmod(za, zc, *zn, &zb);
        if (zscompare(zb, 1l) == 0) {
          zexpmod(za, zR, *zn, &zb);
          zcopy(zb, &zd);
          zsadd(zd, - 1l, &zb);
          zgcd(zb, *zn, &zd);
          success = zscompare(zd, 1l) == 0;
        }
      }
    }
  }
  zfree(&zI);
  zfree(&zR);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&zk);
  zfree(&zl);
  zfree(&zq);
  zfree(&zu);
}

void RSA_gen_keys(long length, verylong *zd,
                  verylong *ze, verylong *zp,
                  verylong *zq)
{
  verylong zp1 = 0, zq1 = 0;
  verylong zphi = 0, zx = 0;

  srand(time(NULL));
  zrstarts(time(NULL));
  PROVABLE_PRIME(length, zp);
  PROVABLE_PRIME(length, zq);
  zsadd(*zp, - 1l, &zp1);
  zsadd(*zq, - 1l, &zq1);
  zmul(zp1, zq1, &zphi);
  do {
    do zrandomb(zphi, ze); while (zscompare(*ze, 1l) <= 0);
    zgcd(*ze, zphi, &zx);
  } while (zscompare(zx, 1l) != 0);
  zinvmod(*ze, zphi, zd);
  zfree(&zp1);
  zfree(&zq1);
  zfree(&zphi);
  zfree(&zx);
}

void RSA_exponentiation(verylong zx, verylong zd,
                        verylong zp, verylong zq,
                        verylong *zM)
{
  verylong zdp = 0, zdq = 0, zp1 = 0, zq1 = 0;
  verylong zm[2], zv[2];

  zsadd(zp, - 1l, &zp1);
  zsadd(zq, - 1l, &zq1);
  zmod(zd, zp1, &zdp);
  zmod(zd, zq1, &zdq);
  zm[0] = zm[1] = zv[0] = zv[1] = 0;
  zcopy(zp, &zm[0]);
  zcopy(zq, &zm[1]);
  zexpmod(zx, zdp, zp, &zv[0]);
  zexpmod(zx, zdq, zq, &zv[1]);
  Garner(2l, zm, zv, zM);
  zfree(&zdp);
  zfree(&zdq);
  zfree(&zp1);
  zfree(&zq1);
  zfree(&zm[0]);
  zfree(&zm[1]);
  zfree(&zv[0]);
  zfree(&zv[1]);
}

int main(void)
{
  verylong zM = 0, zN = 0, zd = 0, ze = 0, zn = 0;
  verylong zp = 0, zq = 0, zx = 0;

  RSA_gen_keys(128l, &zd, &ze, &zp, &zq);
  zintoz(65537l, &zx);
  RSA_exponentiation(zx, zd, zp, zq, &zM);
  zmul(zp, zq, &zn);
  zexpmod(zx, zd, zn, &zN);
  if (zcompare(zM, zN) == 0)
    printf("RSA_exponentiation confirmed\n");
  else
    printf("*error*\nin RSA_exponentiation\n");
  zfree(&zM);
  zfree(&zN);
  zfree(&zd);
  zfree(&ze);
  zfree(&zn);
  zfree(&zp);
  zfree(&zq);
  zfree(&zx);
  return 0;
}
