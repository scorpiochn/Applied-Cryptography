/*
  Author:  Pate Williams (c) 1997

  Maurer's algorithm for generating provable primes.
  See "Handbook of Applied Cryptography" by Alfred J.
  Menezes et al page 153.
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

long OddRandom(long bit_length)
{
  long i, mask = 1, n;

  bit_length--;
  for (i = 1; i <= bit_length; i++)
    mask |= 1 << i;
  if (bit_length < 16)
    n = rand();
  else
    n = (rand() << 16) | rand();
  n |= 1 << bit_length;
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

  srand(time(NULL));
  zrstarts(time(NULL));
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

int main(void)
{
  long k;
  verylong zn = 0;

  for (k = 10; k <= 55; k += 5) {
    PROVABLE_PRIME(k, &zn);
    printf("%ld %ld %ld ", k, z2log(zn), zprobprime(zn, 5));
    zwriteln(zn);
  }
  zfree(&zn);
  return 0;
}
