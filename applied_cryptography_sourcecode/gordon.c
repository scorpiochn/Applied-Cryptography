/*
  Author:  Pate Williams (c) 1997

  Gordon's algorithm for generating strong primes.
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 4.53 Algorithm page 150.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

long Gordon(long bit_length, verylong *zp)
{
  long i, i0, j, k, j0, s_size = bit_length / 2;
  verylong za = 0, zb = 0, zc = 0, zr = 0;
  verylong zs = 0, zt = 0, zp0 = 0;

  zrstarts(time(NULL));
  zrandomprime(s_size, 5l, &zs, zrandomb);
  zrandomprime(s_size, 5l, &zt, zrandomb);
  zlshift(zt, 1l, &za);
  do i0 = rand(); while (i0 == 0);
  i = i0;
  do {
    /* compute r = 2 * i * t + 1 */
    zsmul(za, i, &zb);
    zsadd(zb, 1l, &zr);
    i++;
  } while (!zprobprime(zr, 5l));
  /* compute p0 = ((2 * s) ^ (r - 2) mod r) * s - 1 */
  zlshift(zs, 2l, &za);
  zsadd(zr, - 2l, &zb);
  zexpmod(za, zb, zr, &zc);
  zmul(zc, zs, &za);
  zsadd(za, - 1l, &zp0);
  zlshift(zr, 1l, &zb);
  zmul(zb, zs, &za);
  do j0 = rand(); while (j0 == 0);
  j = j0;
  k = 0;
  do {
    /* compute p = p0 + 2 * j * r * s */
    zsmul(za, j, &zb);
    zadd(zb, zp0, zp);
    j++, k++;
    printf("\b\b\b\b\b%4ld", k);
  } while (k < 1000 && !zprobprime(*zp, 5l));
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  zfree(&zp0);
  if (k == 1000) return Gordon(bit_length, zp);
  return z2log(*zp);
}

int main(void)
{
  long bit_length, i;
  verylong zp = 0;

  for (i = 100; i <= 180; i += 20) {
    bit_length = Gordon(i, &zp);
    printf(" %3ld %3ld ", i, bit_length);
    zwriteln(zp);
  }
  zfree(&zp);
  return 0;
}
