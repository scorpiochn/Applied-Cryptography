/*
  Author:  Pate Williams (c) 1997

  Addition chain exponentiation. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et al
  14.6.2 Section pages 620 - 623.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "lip.h"

#define DEBUG

void long_to_binary(long a, long *e, long *t)
{
  long i;

  *t = z2logs(a);
  for (i = 0; i < *t; i++) {
    e[i] = a & 1;
    a >>= 1;
  }
}

void addition_chain(long exp, verylong zg, verylong *zge)
{
  int found;
  long I[65][2], d[32], e[32], i, j, k, s, t, u[65];
  verylong *zg1;

  long_to_binary(exp, e, &t);
  for (i = 0, j = t - 1; j >= 0; i++, j--) d[i] = e[j];
  u[0] = 1, u[1] = 2 * d[0], u[2] = u[1] + d[1];
  for (s = 3, j = 2; j < t; s += 2, j++)
    u[s] = 2 * u[s - 1], u[s + 1] = u[s] + d[j];
  zg1 = calloc(s, sizeof(verylong));
  assert(zg1 != 0);
  for (i = 1; i < s; i++) {
    found = 0;
    for (j = 0; !found && j < i; j++)
      for (k = 0; !found && k < i; k++)
        if (u[i] == u[j] + u[k])
          found = 1, I[i][0] = j, I[i][1] = k;
  }
  #ifdef DEBUG
  for (i = 0; i < s; i++)
    printf("%ld ", u[i]);
  printf("\n");
  for (i = 1; i < s; i++)
    printf("%ld %ld %ld\n", i, I[i][0], I[i][1]);
  #endif
  zcopy(zg, &zg1[0]);
  for (i = 1; i < s; i++)
    zmul(zg1[I[i][0]], zg1[I[i][1]], &zg1[i]);
  zcopy(zg1[s - 1], zge);
  free(zg1);
}

void main(void)
{
  long exp = 143l;
  verylong za = 0, zg = 0, zge = 0;

  zintoz(2l, &zg);
  addition_chain(exp, zg, &zge);
  zwriteln(zge);
  zsexp(zg, exp, &za);
  zwriteln(za);
  zfree(&za);
  zfree(&zg);
  zfree(&zge);
}
