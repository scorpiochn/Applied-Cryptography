/*
  Author:  Pate Williams (c) 1997

  Sliding window exponentiation. See "Handboook of
  Applied Cryptography" by Alfred J. Menezes et al
  14.6.1 Section pages 614 - 620.
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lip.h"

#define DEBUG

void long_to_binary(char *e, long a, long *t)
{
  long i;

  *t = z2logs(a);
  for (i = 0; i < *t; i++) {
    e[i] = (char) (a & 1);
    a >>= 1;
  }
}

long binary_to_long(char *e, long i, long l)
{
  long a, t;

  a = e[i];
  for (t = i - 1; t >= l; t--)
    a = (a << 1) + e[t];
  return a;
}

void sliding_window(long exp, long k,
                    verylong zg, verylong *zA)
{
  char e[32];
  long i, l, length, limit, m, t;
  verylong za = 0, zb = 0;
  verylong zg1 = 0, zg2 = 0, *zg3;

  limit = pow(2, k - 1) - 1;
  length = 2 * limit + 2;
  zg3 = calloc(length, sizeof(verylong));
  long_to_binary(e, exp, &t);
  #ifdef DEBUG
  for (i = t - 1; i >= 0; i--)
    printf("%d", e[i]);
  printf("\n");
  #endif
  zcopy(zg, &zg1);
  zsq(zg, &zg2);
  for (i = 1; i <= limit; i++)
    zmul(zg2, zg3[2 * i - 1], &zg3[2 * i + 1]);
  zone(zA);
  i = t - 1;
  while (i >= 0) {
    if (e[i] == 0) {
      zsq(*zA, &za);
      zcopy(za, zA);
      i--;
    }
    else {
      l = i - 1;
      while (i - l + 1 <= k && l >= 0) {
        if (e[l] == 1) m = l;
        l--;
      }
      if (i - l + 1 > k) {
        zmul(*zA, *zA, &za);
        zmul(za, zg, zA);
        i = i - 1;
      }
      else {
        l = m;
        zsexp(*zA, pow(2, i - l + 1), &za);
        #ifdef DEBUG
        printf("%ld %ld %ld\n", i, l, binary_to_long(e, i, l));
        #endif
        zsexp(zg, binary_to_long(e, i, l), &zb);
        zmul(za, zb, zA);
        i = l - 1;
      }
    }
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zg1);
  zfree(&zg2);
  for (i = 0; i < length; i++) zfree(&zg3[i]);
}

int main(void)
{
  long exp = 39l;
  verylong zA = 0, zg = 0;

  zintoz(2l, &zg);
  sliding_window(exp, 3l, zg, &zA);
  zwriteln(zA);
  zsexp(zg, exp, &zA);
  zwriteln(zA);
  zfree(&zA);
  zfree(&zg);
  return 0;
}
