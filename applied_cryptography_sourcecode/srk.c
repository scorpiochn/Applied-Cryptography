/*
  Author:  Pate Williams (c) 1997

  k-ary string-replacement exponentiation. See
  "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 14.7.2 Section pages 628-629.
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

void k_ary_string_replacement(long exp, long k,
                              long *f, long *t)
{
  int found;
  long c, e[32], i, i2, j, l, m, n;

  long_to_binary(exp, e, t);
  #ifdef DEBUG
  for (i = *t - 1; i >= 0; i--)
    printf("%ld", e[i]);
  printf("\n");
  #endif
  for (i = k; i >= 2; i--) {
    i2 = pow(2, i) - 1, j = *t - 1, n = j;
    while (j >= 0) {
      if (e[j] == 1) {
        c = j - i + 1;
        if (c >= 0) {
          for (found = 1, l = j; found && l >= c; l--)
            found = e[l] == 1;
          if (found) {
            for (m = j; m > c; m--) f[m] = 0;
            f[c] = i2;
          }
          else
            for (m = j; m >= c; m--) f[m] = e[m];
          j = n = c - 1;
        }
        else
          while (j >= 0) f[j] = e[j], j--;
      }
      else
        f[n--] = e[j--];
    }
    for (j = 0; j < *t; j++) e[j] = f[j];
    #ifdef DEBUG
    for (l = *t - 1; l >= 0; l--)
      printf("%ld", f[l]);
    printf(" SR(%ld)\n", k);
    #endif
  }
}

void srk_exp(long exp, long k, verylong zg, verylong *zA)
{
  long f[32], i, j, l, t;
  verylong za = 0, *zg1;

  l = pow(2, k);
  zg1 = calloc(l, sizeof(verylong));
  assert(zg1 != 0);
  k_ary_string_replacement(exp, k, f, &t);
  zcopy(zg, &zg1[1]);
  for (i = 2; i <= k; i++) {
    j = pow(2, i - 1) - 1;
    l = pow(2, i) - 1;
    zsq(zg1[j], &za);
    zmul(za, zg, &zg1[l]);
  }
  zone(zA);
  for (i = t - 1; i >= 0; i--) {
    zsq(*zA, &za);
    zcopy(za, zA);
    j = f[i];
    if (j != 0) {
      zmul(*zA, zg1[j], &za);
      zcopy(za, zA);
    }
  }
  free(zg1);
  zfree(&za);
}

int main(void)
{
  long exp = 28573l, k = 3l, f[32], t;
  verylong zA = 0, za = 0, zg = 0;

  zintoz(2l, &zg);
  k_ary_string_replacement(exp, k, f, &t);
  exp = 987l;
  srk_exp(exp, k, zg, &zA);
  zsexp(zg, exp, &za);
  zwriteln(zA);
  zwriteln(za);
  if (zcompare(zA, za) != 0)
    printf("*error*\nsrk_exp failure!\n");
  zfree(&zA);
  zfree(&za);
  zfree(&zg);
  return 0;
}
