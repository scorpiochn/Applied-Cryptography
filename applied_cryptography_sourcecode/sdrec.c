/*
  Author:  Pate Williams (c) 1997

  Signed-digit exponent recoding. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et al
  14.7.1 Section pages 627 - 628.
*/

#include <stdio.h>
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

void signed_digit_recoding(long exp, long *d, long *t)
{
  long c[64], e[64], i;

  long_to_binary(exp, e, t);
  #ifdef DEBUG
  for (i = *t - 1; i >= 0; i--)
    printf("%ld", e[i]);
  printf("\n");
  #endif
  e[*t] = e[*t + 1] = 0;
  c[0] = 0;
  for (i = 0; i <= *t; i++) {
    c[i + 1] = (e[i] + e[i + 1] + c[i]) / 2;
    d[i] = e[i] + c[i] - 2 * c[i + 1];
  }
}

int main(void)
{
  long d[64], exp = 887l, i, t;

  signed_digit_recoding(exp, d, &t);
  for (i = t; i >= 0; i--)
    printf("%d", d[i]);
  printf("\n");
  return 0;
}
