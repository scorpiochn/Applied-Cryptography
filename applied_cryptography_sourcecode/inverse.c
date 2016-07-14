/*
  Author:  Pate Williams (c) 1997

  2.142 Algorithm Computing multiplicative
  inverses in Zn
  See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al page 71.
*/

#include <stdio.h>

void extended_euclid(long a, long b, long *x,
                     long *y, long *d)
/* calculates a * *x + b * *y = gcd(a, b) = *d */
{
  long q, r, x1, x2, y1, y2;

  if (b == 0) {
    *d = a, *x = 1, *y = 0;
    return;
  }
  x2 = 1, x1 = 0, y2 = 0, y1 = 1;
  while (b > 0) {
    q = a / b, r = a - q * b;
    *x = x2 - q * x1, *y = y2 - q * y1;
    a = b, b = r;
    x2 = x1, x1 = *x, y2 = y1, y1 = *y;
  }
  *d = a, *x = x2, *y = y2;
}

long inverse(long a, long n)
/* computes the inverse of a modulo n */
{
  long d, x, y;

  extended_euclid(a, n, &x, &y, &d);
  if (d == 1) return x;
  return 0;
}

int main(void)
{
  long a = 5, n = 7;

  printf("the inverse of %ld modulo %2ld is %ld\n",
         a, n, inverse(a, n));
  a = 2, n = 12;
  printf("the inverse of %ld modulo %2ld is %ld\n",
         a, n, inverse(a, n));
  return 0;
}