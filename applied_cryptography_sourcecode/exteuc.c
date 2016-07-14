/*
  Author:  Pate Williams (c) 1997

  2.107 Algorithm Extended Euclidean algorithm
  See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al page 67.
*/

#include <stdio.h>

#define DEBUG

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
  #ifdef DEBUG
  printf("------------------------------");
  printf("-------------------\n");
  printf("q    r    x    y    a    b    ");
  printf("x2   x1   y2   y1\n");
  printf("------------------------------");
  printf("-------------------\n");
  #endif
  while (b > 0) {
    q = a / b, r = a - q * b;
    *x = x2 - q * x1, *y = y2 - q * y1;
    a = b, b = r;
    x2 = x1, x1 = *x, y2 = y1, y1 = *y;
    #ifdef DEBUG
    printf("%4ld %4ld %4ld %4ld ", q, r, *x, *y);
    printf("%4ld %4ld %4ld %4ld ", a, b, x2, x1);
    printf("%4ld %4ld\n", y2, y1);
    #endif
  }
  *d = a, *x = x2, *y = y2;
  #ifdef DEBUG
  printf("------------------------------");
  printf("-------------------\n");
  #endif
}

int main(void)
{
  long a = 4864, b = 3458, d, x, y;

  extended_euclid(a, b, &x, &y, &d);
  printf("x = %ld y = %ld d = %ld\n", x, y, d);
  return 0;
}