/*
  Author:  Pate Williams (c) 1997

  14.54 Algorithm Binary gcd algorithm
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al page 606.
*/

#include <math.h>
#include <stdio.h>

#define DEBUG

long binary_gcd(long x, long y)
{
  long g = 1, t;
  #ifdef DEBUG
  printf("-----------\n");
  printf(" x   y   g\n");
  printf("-----------\n");
  #endif
  while (!(x & 1) && !(y & 1))
    x >>= 1, y >>= 1, g <<= 1;
  while (x != 0) {
    while (!(x & 1)) x >>= 1;
    while (!(y & 1)) y >>= 1;
    t = labs(x - y) >> 1;
    if (x >= y) x = t; else y = t;
    #ifdef DEBUG
    printf("%3ld %3ld %3ld\n", x, y, g);
    #endif
  }
  #ifdef DEBUG
  printf("-----------\n");
  #endif
  return g * y;
}

int main(void)
{
  long x = 1764, y = 868;

  printf("x = %ld y = %ld\n", x, y);
  printf("gcd(x, y) = %ld\n", binary_gcd(x, y));
  return 0;
}
