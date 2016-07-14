/*
  Author:  Pate Williams (c) 1998

  3.34 Algorithm Finding square roots modulo a prime.
  See "Handbook of Applied Cryptography" by Alfred J.
  Menezes et al page 100.
*/

#include <stdio.h>
#include <stdlib.h>

int JACOBI(long a, long n)
{
  int s;
  long a1, b = a, e = 0, m, n1;

  if (a == 0) return 0;
  if (a == 1) return 1;
  while ((b & 1) == 0)
    b >>= 1, e++;
  a1 = b;
  m = n % 8;
  if (!(e & 1)) s = 1;
  else if (m == 1 || m == 7) s = + 1;
  else if (m == 3 || m == 5) s = - 1;
  if (n % 4 == 3 && a1 % 4 == 3) s = - s;
  if (a1 != 1) n1 = n % a1; else n1 = 1;
  return s * JACOBI(n1, a1);
}

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

long inverse(long a, long b)
/* returns the inverse of a modulo b if it exists 0 otherwise */
{
  long d, x, y;

  extended_euclid(a, b, &x, &y, &d);
  if (d == 1) return x;
  return 0;
}

long exp_mod(long x, long b, long n)
/* returns x ^ b mod n */
{
  long a = 1, s = x;

  while (b != 0) {
    if (b & 1) a = (a * s) % n;
    b >>= 1;
    if (b != 0) s = (s * s) % n;
  }
  return a;
}

long square_root_mod(long a, long p)
/* returns the square root of a modulo an odd prime p
   if it exists 0 otherwise */
{
  long ai, b, c, d, e, i, r, s = 0, t = p - 1;

  /* is a quadratic nonresidue */
  if (JACOBI(a, p) == - 1) return 0;
  /* find quadratic nonresidue */
  do
    do b = rand() % p; while (b == 0);
  while (JACOBI(b, p) != - 1);
  /* write p - 1 = 2 ^ s * t for odd t */
  while (!(t & 1)) s++, t >>= 1;
  ai = inverse(a, p);
  c = exp_mod(b, t, p);
  r = exp_mod(a, (t + 1) / 2, p);
  for (i = 1; i < s; i++) {
    e = exp_mod(2, s - i - 1, p);
    d = exp_mod((r * r % p) * ai % p, e, p);
    if (d == p - 1) r = r * c % p;
    c = c * c % p;
  }
  return r;
}

int main(void)
{
  long a, p;

  printf("x ^ 2 = a mod p\n");
  for (;;) {
    printf("a or 0 to quit = ");
    scanf("%ld", &a);
    if (a == 0) break;
    printf("p = ");
    scanf("%ld", &p);
    printf("square_root_mod(%ld, %ld) = %ld\n", a, p,
           square_root_mod(a, p));
  }
  return 0;
}
