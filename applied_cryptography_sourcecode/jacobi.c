/*
  Author:  Pate Williams (c) 1997

  2.149 Algorithm Jacobi symbol (and Legendre
  symbol) computation
  See "Hanbook of Applied Cryptography" by
  Alfred J. Menezes et al page 73.
*/

#include <stdio.h>

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

int main(void)
{
  int j, k;
  long a = 158, n = 235;

  printf("a = %ld n = %ld (a / n) = %ld\n",
         a, n, JACOBI(a, n));
  for (a = 1; a < 21; a++) {
    j = JACOBI(a, 3);
    k = JACOBI(a, 7);
    if (j != 0 && k != 0)
      printf("%2ld %2ld %2d %2d %2d\n", a, a * a % 21,
             j, k, JACOBI(a, 21));
  }
  return 0;
}
