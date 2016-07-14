/*
  Author:  Pate Williams (c) 1997

  The following code tests an implementation of
  the Berlekamp-Massey algorithm for finding the
  linear complexity of a finite binary sequence.
  This is useful in analyzing linear feedback
  shift registers (LFSRs). See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al 6.30 Algorithm page 201.
*/

#include <stdio.h>
#include <stdlib.h>

long BerlekampMassey(char *s, long n, long *C)
/* returns the linear complexity of the finite
   binary sequence s of length n */
{
  long L = 0, N = 0, d, e, i, m = - 1, n1 = n + 1, sum;
  long dB = 0, dC = 0, dT;
  long *B = malloc(n1 * sizeof(long));
  long *D = malloc(n1 * sizeof(long));
  long *T = malloc(n1 * sizeof(long));

  for (i = 1; i < n1; i++) B[i] = C[i] = T[i] = 0;
  T[0] = 0;
  C[0] = B[0] = 1;
  while (N < n) {
    sum = 0;
    for (i = 1; i <= L; i++) sum += C[i] * s[N - i];
    d = (s[N] + sum) & 1l;
    if (d == 1) {
      dT = dC;
      for (i = 0; i <= dT; i++) T[i] = C[i];
      e = N - m;
      for (i = 0; i < e; i++) D[i] = 0;
      for (i = 0; i <= dB; i++) D[i + e] = B[i];
      D[e] = 1;
      for (i = 0; i <= dB + e; i++)
        C[i] = (C[i] + D[i]) & 1l;
      if (dB + e > dC) dC = dB + e;
      if (L <= N / 2) {
        dB = dT;
        for (i = 0; i <= dB; i++) B[i] = T[i];
        L = N + 1 - L, m = N;
      }
    }
    printf("s = %ld d = %ld T = ", s[N], d);
    for (i = 0; i <= L; i++) printf("%ld ", T[i]);
    printf("C = ");
    for (i = 0; i <= L; i++) printf("%ld ", C[i]);
    printf("L = %ld m = %ld B = ", L, m);
    for (i = 0; i <= L; i++) printf("%ld ", B[i]);
    printf("%ld\n", N);
    N++;
  }
  free(B);
  free(D);
  free(T);
  return L;
}

void main(void)
{
  char s[9] = {0, 0, 1, 1, 0, 1, 1, 1, 0};
  long C[10], i, n = 9, L = BerlekampMassey(s, n, C);

  printf("linear complexity: %ld\n", L);
  printf("polynomial: ");
  for (i = 0; i <= L; i++) printf("%ld ", C[i]);
}
