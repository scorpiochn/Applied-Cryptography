/*
  Author:  Pate Williams (c) 1997

  Fixed-base comb method for exponentiation. See
  "Handbook of Applied Cryptography" by Alfred J.
  Menezes et al 14.6.3 Section pages 623 - 627.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

/*#define DEBUG*/

long binary_to_long(long t, long *e)
{
  long i, value = e[t - 1];

  for (i = t - 2; i >= 0; i--)
    value = (value << 1) + e[i];
  return value;
}

void long_to_binary(long a, long *e, long *t)
{
  long i;

  *t = z2logs(a);
  for (i = 0; i < *t; i++) {
    e[i] = a & 1;
    a >>= 1;
  }
}

void fixed_base_comb(long exp, verylong zg, verylong *zA)
{
  long **EA, *X, *Y, Ijk, a, ah, b, c, e[32], f[32];
  long h, h2, i, j, k, s, t, v;
  verylong za = 0, zb = 0, zc = 0, **zG, *zg1;

  long_to_binary(exp, e, &t);
  t--;
  do h = rand() % (t + 2); while (h == 0);
  a = ceil((double)(t + 1) / h);
  h2 = pow(2, h);
  do v = rand() % (a + 1); while (v == 0);
  b = ceil((double) a / v);
  ah = a * h;
  /* create the exponent array */
  EA = calloc(h, sizeof(long *));
  assert(EA != 0);
  for (i = 0; i < h; i++) {
    EA[i] = calloc(a, sizeof(long));
    assert(EA[i] != 0);
  }
  /* allocate other arrays */
  X = calloc(ah, sizeof(long));
  assert(X != 0);
  Y = calloc(h, sizeof(long));
  assert(Y != 0);
  zG = calloc(v, sizeof(verylong *));
  assert(zG != 0);
  for (j = 0; j < v; j++) {
    zG[j] = calloc(h2, sizeof(verylong));
    assert(zG[j] != 0);
  }
  zg1 = calloc(h, sizeof(zg1));
  assert(zg1 != 0);
  for (i = 0; i <= t; i++) X[i] = e[i];
  /* create exponent array from binary representation */
  i = 0;
  for (j = 0; j < h; j++)
    for (k = 0; k < a; k++)
      EA[j][k] = X[i++];
  for (i = 0; i < h; i++)
    zsexp(zg, pow(2, i * a), &zg1[i]);
  for (i = 1; i < h2; i++) {
    long_to_binary(i, f, &s);
    zone(&za);
    for (j = 0; j < s; j++) {
      zsexp(zg1[j], f[j], &zb);
      zmul(zb, za, &zc);
      zcopy(zc, &za);
    }
    zcopy(za, &zG[0][i]);
    for (j = 1; j < v; j++)
      zsexp(zG[0][i], pow(2, j * b), &zG[j][i]);
  }
  #ifdef DEBUG
  printf("a = %ld\n", a);
  printf("b = %ld\n", b);
  printf("h = %ld\n", h);
  printf("t = %ld\n", t + 2);
  printf("v = %ld\n", v);
  for (i = 0; i < h; i++) {
    for (j = 0; j < a; j++)
      printf("%d", EA[i][j]);
    printf("\n");
  }
  printf("i g\n");
  for (i = 0; i < h; i++) {
    printf("%ld ", i);
    zwriteln(zg1[i]);
  }
  printf("j i G[j][i]\n");
  for (j = 0; j < v; j++) {
    for (i = 1; i < h2; i++) {
      printf("%ld %ld ", j, i);
      zwriteln(zG[j][i]);
    }
  }
  #endif
  zone(zA);
  for (k = b - 1; k >= 0; k--) {
    zsq(*zA, &za);
    zcopy(za, zA);
    for (j = v - 1; j >= 0; j--) {
      c = j * b + k;
      for (i = 0; i < h; i++)
        Y[i] = EA[i][c];
      Ijk = binary_to_long(h, Y);
      #ifdef DEBUG
      printf("%ld %ld\n", j, Ijk);
      #endif
      if (Ijk != 0) {
        zmul(*zA, zG[j][Ijk], &za);
        zcopy(za, zA);
      }
    }
  }
  /* free the allocated resources */
  free(X);
  free(Y);
  free(zg1);
  for (i = 0; i < h; i++) free(EA[i]);
  for (i = 0; i < v; i++) free(zG[i]);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
}

void main(void)
{
  long exp;
  verylong zA = 0, za = 0, zg = 0;

  srand(time(NULL));
  zintoz(2l, &zg);
  for (exp = 50l; exp < 155l; exp++) {
    fixed_base_comb(exp, zg, &zA);
    zsexp(zg, exp, &za);
    /*zwriteln(zA);
    zwriteln(za);*/
    if (zcompare(zA, za) != 0)
      printf("%ld error in exponent!\n", exp);
  }
}