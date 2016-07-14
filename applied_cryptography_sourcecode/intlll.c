/*
  Author:  Pate Williams (c) 1997

  "Algorithm 2.6.7 (Integral LLL Algorithm). Given
  a basis b[1], b[2],..., b[n] of a lattice (L, q)
  by its gram matrix which is assumed to have inte-
  gral coefficients, this algorithm transforms the
  vectors b[i] so that when the algorithm terminates,
  the b[i] form an LLL-reduced basis." -Henri Cohen-
  See "A Course in Computational Algebraic Number
  Theory" by Henri Cohen page 94. Also see "Handbook
  of Applied Cryptography by Alfred J. Menezes et al
  3.108 Algorithm "Finding a delta-quality simulta-
  neous diophantine approximation" pages 121-122.
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "lip.h"

void system_error(char error_message[])
{
  fprintf(stderr, "%s", error_message);
  exit(1);
}

verylong **allocate_very_matrix(long lr, long ur,
                                long lc, long uc)
{
  /* Allocates a real matrix of range [lr..ur][lc..uc]. */
  long i;
  verylong **p = calloc((ur - lr + 1), sizeof(verylong *));

  if (!p)
    system_error("Failure in allocate_very_matrix().");
  p -= lr;
  for (i = lr; i <= ur; i++) {
    p[i]= calloc((uc - lc + 1), sizeof(verylong));
	 if (!p[i])
      system_error("Failure in allocate_very_matrix().");
    p[i] -= lc;
  }
  return p;
}

verylong *allocate_very_vector(long l, long u)
{
  /* Allocates a verylong vector of range [l..u]. */
  verylong *p;

  p = calloc((u - l + 1), sizeof(verylong));
  if (!p)
    system_error("Failure in allocate_very_vector().");
  return p - l;
}

void free_very_matrix(verylong **m, long lr, long ur,
                      long lc, long uc)
{
  /* Frees a verylong matrix of range [lr..ur][lc..uc]. */
  long i, j;

  for (i = lr; i <= ur; i++)
    for (j = lc; j <= uc; j++)
      zfree(&m[i][j]);
  for (i = ur; i >= lr; i--)
    free((char *)(m[i] + lc));
  free((char *) (m + lr));
}

void free_very_vector(verylong *v, long l, long u)
{
  /* Frees a verylong vector of range [l..u]. */
  long i;

  for (i = l; i <= u; i++) zfree(&v[i]);
  free((char *)(v + l));
}

void scalar(long n, verylong *za, verylong *zb,
            verylong *zs)
{
  /* *s = inner_product(a, b) */
  long i;
  verylong zt = 0, zu = 0;

  zzero(zs);
  for (i = 1; i <= n; i++) {
    zmul(za[i], zb[i], &zt);
    zadd(zt, *zs, &zu);
    zcopy(zu, zs);
  }
  zfree(&zt);
  zfree(&zu);
}

void RED(long k, long l, long n,
         verylong *zd, verylong **zb,
         verylong **zh, verylong **zl)
{
  long i;
  verylong zq = 0, zr = 0, zs = 0, zt = 0;

  zlshift(zl[k][l], 1l, &zr);
  zcopy(zr, &zs);
  zabs(&zs);
  if (zcompare(zs, zd[l]) > 0) {
    zadd(zr, zd[l], &zs);
    zlshift(zd[l], 1l, &zr);
    zdiv(zs, zr, &zq, &zt);
    for (i = 1; i <= n; i++) {
      zmul(zq, zh[i][l], &zr);
      zsub(zh[i][k], zr, &zs);
      zcopy(zs, &zh[i][k]);
      zmul(zq, zb[l][i], &zr);
      zsub(zb[k][i], zr, &zs);
      zcopy(zs, &zb[k][i]);
    }
    zmul(zq, zd[l], &zr);
    zsub(zl[k][l], zr, &zs);
    zcopy(zs, &zl[k][l]);
    for (i = 1; i <= l - 1; i++) {
      zmul(zq, zl[l][i], &zr);
      zsub(zl[k][i], zr, &zs);
      zcopy(zs, &zl[k][i]);
    }
  }
  zfree(&zq);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
}

void SWAP(long k, long k1, long kmax, long n,
          verylong *zd, verylong **zb,
          verylong **zh, verylong **zl)
{
  long i, j;
  verylong zB = 0, zm = 0, zr = 0, zs = 0, zt = 0;
  verylong zu = 0;

  for (i = 1; i <= n; i++) {
    zcopy(zh[i][k], &zt);
    zcopy(zh[i][k1], &zh[i][k]);
    zcopy(zt, &zh[i][k1]);
  }
  for (j = 1; j <= n; j++) {
    zcopy(zb[k][j], &zt);
    zcopy(zb[k1][j], &zb[k][j]);
    zcopy(zt, &zb[k1][j]);
  }
  if (k > 2) {
    for (j = 1; j <= k - 2; j++) {
      zcopy(zl[k][j], &zt);
      zcopy(zl[k1][j], &zl[k][j]);
      zcopy(zt, &zl[k1][j]);
    }
  }
  zcopy(zl[k][k1], &zm);
  zmul(zd[k - 2], zd[k], &zr);
  zsq(zm, &zs);
  zadd(zr, zs, &zt);
  zdiv(zt, zd[k1], &zB, &zr);
  for (i = k + 1; i <= kmax; i++) {
    zcopy(zl[i][k], &zt);
    zmul(zd[k], zl[i][k1], &zr);
    zmul(zm, zt, &zs);
    zsub(zr, zs, &zu);
    zdiv(zu, zd[k1], &zl[i][k], &zr);
    zmul(zB, zt, &zr);
    zmul(zm, zl[i][k], &zs);
    zadd(zr, zs, &zu);
    zdiv(zu, zd[k], &zl[i][k1], &zr);
  }
  zcopy(zB, &zd[k1]);
  zfree(&zB);
  zfree(&zm);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  zfree(&zu);
}

void int_LLL(long n, verylong **zb, verylong **zh)
{
  double x, y;
  long i, j, k = 2, k1, kmax = 1, l;
  verylong zr = 0, zs = 0, zt = 0, zu = 0;
  verylong *zB = allocate_very_vector(1, n);
  verylong *zd = allocate_very_vector(0, n);
  verylong **zl = allocate_very_matrix(1, n, 1, n);

  zone(&zd[0]);
  scalar(n, zb[1], zb[1], &zd[1]);
  for (i = 1; i <= n; i++) {
    for (j = 1; j <= n; j++)
      zzero(&zh[i][j]);
    zone(&zh[i][i]);
  }
  #ifdef DEBUG
  if (n <= 17) {
    printf("the basis to be reduced is:\n");
    for (i = 1; i <= n; i++) {
      for (j = 1; j <= n; j++) {
        zwrite(zb[i][j]);
        printf(" ");
      }
      printf("\n");
    }
  }
  #endif
  L2:
  if (k <= kmax) goto L3;
  kmax = k;
  for (j = 1; j <= k; j++) {
    scalar(n, zb[k], zb[j], &zu);
    for (i = 1; i <= j - 1; i++) {
      zmul(zd[i], zu, &zr);
      zmul(zl[k][i], zl[j][i], &zs);
      zsub(zr, zs, &zt);
      zdiv(zt, zd[i - 1], &zu, &zr);
    }
    if (j < k) zcopy(zu, &zl[k][j]);
    else if (j == k) {
      zcopy(zu, &zd[k]);
      if (zscompare(zd[k], 0l) == 0)
        system_error("Failure in int_LLL.");
    }
  }
  L3:
  k1 = k - 1;
  RED(k, k1, n, zd, zb, zh, zl);
  zmul(zd[k], zd[k - 2], &zr);
  zsq(zd[k1], &zs);
  zsq(zl[k][k1], &zt);
  x = zdoub(zr);
  y = 3.0 * zdoub(zs) / 4.0 - zdoub(zt);
  if (x < y) {
    SWAP(k, k1, kmax, n, zd, zb, zh, zl);
    k = max(2, k1);
    goto L3;
  }
  for (l = k - 2; l >= 1; l--)
    RED(k, l, n, zd, zb, zh, zl);
  if (++k <= n) goto L2;
  #ifdef DEBUG
  if (n <= 17) {
    printf("the LLL-reduced basis is:\n");
    for (i = 1; i <= n; i++) {
      for (j = 1; j <= n; j++) {
        zwrite(zb[i][j]);
        printf(" ");
      }
      printf("\n");
    }
  }
  #endif
  free_very_matrix(zl, 1, n, 1, n);
  free_very_vector(zB, 1, n);
  free_very_vector(zd, 0, n);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  zfree(&zu);
}

int simultaneous_diophantine(double delta,
                             long n,
                             verylong zQ,
                             verylong *zP,
                             verylong *zp,
                             verylong *zq)
{
  double P, Q, l;
  int equal, found;
  long i, j, n1 = n + 1;
  verylong zd = 0, zl = 0, zr = 0, zs = 0, zt = 0;
  verylong **zA = allocate_very_matrix(1, n1, 1, n1);
  verylong **zh = allocate_very_matrix(1, n1, 1, n1);

  Q = zdoub(zQ);
  zintoz(pow(Q, delta), &zl);
  l = 1.0 / zdoub(zl);
  zmul(zl, zQ, &zd);
  for (i = 1; i <= n; i++)
    zcopy(zd, &zA[i][i]);
  znegate(&zl);
  for (i = 1; i <= n; i++)
    zmul(zl, zq[i], &zA[n1][i]);
  zone(&zA[n1][n1]);
  int_LLL(n1, zA, zh);
  found = 0;
  for (j = 1; !found && j <= n1; j++) {
    zcopy(zA[j][n1], zP);
    if (zcompare(*zP, zQ) != 0) {
      for (i = 1; i <= n; i++) {
        zdiv(zA[j][i], zl, &zr, &zs);
        zmul(*zP, zq[i], &zt);
        zadd(zr, zt, &zs);
        zdiv(zs, zQ, &zp[i], &zr);
      }
      P = zdoub(*zP);
      #ifdef DEBUG
      if (n <= 16) {
        printf("p = ");
        zwrite(*zP);
        printf(" p[i] ");
        for (i = 1; i <= n; i++) {
          zwrite(zp[i]);
          printf(" ");
        }
        printf("\n");
      }
      #endif
      if (zcompare(*zP, 0) != 0) {
        equal = 1;
        for (i = 1; equal && i <= n; i++)
          equal = fabs(P * zdoub(zq[i]) / Q - zdoub(zp[i]))
                <= l;
      }
      else equal = 0;
      found = equal;
    }
  }
  free_very_matrix(zA, 1, n1, 1, n1);
  free_very_matrix(zh, 1, n1, 1, n1);
  zfree(&zd);
  zfree(&zl);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  return found;
}

int main(void)
{
  double delta = 0.15;
  long i, n = 16;
  verylong zP = 0, zQ = 0;
  verylong *zp = allocate_very_vector(1, n);
  verylong *zq = allocate_very_vector(1, n);

  zpstart2();
  for (i = 1; i <= n; i++)
    zintoz(zpnext(), &zq[i]);
  zintoz(zpnext(), &zQ);
  printf("delta = %lf\n", delta);
  printf("n = %ld\n", n);
  if (n <= 16) {
    printf("q = ");
    zwriteln(zQ);
    printf("q[i] ");
    for (i = 1; i <= n; i++) {
      zwrite(zq[i]);
      printf(" ");
    }
  }
  printf("\n");
  if (simultaneous_diophantine(delta, n, zQ, &zP, zp, zq)) {
    printf("p = "); zwriteln(zP);
    printf("p[i] ");
    for (i = 1; i <= n; i++) {
      zwrite(zp[i]);
      printf(" ");
    }
  }
  else
    printf("\nno simultaneous diophantine approximation\n");
  free_very_vector(zp, 1, n);
  free_very_vector(zq, 1, n);
  return 0;
}
