/*
  Author:  Pate Williams (c) 1997

  Berlekamp's Q-matrix algorithm. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes
  et al 3.11.2 Section 3.111 Algorithm page 124.
  Also see "Seminumerical Algorithms" by Donald
  E. Knuth second edition page 423 and "A Course
  in Computational Algebraic Number Theory" by
  Henri Cohen Algorithm 3.4.10 page 132.
*/

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include "lip.h"

#define DEBUG
#define POLY_SIZE 8192l

verylong **create_matrix(long m, long n)
{
  long i;
  verylong **matrix = calloc(m, sizeof(verylong));

  assert(matrix != 0);
  for (i = 0; i < m; i++) {
    matrix[i] = calloc(n, sizeof(verylong));
    assert(matrix[i] != 0);
  }
  return matrix;
}

void delete_matrix(long m, verylong **matrix)
{
  long i;

  for (i = 0; i < m; i++) free(matrix[i]);
  free(matrix);
}

void zpoly_mul(long m, long n, verylong *za, verylong *zb,
               verylong *zc, long *p)
{
  long i, j, k;
  verylong zd = 0, zai = 0, zbk = 0, zsum = 0, zterm = 0;

  *p = m + n;
  for (k = 0; k <= *p; k++) {
    zzero(&zsum);
    for (i = 0; i <= k; i++) {
      j = k - i;
      if (i > m) zzero(&zai);
      else zcopy(za[i], &zai);
      if (j > n) zzero(&zbk);
      else zcopy(zb[j], &zbk);
      zmul(zai, zbk, &zterm);
      zcopy(zsum, &zd);
      zadd(zterm, zd, &zsum);
    }
    zcopy(zsum, &zc[k]);
  }
  zfree(&zd);
  zfree(&zai);
  zfree(&zbk);
  zfree(&zsum);
  zfree(&zterm);
}

void zpoly_div(long m, long n, verylong *zu, verylong *zv,
               verylong *zq, verylong *zr, long *p, long *s)
{
  long j, jk, k, nk;
  verylong za = 0, zb = 0, zvn = 0;

  zcopy(zv[n], &zvn);
  for (j = 0; j <= m; j++)
    zcopy(zu[j], &zr[j]);
  if (m < n) {
    *p = 0, *s = m;
    zzero(&zq[0]);
  }
  else {
    *p = m - n, *s = n - 1;
    for (k = *p; k >= 0; k--) {
      nk = n + k;
      zsexp(zvn, k, &za);
      zmul(zr[nk], za, &zq[k]);
      for (j = nk - 1; j >= 0; j--) {
        jk = j - k;
        if (jk >= 0) {
          zmul(zvn, zr[j], &za);
          zmul(zr[nk], zv[jk], &zb);
          zsub(za, zb, &zr[j]);
        }
        else {
          zcopy(zr[j], &za);
          zmul(zvn, za, &zr[j]);
        }
      }
    }
    while (*p > 0 && zscompare(zq[*p], 0l) == 0) *p = *p - 1;
    while (*s > 0 && zscompare(zr[*s], 0l) == 0) *s = *s - 1;
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zvn);
}

void zpoly_mod(long p, verylong *za, long *da)
{
  long i;

  for (i = 0; i <= *da; i++)
    zintoz(zsmod(za[i], p), &za[i]);
  while (*da > 0 && zscompare(za[*da], 0l) == 0) *da = *da - 1;
}

void zpoly_pow(long degreeA, long degreem, long p,
               verylong zn, verylong *zA,
               verylong *zm, verylong *zs,
               long *ds)
{
  long dp, dq, dx = degreeA, i;
  verylong za = 0, zb = 0, zp[POLY_SIZE], zq[POLY_SIZE],
           zx[POLY_SIZE], zy[POLY_SIZE];

  for (i = 0; i < POLY_SIZE; i++)
    zp[i] = zq[i] = zx[i] = zy[i] = 0;
  *ds = 0;
  zcopy(zn, &za);
  zone(&zs[0]);
  for (i = 0; i <= dx; i++) zcopy(zA[i], &zx[i]);
  while (zscompare(za, 0l) > 0) {
    if (zodd(za)) {
      /* s = (s * x) % m; */
      zpoly_mul(*ds, dx, zs, zx, zp, &dp);
      zpoly_div(dp, degreem, zp, zm, zq, zs, &dq, ds);
      zpoly_mod(p, zs, ds);
    }
    zcopy(za, &zb);
    zrshift(zb, 1l, &za);
    if (zscompare(za, 0l) > 0) {
      /* x = (x * x) % m; */
      for (i = 0; i <= dx; i++) zcopy(zx[i], &zy[i]);
      zpoly_mul(dx, dx, zx, zy, zp, &dp);
      zpoly_div(dp, degreem, zp, zm, zq, zx, &dq, &dx);
      zpoly_mod(p, zx, &dx);
    }
  }
  zfree(&za);
  zfree(&zb);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zp[i]);
    zfree(&zq[i]);
    zfree(&zx[i]);
    zfree(&zy[i]);
  }
}

void zpoly_sub(long da, long db, verylong *za, verylong *zb,
               verylong *zc, long *dc)
{
  long i;
  verylong zz = 0;

  zzero(&zz);
  if (da >= db) {
    for (i = 0; i <= db; i++)
      zsub(za[i], zb[i], &zc[i]);
    for (i = db + 1; i <= da; i++)
      zcopy(za[i], &zc[i]);
    *dc = da;
  }
  else {
    for (i = 0; i <= da; i++)
      zsub(za[i], zb[i], &zc[i]);
    for (i = da + 1; i <= db; i++)
      zsub(zz, zb[i], &zc[i]);
    *dc = db;
  }
  zfree(&zz);
}

void zpoly_gcd(long degreeA, long degreeB, long p,
               verylong *zA, verylong *zB, verylong *za,
               long *da)
{
  int nonzero = 0, zero;
  long db, dq, dr, i;
  verylong zc = 0, zd = 0, zp = 0;
  verylong zb[POLY_SIZE], zq[POLY_SIZE], zr[POLY_SIZE];

  for (i = 0; i < POLY_SIZE; i++)
    zb[i] = zq[i] = zr[i] = 0;
  if (degreeA > degreeB) {
    *da = degreeA;
    db = degreeB;
    for (i = 0; i <= *da; i++) zcopy(zA[i], &za[i]);
    for (i = 0; i <= db; i++) zcopy(zB[i], &zb[i]);
  }
  else {
    *da = degreeB;
    db = degreeA;
    for (i = 0; i <= *da; i++) zcopy(zB[i], &za[i]);
    for (i = 0; i <= db; i++) zcopy(zA[i], &zb[i]);
  }
  for (i = 0; i <= db && !nonzero; i++)
    nonzero = zscompare(zb[i], 0l) != 0;
  zintoz(p, &zp);
  while (nonzero) {
    zpoly_div(*da, db, za, zb, zq, zr, &dq, &dr);
    for (i = 0; i <= dr; i++) {
      zcopy(zr[i], &zc);
      zmod(zc, zp, &zr[i]);
    }
    zero = 1;
    for (i = dr; i >= 0 && zero; i--) {
      zero = zscompare(zr[i], 0l) == 0;
      if (zero && dr > 0) dr--;
    }
    for (i = 0; i <= db; i++) zcopy(zb[i], &za[i]);
    *da = db;
    for (i = 0; i <= dr; i++) zcopy(zr[i], &zb[i]);
    db = dr;
    nonzero = 0;
    for (i = 0; i <= db && !nonzero; i++)
      nonzero = zscompare(zb[i], 0l) != 0;
  }
  if (*da > 0) {
    zinvmod(za[*da], zp, &zd);
    for (i = 0; i <= *da; i++) {
      zmulmod(za[i], zd, zp, &zc);
      zcopy(zc, &za[i]);
    }
  }
  zfree(&zc);
  zfree(&zd);
  zfree(&zp);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zb[i]);
    zfree(&zq[i]);
    zfree(&zr[i]);
  }
}

void zpoly_copy(long da, verylong *za, verylong *zb, long *db)
{
  long i;

  *db = da;
  for (i = 0; i <= da; i++) zcopy(za[i], &zb[i]);
}

void zpoly_print(long da, verylong *za)
{
  long i;

  for (i = da; i >= 0; i--) {
    zwrite(za[i]);
    printf(" ");
  }
  printf("\n");
}

void zpoly_ext_euclid(long dg, long dh, long p, verylong *zg,
                      verylong *zh, verylong *zs,
                      verylong *zt, verylong *zd,
                      long *ds, long *dt, long *dd)
{
  long da, dq, dr, ds1 = 0, ds2 = 0, dt1 = 0, dt2 = 0, i;
  verylong za[POLY_SIZE], zb[POLY_SIZE];
  verylong zq[POLY_SIZE], zr[POLY_SIZE];
  verylong zs1[POLY_SIZE], zs2[POLY_SIZE];
  verylong zt1[POLY_SIZE], zt2[POLY_SIZE];

  if (dh == 0 && zscompare(zh[0], 0l) == 0) {
    zpoly_copy(dg, zg, zd, dd);
    *ds = *dt = 0;
    zone(&zs[0]);
    zzero(&zt[0]);
  }
  for (i = 0; i < POLY_SIZE; i++) {
    za[i] = zb[i] = zq[i] = zr[i] = 0;
    zs1[i] = zs2[i] = zt1[i] = zt2[i] = 0;
  }
  zone(&zs2[0]);
  zzero(&zs1[0]);
  zzero(&zt2[0]);
  zone(&zt1[0]);
  while (dh != 0 || zscompare(zh[0], 0l) != 0) {
    zpoly_div(dg, dh, zg, zh, zq, zr, &dq, &dr);
    zpoly_mod(p, zq, &dq);
    zpoly_mod(p, zr, &dr);
    zpoly_mul(dq, ds1, zq, zs1, za, &da);
    zpoly_sub(ds2, da, zs2, za, zs, ds);
    zpoly_mul(dq, dt1, zq, zt1, za, &da);
    zpoly_sub(dt2, da, zt2, za, zt, dt);
    zpoly_mod(p, zs, ds);
    zpoly_mod(p, zt, dt);
    zpoly_copy(dh, zh, zg, &dg);
    zpoly_copy(dr, zr, zh, &dh);
    zpoly_copy(ds1, zs1, zs2, &ds2);
    zpoly_copy(*ds, zs, zs1, &ds1);
    zpoly_copy(dt1, zt1, zt2, &dt2);
    zpoly_copy(*dt, zt, zt1, &dt1);
    #ifdef DEBUG
    printf("q  = "); zpoly_print(dq, zq);
    printf("r  = "); zpoly_print(dr, zr);
    printf("s  = "); zpoly_print(*ds, zs);
    printf("t  = "); zpoly_print(*dt, zt);
    printf("g  = "); zpoly_print(dg, zg);
    printf("h  = "); zpoly_print(dh, zh);
    printf("s2 = "); zpoly_print(ds2, zs2);
    printf("s1 = "); zpoly_print(ds1, zs1);
    printf("t2 = "); zpoly_print(dt2, zt2);
    printf("t1 = "); zpoly_print(dt1, zt1);
    #endif
  }
  zpoly_copy(dg, zg, zd, dd);
  zpoly_copy(ds2, zs2, zs, ds);
  zpoly_copy(dt2, zt2, zt, dt);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&za[i]);
    zfree(&zb[i]);
    zfree(&zq[i]);
    zfree(&zr[i]);
    zfree(&zs1[i]);
    zfree(&zs2[i]);
    zfree(&zt1[i]);
    zfree(&zt2[i]);
  }
}

void kernel(long m, long n, long p, verylong **zM,
            verylong **zX, long *r)
{
  int found;
  long *c = calloc(m, sizeof(long)), i, j, k, s;
  verylong zD = 0, za = 0, zb = 0, zp = 0;

  assert(c != 0);
  zintoz(p, &zp);
  *r = 0;
  for (i = 0; i < m; i++) c[i] = - 1;
  for (k = 0; k < m; k++) {
    found = 0, j = 0;
    while (!found && j < m) {
      found = zscompare(zM[k][j], 0l) != 0 && c[j] < 0;
      if (!found) j++;
    }
    if (found) {
      zinvmod(zM[k][j], zp, &zD);
      znegate(&zD);
      zintoz(- 1l, &zM[k][j]);
      for (s = k + 1; s < m; s++) {
        zmul(zD, zM[s][j], &za);
        zmod(za, zp, &zM[s][j]);
      }
      for (i = 0; i < n; i++) {
        if (i != j) {
          zcopy(zM[k][i], &zD);
          zzero(&zM[k][i]);
          for (s = k + 1; s < m; s++) {
            zmul(zD, zM[s][j], &za);
            zadd(zM[s][i], za, &zb);
            zmod(zb, zp, &zM[s][i]);
          }
        }
      }
      c[j] = k;
    }
    else {
      for (j = 0; j < n; j++) zzero(&zX[*r][j]);
      for (j = 0; j < n; j++) {
        for (s = 0; s < n; s++) {
          if (j == k) zone(&zX[*r][j]);
          else if (c[s] == j) zcopy(zM[k][s], &zX[*r][j]);
        }
      }
      *r = *r + 1;
    }
  }
  free(c);
  zfree(&zD);
  zfree(&za);
  zfree(&zb);
  zfree(&zp);
}

void Berlekamp_algorithm(long n, long p, verylong *zu,
                         verylong **zc, long *count)
{
  long da, db, dw, i, index = 0, j, k, s, r;
  verylong zd = 0, zn = 0, zp = 0;
  verylong za[POLY_SIZE], zb[POLY_SIZE];
  verylong zw[POLY_SIZE], zX[POLY_SIZE];
  verylong **zq = create_matrix(n, n), **zv = create_matrix(n, n);

  for (i = 0; i < POLY_SIZE; i++)
    za[i] = zb[i] = zw[i] = zX[i] = 0;
  zone(&zq[0][0]);
  zzero(&zX[0]);
  zone(&zX[1]);
  for (k = 1; k < n; k++) zzero(&zq[0][k]);
  zintoz(p, &zp);
  for (k = 1; k < n; k++) {
    zsmul(zp, k, &zn);
    zpoly_pow(1l, n, p, zn, zX, zu, za, &da);
    for (j = 0; j < n; j++)
      zcopy(za[j], &zq[k][j]);
  }
  #ifdef DEBUG
  printf("the Q-matrix is as follows:\n\n");
  for (i = 0; i < n; i++) {
    for (j = 0; j < n; j++) {
      zwrite(zq[i][j]);
      printf(" ");
    }
    printf("\n");
  }
  printf("\n");
  #endif
  for (i = 0; i < n; i++) {
    zsadd(zq[i][i], - 1l, &zd);
    zcopy(zd, &zq[i][i]);
  }
  kernel(n, n, p, zq, zv, &r);
  #ifdef DEBUG
  printf("the linearly independent vectors are as follows:\n\n");
  for (i = 0; i < r; i++) {
    for (j = 0; j < n; j++) {
      zwrite(zv[i][j]);
      printf(" ");
    }
    printf("\n");
  }
  printf("\n");
  #endif
  for (i = 0; i <= n; i++) zcopy(zu[i], &zw[i]);
  dw = n;
  *count = 0;
  for (i = 1; i < r; i++) {
    for (s = 0; s < p; s++) {
      for (j = 0; j < n; j++)
        zcopy(zv[i][j], &za[j]);
      zsadd(za[0], - s, &zd);
      zcopy(zd, &za[0]);
      da = n - 1;
      while (da > 0 && zscompare(za[da], 0l) == 0) da--;
      zpoly_gcd(da, dw, p, za, zw, zb, &db);
      if (db != 0) {
        for (j = 0; j <= db; j++)
          zcopy(zb[j], &zc[*count][j]);
        *count = *count + 1;
      }
    }
    for (j = 0; j < n; j++)
      zcopy(zc[index][j], &zw[j]);
    index++;
    dw = n - 1, j = dw;
    while (dw > 0)
      if (zscompare(zw[j--], 0l) == 0) dw--; else break;
  }
  delete_matrix(n, zq);
  delete_matrix(n, zv);
  zfree(&zd);
  zfree(&zn);
  zfree(&zp);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&za[i]);
    zfree(&zb[i]);
    zfree(&zw[i]);
    zfree(&zX[i]);
  }
}

int main(void)
{
  long i, j, n = 8, p = 13l, r;
  verylong zu[POLY_SIZE];
  verylong **zX = create_matrix(8, 8);

  for (i = 0; i < POLY_SIZE; i++) zu[i] = 0;
  zone(&zu[8]);
  zone(&zu[6]);
  zintoz(10l, &zu[4]);
  zintoz(10l, &zu[3]);
  zintoz(8l, &zu[2]);
  zintoz(2l, &zu[1]);
  zintoz(8l, &zu[0]);
  printf("u = "); zpoly_print(n, zu);
  printf("\n");
  Berlekamp_algorithm(n, p, zu, zX, &r);
  printf("the linear independent polynomials are as follows:\n\n");
  for (i = 0; i < r; i++) {
    for (j = 0; j < n; j++) {
      zwrite(zX[i][j]);
      printf(" ");
    }
    printf("\n");
  }
  delete_matrix(8, zX);
  for (i = 0; i < POLY_SIZE; i++) zfree(&zu[i]);
  return 0;
}
