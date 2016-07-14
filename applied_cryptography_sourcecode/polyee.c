/*
  Author:  Pate Williams (c) 1997

  Polynomial extended Euclidean algorithm. See
  "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 2.6.2 Section 2.2.1 Algorithm
  page 82.
*/

#include <stdio.h>
#include "lip.h"

#define DEBUG
#define POLY_SIZE 8192l

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

void zpoly_pow(long degreeA, long degreem, verylong zn,
               verylong *zA, verylong *zm, verylong *zs,
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
    }
    zcopy(za, &zb);
    zrshift(zb, 1l, &za);
    if (zscompare(za, 0l) > 0) {
      /* x = (x * x) % m; */
      for (i = 0; i <= dx; i++) zcopy(zx[i], &zy[i]);
      zpoly_mul(dx, dx, zx, zy, zp, &dp);
      zpoly_div(dp, degreem, zp, zm, zq, zx, &dq, &dx);
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
  verylong zc = 0, zp = 0;
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
  while (nonzero) {
    zpoly_div(*da, db, za, zb, zq, zr, &dq, &dr);
    zintoz(p, &zp);
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
  zfree(&zc);
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

void zpoly_mod(long p, verylong *za, long *da)
{
  long i;

  for (i = 0; i <= *da; i++)
    zintoz(zsmod(za[i], p), &za[i]);
  while (*da > 0 && zscompare(za[*da], 0l) == 0) *da = *da - 1;
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

int main(void)
{
  long dd, dg, dh, ds, dt, i, p = 2;
  verylong zg[POLY_SIZE], zh[POLY_SIZE];
  verylong zd[POLY_SIZE], zs[POLY_SIZE];
  verylong zt[POLY_SIZE];

  for (i = 0; i < POLY_SIZE; i++)
    zd[i] = zg[i] = zh[i] = zs[i] = zt[i] = 0;
  dg = 10;
  for (i = 0; i <= dg; i++) zzero(&zg[i]);
  zintoz(1l, &zg[10]);
  zintoz(1l, &zg[9]);
  zintoz(1l, &zg[8]);
  zintoz(1l, &zg[6]);
  zintoz(1l, &zg[5]);
  zintoz(1l, &zg[4]);
  zintoz(1l, &zg[0]);
  dh = 9;
  for (i = 0; i <= dh; i++) zzero(&zh[i]);
  zintoz(1l, &zh[9]);
  zintoz(1l, &zh[6]);
  zintoz(1l, &zh[5]);
  zintoz(1l, &zh[3]);
  zintoz(1l, &zh[2]);
  zintoz(1l, &zh[0]);
  zpoly_ext_euclid(dg, dh, p, zg, zh, zs, zt, zd, &ds, &dt, &dd);
  printf("s  = "); zpoly_print(ds, zs);
  printf("t  = "); zpoly_print(dt, zt);
  printf("d  = "); zpoly_print(dd, zd);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zd[i]);
    zfree(&zg[i]);
    zfree(&zh[i]);
    zfree(&zs[i]);
    zfree(&zt[i]);
  }
  return 0;
}
