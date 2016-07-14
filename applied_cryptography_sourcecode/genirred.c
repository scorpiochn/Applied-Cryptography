/*
  Author:  Pate Williams (c) 1997

  Program to generate a random irreducible
  polynomial contained in Zp p prime. See
  "Handbook of Applied Cryptography" pages
  157 - 158. Also see "A Course in Computa-
  tional Algebraic Number Theory" by Henri
  Cohen pages 37 and 127.
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"
#define POLY_SIZE 8192l

void zpoly_copy(long da, verylong *za, verylong *zb, long *db)
{
  long i;

  *db = da;
  for (i = 0; i <= da; i++) zcopy(za[i], &zb[i]);
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

void zpoly_mod(verylong zp, verylong *za, long *da)
{
  long i;
  verylong zb = 0;

  for (i = 0; i <= *da; i++) {
    zmod(za[i], zp, &zb);
    zcopy(zb, &za[i]);
  }
  while (*da > 0 && zscompare(za[*da], 0l) == 0) *da = *da - 1;
  zfree(&zb);
}

void zpoly_pow(long degreeA, long degreem, verylong zn,
               verylong zp, verylong *zA,
               verylong *zm, verylong *zs,
               long *ds)
{
  long dP, dq, dx = degreeA, i;
  verylong za = 0, zb = 0, zP[POLY_SIZE], zq[POLY_SIZE],
           zx[POLY_SIZE], zy[POLY_SIZE];

  for (i = 0; i < POLY_SIZE; i++)
    zP[i] = zq[i] = zx[i] = zy[i] = 0;
  *ds = 0;
  zcopy(zn, &za);
  zone(&zs[0]);
  for (i = 0; i <= dx; i++) zcopy(zA[i], &zx[i]);
  while (zscompare(za, 0l) > 0) {
    if (zodd(za)) {
      /* s = (s * x) % m; */
      zpoly_mul(*ds, dx, zs, zx, zP, &dP);
      zpoly_div(dP, degreem, zP, zm, zq, zs, &dq, ds);
      zpoly_mod(zp, zs, ds);
    }
    zcopy(za, &zb);
    zrshift(zb, 1l, &za);
    if (zscompare(za, 0l) > 0) {
      /* x = (x * x) % m; */
      for (i = 0; i <= dx; i++) zcopy(zx[i], &zy[i]);
      zpoly_mul(dx, dx, zx, zy, zP, &dP);
      zpoly_div(dP, degreem, zP, zm, zq, zx, &dq, &dx);
      zpoly_mod(zp, zx, &dx);
    }
  }
  zfree(&za);
  zfree(&zb);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zP[i]);
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

void zpoly_gcd(long degreeA, long degreeB, verylong zp,
               verylong *zA, verylong *zB, verylong *za,
               long *da)
{
  int nonzero = 0, zero;
  long db, dq, dr, i;
  verylong zc = 0;
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
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zb[i]);
    zfree(&zq[i]);
    zfree(&zr[i]);
  }
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

void zpoly_ext_euclid(long dg, long dh, verylong zp, verylong *zg,
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
    zpoly_mod(zp, zq, &dq);
    zpoly_mod(zp, zr, &dr);
    zpoly_mul(dq, ds1, zq, zs1, za, &da);
    zpoly_sub(ds2, da, zs2, za, zs, ds);
    zpoly_mul(dq, dt1, zq, zt1, za, &da);
    zpoly_sub(dt2, da, zt2, za, zt, dt);
    zpoly_mod(zp, zs, ds);
    zpoly_mod(zp, zt, dt);
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

void Recurse(long degreeA, verylong zp, verylong *zA,
             verylong *zroot, long *rootSize)
{
  long dd, degreeB, dq, dr, du = 1, i;
  verylong zD = 0, za = 0, zb = 0, zc = 0, ze = 0;
  verylong zn = 0;
  verylong zB[POLY_SIZE], zd[POLY_SIZE];
  verylong zq[POLY_SIZE], zr[POLY_SIZE];
  verylong zu[2];

  for (i = 0; i < POLY_SIZE; i++)
    zB[i] = zd[i] = zq[i] = zr[i] = 0;
  zu[0] = zu[1] = 0;
  if (degreeA != 0) {
    if (degreeA == 1) {
      if (zscompare(zA[1], 0l) != 0) {
         zinvmod(zA[1], zp, &za);
         zmul(zA[0], za, &zb);
         znegate(&zb);
         zmod(zb, zp, &zroot[*rootSize]);
      }
      *rootSize = *rootSize + 1;
    }
    else if (degreeA == 2) {
      zsq(zA[1], &za);
      zmul(zA[0], zA[2], &zb);
      zlshift(zb, 2l, &zc);
      zsub(za, zc, &zb);
      zmod(zb, zp, &zD);
      zsqrtmod(zD, zp, &ze);
      zlshift(zA[2], 1l, &za);
      zinvmod(za, zp, &zD);
      zsub(ze, zA[1], &za);
      zmulmod(za, zD, zp, &zroot[*rootSize]);
      *rootSize = *rootSize + 1;
      znegate(&zA[1]);
      znegate(&ze);
      zadd(zA[1], ze, &za);
      zmulmod(za, zD, zp, &zroot[*rootSize]);
      *rootSize = *rootSize + 1;
    }
    else {
      zsadd(zp, - 1l, &za);
      zrshift(za, 1l, &zn);
      do {
        zrandomb(zp, &za);
        zcopy(za, &zu[0]);
        zone(&zu[1]);
        zpoly_pow(du, degreeA, zn, zp, zu, zA, zd, &dd);
        zsadd(zd[0], - 1l, &za);
        zcopy(za, &zd[0]);
        zpoly_gcd(dd, degreeA, zp, zd, zA, zB, &degreeB);
      } while (degreeB == 0 || degreeB == degreeA);
      Recurse(degreeB, zp, zB, zroot, rootSize);
      zpoly_div(degreeA, degreeB, zA, zB, zq, zr, &dq, &dr);
      zpoly_mod(zp, zq, &dq);
      Recurse(dq, zp, zq, zroot, rootSize);
    }
  }
  zfree(&zD);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&ze);
  zfree(&zn);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zB[i]);
    zfree(&zd[i]);
    zfree(&zq[i]);
    zfree(&zr[i]);
  }
  zfree(&zu[0]);
  zfree(&zu[1]);
}

long horner(long degreeP, long p, long x, verylong *zP)
{
  long i, r;
  verylong za = 0, zr = 0;

  zcopy(zP[degreeP], &zr);
  for (i = degreeP - 1; i >= 0; i--) {
    zsmul(zr, x, &za);
    zadd(za, zP[i], &zr);
  }
  r = zsmod(zr, p);
  zfree(&za);
  zfree(&zr);
  return r;
}

void FindRootsModuloAPrime(long degreeP, verylong zp,
                           verylong *zP, verylong *zroot,
                           long *rootSize)
{
  long degreeA, dy, i, j, p, r;
  verylong za = 0, zt = 0;
  verylong zA[POLY_SIZE], zx[POLY_SIZE], zy[POLY_SIZE];

  for (i = 0; i < POLY_SIZE; i++)
    zA[i] = zx[i] = zy[i] = 0;
  *rootSize = 0;
  if (zscompare(zp, degreeP) <= 0) {
    p = ztoint(zp);
    for (i = 0; i < p; i++) {
      r = horner(degreeP, p, i, zP);
      if (r == 0) {
        zintoz(i, &zroot[*rootSize]);
        *rootSize = *rootSize + 1;
      }
    }
  }
  else {
    zzero(&zx[0]);
    zone(&zx[1]);
    zpoly_pow(1, degreeP, zp, zp, zx, zP, zy, &dy);
    zsadd(zy[1], - 1l, &za);
    zcopy(za, &zy[1]);
    zpoly_gcd(dy, degreeP, zp, zy, zP, zA, &degreeA);
    if (zscompare(zA[0], 0l) == 0) {
      zzero(&zroot[*rootSize]);
      *rootSize = *rootSize + 1;
      for (i = 0; i < degreeA; i++)
        zcopy(zA[i + 1], &zA[i]);
      degreeA--;
    }
    Recurse(degreeA, zp, zA, zroot, rootSize);
    /* sort the roots using selection sort */
    for (i = 0; i < *rootSize - 1; i++) {
      for (j = i + 1; j < *rootSize; j++) {
        if (zcompare(zroot[i], zroot[j]) > 0) {
          zcopy(zroot[i], &zt);
          zcopy(zroot[j], &zroot[i]);
          zcopy(zt, &zroot[j]);
        }
      }
    }
  }
  zfree(&zt);
  for (i = 0; i < POLY_SIZE; i++) {
    zfree(&zA[i]);
    zfree(&zx[i]);
    zfree(&zy[i]);
  }
}

void generate(long m, verylong zp, verylong *zf)
/* generates a random irreducible polynomial over Zp
   of degree m */
{
  long i, rootSize;
  verylong *zroot;

  zroot = calloc(m + 1, sizeof(verylong));
  if (!zroot) {
    fprintf(stderr, "fatal error\ninsufficient memory\n");
    exit(1);
  }
  zone(&zf[0]);
  do {
    for (i = 1; i < m; i++) zrandomb(zp, &zf[i]);
    zone(&zf[m]);
    FindRootsModuloAPrime(m, zp, zf, zroot, &rootSize);
  } while (rootSize);
  for (i = 0; i <= m; i++) zfree(&zroot[i]);
}

int main(void)
{
  char answer[256];
  int non, one;
  long i, j, m;
  verylong zf[POLY_SIZE], zp = 0;

  zrstarts(time(NULL));
  for (i = 0; i < POLY_SIZE; i++) zf[i] = 0;
  do {
    printf("degree of polynomial: ");
    scanf("%d", &m);
    do {
      printf("prime: ");
      zread(&zp);
    } while (!zprobprime(zp, 5l));
    generate(m, zp, zf);
    printf("a random irreducible polynomial of ");
    printf("degree %ld over Z", m);
    zwrite(zp);
    printf(" is as follows:\n");
    for (i = m; i >= 0; i--) {
      zwrite(zf[i]);
      printf(" ");
    }
    printf("\n");
    for (i = m; i >= 0; i--) {
      if (zscompare(zf[i], 0l) != 0) {
        if (i != m) {
          non = 0;
          for (j = i - 1; !non && j >= 0; j--)
            non = zscompare(zf[j], 0l) != 0;
          if (non) printf(" + ");
          one = zscompare(zf[i], 1l) == 0;
          if (!one) zwrite(zf[i]);
          if (i == 0 && one) printf(" + 1");
        }
        if (i == 0) printf("\n");
        else if (i == 1) {
          if (one) printf("x"); else printf(" * x");
        }
        else if (i == m) printf("x ^ %ld", i);
        else if (one) printf("x ^ %ld", i);
        else printf(" * x ^ %ld", i);
      }
    }
    printf("again (n or y)? ");
    scanf("%s", answer);
  } while (tolower(answer[0]) == 'y');
  zfree(&zp);
  for (i = 0; i < POLY_SIZE; i++) zfree(&zf[i]);
  return 0;
}
