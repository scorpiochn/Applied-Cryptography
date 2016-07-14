/*
  Author:  Pate Williams (c) 1997

  Index-calculus algorithm for computing discrete
  logarithms. See "Handbook of Applied Cryptography"
  by Alfred J. Menezes et al 3.6.5 Section 3.68
  Algorithm pages 109 - 111. Also see 3.69 Example
  pages 110 - 111.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define BOUND 1000000l
#define CRT_SIZE 128l
#define DEBUG

struct node { long expon, prime; };

verylong  **create_matrix(long m, long n)
{
  long i;
  verylong **zmatrix = calloc(m, sizeof(verylong *));

  assert(zmatrix != 0);
  for (i = 0; i < m; i++) {
    zmatrix[i] = calloc(n, sizeof(verylong));
    assert(zmatrix[i] != 0);
  }
  return zmatrix;
}

void delete_matrix(long m, long n, verylong **zmatrix)
{
  long i, j;

  for (i = 0; i < m; i++) {
    for (j = 0; j < n; j++)
      zfree(&zmatrix[i][j]);
    free(zmatrix[i]);
  }
  free(zmatrix);
}

void zbinary_ext_gcd(verylong zx, verylong zy,
                     verylong *za, verylong *zb,
                     verylong *zv)
/* returns a * x + b * y = v, v = gcd(x, y) */
{
  verylong zA = 0, zB = 0, zC = 0, zD = 0;
  verylong zX = 0, zY = 0, zc = 0,  zg = 0;
  verylong zu = 0;

  zone(&zg);
  zcopy(zx, &zX);
  zcopy(zy, &zY);
  while (!zodd(zX) && !zodd(zY)) {
    zrshift(zX, 1l, &zc);
    zcopy(zc, &zX);
    zrshift(zY, 1l, &zc);
    zcopy(zc, &zY);
    zlshift(zg, 1l, &zc);
    zcopy(zc, &zg);
  }
  zcopy(zX, &zu);
  zcopy(zY, zv);
  zone(&zA);
  zzero(&zB);
  zzero(&zC);
  zone(&zD);
  do {
    while (!zodd(zu)) {
      zrshift(zu, 1l, &zc);
      zcopy(zc, &zu);
      if (!zodd(zA) && !zodd(zB)) {
        zrshift(zA, 1l, &zc);
        zcopy(zc, &zA);
        zrshift(zB, 1l, &zc);
        zcopy(zc, &zB);
      }
      else {
        zadd(zA, zY, &zc);
        zrshift(zc, 1l, &zA);
        zsub(zB, zX, &zc);
        zrshift(zc, 1l, &zB);
      }
    }
    while (!zodd(*zv)) {
      zrshift(*zv, 1l, &zc);
      zcopy(zc, zv);
      if (!zodd(zC) && !zodd(zD)) {
        zrshift(zC, 1l, &zc);
        zcopy(zc, &zC);
        zrshift(zD, 1l, &zc);
        zcopy(zc, &zD);
      }
      else {
        zadd(zC, zY, &zc);
        zrshift(zc, 1l, &zC);
        zsub(zD, zX, &zc);
        zrshift(zc, 1l, &zD);
      }
    }
    if (zcompare(zu, *zv) >= 0) {
      zsub(zu, *zv, &zc);
      zcopy(zc, &zu);
      zsub(zA, zC, &zc);
      zcopy(zc, &zA);
      zsub(zB, zD, &zc);
      zcopy(zc, &zB);
    }
    else {
      zsub(*zv, zu, &zc);
      zcopy(zc, zv);
      zsub(zC, zA, &zc);
      zcopy(zc, &zC);
      zsub(zD, zB, &zc);
      zcopy(zc, &zD);
    }
  } while (zscompare(zu, 0l) != 0);
  zcopy(zC, za);
  zcopy(zD, zb);
  zmul(zg, *zv, &zc);
  zcopy(zc, zv);
  zfree(&zA);
  zfree(&zB);
  zfree(&zC);
  zfree(&zD);
  zfree(&zX);
  zfree(&zY);
  zfree(&zc);
  zfree(&zg);
  zfree(&zu);
}

void zext_euclid(verylong za, verylong zb, verylong *zx,
                 verylong *zy, verylong *zd)
{
  verylong zA = 0, zB = 0, zc = 0, zq = 0, zr = 0;
  verylong zx1 = 0, zx2 = 0, zy1 = 0, zy2 = 0;

  if (zscompare(zb, 0l) == 0) {
    zone(zd);
    zone(zx);
    zzero(zy);
  }
  else {
    zcopy(za, &zA);
    zcopy(zb, &zB);
    zone(&zx2);
    zzero(&zx1);
    zzero(&zy2);
    zone(&zy1);
    while (zscompare(zB, 0l) > 0) {
      zdiv(zA, zB, &zq, &zr);
      zmul(zq, zx1, &zc);
      zsub(zx2, zc, zx);
      zmul(zq, zy1, &zc);
      zsub(zy2, zc, zy);
      zcopy(zB, &zA);
      zcopy(zr, &zB);
      zcopy(zx1, &zx2);
      zcopy(*zx, &zx1);
      zcopy(zy1, &zy2);
      zcopy(*zy, &zy1);
    }
    zcopy(zA, zd);
    zcopy(zx2, zx);
    zcopy(zy2, zy);
  }
  zfree(&zA);
  zfree(&zB);
  zfree(&zc);
  zfree(&zq);
  zfree(&zr);
  zfree(&zx1);
  zfree(&zx2);
  zfree(&zy1);
  zfree(&zy2);
}

void zinvmod_1(verylong zx, verylong zy, verylong *zi)
{
  verylong zb = 0, zv = 0;

  zext_euclid(zx, zy, zi, &zb, &zv);
  if (zscompare(*zi, 0l) < 0) {
    zadd(*zi, zy, &zb);
    zcopy(zb, zi);
  }
  if (zscompare(zv, 1l) != 0) zzero(zi);
  zfree(&zb);
  zfree(&zv);
}

void gaussian_elimination(long m, long n, verylong zp,
                          verylong *zb, verylong *zx,
                          verylong **zm)
{
  int found;
  long i, j, k, l;
  verylong zck = 0, zd = 0, zs = 0, zsum = 0, zt = 0;

  for (j = 0; j < n; j++) {
    found = 0, i = j;
    while (!found && i < m) {
      found = zscompare(zm[i][j], 0l) != 0;
      if (found) {
        zinvmod_1(zm[i][j], zp, &zd);
        found = zscompare(zd, 0l) != 0;
      }
      if (!found) i++;
    }
    if (i > j) {
      /* exchange colums */
      for (l = j; l < n; l++) {
        zcopy(zm[i][l], &zt);
        zcopy(zm[j][l], &zm[i][l]);
        zcopy(zt, &zm[j][l]);
      }
      zcopy(zb[i], &zt);
      zcopy(zb[j], &zb[i]);
      zcopy(zt, &zb[j]);
    }
    for (k = j + 1; k < m; k++) {
      zmulmod(zd, zm[k][j], zp, &zck);
      for (l = j + 1; l < n; l++) {
        zmulmod(zck, zm[j][l], zp, &zt);
        zsubmod(zm[k][l], zt, zp, &zsum);
        zcopy(zsum, &zm[k][l]);
      }
      zmulmod(zck, zb[j], zp, &zt);
      zsubmod(zb[k], zt, zp, &zsum);
      zcopy(zsum, &zb[k]);
    }
  }
  for (i = n - 1; i >= 0; i--) {
    zzero(&zsum);
    for (j = i + 1; j < n; j++) {
      zmulmod(zm[i][j], zx[j], zp, &zt);
      zaddmod(zt, zsum, zp, &zs);
      zcopy(zs, &zsum);
    }
    zinvmod(zm[i][i], zp, &zd);
    zsubmod(zb[i], zsum, zp, &zt);
    zmulmod(zd, zt, zp, &zx[i]);
  }
  zfree(&zck);
  zfree(&zd);
  zfree(&zs);
  zfree(&zsum);
  zfree(&zt);
}

void Garner(long t, verylong *zm, verylong *zv, verylong *zx)
/* solution of the Chinese remaider theorem */
{
  long i, j;
  verylong za = 0, zb = 0, zu = 0, zC[CRT_SIZE];

  for (i = 0; i < CRT_SIZE; i++) zC[i] = 0;
  for (i = 1; i < t; i++) {
    zone(&zC[i]);
    for (j = 0; j <= i - 1; j++) {
      zinvmod(zm[j], zm[i], &zu);
      zmulmod(zu, zC[i], zm[i], &za);
      zcopy(za, &zC[i]);
    }
  }
  zcopy(zv[0], &zu);
  zcopy(zu, zx);
  for (i = 1; i < t; i++) {
    zsub(zv[i], *zx, &za);
    zmulmod(za, zC[i], zm[i], &zu);
    zone(&za);
    for (j = 0; j <= i - 1; j++) {
      zmul(za, zm[j], &zb);
      zcopy(zb, &za);
    }
    zmul(za, zu, &zb);
    zadd(*zx, zb, &za);
    zcopy(za, zx);
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zu);
  for (i = 0; i < CRT_SIZE; i++) zfree(&zC[i]);
}

void trial_divide(struct node *p, verylong zn, long *n)
{
  long e, q;
  verylong za = 0, zb = 0;

  zcopy(zn, &za);
  *n = 0;
  zpstart2();
  do {
    e = 0;
    q = zpnext();
    while (zsmod(za, q) == 0) {
      e++;
      zsdiv(za, q, &zb);
      zcopy(zb, &za);
    }
    if (e != 0) {
      p[*n].expon = e;
      p[*n].prime = q;
      *n = *n + 1;
    }
  } while (!zprobprime(za, 5l) && q < BOUND);
  if (zscompare(za, 1l) != 0) {
    p[*n].expon = 1;
    p[*n].prime = ztoint(za);
    *n = *n + 1;
  }
  zfree(&za);
  zfree(&zb);
}

void solve(long m, long n, verylong zn, verylong *zb,
           verylong *zx, verylong **zm)
{
  long i, j, k, q;
  struct node p[32];
  verylong zq = 0;
  verylong *zB = calloc(m, sizeof(verylong)), *zp;
  verylong *zv = calloc(n, sizeof(verylong));
  verylong **zM = create_matrix(m, n), **zX;

  assert(zB != 0 && zv != 0);
  trial_divide(p, zn, &q);
  zp = calloc(q, sizeof(verylong));
  assert(zp != 0);
  zX = create_matrix(q, n);
  for (i = 0; i < q; i++) {
    for (j = 0; j < m; j++) {
      for (k = 0; k < n; k++)
        zcopy(zm[j][k], &zM[j][k]);
      zcopy(zb[j], &zB[j]);
    }
    zintoz(p[i].prime, &zq);
    zsexp(zq, p[i].expon, &zp[i]);
    gaussian_elimination(m, n, zp[i], zB, zX[i], zM);
  }
  for (i = 0; i < n; i++) {
    for (j = 0; j < q; j++)
      zcopy(zX[j][i], &zv[j]);
    Garner(q, zp, zv, &zx[i]);
  }
  delete_matrix(m, n, zM);
  delete_matrix(q, n, zX);
  free(zB);
  free(zp);
  free(zv);
  zfree(&zq);
}

int trial_division(long t, struct node *p, verylong zn)
{
  int c;
  long e, i, q, s = 0;
  verylong za = 0, zt = 0;

  zpstart2();
  zcopy(zn, &zt);
  for (i = 0; i < t; i++)
    p[i].expon = p[i].prime = 0;
  do {
    q = zpnext();
    e = 0;
    while (zsmod(zt, q) == 0) {
      e++;
      zsdiv(zt, q, &za);
      zcopy(za, &zt);
    }
    if (e != 0) {
      p[s].expon = e;
      p[s].prime = q;
    }
    else {
      p[s].expon = 0;
      p[s].prime = 0;
    }
    s++;
    c = zscompare(zt, 1l) == 0;
  } while (!c && s < t);
  zfree(&za);
  zfree(&zt);
  return c;
}

void index_calculus(long t, verylong za, verylong zb,
                    verylong zn, verylong zp, verylong *zl)
{
  int found = 0;
  long c = 1, count = 0, i, k, m = t + c;
  struct node *p = calloc(t, sizeof(struct node));
  verylong *zc = calloc(m, sizeof(verylong));
  verylong *zx = calloc(t, sizeof(verylong));
  verylong **zm = create_matrix(m, t);
  verylong zd = 0, zk = 0, zq = 0, zr = 0, zs = 0;

  assert(p != 0);
  assert(zc != 0);
  assert(zx != 0);
  zrstarts(time(NULL));
  while (count < m) {
    zrandomb(zn, &zk);
    #ifdef DEBUG
    switch (count) {
      case 0 : k = 100; break;
      case 1 : k =  18; break;
      case 2 : k =  12; break;
      case 3 : k =  62; break;
      case 4 : k = 143; break;
      case 5 : k = 206; break;
    }
    zintoz(k, &zk);
    #endif
    zexpmod(za, zk, zp, &zq);
    if (trial_division(t, p, zq)) {
      zcopy(zk, &zc[count]);
      for (i = 0; i < t; i++) {
        if (p[i].prime == 0)
          zzero(&zm[count][i]);
        else
          zintoz(p[i].expon, &zm[count][i]);
      }
      count++;
    }
  }
  #ifdef DEBUG
  {
    long j;
    for (i = 0; i < m; i++) {
      for (j = 0; j < t; j++) {
        zwrite(zm[i][j]);
        printf(" ");
      }
      zwriteln(zc[i]);
    }
  }
  #endif
  solve(m, t, zn, zc, zx, zm);
  #ifdef DEBUG
  for (i = 0; i < t; i++)
    zwriteln(zx[i]);
  #endif
  while (!found) {
    zrandomb(zn, &zk);
    zexp(za, zk, &zr);
    zmulmod(zb, zr, zp, &zq);
    if (trial_division(t, p, zq)) {
      found = 1;
      zzero(&zs);
      for (i = 0; i < t; i++) {
        zsmulmod(zx[i], p[i].expon, zn, &zr);
        zaddmod(zs, zr, zn, &zd);
        zcopy(zd, &zs);
      }
      zsubmod(zs, zk, zn, zl);
    }
  }
  zfree(&zd);
  zfree(&zk);
  zfree(&zn);
  zfree(&zq);
  zfree(&zr);
  zfree(&zs);
  for (i = 0; i < m; i++) zfree(&zc[i]);
  for (i = 0; i < t; i++) zfree(&zx[i]);
  delete_matrix(m, t, zm);
}

int main(void)
{
  long t = 5l;
  verylong za = 0, zb = 0, zl = 0, zn = 0, zp = 0;

  zintoz(6l, &za);
  zintoz(13l, &zb);
  zintoz(228l, &zn);
  zintoz(229l, &zp);
  index_calculus(t, za, zb, zn, zp, &zl);
  zwriteln(zl);
  zfree(&za);
  zfree(&zb);
  zfree(&zl);
  zfree(&zn);
  zfree(&zp);
  return 0;
}
