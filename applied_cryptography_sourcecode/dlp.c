/*
  Author:  Pate Williams (c) 1997

  The following program implements and tests two
  algorithms for solving the discrete logarithm
  problem. The algorithms are baby-step giant-step
  and Pollard's rho algorithms. The implementations
  are from "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al pages 103 - 107.
*/

#include <stdio.h>
#include <stdlib.h>
#include "lip.h"

struct Element {
  long index;
  verylong alpha_index;
};

long Find(long n, verylong value, struct Element *array)
{
  long c, hi = n - 1, lo = 0, mid;

  for (;;) {
    mid = (hi + lo) / 2;
    c = zcompare(value, array[mid].alpha_index);
    if (c == 0) return mid;
    if (c < 0) hi = mid - 1;
    else lo = mid + 1;
    if (lo > hi) return - 1;
  }
}

int BabyStepGiantStep(verylong zalpha, verylong zbeta,
                      verylong zn, verylong zp, verylong *zx)
/* given a generator alpha of a cyclic group G of
   order n and an element beta compute the discrete
   logarithm x returns 0 if not enough memory
   for the problem 1 otherwise */
{
  long i, j, m;
  static verylong za = 0, zd = 0, zg = 0, zm = 0;
  struct Element *element, temp;

  zsqrt(zn, &za, &zd);
  zsadd(za, 1l, &zm);
  m = ztoint(zm);
  element = (struct Element *) malloc(m * sizeof(struct Element));
  if (element == 0) return 0;
  zone(&zd);
  /* construct table */
  for (i = 0; i < m; i++) {
    element[i].index = i;
    element[i].alpha_index = 0;
    zcopy(zd, &element[i].alpha_index);
    zmul(zd, zalpha, &za);
    zmod(za, zp, &zd);
  }
  /* sort on second values */
  for (i = 0; i < m - 1; i++) {
    for (j = i + 1; j < m; j++) {
      if (zcompare(element[i].alpha_index, element[j].alpha_index) > 0) {
        temp = element[i];
        element[i] = element[j];
        element[j] = temp;
      }
    }
  }
  zinvmod(zalpha, zp, &za);
  zexp(za, zm, &zg);
  zmod(zg, zp, &zd);
  zcopy(zbeta, &zg);
  for (i = 0; i < m; i++) {
    printf("%d ", element[i].index);
    zwriteln(element[i].alpha_index);
  }
  for (i = 0; i < m; i++) {
    j = Find(m, zg, element);
    if (j != - 1) {
      zsmul(zm, i, &za);
      zsadd(za, j, zx);
      for (j = 0; j < m; j++)
        zfree(&element[j].alpha_index);
      free(element);
      return 1;
    }
    zmul(zg, zd, &za);
    zmod(za, zp, &zg);
  }
  return 0;
}

void zai(verylong za0, verylong zn, verylong zx0, verylong *za1)
{
  long x = zsmod(zx0, 3l);
  static verylong za = 0;

  if (x == 1)
    zcopy(za0, za1);
  else if (x == 0) {
    zsmul(za0, 2l, &za);
    zmod(za, zn, za1);
  }
  else {
    zsadd(za0, 1l, &za);
    zmod(za, zn, za1);
  }
}

void zbi(verylong zb0, verylong zn, verylong zx0, verylong *zb1)
{
  long x = zsmod(zx0, 3l);
  static verylong zb = 0;

  if (x == 1) {
    zsadd(zb0, 1l, &zb);
    zmod(zb, zn, zb1);
  }
  else if (x == 0) {
    zsmul(zb0, 2l, &zb);
    zmod(zb, zn, zb1);
  }
  else
    zcopy(zb0, zb1);
}

void zfi(verylong zalpha, verylong zbeta, verylong zp, verylong zx0, verylong *zx1)
{
  long x = zsmod(zx0, 3l);

  if (x == 1)
    zmulmod(zbeta, zx0, zp, zx1);
  else if (x == 0)
    zmulmod(zx0, zx0, zp, zx1);
  else
    zmulmod(zalpha, zx0, zp, zx1);
}

int PollardRho(verylong zalpha, verylong zbeta,
               verylong zn, verylong zp, verylong *zx)
{
  long i = 2, j;
  static verylong za0 = 0, za1 = 0, za2 = 0, za3 = 0;
  static verylong zb0 = 0, zb1 = 0, zb2 = 0, zb3 = 0;
  static verylong zx0 = 0, zx1 = 0, zx2 = 0, zx3 = 0;
  static verylong zr = 0, zri = 0;

  zone(&zx0);
  zzero(&za0);
  zzero(&zb0);
  zfi(zalpha, zbeta, zp, zx0, &zx1);
  zai(za0, zn, zx0, &za1);
  zbi(zb0, zn, zx0, &zb1);
  zfi(zalpha, zbeta, zp, zx1, &zx2);
  zai(za1, zn, zx1, &za2);
  zbi(zb1, zn, zx1, &zb2);
  zcopy(za1, &za0);
  zcopy(zb1, &zb0);
  zcopy(zx1, &zx0);
  for (;;) {
    zfi(zalpha, zbeta, zp, zx0, &zx1);
    zai(za0, zn, zx0, &za1);
    zbi(zb0, zn, zx0, &zb1);
    zcopy(za1, &za2);
    zcopy(zb1, &zb2);
    zcopy(zx1, &zx2);
    i++;
    for (j = 0; j < i; j++) {
      zfi(zalpha, zbeta, zp, zx2, &zx3);
      zai(za2, zn, zx2, &za3);
      zbi(zb2, zn, zx2, &zb3);
      zcopy(za3, &za2);
      zcopy(zb3, &zb2);
      zcopy(zx3, &zx2);
    }
    if (zcompare(zx1, zx3) == 0) {
      zsubmod(zb1, zb3, zn, &zr);
      if (zscompare(zr, 0) == 0) return 0;
      zinvmod(zr, zn, &zri);
      zsub(za3, za1, &za0);
      zmulmod(za0, zri, zn, zx);
      return 1;
    }
    zcopy(za1, &za0);
    zcopy(zb1, &zb0);
    zcopy(zx1, &zx0);
  }
}

int main(void)
{
  verylong zalpha = 0, zbeta = 0, zn = 0, zp = 0, zx = 0;

  zintoz(3l, &zalpha);
  zintoz(57l, &zbeta);
  zintoz(112l, &zn);
  zintoz(113l, &zp);
  BabyStepGiantStep(zalpha, zbeta, zn, zp, &zx);
  printf("the discrete logarithm of 57 base 3 = ");
  zwriteln(zx);
  zintoz(2l, &zalpha);
  zintoz(228l, &zbeta);
  zintoz(191l, &zn);
  zintoz(383l, &zp);
  PollardRho(zalpha, zbeta, zn, zp, &zx);
  printf("the discrete logarithm of 228 base 2 = ");
  zwriteln(zx);
  zfree(&zalpha);
  zfree(&zbeta);
  zfree(&zn);
  zfree(&zp);
  zfree(&zx);
  return 0;
}
