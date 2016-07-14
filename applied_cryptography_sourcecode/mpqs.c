/*
  Author:  Pate Williams (c) 1997

  Quadratic sieve factoring algorithm. See
  "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al 3.21 Algorithm page 96.
  Also see "A Course in Computational
  Algebraic Number Theory" by Henri Cohen
  Section 10.4.2 pages 492 - 493.
  The command line is as follows:

  mpqs number_primes long_integer

  where long_integer is to be factored or

  mpqs number_primes base exponent addend

  where the number base ^ exponent + addend
  is to be factored.
*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "lip.h"

#define LARGE_PRIME_LIMIT 10000l
#define NUMBER_PRIMES 1229l
#define TRIAL_DIVIDE_LIMIT 100000l

typedef struct Node * NodePtr;

struct Node {
  long expon;
  verylong value;
  NodePtr next;
};

int Insert(int e, verylong v, NodePtr *list)
{
  NodePtr currentPtr, newPtr, previousPtr;

  newPtr = malloc(sizeof(struct Node));
  if (newPtr == 0) return 0;
  newPtr->expon = e;
  newPtr->value = 0;
  zcopy(v, &newPtr->value);
  previousPtr = 0;
  for (currentPtr = *list; currentPtr != 0 &&
       zcompare(v, currentPtr->value) > 0; currentPtr = currentPtr->next)
    previousPtr = currentPtr;
  if (currentPtr != 0 && zcompare(v, currentPtr->value) == 0) {
    currentPtr->expon++;
    zfree(&newPtr->value);
    free(newPtr);
  }
  else if (previousPtr == 0) {
    newPtr->next = *list;
    *list = newPtr;
  }
  else {
    previousPtr->next = newPtr;
    newPtr->next = currentPtr;
  }
  return 1;
}

void Delete(NodePtr *list)
{
  NodePtr currentPtr = *list, tempPtr;

  while (currentPtr != 0) {
    zfree(&currentPtr->value);
    tempPtr = currentPtr;
    currentPtr = currentPtr->next;
    free(tempPtr);
  }
  *list = 0;
}

long Find(long value, long *array)
{
  long hi = NUMBER_PRIMES - 1, lo = 0, mid;

  for (;;) {
    mid = (hi + lo) / 2;
    if (value == array[mid]) return mid;
    if (value < array[mid]) hi = mid - 1;
    else lo = mid + 1;
    if (lo > hi) return - 1;
  }
}

void zpow(long base, long exponent, verylong *zs)
{
  static verylong za = 0, zt = 0;

  zone(zs);
  zzero(&zt);
  zsadd(zt, base, &zt);
  while (exponent > 0) {
    zcopy(*zs, &za);
    if ((exponent & 1) == 1) zmul(za, zt, zs);
    exponent >>= 1;
    zcopy(zt, &za);
    zmul(za, za, &zt);
  }
}

void zQx(long x, verylong zA, verylong zB, verylong zN, verylong *zQ)
/* Q(x) = ((A * x + B) ^ 2 - N) / A */
{
  static verylong zu = 0, zv = 0;

  zintoz(x, &zv);
  zmul(zv, zA, &zu);
  zadd(zu, zB, &zv);
  zmul(zv, zv, &zu);
  zsub(zu, zN, &zv);
  zdiv(zv, zA, zQ, &zu);
}

int TrialDivision(char *e, long t, long *p, long *q, verylong *zq)
/* returns 1 if number can be factored using the prime base
   and possibly one large prime */
{
  long count, i, r;
  static verylong zr = 0;

  for (i = 0; i < t; i++) e[i] = 0;
  if (zscompare(*zq, 0l) < 0) {
    e[0] = 1;
    znegate(zq);
  }
  for (i = 1; i < t; i++) {
    r = p[i];
    if (zsmod(*zq, r) == 0l) {
      count = 0;
      do {
        count++;
        zsdiv(*zq, r, &zr);
        zcopy(zr, zq);
      } while (zsmod(*zq, r) == 0);
      e[i] = (char) count;
      if (zscompare(*zq, 1l) == 0) return 1;
      if (zprobprime(*zq, 5)) {
        if (zscompare(*zq, LARGE_PRIME_LIMIT) <= 0) {
          r = ztoint(*zq);
          e[Find(r, q)] = (char) 1;
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}

int TrialDivide(verylong *zn, NodePtr *list)
/* returns 1 if last factor is prime 0 otherwise */
{
  int flag1 = 0, flag2 = 0, found;
  long count, p;
  NodePtr l;
  static verylong zp = 0, zr = 0;

  zpstart2();
  do {
    p = zpnext();
    if (zsmod(*zn, p) == 0) {
      count = 0;
      do {
        count++;
        zsdiv(*zn, p, &zr);
        zcopy(zr, zn);
      } while (zsmod(*zn, p) == 0);
      zintoz(p, &zp);
      found = 0;
      for (l = *list; l != 0 && !found;) {
        found = zcompare(zp, l->value) == 0;
        if (!found) l = l->next;
      }
      if (found) l->expon++;
      else
        Insert(count, zp, list);
      flag1 = zscompare(*zn, 1l) == 0;
      flag2 = zprobprime(*zn, 5);
    }
  } while (p <= TRIAL_DIVIDE_LIMIT && !flag1 && !flag2);
  if (!flag1) Insert(1, *zn, list);
  return flag2;
}

int mpqs(long n, verylong *zn, NodePtr *list)
/* returns - 1 if not enough memory 0 if number not
   completely factored 1 otherwise */
{
  char D, Msi, f[NUMBER_PRIMES], z[NUMBER_PRIMES], **e, **v;
  int flag1 = 0, flag2, found, ln2, lnq, *lnp, *sieve;
  long b, i = 0, j, k, l, length, m, s, t = 0, t1, x, x_max, x_min;
  long b_max, b_min, size, q[NUMBER_PRIMES], r, r1, r2, *c, *p, *x1, *x2;
  static verylong zA = 0, zB = 0, zD = 0;
  static verylong za = 0, zb = 0, zc = 0, zd = 0, zq = 0, zt = 0;
  static verylong zr = 0, zx = 0, zy = 0;
  verylong *a;

  ln2 = log(LARGE_PRIME_LIMIT);
  p = (long *) malloc(n * sizeof(long));
  p[t++] = - 1l;
  /* get the prime base of the first n primes such that
     (N / p) = 1, where (* / *) is the Jacobi symbol */
  zpstart2();
  do {
    s = zpnext();
    zintoz(s, &zq);
    if (i < NUMBER_PRIMES) q[i++] = s;
    m = zjacobi(*zn, zq);
    if (m == 0 || m == 1) p[t++] = s;
  } while (t < n);
  while (i < NUMBER_PRIMES) q[i++] = zpnext();
  t1 = t + 1;
  b_max = p[t + 1] + 1;
  b_min = - b_max;
  size = b_max - b_min + 1;
  /* allocate the required matrices and vectors */
  sieve = (int *) malloc(size * sizeof(int));
  a = (verylong *) malloc(t1 * sizeof(verylong));
  e = (char **) malloc(t1 * sizeof(char *));
  v = (char **) malloc(t1 * sizeof(char *));
  c = (long *) malloc(t1 * sizeof(long));
  lnp = (int *) malloc(t * sizeof(int));
  x1 = (long *) malloc(t * sizeof(long));
  x2 = (long *) malloc(t * sizeof(long));
  for (i = 0; i < t1; i++) {
    a[i] = 0;
    e[i] = (char *) malloc(NUMBER_PRIMES * sizeof(char));
    v[i] = (char *) malloc(NUMBER_PRIMES * sizeof(char));
  }
  if (a == 0 || e == 0 || v == 0 || e[t1 - 1] == 0 || v[t1 - 1] == 0 ||
      c == 0 || lnp == 0 || p == 0 || sieve == 0 || x1 == 0 || x2 == 0) {
  /* memory allocation error */
    for (i = 0; i < t1; i++) {
      zfree(&a[i]);
      free(e[i]);
      free(v[i]);
    }
    free(a);
    free(e);
    free(v);
    free(c);
    free(p);
    free(x1);
    free(x2);
    free(lnp);
    free(sieve);
    return - 1;
  }
  for (i = 1; i < t; i++)
    lnp[i] = log(p[i]);
  /* calculate the minimum length of the coefficient A */
  zsmul(*zn, 2l, &za);
  zsqrt(za, &zb, &zd);
  zsdiv(zb, b_max, &za);
  length = z2log(za);
  if (length < 3) length = 3;
  zpstart2();
  for (i = 0; i < t1;) {
    do
      zrandomprime(length, 5, &zA, zrandomb);
    while (zjacobi(*zn, zA) != 1);
    /* calculate polynomial coefficients A, and B*/
    if (zcompare(*zn, zA) >= 0)
      zmod(*zn, zA, &zr);
    else
      zcopy(*zn, &zr);
    zsqrtmod(zr, zA, &zB);
    zcopy(zB, &zb);
    zmul(zb, zb, &za);
    zsub(za, *zn, &zb);
    zcopy(zB, &zD);
    znegate(&zD);
    zdiv(zB, zA, &za, &zb);
    zcopy(za, &zb);
    znegate(&zb);
    zsadd(zb, b_min, &zt);
    x_min = ztoint(zt);
    zsadd(za, b_max, &zt);
    x_max = ztoint(zt);
    /* calculate the roots of the polynomial modulo the prime base */
    for (l = 1; l < t; l++) {
      r = p[l];
      zintoz(r, &zt);
      if (zcompare(*zn, zt) >= 0)
        zmod(*zn, zt, &zr);
      else
        zcopy(*zn, &zr);
      zsqrtmod(zr, zt, &za);
      s = ztoint(za);
      zsadd(zD, s, &zt);
      zdiv(zt, zA, &za, &zb);
      x1[l] = zsmod(za, r);
      zsadd(zD, - s, &zt);
      zdiv(zD, zA, &za, &zb);
      x2[l] = zsmod(za, r);
    }
    for (x = x_min; x <= x_max && i < t1; x++) {
      zQx(x, zA, zB, *zn, &zq);
      zcopy(zq, &zt);
      zabs(&zt);
      lnq = zln(zt);
      /* initialize the sieve to ln(Q(x)) */
      for (b = 0; b < size; b++)
        sieve[b] = lnq;
      for (l = 1; l < t; l++) {
        r = p[l];
        lnq = lnp[l];
        r1 = (x - x1[l]) % r;
        if (r1 < 0) r1 += r;
        for (m = r1; m < size; m += r)
          sieve[m] -= lnq;
        if (x1[l] == x2[l]) continue;
        r2 = (x - x2[l]) % r;
        if (r2 < 0) r2 += r;
        for (m = r2; m < size; m += r)
          sieve[m] -= lnq;
      }
      for (b = 0; b < size && i < t1; b++) {
        if (sieve[b] <= 4 * ln2) {
          if (TrialDivision(e[i], t, p, q, &zq)) {
            /* a[i] = A * x + B */
            zsmul(zA, x, &za);
            zadd(za, zB, &a[i]);
            for (l = 0; l < NUMBER_PRIMES; l++)
              v[i][l] = (char) (e[i][l] % 2);
            i++;
            printf("\b\b\b\b\b\b\b%6ld", i);
          }
        }
      }
    }
  }
  t = NUMBER_PRIMES;
  /* find the kernel of the v matrix over F2 */
  if (i == t1) {
    for (k = 0; k < t1; k++) {
      found = 0, j = 0;
      while (!found && j < t1) {
        found = v[k][j] != 0 && c[j] < 0;
        if (!found) j++;
      }
      if (found) {
        v[k][j] = 1;
        for (i = 0; i < t; i++) {
          if (i != j) {
            D = v[k][i];
            v[k][i] = 0;
            for (s = k + 1; s < t1; s++) {
              Msi = (char) (v[s][i] + D * v[s][j]);
              Msi &= (char) 1;
              v[s][i] = Msi;
            }
          }
        }
        c[j] = k;
      }
      else {
        for (j = 0; j < t; j++) z[j] = 0;
        for (j = 0; j < t; j++) {
          if (j == k) z[j] = 1;
          else
            for (s = 0; s < t; s++)
              if (c[s] == j) z[j] = v[k][s];
        }
        zone(&za);
        for (i = 0; i < t1; i++) {
          if (z[i] == 1) {
            zcopy(za, &zt);
            zmul(zt, a[i], &za);
          }
        }
        zmod(za, *zn, &zx);
        for (j = 0; j < t; j++) {
          s = 0;
          for (i = 0; i < t1; i++)
            if (z[i] == 1) s += e[i][j];
          f[j] = (char) (s / 2);
        }
        zone(&za);
        for (j = 1; j < t; j++) {
          zintoz(p[j], &zc);
          zintoz(f[j], &zb);
          zexp(zc, zb, &zt);
          zcopy(za, &zb);
          zmul(zt, zb, &za);
        }
        if (f[0] >= 1) znegate(&za);
        zmod(za, *zn, &zy);
        zmod(zy, *zn, &zt);
        if (zcompare(zx, zt) != 0) {
          zsub(zx, zy, &zt);
          zabs(&zt);
          zgcd(zt, *zn, &zd);
          if (zscompare(zd, 1l) != 0) {
            zdiv(*zn, zd, &zt, &za);
            zcopy(zt, zn);
            if (zprobprime(zd, 5)) {
              Insert(1, zd, list);
              break;
            }
            else flag1 |= TrialDivide(&zd, list);
            if (zscompare(*zn, 1l) == 0) break;
          }
        }
      }
    }
  }
  flag2 = 0;
  if (zscompare(*zn, 1l) != 0) {
    if (zprobprime(*zn, 5)) Insert(1, *zn, list);
    else flag2 = TrialDivide(zn, list);
  }
  /* free up the memory that was allocated */
  for (i = 0; i < t1; i++) {
    zfree(&a[i]);
    free(e[i]);
    free(v[i]);
  }
  free(a);
  free(e);
  free(v);
  free(c);
  free(p);
  free(x1);
  free(x2);
  free(lnp);
  free(sieve);
  return flag1 | flag2;
}

int main(int argc, char *argv[])
{
  double time;
  long addend, base, exponent, n;
  NodePtr list = 0, node;
  clock_t time0 = clock();
  verylong zn = 0;

  if (argc != 3 && argc != 5) {
    printf("usage: mpqs n number\n");
    printf("       mpqs n base exponent addend\n");
    printf("where number to be factored is either\n");
    printf("number or base ^ exponent + addend\n");
    printf("n is the number of primes in factor base\n");
    exit(1);
  }
  n = atol(argv[1]);
  base = atol(argv[2]);
  if (argc == 3) {
    verylong zt = 0;
    zzero(&zt);
    zsadd(zt, base, &zn);
    zfree(&zt);
  }
  else {
    exponent = atol(argv[3]);
    addend = atol(argv[4]);
    zpow(base, exponent, &zn);
    zsadd(zn, addend, &zn);
  }
  zwrite(zn);
  printf(" is ");
  if (zprobprime(zn, 5))
    printf("prime\n");
  else {
    int flag;
    long same;
    verylong zt = 0;
    printf("composite\n");
    zcopy(zn, &zt);
    flag = mpqs(n, &zn, &list);
    if (flag == - 1)
      printf("*error*\ninsufficient memory\n");
    else {
      same = zcompare(zn, zt) == 0;
      zfree(&zt);
      if (same)
        printf("\n*error*\nnumber not factored\n");
      else {
        printf("\nfactors:\n");
        for (node = list; node != 0; node = node->next) {
          printf("\t");
          zwrite(node->value);
          if (node->expon != 1)
            printf(" ^ %ld\n", node->expon);
          else
            printf("\n");
        }
        if (!flag) printf("last factor is composite\n");
      }
    }
    Delete(&list);
  }
  zfree(&zn);
  time = (clock() - time0) / (double) CLK_TCK;
  printf("total time required: %f seconds\n", time);
  return 0;
}
