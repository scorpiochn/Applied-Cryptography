/*
  Author:  Pate Williams (c) 1997

  Multiple precision p - 1 factoring method.
  See Algorithm 8.8.2 "A Course in
  Computational Algebraic Number Theory"
  by Henri Cohen page 439. The command line
  is as follows:

  pminone base exponent addend

  where base, exponent, and addend are long
  integers, factors base ^ exponent + addend.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define B 1000000l
#define NUMBER_PRIMES 78498l

typedef struct Node * NodePtr;

struct Node {
  long expon;
  verylong value;
  NodePtr next;
};

int Insert(verylong v, NodePtr *list)
{
  NodePtr currentPtr, newPtr, previousPtr;

  newPtr = malloc(sizeof(struct Node));
  if (newPtr == 0) return 0;
  newPtr->expon = 1l;
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

int MillerRabin(int C, verylong zn)
{
  int i, j, k = 0;
  static verylong za = 0, zb = 0, zar = 0, zn1 = 0, zr = 0;

  zsadd(zn, - 1l, &zn1);
  zcopy(zn1, &zr);
  if (zscompare(zn, 4l) < 1) return 1;
  if (zsmod(zn, 2l) == 0) return 0;
  while (zsmod(zr, 2l) == 0) {
    k++;
    zcopy(zr, &za);
    zsdiv(za, 2l, &zr);
    if (zsmod(zr, 2l) == 1l) break;
  }
  for (j = 0; j < C; j++) {
    zrandomb(zn1, &za);
    if (zscompare(za, 2l) < 0) {
      zzero(&zb);
      zsadd(zb, 2, &za);
    }
    zexpmod(za, zr, zn, &zar);
    if (zscompare(zar, 1l) != 0 && zcompare(zar, zn1) != 0) {
      i = 0;
      do {
        zcopy(zar, &za);
        zmul(za, za, &zar);
        zcopy(zar, &za);
        zmod(za, zn, &zar);
        if (zcompare(zar, zn1) == 0) break;
        i++;
      } while (i < k);
      if (i == k) return 0;
    }
  }
  return 1;
}

int FirstStage(long k, verylong *zN, long x0, long *p,
               verylong *zx, NodePtr *list)
{
  long c = 0, i = - 1, j = i, l, q, q1;
  static verylong zg = 0, zq1 = 0, zt = 0, zx1 = 0, zy = 0;

  zzero(&zg);
  zsadd(zg, x0, zx);
  zcopy(*zx, &zy);
  L2:
    i++;
    if (i >= k) {
      zsadd(*zx, - 1l, &zx1);
      zgcd(zx1, *zN, &zg);
      if (zscompare(zg, 1l) == 0) return 0;
      else {
        i = j;
        zcopy(zy, zx);
        goto L5;
      }
    }
    else {
      q = p[i];
      q1 = q;
      l = B / q;
    }
  L3:
    while (q1 <= l) q1 *= q;
    zzero(&zt);
    zsadd(zt, q1, &zq1);
    zcopy(*zx, &zt);
    zexpmod(zt, zq1, *zN, zx);
    if (++c < 20) goto L2;
  L4:
    zsadd(*zx, - 1l, &zx1);
    zgcd(zx1, *zN, &zg);
    if (zscompare(zg, 1l) == 0) {
      c = 0;
      j = i;
      zcopy(*zx, &zy);
      goto L2;
    }
    else {
      i = j;
      zcopy(zy, zx);
    }
  L5:
    i++;
    q = p[i];
    q1 = q;
  L6:
    zzero(&zt);
    zsadd(zt, q , &zq1);
    zcopy(*zx, &zt);
    zexpmod(zt, zq1, *zN, zx);
    zsadd(*zx, - 1l, &zx1);
    zgcd(zx1, *zN, &zg);
    if (zscompare(zg, 1l) == 0) {
      q1 *= q;
      if (q1 <= B) goto L6; else goto L5;
    }
    else {
      if (zcompare(zg, *zN) < 0) {
        Insert(zg, list);
        zcopy(*zN, &zq1);
        zdiv(zq1, zg, zN, &zx1);
        return 1;
      }
      if (zcompare(zg, *zN) == 0) return 0;
   }
  return 1;
}

int main(int argc, char *argv[])
{
  double time;
  long addend, base, exponent, i, j, *p;
  NodePtr list = 0, node;
  clock_t time0 = clock();
  verylong zn = 0, zx = 0;

  if (argc != 4) {
    printf("usage: pminone base exponent addend\n");
    printf("where number to be factored is\n");
    printf("base ^ exponent + addend\n");
    exit(1);
  }
  base = atol(argv[1]), exponent = atol(argv[2]);
  addend = atol(argv[3]);
  zpow(base, exponent, &zn);
  zsadd(zn, addend, &zn);
  zwrite(zn);
  printf(" is ");
  if (MillerRabin(4, zn))
    printf("prime\n");
  else {
    printf("composite\nfactors:\n");
    p = (long *) malloc(NUMBER_PRIMES * sizeof(long));
    for (i = 0; i < NUMBER_PRIMES; i++) p[i] = zpnext();
    i = 0;
    j = p[0];
    do {
      while (!FirstStage(NUMBER_PRIMES, &zn, j, p, &zx, &list) && i < NUMBER_PRIMES)
        i++, j = p[i];
      j = p[++i];
    } while (!MillerRabin(4, zn) && i < NUMBER_PRIMES);
    Insert(zn, &list);
    for (node = list; node != 0; node = node->next) {
      printf("\t");
      zwrite(node->value);
      if (node->expon != 1)
        printf(" ^ %ld\n", node->expon);
      else
        printf("\n");
    }
    Delete(&list);
    free(p);
  }
  zfree(&zn);
  zfree(&zx);
  time = (clock() - time0) / (double) CLK_TCK;
  printf("total time required: %lf seconds\n", time);
  return 0;
}
