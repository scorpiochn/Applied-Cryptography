/*
  Author:  Pate Williams (c) 1997

  4.9 Algorithm Fermat primality test.
  See "Handbook of Applied Cryptography"
  by Alfred J. Menezes et al page 136.
*/

#include <ctype.h>
#include <stdio.h>
#include "lip.h"

int Fermat(long t, verylong zn)
/* returns 0 if composite 1 if probably prime */
{
  int flag = 1;
  long i;
  verylong za = 0, zn1 = 0, zr = 0;

  if (zodd(zn)) {
    if (zscompare(zn, 3l) > 0) {
      zsadd(zn, - 1l, &zn1);
      for (i = 1; flag && i <= t; i++) {
        do zrandomb(zn1, &za); while (zscompare(za, 2l) < 0);
        zexpmod(za, zn1, zn, &zr);
        if (zscompare(zr, 1l) != 0) flag = 0;
      }
    }
  }
  else flag = zscompare(zn, 2l) == 0;
  zfree(&za);
  zfree(&zn1);
  zfree(&zr);
  return flag;
}

int main(void)
{
  char answer[256];
  long t;
  verylong zn = 0;

  do {
    do {
      printf("enter the security parameter ( >= 1): ");
      scanf("%d", &t);
    } while (t < 1);
    printf("enter the number to be tested below:\n");
    zread(&zn);
    if (Fermat(t, zn))
      printf("number is probably prime\n");
    else
      printf("number is composite\n");
    printf("another number (n or y)? ");
    scanf("%s", answer);
  } while (tolower(answer[0]) == 'y');
  zfree(&zn);
  return 0;
}
