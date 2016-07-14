/*
  Author:  Pate Williams (c) 1997

  4.24 Algorithm Miller-Rabin probabilistic primality
  test. See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al page 139.
*/

#include <ctype.h>
#include <stdio.h>
#include "lip.h"

int Miller_Rabin(long t, verylong zn)
{
  int value = 1;
  long i, j, s = 0;
  verylong za = 0, zb = 0, zn1 = 0, zr = 0, zy = 0;

  if (zodd(zn)) {
    if (zscompare(zn, 3l) > 0) {
      zsadd(zn, - 1l, &zn1);
      zcopy(zn1, &zr);
      while (!zodd(zr)) {
        s++;
        zrshift(zr, 1l, &za);
        zcopy(za, &zr);
      }
      for (i = 1; value && i <= t; i++) {
        do zrandomb(zn1, &za); while (zscompare(za, 2l) < 0);
        zexpmod(za, zr, zn, &zy);
        if (zscompare(zy, 1l) != 0 &&
            zcompare(zy, zn1) != 0) {
          j = 1;
          while (value && j <= s - 1 && zcompare(zy, zn1) != 0) {
            zmulmod(zy, zy, zn, &zb);
            zcopy(zb, &zy);
            if (zscompare(zy, 1l) == 0) value = 0;
            j++;
          }
          if (value && zcompare(zy, zn1) != 0) value = 0;
        }
      }
    }
    else value = 1;
  }
  else value = zscompare(zn, 2l) == 0;
  zfree(&za);
  zfree(&zb);
  zfree(&zn1);
  zfree(&zr);
  zfree(&zy);
  return value;
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
    if (Miller_Rabin(t, zn))
      printf("number is probably prime\n");
    else
      printf("number is composite\n");
    printf("another number (n or y)? ");
    scanf("%s", answer);
  } while (tolower(answer[0]) == 'y');
  zfree(&zn);
  return 0;
}