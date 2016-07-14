/*
  Author:  Pate Williams (c) 1997

  Multiple-precision addition. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al 14.2.2 Section pages 594 - 595.
*/

#include <stdio.h>
#include <stdlib.h>

#define BASE 10

typedef long * mp;

void mp_free(mp *mpa)
{
  free(*mpa);
  *mpa = 0;
}

void mp_set_length(long length, mp *mpa)
{
  mp mpx = *mpa;

  if (mpx != 0 && length <= mpx[0]) return;
  if (mpx != 0) free(mpx);
  mpx = calloc(length + 1, sizeof(long));
  mpx[0] = length;
  *mpa = mpx;
}

void mp_add(mp mpx, mp mpy, mp *mpw)
{
  long c = 0, i, s, x_len = mpx[0], y_len = mpy[0];
  long mx = max(x_len, y_len);
  long mn = min(x_len, y_len);
  long w_len = mx + 1;

  mp_set_length(w_len, mpw);
  for (i = 1; i <= mn; i++) {
    s = mpx[i] + mpy[i] + c;
    (*mpw)[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
  if (x_len > y_len) {
    for (i = mn + 1; i <= x_len; i++) {
      s = mpx[i] + c;
      (*mpw)[i] = s % BASE;
      c = s < BASE ? 0 : 1;
    }
  }
  else if (x_len < y_len) {
    for (i = mn + 1; i <= y_len; i++) {
      s = mpy[i] + c;
      (*mpw)[i] = s % BASE;
      c = s < BASE ? 0 : 1;
    }
  }
  (*mpw)[w_len] = c;
}

void mp_dump(mp mpa)
{
  long i;

  for (i = mpa[0]; i >= 1; i--)
    printf("%ld", mpa[i]);
  printf("\n");
}

void main(void)
{
  mp mpw = 0, mpx = 0, mpy = 0;

  mp_set_length(2, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 9, mpx[2] = 9;
  mpy[1] = 1, mpy[2] = 0, mpy[3] = 1;
  mp_add(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_set_length(3, &mpx);
  mp_set_length(2, &mpy);
  mpx[1] = 1, mpx[2] = 2, mpx[3] = 3;
  mpy[1] = 9, mpy[2] = 8;
  mp_add(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_set_length(3, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 1, mpx[2] = 2, mpx[3] = 3;
  mpy[1] = 4, mpy[2] = 5; mpy[3] = 7;
  mp_add(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_free(&mpw);
  mp_free(&mpx);
  mp_free(&mpy);
}
