/*
  Author:  Pate Williams (c) 1997

  Multiple-precision subtraction. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes
  et al 14.2.2 Section pages 594 - 595.
*/

#include <assert.h>
#include <mem.h>
#include <stdio.h>
#include <stdlib.h>

#define BASE 10

typedef long * mp;

void mp_set_length(long length, mp *mpa)
{
  mp mpx = *mpa;

  if (mpx != 0) free(mpx);
  mpx = calloc(length + 2, sizeof(long));
  assert(mpx != 0);
  mpx[0] = length;
  *mpa = mpx;
}

void mp_extend(long length, mp mpa, mp *mpb)
{
  long i, len = mpa[0], sign = mpa[len + 1];
  mp mpx;

  mp_set_length(length, mpb);
  mpx = *mpb;
  memcpy(mpx, mpa, (len + 2) * sizeof(long));
  if (length == len) return;
  for (i = len + 1; i <= length; i++)
    mpx[i] = sign;
  mpx[0] = length;
  mpx[length + 1] = sign;
}

void mp_free(mp *mpa)
{
  free(*mpa);
  *mpa = 0;
}

void mp_copy(mp mpa, mp *mpb)
{
  long length = mpa[0];

  mp_set_length(length, mpb);
  memcpy(*mpb, mpa, (length + 2) * sizeof(long));
}

void mp_negate(mp *mpa)
{
  mp mpx = *mpa;
  long base_1 = BASE - 1, c = 1, i, length = mpx[0] + 1, s;
  long sign = mpx[length];

  for (i = 1; i <= length; i++)
    mpx[i] = base_1 - mpx[i];
  for (i = 1; i <= length; i++) {
    s = mpx[i] + c;
    mpx[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
  mpx[length] = (sign == 0) ? base_1 : 0;
}

void mp_dump(mp mpa)
{
  char sign = '+';
  long i;
  mp mpb = 0;

  mp_copy(mpa, &mpb);
  if (mpb[mpa[0] + 1] != 0) {
    mp_negate(&mpb);
    sign = '-';
  }
  printf("%c", sign);
  for (i = mpb[0]; i >= 1; i--)
    printf("%ld", mpb[i]);
  printf("\n");
}

void mp_add(mp mpx, mp mpy, mp *mpw)
/* calcuates w = x + y */
{
  long c = 0, i, s, x_len = mpx[0], y_len = mpy[0];
  long length, mx = max(x_len, y_len);
  long w_len = mx;
  mp mpa = 0, mpb = 0, mpv;

  if (x_len == y_len) w_len++;
  mp_extend(mx, mpx, &mpa);
  mp_extend(mx, mpy, &mpb);
  #ifdef DEBUG
  for (i = mpa[0] + 1; i >= 1; i--)
    printf("%ld", mpa[i]);
  printf("\n");
  for (i = mpb[0] + 1; i >= 1; i--)
    printf("%ld", mpb[i]);
  printf("\n");
  #endif
  mp_set_length(w_len, mpw);
  mpv = *mpw;
  for (i = 1; i <= mx + 1; i++) {
    s = mpa[i] + mpb[i] + c;
    mpv[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
  length = mpv[0];
  for (i = length; i >= 1 && mpv[i] == 0; i--) mpv[0]--;
  mpv[mpv[0] + 1] = mpv[length + 1];
  mp_free(&mpa);
  mp_free(&mpb);
}

void mp_sub(mp mpx, mp mpy, mp *mpw)
/* calculates w = x - y */
{
  mp mpz = 0;

  mp_copy(mpy, &mpz);
  mp_negate(&mpz);
  mp_add(mpx, mpz, mpw);
  mp_free(&mpz);
}

void main(void)
{
  mp mpw = 0, mpx = 0, mpy = 0;

  mp_set_length(2, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 9, mpx[2] = 9, mpx[3] = 0;
  mpy[1] = 1, mpy[2] = 0, mpy[3] = 1, mpy[4] = 0;
  mp_sub(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_set_length(3, &mpx);
  mp_set_length(2, &mpy);
  mpx[1] = 1, mpx[2] = 2, mpx[3] = 3, mpx[4] = 0;
  mpy[1] = 9, mpy[2] = 8, mpy[3] = 0;
  mp_sub(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_set_length(3, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 1, mpx[2] = 2, mpx[3] = 3, mpx[4] = 0;
  mpy[1] = 4, mpy[2] = 5; mpy[3] = 2, mpy[4] = 0;
  mp_sub(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_set_length(3, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 2, mpx[2] = 8, mpx[3] = 8, mpx[4] = 0;
  mpy[1] = 4, mpy[2] = 5; mpy[3] = 2, mpy[4] = 0;
  mp_add(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_free(&mpw);
  mp_free(&mpx);
  mp_free(&mpy);
}
