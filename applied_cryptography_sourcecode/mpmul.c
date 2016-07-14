/*
  Author:  Pate Williams (c) 1997

  Multiple-precision multiplication. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et
  al 14.2.3 Section pages 595 - 596.
*/

#include <assert.h>
#include <mem.h>
#include <stdio.h>
#include <stdlib.h>

#define BASE 10
#define DEBUG

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

void mp_mul(mp mpx, mp mpy, mp *mpw)
/* calcuates w = x * y */
{
  long c, i, ij, j, x_len = mpx[0], y_len = mpy[0];
  long u, uv, v, w_len = x_len + y_len + 2, w_sign;
  long x_sign = mpx[x_len + 1], y_sign = mpy[y_len + 1];
  mp mpa = 0, mpb = 0, mpv;

  mp_copy(mpx, &mpa);
  mp_copy(mpy, &mpb);
  if (x_sign != 0) mp_negate(&mpa);
  if (y_sign != 0) mp_negate(&mpb);
  w_sign = (x_sign == y_sign) ? 0 : BASE - 1;
  mp_set_length(w_len, mpw);
  mpv = *mpw;
  #ifdef DEBUG
  printf("i j c u v w\n");
  #endif
  for (i = 1; i <= y_len; i++) {
    c = 0;
    for (j = 1; j <= x_len; j++) {
      ij = i + j - 1;
      uv = mpv[ij] + mpa[j] * mpb[i] + c;
      u = uv / BASE;
      v = uv % BASE;
      mpv[ij] = v;
      c = u;
      #ifdef DEBUG
      {
        long k;

        printf("%ld %ld %ld %ld %ld ", i, j, c, u, v);
        for (k = w_len; k >= 1; k--)
          printf("%ld ", mpv[k]);
        printf("\n");
      }
      #endif
    }
    mpv[i + x_len] = u;
  }
  for (i = w_len; i >= 1 && mpv[i] == 0; i--) mpv[0]--;
  if (w_sign != 0) mp_negate(mpw);
  mp_free(&mpa);
  mp_free(&mpb);
}

int main(void)
{
  mp mpw = 0, mpx = 0, mpy = 0;

  mp_set_length(4, &mpx);
  mp_set_length(3, &mpy);
  mpx[1] = 4, mpx[2] = 7, mpx[3] = 2, mpx[4] = 9;
  mpy[1] = 7, mpy[2] = 4, mpy[3] = 8;
  mp_mul(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_negate(&mpx);
  mp_mul(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_negate(&mpx);
  mp_negate(&mpy);
  mp_mul(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_negate(&mpx);
  mp_mul(mpx, mpy, &mpw);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpw);
  mp_free(&mpw);
  mp_free(&mpx);
  mp_free(&mpy);
  return 0;
}
