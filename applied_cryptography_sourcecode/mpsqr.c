/*
  Author:  Pate Williams (c) 1997

  Multiple-precision squaring. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al 14.2.4 Section pages 596 - 597.
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

void mp_sqr(mp mpx, mp *mpw)
/* calcuates w = x * x */
{
  long c, i, ij, j, x_len = mpx[0];
  long u, uv, v, w_len = 2 * x_len;
  long x_sign = mpx[x_len + 1];
  mp mpa = 0, mpv;

  mp_copy(mpx, &mpa);
  if (x_sign != 0) mp_negate(&mpa);
  mp_set_length(w_len, mpw);
  mpv = *mpw;
  #ifdef DEBUG
  printf("i j u  v  w\n");
  #endif
  for (i = 1; i <= x_len; i++) {
    ij = 2 * i - 1;
    u = mpa[i];
    uv = mpv[ij] + u * u;
    u = uv / BASE;
    v = uv % BASE;
    mpv[ij] = v;
    c = u;
    for (j = i + 1; j <= x_len; j++) {
      ij = i + j - 1;
      uv = mpv[ij] + 2 * mpa[j] * mpa[i] + c;
      u = uv / BASE;
      v = uv % BASE;
      mpv[ij] = v;
      c = u;
      #ifdef DEBUG
      {
        long k;

        printf("%ld %ld %2ld %ld ", i, j, u, v);
        for (k = w_len; k >= 1; k--)
          printf("%2ld ", mpv[k]);
        printf("\n");
      }
      #endif
    }
    mpv[i + x_len] = u;
  }
  #ifdef DEBUG
  {
    long k;

    printf("- - %2ld %ld ", u, v);
    for (k = w_len; k >= 1; k--)
      printf("%2ld ", mpv[k]);
    printf("\n");
  }
  #endif
  mp_free(&mpa);
}

int main(void)
{
  mp mpw = 0, mpx = 0;

  mp_set_length(3, &mpx);
  mpx[1] = 9, mpx[2] = 8, mpx[3] = 9;
  mp_sqr(mpx, &mpw);
  mp_dump(mpx);
  mp_dump(mpw);
  mp_negate(&mpx);
  mp_sqr(mpx, &mpw);
  mp_dump(mpx);
  mp_dump(mpw);
  mp_free(&mpw);
  mp_free(&mpx);
  return 0;
}
