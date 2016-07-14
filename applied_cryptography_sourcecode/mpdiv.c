/*
  Author:  Pate Williams (c) 1997

  Multiple-precision division. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al 14.2.5 Section pages 598 - 599.
*/

#include <assert.h>
#include <mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 10l
#define BITS_PER_LONG 32l
#define DIGITS_PER_LINE 78l
#define DEBUG

typedef long * mp;

void mp_set_length(long length, mp *mpa)
{
  mp mpx = *mpa;

  if (mpx) {
    if (length > mpx[0]) {
      mpx = realloc(mpx, (length + 2) * sizeof(long));
      assert(mpx != 0);
    }
    memset(mpx, 0, (length + 2) * sizeof(long));
  }
  else {
    mpx = calloc(length + 2, sizeof(long));
    assert(mpx != 0);
  }
  mpx[0] = length;
  *mpa = mpx;
}

void mp_copy(mp mpa, mp *mpb)
{
  long length = mpa[0];

  mp_set_length(length, mpb);
  memcpy(*mpb, mpa, (length + 2) * sizeof(long));
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

void mp_add(mp mpx, mp mpy, mp *mpw)
/* calcuates w = x + y */
{
  long c = 0, i, s, x_len = mpx[0], y_len = mpy[0];
  long mx = max(x_len, y_len);
  long w_len = mx;
  mp mpa = 0, mpb = 0, mpv;

  if (x_len == y_len) w_len++;
  mp_extend(w_len, mpx, &mpa);
  mp_extend(w_len, mpy, &mpb);
  mp_set_length(w_len, mpw);
  mpv = *mpw;
  for (i = 1; i <= w_len + 1; i++) {
    s = mpa[i] + mpb[i] + c;
    mpv[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
  mp_free(&mpa);
  mp_free(&mpb);
}

void mp_negate(mp *mpa)
{
  mp mpx = *mpa;
  long base_1 = BASE - 1, c = 1, i, length = mpx[0] + 1, s;

  for (i = 1; i <= length; i++)
    mpx[i] = base_1 - mpx[i];
  for (i = 1; i <= length; i++) {
    s = mpx[i] + c;
    mpx[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
}

int mp_compares(mp mpa, long s)
{
  int value;
  long a_len = mpa[0], s_sign = s < 0;
  long a_sign = mpa[a_len + 1] != 0;
  mp mpb = 0;

  if (a_sign != s_sign)
    value = a_sign ? - 1 : + 1;
  else if (a_len > 1)
    value = s_sign ? - 1 : + 1;
  else {
    if (s_sign) s = - s;
    mp_copy(mpa, &mpb);
    if (a_sign) mp_negate(&mpb);
    if (mpb[1] == 0) value = 0;
    else value = mpb[1] - s;
    if (a_sign) value = - value;
  }
  return value;
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

void mp_sub(mp mpx, mp mpy, mp *mpw)
/* calculates w = x - y */
{
  mp mpz = 0;

  mp_copy(mpy, &mpz);
  mp_negate(&mpz);
  mp_add(mpx, mpz, mpw);
  mp_free(&mpz);
}

int mp_compare(mp mpx, mp mpy)
{
  int zero;
  long i, length, sign;
  mp mpz = 0;

  mp_sub(mpx, mpy, &mpz);
  length = mpz[0];
  sign = mpz[length + 1];
  if (sign != 0) return - 1;
  for (zero = 1, i = length; i >= 1 && zero; i--)
    zero = mpz[i] == 0;
  if (zero) return 0;
  return + 1;
}

void mp_adds(mp mpx, long y, mp *mpw)
/* calcuates w = x + y */
{
  int zero;
  long c = y, i, s, sign, x_len = mpx[0];
  long w_len = x_len + 1;
  mp mpv;

  mp_set_length(w_len, mpw);
  mpv = *mpw;
  for (i = 1; i <= w_len; i++) {
    s = mpx[i] + c;
    mpv[i] = s % BASE;
    c = s < BASE ? 0 : 1;
  }
  sign = mpv[w_len + 1];
  for (i = w_len, zero = mpv[w_len] == 0; i >= 3 && zero; i--)
    zero = mpv[i - 1] == 0, mpv[0]--;
  mpv[mpv[0] + 1] = sign;
}

void mp_base_left_shift(mp mpa, long count, mp *mpb)
{
  long i, length = mpa[0];
  mp mpc;

  mp_set_length(length + count, mpb);
  mpc = *mpb;
  for (i = 1; i <= count; i++)
    mpc[i] = 0;
  for (i = 1; i <= length; i++)
    mpc[i + count] = mpa[i];
}

void mp_div(mp mpx, mp mpy, mp *mpq, mp *mpr)
/* calcuates q = x / y, r = x % y */
{
  int zero = 1;
  long c, l, qj, sign, u, uv, v, xi, xi1, xi2, yt, yt1;
  long i, j, k, x_len = mpx[0], y_len = mpy[0];
  long a_len, q_len = x_len - y_len + 1, r_len = y_len;
  long x_sign = mpx[x_len + 1], y_sign = mpy[y_len + 1];
  mp mpa = 0, mpb = 0, mpc = 0, mpd = 0, mpe = 0;
  mp mpu, mpv, mpw = 0;

  /* test for zero divisor */
  for (i = y_len; i >= 1 && zero; i--)
    zero = mpy[i] == 0;
  assert(zero == 0);
  mp_copy(mpx, &mpa);
  mp_copy(mpy, &mpb);
  if (x_sign != 0) mp_negate(&mpa);
  if (y_sign != 0) mp_negate(&mpb);
  /* check for dividend < divisor */
  if (mp_compare(mpa, mpb) < 0) {
    mp_set_length(1, mpq);
    (*mpq)[1] = 0;
    if (mpx[x_len + 1] == 0)
      mp_copy(mpx, mpr);
    else
      mp_add(mpx, mpy, mpr);
  }
  else {
    mp_set_length(q_len, mpq);
    mp_set_length(r_len, mpr);
    mpu = *mpq;
    mp_base_left_shift(mpb, x_len - y_len, &mpc);
    while (mp_compare(mpa, mpc) >= 0) {
      mpu[q_len]++;
      mp_sub(mpa, mpc, &mpd);
      mp_copy(mpd, &mpa);
    }
    #ifdef DEBUG
    for (j = mpu[0]; j >= 1; j--)
      printf("%ld", mpu[j]);
    printf(" ");
    for (j = mpa[0]; j >= 1; j--)
      printf("%ld", mpa[j]);
    printf("\n");
    #endif
    for (i = mpa[0], zero = mpa[i] == 0; i >= 1 && zero; i--)
      zero = mpa[i - 1] == 0, mpa[0]--;
    mpa[mpa[0] + 1] = 0;
    yt  = mpb[y_len];
    yt1 = mpb[y_len - 1];
    for (i = x_len; i >= y_len + 1; i--) {
      j = i - y_len;
      a_len = mpa[0];
      if (i <= a_len) xi = mpa[i]; else xi = 0;
      if (i - 1 <= a_len) xi1 = mpa[i - 1]; else xi1 = 0;
      if (i - 2 <= a_len) xi2 = mpa[i - 2]; else xi2 = 0;
      if (xi == yt)
        qj = BASE - 1;
      else
        qj = (BASE * xi + xi1) / yt;
      while (qj * (yt * BASE + yt1) >
             xi * BASE * BASE + xi1 * BASE + xi2)
        qj--;
      if (qj != 0) {
        mp_base_left_shift(mpb, j - 1, &mpc);
        c = 0;
        l = mpc[0];
        mp_set_length(l + 1, &mpw);
        for (k = 1; k <= l; k++) {
          uv = mpw[k] + qj * mpc[k] + c;
          u = uv / BASE;
          v = uv % BASE;
          mpw[k] = v;
          c = u;
        }
        mpw[l + 1] = u;
        mp_sub(mpa, mpw, &mpd);
        if (mpd[mpd[0] + 1] != 0) {
          mp_add(mpa, mpc, &mpe);
          mp_copy(mpe, &mpd);
          qj--;
        }
        mp_copy(mpd, &mpa);
      }
      mpu[j] = qj;
      for (j = mpu[0], zero = mpu[j] == 0; j >= 1 && zero; j--)
        zero = mpu[j - 1] == 0, mpu[0]--;
      for (j = mpa[0], zero = mpa[j] == 0; j >= 1 && zero; j--)
        zero = mpa[j - 1] == 0, mpa[0]--;
      mpu[mpu[0] + 1] = 0;
      mpa[mpa[0] + 1] = 0;
      #ifdef DEBUG
      for (j = mpu[0]; j >= 1; j--)
        printf("%ld", mpu[j]);
      printf(" ");
      for (j = mpa[0]; j >= 1; j--)
        printf("%ld", mpa[j]);
      printf("\n");
      #endif
    }
    mp_copy(mpa, mpr);
    for (i = q_len, zero = mpu[q_len] == 0; i >= 3 && zero; i--)
      zero = mpu[i - 1] == 0, q_len--;
    mpu[0] = q_len;
    mpu[q_len + 1] = 0;
    if (x_sign != 0 && y_sign == 0) {
      mp_adds(*mpq, 1l, &mpc);
      mp_copy(mpc, mpq);
      mp_negate(mpq);
      mp_negate(mpr);
      mp_add(*mpr, mpb, &mpc);
      mp_copy(mpc, mpr);
      mpv = *mpr;
      for (i = r_len, zero = mpv[r_len] == 0; i >= 3 && zero; i--)
        zero = mpv[i - 1] == 0, r_len--;
      mpv[0] = r_len;
      mpv[r_len + 1] = 0;
    }
    else if (x_sign == 0 && y_sign != 0) {
      mp_adds(*mpq, 1l, &mpc);
      mp_copy(mpc, mpq);
      mp_negate(mpq);
      mp_add(*mpr, mpy, &mpc);
      mp_copy(mpc, mpr);
      mpv = *mpr;
      sign = mpv[r_len + 1];
      for (i = r_len, zero = mpv[r_len] == 0; i >= 3 && zero; i--)
        zero = mpv[i - 1] == 0, r_len--;
      mpv[0] = r_len;
      mpv[r_len + 1] = sign;
    }
    else if (x_sign != 0 && y_sign != 0) {
      mp_negate(mpr);
      mpv = *mpr;
      sign = mpv[r_len + 1];
      for (i = r_len, zero = mpv[r_len] == 0; i >= 3 && zero; i--)
        zero = mpv[i - 1] == 0, r_len--;
      mpv[0] = r_len;
      mpv[r_len + 1] = sign;
    }
  }
  mp_free(&mpa);
  mp_free(&mpb);
  mp_free(&mpc);
  mp_free(&mpd);
  mp_free(&mpe);
  mp_free(&mpw);
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
  for (i = 1; i <= y_len; i++) {
    c = 0;
    for (j = 1; j <= x_len; j++) {
      ij = i + j - 1;
      uv = mpv[ij] + mpa[j] * mpb[i] + c;
      u = uv / BASE;
      v = uv % BASE;
      mpv[ij] = v;
      c = u;
    }
    mpv[i + x_len] = u;
  }
  for (i = w_len; i >= 1 && mpv[i] == 0; i--) mpv[0]--;
  if (w_sign != 0) mp_negate(mpw);
  mp_free(&mpa);
  mp_free(&mpb);
}

int mp_odd(mp mpa)
/* returns nonzero if a is odd */
{
  return (int) (mpa[1] & 1l);
}

void mp_one(mp *mpa)
/* a = 1 */
{
  mp_set_length(1, mpa);
  (*mpa)[1] = 1;
}

void mp_zero(mp *mpa)
/* a = 0 */
{
  mp_set_length(1, mpa);
}

void mp_long_to_mp(long l, mp *mpa)
{
  long digits[256], i = 0, j, sign = l < 0;

  if (sign) l = - l;
  do {
    digits[i++] = l % BASE;
    l /= BASE;
  } while (l > 0);
  mp_set_length(i, mpa);
  for (j = 1; j <= i; j++) (*mpa)[j] = digits[j - 1];
  if (sign) mp_negate(mpa);
}

void mp_print(mp mpa)
{
  char digits[2048];
  long count, i = 0, j, k, left, sign = 0;
  mp mpb = 0, mpc = 0, mpq = 0, mpr = 0;

  mp_copy(mpa, &mpb);
  if (mpb[mpb[0] + 1] != 0) {
    sign = 1;
    mp_negate(&mpb);
  }
  mp_long_to_mp(10l, &mpc);
  do {
    mp_div(mpb, mpc, &mpq, &mpr);
    digits[i++] = (char) (mpr[1] + '0');
    mp_copy(mpq, &mpb);
  } while (mp_compares(mpq, 0l) > 0);
  digits[i] = 0;
  strrev(digits);
  count = i / DIGITS_PER_LINE;
  left = i % DIGITS_PER_LINE;
  if (sign == 1) printf("-");
  for (i = 0; i < count; i++) {
    j = i * DIGITS_PER_LINE;
    for (k = 0; k < DIGITS_PER_LINE; k++)
      printf("%c", digits[j + k]);
    printf("\\\n");
  }
  i = count * DIGITS_PER_LINE;
  for (j = 0; j < left; j++)
    printf("%c", digits[i + j]);
  printf("\n");
  mp_free(&mpb);
  mp_free(&mpc);
  mp_free(&mpq);
  mp_free(&mpr);
}

int main(void)
{
  mp mpq = 0, mpr = 0, mpx = 0, mpy = 0;

  mp_set_length(9, &mpx);
  mp_set_length(5, &mpy);
  mpx[1] = 7, mpx[2] = 2, mpx[3] = 3, mpx[4] = 8;
  mpx[5] = 4, mpx[6] = 9, mpx[7] = 1, mpx[8] = 2, mpx[9] = 7;
  mpy[1] = 1, mpy[2] = 6, mpy[3] = 4, mpy[4] = 4, mpy[5] = 8;
  mp_div(mpx, mpy, &mpq, &mpr);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpq);
  mp_dump(mpr);
  mp_negate(&mpx);
  mp_div(mpx, mpy, &mpq, &mpr);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpq);
  mp_dump(mpr);
  mp_negate(&mpx);
  mp_negate(&mpy);
  mp_div(mpx, mpy, &mpq, &mpr);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpq);
  mp_dump(mpr);
  mp_negate(&mpx);
  mp_div(mpx, mpy, &mpq, &mpr);
  mp_dump(mpx);
  mp_dump(mpy);
  mp_dump(mpq);
  mp_dump(mpr);
  mp_free(&mpq);
  mp_free(&mpr);
  mp_free(&mpx);
  mp_free(&mpy);
  return 0;
}
