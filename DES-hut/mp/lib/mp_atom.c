#include <ctype.h>
#define MP_PRIVATE 1
#include "amp.h"

static char	digit_arr[] = "0123456789abcdef";

char *
mp_mtoa_n(a,base)

amp	*a;
int	base;

{
  int	digits;
  char	*s;
  amp	*t;
  char	*p;
  mp_long	rem;
  int	negative;

  if (a->d_str_valid == base && a->d_str)
    return a->d_str;
  mp_remove_zeros(a);
  negative = (a->sign == MP_NEGATIVE);
  digits = (a->len * MP_BITS)/3 + 4; /* This works for bases >= 8 */
  if (t = a->denom) {
    digits += (t->len * MP_BITS)/3 + 2;
  }
  if (digits > a->d_str_len || !a->d_str) {
    a->d_str = mp_realloc(a->d_str,digits);
    a->d_str_len = digits;
  }
  t = mp_copy(a);
  p = s = a->d_str;
  if (t->len == 1 && t->data[0] == 0) {
    negative = 0;
    *p++ = '0';
  } else {
    if (negative)
      *p++ = '-';
    for(;;) {
      if (t->len <= 1 && t->data[0] == 0)
	break;
      mp_div_x_to(t,t,(mp_long)base,&rem);
      *p++ = digit_arr[rem];
    }
  }
  *p = 0;
  p--;
  {
    char	*p2;
    int		tmp;
    p2 = s;
    if (negative)
      p2++;
    while (p2 < p) {
      tmp = *p;
      *p-- = *p2;
      *p2++ = tmp;
    }
  }
  mp_free(t);
  if (a->denom) {
    p = a->d_str;
    strcat(p,"/");
    strcat(p,mp_mtoa_n(a->denom,base));
  }
  a->d_str_valid = base;
  return s;
}

char *
mp_mtoa(a)

{
  return mp_mtoa_n(a,10);
}

char *
mp_mtoh(a)

{
  return mp_mtoa_n(a,16);
}

amp *
mp_atom(p)

char	*p;

{
  amp	*r;
  int	c;
  int	sign = MP_POSITIVE;

  r = 0;
  if (*p == '-') {
    sign = MP_NEGATIVE;
    p++;
  }
  for(; c = *p++; ) {
    if (isascii(c) && isdigit(c)) {
      c -= '0';
    } else {
      break;
    }
    if (!r) {
      r = mp_itom((mp_long)c);
    } else {
      mp_mul_x_to(r,r,(mp_long)10);
      mp_add_x_to(r,(long)c);
    }
  }
  r->sign = sign;
  return r;
}

amp *
mp_htom(p)

char	*p;

{
  amp	*r;
  int	c;
  int	sign = MP_POSITIVE;

  r = 0;
  if (*p == '-') {
    sign = MP_NEGATIVE;
    p++;
  }
  for(; c = *p++; ) {
    if (c >= '0' && c <= '9') {
      c -= '0';
    } else if (c >= 'a' && c <= 'f') {
      c -= 'a'-10;
    } else if (c >= 'A' && c <= 'F') {
      c -= 'A'-10;
    } else {
      break;
    }
    if (!r) {
      r = mp_itom((mp_long)c);
    } else {
      mp_mul_x_to(r,r,(mp_long)16);
      mp_add_x_to(r,(long)c);
    }
  }
  r->sign = sign;
  return r;
}
