#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_sub(amp *a, amp *b)

{
  return mp_add_internal((amp*)0,a,b,1);
}

amp *
mp_sub_to(amp *r, amp *a, amp *b)

{
  return mp_add_internal(r,a,b,1);
}

amp *
mp_sub_x_to(amp *r, long x)

{
  mp_int	tmp_arr[MP_SIZE_FOR_LONG];
  amp		tmp;

  tmp = mp_dont_allocate;
  tmp.data = tmp_arr;
  tmp.buflen = MP_SIZE_FOR_LONG;
  tmp.not_malloced = 1;

  mp_itom_to(&tmp,x);
  return mp_add_internal(r,r,&tmp,1);
}
