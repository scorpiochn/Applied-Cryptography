#ifdef __alpha
#include "des-private.h"

/* input data is not modified. output is written after input has been
   read */

/* The least significant bit of input->data[0] is bit # 1 in
   DES-sepcification etc. */

int	des_using_inlining_64 = 1;

#define P_IND(x) (x)

int
des_ecb_encrypt(input,output,schedule,mode)

C_Block		*input;
C_Block		*output;
Key_schedule	*schedule;
int		mode;

{
  C_Block	ibuf;
  des_u_long_64	L,R,R0;
  des_u_long_64	Lnext;
  int	i;
  int	encrypt;
  des_u_long_64	*des_spe_table0 = des_spe_table_64;

  if (!(mode & DES_NOIPERM)) {
    if (mode & DES_REVBITS) {
      des_do_iperm_rev(input,&ibuf);
    } else {
      des_do_iperm(input,&ibuf);
    }
  } else {
    if (mode & DES_REVBITS)
      des_bitrev(input,&ibuf);
    else
      copy8(*input,ibuf);
  }

  encrypt = !(mode & DES_DECRYPT);
  des_expand(&ibuf.data[0],&L);
  des_expand(&ibuf.data[4],&R);
  for(i = 0; i < 16; i++) {
    Lnext = R;
    {
      int		ki = encrypt ? i : 15 - i;
      des_u_long	*keyptr = &schedule->data[ki*2];
      des_u_char	*p;
      des_u_long_64	F;
      des_u_long_64	R0;
      
      F = R;
      F ^= keyptr[0]|((unsigned long)(keyptr[1])<<32);

      R0 = 0;
      R0 |= des_spe_table0[0*64 + ((F>> 0)&0xff)];
      R0 |= des_spe_table0[1*64 + ((F>> 8)&0xff)];
      R0 |= des_spe_table0[2*64 + ((F>>16)&0xff)];
      R0 |= des_spe_table0[3*64 + ((F>>24)&0xff)];
      R0 |= des_spe_table0[4*64 + ((F>>32)&0xff)];
      R0 |= des_spe_table0[5*64 + ((F>>40)&0xff)];
      R0 |= des_spe_table0[6*64 + ((F>>48)&0xff)];
      R0 |= des_spe_table0[7*64 + ((F>>56)&0xff)];
      R = R0;
    }
    R ^= L;
    L = Lnext;
  }
  val4(ibuf.data[0]) = des_unexpand(&R);
  val4(ibuf.data[4]) = des_unexpand(&L);

  if (!(mode & DES_NOFPERM)) {
    if (mode & DES_REVBITS)
      des_do_fperm_rev(&ibuf,output);
    else
      des_do_fperm(&ibuf,output);
  } else {
    if (mode & DES_REVBITS)
      des_bitrev(&ibuf,output);
    else
      copy8(ibuf,*output);
  }
}
#endif
