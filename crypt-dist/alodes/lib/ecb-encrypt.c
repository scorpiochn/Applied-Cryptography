#include "des-private.h"

/* input data is not modified. output is written after input has been
   read */

/* The least significant bit of input->data[0] is bit # 1 in
   DES-sepcification etc. */

#ifdef __alpha
#define des_ecb_encrypt des_ecb_encrypt_32
#endif

int	des_using_inlining = 1;

/* Defining DES_USE_SPE_PTR 1 may speed it up */
#define DES_USE_SPE_PTR 1

#if BIG_ENDIAN
#define P_IND(x) (((x)&04) | (3-((x)&03)))
#else
#define P_IND(x) (x)
#endif

int
des_ecb_encrypt(input,output,schedule,mode)

C_Block		*input;
C_Block		*output;
Key_schedule	*schedule;
int		mode;

{
  C_Block	ibuf;
  des_u_long	L[2],R[2],R0,R1;
  des_u_long	Lnext[2];
  int	i;
  int	encrypt;
#if DES_USE_SPE_PTR
  des_u_long	*des_spe_table0 = des_spe_table;
#define des_spe_table des_spe_table0
#endif

#if BIG_ENDIAN
  des_reverse(input,&ibuf);
  if (mode & DES_REVBITS)
    des_bitrev(&ibuf,&ibuf);
  if (!(mode & DES_NOIPERM)) {
    des_do_iperm(&ibuf,&ibuf);
  }
#else
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
#endif
  encrypt = !(mode & DES_DECRYPT);
  des_expand(&ibuf.data[0],&L[0]);
  des_expand(&ibuf.data[4],&R[0]);
  R0 = R[0]; R1 = R[1];
  for(i = 0; i < 16; i++) {
#if 0
    copy8(*R,*Lnext);
#else
    Lnext[0] = R0; Lnext[1] = R1;
#endif
#if 0
    des_fun(R,schedule,encrypt ? i : 15 - i);
    des_fun(R,schedule,ki);
#endif
    {
      int		ki = encrypt ? i : 15 - i;
      des_u_long	*keyptr = &schedule->data[ki*2];
      des_u_char	*p;
      des_u_long	F[2];
      int		i;
      
#if 0
      copy8(R[0],F[0]);
#else
      F[0] = R0; F[1] = R1;
#endif
      F[0] ^= keyptr[0];
      F[1] ^= keyptr[1];
      p = (des_u_char*)F;
      R0 = R1 = 0;
      i = 0;
      R0 ^= des_spe_table[i++*64 + p[P_IND(0)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(0)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(1)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(1)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(2)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(2)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(3)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(3)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(4)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(4)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(5)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(5)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(6)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(6)]];
      R0 ^= des_spe_table[i++*64 + p[P_IND(7)]];
      R1 ^= des_spe_table[i++*64 + p[P_IND(7)]];
    }
    R0 ^= L[0];
    R1 ^= L[1];
    copy8(*Lnext,*L);
  }
  
  R[0] = R0; R[1] = R1;
  val4(ibuf.data[0]) = des_unexpand(R);
  val4(ibuf.data[4]) = des_unexpand(L);

#if BIG_ENDIAN
  if (!(mode & DES_NOFPERM)) {
    if (mode & DES_REVBITS)
      des_do_fperm_rev(&ibuf,&ibuf);
    else
      des_do_fperm(&ibuf,&ibuf);
  } else {
    if (mode & DES_REVBITS)
      des_bitrev(&ibuf,&ibuf);
  }
  des_reverse(&ibuf,output);
#else
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
#endif
}
